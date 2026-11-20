/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use crate::authenticatorservice::{RegisterArgs, SignArgs};
use crate::ctap2;
use crate::ctap2::commands::client_pin::Pin;
use crate::errors::AuthenticatorError;
use crate::statecallback::StateCallback;
use crate::status_update::{send_status, InteractiveUpdate};
use crate::transport::device_selector::{
    BlinkResult, Device, DeviceBuildParameters, DeviceCommand, DeviceSelectorEvent,
};
use crate::transport::platform::transaction::Transaction;
use crate::transport::{hid::HIDDevice, CtapVersionSupport, FidoDevice, FidoProtocol};
use crate::{InteractiveRequest, ManageResult};
use std::sync::mpsc::{channel, RecvTimeoutError, Sender};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[derive(Default)]
pub struct StateMachine {
    transaction: Option<Transaction>,
    cancel_token: Option<CancelToken>,
}

/// Per-transaction cancellation token.
///
/// A transaction is driven on separate threads and its HID reads can complete
/// after [`StateMachine::cancel`] was invoked. The token is shared with the
/// transaction's wrapper callback: once a transaction is aborted, every result
/// its threads still try to deliver — including a late successful response —
/// is replaced by [`AuthenticatorError::CancelledByUser`]. This keeps the
/// state machine in a provably isolated state between commands, so a new
/// register/sign/reset call can never inherit the previous transaction's
/// UV/device outcome.
#[derive(Clone)]
struct CancelToken {
    cancelled: Arc<AtomicBool>,
}

impl CancelToken {
    fn new() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    /// Wrap a callback so that its result is only delivered while the owning
    /// transaction is still active. A result arriving after cancellation is
    /// dropped and reported as a user cancellation instead.
    fn guard<T>(
        &self,
        callback: StateCallback<crate::Result<T>>,
    ) -> StateCallback<crate::Result<T>>
    where
        T: 'static + Send,
    {
        let token = self.clone();
        StateCallback::new(Box::new(move |result| {
            if token.is_cancelled() {
                info!("Dropping result of a cancelled transaction.");
                callback.call(Err(AuthenticatorError::CancelledByUser));
            } else {
                callback.call(result);
            }
        }))
    }
}

impl StateMachine {
    pub fn new() -> Self {
        Default::default()
    }

    /// Prepare the state machine for a new command.
    ///
    /// Any in-flight transaction is torn down first, and a fresh cancellation
    /// token is created. The returned token marks the new transaction as the
    /// only active one; all callbacks of the command must be wrapped through
    /// [`CancelToken::guard`] so results of a later cancellation cannot leak.
    fn begin_transaction(&mut self) -> CancelToken {
        self.cancel();
        let token = CancelToken::new();
        self.cancel_token = Some(token.clone());
        token
    }

    fn init_device(
        info: DeviceBuildParameters,
        selector: &Sender<DeviceSelectorEvent>,
    ) -> Option<Device> {
        // Create a new device.
        let mut dev = match Device::new(info) {
            Ok(dev) => dev,
            Err((e, id)) => {
                info!("error happened with device: {}", e);
                let _ = selector.send(DeviceSelectorEvent::NotAToken(id));
                return None;
            }
        };

        // Try initializing it.
        if let Err(e) = dev.init() {
            warn!("error while initializing device: {}", e);
            let _ = selector.send(DeviceSelectorEvent::NotAToken(dev.id()));
            return None;
        }

        Some(dev)
    }

    fn wait_for_device_selector(
        dev: &mut Device,
        selector: &Sender<DeviceSelectorEvent>,
        status: &Sender<crate::StatusUpdate>,
        keep_alive: &dyn Fn() -> bool,
    ) -> bool {
        let (tx, rx) = channel();
        if selector
            .send(DeviceSelectorEvent::ImAToken((dev.id(), tx)))
            .is_err()
        {
            // If we fail to register with the device selector, then we're not going
            // to be selected.
            return false;
        }

        // We can be cancelled from the user (through keep_alive()) or from the device selector
        // (through a DeviceCommand::Cancel on rx).  We'll combine those signals into a single
        // predicate to pass to Device::block_and_blink.
        let keep_blinking = || keep_alive() && !matches!(rx.try_recv(), Ok(DeviceCommand::Cancel));

        // Blocking recv. DeviceSelector will tell us what to do
        match rx.recv() {
            Ok(DeviceCommand::Blink) => {
                // The caller wants the user to choose a device. Send a status update and blink
                // this device. NOTE: We send one status update per device, so the recipient should be
                // prepared to receive the message multiple times.
                send_status(status, crate::StatusUpdate::SelectDeviceNotice);
                match dev.block_and_blink(&keep_blinking) {
                    BlinkResult::DeviceSelected => {
                        // User selected us. Let DeviceSelector know, so it can cancel all other
                        // outstanding open blink-requests. If we fail to send the SelectedToken
                        // message to the device selector, then don't consider this token as having
                        // been selected.
                        selector
                            .send(DeviceSelectorEvent::SelectedToken(dev.id()))
                            .is_ok()
                    }
                    BlinkResult::Cancelled => {
                        info!("Device {:?} was not selected", dev.id());
                        false
                    }
                }
            }
            Ok(DeviceCommand::Cancel) => {
                info!("Device {:?} was not selected", dev.id());
                false
            }
            Ok(DeviceCommand::Removed) => {
                info!("Device {:?} was removed", dev.id());
                false
            }
            Ok(DeviceCommand::Continue) => true,
            Err(_) => {
                warn!("Error when trying to receive messages from DeviceSelector! Exiting.");
                false
            }
        }
    }

    pub fn register(
        &mut self,
        timeout: u64,
        args: RegisterArgs,
        status: Sender<crate::StatusUpdate>,
        callback: StateCallback<crate::Result<crate::RegisterResult>>,
    ) {
        // Could the request be handled by a CTAP1 authenticator?
        let ctap2_only = {
            if let Err(e) = ctap2::check_ctap1_register_compatibility(&args) {
                if args.use_ctap1_fallback {
                    // There's no way a CTAP1 authenticator could approve this request, so cancel early.
                    callback.call(Err(e));
                    return;
                }

                true
            } else {
                false
            }
        };

        // Abort any prior register/sign calls and create a fresh cancellation
        // token, so this command cannot inherit state from a previous one.
        let token = self.begin_transaction();
        let mut guarded = token.guard(callback);
        // The observer runs exactly once when the terminal result is delivered.
        // It closes the token so any straggling thread of the finished
        // transaction can never commit another result either.
        guarded.add_uncloneable_observer(Box::new(move || token.cancel()));
        let cbc = guarded.clone();
        let transaction = Transaction::new(
            timeout,
            cbc.clone(),
            status,
            move |info, selector, status, alive| {
                let mut dev = match Self::init_device(info, &selector) {
                    Some(dev) => dev,
                    None => return,
                };

                if ctap2_only && !dev.supports_ctap2() {
                    // CTAP1-only authenticator with a CTAP2-only request.
                    let _ = selector.send(DeviceSelectorEvent::NotAToken(dev.id()));
                    return;
                }

                if args.use_ctap1_fallback && !dev.supports_ctap1() {
                    // CTAP2-only authenticator with a CTAP1-only request.
                    let _ = selector.send(DeviceSelectorEvent::NotAToken(dev.id()));
                    return;
                }

                if !Self::wait_for_device_selector(&mut dev, &selector, &status, alive) {
                    return;
                };

                if args.use_ctap1_fallback && dev.downgrade_to_ctap1().is_err() {
                    // We shouldn't reach this, but not downgrading early lets us use CTAP 2.1
                    // device selection on devices that support it.
                    let _ = selector.send(DeviceSelectorEvent::NotAToken(dev.id()));
                    return;
                }

                info!("Device {:?} continues with the register process", dev.id());
                if ctap2::register(&mut dev, args.clone(), status, cbc.clone(), alive) {
                    // ctap2::register returns true if it called the callback with Ok(..).  Cancel
                    // all other tokens in case we skipped the "blinking"-action and went straight
                    // for the actual request.
                    let _ = selector.send(DeviceSelectorEvent::SelectedToken(dev.id()));
                }
            },
        );

        self.transaction = Some(try_or!(transaction, |e| cbc.call(Err(e))));
    }

    pub fn sign(
        &mut self,
        timeout: u64,
        args: SignArgs,
        status: Sender<crate::StatusUpdate>,
        callback: StateCallback<crate::Result<crate::SignResult>>,
    ) {
        // Could the request be handled by a CTAP1 authenticator?
        let ctap2_only = {
            if let Err(e) = ctap2::check_ctap1_sign_compatibility(&args) {
                if args.use_ctap1_fallback {
                    // There's no way a CTAP1 authenticator could approve this request, so cancel early.
                    callback.call(Err(e));
                    return;
                }
                true
            } else {
                false
            }
        };

        // Abort any prior register/sign calls and create a fresh cancellation
        // token, so this command cannot inherit state from a previous one.
        let token = self.begin_transaction();
        let mut guarded = token.guard(callback);
        guarded.add_uncloneable_observer(Box::new(move || token.cancel()));
        let cbc = guarded.clone();

        let transaction = Transaction::new(
            timeout,
            cbc.clone(),
            status,
            move |info, selector, status, alive| {
                let mut dev = match Self::init_device(info, &selector) {
                    Some(dev) => dev,
                    None => return,
                };

                if ctap2_only && !dev.supports_ctap2() {
                    // CTAP1-only authenticator with a CTAP2-only request.
                    let _ = selector.send(DeviceSelectorEvent::NotAToken(dev.id()));
                    return;
                }

                if args.use_ctap1_fallback && !dev.supports_ctap1() {
                    // CTAP2-only authenticator with a CTAP1-only request.
                    let _ = selector.send(DeviceSelectorEvent::NotAToken(dev.id()));
                    return;
                }

                if !Self::wait_for_device_selector(&mut dev, &selector, &status, alive) {
                    return;
                };

                if args.use_ctap1_fallback && dev.downgrade_to_ctap1().is_err() {
                    // We shouldn't reach this, but not downgrading early lets us use CTAP 2.1
                    // device selection on devices that support it.
                    let _ = selector.send(DeviceSelectorEvent::NotAToken(dev.id()));
                    return;
                }

                info!("Device {:?} continues with the signing process", dev.id());
                if ctap2::sign(&mut dev, args.clone(), status, cbc.clone(), alive) {
                    // ctap2::sign returns true if it called the callback with Ok(..).  Cancel all
                    // other tokens in case we skipped the "blinking"-action and went straight for
                    // the actual request.
                    let _ = selector.send(DeviceSelectorEvent::SelectedToken(dev.id()));
                }
            },
        );

        self.transaction = Some(try_or!(transaction, move |e| cbc.call(Err(e))));
    }

    // This blocks.
    pub fn cancel(&mut self) {
        if let Some(token) = self.cancel_token.take() {
            // Flip the token before tearing the threads down, so any result that
            // is still in flight when the threads exit cannot be committed by the
            // guarded callback.
            token.cancel();
        }
        if let Some(mut transaction) = self.transaction.take() {
            info!("Statemachine was cancelled. Cancelling transaction now.");
            transaction.cancel();
        }
        // Defensive: make sure both fields are cleared regardless of which path
        // was taken.
        self.transaction = None;
        self.cancel_token = None;
    }

    pub fn reset(
        &mut self,
        timeout: u64,
        status: Sender<crate::StatusUpdate>,
        callback: StateCallback<crate::Result<crate::ResetResult>>,
    ) {
        // Abort any prior register/sign calls and create a fresh cancellation
        // token, so this command cannot inherit state from a previous one.
        let token = self.begin_transaction();
        let mut guarded = token.guard(callback);
        guarded.add_uncloneable_observer(Box::new(move || token.cancel()));
        let cbc = guarded.clone();

        let transaction = Transaction::new(
            timeout,
            cbc.clone(),
            status,
            move |info, selector, status, alive| {
                let mut dev = match Self::init_device(info, &selector) {
                    Some(dev) => dev,
                    None => return,
                };

                if dev.get_protocol() != FidoProtocol::CTAP2 {
                    info!("Device does not support CTAP2");
                    let _ = selector.send(DeviceSelectorEvent::NotAToken(dev.id()));
                    return;
                }

                if !Self::wait_for_device_selector(&mut dev, &selector, &status, alive) {
                    return;
                };
                ctap2::reset_helper(&mut dev, selector, status, cbc.clone(), alive);
            },
        );

        self.transaction = Some(try_or!(transaction, move |e| cbc.call(Err(e))));
    }

    pub fn set_pin(
        &mut self,
        timeout: u64,
        new_pin: Pin,
        status: Sender<crate::StatusUpdate>,
        callback: StateCallback<crate::Result<crate::ResetResult>>,
    ) {
        // Abort any prior register/sign calls and create a fresh cancellation
        // token, so this command cannot inherit state from a previous one.
        let token = self.begin_transaction();
        let mut guarded = token.guard(callback);
        guarded.add_uncloneable_observer(Box::new(move || token.cancel()));
        let cbc = guarded.clone();

        let transaction = Transaction::new(
            timeout,
            cbc.clone(),
            status,
            move |info, selector, status, alive| {
                let mut dev = match Self::init_device(info, &selector) {
                    Some(dev) => dev,
                    None => return,
                };

                if dev.get_protocol() != FidoProtocol::CTAP2 {
                    info!("Device does not support CTAP2");
                    let _ = selector.send(DeviceSelectorEvent::NotAToken(dev.id()));
                    return;
                }

                if !Self::wait_for_device_selector(&mut dev, &selector, &status, alive) {
                    return;
                };

                ctap2::set_or_change_pin_helper(
                    &mut dev,
                    None,
                    new_pin.clone(),
                    status,
                    cbc.clone(),
                    alive,
                );
            },
        );
        self.transaction = Some(try_or!(transaction, move |e| cbc.call(Err(e))));
    }

    // Function to interactively manage a specific token.
    // Difference to register/sign: These want to do something and don't care
    // with which token they do it.
    // This function wants to manipulate a specific token. For this, we first
    // have to select one and then do something with it, based on what it
    // supports (Set PIN, Change PIN, Reset, etc.).
    // Hence, we first go through the discovery-phase, then provide the user
    // with the AuthenticatorInfo and then let them interactively decide what to do
    pub fn manage(
        &mut self,
        timeout: u64,
        status: Sender<crate::StatusUpdate>,
        callback: StateCallback<crate::Result<crate::ManageResult>>,
    ) {
        // Abort any prior register/sign calls and create a fresh cancellation
        // token, so this command cannot inherit state from a previous one.
        let token = self.begin_transaction();
        let mut guarded = token.guard(callback);
        guarded.add_uncloneable_observer(Box::new(move || token.cancel()));
        let cbc = guarded.clone();

        let transaction = Transaction::new(
            timeout,
            cbc.clone(),
            status,
            move |info, selector, status, alive| {
                let mut dev = match Self::init_device(info, &selector) {
                    Some(dev) => dev,
                    None => return,
                };

                if dev.get_protocol() != FidoProtocol::CTAP2 {
                    info!("Device does not support CTAP2");
                    let _ = selector.send(DeviceSelectorEvent::NotAToken(dev.id()));
                    return;
                }

                if !Self::wait_for_device_selector(&mut dev, &selector, &status, alive) {
                    return;
                };

                info!("Device {:?} selected for interactive management.", dev.id());

                // Sending the user the info about the token
                let (tx, rx) = channel();
                send_status(
                    &status,
                    crate::StatusUpdate::InteractiveManagement(InteractiveUpdate::StartManagement(
                        (tx, dev.get_authenticator_info().cloned()),
                    )),
                );
                while alive() {
                    match rx.recv_timeout(Duration::from_millis(400)) {
                        Ok(InteractiveRequest::Quit) => {
                            cbc.call(Ok(ManageResult::Success));
                            break;
                        }
                        Ok(InteractiveRequest::Reset) => {
                            ctap2::reset_helper(
                                &mut dev,
                                selector,
                                status,
                                cbc.clone(),
                                alive,
                            );
                        }
                        Ok(InteractiveRequest::ChangePIN(curr_pin, new_pin)) => {
                            ctap2::set_or_change_pin_helper(
                                &mut dev,
                                Some(curr_pin),
                                new_pin,
                                status,
                                cbc.clone(),
                                alive,
                            );
                        }
                        Ok(InteractiveRequest::SetPIN(pin)) => {
                            ctap2::set_or_change_pin_helper(
                                &mut dev,
                                None,
                                pin,
                                status,
                                cbc.clone(),
                                alive,
                            );
                        }
                        Ok(InteractiveRequest::ChangeConfig(authcfg, puat)) => {
                            ctap2::configure_authenticator(
                                &mut dev,
                                puat,
                                authcfg,
                                status.clone(),
                                cbc.clone(),
                                alive,
                            );
                            continue;
                        }
                        Ok(InteractiveRequest::CredentialManagement(cred_management, puat)) => {
                            ctap2::credential_management(
                                &mut dev,
                                puat,
                                cred_management,
                                status.clone(),
                                cbc.clone(),
                                alive,
                            );
                            continue;
                        }
                        Ok(InteractiveRequest::BioEnrollment(bio_enrollment, puat)) => {
                            ctap2::bio_enrollment(
                                &mut dev,
                                puat,
                                bio_enrollment,
                                status.clone(),
                                cbc.clone(),
                                alive,
                            );
                            continue;
                        }
                        Err(RecvTimeoutError::Timeout) => {
                            if !alive() {
                                // We got stopped at some point
                                cbc.call(Err(AuthenticatorError::CancelledByUser));
                                break;
                            }
                            continue;
                        }
                        Err(RecvTimeoutError::Disconnected) => {
                            // recv() failed, because the other side is dropping the Sender.
                            info!(
                                "Callback dropped the channel, so we abort the interactive session"
                            );
                            cbc.call(Err(AuthenticatorError::CancelledByUser));
                        }
                    }
                    break;
                }
            },
        );

        self.transaction = Some(try_or!(transaction, move |e| cbc.call(Err(e))));
    }
}

#[cfg(test)]
mod tests {
    use super::{CancelToken, StateMachine};
    use crate::errors::AuthenticatorError;
    use crate::statecallback::StateCallback;
    use std::sync::mpsc;

    #[test]
    fn guarded_callback_passes_through_success_while_active() {
        // A legitimate register/sign/reset result must be preserved when no
        // cancellation happened.
        let (tx, rx) = mpsc::channel();
        let token = CancelToken::new();
        let callback = StateCallback::new(Box::new(move |rv| tx.send(rv).unwrap()));

        token
            .guard(callback)
            .call(Ok(42u32));

        assert_eq!(rx.recv().unwrap().unwrap(), 42);
    }

    #[test]
    fn guarded_callback_drops_late_success_after_cancel() {
        // Core cancellation race: the authenticator's success response arrives
        // after the transaction was cancelled. The late Ok must never reach the
        // caller; a CancelledByUser error is delivered instead.
        let (tx, rx) = mpsc::channel();
        let token = CancelToken::new();
        let callback = StateCallback::new(Box::new(move |rv| tx.send(rv).unwrap()));
        let guarded = token.guard(callback);

        token.cancel();
        guarded.call(Ok(42u32));

        match rx.recv().unwrap() {
            Err(AuthenticatorError::CancelledByUser) => {}
            other => panic!("expected CancelledByUser, got {other:?}"),
        }
    }

    #[test]
    fn guarded_callback_drops_late_error_after_cancel() {
        // A late error response is normalised to the same cancellation error,
        // so the final state after an abort never depends on response timing.
        let (tx, rx) = mpsc::channel();
        let token = CancelToken::new();
        let callback = StateCallback::new(Box::new(move |rv| tx.send(rv).unwrap()));
        let guarded = token.guard(callback);

        token.cancel();
        guarded.call(Err(AuthenticatorError::Platform));

        assert!(matches!(
            rx.recv().unwrap(),
            Err(AuthenticatorError::CancelledByUser)
        ));
    }

    #[test]
    fn guarded_callback_is_single_use_even_with_racing_threads() {
        // Whichever of cancel/success wins, exactly one terminal result is
        // delivered and every later attempt is a no-op.
        let (tx, rx) = mpsc::channel();
        let token = CancelToken::new();
        let callback = StateCallback::new(Box::new(move |rv| tx.send(rv).unwrap()));
        let guarded = token.guard(callback);
        let late_clone = guarded.clone();

        guarded.call(Ok(1u32));
        token.cancel();
        // Both the single-use semantics and the token would reject this, but the
        // important invariant is that no second result is ever delivered.
        late_clone.call(Ok(2u32));

        assert_eq!(rx.try_recv().unwrap().unwrap(), 1);
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn fresh_token_for_each_command_does_not_inherit_cancellation() {
        // Legal retry: a later command gets its own token. Cancelling one
        // transaction must not poison the next one's results.
        let first = CancelToken::new();
        first.cancel();
        assert!(first.is_cancelled());

        let second = CancelToken::new();
        assert!(!second.is_cancelled());

        let (tx, rx) = mpsc::channel();
        let callback = StateCallback::new(Box::new(move |rv| tx.send(rv).unwrap()));
        second.guard(callback).call(Ok("retry works"));
        assert_eq!(rx.recv().unwrap().unwrap(), "retry works");
    }

    #[test]
    fn cancel_without_transaction_is_idempotent_and_isolated() {
        // Repeated cancellation (including cancel before any command or after a
        // completed command) must leave the state machine in a well-defined,
        // empty state without panicking.
        let mut sm = StateMachine::new();
        sm.cancel();
        sm.cancel();

        assert!(sm.transaction.is_none());
        assert!(sm.cancel_token.is_none());
    }

    #[test]
    fn begin_transaction_rotates_the_cancel_token() {
        // Accessing the private pieces through the same module to prove that a
        // new command installs a fresh token and leaves no stale state behind.
        let mut sm = StateMachine::new();
        let first = sm.begin_transaction();
        first.cancel();

        // A new command must observe a brand new, non-cancelled token even
        // though the previous transaction was aborted.
        let second = sm.begin_transaction();
        assert!(!second.is_cancelled());
        assert!(sm.cancel_token.is_some());

        sm.cancel();
        assert!(sm.transaction.is_none());
        assert!(sm.cancel_token.is_none());
    }
}
