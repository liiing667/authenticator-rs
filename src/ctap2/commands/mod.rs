/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use crate::crypto::{CryptoError, PinUvAuthParam, PinUvAuthToken};
use crate::ctap2::commands::client_pin::{
    GetPinRetries, GetUvRetries, PinError, PinUvAuthTokenPermission,
};
use crate::ctap2::commands::get_info::AuthenticatorInfo;
use crate::ctap2::server::UserVerificationRequirement;
use crate::errors::AuthenticatorError;
use crate::transport::errors::{ApduErrorStatus, HIDError};
use crate::transport::{FidoDevice, VirtualFidoDevice};
#[cfg(test)]
use serde::Serialize;
use serde_cbor::{error::Error as CborError, Value};
use serde_json as json;
use std::error::Error as StdErrorT;
use std::fmt;

pub mod authenticator_config;
pub mod bio_enrollment;
pub mod client_pin;
pub mod credential_management;
pub mod get_assertion;
pub mod get_info;
pub mod get_next_assertion;
pub mod get_version;
pub mod large_blobs;
pub mod make_credentials;
pub mod reset;
pub mod selection;

/// Retryable wraps an error type and may ask manager to retry sending a
/// command, this is useful for ctap1 where token will reply with "condition not
/// sufficient" because user needs to press the button.
#[derive(Debug)]
pub enum Retryable<T> {
    Retry,
    Error(T),
}

impl<T> Retryable<T> {
    pub fn is_retry(&self) -> bool {
        matches!(*self, Retryable::Retry)
    }

    pub fn is_error(&self) -> bool {
        !self.is_retry()
    }
}

impl<T> From<T> for Retryable<T> {
    fn from(e: T) -> Self {
        Retryable::Error(e)
    }
}

pub trait RequestCtap1: fmt::Debug {
    type Output: CtapResponse;
    // E.g.: For GetAssertion, which key-handle is currently being tested
    type AdditionalInfo;

    /// Serializes a request into FIDO v1.x / CTAP1 / U2F format.
    ///
    /// See [`crate::u2ftypes::CTAP1RequestAPDU::serialize()`]
    fn ctap1_format(&self) -> Result<(Vec<u8>, Self::AdditionalInfo), HIDError>;

    /// Deserializes a response from FIDO v1.x / CTAP1 / U2Fv2 format.
    fn handle_response_ctap1<Dev: FidoDevice>(
        &self,
        dev: &mut Dev,
        status: Result<(), ApduErrorStatus>,
        input: &[u8],
        add_info: &Self::AdditionalInfo,
    ) -> Result<Self::Output, Retryable<HIDError>>;

    fn send_to_virtual_device<Dev: VirtualFidoDevice>(
        &self,
        dev: &mut Dev,
    ) -> Result<Self::Output, HIDError>;
}

pub trait RequestCtap2: fmt::Debug {
    type Output: CtapResponse;

    fn command(&self) -> Command;

    fn wire_format(&self) -> Result<Vec<u8>, HIDError>;

    fn handle_response_ctap2<Dev: FidoDevice>(
        &self,
        dev: &mut Dev,
        input: &[u8],
    ) -> Result<Self::Output, HIDError>;

    fn send_to_virtual_device<Dev: VirtualFidoDevice>(
        &self,
        dev: &mut Dev,
    ) -> Result<Self::Output, HIDError>;
}

// Sadly, needs to be 'static to enable us in tests to collect them in a Vec
// but all of them are 'static, so this is currently no problem.
pub trait CtapResponse: std::fmt::Debug + 'static {}

#[derive(Debug, Clone)]
pub enum PinUvAuthResult {
    /// Request is CTAP1 and does not need PinUvAuth
    RequestIsCtap1,
    /// Device is not capable of CTAP2
    DeviceIsCtap1,
    /// Device does not support UV or PINs
    NoAuthTypeSupported,
    /// Request doesn't want user verification (uv = "discouraged")
    NoAuthRequired,
    /// Device is CTAP2.0 and has internal UV capability
    UsingInternalUv,
    /// Successfully established PinUvAuthToken via GetPinToken (CTAP2.0)
    SuccessGetPinToken(PinUvAuthToken),
    /// Successfully established PinUvAuthToken via UV (CTAP2.1)
    SuccessGetPinUvAuthTokenUsingUvWithPermissions(PinUvAuthToken),
    /// Successfully established PinUvAuthToken via Pin (CTAP2.1)
    SuccessGetPinUvAuthTokenUsingPinWithPermissions(PinUvAuthToken),
}

impl PinUvAuthResult {
    pub(crate) fn get_pin_uv_auth_token(&self) -> Option<PinUvAuthToken> {
        match self {
            PinUvAuthResult::RequestIsCtap1
            | PinUvAuthResult::DeviceIsCtap1
            | PinUvAuthResult::NoAuthTypeSupported
            | PinUvAuthResult::NoAuthRequired
            | PinUvAuthResult::UsingInternalUv => None,
            PinUvAuthResult::SuccessGetPinToken(token) => Some(token.clone()),
            PinUvAuthResult::SuccessGetPinUvAuthTokenUsingUvWithPermissions(token) => {
                Some(token.clone())
            }
            PinUvAuthResult::SuccessGetPinUvAuthTokenUsingPinWithPermissions(token) => {
                Some(token.clone())
            }
        }
    }

    /// Check if this (potentially cached) result may be reused for the given
    /// command, and if so, return the pinUvAuthToken.
    ///
    /// The current command, the granted permissions and the UV-state all have
    /// to match. Otherwise the token must not be reused and a new one has to
    /// be established, e.g. after the previous command was cancelled or user
    /// verification failed.
    ///
    /// `permission` is the permission the current command requires and
    /// `skip_uv` indicates whether UV must not be used for it. Tokens that
    /// were obtained via internal UV are not reusable in that case.
    /// `permission_system` indicates whether the device supports the CTAP2.1
    /// permission system. Without it, permissions are meaningless and only
    /// the command-binding is enforced.
    pub(crate) fn get_reusable_pin_uv_auth_token(
        &self,
        command: &Command,
        permission: PinUvAuthTokenPermission,
        skip_uv: bool,
        permission_system: bool,
    ) -> Option<PinUvAuthToken> {
        match self {
            // CTAP2.0 pin tokens have no permissions and are not bound to a
            // specific command. They can only be reused if the device does
            // not support the CTAP2.1 permission system.
            PinUvAuthResult::SuccessGetPinToken(token) if !permission_system => Some(token.clone()),
            PinUvAuthResult::SuccessGetPinUvAuthTokenUsingPinWithPermissions(token)
                if token.is_valid_for(command, permission, permission_system) =>
            {
                Some(token.clone())
            }
            // Tokens obtained via internal UV must not be reused if UV is
            // not allowed for the current command, e.g. because UV got
            // blocked or the command requires a PIN-obtained token.
            PinUvAuthResult::SuccessGetPinUvAuthTokenUsingUvWithPermissions(token)
                if !skip_uv && token.is_valid_for(command, permission, permission_system) =>
            {
                Some(token.clone())
            }
            _ => None,
        }
    }
}

/// Helper-trait to determine pin_uv_auth_param from PIN or UV.
pub(crate) trait PinUvAuthCommand: RequestCtap2 {
    fn set_pin_uv_auth_param(
        &mut self,
        pin_uv_auth_token: Option<PinUvAuthToken>,
    ) -> Result<(), AuthenticatorError>;
    fn get_pin_uv_auth_param(&self) -> Option<&PinUvAuthParam>;
    fn set_uv_option(&mut self, uv: Option<bool>);
    fn get_rp_id(&self) -> Option<&String>;
    fn hmac_requested(&self) -> bool;
    fn can_skip_user_verification(
        &mut self,
        info: &AuthenticatorInfo,
        uv_req: UserVerificationRequirement,
    ) -> bool;
}

pub(crate) fn repackage_pin_errors<D: FidoDevice>(
    dev: &mut D,
    error: HIDError,
) -> AuthenticatorError {
    match error {
        HIDError::Command(CommandError::StatusCode(StatusCode::PinInvalid, _)) => {
            // If the given PIN was wrong, determine no. of left retries
            let cmd = GetPinRetries::new();
            // Treat any error as if the device returned a valid response without a pinRetries
            // field.
            let resp = dev.send_cbor(&cmd, None).unwrap_or_default();
            AuthenticatorError::PinError(PinError::InvalidPin(resp.pin_retries))
        }
        HIDError::Command(CommandError::StatusCode(StatusCode::PinAuthBlocked, _)) => {
            AuthenticatorError::PinError(PinError::PinAuthBlocked)
        }
        HIDError::Command(CommandError::StatusCode(StatusCode::PinBlocked, _)) => {
            AuthenticatorError::PinError(PinError::PinBlocked)
        }
        HIDError::Command(CommandError::StatusCode(StatusCode::PinRequired, _)) => {
            AuthenticatorError::PinError(PinError::PinRequired)
        }
        HIDError::Command(CommandError::StatusCode(StatusCode::PinNotSet, _)) => {
            AuthenticatorError::PinError(PinError::PinNotSet)
        }
        HIDError::Command(CommandError::StatusCode(StatusCode::PinAuthInvalid, _)) => {
            AuthenticatorError::PinError(PinError::PinAuthInvalid)
        }
        HIDError::Command(CommandError::StatusCode(StatusCode::UvInvalid, _)) => {
            // If the internal UV failed, determine no. of left retries
            let cmd = GetUvRetries::new();
            // Treat any error as if the device returned a valid response without a uvRetries
            // field.
            let resp = dev.send_cbor(&cmd, None).unwrap_or_default();
            AuthenticatorError::PinError(PinError::InvalidUv(resp.uv_retries))
        }
        HIDError::Command(CommandError::StatusCode(StatusCode::UvBlocked, _)) => {
            AuthenticatorError::PinError(PinError::UvBlocked)
        }
        // TODO(MS): Add "PinPolicyViolated"
        err => AuthenticatorError::HIDError(err),
    }
}

// Spec: https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticator-api
// and: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticator-api
#[repr(u8)]
#[derive(Debug, PartialEq, Clone)]
pub enum Command {
    MakeCredentials = 0x01,
    GetAssertion = 0x02,
    GetInfo = 0x04,
    ClientPin = 0x06,
    Reset = 0x07,
    GetNextAssertion = 0x08,
    BioEnrollment = 0x09,
    CredentialManagement = 0x0A,
    Selection = 0x0B,
    LargeBlobs = 0x0C,
    AuthenticatorConfig = 0x0D,
    BioEnrollmentPreview = 0x40,
    CredentialManagementPreview = 0x41,
}

#[derive(Debug)]
pub enum StatusCode {
    /// Indicates successful response.
    OK,
    /// The command is not a valid CTAP command.
    InvalidCommand,
    /// The command included an invalid parameter.
    InvalidParameter,
    /// Invalid message or item length.
    InvalidLength,
    /// Invalid message sequencing.
    InvalidSeq,
    /// Message timed out.
    Timeout,
    /// Channel busy.
    ChannelBusy,
    /// Command requires channel lock.
    LockRequired,
    /// Command not allowed on this cid.
    InvalidChannel,
    /// Invalid/unexpected CBOR error.
    CBORUnexpectedType,
    /// Error when parsing CBOR.
    InvalidCBOR,
    /// Missing non-optional parameter.
    MissingParameter,
    /// Limit for number of items exceeded.
    LimitExceeded,
    /// Unsupported extension.
    UnsupportedExtension,
    /// Valid credential found in the exclude list.
    CredentialExcluded,
    /// Processing (Lengthy operation is in progress).
    Processing,
    /// Credential not valid for the authenticator.
    InvalidCredential,
    /// Authentication is waiting for user interaction.
    UserActionPending,
    /// Processing, lengthy operation is in progress.
    OperationPending,
    /// No request is pending.
    NoOperations,
    /// Authenticator does not support requested algorithm.
    UnsupportedAlgorithm,
    /// Not authorized for requested operation.
    OperationDenied,
    /// Internal key storage is full.
    KeyStoreFull,
    /// No outstanding operations.
    NoOperationPending,
    /// Unsupported option.
    UnsupportedOption,
    /// Not a valid option for current operation.
    InvalidOption,
    /// Pending keep alive was cancelled.
    KeepaliveCancel,
    /// No valid credentials provided.
    NoCredentials,
    /// Timeout waiting for user interaction.
    UserActionTimeout,
    /// Continuation command, such as, authenticatorGetNextAssertion not
    /// allowed.
    NotAllowed,
    /// PIN Invalid.
    PinInvalid,
    /// PIN Blocked.
    PinBlocked,
    /// PIN authentication,pinAuth, verification failed.
    PinAuthInvalid,
    /// PIN authentication,pinAuth, blocked. Requires power recycle to reset.
    PinAuthBlocked,
    /// No PIN has been set.
    PinNotSet,
    /// PIN is required for the selected operation.
    PinRequired,
    /// PIN policy violation. Currently only enforces minimum length.
    PinPolicyViolation,
    /// pinToken expired on authenticator.
    PinTokenExpired,
    /// Authenticator cannot handle this request due to memory constraints.
    RequestTooLarge,
    /// The current operation has timed out.
    ActionTimeout,
    /// User presence is required for the requested operation.
    UpRequired,
    /// built-in user verification is disabled.
    UvBlocked,
    /// A checksum did not match.
    IntegrityFailure,
    /// The requested subcommand is either invalid or not implemented.
    InvalidSubcommand,
    /// built-in user verification unsuccessful. The platform SHOULD retry.
    UvInvalid,
    /// The permissions parameter contains an unauthorized permission.
    UnauthorizedPermission,
    /// Other unspecified error.
    Other,

    /// Unknown status.
    Unknown(u8),
}

impl StatusCode {
    fn is_ok(&self) -> bool {
        matches!(*self, StatusCode::OK)
    }

    fn device_busy(&self) -> bool {
        matches!(*self, StatusCode::ChannelBusy)
    }
}

impl From<u8> for StatusCode {
    fn from(value: u8) -> StatusCode {
        match value {
            0x00 => StatusCode::OK,
            0x01 => StatusCode::InvalidCommand,
            0x02 => StatusCode::InvalidParameter,
            0x03 => StatusCode::InvalidLength,
            0x04 => StatusCode::InvalidSeq,
            0x05 => StatusCode::Timeout,
            0x06 => StatusCode::ChannelBusy,
            0x0A => StatusCode::LockRequired,
            0x0B => StatusCode::InvalidChannel,
            0x11 => StatusCode::CBORUnexpectedType,
            0x12 => StatusCode::InvalidCBOR,
            0x14 => StatusCode::MissingParameter,
            0x15 => StatusCode::LimitExceeded,
            0x16 => StatusCode::UnsupportedExtension,
            0x19 => StatusCode::CredentialExcluded,
            0x21 => StatusCode::Processing,
            0x22 => StatusCode::InvalidCredential,
            0x23 => StatusCode::UserActionPending,
            0x24 => StatusCode::OperationPending,
            0x25 => StatusCode::NoOperations,
            0x26 => StatusCode::UnsupportedAlgorithm,
            0x27 => StatusCode::OperationDenied,
            0x28 => StatusCode::KeyStoreFull,
            0x2A => StatusCode::NoOperationPending,
            0x2B => StatusCode::UnsupportedOption,
            0x2C => StatusCode::InvalidOption,
            0x2D => StatusCode::KeepaliveCancel,
            0x2E => StatusCode::NoCredentials,
            0x2f => StatusCode::UserActionTimeout,
            0x30 => StatusCode::NotAllowed,
            0x31 => StatusCode::PinInvalid,
            0x32 => StatusCode::PinBlocked,
            0x33 => StatusCode::PinAuthInvalid,
            0x34 => StatusCode::PinAuthBlocked,
            0x35 => StatusCode::PinNotSet,
            0x36 => StatusCode::PinRequired,
            0x37 => StatusCode::PinPolicyViolation,
            0x38 => StatusCode::PinTokenExpired,
            0x39 => StatusCode::RequestTooLarge,
            0x3A => StatusCode::ActionTimeout,
            0x3B => StatusCode::UpRequired,
            0x3C => StatusCode::UvBlocked,
            0x3D => StatusCode::IntegrityFailure,
            0x3E => StatusCode::InvalidSubcommand,
            0x3F => StatusCode::UvInvalid,
            0x40 => StatusCode::UnauthorizedPermission,
            0x7F => StatusCode::Other,
            othr => StatusCode::Unknown(othr),
        }
    }
}

#[cfg(test)]
impl From<StatusCode> for u8 {
    fn from(v: StatusCode) -> u8 {
        match v {
            StatusCode::OK => 0x00,
            StatusCode::InvalidCommand => 0x01,
            StatusCode::InvalidParameter => 0x02,
            StatusCode::InvalidLength => 0x03,
            StatusCode::InvalidSeq => 0x04,
            StatusCode::Timeout => 0x05,
            StatusCode::ChannelBusy => 0x06,
            StatusCode::LockRequired => 0x0A,
            StatusCode::InvalidChannel => 0x0B,
            StatusCode::CBORUnexpectedType => 0x11,
            StatusCode::InvalidCBOR => 0x12,
            StatusCode::MissingParameter => 0x14,
            StatusCode::LimitExceeded => 0x15,
            StatusCode::UnsupportedExtension => 0x16,
            StatusCode::CredentialExcluded => 0x19,
            StatusCode::Processing => 0x21,
            StatusCode::InvalidCredential => 0x22,
            StatusCode::UserActionPending => 0x23,
            StatusCode::OperationPending => 0x24,
            StatusCode::NoOperations => 0x25,
            StatusCode::UnsupportedAlgorithm => 0x26,
            StatusCode::OperationDenied => 0x27,
            StatusCode::KeyStoreFull => 0x28,
            StatusCode::NoOperationPending => 0x2A,
            StatusCode::UnsupportedOption => 0x2B,
            StatusCode::InvalidOption => 0x2C,
            StatusCode::KeepaliveCancel => 0x2D,
            StatusCode::NoCredentials => 0x2E,
            StatusCode::UserActionTimeout => 0x2f,
            StatusCode::NotAllowed => 0x30,
            StatusCode::PinInvalid => 0x31,
            StatusCode::PinBlocked => 0x32,
            StatusCode::PinAuthInvalid => 0x33,
            StatusCode::PinAuthBlocked => 0x34,
            StatusCode::PinNotSet => 0x35,
            StatusCode::PinRequired => 0x36,
            StatusCode::PinPolicyViolation => 0x37,
            StatusCode::PinTokenExpired => 0x38,
            StatusCode::RequestTooLarge => 0x39,
            StatusCode::ActionTimeout => 0x3A,
            StatusCode::UpRequired => 0x3B,
            StatusCode::UvBlocked => 0x3C,
            StatusCode::IntegrityFailure => 0x3D,
            StatusCode::InvalidSubcommand => 0x3E,
            StatusCode::UvInvalid => 0x3F,
            StatusCode::UnauthorizedPermission => 0x40,
            StatusCode::Other => 0x7F,

            StatusCode::Unknown(othr) => othr,
        }
    }
}

#[derive(Debug)]
pub enum CommandError {
    InputTooSmall,
    MissingRequiredField(&'static str),
    Deserializing(CborError),
    Serializing(CborError),
    StatusCode(StatusCode, Option<Value>),
    Json(json::Error),
    Crypto(CryptoError),
    UnsupportedPinProtocol,
}

impl fmt::Display for CommandError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            CommandError::InputTooSmall => write!(f, "CommandError: Input is too small"),
            CommandError::MissingRequiredField(field) => {
                write!(f, "CommandError: Missing required field {field}")
            }
            CommandError::Deserializing(ref e) => {
                write!(f, "CommandError: Error while parsing: {e}")
            }
            CommandError::Serializing(ref e) => {
                write!(f, "CommandError: Error while serializing: {e}")
            }
            CommandError::StatusCode(ref code, ref value) => {
                write!(f, "CommandError: Unexpected code: {code:?} ({value:?})")
            }
            CommandError::Json(ref e) => write!(f, "CommandError: Json serializing error: {e}"),
            CommandError::Crypto(ref e) => write!(f, "CommandError: Crypto error: {e:?}"),
            CommandError::UnsupportedPinProtocol => {
                write!(f, "CommandError: Pin protocol is not supported")
            }
        }
    }
}

impl StdErrorT for CommandError {}

#[cfg(test)]
/// Asserts that a value encodes to [canonical CBOR encoding according to CTAP2.1 spec][0].
///
/// [0]: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#ctap2-canonical-cbor-encoding-form
fn assert_canonical_cbor_encoding<T: Serialize + fmt::Debug>(value: &T) {
    let bytes = serde_cbor::to_vec(value)
        .unwrap_or_else(|e| panic!("Failed to serialize value {:?}: {}", value, e));
    let opaque_value: serde_cbor::Value = serde_cbor::from_slice(&bytes)
        .unwrap_or_else(|e| panic!("Failed to deserialize value {:?}: {}", value, e));

    // Below, each requirement is first quoted from the spec and then tested (or explained why testing is not necessary):

    // > Integers MUST be encoded as small as possible.
    // > - 0 to 23 and -1 to -24 MUST be expressed in the same byte as the major type;
    // > - 24 to 255 and -25 to -256 MUST be expressed only with an additional uint8_t;
    // > - 256 to 65535 and -257 to -65536 MUST be expressed only with an additional uint16_t;
    // > - 65536 to 4294967295 and -65537 to -4294967296 MUST be expressed only with an additional uint32_t.
    // serde_cbor handles this as required, see https://github.com/pyfisch/cbor/blob/master/src/ser.rs#L140-L182

    // > The representations of any floating-point values are not changed.
    // > Note: The size of a floating point value—16-, 32-, or 64-bits—is considered part of the value for the purpose of CTAP2. E.g., a 16-bit value of 1.5, say, has different semantic meaning than a 32-bit value of 1.5, and both can be canonical for their own meanings.
    // serde_cbor won't change u32 to u64 by itself, so this is fine, too

    // > The expression of lengths in major types 2 through 5 MUST be as short as possible. The rules for these lengths follow the above rule for integers.
    // See above -- serde_cbor handles this for us.

    // > Indefinite-length items MUST be made into definite-length items.
    // serde_cbor might serialize with indefinite length if serde doesn't know the length when beginning to serialize an array/a map.
    // We use a trick here: serde_cbor::Value manages arrays/maps as `Array`/`Map`. Both of these have iterators implementing `ExactIterator`, so serde_cbor does not serialize them with indefinite length (unless the length is larger than usize max value, which shouldn't happen in practice). So, just re-serialize and compare with the result of the first serialization.

    let bytes_after_reserializing = serde_cbor::to_vec(&opaque_value)
        .unwrap_or_else(|e| panic!("Failed to reserialize value {:?}: {}", opaque_value, e));
    assert_eq!(bytes, bytes_after_reserializing, "Bytes aren't equal before and after reserializing, value is probably not in CTAP2 canonical CBOR encoding form");

    // > The keys in every map MUST be sorted lowest value to highest. The sorting rules are:
    // > - If the major types are different, the one with the lower value in numerical order sorts earlier.
    // > - If two keys have different lengths, the shorter one sorts earlier;
    // > - If two keys have different lengths, the shorter one sorts earlier;
    // > - If two keys have the same length, the one with the lower value in (byte-wise) lexical order sorts earlier.
    // This is equivalent to the CBOR core canonicalization requirements (https://datatracker.ietf.org/doc/html/draft-ietf-cbor-7049bis-04#section-4.10), which is how the BTReeMap is sorted. Therefore, the reserialization trick from above also handles this case.

    /// > Tags as defined in [Section 2.4) in RFC8949][1] MUST NOT be present.
    /// [1]: https://www.rfc-editor.org/rfc/rfc8949.html#name-tagging-of-items
    fn assert_has_no_tags(value: &serde_cbor::Value) {
        match value {
                serde_cbor::Value::Array(vec) => {
                    for entry in vec {
                        assert_has_no_tags(entry);
                    }
                }
                serde_cbor::Value::Map(map) => {
                    for (key, entry) in map {
                        assert_has_no_tags(key);
                        assert_has_no_tags(entry);
                    }
                }
                serde_cbor::Value::Tag(tag, value) => panic!(
                    "Tags are not allowed inside canonical CBOR encoding, but found tag {} on value {:?}",
                    tag, value
                ),
                _ => {},
            }
    }

    assert_has_no_tags(&opaque_value);
}

#[cfg(test)]
mod tests {
    use super::{Command, PinUvAuthResult, PinUvAuthToken, PinUvAuthTokenPermission};

    fn token(
        pin_protocol: u64,
        permissions: PinUvAuthTokenPermission,
        command: Command,
    ) -> PinUvAuthToken {
        PinUvAuthToken::create_test(pin_protocol, permissions, Some(command))
    }

    #[test]
    fn reusable_pin_token_for_same_command() {
        // PIN protocol 1 and 2, obtained via PIN: reusable for the same
        // command with sufficient permissions.
        for protocol in [1, 2] {
            let result = PinUvAuthResult::SuccessGetPinUvAuthTokenUsingPinWithPermissions(token(
                protocol,
                PinUvAuthTokenPermission::BioEnrollment,
                Command::BioEnrollment,
            ));
            assert!(result
                .get_reusable_pin_uv_auth_token(
                    &Command::BioEnrollment,
                    PinUvAuthTokenPermission::BioEnrollment,
                    false,
                    true,
                )
                .is_some());
        }
    }

    #[test]
    fn reusable_uv_token_for_same_command() {
        // PIN protocol 1 and 2, obtained via UV: reusable for the same
        // command, if UV is still allowed.
        for protocol in [1, 2] {
            let result = PinUvAuthResult::SuccessGetPinUvAuthTokenUsingUvWithPermissions(token(
                protocol,
                PinUvAuthTokenPermission::CredentialManagement,
                Command::CredentialManagement,
            ));
            assert!(result
                .get_reusable_pin_uv_auth_token(
                    &Command::CredentialManagement,
                    PinUvAuthTokenPermission::CredentialManagement,
                    false,
                    true,
                )
                .is_some());
        }
    }

    #[test]
    fn not_reusable_for_different_command() {
        // A token obtained for one command must not be reused for another,
        // even if the permissions would be sufficient.
        let result = PinUvAuthResult::SuccessGetPinUvAuthTokenUsingPinWithPermissions(token(
            2,
            PinUvAuthTokenPermission::MakeCredential | PinUvAuthTokenPermission::GetAssertion,
            Command::MakeCredentials,
        ));
        assert!(result
            .get_reusable_pin_uv_auth_token(
                &Command::GetAssertion,
                PinUvAuthTokenPermission::GetAssertion,
                false,
                true,
            )
            .is_none());
        // But it is reusable for the command it was obtained for.
        assert!(result
            .get_reusable_pin_uv_auth_token(
                &Command::MakeCredentials,
                PinUvAuthTokenPermission::MakeCredential,
                false,
                true,
            )
            .is_some());
    }

    #[test]
    fn not_reusable_with_insufficient_permissions() {
        let result = PinUvAuthResult::SuccessGetPinUvAuthTokenUsingPinWithPermissions(token(
            1,
            PinUvAuthTokenPermission::GetAssertion,
            Command::BioEnrollment,
        ));
        assert!(result
            .get_reusable_pin_uv_auth_token(
                &Command::BioEnrollment,
                PinUvAuthTokenPermission::BioEnrollment,
                false,
                true,
            )
            .is_none());
    }

    #[test]
    fn uv_token_not_reusable_when_skipping_uv() {
        // After UV failed or got blocked, a token obtained via UV must not
        // be reused. A token obtained via PIN is still fine.
        let uv_result = PinUvAuthResult::SuccessGetPinUvAuthTokenUsingUvWithPermissions(token(
            2,
            PinUvAuthTokenPermission::BioEnrollment,
            Command::BioEnrollment,
        ));
        assert!(uv_result
            .get_reusable_pin_uv_auth_token(
                &Command::BioEnrollment,
                PinUvAuthTokenPermission::BioEnrollment,
                true,
                true,
            )
            .is_none());
        let pin_result = PinUvAuthResult::SuccessGetPinUvAuthTokenUsingPinWithPermissions(token(
            2,
            PinUvAuthTokenPermission::BioEnrollment,
            Command::BioEnrollment,
        ));
        assert!(pin_result
            .get_reusable_pin_uv_auth_token(
                &Command::BioEnrollment,
                PinUvAuthTokenPermission::BioEnrollment,
                true,
                true,
            )
            .is_some());
    }

    #[test]
    fn ctap20_pin_token_only_reusable_without_permission_system() {
        let result = PinUvAuthResult::SuccessGetPinToken(token(
            1,
            PinUvAuthTokenPermission::default(),
            Command::MakeCredentials,
        ));
        // CTAP2.0 tokens have no permissions and are not command-bound, so
        // they can be reused for any command if the device has no permission
        // system ...
        assert!(result
            .get_reusable_pin_uv_auth_token(
                &Command::BioEnrollment,
                PinUvAuthTokenPermission::BioEnrollment,
                false,
                false,
            )
            .is_some());
        // ... but not on CTAP2.1 devices, where the default mc|ga
        // permissions are insufficient for other commands.
        assert!(result
            .get_reusable_pin_uv_auth_token(
                &Command::BioEnrollment,
                PinUvAuthTokenPermission::BioEnrollment,
                false,
                true,
            )
            .is_none());
    }

    #[test]
    fn untagged_token_not_reusable() {
        // Tokens that are not bound to a command must not be reused.
        let result = PinUvAuthResult::SuccessGetPinUvAuthTokenUsingPinWithPermissions(
            PinUvAuthToken::create_test(1, PinUvAuthTokenPermission::BioEnrollment, None),
        );
        assert!(result
            .get_reusable_pin_uv_auth_token(
                &Command::BioEnrollment,
                PinUvAuthTokenPermission::BioEnrollment,
                false,
                true,
            )
            .is_none());
    }

    #[test]
    fn non_token_results_not_reusable() {
        for result in [
            PinUvAuthResult::RequestIsCtap1,
            PinUvAuthResult::DeviceIsCtap1,
            PinUvAuthResult::NoAuthTypeSupported,
            PinUvAuthResult::NoAuthRequired,
            PinUvAuthResult::UsingInternalUv,
        ] {
            assert!(result
                .get_reusable_pin_uv_auth_token(
                    &Command::BioEnrollment,
                    PinUvAuthTokenPermission::BioEnrollment,
                    false,
                    false,
                )
                .is_none());
        }
    }

    #[test]
    fn permissions_ignored_without_permission_system() {
        // On CTAP2.0 / 2.1-preview devices there is no permission system,
        // only the command-binding is enforced.
        let result = PinUvAuthResult::SuccessGetPinUvAuthTokenUsingPinWithPermissions(token(
            1,
            PinUvAuthTokenPermission::empty(),
            Command::BioEnrollmentPreview,
        ));
        assert!(result
            .get_reusable_pin_uv_auth_token(
                &Command::BioEnrollmentPreview,
                PinUvAuthTokenPermission::BioEnrollment,
                false,
                false,
            )
            .is_some());
        assert!(result
            .get_reusable_pin_uv_auth_token(
                &Command::CredentialManagementPreview,
                PinUvAuthTokenPermission::CredentialManagement,
                false,
                false,
            )
            .is_none());
    }
}
