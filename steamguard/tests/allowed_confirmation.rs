use protobuf::{Message, MessageFull};
use steamguard::{
	protobufs::steammessages_auth_steamclient::{
		CAuthentication_AllowedConfirmation, CAuthentication_BeginAuthSessionViaQR_Request,
		CAuthentication_BeginAuthSessionViaQR_Response, EAuthSessionGuardType,
		EAuthTokenPlatformType,
	},
	steamapi::{ApiRequest, ApiResponse, BuildableRequest, EResult},
	transport::{Transport, TransportError},
	DeviceDetails, UserLogin,
};

#[derive(Clone)]
struct SyntheticQrTransport(CAuthentication_BeginAuthSessionViaQR_Response);

impl Transport for SyntheticQrTransport {
	fn send_request<Req: BuildableRequest + MessageFull, Res: MessageFull>(
		&self,
		_req: ApiRequest<Req>,
	) -> Result<ApiResponse<Res>, TransportError> {
		assert_eq!(
			Req::descriptor(),
			CAuthentication_BeginAuthSessionViaQR_Request::descriptor()
		);
		assert_eq!(
			Res::descriptor(),
			CAuthentication_BeginAuthSessionViaQR_Response::descriptor()
		);
		let response = Res::parse_from_bytes(&self.0.write_to_bytes()?)?;
		Ok(ApiResponse::new(EResult::OK, None, response))
	}

	fn close(&mut self) {}
}

#[test]
fn allowed_confirmation_is_public() {
	let expected = [
		(
			EAuthSessionGuardType::k_EAuthSessionGuardType_DeviceConfirmation,
			"Synthetic device approval",
		),
		(
			EAuthSessionGuardType::k_EAuthSessionGuardType_EmailConfirmation,
			"Synthetic email approval",
		),
	];
	let mut response = CAuthentication_BeginAuthSessionViaQR_Response::new();
	response.set_client_id(123);
	response.set_request_id(b"request-id-canary".to_vec());
	response.set_challenge_url("challenge-url-canary".to_owned());
	for (confirmation_type, message) in expected {
		let mut confirmation = CAuthentication_AllowedConfirmation::new();
		confirmation.set_confirmation_type(confirmation_type);
		confirmation.set_associated_message(message.to_owned());
		response.allowed_confirmations.push(confirmation);
	}
	let mut login = UserLogin::new(
		SyntheticQrTransport(response),
		DeviceDetails {
			friendly_name: "Synthetic login test".to_owned(),
			platform_type: EAuthTokenPlatformType::k_EAuthTokenPlatformType_MobileApp,
			os_type: 0,
			gaming_device_type: 0,
		},
	);

	let response = login.begin_auth_via_qr().unwrap();
	let confirmations: &[steamguard::AllowedConfirmation] = response.confirmation_methods();
	assert_eq!(confirmations.len(), expected.len());
	for (confirmation, (confirmation_type, message)) in confirmations.iter().zip(expected) {
		assert_eq!(confirmation.confirmation_type, confirmation_type);
		assert_eq!(confirmation.associated_messsage, message);
	}
}
