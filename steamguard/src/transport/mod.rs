mod network_error;
mod proxy;
pub mod webapi;

pub use network_error::{NetworkError, NetworkErrorKind};
use protobuf::MessageFull;
pub use proxy::{ProxyConfig, ProxyConfigError, ProxyTransportError};
pub use webapi::{WebApiTransport, WebEndpoint, WebRequest, WebResponse};

use crate::steamapi::{ApiRequest, ApiResponse, BuildableRequest};

pub trait Transport {
	fn send_request<Req: BuildableRequest + MessageFull, Res: MessageFull>(
		&self,
		req: ApiRequest<Req>,
	) -> Result<ApiResponse<Res>, TransportError>;

	fn send_web(&self, request: WebRequest<'_>) -> Result<WebResponse, NetworkError> {
		let client = self
			.innner_http_client()
			.map_err(|_| NetworkError::unsupported_transport())?;
		webapi::send_web(&client, request)
	}

	fn close(&mut self);

	fn innner_http_client(&self) -> anyhow::Result<reqwest::blocking::Client> {
		bail!("Transport does not support extracting HTTP client")
	}
}

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
	#[error("Transport failed to parse response headers")]
	HeaderParseFailure {
		header: String,
		#[source]
		source: anyhow::Error,
	},
	#[error("Transport failed to parse response body")]
	ProtobufError(#[from] protobuf::Error),
	#[error("Unauthorized: Access token is missing or invalid")]
	Unauthorized,
	#[error("NetworkFailure: Transport failed to make request: {0}")]
	NetworkFailure(#[from] NetworkError),
	#[error("Unexpected error when transport was making request: {0}")]
	Unknown(#[from] anyhow::Error),
}

impl From<reqwest::Error> for TransportError {
	fn from(error: reqwest::Error) -> Self {
		Self::NetworkFailure(error.into())
	}
}
