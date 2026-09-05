mod network_error;
mod proxy;
pub mod webapi;

#[cfg(test)]
mod tests;

pub use network_error::{NetworkError, NetworkErrorKind, RequestSent};
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

#[derive(thiserror::Error)]
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
	#[error("Unexpected error when transport was making request")]
	Unknown(#[from] anyhow::Error),
}

impl std::fmt::Debug for TransportError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::NetworkFailure(error) => f.debug_tuple("NetworkFailure").field(error).finish(),
			Self::HeaderParseFailure { .. } => f.write_str("HeaderParseFailure([REDACTED])"),
			Self::ProtobufError(_) => f.write_str("ProtobufError([REDACTED])"),
			Self::Unauthorized => f.write_str("Unauthorized"),
			Self::Unknown(_) => f.write_str("Unknown([REDACTED])"),
		}
	}
}

impl From<reqwest::Error> for TransportError {
	fn from(error: reqwest::Error) -> Self {
		Self::NetworkFailure(error.into())
	}
}
