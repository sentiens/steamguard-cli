use std::{borrow::Cow, fmt, io::Read, time::Duration};

use log::{debug, trace};
use protobuf::MessageFull;
use reqwest::{
	blocking::{multipart::Form, RequestBuilder},
	header::{ACCEPT_LANGUAGE, CONTENT_TYPE, COOKIE, ORIGIN, USER_AGENT},
	Url,
};

use super::{NetworkError, ProxyConfig, ProxyTransportError, Transport, TransportError};
use crate::{
	endpoints,
	steamapi::{ApiRequest, ApiResponse, BuildableRequest, EResult},
};

/// Records local DNS requests and refuses every resolution, without querying DNS.
///
/// Clones share the recording. Literal IP addresses bypass reqwest's resolver and can
/// still connect; use a loopback proxy stand when testing remote destination resolution.
#[cfg(feature = "test-endpoints")]
#[derive(Clone, Default)]
pub struct RecordingResolver {
	names: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
}

#[cfg(feature = "test-endpoints")]
impl RecordingResolver {
	pub fn new() -> Self {
		Self::default()
	}

	/// Returns a snapshot in lookup order. This deliberately exposes recorded hostnames.
	pub fn names(&self) -> Vec<String> {
		self.names.lock().unwrap().clone()
	}
}

#[cfg(feature = "test-endpoints")]
impl fmt::Debug for RecordingResolver {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("RecordingResolver")
			.field("names", &"[REDACTED]")
			.finish()
	}
}

#[cfg(feature = "test-endpoints")]
impl reqwest::dns::Resolve for RecordingResolver {
	fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
		self.names.lock().unwrap().push(name.as_str().to_owned());
		Box::pin(std::future::ready(Err(Box::new(std::io::Error::other(
			"test resolver refused resolution",
		)) as _)))
	}
}

#[cfg(feature = "test-endpoints")]
struct TestResolver(std::sync::Arc<dyn reqwest::dns::Resolve>);

#[cfg(feature = "test-endpoints")]
impl reqwest::dns::Resolve for TestResolver {
	fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
		self.0.resolve(name)
	}
}

#[derive(Clone)]
pub struct WebApiTransport {
	client: reqwest::blocking::Client,
	bounded_responses: bool,
	#[cfg(feature = "test-endpoints")]
	proxy_host_ip: Option<std::net::IpAddr>,
}

impl fmt::Debug for WebApiTransport {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("WebApiTransport")
			.field("client", &"[REDACTED]")
			.finish()
	}
}

impl WebApiTransport {
	pub fn new(client: reqwest::blocking::Client) -> Self {
		Self {
			client,
			bounded_responses: false,
			// An externally built client's proxy configuration cannot be inspected.
			#[cfg(feature = "test-endpoints")]
			proxy_host_ip: None,
		}
	}

	/// Creates a transport whose requests are routed through `proxy`.
	///
	/// Create one transport per account when accounts require different proxy routes. Use
	/// [`WebApiTransport::new`] to retain the existing client construction behavior when no proxy is
	/// required.
	pub fn new_with_proxy(proxy: &ProxyConfig) -> Result<Self, ProxyTransportError> {
		let builder = Self::proxy_client_builder(proxy)?;
		#[cfg(feature = "test-endpoints")]
		let builder = match &proxy.test_resolver {
			Some(resolver) => builder.dns_resolver(std::sync::Arc::new(TestResolver(
				std::sync::Arc::clone(resolver),
			))),
			None => builder,
		};
		Self::from_proxy_client(
			builder.build(),
			#[cfg(feature = "test-endpoints")]
			proxy.host_ip(),
		)
	}

	/// Installs a recording, always-failing resolver on the approved proxy factory path.
	///
	/// HTTP, HTTPS and socks5h proxies resolve destination names remotely. Named proxy
	/// hosts are resolved locally and will fail here. Literal proxy IPs can still connect.
	#[cfg(feature = "test-endpoints")]
	pub fn new_with_proxy_and_recording_resolver(
		proxy: &ProxyConfig,
		resolver: &RecordingResolver,
	) -> Result<Self, ProxyTransportError> {
		Self::new_with_proxy_and_test_resolver(proxy, std::sync::Arc::new(resolver.clone()))
	}

	/// Constructs the approved proxy client with a resolver spy for offline tests.
	///
	/// Available only with `test-endpoints`; the resolver is the only policy override.
	#[cfg(feature = "test-endpoints")]
	pub fn new_with_proxy_and_test_resolver<R: reqwest::dns::Resolve + 'static>(
		proxy: &ProxyConfig,
		resolver: std::sync::Arc<R>,
	) -> Result<Self, ProxyTransportError> {
		let mut proxy = proxy.clone();
		proxy.test_resolver = Some(resolver);
		Self::new_with_proxy(&proxy)
	}

	// The single reviewed construction policy for all proxy entry points.
	fn proxy_client_builder(
		proxy: &ProxyConfig,
	) -> Result<reqwest::blocking::ClientBuilder, ProxyTransportError> {
		let proxy = proxy.to_reqwest_proxy()?;
		Ok(reqwest::blocking::Client::builder()
			.no_proxy()
			.proxy(proxy)
			.use_rustls_tls()
			.tls_built_in_root_certs(false)
			.tls_built_in_webpki_certs(true)
			.redirect(reqwest::redirect::Policy::none())
			.retry(reqwest::retry::never())
			.connect_timeout(Duration::from_secs(10))
			.timeout(Duration::from_secs(30))
			.cookie_store(false)
			// Read compressed bytes within a budget before decoding them ourselves.
			.no_gzip()
			.no_brotli()
			.no_zstd()
			.no_deflate())
	}

	fn from_proxy_client(
		client: Result<reqwest::blocking::Client, reqwest::Error>,
		#[cfg(feature = "test-endpoints")] proxy_host_ip: Option<std::net::IpAddr>,
	) -> Result<Self, ProxyTransportError> {
		Ok(Self {
			client: client.map_err(|_| ProxyTransportError::ClientBuild)?,
			bounded_responses: true,
			#[cfg(feature = "test-endpoints")]
			proxy_host_ip,
		})
	}
}

// A service base must be HTTP(S), with either a literal loopback destination or
// a literal loopback proxy from the approved client factory. Validation never
// resolves names or rereads proxy environment variables.
#[cfg(feature = "test-endpoints")]
fn require_loopback_route(
	url: &Url,
	proxy_host_ip: Option<std::net::IpAddr>,
) -> Result<(), NetworkError> {
	if matches!(url.scheme(), "http" | "https") && proxy_host_ip.is_some_and(|ip| ip.is_loopback())
	{
		return Ok(());
	}
	require_loopback_base(url)
}

#[cfg(feature = "test-endpoints")]
pub(super) fn require_loopback_base(url: &Url) -> Result<(), NetworkError> {
	let loopback = url
		.host_str()
		.and_then(|host| {
			host.trim_matches(['[', ']'])
				.parse::<std::net::IpAddr>()
				.ok()
		})
		.is_some_and(|ip| ip.is_loopback());
	if !loopback || !matches!(url.scheme(), "http" | "https") {
		return Err(NetworkError::invalid_request());
	}
	Ok(())
}

fn build_web_request(
	client: &reqwest::blocking::Client,
	request: WebRequest<'_>,
) -> Result<RequestBuilder, NetworkError> {
	let method = if request.form_body.is_some() {
		reqwest::Method::POST
	} else {
		reqwest::Method::GET
	};
	let mut builder = client
		.request(method, request.endpoint.url()?)
		.header(USER_AGENT, request.user_agent)
		.header(COOKIE, request.cookie)
		.header(ACCEPT_LANGUAGE, request.accept_language)
		.query(request.query);
	if let Some(origin) = request.origin {
		builder = builder.header(ORIGIN, origin);
	}
	if let Some(body) = request.form_body {
		builder = builder
			.header(
				CONTENT_TYPE,
				"application/x-www-form-urlencoded; charset=UTF-8",
			)
			.body(body.to_owned());
	}
	Ok(builder)
}

pub(crate) fn send_web(
	client: &reqwest::blocking::Client,
	request: WebRequest<'_>,
) -> Result<WebResponse, NetworkError> {
	send_web_with_limits(
		client,
		request,
		false,
		#[cfg(feature = "test-endpoints")]
		None,
	)
}

fn send(
	request: RequestBuilder,
	approved: bool,
) -> Result<reqwest::blocking::Response, NetworkError> {
	let (client, request) = request.build_split();
	let request = request.map_err(NetworkError::from_request_build)?;
	client.execute(request).map_err(|error| {
		if approved {
			NetworkError::from_approved_send(error)
		} else {
			NetworkError::from(error)
		}
	})
}

fn send_web_with_limits(
	client: &reqwest::blocking::Client,
	request: WebRequest<'_>,
	bounded: bool,
	#[cfg(feature = "test-endpoints")] proxy_host_ip: Option<std::net::IpAddr>,
) -> Result<WebResponse, NetworkError> {
	#[cfg(feature = "test-endpoints")]
	if !matches!(request.endpoint, WebEndpoint::Test(_)) {
		require_loopback_route(
			&Url::parse(endpoints::community_base_url())
				.map_err(|_| NetworkError::invalid_request())?,
			proxy_host_ip,
		)?;
	}
	let endpoint = request.endpoint.name();
	let response = send(build_web_request(client, request)?, bounded)?;
	let status = response.status().as_u16();
	debug!("Web request completed: endpoint={endpoint}, status={status}");
	if bounded {
		check_headers(&response)?;
		if !response.status().is_success() {
			return Err(NetworkError::http_status(&response));
		}
	}
	let response = NetworkError::ensure_success(response)?;
	let body = if bounded {
		let status = response.status();
		String::from_utf8(read_response(response)?)
			.map_err(|_| NetworkError::response_body(status, None))?
	} else {
		response.text()?
	};
	Ok(WebResponse { status, body })
}

const MAX_RAW_BODY: usize = 8 * 1024 * 1024;
const MAX_DECODED_BODY: usize = 16 * 1024 * 1024;
const MAX_HEADERS: usize = 64 * 1024;

fn read_bounded(
	mut reader: impl Read,
	limit: usize,
	status: reqwest::StatusCode,
) -> Result<Vec<u8>, NetworkError> {
	let mut bytes = Vec::new();
	let mut chunk = [0; 8192];
	loop {
		// One extra byte distinguishes exact-limit EOF from a response that must be rejected.
		let available = chunk.len().min(limit - bytes.len() + 1);
		let count = reader
			.read(&mut chunk[..available])
			.map_err(|error| NetworkError::response_body(status, Some(error)))?;
		if count == 0 {
			return Ok(bytes);
		}
		if count > limit - bytes.len() {
			return Err(NetworkError::response_body(status, None));
		}
		bytes.extend_from_slice(&chunk[..count]);
	}
}

fn check_headers(response: &reqwest::blocking::Response) -> Result<(), NetworkError> {
	let status = response.status();
	// reqwest has already parsed headers here; this bounds accepted data, not its parser allocation.
	let mut header_bytes = 2usize;
	for (name, value) in response.headers() {
		header_bytes = header_bytes
			.saturating_add(name.as_str().len())
			.saturating_add(value.as_bytes().len())
			.saturating_add(4);
		if header_bytes > MAX_HEADERS {
			return Err(NetworkError::response_body(status, None));
		}
	}
	Ok(())
}

fn read_response(response: reqwest::blocking::Response) -> Result<Vec<u8>, NetworkError> {
	use reqwest::header::CONTENT_ENCODING;
	let status = response.status();
	if response
		.content_length()
		.is_some_and(|length| length > MAX_RAW_BODY as u64)
	{
		return Err(NetworkError::response_body(status, None));
	}
	let mut encodings = response.headers().get_all(CONTENT_ENCODING).iter();
	let gzip = match (encodings.next(), encodings.next()) {
		(None, None) => false,
		(Some(value), None) if value.as_bytes().eq_ignore_ascii_case(b"identity") => false,
		(Some(value), None) if value.as_bytes().eq_ignore_ascii_case(b"gzip") => true,
		_ => return Err(NetworkError::response_body(status, None)),
	};
	let bytes = read_bounded(response, MAX_RAW_BODY, status)?;
	if gzip {
		read_bounded(
			flate2::read::MultiGzDecoder::new(bytes.as_slice()),
			MAX_DECODED_BODY,
			status,
		)
	} else {
		Ok(bytes)
	}
}

impl Transport for WebApiTransport {
	fn send_request<Req: BuildableRequest + MessageFull, Res: MessageFull>(
		&self,
		apireq: ApiRequest<Req>,
	) -> Result<ApiResponse<Res>, TransportError> {
		// All the API endpoints accept 2 data formats: json and protobuf.
		// Depending on the http method for the request, the data can go in 2 places:
		// - GET: query string, with the key `input_protobuf_encoded` or `input_json`
		// - POST: multipart form body, with the key `input_protobuf_encoded` or `input_json`, however url encoded form data seems to also be accepted

		// input protobuf data is always encoded in base64

		if Req::requires_access_token() && apireq.access_token().is_none() {
			return Err(TransportError::Unauthorized);
		}

		let url = apireq.build_url();
		#[cfg(feature = "test-endpoints")]
		require_loopback_route(
			&Url::parse(&url).map_err(|_| NetworkError::invalid_request())?,
			self.proxy_host_ip,
		)?;
		debug!("HTTP Request method: {}", Req::method());
		trace!("HTTP request metadata: {apireq:#?}");
		let mut req = self.client.request(Req::method(), &url);

		req = if Req::method() == reqwest::Method::GET {
			let encoded = encode_msg(
				apireq.request_data(),
				base64::engine::general_purpose::URL_SAFE,
			)?;
			let mut params = vec![("input_protobuf_encoded", encoded.as_str())];
			if let Some(access_token) = apireq.access_token() {
				params.push(("access_token", access_token.expose_secret()));
			}
			req.query(&params)
		} else {
			if let Some(access_token) = apireq.access_token() {
				req = req.query(&[("access_token", access_token)]);
			}
			let encoded = encode_msg(
				apireq.request_data(),
				base64::engine::general_purpose::STANDARD,
			)?;
			let form = Form::new().text("input_protobuf_encoded", encoded);
			req.multipart(form)
		};

		let resp = send(req, self.bounded_responses)?;
		let status = resp.status();
		debug!("Response HTTP status: {}", status);
		if self.bounded_responses {
			check_headers(&resp)?;
		} else if status == reqwest::StatusCode::UNAUTHORIZED {
			return Err(TransportError::Unauthorized);
		}
		if !status.is_success() {
			return Err(NetworkError::http_status(&resp).into());
		}
		let resp = NetworkError::ensure_success(resp)?;

		let eresult = if let Some(eresult) = resp.headers().get("x-eresult") {
			let s = eresult
				.to_str()
				.map_err(|err| TransportError::HeaderParseFailure {
					header: "x-eresult".to_owned(),
					source: err.into(),
				})?;
			s.parse::<i32>()
				.map_err(|err| TransportError::HeaderParseFailure {
					header: "x-eresult".to_owned(),
					source: err.into(),
				})?
				.into()
		} else {
			EResult::Invalid
		};
		let error_msg = if let Some(error_message) = resp.headers().get("x-error_message") {
			let s = error_message
				.to_str()
				.map_err(|err| TransportError::HeaderParseFailure {
					header: "x-error_message".to_owned(),
					source: err.into(),
				})?;
			debug!("HTTP Header x-error_message was present");
			Some(s.to_owned())
		} else {
			None
		};

		let res = if self.bounded_responses {
			decode_msg::<Res>(&read_response(resp)?)?
		} else {
			decode_msg::<Res>(&resp.bytes().map_err(NetworkError::from)?)?
		};
		let api_resp = ApiResponse {
			http_status: Some(status.as_u16()),
			result: eresult,
			error_message: error_msg,
			response_data: res,
		};
		trace!("HTTP response metadata: {api_resp:#?}");

		Ok(api_resp)
	}

	fn send_web(&self, request: WebRequest<'_>) -> Result<WebResponse, NetworkError> {
		send_web_with_limits(
			&self.client,
			request,
			self.bounded_responses,
			#[cfg(feature = "test-endpoints")]
			self.proxy_host_ip,
		)
	}

	fn close(&mut self) {}

	fn innner_http_client(&self) -> anyhow::Result<reqwest::blocking::Client> {
		Ok(self.client.clone())
	}
}

/// A Steam Community endpoint supported by [`WebApiTransport`].
#[non_exhaustive]
#[derive(Clone, Copy)]
pub enum WebEndpoint<'a> {
	ConfirmationList,
	ConfirmationAction,
	ConfirmationBulkAction,
	ConfirmationDetails(&'a str),
	#[cfg(any(test, feature = "test-endpoints"))]
	Test(&'a str),
}

impl WebEndpoint<'_> {
	fn name(self) -> &'static str {
		match self {
			Self::ConfirmationList => "confirmation-list",
			Self::ConfirmationAction => "confirmation-action",
			Self::ConfirmationBulkAction => "confirmation-bulk-action",
			Self::ConfirmationDetails(_) => "confirmation-details",
			#[cfg(any(test, feature = "test-endpoints"))]
			Self::Test(_) => "test",
		}
	}

	fn url(self) -> Result<Url, NetworkError> {
		match self {
			Self::ConfirmationList => endpoints::community_url("mobileconf/getlist")
				.map_err(|_| NetworkError::invalid_request()),
			Self::ConfirmationAction => endpoints::community_url("mobileconf/ajaxop")
				.map_err(|_| NetworkError::invalid_request()),
			Self::ConfirmationBulkAction => endpoints::community_url("mobileconf/multiajaxop")
				.map_err(|_| NetworkError::invalid_request()),
			Self::ConfirmationDetails(id) => {
				let mut url = endpoints::community_url("mobileconf/details/")
					.map_err(|_| NetworkError::invalid_request())?;
				url.path_segments_mut()
					.map_err(|_| NetworkError::invalid_request())?
					.pop_if_empty()
					.push(id);
				Ok(url)
			}
			#[cfg(any(test, feature = "test-endpoints"))]
			Self::Test(url) => Url::parse(url).map_err(|_| NetworkError::invalid_request()),
		}
	}
}

impl fmt::Debug for WebEndpoint<'_> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(self.name())
	}
}

/// A request to a Steam Community endpoint.
pub struct WebRequest<'a> {
	endpoint: WebEndpoint<'a>,
	query: &'a [(&'static str, Cow<'a, str>)],
	user_agent: &'a str,
	cookie: &'a str,
	accept_language: &'a str,
	origin: Option<&'a str>,
	form_body: Option<&'a str>,
}

impl<'a> WebRequest<'a> {
	pub fn new(
		endpoint: WebEndpoint<'a>,
		query: &'a [(&'static str, Cow<'a, str>)],
		user_agent: &'a str,
		cookie: &'a str,
		accept_language: &'a str,
	) -> Self {
		Self {
			endpoint,
			query,
			user_agent,
			cookie,
			accept_language,
			origin: None,
			form_body: None,
		}
	}

	pub fn with_origin(mut self, origin: &'a str) -> Self {
		self.origin = Some(origin);
		self
	}

	/// Sends the request as a POST with a URL-encoded form body.
	pub fn with_form_body(mut self, body: &'a str) -> Self {
		self.form_body = Some(body);
		self
	}

	/// The destination of this request, for custom transports.
	pub fn endpoint(&self) -> WebEndpoint<'a> {
		self.endpoint
	}

	/// Query parameters, which may contain credentials and confirmation nonces.
	pub fn query(&self) -> &[(&'static str, Cow<'a, str>)] {
		self.query
	}

	/// The form body, which may contain credentials and confirmation nonces.
	pub fn form_body(&self) -> Option<&str> {
		self.form_body
	}
}

impl fmt::Debug for WebRequest<'_> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("WebRequest")
			.field(
				"method",
				&if self.form_body.is_some() {
					"POST"
				} else {
					"GET"
				},
			)
			.field("endpoint", &self.endpoint)
			.field("query", &"[REDACTED]")
			.field("headers", &"[REDACTED]")
			.field("body", &self.form_body.as_ref().map(|_| "[REDACTED]"))
			.finish()
	}
}

/// The status and body returned by a Steam Community endpoint.
pub struct WebResponse {
	status: u16,
	body: String,
}

impl WebResponse {
	/// Creates a successful HTTP response for a custom [`Transport`] implementation.
	/// The transport must classify non-success HTTP statuses before returning a response.
	pub fn new(status: u16, body: impl Into<String>) -> Self {
		Self {
			status,
			body: body.into(),
		}
	}

	pub fn status(&self) -> u16 {
		self.status
	}

	pub fn into_body(self) -> String {
		self.body
	}
}

impl fmt::Debug for WebResponse {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("WebResponse")
			.field("status", &self.status)
			.field("body", &"[REDACTED]")
			.finish()
	}
}

fn encode_msg<T: MessageFull>(msg: &T, engine: impl base64::Engine) -> anyhow::Result<String> {
	let bytes = msg.write_to_bytes()?;
	let b64 = engine.encode(bytes);
	Ok(b64)
}

fn decode_msg<T: MessageFull>(bytes: &[u8]) -> Result<T, protobuf::Error> {
	T::parse_from_bytes(bytes)
}

#[cfg(test)]
mod tests {
	use std::{
		io::{Read, Write},
		net::TcpListener,
		thread,
	};

	use crate::protobufs::steammessages_auth_steamclient::{
		CAuthentication_BeginAuthSessionViaCredentials_Request,
		CAuthentication_GetPasswordRSAPublicKey_Response,
		CAuthentication_PollAuthSessionStatus_Response,
		CAuthentication_UpdateAuthSessionWithSteamGuardCode_Request,
	};
	use crate::{steamapi::EResult, token::Jwt};

	use super::*;
	use base64::{engine::general_purpose::STANDARD, Engine};

	#[derive(Clone)]
	struct AccessorOnlyTransport(reqwest::blocking::Client);

	impl Transport for AccessorOnlyTransport {
		fn send_request<Req: BuildableRequest + MessageFull, Res: MessageFull>(
			&self,
			_req: ApiRequest<Req>,
		) -> Result<ApiResponse<Res>, TransportError> {
			unreachable!()
		}

		fn close(&mut self) {}

		fn innner_http_client(&self) -> anyhow::Result<reqwest::blocking::Client> {
			Ok(self.0.clone())
		}
	}

	#[test]
	fn default_web_transport_uses_existing_http_accessor() {
		let listener = TcpListener::bind("127.0.0.1:0").unwrap();
		let address = listener.local_addr().unwrap();
		let server = thread::spawn(move || {
			let (mut stream, _) = listener.accept().unwrap();
			let mut request = [0; 1024];
			let _ = stream.read(&mut request).unwrap();
			stream
				.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
				.unwrap();
		});
		let transport = AccessorOnlyTransport(
			reqwest::blocking::Client::builder()
				.no_proxy()
				.build()
				.unwrap(),
		);
		let no_query = [];

		let response = transport
			.send_web(WebRequest::new(
				WebEndpoint::Test(&format!("http://{address}/request")),
				&no_query,
				"test-agent",
				"session=test-cookie",
				"en-US",
			))
			.unwrap();

		assert_eq!(response.status(), 200);
		assert_eq!(response.into_body(), "ok");
		server.join().unwrap();
	}

	#[test]
	fn builds_get_and_form_web_requests() {
		let transport = WebApiTransport::new(
			reqwest::blocking::Client::builder()
				.no_proxy()
				.build()
				.unwrap(),
		);
		let query = [("key", Cow::Borrowed("value"))];
		let get = build_web_request(
			&transport.client,
			WebRequest::new(
				WebEndpoint::Test("https://example.invalid/request"),
				&query,
				"test-agent",
				"session=test-cookie",
				"en-US",
			),
		)
		.unwrap()
		.build()
		.unwrap();

		assert_eq!(get.method(), reqwest::Method::GET);
		assert_eq!(get.url().query(), Some("key=value"));
		assert!(
			(get.headers()[USER_AGENT]) == ("test-agent"),
			"sensitive assertion failed"
		);
		assert!(
			(get.headers()[COOKIE]) == ("session=test-cookie"),
			"sensitive assertion failed"
		);

		let no_query = [];
		let post = build_web_request(&transport.client, {
			WebRequest::new(
				WebEndpoint::Test("https://example.invalid/request"),
				&no_query,
				"test-agent",
				"session=test-cookie",
				"en-US",
			)
			.with_origin("https://steamcommunity.com")
			.with_form_body("key=value")
		})
		.unwrap()
		.build()
		.unwrap();

		assert_eq!(post.method(), reqwest::Method::POST);
		assert!(
			(post.headers()[ORIGIN]) == ("https://steamcommunity.com"),
			"sensitive assertion failed"
		);
		assert!(
			(post.headers()[CONTENT_TYPE]) == ("application/x-www-form-urlencoded; charset=UTF-8"),
			"sensitive assertion failed"
		);
		assert!(
			(post.body().unwrap().as_bytes()) == (Some(b"key=value".as_slice())),
			"sensitive assertion failed"
		);
	}

	#[test]
	fn builds_confirmation_details_requests_with_safe_paths() {
		let client = reqwest::blocking::Client::builder()
			.no_proxy()
			.build()
			.unwrap();
		let query = [("key", Cow::Borrowed("value"))];
		for (id, expected_path) in [
			("123", "/mobileconf/details/123"),
			("../123/45%?#", "/mobileconf/details/..%2F123%2F45%25%3F%23"),
		] {
			let request = build_web_request(
				&client,
				WebRequest::new(
					WebEndpoint::ConfirmationDetails(id),
					&query,
					"test-agent",
					"session=test-cookie",
					"en-US",
				),
			)
			.unwrap()
			.build()
			.unwrap();

			assert_eq!(request.method(), reqwest::Method::GET);
			assert_eq!(request.url().path(), expected_path);
			assert_eq!(request.url().query(), Some("key=value"));
			assert_eq!(request.url().fragment(), None);
		}
	}

	#[test]
	fn web_request_and_response_debug_redact_sensitive_data() {
		let query = [("key", Cow::Borrowed("query-secret-canary"))];
		let request = WebRequest::new(
			WebEndpoint::ConfirmationDetails("confirmation-id-canary"),
			&query,
			"agent-canary",
			"cookie-secret-canary",
			"language-canary",
		)
		.with_origin("origin-canary")
		.with_form_body("request-body-canary");
		let response = WebResponse {
			status: 200,
			body: "response-body-canary".to_owned(),
		};

		let output = format!("{request:?} {response:?}");
		for canary in [
			"query-secret-canary",
			"confirmation-id-canary",
			"agent-canary",
			"cookie-secret-canary",
			"language-canary",
			"origin-canary",
			"request-body-canary",
			"response-body-canary",
		] {
			assert!(!output.contains(canary), "sensitive assertion failed");
		}
		assert!(output.contains("[REDACTED]"), "sensitive assertion failed");
	}

	#[test]
	fn api_request_and_response_debug_redact_payloads() {
		let token = Jwt::from("access-token-canary".to_owned());
		let mut request_data = CAuthentication_UpdateAuthSessionWithSteamGuardCode_Request::new();
		request_data.set_code("request-body-canary".to_owned());
		let request = ApiRequest::new("ITestService", "SubmitSecret", 1, request_data)
			.with_access_token(&token);
		let response = ApiResponse {
			http_status: None,
			result: EResult::Fail,
			error_message: Some("response-error-canary".to_owned()),
			response_data: "response-body-canary",
		};

		let output = format!("{request:?} {response:?}");
		for canary in [
			"access-token-canary",
			"request-body-canary",
			"response-error-canary",
			"response-body-canary",
		] {
			assert!(!output.contains(canary), "sensitive assertion failed");
		}
		assert!(output.contains("[REDACTED]"), "sensitive assertion failed");
	}

	#[test]
	fn socks5h_proxy_uses_remote_dns_and_credentials() {
		let listener = TcpListener::bind("127.0.0.1:0").unwrap();
		let proxy_address = listener.local_addr().unwrap();
		let server = thread::spawn(move || {
			let (mut stream, _) = listener.accept().unwrap();

			let mut greeting = [0; 2];
			stream.read_exact(&mut greeting).unwrap();
			assert_eq!(greeting[0], 5);
			let mut methods = vec![0; greeting[1] as usize];
			stream.read_exact(&mut methods).unwrap();
			assert!(methods.contains(&2));
			stream.write_all(&[5, 2]).unwrap();

			let mut auth = [0; 2];
			stream.read_exact(&mut auth).unwrap();
			assert_eq!(auth[0], 1);
			let mut username = vec![0; auth[1] as usize];
			stream.read_exact(&mut username).unwrap();
			let mut password_length = [0];
			stream.read_exact(&mut password_length).unwrap();
			let mut password = vec![0; password_length[0] as usize];
			stream.read_exact(&mut password).unwrap();
			stream.write_all(&[1, 0]).unwrap();

			let mut request = [0; 4];
			stream.read_exact(&mut request).unwrap();
			assert_eq!(request, [5, 1, 0, 3]);
			let mut domain_length = [0];
			stream.read_exact(&mut domain_length).unwrap();
			let mut domain = vec![0; domain_length[0] as usize];
			stream.read_exact(&mut domain).unwrap();
			let mut port = [0; 2];
			stream.read_exact(&mut port).unwrap();

			stream.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
			(
				String::from_utf8(username).unwrap(),
				String::from_utf8(password).unwrap(),
				String::from_utf8(domain).unwrap(),
				u16::from_be_bytes(port),
			)
		});

		let proxy = ProxyConfig::new(format!("socks5h://{proxy_address}"))
			.unwrap()
			.with_basic_auth("socks-user-%40-canary", "socks:password-%40-canary");
		let transport = WebApiTransport::new_with_proxy(&proxy).unwrap();
		let error = transport
			.innner_http_client()
			.unwrap()
			.get("http://remote-name.invalid:8080/proxy-check")
			.send()
			.unwrap_err();

		let output = format!("{error:?} {error}");
		assert!(
			!output.contains("socks-user-%40-canary"),
			"sensitive assertion failed"
		);
		assert!(
			!output.contains("socks:password-%40-canary"),
			"sensitive assertion failed"
		);
		let (username, password, domain, port) = server.join().unwrap();
		assert!(
			(username) == ("socks-user-%40-canary"),
			"sensitive assertion failed"
		);
		assert!(
			(password) == ("socks:password-%40-canary"),
			"sensitive assertion failed"
		);
		assert_eq!(domain, "remote-name.invalid");
		assert_eq!(port, 8080);
	}

	#[test]
	fn test_parse_poll_response() {
		let sample = b"GuUDZXlBaWRIbHdJam9nSWtwWFZDSXNJQ0poYkdjaU9pQWlSV1JFVTBFaUlIMC5leUFpYVhOeklqb2dJbk4wWldGdElpd2dJbk4xWWlJNklDSTNOalUyTVRFNU9URTFOVGN3TmpnNU1pSXNJQ0poZFdRaU9pQmJJQ0ozWldJaUxDQWljbVZ1WlhjaUxDQWlaR1Z5YVhabElpQmRMQ0FpWlhod0lqb2dNVGN3TlRBeE1UazFOU3dnSW01aVppSTZJREUyTnpnME5qUTRNemNzSUNKcFlYUWlPaUF4TmpnM01UQTBPRE0zTENBaWFuUnBJam9nSWpFNFF6VmZNakpDTTBZME16RmZRMFJHTmtFaUxDQWliMkYwSWpvZ01UWTROekV3TkRnek55d2dJbkJsY2lJNklERXNJQ0pwY0Y5emRXSnFaV04wSWpvZ0lqWTVMakV5TUM0eE16WXVNVEkwSWl3Z0ltbHdYMk52Ym1acGNtMWxjaUk2SUNJMk9TNHhNakF1TVRNMkxqRXlOQ0lnZlEuR3A1VFBqOXBHUWJ4SXpXREROQ1NQOU9rS1lTZXduV0JFOEUtY1ZxalFxcVQ1M0FzRTRya213OER5TThoVXJ4T0VQQ1dDWHdyYkRVcmgxOTlSempQRHci/gNleUFpZEhsd0lqb2dJa3BYVkNJc0lDSmhiR2NpT2lBaVJXUkVVMEVpSUgwLmV5QWlhWE56SWpvZ0luSTZNVGhETlY4eU1rSXpSalF6TVY5RFJFWTJRU0lzSUNKemRXSWlPaUFpTnpZMU5qRXhPVGt4TlRVM01EWTRPVElpTENBaVlYVmtJam9nV3lBaWQyVmlJaUJkTENBaVpYaHdJam9nTVRZNE56RTVNamM0T0N3Z0ltNWlaaUk2SURFMk56ZzBOalE0TXpjc0lDSnBZWFFpT2lBeE5qZzNNVEEwT0RNM0xDQWlhblJwSWpvZ0lqRXlSREZmTWpKQ00wVTROekZmT1RaRk5EQWlMQ0FpYjJGMElqb2dNVFk0TnpFd05EZ3pOeXdnSW5KMFgyVjRjQ0k2SURFM01EVXdNVEU1TlRVc0lDSndaWElpT2lBd0xDQWlhWEJmYzNWaWFtVmpkQ0k2SUNJMk9TNHhNakF1TVRNMkxqRXlOQ0lzSUNKcGNGOWpiMjVtYVhKdFpYSWlPaUFpTmprdU1USXdMakV6Tmk0eE1qUWlJSDAuMVNnUEotSVZuWEp6Nk9nSW1udUdOQ0hMbEJTcGdvc0Z0UkxoOV9iVVBHQ1RaMmFtRWY2ZTZVYkJzVWZ3bnlYbEdFdG5LSHhPemhibTdLNzBwVFhEQ0EoADIKaHlkcmFzdGFyMg==";

		let bytes = STANDARD.decode(sample).unwrap();

		let resp: CAuthentication_PollAuthSessionStatus_Response = decode_msg(&bytes).unwrap();

		assert!(
			!resp.access_token().is_empty(),
			"poll response token missing"
		);
	}

	#[test]
	fn parse_get_public_rsa_response() {
		let sample = b"CoAEYjYyMGI1ZWNhMWIxMjgyYjkxYzZkZmZkYWFhOWI0ODI0YjlhNmRiYmEyZDVmYjc0ODcxNDczZDc1MDYxNGEzNWM4ODQ3NDYzZTEyNjAwNTJmNzZlNTYxMDM5ODdlN2U3NGJkMWZjZGRjYWJhMDVmZGM5OTBjMWIyNmQ2ZDg5MGM2MTEzZmRkNTZmMmQ1YmZjNzU4ODhlMzZhNTM2NjM3N2IzZTE3ZTJiZWM5MjhlNGY4MmE1YzY0NGYxZTZlMTk3NzZkNjIzMDIxYjhmYTA0MGRjNWE5YjY0M2I0N2I5YmVhMjM2YmEyZjM4ODVjM2ZlNWVhNjMzZThlNjJjNGE1YTY4NjNmMzNiMzdlMTQ4M2MwZTUzZTg4ODIzMGFkNTVjNzg5ZmU4Y2NkMjVjNzdiMTkxOTg0ZThjN2JmNWYzNzY2MjI0OGI1NWVmOWM1OGY3NDM5YjA4ZjNhNWJiNzljNTc5ZDE5M2I3NzhmMzFiY2IwYTA3MmVhZWYxOGEyYjljZDY2M2VmYmY2YmRiZDU3MGEyMTNiOTIxNTc4ODk0MjJkMDY3ODFiNTVkY2VjYjQ4NjA4MjUyMmUzZWQyOWM4MjExYzQ5N2Q1YjNhYTk2OGM2MDY1YWFhZTNhNGVmYzZiMGJjNDYyMzMxNmVmYTUxN2JjNzRiZDYzODcxMWU4ZWYSBjAxMDAwMRiQn6Ly3wk=";

		let bytes = STANDARD.decode(sample).unwrap();

		let resp: CAuthentication_GetPasswordRSAPublicKey_Response = decode_msg(&bytes).unwrap();

		assert!(!resp.publickey_mod().is_empty(), "RSA public key missing");
	}

	#[test]
	fn test_decode_encode_roundtrip() {
		let sample = b"EgpoeWRyYXN0YXIyGtgCRUxaNTBXdHM2Z0kxWlZaVjl6bzRJNFBEcEhTMGRZR3RSNzJPbytqZkR5QmRBUitrbnBUcUVGcGF4NDd1UVdqdUQ1R2hpRC9JanA2cEtGQzlrdUZDdzBFT0RMSFpINERZUG5hci9IMktOZGoxSFNjWEhyemZjNmk1OWpsRE5OTTI0RVllNUEyUjVSdzBoa2lodU14Z1A4NDJESFUxMkgwNWFyYmdRUWp3NFJmVHh6cDBQQlRjdTk4VUViUjJnak1RajlVK3RsYStPdTN6WTQ5K1BKc0szTkpMTVdxWm4vaFZ1dTR3NFprZGhXNVBqNWphb2Flb3J6MG8zbWIvUXo2M0NlNFdwWmUra1lFYUlSa29oUXBaZkliaW4rTWdQcVpNelg4cW4vNDcyNFp5N05mblpETlVBV3RoTkowTkUxSDVESXZ4N0IwRFJHZVBwdk5FbVdqWEJ3PT0g4MCW2tYBOAFCBk1vYmlsZUocCgpHYWxheHkgUzIyEAMYjPz/////////ASCQBA==";

		let bytes = STANDARD.decode(sample).unwrap();
		let decoded: CAuthentication_BeginAuthSessionViaCredentials_Request =
			decode_msg(&bytes).expect("Failed to decode");

		let encoded = encode_msg(&decoded, STANDARD).expect("Failed to encode");

		assert!(
			(encoded) == (String::from_utf8(sample.to_vec()).unwrap()),
			"sensitive assertion failed"
		);
	}
}

#[cfg(all(test, feature = "test-endpoints"))]
#[path = "tests/endpoint_guard.rs"]
mod endpoint_guard_tests;
