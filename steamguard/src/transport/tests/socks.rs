use super::*;

const TARGET: &str = "socks-target.invalid";
const USERNAME: &str = "proxy-user-%40-canary";
const PASSWORD: &str = "proxy:password-%40-canary";

fn read_socks_string(stream: &mut TcpStream) -> Vec<u8> {
	let mut length = [0];
	stream.read_exact(&mut length).unwrap();
	let mut bytes = vec![0; usize::from(length[0])];
	stream.read_exact(&mut bytes).unwrap();
	bytes
}

// Only receives a SOCKS exchange: it never resolves or connects to the requested origin.
fn socks_sink(listener: TcpListener, authenticated: bool) -> thread::JoinHandle<(String, u16)> {
	thread::spawn(move || {
		// accept() explicitly clears inherited O_NONBLOCK on macOS/BSD and bounds all I/O.
		let mut stream = accept(&listener);
		let mut version = [0];
		stream.read_exact(&mut version).unwrap();
		assert_eq!(version, [5]);
		let methods = read_socks_string(&mut stream);
		let method = if authenticated { 2 } else { 0 };
		assert!(methods.contains(&method));
		stream.write_all(&[5, method]).unwrap();
		if authenticated {
			stream.read_exact(&mut version).unwrap();
			assert_eq!(version, [1]);
			assert!(
				read_socks_string(&mut stream) == USERNAME.as_bytes(),
				"SOCKS username did not round-trip"
			);
			assert!(
				read_socks_string(&mut stream) == PASSWORD.as_bytes(),
				"SOCKS password did not round-trip"
			);
			stream.write_all(&[1, 0]).unwrap();
		}
		let mut connect = [0; 4];
		stream.read_exact(&mut connect).unwrap();
		assert_eq!(
			connect,
			[5, 1, 0, 0x03],
			"expected CONNECT with domain ATYP"
		);
		let hostname = String::from_utf8(read_socks_string(&mut stream)).unwrap();
		let mut port = [0; 2];
		stream.read_exact(&mut port).unwrap();
		// A complete host-unreachable reply ends the request without any origin connection.
		stream.write_all(&[5, 4, 0, 1, 127, 0, 0, 1, 0, 0]).unwrap();
		(hostname, u16::from_be_bytes(port))
	})
}

fn check_connect(
	transport: &WebApiTransport,
	listener: TcpListener,
	authenticated: bool,
	port: u16,
) {
	let server = socks_sink(listener, authenticated);
	let scheme = if port == 443 { "https" } else { "http" };
	let error = web_get(transport, &format!("{scheme}://{TARGET}:{port}/probe")).unwrap_err();
	let (hostname, received_port) = server.join().unwrap();
	assert_eq!(hostname, TARGET);
	assert_eq!(received_port, port);
	assert!(
		error.kind() == NetworkErrorKind::Connection && error.sent() == RequestSent::No,
		"expected the sink's SOCKS connection rejection"
	);
}

/// T-09/C03: inspect the actual SOCKS5 CONNECT, including separate percent-containing auth.
#[test]
fn socks5h_sends_domain_name_to_proxy() {
	for authenticated in [false, true] {
		for port in [80, 443] {
			let listener = TcpListener::bind("127.0.0.1:0").unwrap();
			let mut proxy =
				ProxyConfig::new(format!("socks5h://{}", listener.local_addr().unwrap())).unwrap();
			if authenticated {
				proxy = proxy.with_basic_auth(USERNAME, PASSWORD);
			}
			let transport = WebApiTransport::new_with_proxy(&proxy).unwrap();
			check_connect(&transport, listener, authenticated, port);
		}
	}
}

#[cfg(feature = "test-endpoints")]
mod resolver {
	use super::*;
	use reqwest::dns::{Addrs, Name, Resolve, Resolving};
	use std::sync::Mutex;

	const PROXY: &str = "resolver-proxy.invalid";

	struct ResolverSpy {
		address: SocketAddr,
		lookups: Mutex<Vec<String>>,
	}

	impl Resolve for ResolverSpy {
		fn resolve(&self, name: Name) -> Resolving {
			self.lookups.lock().unwrap().push(name.as_str().to_owned());
			let result = if name.as_str() == PROXY {
				Ok(Box::new(std::iter::once(self.address)) as Addrs)
			} else {
				// A regression fails locally instead of asking a real DNS service.
				Err(Box::new(std::io::Error::other("unexpected DNS lookup")) as _)
			};
			Box::pin(std::future::ready(result))
		}
	}

	/// The named-proxy control proves the hook is installed on the real connector. With a
	/// literal proxy address it observes zero lookups; with a proxy name only that name is
	/// resolved. In both cases the sink must receive the unchanged HTTP/HTTPS target name.
	#[test]
	fn socks5h_targets_never_use_local_dns() {
		for named_proxy in [false, true] {
			for port in [80, 443] {
				let listener = TcpListener::bind("127.0.0.1:0").unwrap();
				let address = listener.local_addr().unwrap();
				let spy = Arc::new(ResolverSpy {
					address,
					lookups: Mutex::new(Vec::new()),
				});
				let proxy = if named_proxy {
					format!("socks5h://{PROXY}:{}", address.port())
				} else {
					format!("socks5h://{address}")
				};
				let transport = WebApiTransport::new_with_proxy_and_test_resolver(
					&ProxyConfig::new(proxy).unwrap(),
					Arc::clone(&spy),
				)
				.unwrap();
				check_connect(&transport, listener, false, port);
				let lookups = spy.lookups.lock().unwrap();
				if named_proxy {
					assert_eq!(lookups.as_slice(), [PROXY]);
				} else {
					assert!(lookups.is_empty());
				}
			}
		}
	}
}
