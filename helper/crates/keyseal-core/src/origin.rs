//! Origin rules (section 4). Every request for a job goes through an agent
//! from [`Origin::agent`], whose resolver refuses any other origin (so
//! cross-origin redirects fail) and, outside the development override, any
//! connection to a loopback, private or link-local address, checked on
//! every connection so a changed DNS answer can't reach the user's network.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use ureq::Agent;
use ureq::config::Config;
use ureq::http::Uri;
use ureq::tls::{RootCerts, TlsConfig};
use ureq::unversioned::resolver::{DefaultResolver, ResolvedSocketAddrs, Resolver};
use ureq::unversioned::transport::{DefaultConnector, NextTimeout};
use url::{Host, Url};

/// `KEYSEAL_ALLOW_INSECURE_ORIGINS=1` also allows `http://localhost` and
/// `http://127.0.0.1` on any port (section 4.4).
pub fn insecure_origins_allowed() -> bool {
    std::env::var("KEYSEAL_ALLOW_INSECURE_ORIGINS").is_ok_and(|v| v == "1")
}

/// Same-origin redirects followed per request (section 4.3).
const MAX_REDIRECTS: u32 = 5;

/// Each connection attempt's limit, so an address that never answers can't
/// hold a request for most of its budget before the next one is tried.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Origin {
    scheme: String,
    host: String,
    port: u16,
    /// A development origin allowed by the override: never stored as
    /// trusted, shown with an insecure-origin banner.
    pub insecure: bool,
}

impl Origin {
    /// The origin of `url` if section 4 allows it. Hosts are compared and
    /// shown in lowercase A-label form, which is how `url` holds them.
    pub fn of_url(url: &Url, allow_insecure: bool) -> Result<Self, String> {
        let port = url
            .port_or_known_default()
            .ok_or("The job URL has no port.")?;
        let host = match url.host() {
            Some(Host::Domain(domain)) => domain.to_owned(),
            Some(Host::Ipv4(ip)) => ip.to_string(),
            Some(Host::Ipv6(_)) | None => {
                return Err("The job URL's host must be a domain name.".into());
            }
        };
        let insecure = match url.scheme() {
            "https" => false,
            "http" if allow_insecure && (host == "localhost" || host == "127.0.0.1") => true,
            _ => {
                return Err(format!("The job URL must use https, not {}.", url.scheme()));
            }
        };
        if !insecure {
            let name = host.trim_end_matches('.');
            if matches!(url.host(), Some(Host::Ipv4(_))) {
                return Err("The job URL's host must be a domain name.".into());
            }
            if name == "localhost" || name.ends_with(".localhost") {
                return Err("The job URL can't be on localhost.".into());
            }
        }
        Ok(Self {
            scheme: url.scheme().to_owned(),
            host,
            port,
            insecure,
        })
    }

    /// The origin as `scheme://host[:port]`, the trust store key.
    pub fn as_string(&self) -> String {
        let default = if self.scheme == "https" { 443 } else { 80 };
        if self.port == default {
            format!("{}://{}", self.scheme, self.host)
        } else {
            format!("{}://{}:{}", self.scheme, self.host, self.port)
        }
    }

    pub fn contains(&self, url: &Url) -> bool {
        url.scheme() == self.scheme
            && url.host_str() == Some(self.host.as_str())
            && url.port_or_known_default() == Some(self.port)
    }

    fn contains_uri(&self, uri: &Uri) -> bool {
        let default = match uri.scheme_str() {
            Some("https") => 443,
            _ => 80,
        };
        uri.scheme_str() == Some(self.scheme.as_str())
            && uri
                .host()
                .is_some_and(|host| host.eq_ignore_ascii_case(&self.host))
            && uri.port_u16().unwrap_or(default) == self.port
    }

    /// An agent for requests to this origin only. Statuses are not errors,
    /// so error bodies can be read; proxies from the environment are not
    /// used, since the resolved address of the server couldn't be checked;
    /// TLS uses the system trust store.
    pub fn agent(&self, timeout: Duration) -> Agent {
        let tls = TlsConfig::builder()
            .root_certs(RootCerts::PlatformVerifier)
            .build();
        let config = Agent::config_builder()
            .http_status_as_error(false)
            .https_only(!self.insecure)
            .max_redirects(MAX_REDIRECTS)
            .proxy(None)
            .tls_config(tls)
            .timeout_global(Some(timeout))
            .timeout_connect(Some(CONNECT_TIMEOUT))
            .user_agent(format!("keyseal/{}", crate::VERSION))
            .build();
        let resolver = OriginResolver {
            origin: self.clone(),
            inner: DefaultResolver::default(),
        };
        Agent::with_parts(config, DefaultConnector::default(), resolver)
    }
}

impl std::fmt::Display for Origin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.as_string())
    }
}

/// Addresses that aren't public unicast (section 4.2): loopback,
/// unspecified, private, CGNAT, link-local, ULA, documentation,
/// benchmarking, protocol assignments, multicast and reserved ranges from
/// the IANA special-purpose registries, and IPv6 forms that carry such an
/// IPv4 address (IPv4-mapped, IPv4-compatible, NAT64 `64:ff9b::/96` and
/// 6to4).
pub fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_private_v4(ip),
        IpAddr::V6(ip) => is_private_v6(ip),
    }
}

fn is_private_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    a == 0
        || a == 10
        || a == 127
        || a >= 224 // 224.0.0.0/4 multicast, 240.0.0.0/4 reserved and broadcast
        || (a == 100 && b & 0xc0 == 64)
        || (a == 169 && b == 254)
        || (a == 172 && b & 0xf0 == 16)
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 0 && c == 2)
        || (a == 192 && b == 88 && c == 99)
        || (a == 192 && b == 168)
        || (a == 198 && b & 0xfe == 18)
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
}

fn is_private_v6(ip: Ipv6Addr) -> bool {
    let s = ip.segments();
    let embedded = |high: u16, low: u16| {
        let [a, b] = high.to_be_bytes();
        let [c, d] = low.to_be_bytes();
        is_private_v4(Ipv4Addr::new(a, b, c, d))
    };
    match s {
        // ::/96: unspecified, loopback and the deprecated IPv4-compatible form.
        [0, 0, 0, 0, 0, 0, _, _] => true,
        // ::ffff:0:0/96, IPv4-mapped.
        [0, 0, 0, 0, 0, 0xffff, high, low] => embedded(high, low),
        // 64:ff9b::/96, NAT64 with the well-known prefix.
        [0x64, 0xff9b, 0, 0, 0, 0, high, low] => embedded(high, low),
        // 64:ff9b:1::/48, NAT64 for local use.
        [0x64, 0xff9b, 1, ..] => true,
        // 100::/64, discard only.
        [0x100, 0, 0, 0, ..] => true,
        // 2001:2::/48 benchmarking, 2001:db8::/32 documentation.
        [0x2001, 2, 0, ..] | [0x2001, 0xdb8, ..] => true,
        // 2002::/16, 6to4, whose next 32 bits are an IPv4 address.
        [0x2002, high, low, ..] => embedded(high, low),
        // 3fff::/20 documentation, 5f00::/16 SRv6 SIDs.
        [first, ..] if first & 0xfff0 == 0x3ff0 || first == 0x5f00 => true,
        // fc00::/7 ULA, fe80::/10 link-local, fec0::/10 deprecated site-local,
        // ff00::/8 multicast.
        [first, ..] => first & 0xfe00 == 0xfc00 || first & 0xff80 == 0xfe80 || first >> 8 == 0xff,
    }
}

#[derive(Debug)]
struct OriginResolver {
    origin: Origin,
    inner: DefaultResolver,
}

impl Resolver for OriginResolver {
    fn resolve(
        &self,
        uri: &Uri,
        config: &Config,
        timeout: NextTimeout,
    ) -> Result<ResolvedSocketAddrs, ureq::Error> {
        if !self.origin.contains_uri(uri) {
            return Err(ureq::Error::Other(
                format!("refused a request to {uri}, outside {}", self.origin).into(),
            ));
        }
        let mut addresses = self.inner.resolve(uri, config, timeout)?;
        if !self.origin.insecure
            && let Some(address) = addresses.iter().find(|a| is_private(a.ip()))
        {
            return Err(ureq::Error::Other(
                format!(
                    "{} resolves to {}, a private address",
                    self.origin,
                    address.ip()
                )
                .into(),
            ));
        }
        // IPv4 first: many networks hand out IPv6 addresses whose route never
        // answers, which browsers hide by racing both families. The order is
        // otherwise the resolver's, and IPv6 still follows.
        addresses.sort_by_key(SocketAddr::is_ipv6);
        Ok(addresses)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn origin(url: &str, allow_insecure: bool) -> Result<String, String> {
        Origin::of_url(&Url::parse(url).unwrap(), allow_insecure).map(|o| o.as_string())
    }

    #[test]
    fn accepts_https_domains_in_a_label_form() {
        assert_eq!(
            origin("https://Dash.Example.org/x", false).unwrap(),
            "https://dash.example.org"
        );
        assert_eq!(
            origin("https://dash.example.org:8443/x", false).unwrap(),
            "https://dash.example.org:8443"
        );
        assert_eq!(
            origin("https://dash.example.org:443/x", false).unwrap(),
            "https://dash.example.org"
        );
        assert_eq!(
            origin("https://b\u{fc}cher.example/x", false).unwrap(),
            "https://xn--bcher-kva.example"
        );
    }

    #[test]
    fn refuses_http_ip_literals_and_localhost() {
        for url in [
            "http://dash.example.org/",
            "ftp://dash.example.org/",
            "https://192.0.2.1/",
            "https://0x7f.1/",
            "https://[2001:db8::1]/",
            "https://localhost/",
            "https://LOCALHOST./",
            "https://app.localhost/",
            "http://localhost:3000/",
            "http://127.0.0.1:3000/",
        ] {
            assert!(origin(url, false).is_err(), "{url}");
        }
    }

    #[test]
    fn development_override_allows_only_http_loopback() {
        assert_eq!(
            origin("http://localhost:3000/x", true).unwrap(),
            "http://localhost:3000"
        );
        assert_eq!(
            origin("http://127.0.0.1:8080/x", true).unwrap(),
            "http://127.0.0.1:8080"
        );
        let url = Url::parse("http://127.0.0.1:8080/").unwrap();
        assert!(Origin::of_url(&url, true).unwrap().insecure);
        for url in [
            "https://localhost/",
            "https://127.0.0.1/",
            "http://127.0.0.2/",
            "http://[::1]/",
            "http://dash.example.org/",
        ] {
            assert!(origin(url, true).is_err(), "{url}");
        }
    }

    #[test]
    fn compares_origins_exactly() {
        let job =
            Origin::of_url(&Url::parse("https://dash.example.org/v1").unwrap(), false).unwrap();
        assert!(job.contains(&Url::parse("https://DASH.example.org:443/icon.png").unwrap()));
        assert!(!job.contains(&Url::parse("http://dash.example.org/").unwrap()));
        assert!(!job.contains(&Url::parse("https://dash.example.org:8443/").unwrap()));
        assert!(!job.contains(&Url::parse("https://evil.example.org/").unwrap()));
    }

    #[test]
    fn classifies_private_addresses() {
        for ip in [
            "0.0.0.0",
            "0.1.2.3",
            "10.1.2.3",
            "100.64.0.1",
            "100.127.255.255",
            "127.0.0.1",
            "169.254.1.1",
            "172.16.0.1",
            "172.31.255.255",
            "192.0.0.8",
            "192.0.2.1",
            "192.88.99.1",
            "192.168.1.1",
            "198.18.0.1",
            "198.19.255.255",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "239.255.255.255",
            "240.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "::10.0.0.1",
            "::8.8.8.8",
            "::ffff:10.0.0.1",
            "::ffff:127.0.0.1",
            "::ffff:100.64.0.1",
            "64:ff9b::10.0.0.1",
            "64:ff9b::127.0.0.1",
            "64:ff9b::169.254.169.254",
            "64:ff9b:1::1",
            "100::1",
            "2001:2::1",
            "2001:db8::1",
            "2002:0a00:0001::1",
            "2002:c0a8:0101::1",
            "3fff::1",
            "5f00::1",
            "fc00::1",
            "fd12::1",
            "fe80::1",
            "febf::1",
            "fec0::1",
            "ff02::1",
        ] {
            assert!(is_private(ip.parse().unwrap()), "{ip}");
        }
        for ip in [
            "1.1.1.1",
            "8.8.8.8",
            "100.63.255.255",
            "100.128.0.0",
            "172.15.255.255",
            "172.32.0.0",
            "192.0.1.1",
            "192.0.3.1",
            "192.169.0.1",
            "198.17.255.255",
            "198.20.0.0",
            "198.51.101.1",
            "203.0.114.1",
            "223.255.255.255",
            "::ffff:1.1.1.1",
            "64:ff9b::1.1.1.1",
            "64:ff9b:2::1",
            "100:0:0:1::1",
            "2001:3::1",
            "2001:db9::1",
            "2002:0808:0808::1",
            "2606:4700:4700::1111",
            "4000::1",
            "5f01::1",
        ] {
            assert!(!is_private(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn resolver_refuses_other_origins_and_private_addresses() {
        let job = Origin::of_url(&Url::parse("https://dash.example.org/").unwrap(), false).unwrap();
        let resolver = OriginResolver {
            origin: job,
            inner: DefaultResolver::default(),
        };
        let config = Agent::config_builder().build();
        let timeout = NextTimeout::default();
        let other: Uri = "https://evil.example.org/".parse().unwrap();
        let error = resolver.resolve(&other, &config, timeout).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("outside https://dash.example.org")
        );

        // A trusted name that resolves to loopback is refused at connect time.
        let looped = Origin {
            scheme: "https".into(),
            host: "localhost".into(),
            port: 443,
            insecure: false,
        };
        let resolver = OriginResolver {
            origin: looped,
            inner: DefaultResolver::default(),
        };
        let uri: Uri = "https://localhost/".parse().unwrap();
        let error = resolver.resolve(&uri, &config, timeout).unwrap_err();
        assert!(error.to_string().contains("a private address"), "{error}");
    }

    /// IPv4 comes first, so a network whose IPv6 route never answers costs
    /// nothing; `localhost` resolves to both families on most systems.
    #[test]
    fn resolver_puts_ipv4_first() {
        let local = Origin {
            scheme: "http".into(),
            host: "localhost".into(),
            port: 8080,
            insecure: true,
        };
        let resolver = OriginResolver {
            origin: local,
            inner: DefaultResolver::default(),
        };
        let config = Agent::config_builder().build();
        let uri: Uri = "http://localhost:8080/".parse().unwrap();
        let addresses = resolver
            .resolve(&uri, &config, NextTimeout::default())
            .unwrap();
        let families: Vec<bool> = addresses.iter().map(SocketAddr::is_ipv6).collect();
        assert!(families.is_sorted(), "{addresses:?}");
        assert!(!families.is_empty());
    }
}
