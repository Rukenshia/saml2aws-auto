use reqwest::{header, header::Basic, header::Headers, ClientBuilder, Proxy};
use std::env;
use url::Url;

pub fn get_proxied_client_builder() -> ClientBuilder {
    let mut cb = ClientBuilder::new();

    trace!("get_proxied_client_builder.http_proxy.before_check");
    if let Ok(http_proxy) = env::var("s2a_http_proxy") {
        trace!("get_proxied_client_builder.http_proxy.before_unwrap");
        let url = Url::parse(&http_proxy).expect("Could not parse http_proxy environment variable");

        trace!("http_proxy.username='{}'", url.username());
        trace!("http_proxy.password='{:?}'", url.password());
        trace!("http_proxy.url='{}'", http_proxy);

        trace!("get_proxied_client_builder.http_proxy.proxy.before_unwrap");

        let mut basic_url = url.clone();
        basic_url
            .set_password(None)
            .expect("Could not remove basic_url password");
        basic_url
            .set_username("")
            .expect("Could not remove baisc_url username");
        trace!("http_proxy.basic_url='{}'", basic_url);

        let proxy = Proxy::http(basic_url.as_str()).expect("Could not unwrap http proxy");

        let mut headers = Headers::new();
        headers.set(header::ProxyAuthorization(Basic {
            username: url.username().to_owned(),
            password: Some(url.password().unwrap().to_owned()),
        }));

        trace!(
            "http_proxy.default_headers!overwritable='{}'",
            headers.get::<header::ProxyAuthorization<Basic>>().unwrap()
        );
        cb.default_headers(headers);
        cb.proxy(proxy);
    }

    trace!("get_proxied_client_builder.https_proxy.before_check");
    if let Ok(https_proxy) = env::var("s2a_https_proxy") {
        trace!("get_proxied_client_builder.https_proxy.before_unwrap");
        let url =
            Url::parse(&https_proxy).expect("Could not parse https_proxy environment variable");

        trace!("https_proxy.username='{}'", url.username());
        trace!("https_proxy.password='{:?}'", url.password());
        trace!("https_proxy.url='{}'", https_proxy);

        trace!("get_proxied_client_builder.https_proxy.proxy.before_unwrap");

        let mut basic_url = url.clone();
        basic_url
            .set_password(None)
            .expect("Could not remove basic_url password");
        basic_url
            .set_username("")
            .expect("Could not remove baisc_url username");
        trace!("https_proxy.basic_url='{}'", basic_url);

        let proxy = Proxy::https(basic_url.as_str()).expect("Could not unwrap https proxy");

        let mut headers = Headers::new();
        headers.set(header::ProxyAuthorization(Basic {
            username: url.username().to_owned(),
            password: Some(url.password().unwrap().to_owned()),
        }));

        trace!(
            "https_proxy.default_headers='{}'",
            headers.get::<header::ProxyAuthorization<Basic>>().unwrap()
        );
        cb.default_headers(headers);
        cb.proxy(proxy);
    }

    trace!("get_proxied_client_builder.done");
    cb
}
