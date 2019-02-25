use reqwest::{ClientBuilder, Proxy};
use std::env;
use url::Url;

pub fn get_proxied_client_builder() -> ClientBuilder {
    let mut cb = ClientBuilder::new();

    trace!("get_proxied_client_builder.http_proxy.before_check");
    if let Ok(http_proxy) = env::var("http_proxy") {
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

        let proxy = Proxy::http(basic_url.as_str())
            .expect("Could not unwrap http proxy")
            .basic_auth(url.username(), url.password().unwrap_or(""));

        cb = cb.proxy(proxy);
    }

    trace!("get_proxied_client_builder.https_proxy.before_check");
    if let Ok(https_proxy) = env::var("https_proxy") {
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

        let proxy = Proxy::https(basic_url.as_str())
            .expect("Could not unwrap https proxy")
            .basic_auth(url.username(), url.password().unwrap_or(""));

        cb = cb.proxy(proxy);
    }

    trace!("get_proxied_client_builder.done");
    cb
}
