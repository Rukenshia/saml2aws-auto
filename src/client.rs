use reqwest::{ClientBuilder, Proxy};
use std::env;

pub fn get_proxied_client_builder() -> ClientBuilder {
    let mut cb = ClientBuilder::new();

    trace!("get_proxied_client_builder.http_proxy.before_check");
    if let Ok(http_proxy) = env::var("http_proxy") {
        trace!("get_proxied_client_builder.http_proxy.before_unwrap");
        let proxy = Proxy::http(&http_proxy).unwrap();
        cb.proxy(proxy);
    }

    trace!("get_proxied_client_builder.https_proxy.before_check");
    if let Ok(https_proxy) = env::var("https_proxy") {
        trace!("get_proxied_client_builder.https_proxy.before_unwrap");
        let proxy = Proxy::https(&https_proxy).unwrap();
        cb.proxy(proxy);
    }

    trace!("get_proxied_client_builder.done");
    cb
}
