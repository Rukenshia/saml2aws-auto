use reqwest::{header, header::Basic, header::Headers, ClientBuilder};
use std::env;
use url::Url;

pub fn get_proxied_client_builder() -> ClientBuilder {
    let mut cb = ClientBuilder::new();

    trace!("get_proxied_client_builder.http_proxy.before_check");
    if let Ok(http_proxy) = env::var("http_proxy") {
        trace!("get_proxied_client_builder.http_proxy.before_unwrap");
        let url = Url::parse(&http_proxy).expect("Could not parse http_proxy environment variable");

        let mut headers = Headers::new();
        headers.set(header::ProxyAuthorization(Basic {
            username: url.username().to_owned(),
            password: Some(url.password().unwrap().to_owned()),
        }));
        cb.default_headers(headers);
    } else {
        trace!("get_proxied_client_builder.https_proxy.before_check");
        if let Ok(https_proxy) = env::var("https_proxy") {
            trace!("get_proxied_client_builder.https_proxy.before_unwrap");
            let url =
                Url::parse(&https_proxy).expect("Could not parse https_proxy environment variable");

            let mut headers = Headers::new();
            headers.set(header::ProxyAuthorization(Basic {
                username: url.username().to_owned(),
                password: Some(url.password().unwrap().to_owned()),
            }));
            cb.default_headers(headers);
        }
    }

    trace!("get_proxied_client_builder.done");
    cb
}
