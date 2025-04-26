use hyper::Client;
use hyper_proxy::{Proxy, ProxyConnector};
use tauri::{AppHandle, Runtime};
use tonic_web::GrpcWebClientLayer;
use tower::ServiceBuilder;
use std::sync::Arc;
use futures_util::TryFutureExt; // Required for map_ok
use std::pin::Pin;
use tokio::sync::RwLock;
use tower::Service; // Import the Service trait for .call()

use crate::{BoxDynError, Error, Result};

pub struct RetromPluginServiceClient<R: tauri::Runtime> {
    app_handle: AppHandle<R>,
    service_host: Arc<RwLock<String>>,
    grpc_web_client: Arc<dyn tower::Service<
        hyper::Request<tonic_web::GrpcWebCall<hyper::Body>>,
        Response = hyper::Response<tonic_web::GrpcWebCall<hyper::Body>>,
        Error = BoxDynError,
        Future = Pin<Box<dyn std::future::Future<Output = std::result::Result<hyper::Response<tonic_web::GrpcWebCall<hyper::Body>>, BoxDynError>> + Send + 'static>>,
    > + Send + Sync + 'static>,
}

impl<R: tauri::Runtime> RetromPluginServiceClient<R> {
    pub async fn get_service_host(&self) -> String {
        // Returning String to avoid lifetime issues with &str in async context
        self.service_host.read().await.clone()
    }

    pub fn new(app_handle: AppHandle<R>, service_host: String) -> Result<Self> {
        let mut connector = hyper::client::HttpConnector::new();
        connector.enforce_http(false); // Allow non-HTTP connections for SOCKS proxy
        let proxy = Proxy::new(
            hyper_proxy::Intercept::All,
            "socks5h://localhost:9050"
                .parse()
                .map_err(|e| Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, e)))?,
        );
        let mut proxy_connector = ProxyConnector::new(connector)
            .map_err(|e| Error::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?;
        proxy_connector.add_proxy(proxy);
        let client = Client::builder().build(proxy_connector);
    
        // Use tower::Service with GrpcWebClientLayer directly
        let grpc_web_service = ServiceBuilder::new()
            .layer(GrpcWebClientLayer::new())
            .service(client);

        // Wrap the service to box its error and response types
        let boxed_service: Arc<dyn tower::Service<
            hyper::Request<tonic_web::GrpcWebCall<hyper::Body>>,
            Response = hyper::Response<tonic_web::GrpcWebCall<hyper::Body>>,
            Error = BoxDynError,
            Future = Pin<Box<dyn std::future::Future<Output = std::result::Result<hyper::Response<tonic_web::GrpcWebCall<hyper::Body>>, BoxDynError>> + Send + 'static>>,
        > + Send + Sync + 'static> = Arc::new(tower::service_fn(
            move |req: hyper::Request<tonic_web::GrpcWebCall<hyper::Body>>| {
                let mut svc = grpc_web_service.clone();
                Box::pin(async move {
                    svc.call(req).await.map_err(|e| Box::new(e) as BoxDynError)
                }) as Pin<Box<dyn std::future::Future<Output = std::result::Result<hyper::Response<tonic_web::GrpcWebCall<hyper::Body>>, BoxDynError>> + Send + 'static>>
            }
        ));

        Ok(Self {
            app_handle,
            service_host: Arc::new(RwLock::new(service_host)),
            grpc_web_client: boxed_service,
        })
    }

    pub fn get_grpc_web_client(&self) -> Arc<dyn tower::Service<
        hyper::Request<tonic_web::GrpcWebCall<hyper::Body>>,
        Response = hyper::Response<tonic_web::GrpcWebCall<hyper::Body>>,
        Error = BoxDynError,
        Future = Pin<Box<dyn std::future::Future<Output = std::result::Result<hyper::Response<tonic_web::GrpcWebCall<hyper::Body>>, BoxDynError>> + Send + 'static>>,
    > + Send + Sync + 'static> {
        Arc::clone(&self.grpc_web_client)
    }
}

pub fn init<R: Runtime>(app: &AppHandle<R>) -> Result<RetromPluginServiceClient<R>> {
    RetromPluginServiceClient::new(app.clone(), "http://localhost:50051".to_string())
}
