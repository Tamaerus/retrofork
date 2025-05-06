use std::fs::OpenOptions;
use std::sync::Arc;

use arti_client::{TorClient, TorClientConfig};
use tor_rtcompat::PreferredRuntime;
use hyper::{Request, Body};
use hyper::client::conn;
use retrom_service::get_server;

use opentelemetry::{
    global,
    trace::TracerProvider as _,
    KeyValue,
};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{
    metrics::{MeterProviderBuilder, PeriodicReader, SdkMeterProvider},
    trace::{RandomIdGenerator, Sampler, TracerProvider},
    Resource,
};
use opentelemetry_semantic_conventions::{
    attribute::{SERVICE_NAME, SERVICE_VERSION},
    SCHEMA_URL,
};
use tracing::Level;
use tracing_opentelemetry::{MetricsLayer, OpenTelemetryLayer};
use tracing_subscriber::{layer::SubscriberExt, prelude::*, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing_subscriber();

    // Initialize the Arti client with SOCKS5 proxy configuration
    let mut config_builder = TorClientConfig::builder();
    // Configure Arti to listen on a SOCKS5 proxy port (e.g., 9050)
    // Note: Depending on the version, this might be socks_port or require a different approach
    // config_builder.socks_port(9050); // You can change to 9150 if 9050 is in use
    let config = config_builder.build()?;
    println!("Configuring Tor client to expose SOCKS5 proxy on port 9050");

    let tor_client = TorClient::create_bootstrapped(config).await?;
    let tor_client = Arc::new(tor_client);
    // println!("Tor client bootstrapped successfully with SOCKS5 proxy on port 9050");

    // Test request through Arti to verify Tor connectivity
    let test_url = "http://check.torproject.org/";
    let test_response = fetch_onion_url(test_url, &tor_client).await?;
    // println!("Test response: {}", test_response);

    #[cfg(not(feature = "embedded_db"))]
    let opts = None;

    #[cfg(feature = "embedded_db")]
    let db_opts = std::env::var("EMBEDDED_DB_OPTS").ok();
    #[cfg(feature = "embedded_db")]
    let  opts: Option<&str> = db_opts.as_deref();

    let (server, _port) = get_server(opts).await;

    if let Err(e) = server.await {
        eprintln!("Server error: {}", e);
    }

    Ok(())
}

async fn fetch_onion_url(url: &str, tor_client: &TorClient<PreferredRuntime>) -> Result<String, Box<dyn std::error::Error>> {
    let host = url.trim_start_matches("http://").trim_end_matches("/");
    let stream = tor_client
        .connect_with_prefs(format!("{}:80", host), &arti_client::StreamPrefs::new())
        .await?;

    let (mut request_sender, connection) = conn::handshake(stream).await?;
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Connection failed: {}", e);
        }
    });

    let request = Request::builder()
        .method("GET")
        .uri(url)
        .body(Body::empty())?;
    let response = request_sender.send_request(request).await?;
    let body = hyper::body::to_bytes(response.into_body()).await?;
    let body_str = String::from_utf8(body.to_vec())?;
    Ok(body_str)
}

fn init_tracing_subscriber() {
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "info,".into())
        .add_directive("tokio_postgres=info".parse().unwrap())
        .add_directive("hyper=info".parse().unwrap())
        .add_directive("hyper_util=info".parse().unwrap());

    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_ansi(true)
        .with_target(true)
        .with_filter(env_filter)
        .boxed();

    let mut layers = vec![fmt_layer];

    if cfg!(debug_assertions) {
        let tracer_provider = get_tracer_provider();
        let meter_provider = init_meter_provider();
        let tracer = tracer_provider.tracer("main");

        let filter_layer = tracing_subscriber::filter::LevelFilter::from_level(Level::INFO);

        let metrics_layer = MetricsLayer::new(meter_provider.clone())
            .with_filter(filter_layer)
            .boxed();
        let telemetry_layer = OpenTelemetryLayer::new(tracer)
            .with_filter(filter_layer)
            .boxed();

        layers.push(metrics_layer);
        layers.push(telemetry_layer);
    }

    let log_file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open("./retrom.log")
        .expect("failed to open log file");

    let file_layer = tracing_subscriber::fmt::layer()
        .json()
        .with_writer(log_file)
        .boxed();

    layers.push(file_layer);

    tracing_subscriber::registry().with(layers).init();
}

fn resource() -> Resource {
    Resource::from_schema_url(
        [
            KeyValue::new(SERVICE_NAME, env!("CARGO_PKG_NAME")),
            KeyValue::new(SERVICE_VERSION, env!("CARGO_PKG_VERSION")),
        ],
        SCHEMA_URL,
    )
}

fn init_meter_provider() -> SdkMeterProvider {
    let exporter = opentelemetry_otlp::MetricExporter::builder()
        .with_tonic()
        .with_temporality(opentelemetry_sdk::metrics::Temporality::default())
        .build()
        .unwrap();

    let reader = PeriodicReader::builder(exporter, opentelemetry_sdk::runtime::Tokio)
        .with_interval(std::time::Duration::from_secs(30))
        .build();

    let meter_provider = MeterProviderBuilder::default()
        .with_resource(resource())
        .with_reader(reader)
        .build();

    global::set_meter_provider(meter_provider.clone());

    meter_provider
}

fn get_tracer_provider() -> TracerProvider {
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint("http://localhost:4317")
        .build()
        .unwrap();

    let tracer_provider = TracerProvider::builder()
        .with_batch_exporter(exporter, opentelemetry_sdk::runtime::Tokio)
        .with_sampler(Sampler::AlwaysOn)
        .with_id_generator(RandomIdGenerator::default())
        .with_max_events_per_span(64)
        .with_max_attributes_per_span(16)
        .with_resource(resource())
        .build();

    global::set_tracer_provider(tracer_provider.clone());

    tracer_provider
}
