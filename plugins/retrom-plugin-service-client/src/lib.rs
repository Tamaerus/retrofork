// File: retrofork/plugins/retrom-plugin-service-client/src/lib.rs
use std::str::FromStr;
use hyper::Uri;
use retrom_codegen::retrom::{
    emulator_service_client::EmulatorServiceClient,
    game_service_client::GameServiceClient,
    metadata_service_client::MetadataServiceClient,
    platform_service_client::PlatformServiceClient,
};
use tauri::{
    plugin::{Builder, TauriPlugin}, Manager, Runtime
};
use std::error::Error as StdError;
use tower::util::ServiceExt;

mod commands;
mod desktop;
mod error;

use desktop::RetromPluginServiceClient;
pub use error::{Error, Result};

type BoxDynError = Box<dyn StdError + Send + Sync + 'static>;

type GrpcChannel = tonic::transport::Channel;

type MetadataClient = MetadataServiceClient<GrpcChannel>;
type GameClient = GameServiceClient<GrpcChannel>;
type EmulatorClient = EmulatorServiceClient<GrpcChannel>;
type PlatformClient = PlatformServiceClient<GrpcChannel>;

pub trait RetromPluginServiceClientExt<R: Runtime> {
    fn service_client(&self) -> &RetromPluginServiceClient<R>;
    async fn get_metadata_client(&self) -> Result<MetadataClient>;
    async fn get_game_client(&self) -> Result<GameClient>;
    async fn get_emulator_client(&self) -> Result<EmulatorClient>;
    async fn get_platform_client(&self) -> Result<PlatformClient>;
    fn init_plugin() -> TauriPlugin<R>;
}

impl<R: Runtime, T: Manager<R>> RetromPluginServiceClientExt<R> for T {
    fn service_client(&self) -> &RetromPluginServiceClient<R> {
        self.state::<RetromPluginServiceClient<R>>().inner()
    }

    async fn get_metadata_client(&self) -> Result<MetadataClient> {
        let state = self.service_client();
        let host = state.get_service_host().await.to_string();
        let uri = Uri::from_str(&host).map_err(|e| Error::Other(e.to_string()))?;
        let channel = tonic::transport::Channel::builder(uri).connect_lazy();
        Ok(MetadataServiceClient::new(channel))
    }

    async fn get_game_client(&self) -> Result<GameClient> {
        let state = self.service_client();
        let host = state.get_service_host().await.to_string();
        let uri = Uri::from_str(&host).map_err(|e| Error::Other(e.to_string()))?;
        let channel = tonic::transport::Channel::builder(uri).connect_lazy();
        Ok(GameServiceClient::new(channel))
    }

    async fn get_emulator_client(&self) -> Result<EmulatorClient> {
        let state = self.service_client();
        let host = state.get_service_host().await.to_string();
        let uri = Uri::from_str(&host).map_err(|e| Error::Other(e.to_string()))?;
        let channel = tonic::transport::Channel::builder(uri).connect_lazy();
        Ok(EmulatorServiceClient::new(channel))
    }

    async fn get_platform_client(&self) -> Result<PlatformClient> {
        let state = self.service_client();
        let host = state.get_service_host().await.to_string();
        let uri = Uri::from_str(&host).map_err(|e| Error::Other(e.to_string()))?;
        let channel = tonic::transport::Channel::builder(uri).connect_lazy();
        Ok(PlatformServiceClient::new(channel))
    }

    fn init_plugin() -> TauriPlugin<R> {
        Builder::new("retrom-plugin-service-client")
            .setup(|app, _api| {
                let client = RetromPluginServiceClient::new(app.clone(), "".to_string())?;
                app.manage(client);
                Ok(())
            })
            .build()
    }
    
    
    
}
