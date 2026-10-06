/*
* Copyright (C) 2019-2021 TON Labs. All Rights Reserved.
*
* Licensed under the SOFTWARE EVALUATION License (the "License"); you may not use
* this file except in compliance with the License.
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific TON DEV software governing permissions and
* limitations under the License.
*/

#![cfg(any(feature = "client", feature = "server"))]

include!("../common/src/test.rs");

#[cfg(feature = "client")]
use adnl::client::{AdnlClient, AdnlClientConfig};
#[cfg(feature = "server")]
use adnl::server::{AdnlServer, AdnlServerConfig};  
#[cfg(feature = "client")]
use std::time::Instant;
#[cfg(feature = "server")]
use std::{thread::sleep, time::Duration};    
#[cfg(all(feature = "client", feature = "server"))]
use adnl::common::Timeouts;
#[cfg(all(feature = "client", feature = "server"))]
use ever_block::{Ed25519KeyOption, Result};

#[cfg(feature = "client")]
const ADNL_CLIENT_CONFIG: &str = "{
    \"server_address\": \"127.0.0.1:4924\",
    \"server_key\": {
        \"type_id\": 1209251014,
        \"pub_key\": \"BBKmgGAxz4ZofRgMO2qhYt+K1bGlGeowukPONVAkOcU=\"
    }
}";

#[cfg(feature = "server")]
const ADNL_SERVER_CONFIG: &str = "{
    \"address\": \"0.0.0.0:4924\", 
    \"clients\": {
        \"any\": null
    },
    \"server_key\": {
        \"type_id\": 1209251014,
        \"pvt_key\": \"3CFeiTSlGkJf3D8w3ZXS4QS+6/0p+MFZGuv0XYMvMRo=\"
    }
}";

#[cfg(all(feature = "client", feature = "server"))]
async fn request_server(client: &mut AdnlClient) -> Result<()> {
    client.ping().await?;
    Ok(())
}

#[cfg(all(feature = "client", feature = "server"))]
fn init_client(config: &str, rt: &mut tokio::runtime::Runtime) -> AdnlClient {
    let (_, config) = AdnlClientConfig::from_json(config).unwrap();
    rt.block_on(AdnlClient::connect(&config)).unwrap()
}

#[cfg(all(feature = "client", feature = "server"))]
fn init_client_server_test(
    server: &str, 
    client: &str
) -> (tokio::runtime::Runtime, AdnlServer, AdnlClient) {
    let mut rt = init_test();
    let sv = init_server(server, &mut rt);
    let cl = init_client(client, &mut rt);
    (rt, sv, cl)
}

#[cfg(feature = "server")]
fn init_server(config: &str, rt: &mut tokio::runtime::Runtime) -> AdnlServer {
    let config = AdnlServerConfig::from_json(config).unwrap();
    rt.block_on(AdnlServer::listen(config, vec![])).unwrap()
}

#[cfg(feature = "server")]
#[test]
fn tcp_no_client() {
    let mut rt = init_test();
    let server = init_server(ADNL_SERVER_CONFIG, &mut rt);
    rt.block_on(
        async move {
            sleep(Duration::from_millis(500));
            server.shutdown().await;
            sleep(Duration::from_millis(500));
        }
    )
}

#[cfg(feature = "client")]
#[test]
fn tcp_no_server() {
    let (_, config )= AdnlClientConfig::from_json(ADNL_CLIENT_CONFIG).unwrap();
    let start = Instant::now();
    let rt = init_test();
    assert!(rt.block_on(AdnlClient::connect(&config)).is_err());
    assert!(start.elapsed().as_secs() < 3);
}

#[cfg(all(feature = "client", feature = "server"))]
#[test]
fn tcp_session() {
    let (rt, server, mut client) = init_client_server_test(
        ADNL_SERVER_CONFIG, 
        ADNL_CLIENT_CONFIG
    );
    rt.block_on(
       async move {
            request_server(&mut client).await.unwrap();
            request_server(&mut client).await.unwrap();
            client.shutdown().await.unwrap();
            server.shutdown().await;
            // Ensure server socket close
            sleep(Duration::from_millis(200));
        }
    )
}

#[cfg(all(feature = "client", feature = "server"))]
#[test]
fn tcp_session_without_json() {
    let rt = init_test();

    let address = "127.0.0.1:4925".parse().unwrap();
    let server_key = Ed25519KeyOption::generate().unwrap();
    let client_key = Ed25519KeyOption::generate().unwrap();
    let timeouts = Timeouts::new(Duration::from_secs(5), Duration::from_secs(5));

    let server_config = AdnlServerConfig::new(address, server_key.clone())
        .with_clients(&[client_key.clone()]).unwrap()
        .with_timeouts(timeouts.clone());

    let server_key = Ed25519KeyOption::from_public_key(
        server_key.pub_key().unwrap().try_into().unwrap()
    );

    let client_config = AdnlClientConfig::new(address, server_key.clone())
        .with_client_key(client_key)
        .with_timeouts(timeouts)
        .with_max_packet_size(Some(1024)).unwrap();

    // Generated client key is not in the server list
    let unknown_config = AdnlClientConfig::new(address, server_key.clone());
    let wrong_key_config = AdnlClientConfig::new(address, Ed25519KeyOption::generate().unwrap());

    assert!(AdnlClientConfig::new(address, server_key).with_max_packet_size(Some(32)).is_err());

    rt.block_on(
        async move {
            let server = AdnlServer::listen(server_config, vec![]).await.unwrap();
            let mut client = AdnlClient::connect(&client_config).await.unwrap();

            request_server(&mut client).await.unwrap();

            assert!(AdnlClient::connect(&unknown_config).await.is_err());
            assert!(AdnlClient::connect(&wrong_key_config).await.is_err());

            client.shutdown().await.unwrap();
            server.shutdown().await;
        }
    )
}
