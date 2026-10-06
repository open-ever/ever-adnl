/*
* Copyright (C) 2019-2023 EverX. All Rights Reserved.
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

use crate::common::{
    AdnlHandshake, AdnlStream, AdnlStreamCrypto, Query, TaggedTlObject, Timeouts
};
use rand::Rng;
use std::{convert::TryInto, net::SocketAddr, sync::Arc, time::SystemTime};
use ton_api::{deserialize_boxed, deserialize_typed, serialize_boxed,
    ton::{
        TLObject, adnl::{Message as AdnlMessage, Pong as AdnlPongBoxed},
        rpc::adnl::Ping as AdnlPing
    }
};
#[cfg(feature = "telemetry")]
use ton_api::{BoxedSerialize, ConstructorNumber};
use ever_block::{error, fail, Ed25519KeyOption, KeyOption, KeyOptionJson, Result};

#[derive(serde::Deserialize, serde::Serialize)]
pub struct AdnlClientConfigJson {
    client_key: Option<KeyOptionJson>,
    server_address: String,
    server_key: KeyOptionJson,
    timeouts: Option<Timeouts>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    max_packet_size: Option<usize>
}

impl AdnlClientConfigJson {
    pub fn with_params(server: &str, server_key: KeyOptionJson, timeouts: Option<Timeouts>) -> Self {
        AdnlClientConfigJson {
            client_key: None,
            server_address: server.to_string(),
            server_key,
            timeouts,
            max_packet_size: None
        }
    }
}

/// ADNL client configuration
pub struct AdnlClientConfig {
    client_key: Option<Arc<dyn KeyOption>>,
    server_address: SocketAddr,
    server_key: Arc<dyn KeyOption>,
    timeouts: Timeouts,
    max_packet_size: Option<usize>
}

impl AdnlClientConfig {
    /// Constructs configuration with default timeouts and unlimited packet size,
    /// a new client key is generated for each connection unless it is set
    pub fn new(server_address: SocketAddr, server_key: Arc<dyn KeyOption>) -> Self {
        AdnlClientConfig {
            client_key: None,
            server_address,
            server_key,
            timeouts: Timeouts::default(),
            max_packet_size: None
        }
    }

    /// Set client key
    pub fn with_client_key(mut self, client_key: Arc<dyn KeyOption>) -> Self {
        self.client_key = Some(client_key);
        self
    }

    /// Set timeouts
    pub fn with_timeouts(mut self, timeouts: Timeouts) -> Self {
        self.timeouts = timeouts;
        self
    }

    /// Set limit of incoming packet size, `None` is unlimited
    pub fn with_max_packet_size(mut self, max_packet_size: Option<usize>) -> Result<Self> {
        if let Some(size) = max_packet_size.filter(|size| *size < 64) {
            fail!("Max ADNL packet size {} is less than packet header size", size)
        }

        self.max_packet_size = max_packet_size;
        Ok(self)
    }

    /// Costructs new configuration from JSON string
    pub fn from_json(json: &str) -> Result<(Option<AdnlClientConfigJson>, Self)> {
        let json_config: AdnlClientConfigJson = serde_json::from_str(json)?;
        Self::from_json_config(json_config)
    }

    /// Costructs new configuration from JSON data
    pub fn from_json_config(
        json_config: AdnlClientConfigJson
    ) -> Result<(Option<AdnlClientConfigJson>, Self)> {
        let server_key = Ed25519KeyOption::from_public_key_json(&json_config.server_key)?;
        let mut result_config = None;

        let client_key = if let Some(key) = &json_config.client_key {
            Ed25519KeyOption::from_private_key_json(key)?
        } else {
            let (json, key) = Ed25519KeyOption::generate_with_json()?;
            result_config = Some(
                AdnlClientConfigJson {
                    client_key: Some(json),
                    server_address: json_config.server_address.clone(),
                    server_key: json_config.server_key,
                    timeouts: json_config.timeouts.clone(),
                    max_packet_size: json_config.max_packet_size
                }
            );
            key
        };

        let ret = AdnlClientConfig::new(json_config.server_address.parse()?, server_key)
            .with_client_key(client_key)
            .with_timeouts(json_config.timeouts.unwrap_or_default())
            .with_max_packet_size(json_config.max_packet_size)?;

        Ok((result_config, ret))
    }

    /// Get timeouts
    pub fn timeouts(&self) -> &Timeouts {
        &self.timeouts
    }

    /// Get limit of incoming packet size, `None` is unlimited
    pub fn max_packet_size(&self) -> Option<usize> {
        self.max_packet_size
    }

}

/// ADNL client
pub struct AdnlClient{
    crypto: AdnlStreamCrypto,
    stream: AdnlStream
}

impl AdnlClient {

    /// Connect to server
    pub async fn connect(config: &AdnlClientConfig) -> Result<Self> {
        let socket = if config.server_address.is_ipv4() {
            tokio::net::TcpSocket::new_v4()?
        } else {
            tokio::net::TcpSocket::new_v6()?
        };

        socket.set_reuseaddr(true)?;
        socket.set_zero_linger()?;

        let stream = tokio::time::timeout(
            config.timeouts.write(),
            socket.connect(config.server_address)
        ).await.map_err(
            |_| error!("Timeout while connecting to {}", config.server_address)
        )??;

        let mut stream = AdnlStream::from_stream_with_timeouts(stream, config.timeouts());
        Ok(
            Self {
                crypto: Self::send_init_packet(&mut stream, config).await?,
                stream
            }
        )

    }

    /// Ping server
    pub async fn ping(&mut self) -> Result<u64> {
        let now = SystemTime::now();
        let value = rand::thread_rng().gen();
        let query = TLObject::new(
            AdnlPing {
                value
            }
        );
        #[cfg(feature = "telemetry")]
        let (ConstructorNumber(tag), _) = query.serialize_boxed();
        let query = TaggedTlObject {
            object: query,
            #[cfg(feature = "telemetry")]
            tag
        };
        let answer: AdnlPongBoxed = Query::parse(self.query(&query).await?, &query.object)?;
        if answer.value() != &value {
            fail!("Bad reply to ADNL ping")
        }
        Ok(now.elapsed()?.as_secs())
    }

    /// Shutdown client
    pub async fn shutdown(mut self) -> Result<()> {
        self.stream.shutdown().await?;
        Ok(())
    }

    /// Query server
    pub async fn query(&mut self, query: &TaggedTlObject) -> Result<TLObject> {
        let (query_id, msg) = Query::build(None, query)?;
        let mut buf = serialize_boxed(&msg.object)?;
        self.crypto.send(&mut self.stream, &mut buf).await?;
        loop {
            self.crypto.receive(&mut buf, &mut self.stream).await?;
            if !buf.is_empty() {
                break;
            }
        }
        match deserialize_typed(buf)? {
            AdnlMessage::Adnl_Message_Answer(answer) =>
                if &query_id == answer.query_id.as_slice() {
                    deserialize_boxed(&answer.answer)
                } else {
                    fail!("Query ID mismatch {:?} vs {:?}", query.object, answer)
                },
            answer => fail!("Unexpected answer to query {:?}: {:?}", query.object, answer)
        }
    }

    async fn send_init_packet(
        stream: &mut AdnlStream,
        config: &AdnlClientConfig
    ) -> Result<AdnlStreamCrypto> {
        let mut buf = vec![0u8; 160];
        rand::thread_rng().fill(buf.as_mut_slice());
        let nonce = buf.as_slice().try_into()?;
        let mut ret = AdnlStreamCrypto::with_nonce_as_client(nonce)
            .with_max_packet_size(config.max_packet_size);
        if let Some(client_key) = &config.client_key {
            AdnlHandshake::build_packet(&mut buf, client_key, &config.server_key, None)?
        } else {
            AdnlHandshake::build_packet(
                &mut buf,
                &Ed25519KeyOption::generate()?,
                &config.server_key,
                None
            )?
        }
        stream.write(&mut buf).await?;

        ret.receive(&mut buf, stream).await.map_err(
            |e| error!("ADNL handshake is not confirmed: {}", e)
        )?;

        if !buf.is_empty() {
            fail!("Unexpected answer to ADNL handshake")
        }

        Ok(ret)
    }

}
