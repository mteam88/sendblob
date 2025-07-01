use alloy::{
    consensus::{SidecarBuilder, SimpleCoder},
    eips::Encodable2718,
    network::{TransactionBuilder, TransactionBuilder4844},
    primitives::{U256, address, hex, keccak256},
    providers::{Provider, ProviderBuilder},
    rpc::client::RpcClient,
    rpc::types::TransactionRequest,
    signers::Signer,
    signers::local::PrivateKeySigner,
    transports::http::Http,
};

use alloy_json_rpc::Request;
use alloy_rpc_types_mev::EthSendBundle;
use eyre::Result;
use reqwest::Client;
use reqwest::header::{HeaderMap, HeaderValue};
use std::borrow::Cow;

/// Sign the payload with the provided signer for Flashbots authentication. It returns the authentication
/// header value that can be used for `X-Flashbots-Signature`.
///
/// For more details: <https://docs.flashbots.net/flashbots-auction/advanced/rpc-endpoint#authentication>
pub async fn sign_flashbots_payload<S: Signer + Sync>(
    body: String,
    signer: &S,
) -> Result<String, alloy::signers::Error> {
    let message_hash = keccak256(body.as_bytes()).to_string();
    let signature = signer.sign_message(message_hash.as_bytes()).await?;
    Ok(format!(
        "{}:{}",
        signer.address(),
        hex::encode_prefixed(signature.as_bytes())
    ))
}

#[tokio::main]
async fn main() -> Result<()> {
    let builder_url = "https://relay.flashbots.net";

    // Signer for Flashbots authentication
    let fb_signer = PrivateKeySigner::random();

    let signer: PrivateKeySigner =
        dotenv::var("PRIVATE_KEY").unwrap()
            .parse()
            .unwrap();
    let provider = ProviderBuilder::new()
        .wallet(signer.clone())
        .connect_http("https://eth.drpc.org".parse().unwrap());

    println!("Signer: {:?}", signer.address());

    // Create a sidecar with some data.
    let sidecar: SidecarBuilder<SimpleCoder> = SidecarBuilder::from_slice(b"Blobs are fun!");
    let sidecar = sidecar.build()?;

    let vitalik = address!("0xd8da6bf26964af9d7eed9e03e53415d37aa96045");

    let mut tx = TransactionRequest::default()
        // .with_from(signer.address())
        .with_to(vitalik)
        .with_blob_sidecar(sidecar)
        .with_value(U256::from(0))
        .with_gas_limit(100000);

    tx.prep_for_submission();

    let sendable_tx = provider.fill(tx.clone()).await?;

    println!("Sendable transaction: {:?}", sendable_tx);

    // get raw tx
    let raw_tx = sendable_tx
        .as_envelope()
        .unwrap()
        .encoded_2718()
        .into();

    // println!("Raw transaction: {:?}", raw_tx);

    // Create the bundle with the raw transaction
    let current_block = provider.get_block_number().await?;
    let bundle = EthSendBundle {
        txs: vec![raw_tx],
        block_number: current_block + 1, // Next block
        ..Default::default()
    };

    // Prepare the header for Flashbots authentication
    let mut headers = HeaderMap::new();
    let req = Request::<Vec<EthSendBundle>>::new(
        Cow::Borrowed("eth_sendBundle"),
        0.into(),
        vec![bundle.clone()],
    );
    let body = serde_json::to_string(&req)?;
    let signature = sign_flashbots_payload(body, &fb_signer).await?;
    headers.insert("X-Flashbots-Signature", HeaderValue::try_from(signature)?);

    // Build the http client with the header
    let client_with_auth = Client::builder().default_headers(headers).build()?;
    let http = Http::with_client(client_with_auth, builder_url.parse()?);
    let rpc_client = RpcClient::new(http, false);
    let builder_provider = ProviderBuilder::new().connect_client(rpc_client);

    // Send the bundle to the builder
    let resp = builder_provider
        .raw_request::<_, serde_json::Value>(Cow::Borrowed("eth_sendBundle"), (bundle,))
        .await;

    match resp {
        Ok(resp) => println!("Sent bundle successfully: {resp:?}"),
        Err(err) => println!("Failed to send bundle: {err:?}"),
    }

    Ok(())
}
