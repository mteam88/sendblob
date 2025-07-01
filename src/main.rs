use alloy::{
    consensus::{SidecarBuilder, SimpleCoder},
    eips::Encodable2718,
    network::{TransactionBuilder, TransactionBuilder4844},
    primitives::{U256, address},
    providers::{Provider, ProviderBuilder},
    rpc::types::TransactionRequest,
    signers::local::PrivateKeySigner,
};

use alloy_provider::ext::MevApi;

use alloy_rpc_types_mev::EthSendBundle;
use eyre::Result;

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

    let tx = TransactionRequest::default()
        // .with_from(signer.address())
        .with_to(vitalik)
        .with_blob_sidecar(sidecar)
        .with_value(U256::from(0))
        .with_gas_limit(100000);

    let raw_tx = provider.fill(tx.clone()).await?
        .as_envelope()
        .unwrap()
        .encoded_2718()
        .into();

    let bundle = EthSendBundle {
        txs: vec![raw_tx],
        block_number: provider.get_block_number().await? + 1,
        ..Default::default()
    };

    let flashbots_provider = ProviderBuilder::new()
        .connect_http(builder_url.parse().unwrap());
    let resp = flashbots_provider.send_bundle(bundle).with_auth(fb_signer.clone()).await;

    match resp {
        Ok(resp) => println!("Sent bundle successfully: {resp:?}"),
        Err(err) => println!("Failed to send bundle: {err:?}"),
    }

    Ok(())
}
