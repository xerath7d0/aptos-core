// Copyright © Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use aptos_comparison_testing::{DataCollection, Execution};
use aptos_rest_client::Client;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use url::Url;

#[derive(Subcommand)]
pub enum Cmd {
    /// Collect and dump the data
    Dump {
        endpoint: String,
        output_path: Option<PathBuf>,
        #[clap(long, default_value_t = false)]
        overwrite: bool,
    },
    /// Execution
    Execute {
        input_path: Option<PathBuf>,
        #[clap(long, default_value_t = false)]
        compare: bool,
    },
}

#[derive(Parser)]
pub struct Argument {
    #[clap(subcommand)]
    cmd: Cmd,

    #[clap(long)]
    begin_version: u64,

    #[clap(long)]
    limit: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Argument::parse();

    match args.cmd {
        Cmd::Dump {
            endpoint,
            output_path,
            overwrite,
        } => {
            let batch_size = 100; // magic number
            let output = if let Some(path) = output_path {
                path
            } else {
                PathBuf::from(".")
            };
            let data_collector = DataCollection::new_with_rest_client(
                Client::new(Url::parse(&endpoint)?),
                output,
                batch_size,
                overwrite,
            )?;
            data_collector
                .dump_data(args.begin_version, args.limit)
                .await?;
        },
        Cmd::Execute {
            input_path,
            compare,
        } => {
            let input = if let Some(path) = input_path {
                path
            } else {
                PathBuf::from(".")
            };
            let executor = Execution::new(input, compare);
            executor.exec(args.begin_version, args.limit).await?;
            return Ok(());
        },
    };
    Ok(())
}
