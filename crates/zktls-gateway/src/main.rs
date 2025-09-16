//! zkTLS Gateway CLI Entry Point
//!
//! This is the main entry point for the zkTLS gateway command-line interface.
//! It provides a unified CLI for all zkTLS operations including proof generation,
//! verification, and server management.

use clap::{Parser, Subcommand};
use std::process;
use tracing::{info, error};
use zktls_gateway::{GatewayConfig, ZkTlsGateway, error::GatewayError};

#[derive(Parser)]
#[command(name = "zktls")]
#[command(version = zktls_gateway::VERSION)]
#[command(about = "zkTLS Gateway - Unified API and CLI for zkTLS verification")]
#[command(long_about = "A production-grade gateway providing both HTTP API and CLI interfaces for zkTLS verification across multiple zkVM platforms (SP1, RISC0).")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    
    /// Configuration file path
    #[arg(short, long, default_value = zktls_gateway::DEFAULT_CONFIG_FILE)]
    config: String,
    
    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a zkTLS proof
    Prove {
        /// Target platform (sp1, risc0)
        #[arg(short, long, default_value = "sp1")]
        platform: String,
        
        /// Input data file path
        #[arg(short, long)]
        input: String,
        
        /// Output proof file path
        #[arg(short, long, default_value = "proof.bin")]
        output: String,
    },
    
    /// Verify a zkTLS proof
    Verify {
        /// Target platform (sp1, risc0)
        #[arg(short, long, default_value = "sp1")]
        platform: String,
        
        /// Proof file path
        #[arg(short, long)]
        proof: String,
        
        /// Expected result file path (optional)
        #[arg(short, long)]
        expected: Option<String>,
    },
    
    /// Start the API server
    Server {
        /// Server port
        #[arg(short, long, default_value_t = zktls_gateway::DEFAULT_PORT)]
        port: u16,
        
        /// Server host
        #[arg(long, default_value = zktls_gateway::DEFAULT_HOST)]
        host: String,
        
        /// Default platform for server
        #[arg(short, long, default_value = "sp1")]
        platform: String,
    },
    
    /// Configuration management
    Config {
        #[command(subcommand)]
        action: ConfigCommands,
    },
    
    /// Show gateway status and information
    Status,
}

#[derive(Subcommand)]
enum ConfigCommands {
    /// Show current configuration
    Show,
    
    /// Set configuration value
    Set {
        /// Configuration key
        key: String,
        /// Configuration value
        value: String,
    },
    
    /// Initialize default configuration
    Init,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    
    // Initialize logging
    init_logging(cli.verbose);
    
    // Load configuration
    let config = match GatewayConfig::load(&cli.config) {
        Ok(config) => config,
        Err(e) => {
            error!("Failed to load configuration: {}", e);
            process::exit(1);
        }
    };
    
    // Initialize gateway
    let gateway = match ZkTlsGateway::new(config) {
        Ok(gateway) => gateway,
        Err(e) => {
            error!("Failed to initialize gateway: {}", e);
            process::exit(1);
        }
    };
    
    // Execute command
    let result = match cli.command {
        Commands::Prove { platform, input, output } => {
            info!("Generating proof for platform: {}", platform);
            gateway.prove_cli(&platform, &input, &output).await
        },
        Commands::Verify { platform, proof, expected } => {
            info!("Verifying proof for platform: {}", platform);
            gateway.verify_cli(&platform, &proof).await
        },
        Commands::Server { port, host, platform } => {
            info!("Starting API server on {}:{}", host, port);
            gateway.start_server(&host, port, &platform).await
        },
        Commands::Config { action } => {
            match action {
                ConfigCommands::Show => gateway.show_config(),
                ConfigCommands::Set { key, value } => gateway.set_config(&key, &value),
                ConfigCommands::Init => gateway.init_config(),
            }
        },
        Commands::Status => {
            gateway.get_status_cli().await
        },
    };
    
    if let Err(e) = result {
        error!("Command failed: {}", e);
        process::exit(1);
    }
}

/// Initialize logging based on verbosity level
fn init_logging(verbose: bool) {
    let level = if verbose { "debug" } else { "info" };
    
    tracing_subscriber::fmt()
        .with_env_filter(format!("zktls_gateway={},hyper=warn,tower=warn", level))
        .init();
    
    info!("zkTLS Gateway v{} initialized", zktls_gateway::VERSION);
}
