use clap::{Args, Parser, Subcommand};

#[derive(Debug, Parser)]
#[clap(author, version, about)]
pub struct Cli {
    #[clap(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Real-time feature extraction
    Realtime {
        /// The network interface to capture packets from
        interface: String,

        #[clap(value_enum)]
        flow_type: FlowType,

        /// The maximum lifespan of a flow in seconds
        lifespan: u64,

        /// Whether not to include contaminant features
        #[clap(short, long, action = clap::ArgAction::SetTrue)]
        no_contaminant_features: bool,

        /// Whether to add the header
        #[clap(short, long, action = clap::ArgAction::SetTrue)]
        feature_header: bool,

        /// Only ingress traffic will be captured
        #[clap(short, long, action = clap::ArgAction::SetTrue)]
        only_ingress: bool,

        /// Output method
        #[clap(flatten)]
        export_method: Output,

        /// The print interval for open flows in seconds, needs to be smaller than the flow maximum lifespan
        #[clap(long)]
        interval: Option<u64>,
    },

    /// Feature extraction from a pcap file
    Pcap {
        #[clap(value_enum)]
        flow_type: FlowType,

        /// The maximum lifespan of a flow in seconds
        lifespan: u64,

        /// The relative path to the pcap file
        path: String,

        /// Whether not to include contaminant features
        #[clap(short, long, action = clap::ArgAction::SetTrue)]
        no_contaminant_features: bool,

        /// Whether to add the header
        #[clap(short, long, action = clap::ArgAction::SetTrue)]
        feature_header: bool,

        /// Output method
        #[clap(flatten)]
        export_method: Output,
    },
}

#[derive(Args, Debug, Clone)]
pub struct Output {
    /// Output method
    #[clap(value_enum)]
    pub method: ExportMethodType,

    /// File path for output (used if method is Csv)
    #[clap(required_if_eq("method", "Csv"))]
    pub export_path: Option<String>,
}

#[derive(clap::ValueEnum, Clone, Debug)]
pub enum ExportMethodType {
    /// The output will be printed to the console
    Print,

    /// The output will be written to a CSV file
    Csv,
}

#[derive(clap::ValueEnum, Clone, Debug)]
pub enum FlowType {
    /// A basic flow that stores the basic features of a flow.
    BasicFlow,

    /// Represents the CIC Flow, giving 83 features.
    CicFlow,

    /// Represents the CIDDS Flow, giving 10 features.
    CiddsFlow,

    /// Represents a nfstream inspired flow, giving 69 features.
    NfFlow,

    /// Represents the NTL Flow, giving 120 features.
    NtlFlow,

    /// Represents a flow that you can implement yourself.
    CustomFlow,
}
