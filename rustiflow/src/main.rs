mod args;
mod flows;
mod output;
mod utils;

use crate::{
    flows::{cic_flow::CicFlow, ntl_flow::NTLFlow},
    output::Export,
    utils::utils::{create_flow_id, get_duration},
};
use args::{Cli, Commands, ExportMethodType, FlowType};
use aya::{
    include_bytes_aligned,
    maps::AsyncPerfEventArray,
    programs::{tc, SchedClassifier, TcAttachType},
    util::online_cpus,
    Ebpf,
};
use bytes::BytesMut;
use chrono::{DateTime, Utc};
use clap::Parser;
use common::{BasicFeaturesIpv4, BasicFeaturesIpv6};
use core::panic;
use dashmap::DashMap;
use flows::{
    basic_flow::BasicFlow, cidds_flow::CiddsFlow, custom_flow::CustomFlow, flow::Flow,
    nf_flow::NfFlow,
};
use lazy_static::lazy_static;
use log::{debug, error, info};
use pnet::packet::{
    ethernet::{EtherTypes, EthernetPacket},
    ip::IpNextHeaderProtocols,
    ipv4::Ipv4Packet,
    ipv6::Ipv6Packet,
    tcp::TcpPacket,
    Packet,
};
use std::{
    fs::{File, OpenOptions},
    io::{BufWriter, Read, Write},
    ops::{Deref, DerefMut},
    sync::atomic::{AtomicUsize, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};
use std::{
    net::{Ipv4Addr, Ipv6Addr},
    sync::{Arc, Mutex},
    time::Instant,
};
use tokio::time::{self, Duration};
use tokio::{signal, task};
use utils::utils::BasicFeatures;

lazy_static! {
    static ref EXPORT_FUNCTION: Arc<Mutex<Option<Export>>> = Arc::new(Mutex::new(None));
    static ref EXPORT_FILE: Arc<Mutex<Option<BufWriter<File>>>> = Arc::new(Mutex::new(None));
    static ref FLUSH_COUNTER: Arc<Mutex<Option<u8>>> = Arc::new(Mutex::new(Some(0)));
    static ref AMOUNT_OF_FLOWS: Arc<Mutex<Option<usize>>> = Arc::new(Mutex::new(Some(0)));
    static ref NO_CONTAMINANT_FEATURES: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));
    static ref PATH: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));
}

const UNDERLINE: &str = "#############################################################";
const DIVIDER: &str = "-------------------------------------------------------------";

#[tokio::main]
async fn main() {
    env_logger::init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Realtime {
            interface,
            flow_type,
            export_method,
            lifespan,
            no_contaminant_features,
            feature_header,
            only_ingress,
            interval,
        } => {
            if let Some(interval) = interval {
                if interval >= lifespan {
                    panic!("The interval needs to be smaller than the lifespan!");
                }
            }
            info!("{UNDERLINE}");
            info!("Starting the feature extraction tool in realtime mode...");
            info!("{UNDERLINE}");

            let mut ncf = NO_CONTAMINANT_FEATURES.lock().unwrap();
            *ncf = no_contaminant_features;

            // needed to be dropped, because he stayed in scope.
            drop(ncf);

            match export_method.method {
                ExportMethodType::Print => {
                    info!("Selecting the print export method...");
                    info!("{DIVIDER}");

                    let func = output::print::print;
                    let mut export_func = EXPORT_FUNCTION.lock().unwrap();
                    *export_func = Some(func);
                    drop(export_func);
                }
                ExportMethodType::Csv => {
                    let func = output::csv::export_to_csv;
                    let mut export_func = EXPORT_FUNCTION.lock().unwrap();
                    *export_func = Some(func);

                    if let Some(path) = export_method.export_path {
                        info!(
                            "Selecting the CSV export method with output file: {:?} ...",
                            path
                        );
                        info!("{DIVIDER}");

                        let mut static_path = PATH.lock().unwrap();
                        *static_path = path.clone();

                        let file = OpenOptions::new()
                            .create(true)
                            .append(true)
                            .open(path)
                            .unwrap_or_else(|err| {
                                panic!("Error opening file: {:?}", err);
                            });
                        let mut export_file = EXPORT_FILE.lock().unwrap();
                        *export_file = Some(BufWriter::new(file));
                    }
                    drop(export_func);
                }
            }

            match flow_type {
                FlowType::BasicFlow => {
                    info!("Selecting the basic flow type...");
                    info!("{DIVIDER}");
                    info!("Starting!");
                    info!("{UNDERLINE}");

                    if let Err(err) = handle_realtime::<BasicFlow>(
                        interface,
                        interval,
                        lifespan,
                        only_ingress,
                        feature_header,
                    )
                    .await
                    {
                        error!("Error: {:?}", err);
                    }
                }
                FlowType::CicFlow => {
                    info!("Selecting the CIC flow type...");
                    info!("{DIVIDER}");
                    info!("Starting!");
                    info!("{UNDERLINE}");

                    if let Err(err) = handle_realtime::<CicFlow>(
                        interface,
                        interval,
                        lifespan,
                        only_ingress,
                        feature_header,
                    )
                    .await
                    {
                        error!("Error: {:?}", err);
                    }
                }
                FlowType::CiddsFlow => {
                    info!("Selecting the CIDDS flow type...");
                    info!("{DIVIDER}");
                    info!("Starting!");
                    info!("{UNDERLINE}");

                    if let Err(err) = handle_realtime::<CiddsFlow>(
                        interface,
                        interval,
                        lifespan,
                        only_ingress,
                        feature_header,
                    )
                    .await
                    {
                        error!("Error: {:?}", err);
                    }
                }
                FlowType::NfFlow => {
                    info!("Selecting the NF flow type...");
                    info!("{DIVIDER}");
                    info!("Starting!");
                    info!("{UNDERLINE}");

                    if let Err(err) = handle_realtime::<NfFlow>(
                        interface,
                        interval,
                        lifespan,
                        only_ingress,
                        feature_header,
                    )
                    .await
                    {
                        error!("Error: {:?}", err);
                    }
                }
                FlowType::NtlFlow => {
                    info!("Selecting the Ntl flow type...");
                    info!("{DIVIDER}");
                    info!("Starting!");
                    info!("{UNDERLINE}");

                    if let Err(err) = handle_realtime::<NTLFlow>(
                        interface,
                        interval,
                        lifespan,
                        only_ingress,
                        feature_header,
                    )
                    .await
                    {
                        error!("Error: {:?}", err);
                    }
                }
                FlowType::CustomFlow => {
                    info!("Selecting the custom flow type...");
                    info!("{DIVIDER}");
                    info!("Starting!");
                    info!("{UNDERLINE}");

                    if let Err(err) = handle_realtime::<CustomFlow>(
                        interface,
                        interval,
                        lifespan,
                        only_ingress,
                        feature_header,
                    )
                    .await
                    {
                        error!("Error: {:?}", err);
                    }
                }
            }
        }
        Commands::Pcap {
            path,
            flow_type,
            lifespan,
            no_contaminant_features,
            feature_header,
            export_method,
        } => {
            let mut ncf = NO_CONTAMINANT_FEATURES.lock().unwrap();
            *ncf = no_contaminant_features;

            // needed to be dropped, because he stayed in scope.
            drop(ncf);

            info!("{UNDERLINE}");
            info!("Starting the feature extraction tool in pcap mode...");
            info!("{UNDERLINE}");

            match export_method.method {
                ExportMethodType::Print => {
                    info!("Selecting the print export method...");
                    info!("{DIVIDER}");

                    let func = output::print::print;
                    let mut export_func = EXPORT_FUNCTION.lock().unwrap();
                    *export_func = Some(func);
                }
                ExportMethodType::Csv => {
                    let func = output::csv::export_to_csv;
                    let mut export_func = EXPORT_FUNCTION.lock().unwrap();
                    *export_func = Some(func);

                    if let Some(path) = export_method.export_path {
                        info!(
                            "Selecting the CSV export method with output file: {:?} ...",
                            path
                        );
                        info!("{DIVIDER}");

                        let file = OpenOptions::new()
                            .create(true)
                            .append(true)
                            .open(path)
                            .unwrap_or_else(|err| {
                                panic!("Error opening file: {:?}", err);
                            });
                        let mut export_file = EXPORT_FILE.lock().unwrap();
                        *export_file = Some(BufWriter::new(file));
                    }
                }
            }

            match flow_type {
                FlowType::BasicFlow => {
                    info!("Selecting the  basic flow type..");
                    info!("{DIVIDER}");
                    info!("Starting!");
                    info!("{UNDERLINE}");

                    read_pcap_file::<BasicFlow>(&path, lifespan, feature_header).await
                }
                FlowType::CicFlow => {
                    info!("Selecting the CIC flow type...");
                    info!("{DIVIDER}");
                    info!("Starting!");
                    info!("{UNDERLINE}");

                    read_pcap_file::<CicFlow>(&path, lifespan, feature_header).await
                }
                FlowType::CiddsFlow => {
                    info!("Selecting the CIDDS flow type...");
                    info!("{DIVIDER}");
                    info!("Starting!");
                    info!("{UNDERLINE}");

                    read_pcap_file::<CiddsFlow>(&path, lifespan, feature_header).await
                }
                FlowType::NfFlow => {
                    info!("Selecting the NF flow type...");
                    info!("{DIVIDER}");
                    info!("Starting!");
                    info!("{UNDERLINE}");

                    read_pcap_file::<NfFlow>(&path, lifespan, feature_header).await
                }
                FlowType::NtlFlow => {
                    info!("Selecting the Ntl flow type...");
                    info!("{DIVIDER}");
                    info!("Starting!");
                    info!("{UNDERLINE}");

                    read_pcap_file::<NTLFlow>(&path, lifespan, feature_header).await
                }
                FlowType::CustomFlow => {
                    info!("Selecting the custom flow type...");
                    info!("{DIVIDER}");
                    info!("Starting!");
                    info!("{UNDERLINE}");

                    read_pcap_file::<CustomFlow>(&path, lifespan, feature_header).await
                }
            }
        }
    }
}

async fn handle_realtime<T>(
    interface: String,
    interval: Option<u64>,
    lifespan: u64,
    only_ingress: bool,
    header: bool,
) -> Result<(), anyhow::Error>
where
    T: Flow + Send + Sync + 'static,
{
    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // Loading the eBPF program for egress, the macros make sure the correct file is loaded
    #[cfg(debug_assertions)]
    let mut bpf_egress_ipv4 = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/rustiflow-ebpf-ipv4"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf_egress_ipv4 = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/rustiflow-ebpf-ipv4"
    ))?;

    #[cfg(debug_assertions)]
    let mut bpf_egress_ipv6 = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/rustiflow-ebpf-ipv6"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf_egress_ipv6 = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/rustiflow-ebpf-ipv6"
    ))?;

    // Loading the eBPF program for ingress, the macros make sure the correct file is loaded
    #[cfg(debug_assertions)]
    let mut bpf_ingress_ipv4 = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/rustiflow-ebpf-ipv4"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf_ingress_ipv4 = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/rustiflow-ebpf-ipv4"
    ))?;

    #[cfg(debug_assertions)]
    let mut bpf_ingress_ipv6 = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/rustiflow-ebpf-ipv6"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf_ingress_ipv6 = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/rustiflow-ebpf-ipv6"
    ))?;

    if !only_ingress {
        // Loading and attaching the eBPF program function for egress
        let _ = tc::qdisc_add_clsact(interface.as_str());
        let program_egress_ipv4: &mut SchedClassifier = bpf_egress_ipv4
            .program_mut("tc_flow_track")
            .unwrap()
            .try_into()?;
        program_egress_ipv4.load()?;
        program_egress_ipv4.attach(&interface, TcAttachType::Egress)?;

        let _ = tc::qdisc_add_clsact(interface.as_str());
        let program_egress_ipv6: &mut SchedClassifier = bpf_egress_ipv6
            .program_mut("tc_flow_track")
            .unwrap()
            .try_into()?;
        program_egress_ipv6.load()?;
        program_egress_ipv6.attach(&interface, TcAttachType::Egress)?;
    }

    // Loading and attaching the eBPF program function for ingress
    let _ = tc::qdisc_add_clsact(interface.as_str());
    let program_ingress_ipv4: &mut SchedClassifier = bpf_ingress_ipv4
        .program_mut("tc_flow_track")
        .unwrap()
        .try_into()?;
    program_ingress_ipv4.load()?;
    program_ingress_ipv4.attach(&interface, TcAttachType::Ingress)?;

    let _ = tc::qdisc_add_clsact(interface.as_str());
    let program_ingress_ipv6: &mut SchedClassifier = bpf_ingress_ipv6
        .program_mut("tc_flow_track")
        .unwrap()
        .try_into()?;
    program_ingress_ipv6.load()?;
    program_ingress_ipv6.attach(&interface, TcAttachType::Ingress)?;

    // Attach to the event arrays
    let mut flows_egress_ipv4 =
        AsyncPerfEventArray::try_from(bpf_egress_ipv4.take_map("EVENTS_IPV4").unwrap())?;

    let mut flows_egress_ipv6 =
        AsyncPerfEventArray::try_from(bpf_egress_ipv6.take_map("EVENTS_IPV6").unwrap())?;

    let mut flows_ingress_ipv4 =
        AsyncPerfEventArray::try_from(bpf_ingress_ipv4.take_map("EVENTS_IPV4").unwrap())?;

    let mut flows_ingress_ipv6 =
        AsyncPerfEventArray::try_from(bpf_ingress_ipv6.take_map("EVENTS_IPV6").unwrap())?;

    let flow_map_ipv4: Arc<DashMap<String, T>> = Arc::new(DashMap::new());

    let flow_map_ipv6: Arc<DashMap<String, T>> = Arc::new(DashMap::new());

    let total_lost_events = Arc::new(AtomicUsize::new(0));

    // Use all online CPUs to process the events in the user space
    for cpu_id in online_cpus()? {
        let mut buf_egress_ipv4 = flows_egress_ipv4.open(cpu_id, None)?;
        let flow_map_clone_egress_ipv4 = flow_map_ipv4.clone();
        let total_lost_events_clone_egress_ipv4 = total_lost_events.clone();

        task::spawn(async move {
            // 10 buffers with 98_304 bytes each, meaning a capacity of 4096 packets per buffer (24 bytes per packet)
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(24 * 4096))
                .collect::<Vec<_>>();

            loop {
                let events = buf_egress_ipv4.read_events(&mut buffers).await.unwrap();
                total_lost_events_clone_egress_ipv4.fetch_add(events.lost, Ordering::SeqCst);

                for buf in buffers.iter_mut().take(events.read) {
                    let ptr = buf.as_ptr() as *const BasicFeaturesIpv4;
                    let data = unsafe { ptr.read_unaligned() };

                    process_packet_ipv4(&data, &flow_map_clone_egress_ipv4, false, None, None);
                }
            }
        });

        let mut buf_ingress_ipv4 = flows_ingress_ipv4.open(cpu_id, None)?;
        let flow_map_clone_ingress_ipv4 = flow_map_ipv4.clone();
        let total_lost_events_clone_ingress_ipv4 = total_lost_events.clone();

        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(24 * 4096))
                .collect::<Vec<_>>();

            loop {
                let events = buf_ingress_ipv4.read_events(&mut buffers).await.unwrap();
                total_lost_events_clone_ingress_ipv4.fetch_add(events.lost, Ordering::SeqCst);

                for buf in buffers.iter_mut().take(events.read) {
                    let ptr = buf.as_ptr() as *const BasicFeaturesIpv4;
                    let data = unsafe { ptr.read_unaligned() };

                    process_packet_ipv4(&data, &flow_map_clone_ingress_ipv4, true, None, None);
                }
            }
        });

        let mut buf_egress_ipv6 = flows_egress_ipv6.open(cpu_id, None)?;
        let flow_map_clone_egress_ipv6 = flow_map_ipv6.clone();
        let total_lost_events_clone_egress_ipv6 = total_lost_events.clone();

        task::spawn(async move {
            // 10 buffers with 196_608 bytes each, meaning a capacity of 4096 packets per buffer (48 bytes per packet)
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(48 * 4096))
                .collect::<Vec<_>>();

            loop {
                let events = buf_egress_ipv6.read_events(&mut buffers).await.unwrap();
                total_lost_events_clone_egress_ipv6.fetch_add(events.lost, Ordering::SeqCst);

                for buf in buffers.iter_mut().take(events.read) {
                    let ptr = buf.as_ptr() as *const BasicFeaturesIpv6;
                    let data = unsafe { ptr.read_unaligned() };

                    process_packet_ipv6(&data, &flow_map_clone_egress_ipv6, false, None, None);
                }
            }
        });

        let mut buf_ingress_ipv6 = flows_ingress_ipv6.open(cpu_id, None)?;
        let flow_map_clone_ingress_ipv6 = flow_map_ipv6.clone();
        let total_lost_events_clone_ingress_ipv6 = total_lost_events.clone();

        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(48 * 4096))
                .collect::<Vec<_>>();

            loop {
                let events = buf_ingress_ipv6.read_events(&mut buffers).await.unwrap();
                total_lost_events_clone_ingress_ipv6.fetch_add(events.lost, Ordering::SeqCst);

                for buf in buffers.iter_mut().take(events.read) {
                    let ptr = buf.as_ptr() as *const BasicFeaturesIpv6;
                    let data = unsafe { ptr.read_unaligned() };

                    process_packet_ipv6(&data, &flow_map_clone_ingress_ipv6, true, None, None);
                }
            }
        });
    }

    if let Some(interval) = interval {
        let flow_map_print_ipv4 = flow_map_ipv4.clone();
        let flow_map_print_ipv6 = flow_map_ipv6.clone();
        task::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(interval));
            loop {
                interval.tick().await;
                for entry in flow_map_print_ipv4.iter() {
                    let flow = entry.value();
                    if *NO_CONTAMINANT_FEATURES.lock().unwrap().deref() {
                        export(&flow.dump_without_contamination());
                    } else {
                        export(&flow.dump());
                    }
                }
                for entry in flow_map_print_ipv6.iter() {
                    let flow = entry.value();
                    if *NO_CONTAMINANT_FEATURES.lock().unwrap().deref() {
                        export(&flow.dump_without_contamination());
                    } else {
                        export(&flow.dump());
                    }
                }
            }
        });
    }

    let flow_map_end_ipv4 = flow_map_ipv4.clone();
    let flow_map_end_ipv6 = flow_map_ipv6.clone();
    task::spawn(async move {
        let mut interval = time::interval(Duration::from_secs(2));
        loop {
            interval.tick().await;
            let timestamp = Utc::now();

            // Collect keys to remove
            let mut keys_to_remove_ipv4 = Vec::new();
            for entry in flow_map_end_ipv4.iter() {
                let flow = entry.value();
                let end = get_duration(flow.get_first_timestamp(), timestamp) / 1_000_000.0;

                if end >= lifespan as f64 {
                    if *NO_CONTAMINANT_FEATURES.lock().unwrap().deref() {
                        export(&flow.dump_without_contamination());
                    } else {
                        export(&flow.dump());
                    }
                    keys_to_remove_ipv4.push(entry.key().clone());
                }
            }

            // Collect keys to remove
            let mut keys_to_remove_ipv6 = Vec::new();
            for entry in flow_map_end_ipv6.iter() {
                let flow = entry.value();
                let end = get_duration(flow.get_first_timestamp(), timestamp) / 1_000_000.0;

                if end >= lifespan as f64 {
                    if *NO_CONTAMINANT_FEATURES.lock().unwrap().deref() {
                        export(&flow.dump_without_contamination());
                    } else {
                        export(&flow.dump());
                    }
                    keys_to_remove_ipv6.push(entry.key().clone());
                }
            }

            // Remove entries outside of the iteration
            for key in keys_to_remove_ipv4 {
                flow_map_end_ipv4.remove(&key);
            }

            // Remove entries outside of the iteration
            for key in keys_to_remove_ipv6 {
                flow_map_end_ipv6.remove(&key);
            }
        }
    });

    info!("Waiting for Ctrl-C...");

    if header {
        if *NO_CONTAMINANT_FEATURES.lock().unwrap().deref() {
            export(&T::get_features_without_contamination());
        } else {
            export(&T::get_features());
        }
    }

    signal::ctrl_c().await?;

    for entry in flow_map_ipv4.iter() {
        let flow = entry.value();
        if *NO_CONTAMINANT_FEATURES.lock().unwrap().deref() {
            export(&flow.dump_without_contamination());
        } else {
            export(&flow.dump());
        }
    }

    for entry in flow_map_ipv6.iter() {
        let flow = entry.value();
        if *NO_CONTAMINANT_FEATURES.lock().unwrap().deref() {
            export(&flow.dump_without_contamination());
        } else {
            export(&flow.dump());
        }
    }

    if let Some(export_file) = EXPORT_FILE.lock().unwrap().deref_mut() {
        export_file.flush()?;
    }

    info!("{UNDERLINE}");
    info!("A small report:");
    info!("{UNDERLINE}");

    info!(
        "{} events were lost",
        total_lost_events.load(Ordering::SeqCst)
    );
    info!("{DIVIDER}");
    info!("Exiting...");

    Ok(())
}

async fn read_pcap_file<T>(path: &str, lifespan: u64, header: bool)
where
    T: Flow + Send + Sync + 'static,
{
    let start = Instant::now();
    let mut amount_of_packets = 0;

    // Define constants for Linux cooked capture EtherTypes
    const SLL_IPV4: u16 = 0x0800;
    const SLL_IPV6: u16 = 0x86DD;

    let flow_map_ipv4: Arc<DashMap<String, T>> = Arc::new(DashMap::new());
    let flow_map_ipv6: Arc<DashMap<String, T>> = Arc::new(DashMap::new());

    info!("Reading the pcap file: {:?} ...", path);

    let mut cap = match pcap::Capture::from_file(path) {
        Ok(c) => c,
        Err(e) => {
            error!("Error opening file: {:?}", e);
            return;
        }
    };

    if header {
        if *NO_CONTAMINANT_FEATURES.lock().unwrap().deref() {
            export(&T::get_features_without_contamination());
        } else {
            export(&T::get_features());
        }
    }
    while let Ok(packet) = cap.next_packet() {
        let ts = packet.header.ts;

        let system_time = timeval_to_system_time(ts.tv_sec, ts.tv_usec);
        let now = SystemTime::now();

        let elapsed_duration = match now.duration_since(system_time) {
            Ok(duration) => duration,
            Err(e) => {
                error!("Error calculating duration: {:?}", e);
                Duration::new(0, 0)
            }
        };

        let ts_instant = Instant::now() - elapsed_duration;
        let ts_datetime = system_time_to_datetime(system_time);

        if let Some(ethernet) = EthernetPacket::new(packet.data) {
            match ethernet.get_ethertype() {
                EtherTypes::Ipv4 => {
                    if let Some(ipv4_packet) = Ipv4Packet::new(ethernet.payload()) {
                        if let Some(features_ipv4) = extract_ipv4_features(&ipv4_packet) {
                            amount_of_packets += 1;
                            if amount_of_packets % 10_000 == 0 {
                                info!("{} packets have been processed...", amount_of_packets);
                            }
                            redirect_packet_ipv4(&features_ipv4, &flow_map_ipv4, ts_instant, ts_datetime);
                        }
                    }
                }
                EtherTypes::Ipv6 => {
                    if let Some(ipv6_packet) = Ipv6Packet::new(ethernet.payload()) {
                        if let Some(features_ipv6) = extract_ipv6_features(&ipv6_packet) {
                            amount_of_packets += 1;
                            if amount_of_packets % 10_000 == 0 {
                                info!("{} packets have been processed...", amount_of_packets);
                            }
                            redirect_packet_ipv6(&features_ipv6, &flow_map_ipv6, ts_instant, ts_datetime);
                        }
                    }
                }
                _ => {
                    let ethertype = u16::from_be_bytes([packet.data[14], packet.data[15]]);
                    match ethertype {
                        SLL_IPV4 => {
                            if let Some(ipv4_packet) = Ipv4Packet::new(&packet.data[16..]) {
                                if let Some(features_ipv4) = extract_ipv4_features(&ipv4_packet) {
                                    amount_of_packets += 1;
                                    if amount_of_packets % 10_000 == 0 {
                                        info!(
                                            "{} packets have been processed...",
                                            amount_of_packets
                                        );
                                    }
                                    redirect_packet_ipv4(
                                        &features_ipv4,
                                        &flow_map_ipv4,
                                        ts_instant,
                                        ts_datetime,
                                    );
                                }
                            }
                        }
                        SLL_IPV6 => {
                            if let Some(ipv6_packet) = Ipv6Packet::new(&packet.data[16..]) {
                                if let Some(features_ipv6) = extract_ipv6_features(&ipv6_packet) {
                                    amount_of_packets += 1;
                                    if amount_of_packets % 10_000 == 0 {
                                        info!(
                                            "{} packets have been processed...",
                                            amount_of_packets
                                        );
                                    }
                                    redirect_packet_ipv6(
                                        &features_ipv6,
                                        &flow_map_ipv6,
                                        ts_instant,
                                        ts_datetime,
                                    );
                                }
                            }
                        }
                        _ => {
                            debug!("Unknown SLL EtherType!");
                        }
                    }
                }
            }
        } else {
            error!("Error parsing packet...");
        }
    }

    let flow_map_end_ipv4 = flow_map_ipv4.clone();
    let flow_map_end_ipv6 = flow_map_ipv6.clone();
    task::spawn(async move {
        let mut interval = time::interval(Duration::from_secs(2));
        loop {
            interval.tick().await;
            let timestamp = Utc::now();

            // Collect keys to remove
            let mut keys_to_remove_ipv4 = Vec::new();
            for entry in flow_map_end_ipv4.iter() {
                let flow = entry.value();
                let end = get_duration(flow.get_first_timestamp(), timestamp) / 1_000_000.0;

                if end >= lifespan as f64 {
                    if *NO_CONTAMINANT_FEATURES.lock().unwrap().deref() {
                        export(&flow.dump_without_contamination());
                    } else {
                        export(&flow.dump());
                    }
                    keys_to_remove_ipv4.push(entry.key().clone());
                }
            }

            // Collect keys to remove
            let mut keys_to_remove_ipv6 = Vec::new();
            for entry in flow_map_end_ipv6.iter() {
                let flow = entry.value();
                let end = get_duration(flow.get_first_timestamp(), timestamp) / 1_000_000.0;

                if end >= lifespan as f64 {
                    if *NO_CONTAMINANT_FEATURES.lock().unwrap().deref() {
                        export(&flow.dump_without_contamination());
                    } else {
                        export(&flow.dump());
                    }
                    keys_to_remove_ipv6.push(entry.key().clone());
                }
            }

            // Remove entries outside of the iteration
            for key in keys_to_remove_ipv4 {
                flow_map_end_ipv4.remove(&key);
            }

            // Remove entries outside of the iteration
            for key in keys_to_remove_ipv6 {
                flow_map_end_ipv6.remove(&key);
            }
        }
    });

    for entry in flow_map_ipv4.iter() {
        let flow = entry.value();
        if *NO_CONTAMINANT_FEATURES.lock().unwrap().deref() {
            export(&flow.dump_without_contamination());
        } else {
            export(&flow.dump());
        }
    }

    for entry in flow_map_ipv6.iter() {
        let flow = entry.value();
        if *NO_CONTAMINANT_FEATURES.lock().unwrap().deref() {
            export(&flow.dump_without_contamination());
        } else {
            export(&flow.dump());
        }
    }

    if let Some(export_file) = EXPORT_FILE.lock().unwrap().deref_mut() {
        let _ = export_file.flush();
    }

    info!("{UNDERLINE}");
    info!("A small report:");
    info!("{UNDERLINE}");

    let end = Instant::now();
    info!("{} packets processed", amount_of_packets);
    info!(
        "Duration: {:?} milliseconds",
        end.duration_since(start).as_millis()
    );
}

/// Export the flow to the set export function.
///
/// ### Arguments
///
/// * `output` - The output to export.
fn export(output: &String) {
    let export_func = EXPORT_FUNCTION.lock().unwrap();
    let amount_of_flows = AMOUNT_OF_FLOWS.lock().unwrap();

    if let Some(function) = export_func.deref() {
        let mut export_file_option = EXPORT_FILE.lock().unwrap();
        let mut flush_counter_option = FLUSH_COUNTER.lock().unwrap();

        if let Some(ref mut flush_counter) = flush_counter_option.deref_mut() {
            amount_of_flows.deref().map(|mut amount| {
                amount += 1;
                if amount % 1000 == 0 {
                    info!("{} flows have been processed...", amount);
                }
                if amount % 100_000 == 0 {
                    info!("Opening new file...");
                    if let Some(file) = export_file_option.deref_mut() {
                        file.flush().unwrap();
                    }

                    let path = PATH.lock().unwrap();

                    let file = OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(
                            path.clone()
                                .replace(".csv", format!("_{}.csv", amount).as_str()),
                        )
                        .unwrap_or_else(|err| {
                            panic!("Error opening file: {:?}", err);
                        });

                    *export_file_option = Some(BufWriter::new(file));
                }
            });
            function(&output, export_file_option.deref_mut(), flush_counter);
        } else {
            error!("No export file set...")
        }
    } else {
        error!("No export function set...")
    }
}

/// Processes an ipv4 packet and updates the flow map.
///
/// ### Arguments
///
/// * `data` - Basic features of the packet.
/// * `flow_map` - Map of flows.
/// * `fwd` - Direction of the packet.
/// * `timestamp` - Timestamp of the packet.
fn process_packet_ipv4<T>(
    data: &BasicFeaturesIpv4,
    flow_map: &Arc<DashMap<String, T>>,
    fwd: bool,
    timestamp: Option<Instant>,
    ts_datetime: Option<DateTime<Utc>>,
) where
    T: Flow,
{
    let ts;
    let ts_date;
    if let Some(timestamp) = timestamp {
        ts = timestamp;
    } else {
        ts = Instant::now();
    }

    if let Some(ts_datetime) = ts_datetime {
        ts_date = ts_datetime;
    } else {
        ts_date = Utc::now();
    }
    let destination = std::net::IpAddr::V4(Ipv4Addr::from(u32::from_le_bytes(
        data.ipv4_source
            .to_be_bytes()
            .try_into()
            .expect("Invalid IP length"),
    )));
    let source = std::net::IpAddr::V4(Ipv4Addr::from(u32::from_le_bytes(
        data.ipv4_destination
            .to_be_bytes()
            .try_into()
            .expect("Invalid IP length"),
    )));
    let combined_flags = data.combined_flags;
    let features = BasicFeatures {
        fin_flag: ((combined_flags & 0b00000001) != 0) as u8,
        syn_flag: ((combined_flags & 0b00000010) != 0) as u8,
        rst_flag: ((combined_flags & 0b00000100) != 0) as u8,
        psh_flag: ((combined_flags & 0b00001000) != 0) as u8,
        ack_flag: ((combined_flags & 0b00010000) != 0) as u8,
        urg_flag: ((combined_flags & 0b00100000) != 0) as u8,
        ece_flag: ((combined_flags & 0b01000000) != 0) as u8,
        cwe_flag: ((combined_flags & 0b10000000) != 0) as u8,
        data_length: data.data_length,
        header_length: data.header_length,
        length: data.length,
        window_size: data.window_size,
    };
    let flow_id = if fwd {
        create_flow_id(
            &source,
            data.port_source,
            &destination,
            data.port_destination,
            data.protocol,
        )
    } else {
        create_flow_id(
            &destination,
            data.port_destination,
            &source,
            data.port_source,
            data.protocol,
        )
    };

    let flow_id_clone = flow_id.clone();
    let flow_id_remove = flow_id.clone();
    let mut entry = flow_map.entry(flow_id).or_insert_with(|| {
        if fwd {
            T::new(
                flow_id_clone,
                source,
                data.port_source,
                destination,
                data.port_destination,
                data.protocol,
                ts_date,
            )
        } else {
            T::new(
                flow_id_clone,
                destination,
                data.port_destination,
                source,
                data.port_source,
                data.protocol,
                ts_date,
            )
        }
    });

    let end = entry.update_flow(&features, &ts, ts_date, fwd);
    if end.is_some() {
        export(&end.unwrap());
        drop(entry);
        flow_map.remove(&flow_id_remove);
    }
}

/// Processes an ipv6 packet and updates the flow map.
///
/// ### Arguments
///
/// * `data` - Basic features of the packet.
/// * `flow_map` - Map of flows.
/// * `fwd` - Direction of the packet.
/// * `timestamp` - Timestamp of the packet.
fn process_packet_ipv6<T>(
    data: &BasicFeaturesIpv6,
    flow_map: &Arc<DashMap<String, T>>,
    fwd: bool,
    timestamp: Option<Instant>,
    ts_datetime: Option<DateTime<Utc>>,
) where
    T: Flow,
{
    let ts;
    let ts_date;
    if let Some(timestamp) = timestamp {
        ts = timestamp;
    } else {
        ts = Instant::now();
    }
    if let Some(ts_datetime) = ts_datetime {
        ts_date = ts_datetime;
    } else {
        ts_date = Utc::now();
    }
    let destination = std::net::IpAddr::V6(Ipv6Addr::from(data.ipv6_destination));
    let source = std::net::IpAddr::V6(Ipv6Addr::from(data.ipv6_source));
    let combined_flags = data.combined_flags;
    let features = BasicFeatures {
        fin_flag: ((combined_flags & 0b00000001) != 0) as u8,
        syn_flag: ((combined_flags & 0b00000010) != 0) as u8,
        rst_flag: ((combined_flags & 0b00000100) != 0) as u8,
        psh_flag: ((combined_flags & 0b00001000) != 0) as u8,
        ack_flag: ((combined_flags & 0b00010000) != 0) as u8,
        urg_flag: ((combined_flags & 0b00100000) != 0) as u8,
        ece_flag: ((combined_flags & 0b01000000) != 0) as u8,
        cwe_flag: ((combined_flags & 0b10000000) != 0) as u8,
        data_length: data.data_length,
        header_length: data.header_length,
        length: data.length,
        window_size: data.window_size,
    };

    let flow_id = if fwd {
        create_flow_id(
            &source,
            data.port_source,
            &destination,
            data.port_destination,
            data.protocol,
        )
    } else {
        create_flow_id(
            &destination,
            data.port_destination,
            &source,
            data.port_source,
            data.protocol,
        )
    };

    let flow_id_clone = flow_id.clone();
    let flow_id_remove = flow_id.clone();
    let mut entry = flow_map.entry(flow_id).or_insert_with(|| {
        if fwd {
            T::new(
                flow_id_clone,
                source,
                data.port_source,
                destination,
                data.port_destination,
                data.protocol,
                ts_date,
            )
        } else {
            T::new(
                flow_id_clone,
                destination,
                data.port_destination,
                source,
                data.port_source,
                data.protocol,
                ts_date,
            )
        }
    });

    let end = entry.update_flow(&features, &ts, ts_date, fwd);
    if end.is_some() {
        export(&end.unwrap());
        drop(entry);
        flow_map.remove(&flow_id_remove);
    }
}

/// Redirects an ipv4 packet to the correct flow.
///
/// ### Arguments
///
/// * `features_ipv4` - Basic features of the packet.
/// * `flow_map` - Map of flows.
/// * `timestamp` - Timestamp of the packet.
fn redirect_packet_ipv4<T>(
    features_ipv4: &BasicFeaturesIpv4,
    flow_map: &Arc<DashMap<String, T>>,
    timestamp: Instant,
    ts_datetime: DateTime<Utc>,
) where
    T: Flow,
{
    let fwd_flow_id = create_flow_id(
        &std::net::IpAddr::V4(Ipv4Addr::from(features_ipv4.ipv4_source)),
        features_ipv4.port_source,
        &std::net::IpAddr::V4(Ipv4Addr::from(features_ipv4.ipv4_destination)),
        features_ipv4.port_destination,
        features_ipv4.protocol,
    );
    let bwd_flow_id = create_flow_id(
        &std::net::IpAddr::V4(Ipv4Addr::from(features_ipv4.ipv4_destination)),
        features_ipv4.port_destination,
        &std::net::IpAddr::V4(Ipv4Addr::from(features_ipv4.ipv4_source)),
        features_ipv4.port_source,
        features_ipv4.protocol,
    );

    if flow_map.contains_key(&fwd_flow_id) {
        process_packet_ipv4(&features_ipv4, &flow_map, true, Some(timestamp), Some(ts_datetime));
    } else if flow_map.contains_key(&bwd_flow_id) {
        process_packet_ipv4(&features_ipv4, &flow_map, false, Some(timestamp), Some(ts_datetime));
    } else {
        process_packet_ipv4(&features_ipv4, &flow_map, true, Some(timestamp), Some(ts_datetime));
    }
}

/// Redirects an ipv6 packet to the correct flow.
///
/// ### Arguments
///
/// * `features_ipv6` - Basic features of the packet.
/// * `flow_map` - Map of flows.
/// * `timestamp` - Timestamp of the packet.
fn redirect_packet_ipv6<T>(
    features_ipv6: &BasicFeaturesIpv6,
    flow_map: &Arc<DashMap<String, T>>,
    timestamp: Instant,
    ts_datetime: DateTime<Utc>,
) where
    T: Flow,
{
    let fwd_flow_id = create_flow_id(
        &std::net::IpAddr::V6(Ipv6Addr::from(features_ipv6.ipv6_source)),
        features_ipv6.port_source,
        &std::net::IpAddr::V6(Ipv6Addr::from(features_ipv6.ipv6_destination)),
        features_ipv6.port_destination,
        features_ipv6.protocol,
    );
    let bwd_flow_id = create_flow_id(
        &std::net::IpAddr::V6(Ipv6Addr::from(features_ipv6.ipv6_destination)),
        features_ipv6.port_destination,
        &std::net::IpAddr::V6(Ipv6Addr::from(features_ipv6.ipv6_source)),
        features_ipv6.port_source,
        features_ipv6.protocol,
    );

    if flow_map.contains_key(&fwd_flow_id) {
        process_packet_ipv6(&features_ipv6, &flow_map, true, Some(timestamp), Some(ts_datetime));
    } else if flow_map.contains_key(&bwd_flow_id) {
        process_packet_ipv6(&features_ipv6, &flow_map, false, Some(timestamp), Some(ts_datetime));
    } else {
        process_packet_ipv6(&features_ipv6, &flow_map, true, Some(timestamp), Some(ts_datetime));
    }
}

/// Extracts the basic features of an ipv4 packet pnet struct.
///
/// ### Arguments
///
/// * `ipv4_packet` - Ipv4 packet pnet struct.
///
/// ### Returns
///
/// * `Option<BasicFeaturesIpv4>` - Basic features of the packet.
fn extract_ipv4_features(ipv4_packet: &Ipv4Packet) -> Option<BasicFeaturesIpv4> {
    let source_ip = ipv4_packet.get_source();
    let destination_ip = ipv4_packet.get_destination();
    let protocol = ipv4_packet.get_next_level_protocol();

    let source_port: u16;
    let destination_port: u16;

    let mut combined_flags: u8 = 0;

    let data_length: u16;
    let header_length: u8;
    let length: u16;

    let mut window_size: u16 = 0;

    if protocol.0 == IpNextHeaderProtocols::Tcp.0 {
        if let Some(tcp_packet) = TcpPacket::new(ipv4_packet.payload()) {
            source_port = tcp_packet.get_source();
            destination_port = tcp_packet.get_destination();

            data_length = tcp_packet.payload().len() as u16;
            header_length = (tcp_packet.get_data_offset() * 4) as u8;
            length = ipv4_packet.get_total_length();

            window_size = tcp_packet.get_window();

            combined_flags = tcp_packet.get_flags();
        } else {
            return None;
        }
    } else if protocol.0 == IpNextHeaderProtocols::Udp.0 {
        if let Some(udp_packet) = pnet::packet::udp::UdpPacket::new(ipv4_packet.payload()) {
            source_port = udp_packet.get_source();
            destination_port = udp_packet.get_destination();

            data_length = udp_packet.payload().len() as u16;
            header_length = 8;
            length = udp_packet.get_length();
        } else {
            return None;
        }
    } else {
        return None;
    }

    Some(BasicFeaturesIpv4::new(
        destination_ip.into(),
        source_ip.into(),
        destination_port,
        source_port,
        data_length,
        length,
        window_size,
        combined_flags,
        protocol.0,
        header_length,
    ))
}

/// Extracts the basic features of an ipv6 packet pnet struct.
///
/// ### Arguments
///
/// * `ipv6_packet` - Ipv6 packet pnet struct.
///
/// ### Returns
///
/// * `Option<BasicFeaturesIpv6>` - Basic features of the packet.
fn extract_ipv6_features(ipv6_packet: &Ipv6Packet) -> Option<BasicFeaturesIpv6> {
    let source_ip = ipv6_packet.get_source();
    let destination_ip = ipv6_packet.get_destination();
    let protocol = ipv6_packet.get_next_header();

    let source_port: u16;
    let destination_port: u16;

    let mut combined_flags: u8 = 0;

    let data_length: u16;
    let header_length: u8;
    let length: u16;

    let mut window_size: u16 = 0;

    if protocol == IpNextHeaderProtocols::Tcp {
        if let Some(tcp_packet) = TcpPacket::new(ipv6_packet.payload()) {
            source_port = tcp_packet.get_source();
            destination_port = tcp_packet.get_destination();

            data_length = tcp_packet.payload().len() as u16;
            header_length = (tcp_packet.get_data_offset() * 4) as u8;
            length = ipv6_packet.packet().bytes().count() as u16;

            window_size = tcp_packet.get_window();

            combined_flags = tcp_packet.get_flags();
        } else {
            return None;
        }
    } else if protocol == IpNextHeaderProtocols::Udp {
        if let Some(udp_packet) = pnet::packet::udp::UdpPacket::new(ipv6_packet.payload()) {
            source_port = udp_packet.get_source();
            destination_port = udp_packet.get_destination();

            data_length = udp_packet.payload().len() as u16;
            header_length = 8;
            length = udp_packet.get_length();
        } else {
            return None;
        }
    } else {
        return None;
    }

    Some(BasicFeaturesIpv6::new(
        destination_ip.into(),
        source_ip.into(),
        destination_port,
        source_port,
        data_length,
        length,
        window_size,
        combined_flags,
        protocol.0,
        header_length,
    ))
}

fn timeval_to_system_time(tv_sec: i64, tv_usec: i64) -> SystemTime {
    UNIX_EPOCH + Duration::new(tv_sec as u64, (tv_usec * 1000) as u32)
}

fn system_time_to_datetime(system_time: SystemTime) -> DateTime<Utc> {
    let duration_since_epoch = system_time.duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    let datetime = DateTime::<Utc>::from(UNIX_EPOCH + duration_since_epoch);
    datetime
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_flow_termination() {
        let flow_map = Arc::new(DashMap::new());

        let data_1 = BasicFeaturesIpv4 {
            ipv4_source: 1,
            port_source: 8080,
            ipv4_destination: 2,
            port_destination: 8000,
            protocol: 6,
            combined_flags: 0b00000010,
            data_length: 100,
            header_length: 20,
            length: 140,
            window_size: 1000,
            _padding: [0; 3],
        };

        process_packet_ipv4::<CicFlow>(&data_1, &flow_map, true, None, None);

        assert_eq!(flow_map.len(), 1);

        let data_2 = BasicFeaturesIpv4 {
            ipv4_source: 2,
            port_source: 8000,
            ipv4_destination: 1,
            port_destination: 8080,
            protocol: 6,
            combined_flags: 0b00000010,
            data_length: 100,
            header_length: 20,
            length: 140,
            window_size: 1000,
            _padding: [0; 3],
        };
        process_packet_ipv4(&data_2, &flow_map, false, None, None);

        assert_eq!(flow_map.len(), 1);
        // 17 is for udp, here we just use it to create a new flow
        let data_3 = BasicFeaturesIpv4 {
            ipv4_source: 1,
            port_source: 8080,
            ipv4_destination: 2,
            port_destination: 8000,
            protocol: 17,
            combined_flags: 0b00010000,
            data_length: 100,
            header_length: 20,
            length: 140,
            window_size: 1000,
            _padding: [0; 3],
        };
        process_packet_ipv4(&data_3, &flow_map, true, None, None);

        assert_eq!(flow_map.len(), 2);

        let data_4 = BasicFeaturesIpv4 {
            ipv4_source: 1,
            port_source: 8080,
            ipv4_destination: 2,
            port_destination: 8000,
            protocol: 6,
            combined_flags: 0b00010001,
            data_length: 100,
            header_length: 20,
            length: 140,
            window_size: 1000,
            _padding: [0; 3],
        };
        process_packet_ipv4(&data_4, &flow_map, true, None, None);

        assert_eq!(flow_map.len(), 2);

        let data_5 = BasicFeaturesIpv4 {
            ipv4_source: 2,
            port_source: 8000,
            ipv4_destination: 1,
            port_destination: 8080,
            protocol: 6,
            combined_flags: 0b00010001,
            data_length: 100,
            header_length: 20,
            length: 140,
            window_size: 1000,
            _padding: [0; 3],
        };
        process_packet_ipv4(&data_5, &flow_map, false, None ,None);

        assert_eq!(flow_map.len(), 2);

        let data_6 = BasicFeaturesIpv4 {
            ipv4_source: 1,
            port_source: 8080,
            ipv4_destination: 2,
            port_destination: 8000,
            protocol: 6,
            combined_flags: 0b00010000,
            data_length: 100,
            header_length: 20,
            length: 140,
            window_size: 1000,
            _padding: [0; 3],
        };
        process_packet_ipv4(&data_6, &flow_map, true, None ,None);

        assert_eq!(flow_map.len(), 1);

        let data_7 = BasicFeaturesIpv4 {
            ipv4_source: 2,
            port_source: 8000,
            ipv4_destination: 1,
            port_destination: 8080,
            protocol: 17,
            combined_flags: 0b00000100,
            data_length: 100,
            header_length: 20,
            length: 140,
            window_size: 1000,
            _padding: [0; 3],
        };
        process_packet_ipv4(&data_7, &flow_map, false, None ,None);

        assert_eq!(flow_map.len(), 0);

        let data_8 = BasicFeaturesIpv4 {
            ipv4_source: 1,
            port_source: 8080,
            ipv4_destination: 2,
            port_destination: 8000,
            protocol: 6,
            combined_flags: 0b00010000,
            data_length: 100,
            header_length: 20,
            length: 140,
            window_size: 1000,
            _padding: [0; 3],
        };
        process_packet_ipv4(&data_8, &flow_map, true, None ,None);

        assert_eq!(flow_map.len(), 1);

        let data_9 = BasicFeaturesIpv4 {
            ipv4_source: 1,
            port_source: 8080,
            ipv4_destination: 2,
            port_destination: 8000,
            protocol: 6,
            combined_flags: 0b00010001,
            data_length: 100,
            header_length: 20,
            length: 140,
            window_size: 1000,
            _padding: [0; 3],
        };
        process_packet_ipv4(&data_9, &flow_map, true, None ,None);

        assert_eq!(flow_map.len(), 1);

        let data_10 = BasicFeaturesIpv4 {
            ipv4_source: 1,
            port_source: 8080,
            ipv4_destination: 2,
            port_destination: 8000,
            protocol: 6,
            combined_flags: 0b00010001,
            data_length: 100,
            header_length: 20,
            length: 140,
            window_size: 1000,
            _padding: [0; 3],
        };

        process_packet_ipv4(&data_10, &flow_map, true, None ,None);

        assert_eq!(flow_map.len(), 1);

        let data_11 = BasicFeaturesIpv4 {
            ipv4_source: 2,
            port_source: 8000,
            ipv4_destination: 1,
            port_destination: 8080,
            protocol: 6,
            combined_flags: 0b00010001,
            data_length: 100,
            header_length: 20,
            length: 140,
            window_size: 1000,
            _padding: [0; 3],
        };
        process_packet_ipv4(&data_11, &flow_map, false, None ,None);

        assert_eq!(flow_map.len(), 1);

        let data_12 = BasicFeaturesIpv4 {
            ipv4_source: 2,
            port_source: 8000,
            ipv4_destination: 1,
            port_destination: 8080,
            protocol: 6,
            combined_flags: 0b00010000,
            data_length: 100,
            header_length: 20,
            length: 140,
            window_size: 1000,
            _padding: [0; 3],
        };
        process_packet_ipv4(&data_12, &flow_map, false, None ,None);

        assert_eq!(flow_map.len(), 0);
    }
}
