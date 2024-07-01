use std::{
    net::IpAddr,
    ops::Deref,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use chrono::{DateTime, Utc};

use crate::{utils::utils::BasicFeatures, NO_CONTAMINANT_FEATURES};

use super::{cic_flow::CicFlow, flow::Flow};

/// Represents a Nfstream inspired Flow, encapsulating various metrics and states of a network flow.
///
/// This struct includes detailed information about both forward and backward
pub struct NfFlow {
    pub cic_flow: CicFlow,
    pub first_timestamp: SystemTime,
    pub last_timestamp: SystemTime,
    pub fwd_first_timestamp: SystemTime,
    pub fwd_last_timestamp: SystemTime,
    pub bwd_first_timestamp: SystemTime,
    pub bwd_last_timestamp: SystemTime,
}

impl Flow for NfFlow {
    fn new(
        flow_id: String,
        ipv4_source: IpAddr,
        port_source: u16,
        ipv4_destination: IpAddr,
        port_destination: u16,
        protocol: u8,
        ts_date: DateTime<Utc>,
    ) -> Self {
        NfFlow {
            cic_flow: CicFlow::new(
                flow_id,
                ipv4_source,
                port_source,
                ipv4_destination,
                port_destination,
                protocol,
                ts_date,
            ),
            first_timestamp: ts_date.into(),
            last_timestamp: ts_date.into(),
            fwd_first_timestamp: ts_date.into(),
            fwd_last_timestamp: ts_date.into(),
            bwd_first_timestamp: ts_date.into(),
            bwd_last_timestamp: ts_date.into(),
        }
    }

    fn update_flow(
        &mut self,
        packet: &BasicFeatures,
        timestamp: &Instant,
        ts_date: DateTime<Utc>,
        fwd: bool,
    ) -> Option<String> {
        if fwd {
            self.fwd_last_timestamp = ts_date.into();
        } else {
            self.bwd_last_timestamp = ts_date.into();
        }

        let end = self.cic_flow.update_flow(packet, timestamp, ts_date, fwd);
        if end.is_some() {
            if *NO_CONTAMINANT_FEATURES.lock().unwrap().deref() {
                return Some(self.dump_without_contamination());
            } else {
                return Some(self.dump());
            }
        }

        None
    }

    fn dump(&self) -> String {
        format!("{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            self.cic_flow.basic_flow.flow_id,
            self.cic_flow.basic_flow.ip_source,
            self.cic_flow.basic_flow.port_source,
            self.cic_flow.basic_flow.ip_destination,
            self.cic_flow.basic_flow.port_destination,
            self.cic_flow.basic_flow.protocol,
            self.first_timestamp.duration_since(UNIX_EPOCH).unwrap().as_millis(),
            self.last_timestamp.duration_since(UNIX_EPOCH).unwrap().as_millis(),
            self.last_timestamp.duration_since(UNIX_EPOCH).unwrap().as_millis() - self.first_timestamp.duration_since(UNIX_EPOCH).unwrap().as_millis(),
            self.cic_flow.basic_flow.fwd_packet_count + self.cic_flow.basic_flow.bwd_packet_count,
            self.cic_flow.fwd_pkt_len_tot + self.cic_flow.bwd_pkt_len_tot,
            self.fwd_first_timestamp.duration_since(UNIX_EPOCH).unwrap().as_millis(),
            self.fwd_last_timestamp.duration_since(UNIX_EPOCH).unwrap().as_millis(),
            self.fwd_last_timestamp.duration_since(UNIX_EPOCH).unwrap().as_millis() - self.fwd_first_timestamp.duration_since(UNIX_EPOCH).unwrap().as_millis(),
            self.cic_flow.basic_flow.fwd_packet_count,
            self.cic_flow.fwd_pkt_len_tot,
            self.bwd_first_timestamp.duration_since(UNIX_EPOCH).unwrap().as_millis(),
            self.bwd_last_timestamp.duration_since(UNIX_EPOCH).unwrap().as_millis(),
            self.bwd_last_timestamp.duration_since(UNIX_EPOCH).unwrap().as_millis() - self.bwd_first_timestamp.duration_since(UNIX_EPOCH).unwrap().as_millis(),
            self.cic_flow.basic_flow.bwd_packet_count,
            self.cic_flow.bwd_pkt_len_tot,
            self.cic_flow.get_flow_packet_length_min(),
            self.cic_flow.get_flow_packet_length_mean(),
            self.cic_flow.get_flow_packet_length_std(),
            self.cic_flow.get_flow_packet_length_max(),
            self.cic_flow.get_fwd_packet_length_min(),
            self.cic_flow.fwd_pkt_len_mean,
            self.cic_flow.fwd_pkt_len_std,
            self.cic_flow.fwd_pkt_len_max,
            self.cic_flow.get_bwd_packet_length_min(),
            self.cic_flow.bwd_pkt_len_mean,
            self.cic_flow.bwd_pkt_len_std,
            self.cic_flow.bwd_pkt_len_max,
            self.cic_flow.get_flow_iat_min() / 1000.0,
            self.cic_flow.get_flow_iat_mean() / 1000.0,
            self.cic_flow.get_flow_iat_std() / 1000.0,
            self.cic_flow.get_flow_iat_max() / 1000.0,
            self.cic_flow.get_fwd_iat_min() / 1000.0,
            self.cic_flow.fwd_iat_mean / 1000.0,
            self.cic_flow.fwd_iat_std / 1000.0,
            self.cic_flow.fwd_iat_max / 1000.0,
            self.cic_flow.get_bwd_iat_min() / 1000.0,
            self.cic_flow.bwd_iat_mean / 1000.0,
            self.cic_flow.bwd_iat_std / 1000.0,
            self.cic_flow.bwd_iat_max / 1000.0,
            self.cic_flow.basic_flow.fwd_syn_flag_count + self.cic_flow.basic_flow.bwd_syn_flag_count,
            self.cic_flow.basic_flow.fwd_cwe_flag_count + self.cic_flow.basic_flow.bwd_cwe_flag_count,
            self.cic_flow.basic_flow.fwd_ece_flag_count + self.cic_flow.basic_flow.bwd_ece_flag_count,
            self.cic_flow.basic_flow.fwd_urg_flag_count + self.cic_flow.basic_flow.bwd_urg_flag_count,
            self.cic_flow.basic_flow.fwd_ack_flag_count + self.cic_flow.basic_flow.bwd_ack_flag_count,
            self.cic_flow.basic_flow.fwd_psh_flag_count + self.cic_flow.basic_flow.bwd_psh_flag_count,
            self.cic_flow.basic_flow.fwd_rst_flag_count + self.cic_flow.basic_flow.bwd_rst_flag_count,
            self.cic_flow.basic_flow.fwd_fin_flag_count + self.cic_flow.basic_flow.bwd_fin_flag_count,
            self.cic_flow.basic_flow.fwd_syn_flag_count,
            self.cic_flow.basic_flow.fwd_cwe_flag_count,
            self.cic_flow.basic_flow.fwd_ece_flag_count,
            self.cic_flow.basic_flow.fwd_urg_flag_count,
            self.cic_flow.basic_flow.fwd_ack_flag_count,
            self.cic_flow.basic_flow.fwd_psh_flag_count,
            self.cic_flow.basic_flow.fwd_rst_flag_count,
            self.cic_flow.basic_flow.fwd_fin_flag_count,
            self.cic_flow.basic_flow.bwd_syn_flag_count,
            self.cic_flow.basic_flow.bwd_cwe_flag_count,
            self.cic_flow.basic_flow.bwd_ece_flag_count,
            self.cic_flow.basic_flow.bwd_urg_flag_count,
            self.cic_flow.basic_flow.bwd_ack_flag_count,
            self.cic_flow.basic_flow.bwd_psh_flag_count,
            self.cic_flow.basic_flow.bwd_rst_flag_count,
            self.cic_flow.basic_flow.bwd_fin_flag_count,
        )
    }

    fn get_features() -> String {
        format!(
            "FLOW_ID,IP_SRC,PORT_SRC,IP_DST,PORT_DST,PROTOCOL,FIRST_TS,LAST_TS,\
            DURATION,FLOW_PKTS,FLOW_BYTES,FWD_FIRST_TS,FWD_LAST_TS,FWD_DURATION,FWD_PKTS,\
            FWD_BYTES,BWD_FIRST_TS,BWD_LAST_TS,BWD_DURATION,BWD_PKTS,BWD_BYTES,FLOW_PKT_LEN_MIN,\
            FLOW_PKT_LEN_MEAN,FLOW_PKT_LEN_STD,FLOW_PKT_LEN_MAX,FWD_PKT_LEN_MIN,FWD_PKT_LEN_MEAN,\
            FWD_PKT_LEN_STD,FWD_PKT_LEN_MAX,BWD_PKT_LEN_MIN,BWD_PKT_LEN_MEAN,BWD_PKT_LEN_STD,\
            BWD_PKT_LEN_MAX,FLOW_IAT_MIN,FLOW_IAT_MEAN,FLOW_IAT_STD,FLOW_IAT_MAX,FWD_IAT_MIN,\
            FWD_IAT_MEAN,FWD_IAT_STD,FWD_IAT_MAX,BWD_IAT_MIN,BWD_IAT_MEAN,BWD_IAT_STD,\
            BWD_IAT_MAX,FLOW_SYN,FLOW_CWE,FLOW_ECE,FLOW_URG,FLOW_ACK,FLOW_PSH,FLOW_RST,\
            FLOW_FIN,FWD_SYN,FWD_CWE,FWD_ECE,FWD_URG,FWD_ACK,FWD_PSH,FWD_RST,FWD_FIN,\
            BWD_SYN,BWD_CWE,BWD_ECE,BWD_URG,BWD_ACK,BWD_PSH,BWD_RST,BWD_FIN"
        )
    }

    fn dump_without_contamination(&self) -> String {
        format!(
            "{},{},{},{},{},{},{},{},{},{},{},{},{},\
        {},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},\
        {},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},\
        {},{},{},{},{},{},{},{},{},{},{},{},{}",
            self.cic_flow.basic_flow.protocol,
            self.last_timestamp
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis()
                - self
                    .first_timestamp
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis(),
            self.cic_flow.basic_flow.fwd_packet_count + self.cic_flow.basic_flow.bwd_packet_count,
            self.cic_flow.fwd_pkt_len_tot + self.cic_flow.bwd_pkt_len_tot,
            self.fwd_last_timestamp
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis()
                - self
                    .fwd_first_timestamp
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis(),
            self.cic_flow.basic_flow.fwd_packet_count,
            self.cic_flow.fwd_pkt_len_tot,
            self.bwd_last_timestamp
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis()
                - self
                    .bwd_first_timestamp
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis(),
            self.cic_flow.basic_flow.bwd_packet_count,
            self.cic_flow.bwd_pkt_len_tot,
            self.cic_flow.get_flow_packet_length_min(),
            self.cic_flow.get_flow_packet_length_mean(),
            self.cic_flow.get_flow_packet_length_std(),
            self.cic_flow.get_flow_packet_length_max(),
            self.cic_flow.get_fwd_packet_length_min(),
            self.cic_flow.fwd_pkt_len_mean,
            self.cic_flow.fwd_pkt_len_std,
            self.cic_flow.fwd_pkt_len_max,
            self.cic_flow.get_bwd_packet_length_min(),
            self.cic_flow.bwd_pkt_len_mean,
            self.cic_flow.bwd_pkt_len_std,
            self.cic_flow.bwd_pkt_len_max,
            self.cic_flow.get_flow_iat_min() / 1000.0,
            self.cic_flow.get_flow_iat_mean() / 1000.0,
            self.cic_flow.get_flow_iat_std() / 1000.0,
            self.cic_flow.get_flow_iat_max() / 1000.0,
            self.cic_flow.get_fwd_iat_min() / 1000.0,
            self.cic_flow.fwd_iat_mean / 1000.0,
            self.cic_flow.fwd_iat_std / 1000.0,
            self.cic_flow.fwd_iat_max / 1000.0,
            self.cic_flow.get_bwd_iat_min() / 1000.0,
            self.cic_flow.bwd_iat_mean / 1000.0,
            self.cic_flow.bwd_iat_std / 1000.0,
            self.cic_flow.bwd_iat_max / 1000.0,
            self.cic_flow.basic_flow.fwd_syn_flag_count
                + self.cic_flow.basic_flow.bwd_syn_flag_count,
            self.cic_flow.basic_flow.fwd_cwe_flag_count
                + self.cic_flow.basic_flow.bwd_cwe_flag_count,
            self.cic_flow.basic_flow.fwd_ece_flag_count
                + self.cic_flow.basic_flow.bwd_ece_flag_count,
            self.cic_flow.basic_flow.fwd_urg_flag_count
                + self.cic_flow.basic_flow.bwd_urg_flag_count,
            self.cic_flow.basic_flow.fwd_ack_flag_count
                + self.cic_flow.basic_flow.bwd_ack_flag_count,
            self.cic_flow.basic_flow.fwd_psh_flag_count
                + self.cic_flow.basic_flow.bwd_psh_flag_count,
            self.cic_flow.basic_flow.fwd_rst_flag_count
                + self.cic_flow.basic_flow.bwd_rst_flag_count,
            self.cic_flow.basic_flow.fwd_fin_flag_count
                + self.cic_flow.basic_flow.bwd_fin_flag_count,
            self.cic_flow.basic_flow.fwd_syn_flag_count,
            self.cic_flow.basic_flow.fwd_cwe_flag_count,
            self.cic_flow.basic_flow.fwd_ece_flag_count,
            self.cic_flow.basic_flow.fwd_urg_flag_count,
            self.cic_flow.basic_flow.fwd_ack_flag_count,
            self.cic_flow.basic_flow.fwd_psh_flag_count,
            self.cic_flow.basic_flow.fwd_rst_flag_count,
            self.cic_flow.basic_flow.fwd_fin_flag_count,
            self.cic_flow.basic_flow.bwd_syn_flag_count,
            self.cic_flow.basic_flow.bwd_cwe_flag_count,
            self.cic_flow.basic_flow.bwd_ece_flag_count,
            self.cic_flow.basic_flow.bwd_urg_flag_count,
            self.cic_flow.basic_flow.bwd_ack_flag_count,
            self.cic_flow.basic_flow.bwd_psh_flag_count,
            self.cic_flow.basic_flow.bwd_rst_flag_count,
            self.cic_flow.basic_flow.bwd_fin_flag_count,
        )
    }

    fn get_features_without_contamination() -> String {
        format!(
            "PROTOCOL,DURATION,FLOW_PKTS,FLOW_BYTES,FWD_DURATION,FWD_PKTS,FWD_BYTES,\
            BWD_DURATION,BWD_PKTS,BWD_BYTES,FLOW_PKT_LEN_MIN,FLOW_PKT_LEN_MEAN,FLOW_PKT_LEN_STD,\
            FLOW_PKT_LEN_MAX,FWD_PKT_LEN_MIN,FWD_PKT_LEN_MEAN,FWD_PKT_LEN_STD,FWD_PKT_LEN_MAX,\
            BWD_PKT_LEN_MIN,BWD_PKT_LEN_MEAN,BWD_PKT_LEN_STD,BWD_PKT_LEN_MAX,FLOW_IAT_MIN,\
            FLOW_IAT_MEAN,FLOW_IAT_STD,FLOW_IAT_MAX,FWD_IAT_MIN,FWD_IAT_MEAN,FWD_IAT_STD,\
            FWD_IAT_MAX,BWD_IAT_MIN,BWD_IAT_MEAN,BWD_IAT_STD,BWD_IAT_MAX,FLOW_SYN,FLOW_CWE,\
            FLOW_ECE,FLOW_URG,FLOW_ACK,FLOW_PSH,FLOW_RST,FLOW_FIN,FWD_SYN,FWD_CWE,FWD_ECE,\
            FWD_URG,FWD_ACK,FWD_PSH,FWD_RST,FWD_FIN,BWD_SYN,BWD_CWE,BWD_ECE,BWD_URG,BWD_ACK,\
            BWD_PSH,BWD_RST,BWD_FIN"
        )
    }

    fn get_first_timestamp(&self) -> DateTime<Utc> {
        self.cic_flow.get_first_timestamp()
    }
}
