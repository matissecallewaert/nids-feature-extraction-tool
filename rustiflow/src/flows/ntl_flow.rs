use chrono::{DateTime, Utc};
use std::ops::Deref;
use std::{net::IpAddr, time::Instant};

use crate::utils::utils::{calculate_mean, calculate_std, get_duration, BasicFeatures};
use crate::NO_CONTAMINANT_FEATURES;

use super::{cic_flow::CicFlow, flow::Flow};

/// Represents a NTL Flow, encapsulating various metrics and states of a network flow.
///
/// This flow represents the same flow as the NTLFlowLyzer does.
pub struct NTLFlow {
    /// The cic flow information.
    pub basic_flow: CicFlow,
    /// The minimum header length of the forward flow.
    fwd_header_len_min: u32,
    /// The maximum header length of the forward flow.
    fwd_header_len_max: u32,
    /// The mean packet length of the forward flow.
    fwd_header_len_mean: f32,
    /// The std header length of the forward flow.
    fwd_header_len_std: f32,
    /// The minimum header length of the backward flow.
    bwd_header_len_min: u32,
    /// The maximum header length of the backward flow.
    bwd_header_len_max: u32,
    /// The mean packet length of the backward flow.
    bwd_header_len_mean: f32,
    /// The std header length of the backward flow.
    bwd_header_len_std: f32,
}

impl NTLFlow {
    /// Updates statistics for the header length of forward packets.
    ///
    /// This method updates the maximum, minimum, total, mean, and standard deviation
    /// for the header lengths of forward packets. It's used for analyzing header size
    /// distributions in the forward direction of the flow.
    ///
    /// ### Arguments
    ///
    /// * `len` - The length of the new packet header to be incorporated into the statistics.
    fn update_fwd_header_len_stats(&mut self, len: u32) {
        // update max and min
        if len > self.fwd_header_len_max {
            self.fwd_header_len_max = len;
        }
        if len < self.fwd_header_len_min {
            self.fwd_header_len_min = len;
        }

        // update total
        self.basic_flow.fwd_header_length += len;

        // update mean and std
        let new_fwd_header_len_mean = calculate_mean(
            self.basic_flow.basic_flow.fwd_packet_count as u64,
            self.fwd_header_len_mean as f64,
            len as f64,
        ) as f32;
        self.fwd_header_len_std = calculate_std(
            self.basic_flow.basic_flow.fwd_packet_count as u64,
            self.fwd_header_len_std as f64,
            self.fwd_header_len_mean as f64,
            new_fwd_header_len_mean as f64,
            len as f64,
        ) as f32;
        self.fwd_header_len_mean = new_fwd_header_len_mean;
    }

    /// Updates statistics for the length of forward packets.
    ///
    /// This method updates the maximum, minimum, total, mean, and standard deviation
    /// for the lengths of forward packets. It's used for analyzing packet size
    /// distributions in the forward direction of the flow.
    ///
    /// ### Arguments
    ///
    /// * `len` - The length of the new packet to be incorporated into the statistics.
    fn update_bwd_header_len_stats(&mut self, len: u32) {
        // update max and min
        if len > self.bwd_header_len_max {
            self.bwd_header_len_max = len;
        }
        if len < self.bwd_header_len_min {
            self.bwd_header_len_min = len;
        }

        // update total
        self.basic_flow.bwd_header_length += len;

        // update mean and std
        let new_bwd_header_len_mean = calculate_mean(
            self.basic_flow.basic_flow.bwd_packet_count as u64,
            self.bwd_header_len_mean as f64,
            len as f64,
        ) as f32;
        self.bwd_header_len_std = calculate_std(
            self.basic_flow.basic_flow.bwd_packet_count as u64,
            self.bwd_header_len_std as f64,
            self.bwd_header_len_mean as f64,
            new_bwd_header_len_mean as f64,
            len as f64,
        ) as f32;
        self.bwd_header_len_mean = new_bwd_header_len_mean;
    }

    /// Retrieves the minimum packet header length for forward packets.
    ///
    /// Returns the minimum packet header length observed in the forward direction.
    /// Returns 0 if the minimum header length is not set (indicated by `u32::MAX`).
    ///
    /// ### Returns
    ///
    /// Minimum forward packet header length, or 0 if not set.
    pub fn get_fwd_header_length_min(&self) -> u32 {
        if self.fwd_header_len_min == u32::MAX {
            return 0;
        }
        self.fwd_header_len_min
    }

    /// Retrieves the minimum packet header length for backward packets.
    ///
    /// Returns the minimum packet header length observed in the backward direction.
    /// Returns 0 if the minimum header length is not set (indicated by `u32::MAX`).
    ///
    /// ### Returns
    ///
    /// Minimum backward packet header length, or 0 if not set.
    pub fn get_bwd_header_length_min(&self) -> u32 {
        if self.bwd_header_len_min == u32::MAX {
            return 0;
        }
        self.bwd_header_len_min
    }

    /// Retrieves the maximum packet header length in the flow, considering both forward and backward directions.
    ///
    /// Compares the maximum packet header lengths of forward and backward flows and returns the larger value.
    ///
    /// ### Returns
    ///
    /// Maximum packet header length in the flow.
    pub fn get_flow_header_length_max(&self) -> u32 {
        if self.fwd_header_len_max > self.bwd_header_len_max {
            return self.fwd_header_len_max;
        }
        self.bwd_header_len_max
    }

    /// Retrieves the minimum packet header length in the flow, considering both forward and backward directions.
    ///
    /// Compares the minimum packet header lengths of forward and backward flows and returns the smaller value.
    /// Returns 0 if the minimum length is not set (indicated by `u32::MAX`).
    ///
    /// ### Returns
    ///
    /// Minimum packet header length in the flow, or 0 if not set.
    pub fn get_flow_header_length_min(&self) -> u32 {
        if self.fwd_header_len_min < self.bwd_header_len_min {
            if self.fwd_header_len_min == u32::MAX {
                return 0;
            }
            self.fwd_header_len_min
        } else {
            if self.bwd_header_len_min == u32::MAX {
                return 0;
            }
            self.bwd_header_len_min
        }
    }

    /// Calculates the mean packet header length of the flow, averaging both forward and backward packet header lengths.
    ///
    /// The mean is computed by considering the header lengths and counts of packets in both directions.
    ///
    /// ### Returns
    ///
    /// Mean packet header length of the flow.
    pub fn get_flow_header_length_mean(&self) -> f32 {
        (self.fwd_header_len_mean * self.basic_flow.basic_flow.fwd_packet_count as f32
            + self.bwd_header_len_mean * self.basic_flow.basic_flow.bwd_packet_count as f32)
            as f32
            / (self.basic_flow.basic_flow.fwd_packet_count
                + self.basic_flow.basic_flow.bwd_packet_count) as f32
    }

    /// Calculates the variance of the packet lengths in the flow.
    ///
    /// Computes the variance by considering the standard deviations of packet lengths
    /// in both forward and backward directions.
    ///
    /// ### Returns
    ///
    /// Variance of the flow's packet lengths, or 0 if not enough data.
    pub fn get_flow_header_length_variance(&self) -> f64 {
        if self.basic_flow.basic_flow.fwd_packet_count < 1
            || self.basic_flow.basic_flow.bwd_packet_count < 1
            || self.basic_flow.basic_flow.fwd_packet_count
                + self.basic_flow.basic_flow.bwd_packet_count
                < 3
        {
            return 0.0;
        }

        let fwd_pkt_std_squared = self.fwd_header_len_std.powf(2.0);
        let bwd_pkt_std_squared = self.bwd_header_len_std.powf(2.0);

        ((self.basic_flow.basic_flow.fwd_packet_count - 1) as f64 * fwd_pkt_std_squared as f64
            + (self.basic_flow.basic_flow.bwd_packet_count - 1) as f64 * bwd_pkt_std_squared as f64)
            / (self.basic_flow.basic_flow.fwd_packet_count
                + self.basic_flow.basic_flow.bwd_packet_count
                - 2) as f64
    }

    /// Retrieves the standard deviation of packet lengths in the flow.
    ///
    /// Utilizes the calculated variance of packet lengths to compute the standard deviation.
    ///
    /// ### Returns
    ///
    /// Standard deviation of the flow's packet lengths.
    pub fn get_flow_header_length_std(&self) -> f64 {
        self.get_flow_header_length_variance().sqrt()
    }
}

impl Flow for NTLFlow {
    fn new(
        flow_id: String,
        ipv4_source: IpAddr,
        port_source: u16,
        ipv4_destination: IpAddr,
        port_destination: u16,
        protocol: u8,
        ts_date: DateTime<Utc>,
    ) -> Self {
        NTLFlow {
            basic_flow: CicFlow::new(
                flow_id,
                ipv4_source,
                port_source,
                ipv4_destination,
                port_destination,
                protocol,
                ts_date,
            ),
            fwd_header_len_min: u32::MAX,
            fwd_header_len_max: 0,
            fwd_header_len_mean: 0.0,
            fwd_header_len_std: 0.0,
            bwd_header_len_min: u32::MAX,
            bwd_header_len_max: 0,
            bwd_header_len_mean: 0.0,
            bwd_header_len_std: 0.0,
        }
    }

    fn update_flow(
        &mut self,
        packet: &BasicFeatures,
        timestamp: &Instant,
        ts_date: DateTime<Utc>,
        fwd: bool,
    ) -> Option<String> {
        let end = self.basic_flow.update_flow(packet, timestamp, ts_date, fwd);

        if fwd {
            self.update_fwd_header_len_stats(packet.header_length as u32);
        } else {
            self.update_bwd_header_len_stats(packet.header_length as u32);
        }

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
        format!(
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            self.basic_flow.basic_flow.flow_id,
            self.basic_flow.basic_flow.ip_source,
            self.basic_flow.basic_flow.port_source,
            self.basic_flow.basic_flow.ip_destination,
            self.basic_flow.basic_flow.port_destination,
            self.basic_flow.basic_flow.protocol,
            get_duration(
                self.basic_flow.basic_flow.first_timestamp,
                self.basic_flow.basic_flow.last_timestamp
            ),
            self.basic_flow.basic_flow.fwd_packet_count
                + self.basic_flow.basic_flow.bwd_packet_count,
            self.basic_flow.basic_flow.fwd_packet_count,
            self.basic_flow.basic_flow.bwd_packet_count,
            self.basic_flow.fwd_pkt_len_tot + self.basic_flow.bwd_pkt_len_tot,
            self.basic_flow.fwd_pkt_len_tot,
            self.basic_flow.bwd_pkt_len_tot,
            self.basic_flow.get_flow_packet_length_max(),
            self.basic_flow.get_flow_packet_length_min(),
            self.basic_flow.get_flow_packet_length_mean(),
            self.basic_flow.get_flow_packet_length_std(),
            self.basic_flow.get_flow_packet_length_variance(),
            self.basic_flow.fwd_pkt_len_max,
            self.basic_flow.get_fwd_packet_length_min(),
            self.basic_flow.fwd_pkt_len_mean,
            self.basic_flow.fwd_pkt_len_std,
            self.basic_flow.fwd_pkt_len_std.powf(2.0),
            self.basic_flow.bwd_pkt_len_max,
            self.basic_flow.get_bwd_packet_length_min(),
            self.basic_flow.bwd_pkt_len_mean,
            self.basic_flow.bwd_pkt_len_std,
            self.basic_flow.bwd_pkt_len_std.powf(2.0),
            self.basic_flow.fwd_header_length + self.basic_flow.bwd_header_length,
            self.get_flow_header_length_max(),
            self.get_flow_header_length_min(),
            self.get_flow_header_length_mean(),
            self.get_flow_header_length_std(),
            self.basic_flow.fwd_header_length,
            self.fwd_header_len_max,
            self.get_fwd_header_length_min(),
            self.fwd_header_len_mean,
            self.fwd_header_len_std,
            self.basic_flow.bwd_header_length,
            self.bwd_header_len_max,
            self.get_bwd_header_length_min(),
            self.bwd_header_len_mean,
            self.bwd_header_len_std,
            self.basic_flow.get_fwd_segment_length_mean(),
            self.basic_flow.get_bwd_segment_length_mean(),
            self.basic_flow.get_flow_segment_length_mean(),
            self.basic_flow.fwd_init_win_bytes,
            self.basic_flow.bwd_init_win_bytes,
            self.basic_flow.get_active_min(),
            self.basic_flow.active_max,
            self.basic_flow.active_mean,
            self.basic_flow.active_std,
            self.basic_flow.get_idle_min(),
            self.basic_flow.idle_max,
            self.basic_flow.idle_mean,
            self.basic_flow.idle_std,
            (self.basic_flow.fwd_pkt_len_tot + self.basic_flow.bwd_pkt_len_tot) as f64
                / (get_duration(
                    self.basic_flow.basic_flow.first_timestamp,
                    self.basic_flow.basic_flow.last_timestamp
                ))
                / 1_000_000.0,
            self.basic_flow.fwd_pkt_len_tot as f64
                / (get_duration(
                    self.basic_flow.basic_flow.first_timestamp,
                    self.basic_flow.basic_flow.last_timestamp
                ))
                / 1_000_000.0,
            self.basic_flow.bwd_pkt_len_tot as f64
                / (get_duration(
                    self.basic_flow.basic_flow.first_timestamp,
                    self.basic_flow.basic_flow.last_timestamp
                ))
                / 1_000_000.0,
            (self.basic_flow.basic_flow.fwd_packet_count
                + self.basic_flow.basic_flow.bwd_packet_count) as f64
                / (get_duration(
                    self.basic_flow.basic_flow.first_timestamp,
                    self.basic_flow.basic_flow.last_timestamp
                ))
                / 1_000_000.0,
            self.basic_flow.basic_flow.bwd_packet_count as f64
                / (get_duration(
                    self.basic_flow.basic_flow.first_timestamp,
                    self.basic_flow.basic_flow.last_timestamp
                ))
                / 1_000_000.0,
            self.basic_flow.basic_flow.fwd_packet_count as f64
                / (get_duration(
                    self.basic_flow.basic_flow.first_timestamp,
                    self.basic_flow.basic_flow.last_timestamp
                ))
                / 1_000_000.0,
            self.basic_flow.get_down_up_ratio(),
            self.basic_flow.get_fwd_bytes_bulk(),
            self.basic_flow.get_fwd_packets_bulk(),
            self.basic_flow.get_fwd_bulk_rate(),
            self.basic_flow.get_bwd_bytes_bulk(),
            self.basic_flow.get_bwd_packets_bulk(),
            self.basic_flow.get_bwd_bulk_rate(),
            self.basic_flow.fwd_bulk_state_count,
            self.basic_flow.fwd_bulk_size_total,
            self.basic_flow.fwd_bulk_packet_count,
            self.basic_flow.fwd_bulk_duration,
            self.basic_flow.bwd_bulk_state_count,
            self.basic_flow.bwd_bulk_size_total,
            self.basic_flow.bwd_bulk_packet_count,
            self.basic_flow.bwd_bulk_duration,
            self.basic_flow.basic_flow.fwd_fin_flag_count
                + self.basic_flow.basic_flow.bwd_fin_flag_count,
            self.basic_flow.basic_flow.fwd_psh_flag_count
                + self.basic_flow.basic_flow.bwd_psh_flag_count,
            self.basic_flow.basic_flow.fwd_urg_flag_count
                + self.basic_flow.basic_flow.bwd_urg_flag_count,
            self.basic_flow.basic_flow.fwd_ece_flag_count
                + self.basic_flow.basic_flow.bwd_ece_flag_count,
            self.basic_flow.basic_flow.fwd_syn_flag_count
                + self.basic_flow.basic_flow.bwd_syn_flag_count,
            self.basic_flow.basic_flow.fwd_ack_flag_count
                + self.basic_flow.basic_flow.bwd_ack_flag_count,
            self.basic_flow.basic_flow.fwd_cwe_flag_count
                + self.basic_flow.basic_flow.bwd_cwe_flag_count,
            self.basic_flow.basic_flow.fwd_rst_flag_count
                + self.basic_flow.basic_flow.bwd_rst_flag_count,
            self.basic_flow.basic_flow.fwd_fin_flag_count,
            self.basic_flow.basic_flow.fwd_psh_flag_count,
            self.basic_flow.basic_flow.fwd_urg_flag_count,
            self.basic_flow.basic_flow.fwd_ece_flag_count,
            self.basic_flow.basic_flow.fwd_syn_flag_count,
            self.basic_flow.basic_flow.fwd_ack_flag_count,
            self.basic_flow.basic_flow.fwd_cwe_flag_count,
            self.basic_flow.basic_flow.fwd_rst_flag_count,
            self.basic_flow.basic_flow.bwd_fin_flag_count,
            self.basic_flow.basic_flow.bwd_psh_flag_count,
            self.basic_flow.basic_flow.bwd_urg_flag_count,
            self.basic_flow.basic_flow.bwd_ece_flag_count,
            self.basic_flow.basic_flow.bwd_syn_flag_count,
            self.basic_flow.basic_flow.bwd_ack_flag_count,
            self.basic_flow.basic_flow.bwd_cwe_flag_count,
            self.basic_flow.basic_flow.bwd_rst_flag_count,
            self.basic_flow.get_flow_iat_mean(),
            self.basic_flow.get_flow_iat_std(),
            self.basic_flow.get_flow_iat_max(),
            self.basic_flow.get_flow_iat_min(),
            self.basic_flow.fwd_iat_total + self.basic_flow.bwd_iat_total,
            self.basic_flow.fwd_iat_mean,
            self.basic_flow.fwd_iat_std,
            self.basic_flow.fwd_iat_max,
            self.basic_flow.get_fwd_iat_min(),
            self.basic_flow.fwd_iat_total,
            self.basic_flow.bwd_iat_mean,
            self.basic_flow.bwd_iat_std,
            self.basic_flow.bwd_iat_max,
            self.basic_flow.get_bwd_iat_min(),
            self.basic_flow.bwd_iat_total,
            self.basic_flow.get_sf_fwd_packets(),
            self.basic_flow.get_sf_bwd_packets(),
            self.basic_flow.get_sf_fwd_bytes(),
            self.basic_flow.get_sf_bwd_bytes(),
        )
    }

    fn get_features() -> String {
        format!(
            "FLOW_ID,IP_SOURCE,PORT_SOURCE,IP_DESTINATION,PORT_DESTINATION,PROTOCOL,\
            DURATION,TOTAL_PACKETS,FWD_PACKETS,BWD_PACKETS,TOTAL_BYTES,FWD_BYTES,BWD_BYTES,\
            PACKET_LENGTH_MAX,PACKET_LENGTH_MIN,PACKET_LENGTH_MEAN,PACKET_LENGTH_STD,\
            PACKET_LENGTH_VARIANCE,FWD_PACKET_LENGTH_MAX,FWD_PACKET_LENGTH_MIN,\
            FWD_PACKET_LENGTH_MEAN,FWD_PACKET_LENGTH_STD,FWD_PACKET_LENGTH_VARIANCE,\
            BWD_PACKET_LENGTH_MAX,BWD_PACKET_LENGTH_MIN,BWD_PACKET_LENGTH_MEAN,\
            BWD_PACKET_LENGTH_STD,BWD_PACKET_LENGTH_VARIANCE,HEADER_LENGTH_TOTAL,\
            HEADER_LENGTH_MAX,HEADER_LENGTH_MIN,HEADER_LENGTH_MEAN,HEADER_LENGTH_STD,\
            FWD_HEADER_LENGTH_TOTAL,FWD_HEADER_LENGTH_MAX,FWD_HEADER_LENGTH_MIN,\
            FWD_HEADER_LENGTH_MEAN,FWD_HEADER_LENGTH_STD,BWD_HEADER_LENGTH_TOTAL,\
            BWD_HEADER_LENGTH_MAX,BWD_HEADER_LENGTH_MIN,BWD_HEADER_LENGTH_MEAN,\
            BWD_HEADER_LENGTH_STD,FWD_SEGMENT_LENGTH_MEAN,BWD_SEGMENT_LENGTH_MEAN,\
            FLOW_SEGMENT_LENGTH_MEAN,FWD_INIT_WIN_BYTES,BWD_INIT_WIN_BYTES,ACTIVE_MIN,\
            ACTIVE_MAX,ACTIVE_MEAN,ACTIVE_STD,IDLE_MIN,IDLE_MAX,IDLE_MEAN,IDLE_STD,\
            THROUGHPUT_MEAN,THROUGHPUT_FWD_MEAN,THROUGHPUT_BWD_MEAN,THROUGHPUT_TOTAL_MEAN,\
            THROUGHPUT_TOTAL_MAX,DOWN_UP_RATIO,FWD_BYTES_BULK,FWD_PACKETS_BULK,FWD_BULK_RATE,\
            BWD_BYTES_BULK,BWD_PACKETS_BULK,BWD_BULK_RATE,FWD_BULK_STATE_COUNT,\
            FWD_BULK_SIZE_TOTAL,FWD_BULK_PACKET_COUNT,FWD_BULK_DURATION,BWD_BULK_STATE_COUNT,\
            BWD_BULK_SIZE_TOTAL,BWD_BULK_PACKET_COUNT,BWD_BULK_DURATION,FLOW_FIN_COUNT,\
            FLOW_PSH_COUNT,FLOW_URG_COUNT,FLOW_ECE_COUNT,FLOW_SYN_COUNT,FLOW_ACK_COUNT,\
            FLOW_CWE_COUNT,FLOW_RST_COUNT,FWD_FIN_COUNT,FWD_PSH_COUNT,FWD_URG_COUNT,\
            FWD_ECE_COUNT,FWD_SYN_COUNT,FWD_ACK_COUNT,FWD_CWE_COUNT,FWD_RST_COUNT,\
            BWD_FIN_COUNT,BWD_PSH_COUNT,BWD_URG_COUNT,BWD_ECE_COUNT,BWD_SYN_COUNT,\
            BWD_ACK_COUNT,BWD_CWE_COUNT,BWD_RST_COUNT,FLOW_IAT_MEAN,FLOW_IAT_STD,\
            FLOW_IAT_MAX,FLOW_IAT_MIN,FWD_IAT_TOTAL,BWD_IAT_TOTAL,FWD_IAT_MEAN,\
            FWD_IAT_STD,FWD_IAT_MAX,FWD_IAT_MIN,BWD_IAT_MEAN,BWD_IAT_STD,BWD_IAT_MAX,\
            BWD_IAT_MIN,SF_FWD_PACKETS,SF_BWD_PACKETS,SF_FWD_BYTES,SF_BWD_BYTES"
        )
    }

    fn dump_without_contamination(&self) -> String {
        // Can be further updated after more research
        format!(
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{},{},{},{}",
            get_duration(
                self.basic_flow.basic_flow.first_timestamp,
                self.basic_flow.basic_flow.last_timestamp
            ),
            self.basic_flow.basic_flow.fwd_packet_count
                + self.basic_flow.basic_flow.bwd_packet_count,
            self.basic_flow.basic_flow.fwd_packet_count,
            self.basic_flow.basic_flow.bwd_packet_count,
            self.basic_flow.fwd_pkt_len_tot + self.basic_flow.bwd_pkt_len_tot,
            self.basic_flow.fwd_pkt_len_tot,
            self.basic_flow.bwd_pkt_len_tot,
            self.basic_flow.get_flow_packet_length_max(),
            self.basic_flow.get_flow_packet_length_min(),
            self.basic_flow.get_flow_packet_length_mean(),
            self.basic_flow.get_flow_packet_length_std(),
            self.basic_flow.get_flow_packet_length_variance(),
            self.basic_flow.fwd_pkt_len_max,
            self.basic_flow.get_fwd_packet_length_min(),
            self.basic_flow.fwd_pkt_len_mean,
            self.basic_flow.fwd_pkt_len_std,
            self.basic_flow.fwd_pkt_len_std.powf(2.0),
            self.basic_flow.bwd_pkt_len_max,
            self.basic_flow.get_bwd_packet_length_min(),
            self.basic_flow.bwd_pkt_len_mean,
            self.basic_flow.bwd_pkt_len_std,
            self.basic_flow.bwd_pkt_len_std.powf(2.0),
            self.basic_flow.fwd_header_length + self.basic_flow.bwd_header_length,
            self.get_flow_header_length_max(),
            self.get_flow_header_length_min(),
            self.get_flow_header_length_mean(),
            self.get_flow_header_length_std(),
            self.basic_flow.fwd_header_length,
            self.fwd_header_len_max,
            self.get_fwd_header_length_min(),
            self.fwd_header_len_mean,
            self.fwd_header_len_std,
            self.basic_flow.bwd_header_length,
            self.bwd_header_len_max,
            self.get_bwd_header_length_min(),
            self.bwd_header_len_mean,
            self.bwd_header_len_std,
            self.basic_flow.get_fwd_segment_length_mean(),
            self.basic_flow.get_bwd_segment_length_mean(),
            self.basic_flow.get_flow_segment_length_mean(),
            self.basic_flow.fwd_init_win_bytes,
            self.basic_flow.bwd_init_win_bytes,
            self.basic_flow.get_active_min(),
            self.basic_flow.active_max,
            self.basic_flow.active_mean,
            self.basic_flow.active_std,
            self.basic_flow.get_idle_min(),
            self.basic_flow.idle_max,
            self.basic_flow.idle_mean,
            self.basic_flow.idle_std,
            (self.basic_flow.fwd_pkt_len_tot + self.basic_flow.bwd_pkt_len_tot) as f64
                / (get_duration(
                    self.basic_flow.basic_flow.first_timestamp,
                    self.basic_flow.basic_flow.last_timestamp
                ))
                / 1_000_000.0,
            self.basic_flow.fwd_pkt_len_tot as f64
                / (get_duration(
                    self.basic_flow.basic_flow.first_timestamp,
                    self.basic_flow.basic_flow.last_timestamp
                ))
                / 1_000_000.0,
            self.basic_flow.bwd_pkt_len_tot as f64
                / (get_duration(
                    self.basic_flow.basic_flow.first_timestamp,
                    self.basic_flow.basic_flow.last_timestamp
                ))
                / 1_000_000.0,
            (self.basic_flow.basic_flow.fwd_packet_count
                + self.basic_flow.basic_flow.bwd_packet_count) as f64
                / (get_duration(
                    self.basic_flow.basic_flow.first_timestamp,
                    self.basic_flow.basic_flow.last_timestamp
                ))
                / 1_000_000.0,
            self.basic_flow.basic_flow.bwd_packet_count as f64
                / (get_duration(
                    self.basic_flow.basic_flow.first_timestamp,
                    self.basic_flow.basic_flow.last_timestamp
                ))
                / 1_000_000.0,
            self.basic_flow.basic_flow.fwd_packet_count as f64
                / (get_duration(
                    self.basic_flow.basic_flow.first_timestamp,
                    self.basic_flow.basic_flow.last_timestamp
                ))
                / 1_000_000.0,
            self.basic_flow.get_down_up_ratio(),
            self.basic_flow.get_fwd_bytes_bulk(),
            self.basic_flow.get_fwd_packets_bulk(),
            self.basic_flow.get_fwd_bulk_rate(),
            self.basic_flow.get_bwd_bytes_bulk(),
            self.basic_flow.get_bwd_packets_bulk(),
            self.basic_flow.get_bwd_bulk_rate(),
            self.basic_flow.fwd_bulk_state_count,
            self.basic_flow.fwd_bulk_size_total,
            self.basic_flow.fwd_bulk_packet_count,
            self.basic_flow.fwd_bulk_duration,
            self.basic_flow.bwd_bulk_state_count,
            self.basic_flow.bwd_bulk_size_total,
            self.basic_flow.bwd_bulk_packet_count,
            self.basic_flow.bwd_bulk_duration,
            self.basic_flow.basic_flow.fwd_fin_flag_count
                + self.basic_flow.basic_flow.bwd_fin_flag_count,
            self.basic_flow.basic_flow.fwd_psh_flag_count
                + self.basic_flow.basic_flow.bwd_psh_flag_count,
            self.basic_flow.basic_flow.fwd_urg_flag_count
                + self.basic_flow.basic_flow.bwd_urg_flag_count,
            self.basic_flow.basic_flow.fwd_ece_flag_count
                + self.basic_flow.basic_flow.bwd_ece_flag_count,
            self.basic_flow.basic_flow.fwd_syn_flag_count
                + self.basic_flow.basic_flow.bwd_syn_flag_count,
            self.basic_flow.basic_flow.fwd_ack_flag_count
                + self.basic_flow.basic_flow.bwd_ack_flag_count,
            self.basic_flow.basic_flow.fwd_cwe_flag_count
                + self.basic_flow.basic_flow.bwd_cwe_flag_count,
            self.basic_flow.basic_flow.fwd_rst_flag_count
                + self.basic_flow.basic_flow.bwd_rst_flag_count,
            self.basic_flow.basic_flow.fwd_fin_flag_count,
            self.basic_flow.basic_flow.fwd_psh_flag_count,
            self.basic_flow.basic_flow.fwd_urg_flag_count,
            self.basic_flow.basic_flow.fwd_ece_flag_count,
            self.basic_flow.basic_flow.fwd_syn_flag_count,
            self.basic_flow.basic_flow.fwd_ack_flag_count,
            self.basic_flow.basic_flow.fwd_cwe_flag_count,
            self.basic_flow.basic_flow.fwd_rst_flag_count,
            self.basic_flow.basic_flow.bwd_fin_flag_count,
            self.basic_flow.basic_flow.bwd_psh_flag_count,
            self.basic_flow.basic_flow.bwd_urg_flag_count,
            self.basic_flow.basic_flow.bwd_ece_flag_count,
            self.basic_flow.basic_flow.bwd_syn_flag_count,
            self.basic_flow.basic_flow.bwd_ack_flag_count,
            self.basic_flow.basic_flow.bwd_cwe_flag_count,
            self.basic_flow.basic_flow.bwd_rst_flag_count,
            self.basic_flow.get_flow_iat_mean(),
            self.basic_flow.get_flow_iat_std(),
            self.basic_flow.get_flow_iat_max(),
            self.basic_flow.get_flow_iat_min(),
            self.basic_flow.fwd_iat_total + self.basic_flow.bwd_iat_total,
            self.basic_flow.fwd_iat_mean,
            self.basic_flow.fwd_iat_std,
            self.basic_flow.fwd_iat_max,
            self.basic_flow.get_fwd_iat_min(),
            self.basic_flow.fwd_iat_total,
            self.basic_flow.bwd_iat_mean,
            self.basic_flow.bwd_iat_std,
            self.basic_flow.bwd_iat_max,
            self.basic_flow.get_bwd_iat_min(),
            self.basic_flow.bwd_iat_total,
            self.basic_flow.get_sf_fwd_packets(),
            self.basic_flow.get_sf_bwd_packets(),
            self.basic_flow.get_sf_fwd_bytes(),
            self.basic_flow.get_sf_bwd_bytes(),
        )
    }

    fn get_features_without_contamination() -> String {
        format!(
            "DURATION,TOTAL_PACKETS,FWD_PACKETS,BWD_PACKETS,TOTAL_BYTES,FWD_BYTES,BWD_BYTES,\
            PACKET_LENGTH_MAX,PACKET_LENGTH_MIN,PACKET_LENGTH_MEAN,PACKET_LENGTH_STD,\
            PACKET_LENGTH_VARIANCE,FWD_PACKET_LENGTH_MAX,FWD_PACKET_LENGTH_MIN,\
            FWD_PACKET_LENGTH_MEAN,FWD_PACKET_LENGTH_STD,FWD_PACKET_LENGTH_VARIANCE,\
            BWD_PACKET_LENGTH_MAX,BWD_PACKET_LENGTH_MIN,BWD_PACKET_LENGTH_MEAN,\
            BWD_PACKET_LENGTH_STD,BWD_PACKET_LENGTH_VARIANCE,HEADER_LENGTH_TOTAL,\
            HEADER_LENGTH_MAX,HEADER_LENGTH_MIN,HEADER_LENGTH_MEAN,HEADER_LENGTH_STD,\
            FWD_HEADER_LENGTH_TOTAL,FWD_HEADER_LENGTH_MAX,FWD_HEADER_LENGTH_MIN,\
            FWD_HEADER_LENGTH_MEAN,FWD_HEADER_LENGTH_STD,BWD_HEADER_LENGTH_TOTAL,\
            BWD_HEADER_LENGTH_MAX,BWD_HEADER_LENGTH_MIN,BWD_HEADER_LENGTH_MEAN,\
            BWD_HEADER_LENGTH_STD,FWD_SEGMENT_LENGTH_MEAN,BWD_SEGMENT_LENGTH_MEAN,\
            FLOW_SEGMENT_LENGTH_MEAN,FWD_INIT_WIN_BYTES,BWD_INIT_WIN_BYTES,ACTIVE_MIN,\
            ACTIVE_MAX,ACTIVE_MEAN,ACTIVE_STD,IDLE_MIN,IDLE_MAX,IDLE_MEAN,IDLE_STD,\
            THROUGHPUT_MEAN,THROUGHPUT_FWD_MEAN,THROUGHPUT_BWD_MEAN,THROUGHPUT_TOTAL_MEAN,\
            THROUGHPUT_TOTAL_MAX,DOWN_UP_RATIO,FWD_BYTES_BULK,FWD_PACKETS_BULK,FWD_BULK_RATE,\
            BWD_BYTES_BULK,BWD_PACKETS_BULK,BWD_BULK_RATE,FWD_BULK_STATE_COUNT,\
            FWD_BULK_SIZE_TOTAL,FWD_BULK_PACKET_COUNT,FWD_BULK_DURATION,BWD_BULK_STATE_COUNT,\
            BWD_BULK_SIZE_TOTAL,BWD_BULK_PACKET_COUNT,BWD_BULK_DURATION,FLOW_FIN_COUNT,\
            FLOW_PSH_COUNT,FLOW_URG_COUNT,FLOW_ECE_COUNT,FLOW_SYN_COUNT,FLOW_ACK_COUNT,\
            FLOW_CWE_COUNT,FLOW_RST_COUNT,FWD_FIN_COUNT,FWD_PSH_COUNT,FWD_URG_COUNT,\
            FWD_ECE_COUNT,FWD_SYN_COUNT,FWD_ACK_COUNT,FWD_CWE_COUNT,FWD_RST_COUNT,\
            BWD_FIN_COUNT,BWD_PSH_COUNT,BWD_URG_COUNT,BWD_ECE_COUNT,BWD_SYN_COUNT,\
            BWD_ACK_COUNT,BWD_CWE_COUNT,BWD_RST_COUNT,FLOW_IAT_MEAN,FLOW_IAT_STD,\
            FLOW_IAT_MAX,FLOW_IAT_MIN,FWD_IAT_TOTAL,BWD_IAT_TOTAL,FWD_IAT_MEAN,\
            FWD_IAT_STD,FWD_IAT_MAX,FWD_IAT_MIN,BWD_IAT_MEAN,BWD_IAT_STD,BWD_IAT_MAX,\
            BWD_IAT_MIN,SF_FWD_PACKETS,SF_BWD_PACKETS,SF_FWD_BYTES,SF_BWD_BYTES"
        )
    }

    fn get_first_timestamp(&self) -> DateTime<Utc> {
        self.basic_flow.get_first_timestamp()
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use crate::flows::flow::Flow;

    use super::NTLFlow;

    fn setup_ntl_flow() -> NTLFlow {
        NTLFlow::new(
            "".to_string(),
            IpAddr::V4(Ipv4Addr::from(1)),
            80,
            IpAddr::V4(Ipv4Addr::from(2)),
            8080,
            6,
            chrono::Utc::now(),
        )
    }

    #[test]
    fn test_update_fwd_pkt_len_stats() {
        let mut ntl_flow = setup_ntl_flow();

        ntl_flow.basic_flow.basic_flow.fwd_packet_count = 1;

        ntl_flow.update_fwd_header_len_stats(100);

        assert_eq!(ntl_flow.fwd_header_len_max, 100);
        assert_eq!(ntl_flow.fwd_header_len_min, 100);
        assert_eq!(ntl_flow.fwd_header_len_mean, 100.0);
        assert_eq!(ntl_flow.fwd_header_len_std, 0.0);
        assert_eq!(ntl_flow.basic_flow.fwd_header_length, 100);

        ntl_flow.basic_flow.basic_flow.fwd_packet_count = 2;

        ntl_flow.update_fwd_header_len_stats(50);

        assert_eq!(ntl_flow.fwd_header_len_max, 100);
        assert_eq!(ntl_flow.fwd_header_len_min, 50);
        assert_eq!(ntl_flow.fwd_header_len_mean, 75.0);
        assert_eq!(ntl_flow.fwd_header_len_std, 25.0);
        assert_eq!(ntl_flow.basic_flow.fwd_header_length, 150);

        ntl_flow.basic_flow.basic_flow.fwd_packet_count = 3;

        ntl_flow.update_fwd_header_len_stats(0);

        assert_eq!(ntl_flow.fwd_header_len_max, 100);
        assert_eq!(ntl_flow.fwd_header_len_min, 0);
        assert_eq!(ntl_flow.fwd_header_len_mean, 50.0);
        assert_eq!(ntl_flow.fwd_header_len_std, 40.824829046386306);
        assert_eq!(ntl_flow.basic_flow.fwd_header_length, 150);
    }

    #[test]
    fn test_update_bwd_pkt_len_stats() {
        let mut ntl_flow = setup_ntl_flow();

        ntl_flow.basic_flow.basic_flow.bwd_packet_count = 1;

        ntl_flow.update_bwd_header_len_stats(100);

        assert_eq!(ntl_flow.bwd_header_len_max, 100);
        assert_eq!(ntl_flow.bwd_header_len_min, 100);
        assert_eq!(ntl_flow.bwd_header_len_mean, 100.0);
        assert_eq!(ntl_flow.bwd_header_len_std, 0.0);
        assert_eq!(ntl_flow.basic_flow.bwd_header_length, 100);

        ntl_flow.basic_flow.basic_flow.bwd_packet_count = 2;

        ntl_flow.update_bwd_header_len_stats(50);

        assert_eq!(ntl_flow.bwd_header_len_max, 100);
        assert_eq!(ntl_flow.bwd_header_len_min, 50);
        assert_eq!(ntl_flow.bwd_header_len_mean, 75.0);
        assert_eq!(ntl_flow.bwd_header_len_std, 25.0);
        assert_eq!(ntl_flow.basic_flow.bwd_header_length, 150);

        ntl_flow.basic_flow.basic_flow.bwd_packet_count = 3;

        ntl_flow.update_bwd_header_len_stats(0);

        assert_eq!(ntl_flow.bwd_header_len_max, 100);
        assert_eq!(ntl_flow.bwd_header_len_min, 0);
        assert_eq!(ntl_flow.bwd_header_len_mean, 50.0);
        assert_eq!(ntl_flow.bwd_header_len_std, 40.824829046386306);
        assert_eq!(ntl_flow.basic_flow.bwd_header_length, 150);
    }

    #[test]
    fn test_get_fwd_header_length_min() {
        let mut cic_flow = setup_ntl_flow();

        assert_eq!(cic_flow.get_fwd_header_length_min(), 0);

        cic_flow.fwd_header_len_min = 50;

        assert_eq!(cic_flow.get_fwd_header_length_min(), 50);
    }

    #[test]
    fn test_get_bwd_header_length_min() {
        let mut cic_flow = setup_ntl_flow();

        assert_eq!(cic_flow.get_bwd_header_length_min(), 0);

        cic_flow.bwd_header_len_min = 100;

        assert_eq!(cic_flow.get_bwd_header_length_min(), 100);
    }

    #[test]
    fn test_get_flow_packet_length_min() {
        let mut cic_flow = setup_ntl_flow();

        cic_flow.fwd_header_len_min = 100;
        cic_flow.bwd_header_len_min = 50;

        assert_eq!(cic_flow.get_flow_header_length_min(), 50);
    }

    #[test]
    fn test_get_flow_packet_length_max() {
        let mut cic_flow = setup_ntl_flow();

        cic_flow.fwd_header_len_max = 100;
        cic_flow.bwd_header_len_max = 50;

        assert_eq!(cic_flow.get_flow_header_length_max(), 100);
    }

    #[test]
    fn test_get_flow_packet_length_mean() {
        let mut cic_flow = setup_ntl_flow();

        //let forward_iat = [10, 20, 30, 40, 50];
        //let backward_iat = [15, 25, 35];

        cic_flow.fwd_header_len_mean = 30.0;
        cic_flow.bwd_header_len_mean = 25.0;

        cic_flow.basic_flow.basic_flow.fwd_packet_count = 5;
        cic_flow.basic_flow.basic_flow.bwd_packet_count = 3;

        assert_eq!(cic_flow.get_flow_header_length_mean(), 28.125);
    }

    #[test]
    fn test_get_flow_packet_length_variance() {
        let mut cic_flow = setup_ntl_flow();

        //let forward_iat = [10, 20, 30, 40, 50];
        //let backward_iat = [15, 25, 35];

        cic_flow.fwd_header_len_std = 14.142135623731;
        cic_flow.bwd_header_len_std = 8.1649658092773;

        cic_flow.basic_flow.basic_flow.fwd_packet_count = 5;
        cic_flow.basic_flow.basic_flow.bwd_packet_count = 3;

        assert_eq!(cic_flow.get_flow_header_length_variance() as u32, 155); // removing everything behind the comma because of arithmetic errors
    }

    #[test]
    fn test_get_flow_packet_length_std() {
        let mut cic_flow = setup_ntl_flow();
        let epsilon = 1e-1; // floating-point arithmetic is not exact, here we have a lot of casting and the formula is also an approximation

        //let forward_iat = [10, 20, 30, 40, 50];
        //let backward_iat = [15, 25, 35];

        cic_flow.fwd_header_len_std = 14.142135623731;
        cic_flow.bwd_header_len_std = 8.1649658092773;

        cic_flow.basic_flow.basic_flow.fwd_packet_count = 5;
        cic_flow.basic_flow.basic_flow.bwd_packet_count = 3;

        assert!(
            (cic_flow.get_flow_header_length_std() - 12.484365222149).abs() < epsilon,
            "get_flow_packet_length_std is not within the expected range"
        );
    }
}
