use chrono::{DateTime, Utc};
use std::{net::IpAddr, ops::Deref, time::Instant};

use crate::{
    utils::utils::{calculate_mean, calculate_std, get_duration, BasicFeatures},
    NO_CONTAMINANT_FEATURES,
};

use super::{basic_flow::BasicFlow, flow::Flow};

/// Represents a CIC Flow, encapsulating various metrics and states of a network flow.
///
/// This struct includes detailed information about both forward and backward
/// flow, active and idle times, as well as subflows.
pub struct CicFlow {
    /// The basic flow information.
    pub basic_flow: BasicFlow,
    /// The timestamp of the last packet in the subflow.
    pub sf_last_packet_timestamp: Option<Instant>,
    /// The number of subflows.
    pub sf_count: u32,
    /// The timestamp of the start of an active period.
    pub start_active: Instant,
    /// The timestamp of the end of an active period.
    pub end_active: Instant,
    /// The number of active periods.
    pub active_count: u32,
    /// The mean of active periods.
    pub active_mean: f64,
    /// The standard deviation of active periods.
    pub active_std: f64,
    /// The maximum active period.
    pub active_max: f64,
    /// The minimum active period.
    active_min: f64,
    /// The number of idle periods.
    pub idle_count: u32,
    /// The mean of idle periods.
    pub idle_mean: f64,
    /// The standard deviation of idle periods.
    pub idle_std: f64,
    /// The maximum idle period.
    pub idle_max: f64,
    /// The minimum idle period.
    idle_min: f64,
    /// The initial window size of the forward flow.
    pub fwd_init_win_bytes: u16,
    /// The number of data packets in the forward flow with more than one byte of data.
    pub fwd_act_data_pkt: u32,
    /// The minimum header length of the forward flow.
    fwd_header_len_min: u32,
    /// The timestamp of the last packet in the forward flow.
    pub fwd_last_timestamp: Option<Instant>,
    /// The total length of packets in the forward flow.
    pub fwd_pkt_len_tot: u32,
    /// The total length of transport layer segments in the forward flow (tcp/udp header + data).
    pub fwd_seg_len_tot: u32,
    /// The maximum length of packets in the forward flow.
    pub fwd_pkt_len_max: u32,
    /// The minimum length of packets in the forward flow.
    fwd_pkt_len_min: u32,
    /// The mean length of packets in the forward flow.
    pub fwd_pkt_len_mean: f32,
    /// The standard deviation of the length of packets in the forward flow.
    pub fwd_pkt_len_std: f32,
    /// The total inter-arrival time of packets in the forward flow.
    pub fwd_iat_total: f64,
    /// The mean inter-arrival time of packets in the forward flow.
    pub fwd_iat_mean: f64,
    /// The standard deviation of the inter-arrival time of packets in the forward flow.
    pub fwd_iat_std: f64,
    /// The maximum inter-arrival time of packets in the forward flow.
    pub fwd_iat_max: f64,
    /// The minimum inter-arrival time of packets in the forward flow.
    fwd_iat_min: f64,
    /// The total header length of the forward flow.
    pub fwd_header_length: u32,
    /// The total duration of bulk packets in the forward flow.
    pub fwd_bulk_duration: f64,
    /// The number of bulk packets in the forward flow.
    pub fwd_bulk_packet_count: u64,
    /// The total size of bulk packets in the forward flow.
    pub fwd_bulk_size_total: u32,
    /// The number of bulk states in the forward flow.
    pub fwd_bulk_state_count: u64,
    /// Helper variable for bulk packet count.
    fwd_bulk_packet_count_help: u64,
    /// Helper variable for bulk start timestamp.
    fwd_bulk_start_help: Option<Instant>,
    /// Helper variable for bulk size.
    fwd_bulk_size_help: u32,
    /// The timestamp of the last bulk packet in the forward flow.
    pub fwd_last_bulk_timestamp: Option<Instant>,
    /// The initial window size of the backward flow.
    pub bwd_init_win_bytes: u16,
    /// The timestamp of the last packet in the backward flow.
    pub bwd_last_timestamp: Option<Instant>,
    /// The total length of packets in the backward flow.
    pub bwd_pkt_len_tot: u32,
    /// The total length of transport layer segments in the backward flow (tcp/udp header + data).
    pub bwd_seg_len_tot: u32,
    /// The maximum length of packets in the backward flow.
    pub bwd_pkt_len_max: u32,
    /// The minimum length of packets in the backward flow.
    bwd_pkt_len_min: u32,
    /// The mean length of packets in the backward flow.
    pub bwd_pkt_len_mean: f32,
    /// The standard deviation of the length of packets in the backward flow.
    pub bwd_pkt_len_std: f32,
    /// The total inter-arrival time of packets in the backward flow.
    pub bwd_iat_total: f64,
    /// The mean inter-arrival time of packets in the backward flow.
    pub bwd_iat_mean: f64,
    /// The standard deviation of the inter-arrival time of packets in the backward flow.
    pub bwd_iat_std: f64,
    /// The maximum inter-arrival time of packets in the backward flow.
    pub bwd_iat_max: f64,
    /// The minimum inter-arrival time of packets in the backward flow.
    bwd_iat_min: f64,
    /// The total header length of the backward flow.
    pub bwd_header_length: u32,
    /// The total duration of bulk packets in the backward flow.
    pub bwd_bulk_duration: f64,
    /// The number of bulk packets in the backward flow.
    pub bwd_bulk_packet_count: u64,
    /// The total size of bulk packets in the backward flow.
    pub bwd_bulk_size_total: u32,
    /// The number of bulk states in the backward flow.
    pub bwd_bulk_state_count: u64,
    /// Helper variable for bulk packet count.
    bwd_bulk_packet_count_help: u64,
    /// Helper variable for bulk start timestamp.
    bwd_bulk_start_help: Option<Instant>,
    /// Helper variable for bulk size.
    bwd_bulk_size_help: u32,
    /// The timestamp of the last bulk packet in the backward flow.
    bwd_last_bulk_timestamp: Option<Instant>,
}

impl CicFlow {
    /// Increases the length of the forward header.
    ///
    /// This method adds the specified length to the current forward header length.
    /// It's used to accumulate the total size of the headers over multiple packets.
    ///
    /// ### Arguments
    ///
    /// * `len` - The length to be added to the forward header length.
    fn increase_fwd_header_length(&mut self, len: u32) {
        self.fwd_header_length += len;
    }

    /// Increases the length of the backward header.
    ///
    /// Similar to `increase_fwd_header_length`, this method accumulates the length
    /// of backward headers. It's used in tracking the size of headers from the
    /// opposite direction of the flow.
    ///
    /// ### Arguments
    ///
    /// * `len` - The length to be added to the backward header length.
    fn increase_bwd_header_length(&mut self, len: u32) {
        self.bwd_header_length += len;
    }

    /// Updates the minimum length of the forward header.
    ///
    /// This method updates the minimum forward header length if the provided length
    /// is smaller than the current minimum.
    ///
    /// ### Arguments
    ///
    /// * `len` - The length to compare against the current minimum forward header length.
    fn update_fwd_header_len_min(&mut self, len: u32) {
        if len < self.fwd_header_len_min {
            self.fwd_header_len_min = len;
        }
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
    fn update_fwd_pkt_len_stats(&mut self, len: u32) {
        // update max and min
        if len > self.fwd_pkt_len_max {
            self.fwd_pkt_len_max = len;
        }
        if len < self.fwd_pkt_len_min {
            self.fwd_pkt_len_min = len;
        }

        // update total
        self.fwd_pkt_len_tot += len;

        // update mean and std
        let new_fwd_pkt_len_mean = calculate_mean(
            self.basic_flow.fwd_packet_count as u64,
            self.fwd_pkt_len_mean as f64,
            len as f64,
        ) as f32;
        self.fwd_pkt_len_std = calculate_std(
            self.basic_flow.fwd_packet_count as u64,
            self.fwd_pkt_len_std as f64,
            self.fwd_pkt_len_mean as f64,
            new_fwd_pkt_len_mean as f64,
            len as f64,
        ) as f32;
        self.fwd_pkt_len_mean = new_fwd_pkt_len_mean;
    }

    /// Updates statistics for the length of backward packets.
    ///
    /// Similar to `update_fwd_pkt_len_stats`, but for backward packets. It updates
    /// the statistical measures for packet sizes in the backward direction.
    ///
    /// ### Arguments
    ///
    /// * `len` - The length of the new backward packet to be included in the stats.
    fn update_bwd_pkt_len_stats(&mut self, len: u32) {
        // update max and min
        if len > self.bwd_pkt_len_max {
            self.bwd_pkt_len_max = len;
        }
        if len < self.bwd_pkt_len_min {
            self.bwd_pkt_len_min = len;
        }

        // update total
        self.bwd_pkt_len_tot += len;

        // update mean and std
        let new_bwd_pkt_len_mean = calculate_mean(
            self.basic_flow.bwd_packet_count as u64,
            self.bwd_pkt_len_mean as f64,
            len as f64,
        ) as f32;
        self.bwd_pkt_len_std = calculate_std(
            self.basic_flow.bwd_packet_count as u64,
            self.bwd_pkt_len_std as f64,
            self.bwd_pkt_len_mean as f64,
            new_bwd_pkt_len_mean as f64,
            len as f64,
        ) as f32;
        self.bwd_pkt_len_mean = new_bwd_pkt_len_mean;
    }

    /// Updates inter-arrival time (IAT) stats for forward packets.
    ///
    /// This method updates the maximum, minimum, total, mean, and standard deviation
    /// of inter-arrival times between forward packets.
    ///
    /// ### Arguments
    ///
    /// * `iat` - The inter-arrival time to be added to the statistics.
    fn update_fwd_iat_stats(&mut self, iat: f64) {
        // update max and min
        if iat > self.fwd_iat_max {
            self.fwd_iat_max = iat;
        }
        if iat < self.fwd_iat_min {
            self.fwd_iat_min = iat;
        }
        // update total
        self.fwd_iat_total += iat;

        // update mean and std
        let new_fwd_iat_mean = calculate_mean(
            (self.basic_flow.fwd_packet_count - 1) as u64,
            self.fwd_iat_mean,
            iat,
        );
        self.fwd_iat_std = calculate_std(
            (self.basic_flow.fwd_packet_count - 1) as u64,
            self.fwd_iat_std,
            self.fwd_iat_mean,
            new_fwd_iat_mean,
            iat,
        );
        self.fwd_iat_mean = new_fwd_iat_mean;
    }

    /// Updates inter-arrival time (IAT) stats for backward packets.
    ///
    /// Similar to `update_fwd_iat_stats`, but focuses on the inter-arrival times
    /// of backward packets.
    ///
    /// ### Arguments
    ///
    /// * `iat` - The backward inter-arrival time to be incorporated into the stats.
    fn update_bwd_iat_stats(&mut self, iat: f64) {
        // update max and min
        if iat > self.bwd_iat_max {
            self.bwd_iat_max = iat;
        }
        if iat < self.bwd_iat_min {
            self.bwd_iat_min = iat;
        }
        // update total
        self.bwd_iat_total += iat;

        // update mean and std
        let new_bwd_iat_mean = calculate_mean(
            (self.basic_flow.bwd_packet_count - 1) as u64,
            self.bwd_iat_mean,
            iat,
        );
        self.bwd_iat_std = calculate_std(
            (self.basic_flow.bwd_packet_count - 1) as u64,
            self.bwd_iat_std,
            self.bwd_iat_mean,
            new_bwd_iat_mean,
            iat,
        );
        self.bwd_iat_mean = new_bwd_iat_mean;
    }

    /// Updates the statistics for active flow periods.
    ///
    /// This method updates the count, mean, standard deviation, and max/min values
    /// for the durations of active flow periods.
    ///
    /// ### Arguments
    ///
    /// * `duration` - The duration of the active period to be included in the stats.
    fn update_active_flow(&mut self, duration: f64) {
        self.active_count += 1;

        // update max and min
        if duration > self.active_max {
            self.active_max = duration;
        }
        if duration < self.active_min {
            self.active_min = duration;
        }

        // update mean and std
        let new_active_mean = calculate_mean(self.active_count as u64, self.active_mean, duration);
        self.active_std = calculate_std(
            self.active_count as u64,
            self.active_std,
            self.active_mean,
            new_active_mean,
            duration,
        );
        self.active_mean = new_active_mean;
    }

    /// Updates the statistics for idle flow periods.
    ///
    /// Similar to `update_active_flow`, but for idle periods. This method updates
    /// the statistical measures related to the duration of idle periods in the flow.
    ///
    /// ### Arguments
    ///
    /// * `duration` - The duration of the idle period to be added to the stats.
    fn update_idle_flow(&mut self, duration: f64) {
        self.idle_count += 1;

        // update max and min
        if duration > self.idle_max {
            self.idle_max = duration;
        }
        if duration < self.idle_min {
            self.idle_min = duration;
        }

        // update mean and std
        let new_idle_mean = calculate_mean(self.idle_count as u64, self.idle_mean, duration);
        self.idle_std = calculate_std(
            self.idle_count as u64,
            self.idle_std,
            self.idle_mean,
            new_idle_mean,
            duration,
        );
        self.idle_mean = new_idle_mean;
    }

    /// Updates the forward bulk statistics based on the incoming packet.
    ///
    /// This method takes into account the timestamp and length of the packet to
    /// determine whether it's part of an existing bulk transfer or the start of a new one.
    /// It updates various metrics related to bulk transfers in the forward direction.
    ///
    /// ### Arguments
    ///
    /// * `timestamp` - The timestamp of the packet.
    /// * `len` - The length of the packet.
    fn update_fwd_bulk_stats(&mut self, timestamp: &Instant, len: u32) {
        if self.bwd_last_bulk_timestamp > self.fwd_bulk_start_help {
            self.fwd_bulk_start_help = None;
        }
        if len <= 0 {
            return;
        }

        if self.fwd_bulk_start_help == None {
            self.fwd_bulk_start_help = Some(*timestamp);
            self.fwd_bulk_packet_count_help = 1;
            self.fwd_bulk_size_help = len;
            self.fwd_last_bulk_timestamp = Some(*timestamp);
        } else {
            // too much idle time -> new bulk
            if timestamp
                .duration_since(self.fwd_last_bulk_timestamp.unwrap())
                .as_secs_f64()
                > 1.0
            {
                self.fwd_bulk_start_help = Some(*timestamp);
                self.fwd_last_bulk_timestamp = Some(*timestamp);
                self.fwd_bulk_packet_count_help = 1;
                self.fwd_bulk_size_help = len;
            } else {
                self.fwd_bulk_packet_count_help += 1;
                self.fwd_bulk_size_help += len;
                // new bulk
                if self.fwd_bulk_packet_count_help == 4 {
                    self.fwd_bulk_state_count += 1;
                    self.fwd_bulk_packet_count += self.fwd_bulk_packet_count_help;
                    self.fwd_bulk_size_total += self.fwd_bulk_size_help;
                    self.fwd_bulk_duration += timestamp
                        .duration_since(self.fwd_bulk_start_help.unwrap())
                        .as_micros() as f64;
                }
                // continu bulk
                else if self.fwd_bulk_packet_count_help > 4 {
                    self.fwd_bulk_packet_count += 1;
                    self.fwd_bulk_size_total += len;
                    self.fwd_bulk_duration += timestamp
                        .duration_since(self.fwd_bulk_start_help.unwrap())
                        .as_micros() as f64;
                }
            }
            self.fwd_last_bulk_timestamp = Some(*timestamp);
        }
    }

    /// Updates the backward bulk statistics in a similar manner to `update_fwd_bulk_stats`.
    ///
    /// It analyzes incoming packets in the backward direction and updates
    /// metrics related to bulk transfers based on the packet's timestamp and length.
    ///
    /// ### Arguments
    ///
    /// * `timestamp` - The timestamp of the packet.
    /// * `len` - The length of the packet.
    fn update_bwd_bulk_stats(&mut self, timestamp: &Instant, len: u32) {
        if self.fwd_last_bulk_timestamp > self.bwd_bulk_start_help {
            self.bwd_bulk_start_help = None;
        }
        if len <= 0 {
            return;
        }

        if self.bwd_bulk_start_help == None {
            self.bwd_bulk_start_help = Some(*timestamp);
            self.bwd_bulk_packet_count_help = 1;
            self.bwd_bulk_size_help = len;
            self.bwd_last_bulk_timestamp = Some(*timestamp);
        } else {
            // to much idle time -> new bulk
            if timestamp
                .duration_since(self.bwd_last_bulk_timestamp.unwrap())
                .as_secs_f64()
                > 1.0
            {
                self.bwd_bulk_start_help = Some(*timestamp);
                self.bwd_last_bulk_timestamp = Some(*timestamp);
                self.bwd_bulk_packet_count_help = 1;
                self.bwd_bulk_size_help = len;
            } else {
                self.bwd_bulk_packet_count_help += 1;
                self.bwd_bulk_size_help += len;
                // new bulk
                if self.bwd_bulk_packet_count_help == 4 {
                    self.bwd_bulk_state_count += 1;
                    self.bwd_bulk_packet_count += self.bwd_bulk_packet_count_help;
                    self.bwd_bulk_size_total += self.bwd_bulk_size_help;
                    self.bwd_bulk_duration += timestamp
                        .duration_since(self.bwd_bulk_start_help.unwrap())
                        .as_micros() as f64;
                }
                // continu bulk
                else if self.bwd_bulk_packet_count_help > 4 {
                    self.bwd_bulk_packet_count += 1;
                    self.bwd_bulk_size_total += len;
                    self.bwd_bulk_duration += timestamp
                        .duration_since(self.bwd_bulk_start_help.unwrap())
                        .as_micros() as f64;
                }
            }
            self.bwd_last_bulk_timestamp = Some(*timestamp);
        }
    }

    /// Updates the subflow count based on the timestamp of the incoming packet.
    ///
    /// This method increments the subflow count if the time since the last packet exceeds a threshold.
    /// It also updates the active and idle times of the flow based on the timestamp.
    ///
    /// ### Arguments
    ///
    /// * `timestamp` - The timestamp of the packet.
    fn update_subflows(&mut self, timestamp: &Instant) {
        if self.sf_last_packet_timestamp == None {
            self.sf_last_packet_timestamp = Some(*timestamp);
        }

        if timestamp
            .duration_since(self.sf_last_packet_timestamp.unwrap())
            .as_secs_f64()
            > 1.0
        {
            self.sf_count += 1;
            self.update_active_idle_time(timestamp, 5_000_000.0);
        }

        self.sf_last_packet_timestamp = Some(*timestamp);
    }

    /// Updates the active and idle time statistics of the flow.
    ///
    /// Based on the timestamp and a specified threshold, this method determines whether the flow is active or idle,
    /// and updates the respective statistics. It is used for tracking how long the flow has been in each state.
    ///
    /// ### Arguments
    ///
    /// * `timestamp` - The timestamp of the packet or event triggering the update.
    /// * `threshold` - The threshold in microseconds to determine state transitions between active and idle.
    fn update_active_idle_time(&mut self, timestamp: &Instant, threshold: f64) {
        if timestamp.duration_since(self.end_active).as_micros() as f64 > threshold {
            let duration = self.end_active.duration_since(self.start_active);
            if duration.as_secs_f64() > 0.0 {
                self.update_active_flow(duration.as_micros() as f64);
            }
            self.update_idle_flow(timestamp.duration_since(self.end_active).as_micros() as f64);
            self.start_active = *timestamp;
            self.end_active = *timestamp;
        } else {
            self.end_active = *timestamp;
        }
    }

    /// Retrieves the minimum length of the forward header.
    ///
    /// Returns the minimum length observed for forward headers. If no forward headers
    /// have been recorded, it returns 0.
    ///
    /// ### Returns
    ///
    /// The minimum length of the forward header or 0 if not set.
    fn get_fwd_header_len_min(&self) -> u32 {
        if self.fwd_header_len_min == u32::MAX {
            0
        } else {
            self.fwd_header_len_min
        }
    }

    /// Calculates the pooled standard deviation of inter-arrival times (IAT) for the flow.
    ///
    /// This method considers both forward and backward packet inter-arrival times to compute
    /// a pooled variance, which is then square-rooted to get the standard deviation.
    ///
    /// ### Returns
    ///
    /// Pooled standard deviation of the flow's IATs.
    pub fn get_flow_iat_std(&self) -> f64 {
        if self.basic_flow.fwd_packet_count < 1
            || self.basic_flow.bwd_packet_count < 1
            || self.basic_flow.fwd_packet_count + self.basic_flow.bwd_packet_count < 3
        {
            return 0.0;
        }

        let fwd_iat_std_squared = self.fwd_iat_std.powi(2);
        let bwd_iat_std_squared = self.bwd_iat_std.powi(2);

        let pooled_variance = ((self.basic_flow.fwd_packet_count - 1) as f64 * fwd_iat_std_squared
            + (self.basic_flow.bwd_packet_count - 1) as f64 * bwd_iat_std_squared)
            / (self.basic_flow.fwd_packet_count + self.basic_flow.bwd_packet_count - 2) as f64;

        pooled_variance.sqrt()
    }

    /// Calculates the mean inter-arrival time (IAT) for the flow.
    ///
    /// Averages the IATs of forward and backward packets to compute the overall mean IAT of the flow.
    ///
    /// ### Returns
    ///
    /// Mean inter-arrival time of the flow.
    pub fn get_flow_iat_mean(&self) -> f64 {
        (self.fwd_iat_mean * self.basic_flow.fwd_packet_count as f64
            + self.bwd_iat_mean * self.basic_flow.bwd_packet_count as f64)
            / (self.basic_flow.fwd_packet_count + self.basic_flow.bwd_packet_count) as f64
    }

    /// Retrieves the maximum inter-arrival time (IAT) observed in the flow.
    ///
    /// Compares the maximum IATs in both directions (forward and backward) and returns the larger one.
    ///
    /// ### Returns
    ///
    /// Maximum inter-arrival time observed in the flow.
    pub fn get_flow_iat_max(&self) -> f64 {
        if self.fwd_iat_max > self.bwd_iat_max {
            return self.fwd_iat_max;
        }
        self.bwd_iat_max
    }

    /// Retrieves the minimum inter-arrival time (IAT) observed in the flow.
    ///
    /// Compares the minimum IATs in both directions and returns the smaller one, or 0 if not set.
    ///
    /// ### Returns
    ///
    /// Minimum inter-arrival time observed in the flow or 0 if not set.
    pub fn get_flow_iat_min(&self) -> f64 {
        if self.fwd_iat_min < self.bwd_iat_min {
            if self.fwd_iat_min == f64::MAX {
                return 0.0;
            }
            self.fwd_iat_min
        } else {
            if self.bwd_iat_min == f64::MAX {
                return 0.0;
            }
            self.bwd_iat_min
        }
    }

    /// Retrieves the minimum IAT of packets in the forward flow.
    ///
    /// Compares the minimum IAT to the max of the f64 type and returns the IAT if it is not the same as the max value.
    ///
    /// ### Returns
    ///
    /// The minimum IAT observed in the forward flow or 0 if not set.
    pub fn get_fwd_iat_min(&self) -> f64 {
        if self.fwd_iat_min == f64::MAX {
            return 0.0;
        }
        self.fwd_iat_min
    }

    /// Retrieves the minimum IAT of packets in the backward flow.
    ///
    /// Compares the minimum IAT to the max of the f64 type and returns the IAT if it is not the same as the max value.
    ///
    /// ### Returns
    ///
    /// The minimum IAT observed in the backward flow or 0 if not set.
    pub fn get_bwd_iat_min(&self) -> f64 {
        if self.bwd_iat_min == f64::MAX {
            return 0.0;
        }
        self.bwd_iat_min
    }

    /// Retrieves the minimum packet length in the flow, considering both forward and backward directions.
    ///
    /// Compares the minimum packet lengths of forward and backward flows and returns the smaller value.
    /// Returns 0 if the minimum length is not set (indicated by `u32::MAX`).
    ///
    /// ### Returns
    ///
    /// Minimum packet length in the flow, or 0 if not set.
    pub fn get_flow_packet_length_min(&self) -> u32 {
        if self.fwd_pkt_len_min < self.bwd_pkt_len_min {
            if self.fwd_pkt_len_min == u32::MAX {
                return 0;
            }
            self.fwd_pkt_len_min
        } else {
            if self.bwd_pkt_len_min == u32::MAX {
                return 0;
            }
            self.bwd_pkt_len_min
        }
    }

    /// Retrieves the maximum packet length in the flow, considering both forward and backward directions.
    ///
    /// Compares the maximum packet lengths of forward and backward flows and returns the larger value.
    ///
    /// ### Returns
    ///
    /// Maximum packet length in the flow.
    pub fn get_flow_packet_length_max(&self) -> u32 {
        if self.fwd_pkt_len_max > self.bwd_pkt_len_max {
            return self.fwd_pkt_len_max;
        }
        self.bwd_pkt_len_max
    }

    /// Retrieves the minimum packet length for forward packets.
    ///
    /// Returns the minimum packet length observed in the forward direction.
    /// Returns 0 if the minimum length is not set (indicated by `u32::MAX`).
    ///
    /// ### Returns
    ///
    /// Minimum forward packet length, or 0 if not set.
    pub fn get_fwd_packet_length_min(&self) -> u32 {
        if self.fwd_pkt_len_min == u32::MAX {
            return 0;
        }
        self.fwd_pkt_len_min
    }

    /// Retrieves the minimum packet length for backward packets.
    ///
    /// Returns the minimum packet length observed in the backward direction.
    /// Returns 0 if the minimum length is not set (indicated by `u32::MAX`).
    ///
    /// ### Returns
    ///
    /// Minimum backward packet length, or 0 if not set.
    pub fn get_bwd_packet_length_min(&self) -> u32 {
        if self.bwd_pkt_len_min == u32::MAX {
            return 0;
        }
        self.bwd_pkt_len_min
    }

    /// Calculates the mean packet length of the flow, averaging both forward and backward packet lengths.
    ///
    /// The mean is computed by considering the lengths and counts of packets in both directions.
    ///
    /// ### Returns
    ///
    /// Mean packet length of the flow.
    pub fn get_flow_packet_length_mean(&self) -> f32 {
        (self.fwd_pkt_len_mean * self.basic_flow.fwd_packet_count as f32
            + self.bwd_pkt_len_mean * self.basic_flow.bwd_packet_count as f32) as f32
            / (self.basic_flow.fwd_packet_count + self.basic_flow.bwd_packet_count) as f32
    }

    /// Calculates the mean packet segment length of the flow, averaging both forward and backward packet segment lengths.
    ///
    /// The mean is computed by considering the lengths and counts of packets in both directions.
    ///
    /// ### Returns
    ///
    /// Mean packet segment length of the flow.
    pub fn get_flow_segment_length_mean(&self) -> f32 {
        (self.get_fwd_segment_length_mean() * self.basic_flow.fwd_packet_count as f32
            + self.get_bwd_segment_length_mean() * self.basic_flow.bwd_packet_count as f32)
            as f32
            / (self.basic_flow.fwd_packet_count + self.basic_flow.bwd_packet_count) as f32
    }

    /// Calculates the variance of the packet lengths in the flow.
    ///
    /// Computes the variance by considering the standard deviations of packet lengths
    /// in both forward and backward directions.
    ///
    /// ### Returns
    ///
    /// Variance of the flow's packet lengths, or 0 if not enough data.
    pub fn get_flow_packet_length_variance(&self) -> f64 {
        if self.basic_flow.fwd_packet_count < 1
            || self.basic_flow.bwd_packet_count < 1
            || self.basic_flow.fwd_packet_count + self.basic_flow.bwd_packet_count < 3
        {
            return 0.0;
        }

        let fwd_pkt_std_squared = self.fwd_pkt_len_std.powf(2.0);
        let bwd_pkt_std_squared = self.bwd_pkt_len_std.powf(2.0);

        ((self.basic_flow.fwd_packet_count - 1) as f64 * fwd_pkt_std_squared as f64
            + (self.basic_flow.bwd_packet_count - 1) as f64 * bwd_pkt_std_squared as f64)
            / (self.basic_flow.fwd_packet_count + self.basic_flow.bwd_packet_count - 2) as f64
    }

    /// Retrieves the standard deviation of packet lengths in the flow.
    ///
    /// Utilizes the calculated variance of packet lengths to compute the standard deviation.
    ///
    /// ### Returns
    ///
    /// Standard deviation of the flow's packet lengths.
    pub fn get_flow_packet_length_std(&self) -> f64 {
        self.get_flow_packet_length_variance().sqrt()
    }

    /// Calculates the down/up ratio of the flow.
    ///
    /// Computes the ratio of the number of forward packets to backward packets.
    /// Returns 0 if there are no backward packets, to avoid division by zero.
    ///
    /// ### Returns
    ///
    /// The down/up ratio of the flow, or 0 if there are no backward packets.
    pub fn get_down_up_ratio(&self) -> f64 {
        if self.basic_flow.bwd_packet_count > 0 {
            return self.basic_flow.fwd_packet_count as f64
                / self.basic_flow.bwd_packet_count as f64;
        }

        0.0
    }

    /// Retrieves the mean segment length of forward packets.
    ///
    /// Calculates the average segment length of forward packets by dividing the total segments length
    /// of forward packets by their count. Returns 0 if no forward packets are present.
    ///
    /// ### Returns
    ///
    /// Mean segment length of forward packets, or 0 if no forward packets are present.
    pub fn get_fwd_segment_length_mean(&self) -> f32 {
        if self.basic_flow.fwd_packet_count == 0 {
            return 0.0;
        }
        self.fwd_seg_len_tot as f32 / self.basic_flow.fwd_packet_count as f32
    }

    /// Retrieves the mean segemnt length of backward packets.
    ///
    /// Similar to `get_fwd_segment_length_mean`, but calculates the average segment length
    /// for backward packets. Returns 0 if no backward packets are present.
    ///
    /// ### Returns
    ///
    /// Mean segment length of backward packets, or 0 if no backward packets are present.
    pub fn get_bwd_segment_length_mean(&self) -> f32 {
        if self.basic_flow.bwd_packet_count == 0 {
            return 0.0;
        }
        self.bwd_seg_len_tot as f32 / self.basic_flow.bwd_packet_count as f32
    }

    /// Calculates the bytes per second rate of the flow.
    ///
    /// Computes the total number of bytes (forward and backward) transferred in the flow
    /// and divides it by the total duration of the flow in seconds.
    ///
    /// ### Returns
    ///
    /// Bytes per second rate of the flow.
    fn get_flow_bytes_s(&self) -> f64 {
        (self.fwd_pkt_len_tot + self.bwd_pkt_len_tot) as f64
            / (get_duration(
                self.basic_flow.first_timestamp,
                self.basic_flow.last_timestamp,
            ) / 1_000_000.0)
    }

    /// Calculates the packets per second rate of the flow.
    ///
    /// Computes the total number of packets (forward and backward) in the flow
    /// and divides it by the total duration of the flow in seconds.
    ///
    /// ### Returns
    ///
    /// Packets per second rate of the flow.
    fn get_flow_packets_s(&self) -> f64 {
        (self.basic_flow.fwd_packet_count + self.basic_flow.bwd_packet_count) as f64
            / (get_duration(
                self.basic_flow.first_timestamp,
                self.basic_flow.last_timestamp,
            ) / 1_000_000.0)
    }

    /// Calculates the forward packets per second rate of the flow.
    ///
    /// Computes the number of forward packets in the flow and divides it
    /// by the total duration of the flow in seconds.
    ///
    /// ### Returns
    ///
    /// Forward packets per second rate of the flow.
    pub fn get_fwd_packets_s(&self) -> f64 {
        self.basic_flow.fwd_packet_count as f64
            / (get_duration(
                self.basic_flow.first_timestamp,
                self.basic_flow.last_timestamp,
            ) / 1_000_000.0)
    }

    /// Calculates the backward packets per second rate of the flow.
    ///
    /// Computes the number of backward packets in the flow and divides it
    /// by the total duration of the flow in seconds.
    ///
    /// ### Returns
    ///
    /// Backward packets per second rate of the flow.
    pub fn get_bwd_packets_s(&self) -> f64 {
        self.basic_flow.bwd_packet_count as f64
            / (get_duration(
                self.basic_flow.first_timestamp,
                self.basic_flow.last_timestamp,
            ) / 1_000_000.0)
    }

    /// Retrieves the average size of bulk transfers in the forward direction.
    ///
    /// Calculates the mean size of bulk data transfers based on the total size
    /// and the number of bulk transfer states in the forward direction.
    ///
    /// ### Returns
    ///
    /// Average size of forward bulk transfers, or 0 if there are no bulk transfers.
    pub fn get_fwd_bytes_bulk(&self) -> f64 {
        if self.fwd_bulk_state_count == 0 {
            return 0.0;
        }

        self.fwd_bulk_size_total as f64 / self.fwd_bulk_state_count as f64
    }

    /// Retrieves the average number of packets in bulk transfers in the forward direction.
    ///
    /// Calculates the mean number of packets in bulk transfers based on the total number
    /// and the count of bulk transfer states in the forward direction.
    ///
    /// ### Returns
    ///
    /// Average number of packets in forward bulk transfers, or 0 if there are no bulk transfers.
    pub fn get_fwd_packets_bulk(&self) -> f64 {
        if self.fwd_bulk_state_count == 0 {
            return 0.0;
        }

        self.fwd_bulk_packet_count as f64 / self.fwd_bulk_state_count as f64
    }

    /// Calculates the forward bulk rate.
    ///
    /// Computes the rate of bulk data transfer in the forward direction by dividing the total
    /// size of forward bulk transfers by the total duration of these transfers in seconds.
    ///
    /// ### Returns
    ///
    /// Forward bulk data transfer rate in bytes per second, or 0 if there are no forward bulk transfers.
    pub fn get_fwd_bulk_rate(&self) -> f64 {
        if self.fwd_bulk_duration == 0.0 {
            return 0.0;
        }

        self.fwd_bulk_size_total as f64 / (self.fwd_bulk_duration / 1_000_000.0)
    }

    /// Retrieves the average size of bulk transfers in the backward direction.
    ///
    /// Calculates the mean size of bulk data transfers based on the total size
    /// and the number of bulk transfer states in the backward direction.
    ///
    /// ### Returns
    ///
    /// Average size of backward bulk transfers, or 0 if there are no bulk transfers.
    pub fn get_bwd_bytes_bulk(&self) -> f64 {
        if self.bwd_bulk_state_count == 0 {
            return 0.0;
        }

        self.bwd_bulk_size_total as f64 / self.bwd_bulk_state_count as f64
    }

    /// Retrieves the average number of packets in bulk transfers in the backward direction.
    ///
    /// Calculates the mean number of packets in bulk transfers based on the total number
    /// and the count of bulk transfer states in the backward direction.
    ///
    /// ### Returns
    ///
    /// Average number of packets in backward bulk transfers, or 0 if there are no bulk transfers.
    pub fn get_bwd_packets_bulk(&self) -> f64 {
        if self.bwd_bulk_state_count == 0 {
            return 0.0;
        }

        self.bwd_bulk_packet_count as f64 / self.bwd_bulk_state_count as f64
    }

    /// Calculates the backward bulk rate.
    ///
    /// Computes the rate of bulk data transfer in the backward direction by dividing the total
    /// size of backward bulk transfers by the total duration of these transfers in seconds.
    ///
    /// ### Returns
    ///
    /// Backward bulk data transfer rate in bytes per second, or 0 if there are no backward bulk transfers.
    pub fn get_bwd_bulk_rate(&self) -> f64 {
        if self.bwd_bulk_duration == 0.0 {
            return 0.0;
        }

        self.bwd_bulk_size_total as f64 / (self.bwd_bulk_duration / 1_000_000.0)
    }

    /// Calculates the average number of forward packets per subflow.
    ///
    /// Determines the mean number of forward packets across subflows.
    ///
    /// ### Returns
    ///
    /// Average number of forward packets per subflow, or 0 if there are no subflows.
    pub fn get_sf_fwd_packets(&self) -> f64 {
        if self.sf_count == 0 {
            return 0.0;
        }
        self.basic_flow.fwd_packet_count as f64 / self.sf_count as f64
    }

    /// Calculates the average number of forward bytes per subflow.
    ///
    /// Determines the mean number of bytes in the forward direction across subflows.
    ///
    /// ### Returns
    ///
    /// Average number of forward bytes per subflow, or 0 if there are no subflows.
    pub fn get_sf_fwd_bytes(&self) -> f64 {
        if self.sf_count == 0 {
            return 0.0;
        }
        self.fwd_pkt_len_tot as f64 / self.sf_count as f64
    }

    /// Calculates the average number of backward packets per subflow.
    ///
    /// Determines the mean number of backward packets across subflows.
    ///
    /// ### Returns
    ///
    /// Average number of backward packets per subflow, or 0 if there are no subflows.
    pub fn get_sf_bwd_packets(&self) -> f64 {
        if self.sf_count == 0 {
            return 0.0;
        }
        self.basic_flow.bwd_packet_count as f64 / self.sf_count as f64
    }

    /// Calculates the average number of backward bytes per subflow.
    ///
    /// Determines the mean number of bytes in the backward direction across subflows.
    /// It's useful for understanding the data transfer characteristics in each identified subflow.
    ///
    /// ### Returns
    ///
    /// Average number of backward bytes per subflow, or 0 if there are no subflows.
    pub fn get_sf_bwd_bytes(&self) -> f64 {
        if self.sf_count == 0 {
            return 0.0;
        }
        self.bwd_pkt_len_tot as f64 / self.sf_count as f64
    }

    /// Retrieves the minimum active time observed in the flow.
    ///
    /// This function returns the shortest period of time in which the flow was active.
    /// If the minimum active time has never been updated (indicated by `f64::MAX`), it returns 0.0.
    ///
    /// ### Returns
    ///
    /// Minimum active time in microseconds, or 0.0 if not set.
    pub fn get_active_min(&self) -> f64 {
        if self.active_min == f64::MAX {
            0.0
        } else {
            self.active_min
        }
    }

    /// Retrieves the minimum idle time observed in the flow.
    ///
    /// Similar to `get_active_min`, this function returns the shortest idle period in the flow.
    /// If the minimum idle time has never been updated (indicated by `f64::MAX`), it returns 0.0.
    ///
    /// ### Returns
    ///
    /// Minimum idle time in microseconds, or 0.0 if not set.
    pub fn get_idle_min(&self) -> f64 {
        if self.idle_min == f64::MAX {
            0.0
        } else {
            self.idle_min
        }
    }
}

impl Flow for CicFlow {
    fn new(
        flow_id: String,
        ipv4_source: IpAddr,
        port_source: u16,
        ipv4_destination: IpAddr,
        port_destination: u16,
        protocol: u8,
        ts_date: DateTime<Utc>,
    ) -> Self {
        CicFlow {
            basic_flow: BasicFlow::new(
                flow_id,
                ipv4_source,
                port_source,
                ipv4_destination,
                port_destination,
                protocol,
                ts_date,
            ),
            sf_last_packet_timestamp: None,
            sf_count: 0,
            start_active: Instant::now(),
            end_active: Instant::now(),
            active_count: 0,
            active_mean: 0.0,
            active_std: 0.0,
            active_max: 0.0,
            active_min: f64::MAX,
            idle_count: 0,
            idle_mean: 0.0,
            idle_std: 0.0,
            idle_max: 0.0,
            idle_min: f64::MAX,
            fwd_act_data_pkt: 0,
            fwd_init_win_bytes: 0,
            fwd_header_len_min: u32::MAX,
            fwd_last_timestamp: None,
            fwd_pkt_len_tot: 0,
            fwd_seg_len_tot: 0,
            fwd_pkt_len_max: 0,
            fwd_pkt_len_min: u32::MAX,
            fwd_pkt_len_mean: 0.0,
            fwd_pkt_len_std: 0.0,
            fwd_iat_total: 0.0,
            fwd_iat_mean: 0.0,
            fwd_iat_std: 0.0,
            fwd_iat_max: 0.0,
            fwd_iat_min: f64::MAX,
            fwd_header_length: 0,
            fwd_bulk_duration: 0.0,
            fwd_bulk_packet_count: 0,
            fwd_bulk_size_total: 0,
            fwd_bulk_state_count: 0,
            fwd_bulk_packet_count_help: 0,
            fwd_bulk_start_help: None,
            fwd_bulk_size_help: 0,
            fwd_last_bulk_timestamp: None,
            bwd_init_win_bytes: 0,
            bwd_last_timestamp: None,
            bwd_pkt_len_tot: 0,
            bwd_seg_len_tot: 0,
            bwd_pkt_len_max: 0,
            bwd_pkt_len_min: u32::MAX,
            bwd_pkt_len_mean: 0.0,
            bwd_pkt_len_std: 0.0,
            bwd_iat_total: 0.0,
            bwd_iat_mean: 0.0,
            bwd_iat_std: 0.0,
            bwd_iat_max: 0.0,
            bwd_iat_min: f64::MAX,
            bwd_header_length: 0,
            bwd_bulk_duration: 0.0,
            bwd_bulk_packet_count: 0,
            bwd_bulk_size_total: 0,
            bwd_bulk_state_count: 0,
            bwd_bulk_packet_count_help: 0,
            bwd_bulk_start_help: None,
            bwd_bulk_size_help: 0,
            bwd_last_bulk_timestamp: None,
        }
    }

    fn update_flow(
        &mut self,
        packet: &BasicFeatures,
        timestamp: &Instant,
        ts_date: DateTime<Utc>,
        fwd: bool,
    ) -> Option<String> {
        self.basic_flow.update_flow(packet, timestamp, ts_date, fwd);
        self.update_subflows(timestamp);

        if fwd {
            self.update_fwd_pkt_len_stats(packet.data_length as u32);
            self.update_fwd_header_len_min(packet.header_length as u32);

            self.fwd_seg_len_tot += packet.length as u32;

            if self.basic_flow.fwd_packet_count > 1 {
                self.update_fwd_iat_stats(
                    timestamp
                        .duration_since(self.fwd_last_timestamp.unwrap())
                        .as_micros() as f64,
                );
            }

            if self.basic_flow.fwd_packet_count == 1 {
                self.fwd_init_win_bytes = packet.window_size;
            }

            if packet.data_length > 0 {
                self.fwd_act_data_pkt += 1;
            }

            self.update_fwd_bulk_stats(timestamp, packet.data_length as u32);
            self.increase_fwd_header_length(packet.header_length as u32);
            self.fwd_last_timestamp = Some(*timestamp);
        } else {
            self.update_bwd_pkt_len_stats(packet.data_length as u32);

            self.bwd_seg_len_tot += packet.length as u32;

            if self.basic_flow.bwd_packet_count > 1 {
                self.update_bwd_iat_stats(
                    timestamp
                        .duration_since(self.bwd_last_timestamp.unwrap())
                        .as_micros() as f64,
                );
            }

            if self.basic_flow.bwd_packet_count == 1 {
                self.bwd_init_win_bytes = packet.window_size;
            }

            self.update_bwd_bulk_stats(timestamp, packet.data_length as u32);
            self.increase_bwd_header_length(packet.header_length as u32);
            self.bwd_last_timestamp = Some(*timestamp);
        }

        if self.basic_flow.flow_end_of_flow_ack > 0
            || self.basic_flow.fwd_rst_flag_count > 0
            || self.basic_flow.bwd_rst_flag_count > 0
        {
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
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},\
            {},{},{},{}",
            self.basic_flow.flow_id,
            self.basic_flow.ip_source,
            self.basic_flow.port_source,
            self.basic_flow.ip_destination,
            self.basic_flow.port_destination,
            self.basic_flow.protocol,
            self.basic_flow.first_timestamp,
            get_duration(
                self.basic_flow.first_timestamp,
                self.basic_flow.last_timestamp
            ),
            self.basic_flow.fwd_packet_count,
            self.basic_flow.bwd_packet_count,
            self.fwd_pkt_len_tot,
            self.bwd_pkt_len_tot,
            self.fwd_pkt_len_max,
            self.get_fwd_packet_length_min(),
            self.fwd_pkt_len_mean,
            self.fwd_pkt_len_std,
            self.bwd_pkt_len_max,
            self.get_bwd_packet_length_min(),
            self.bwd_pkt_len_mean,
            self.bwd_pkt_len_std,
            self.get_flow_bytes_s(),
            self.get_flow_packets_s(),
            self.get_flow_iat_mean(),
            self.get_flow_iat_std(),
            self.get_flow_iat_max(),
            self.get_flow_iat_min(),
            self.fwd_iat_total,
            self.fwd_iat_mean,
            self.fwd_iat_std,
            self.fwd_iat_max,
            self.get_fwd_iat_min(),
            self.bwd_iat_total,
            self.bwd_iat_mean,
            self.bwd_iat_std,
            self.bwd_iat_max,
            self.get_bwd_iat_min(),
            self.basic_flow.fwd_psh_flag_count,
            self.basic_flow.bwd_psh_flag_count,
            self.basic_flow.fwd_urg_flag_count,
            self.basic_flow.bwd_urg_flag_count,
            self.fwd_header_length,
            self.bwd_header_length,
            self.get_fwd_packets_s(),
            self.get_bwd_packets_s(),
            self.get_flow_packet_length_min(),
            self.get_flow_packet_length_max(),
            self.get_flow_packet_length_mean(),
            self.get_flow_packet_length_std(),
            self.get_flow_packet_length_variance(),
            self.basic_flow.fwd_fin_flag_count + self.basic_flow.bwd_fin_flag_count,
            self.basic_flow.fwd_syn_flag_count + self.basic_flow.bwd_syn_flag_count,
            self.basic_flow.fwd_rst_flag_count + self.basic_flow.bwd_rst_flag_count,
            self.basic_flow.fwd_psh_flag_count + self.basic_flow.bwd_psh_flag_count,
            self.basic_flow.fwd_ack_flag_count + self.basic_flow.bwd_ack_flag_count,
            self.basic_flow.fwd_urg_flag_count + self.basic_flow.bwd_urg_flag_count,
            self.basic_flow.fwd_cwe_flag_count + self.basic_flow.bwd_cwe_flag_count,
            self.basic_flow.fwd_ece_flag_count + self.basic_flow.bwd_ece_flag_count,
            self.get_down_up_ratio(),
            self.get_flow_segment_length_mean(), // this is a duplicate feature
            self.get_fwd_segment_length_mean(),
            self.get_bwd_segment_length_mean(),
            self.fwd_header_length, // this is a duplicate feature
            self.get_fwd_bytes_bulk(),
            self.get_fwd_packets_bulk(),
            self.get_fwd_bulk_rate(),
            self.get_bwd_bytes_bulk(),
            self.get_bwd_packets_bulk(),
            self.get_bwd_bulk_rate(),
            self.get_sf_fwd_packets(),
            self.get_sf_fwd_bytes(),
            self.get_sf_bwd_packets(),
            self.get_sf_bwd_bytes(),
            self.fwd_init_win_bytes,
            self.bwd_init_win_bytes,
            self.fwd_act_data_pkt,
            self.get_fwd_header_len_min(), // known as min_seg_size_forward but this is actually the min header length in the forward direction
            self.active_mean,
            self.active_std,
            self.active_max,
            self.get_active_min(),
            self.idle_mean,
            self.idle_std,
            self.idle_max,
            self.get_idle_min(),
        )
    }

    fn get_features() -> String {
        format!(
            "FLOW_ID,IP_SOURCE,PORT_SOURCE,IP_DESTINATION,PORT_DESTINATION,PROTOCOL,\
            FIRST_TIMESTAMP,LAST_TIMESTAMP,DURATION,FWD_PACKET_COUNT,BWD_PACKET_COUNT,\
            FWD_PKT_LEN_TOT,BWD_PKT_LEN_TOT,FWD_PKT_LEN_MAX,FWD_PKT_LEN_MIN,FWD_PKT_LEN_MEAN,\
            FWD_PKT_LEN_STD,BWD_PKT_LEN_MAX,BWD_PKT_LEN_MIN,BWD_PKT_LEN_MEAN,BWD_PKT_LEN_STD,\
            FLOW_BYTES_S,FLOW_PACKETS_S,FLOW_IAT_MEAN,FLOW_IAT_STD,FLOW_IAT_MAX,FLOW_IAT_MIN,\
            FWD_IAT_TOTAL,FWD_IAT_MEAN,FWD_IAT_STD,FWD_IAT_MAX,FWD_IAT_MIN,BWD_IAT_TOTAL,\
            BWD_IAT_MEAN,BWD_IAT_STD,BWD_IAT_MAX,BWD_IAT_MIN,FWD_PSH_FLAG_COUNT,BWD_PSH_FLAG_COUNT,\
            FWD_URG_FLAG_COUNT,BWD_URG_FLAG_COUNT,FWD_HEADER_LENGTH,BWD_HEADER_LENGTH,FWD_PACKETS_S,\
            BWD_PACKETS_S,FLOW_PACKET_LENGTH_MIN,FLOW_PACKET_LENGTH_MAX,FLOW_PACKET_LENGTH_MEAN,\
            FLOW_PACKET_LENGTH_STD,FLOW_PACKET_LENGTH_VARIANCE,FLOW_FIN_COUNT,FLOW_SYN_COUNT,\
            FLOW_RST_COUNT,FLOW_PSH_COUNT,FLOW_ACK_COUNT,FLOW_URG_COUNT,FLOW_CWE_COUNT,FLOW_ECE_COUNT,\
            DOWN_UP_RATIO,FLOW_SEGMENT_LENGTH_MEAN,FWD_SEGMENT_LENGTH_MEAN,BWD_SEGMENT_LENGTH_MEAN,\
            FWD_HEADER_LENGTH,FWD_BYTES_BULK,FWD_PACKETS_BULK,FWD_BULK_RATE,BWD_BYTES_BULK,\
            BWD_PACKETS_BULK,BWD_BULK_RATE,SF_FWD_PACKETS,SF_FWD_BYTES,SF_BWD_PACKETS,SF_BWD_BYTES,\
            FWD_INIT_WIN_BYTES,BWD_INIT_WIN_BYTES,FWD_ACT_DATA_PKT,FWD_HEADER_LEN_MIN,ACTIVE_MEAN,\
            ACTIVE_STD,ACTIVE_MAX,ACTIVE_MIN,IDLE_MEAN,IDLE_STD,IDLE_MAX,IDLE_MIN")
    }

    fn dump_without_contamination(&self) -> String {
        format!(
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{}",
            get_duration(
                self.basic_flow.first_timestamp,
                self.basic_flow.last_timestamp
            ),
            self.basic_flow.fwd_packet_count,
            self.basic_flow.bwd_packet_count,
            self.fwd_pkt_len_tot,
            self.bwd_pkt_len_tot,
            self.fwd_pkt_len_max,
            self.fwd_pkt_len_mean,
            self.fwd_pkt_len_std,
            self.bwd_pkt_len_max,
            self.bwd_pkt_len_mean,
            self.bwd_pkt_len_std,
            self.get_flow_bytes_s(),
            self.get_flow_packets_s(),
            self.get_flow_iat_mean(),
            self.get_flow_iat_std(),
            self.get_flow_iat_max(),
            self.get_flow_iat_min(),
            self.fwd_iat_total,
            self.fwd_iat_mean,
            self.fwd_iat_std,
            self.fwd_iat_max,
            self.get_fwd_iat_min(),
            self.bwd_iat_total,
            self.bwd_iat_mean,
            self.bwd_iat_std,
            self.bwd_iat_max,
            self.get_bwd_iat_min(),
            self.basic_flow.fwd_psh_flag_count,
            self.basic_flow.bwd_psh_flag_count,
            self.basic_flow.fwd_urg_flag_count,
            self.basic_flow.bwd_urg_flag_count,
            self.fwd_header_length,
            self.bwd_header_length,
            self.get_fwd_packets_s(),
            self.get_bwd_packets_s(),
            self.get_flow_packet_length_max(),
            self.get_flow_packet_length_mean(),
            self.get_flow_packet_length_std(),
            self.get_flow_packet_length_variance(),
            self.basic_flow.fwd_fin_flag_count + self.basic_flow.bwd_fin_flag_count,
            self.basic_flow.fwd_syn_flag_count + self.basic_flow.bwd_syn_flag_count,
            self.basic_flow.fwd_urg_flag_count + self.basic_flow.bwd_urg_flag_count,
            self.basic_flow.fwd_cwe_flag_count + self.basic_flow.bwd_cwe_flag_count,
            self.get_fwd_segment_length_mean(),
            self.get_bwd_segment_length_mean(),
            self.get_fwd_bytes_bulk(),
            self.get_fwd_packets_bulk(),
            self.get_fwd_bulk_rate(),
            self.get_bwd_bytes_bulk(),
            self.get_bwd_packets_bulk(),
            self.get_bwd_bulk_rate(),
            self.get_sf_fwd_packets(),
            self.get_sf_fwd_bytes(),
            self.get_sf_bwd_packets(),
            self.get_sf_bwd_bytes(),
            self.fwd_init_win_bytes,
            self.bwd_init_win_bytes,
            self.fwd_act_data_pkt,
            self.get_fwd_header_len_min(), // known as min_seg_size_forward but this is actually the min header length in the forward direction
            self.active_mean,
            self.active_max,
            self.get_active_min(),
            self.idle_mean,
            self.idle_max,
            self.get_idle_min(),
        )
    }

    fn get_features_without_contamination() -> String {
        format!(
            "DURATION,FWD_PACKET_COUNT,BWD_PACKET_COUNT,FWD_PKT_LEN_TOT,BWD_PKT_LEN_TOT,\
            FWD_PKT_LEN_MAX,FWD_PKT_LEN_MEAN,FWD_PKT_LEN_STD,BWD_PKT_LEN_MAX,BWD_PKT_LEN_MEAN,\
            BWD_PKT_LEN_STD,FLOW_BYTES_S,FLOW_PACKETS_S,FLOW_IAT_MEAN,FLOW_IAT_STD,FLOW_IAT_MAX,\
            FLOW_IAT_MIN,FWD_IAT_TOTAL,FWD_IAT_MEAN,FWD_IAT_STD,FWD_IAT_MAX,FWD_IAT_MIN,BWD_IAT_TOTAL,\
            BWD_IAT_MEAN,BWD_IAT_STD,BWD_IAT_MAX,BWD_IAT_MIN,FWD_PSH_FLAG_COUNT,BWD_PSH_FLAG_COUNT,\
            FWD_URG_FLAG_COUNT,BWD_URG_FLAG_COUNT,FWD_HEADER_LENGTH,BWD_HEADER_LENGTH,FWD_PACKETS_S,\
            BWD_PACKETS_S,FLOW_PACKET_LENGTH_MAX,FLOW_PACKET_LENGTH_MEAN,FLOW_PACKET_LENGTH_STD,\
            FLOW_PACKET_LENGTH_VARIANCE,FLOW_FIN_COUNT,FLOW_SYN_COUNT,FLOW_URG_COUNT,FLOW_CWE_COUNT,\
            FWD_SEGMENT_LENGTH_MEAN,BWD_SEGMENT_LENGTH_MEAN,FWD_BYTES_BULK,FWD_PACKETS_BULK,FWD_BULK_RATE,\
            BWD_BYTES_BULK,BWD_PACKETS_BULK,BWD_BULK_RATE,SF_FWD_PACKETS,SF_FWD_BYTES,SF_BWD_PACKETS,\
            SF_BWD_BYTES,FWD_INIT_WIN_BYTES,BWD_INIT_WIN_BYTES,FWD_ACT_DATA_PKT,FWD_HEADER_LEN_MIN,\
            ACTIVE_MEAN,ACTIVE_MAX,ACTIVE_MIN,IDLE_MEAN,IDLE_MAX,IDLE_MIN"
        )
    }

    fn get_first_timestamp(&self) -> DateTime<Utc> {
        self.basic_flow.get_first_timestamp()
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        flows::{cic_flow::CicFlow, flow::Flow},
        utils::utils::{get_duration, BasicFeatures},
    };
    use std::{
        net::{IpAddr, Ipv4Addr},
        time::{Duration, Instant},
    };

    fn setup_cic_flow() -> CicFlow {
        CicFlow::new(
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
    fn test_increase_fwd_header_length() {
        let mut cic_flow = setup_cic_flow();

        let initial_length = cic_flow.fwd_header_length;

        cic_flow.increase_fwd_header_length(20);
        assert_eq!(cic_flow.fwd_header_length, initial_length + 20);

        cic_flow.increase_fwd_header_length(0);
        assert_eq!(cic_flow.fwd_header_length, initial_length + 20);
    }

    #[test]
    fn test_increase_bwd_header_length() {
        let mut cic_flow = setup_cic_flow();

        let initial_length = cic_flow.bwd_header_length;

        cic_flow.increase_bwd_header_length(30);
        assert_eq!(cic_flow.bwd_header_length, initial_length + 30);

        cic_flow.increase_bwd_header_length(0);
        assert_eq!(cic_flow.bwd_header_length, initial_length + 30);
    }

    #[test]
    fn test_update_fwd_pkt_len_stats() {
        let mut cic_flow = setup_cic_flow();

        cic_flow.basic_flow.fwd_packet_count = 1;

        cic_flow.update_fwd_pkt_len_stats(100);

        assert_eq!(cic_flow.fwd_pkt_len_max, 100);
        assert_eq!(cic_flow.fwd_pkt_len_min, 100);
        assert_eq!(cic_flow.fwd_pkt_len_mean, 100.0);
        assert_eq!(cic_flow.fwd_pkt_len_std, 0.0);
        assert_eq!(cic_flow.fwd_pkt_len_tot, 100);

        cic_flow.basic_flow.fwd_packet_count = 2;

        cic_flow.update_fwd_pkt_len_stats(50);

        assert_eq!(cic_flow.fwd_pkt_len_max, 100);
        assert_eq!(cic_flow.fwd_pkt_len_min, 50);
        assert_eq!(cic_flow.fwd_pkt_len_mean, 75.0);
        assert_eq!(cic_flow.fwd_pkt_len_std, 25.0);
        assert_eq!(cic_flow.fwd_pkt_len_tot, 150);

        cic_flow.basic_flow.fwd_packet_count = 3;

        cic_flow.update_fwd_pkt_len_stats(0);

        assert_eq!(cic_flow.fwd_pkt_len_max, 100);
        assert_eq!(cic_flow.fwd_pkt_len_min, 0);
        assert_eq!(cic_flow.fwd_pkt_len_mean, 50.0);
        assert_eq!(cic_flow.fwd_pkt_len_std, 40.824829046386306);
        assert_eq!(cic_flow.fwd_pkt_len_tot, 150);
    }

    #[test]
    fn test_update_bwd_pkt_len_stats() {
        let mut cic_flow = setup_cic_flow();

        cic_flow.basic_flow.bwd_packet_count = 1;

        cic_flow.update_bwd_pkt_len_stats(100);

        assert_eq!(cic_flow.bwd_pkt_len_max, 100);
        assert_eq!(cic_flow.bwd_pkt_len_min, 100);
        assert_eq!(cic_flow.bwd_pkt_len_mean, 100.0);
        assert_eq!(cic_flow.bwd_pkt_len_std, 0.0);
        assert_eq!(cic_flow.bwd_pkt_len_tot, 100);

        cic_flow.basic_flow.bwd_packet_count = 2;

        cic_flow.update_bwd_pkt_len_stats(50);

        assert_eq!(cic_flow.bwd_pkt_len_max, 100);
        assert_eq!(cic_flow.bwd_pkt_len_min, 50);
        assert_eq!(cic_flow.bwd_pkt_len_mean, 75.0);
        assert_eq!(cic_flow.bwd_pkt_len_std, 25.0);
        assert_eq!(cic_flow.bwd_pkt_len_tot, 150);

        cic_flow.basic_flow.bwd_packet_count = 3;

        cic_flow.update_bwd_pkt_len_stats(0);

        assert_eq!(cic_flow.bwd_pkt_len_max, 100);
        assert_eq!(cic_flow.bwd_pkt_len_min, 0);
        assert_eq!(cic_flow.bwd_pkt_len_mean, 50.0);
        assert_eq!(cic_flow.bwd_pkt_len_std, 40.824829046386306);
        assert_eq!(cic_flow.bwd_pkt_len_tot, 150);
    }

    #[test]
    fn test_update_fwd_iat_stats() {
        let mut cic_flow = setup_cic_flow();
        let epsilon = 1e-9; // floating-point arithmetic is not exact

        cic_flow.basic_flow.fwd_packet_count = 2;

        cic_flow.update_fwd_iat_stats(0.05);

        assert_eq!(cic_flow.fwd_iat_max, 0.05);
        assert_eq!(cic_flow.fwd_iat_min, 0.05);
        assert_eq!(cic_flow.fwd_iat_mean, 0.05);
        assert_eq!(cic_flow.fwd_iat_std, 0.0);
        assert_eq!(cic_flow.fwd_iat_total, 0.05);

        cic_flow.basic_flow.fwd_packet_count = 3;

        cic_flow.update_fwd_iat_stats(0.01);

        assert_eq!(cic_flow.fwd_iat_max, 0.05);
        assert_eq!(cic_flow.fwd_iat_min, 0.01);
        assert!(
            (cic_flow.fwd_iat_mean - 0.03).abs() < epsilon,
            "fwd_iat_mean is not within the expected range"
        );
        assert_eq!(cic_flow.fwd_iat_std, 0.02);
        assert!(
            (cic_flow.fwd_iat_total - 0.06).abs() < epsilon,
            "fwd_iat_total is not within the expected range"
        );

        cic_flow.basic_flow.fwd_packet_count = 4;

        cic_flow.update_fwd_iat_stats(0.698456231458);

        assert_eq!(cic_flow.fwd_iat_max, 0.698456231458);
        assert_eq!(cic_flow.fwd_iat_min, 0.01);
        assert_eq!(cic_flow.fwd_iat_mean, 0.25281874381933334);
        assert_eq!(cic_flow.fwd_iat_std, 0.31553613400230096);
        assert_eq!(cic_flow.fwd_iat_total, 0.758456231458);
    }

    #[test]
    fn test_update_bwd_iat_stats() {
        let mut cic_flow = setup_cic_flow();
        let epsilon = 1e-9; // floating-point arithmetic is not exact

        cic_flow.basic_flow.bwd_packet_count = 2;

        cic_flow.update_bwd_iat_stats(0.05);

        assert_eq!(cic_flow.bwd_iat_max, 0.05);
        assert_eq!(cic_flow.bwd_iat_min, 0.05);
        assert_eq!(cic_flow.bwd_iat_mean, 0.05);
        assert_eq!(cic_flow.bwd_iat_std, 0.0);
        assert_eq!(cic_flow.bwd_iat_total, 0.05);

        cic_flow.basic_flow.bwd_packet_count = 3;

        cic_flow.update_bwd_iat_stats(0.01);

        assert_eq!(cic_flow.bwd_iat_max, 0.05);
        assert_eq!(cic_flow.bwd_iat_min, 0.01);
        assert!(
            (cic_flow.bwd_iat_mean - 0.03).abs() < epsilon,
            "fwd_iat_mean is not within the expected range"
        );
        assert_eq!(cic_flow.bwd_iat_std, 0.02);
        assert!(
            (cic_flow.bwd_iat_total - 0.06).abs() < epsilon,
            "fwd_iat_total is not within the expected range"
        );

        cic_flow.basic_flow.bwd_packet_count = 4;

        cic_flow.update_bwd_iat_stats(0.698456231458);

        assert_eq!(cic_flow.bwd_iat_max, 0.698456231458);
        assert_eq!(cic_flow.bwd_iat_min, 0.01);
        assert_eq!(cic_flow.bwd_iat_mean, 0.25281874381933334);
        assert_eq!(cic_flow.bwd_iat_std, 0.31553613400230096);
        assert_eq!(cic_flow.bwd_iat_total, 0.758456231458);
    }

    #[test]
    fn test_update_fwd_bulk_stats() {
        let mut cic_flow = setup_cic_flow();
        let timestamp = Instant::now();
        let timestamp_2 = Instant::now();
        let timestamp_3 = Instant::now();
        let timestamp_4 = Instant::now();

        cic_flow.update_fwd_bulk_stats(&timestamp, 100);

        assert_eq!(cic_flow.fwd_bulk_state_count, 0);
        assert_eq!(cic_flow.fwd_bulk_packet_count, 0);
        assert_eq!(cic_flow.fwd_bulk_size_total, 0);
        assert_eq!(cic_flow.fwd_bulk_duration, 0.0);
        assert_eq!(cic_flow.fwd_bulk_packet_count_help, 1);
        assert_eq!(cic_flow.fwd_bulk_start_help, Some(timestamp));
        assert_eq!(cic_flow.fwd_bulk_size_help, 100);
        assert_eq!(cic_flow.fwd_last_bulk_timestamp, Some(timestamp));

        cic_flow.update_fwd_bulk_stats(&timestamp_2, 200);

        assert_eq!(cic_flow.fwd_bulk_state_count, 0);
        assert_eq!(cic_flow.fwd_bulk_packet_count, 0);
        assert_eq!(cic_flow.fwd_bulk_size_total, 0);
        assert_eq!(cic_flow.fwd_bulk_duration, 0.0);
        assert_eq!(cic_flow.fwd_bulk_packet_count_help, 2);
        assert_eq!(cic_flow.fwd_bulk_start_help, Some(timestamp));
        assert_eq!(cic_flow.fwd_bulk_size_help, 300);
        assert_eq!(cic_flow.fwd_last_bulk_timestamp, Some(timestamp_2));

        cic_flow.update_fwd_bulk_stats(&timestamp_3, 150);

        assert_eq!(cic_flow.fwd_bulk_state_count, 0);
        assert_eq!(cic_flow.fwd_bulk_packet_count, 0);
        assert_eq!(cic_flow.fwd_bulk_size_total, 0);
        assert_eq!(cic_flow.fwd_bulk_duration, 0.0);
        assert_eq!(cic_flow.fwd_bulk_packet_count_help, 3);
        assert_eq!(cic_flow.fwd_bulk_start_help, Some(timestamp));
        assert_eq!(cic_flow.fwd_bulk_size_help, 450);
        assert_eq!(cic_flow.fwd_last_bulk_timestamp, Some(timestamp_3));

        cic_flow.update_fwd_bulk_stats(&timestamp_4, 50);

        assert_eq!(cic_flow.fwd_bulk_state_count, 1);
        assert_eq!(cic_flow.fwd_bulk_packet_count, 4);
        assert_eq!(cic_flow.fwd_bulk_size_total, 500);
        assert_eq!(
            cic_flow.fwd_bulk_duration,
            timestamp_4.duration_since(timestamp).as_micros() as f64
        );
        assert_eq!(cic_flow.fwd_bulk_packet_count_help, 4);
        assert_eq!(cic_flow.fwd_bulk_start_help, Some(timestamp));
        assert_eq!(cic_flow.fwd_bulk_size_help, 500);
        assert_eq!(cic_flow.fwd_last_bulk_timestamp, Some(timestamp_4));

        std::thread::sleep(std::time::Duration::from_secs(1));

        let new_timestamp = Instant::now();

        cic_flow.update_fwd_bulk_stats(&new_timestamp, 50);

        assert_eq!(cic_flow.fwd_bulk_state_count, 1);
        assert_eq!(cic_flow.fwd_bulk_packet_count, 4);
        assert_eq!(cic_flow.fwd_bulk_size_total, 500);
        assert_eq!(
            cic_flow.fwd_bulk_duration,
            timestamp_4.duration_since(timestamp).as_micros() as f64
        );
        assert_eq!(cic_flow.fwd_bulk_packet_count_help, 1);
        assert_eq!(cic_flow.fwd_bulk_start_help, Some(new_timestamp));
        assert_eq!(cic_flow.fwd_bulk_size_help, 50);
        assert_eq!(cic_flow.fwd_last_bulk_timestamp, Some(new_timestamp));
    }

    #[test]
    fn test_update_bwd_bulk_stats() {
        let mut cic_flow = setup_cic_flow();
        let timestamp = Instant::now();
        let timestamp_2 = Instant::now();
        let timestamp_3 = Instant::now();
        let timestamp_4 = Instant::now();

        cic_flow.update_bwd_bulk_stats(&timestamp, 100);

        assert_eq!(cic_flow.bwd_bulk_state_count, 0);
        assert_eq!(cic_flow.bwd_bulk_packet_count, 0);
        assert_eq!(cic_flow.bwd_bulk_size_total, 0);
        assert_eq!(cic_flow.bwd_bulk_duration, 0.0);
        assert_eq!(cic_flow.bwd_bulk_packet_count_help, 1);
        assert_eq!(cic_flow.bwd_bulk_start_help, Some(timestamp));
        assert_eq!(cic_flow.bwd_bulk_size_help, 100);
        assert_eq!(cic_flow.bwd_last_bulk_timestamp, Some(timestamp));

        cic_flow.update_bwd_bulk_stats(&timestamp_2, 200);

        assert_eq!(cic_flow.bwd_bulk_state_count, 0);
        assert_eq!(cic_flow.bwd_bulk_packet_count, 0);
        assert_eq!(cic_flow.bwd_bulk_size_total, 0);
        assert_eq!(cic_flow.bwd_bulk_duration, 0.0);
        assert_eq!(cic_flow.bwd_bulk_packet_count_help, 2);
        assert_eq!(cic_flow.bwd_bulk_start_help, Some(timestamp));
        assert_eq!(cic_flow.bwd_bulk_size_help, 300);
        assert_eq!(cic_flow.bwd_last_bulk_timestamp, Some(timestamp_2));

        cic_flow.update_bwd_bulk_stats(&timestamp_3, 150);

        assert_eq!(cic_flow.bwd_bulk_state_count, 0);
        assert_eq!(cic_flow.bwd_bulk_packet_count, 0);
        assert_eq!(cic_flow.bwd_bulk_size_total, 0);
        assert_eq!(cic_flow.bwd_bulk_duration, 0.0);
        assert_eq!(cic_flow.bwd_bulk_packet_count_help, 3);
        assert_eq!(cic_flow.bwd_bulk_start_help, Some(timestamp));
        assert_eq!(cic_flow.bwd_bulk_size_help, 450);
        assert_eq!(cic_flow.bwd_last_bulk_timestamp, Some(timestamp_3));

        cic_flow.update_bwd_bulk_stats(&timestamp_4, 50);

        assert_eq!(cic_flow.bwd_bulk_state_count, 1);
        assert_eq!(cic_flow.bwd_bulk_packet_count, 4);
        assert_eq!(cic_flow.bwd_bulk_size_total, 500);
        assert_eq!(
            cic_flow.bwd_bulk_duration,
            timestamp_4.duration_since(timestamp).as_micros() as f64
        );
        assert_eq!(cic_flow.bwd_bulk_packet_count_help, 4);
        assert_eq!(cic_flow.bwd_bulk_start_help, Some(timestamp));
        assert_eq!(cic_flow.bwd_bulk_size_help, 500);
        assert_eq!(cic_flow.bwd_last_bulk_timestamp, Some(timestamp_4));

        std::thread::sleep(std::time::Duration::from_secs(1));

        let new_timestamp = Instant::now();

        cic_flow.update_bwd_bulk_stats(&new_timestamp, 50);

        assert_eq!(cic_flow.bwd_bulk_state_count, 1);
        assert_eq!(cic_flow.bwd_bulk_packet_count, 4);
        assert_eq!(cic_flow.bwd_bulk_size_total, 500);
        assert_eq!(
            cic_flow.bwd_bulk_duration,
            timestamp_4.duration_since(timestamp).as_micros() as f64
        );
        assert_eq!(cic_flow.bwd_bulk_packet_count_help, 1);
        assert_eq!(cic_flow.bwd_bulk_start_help, Some(new_timestamp));
        assert_eq!(cic_flow.bwd_bulk_size_help, 50);
        assert_eq!(cic_flow.bwd_last_bulk_timestamp, Some(new_timestamp));
    }

    #[test]
    fn test_update_active_flow() {
        let mut cic_flow = setup_cic_flow();

        cic_flow.update_active_flow(100.0);

        assert_eq!(cic_flow.active_max, 100.0);
        assert_eq!(cic_flow.active_min, 100.0);
        assert_eq!(cic_flow.active_mean, 100.0);
        assert_eq!(cic_flow.active_std, 0.0);
        assert_eq!(cic_flow.active_count, 1);

        cic_flow.update_active_flow(50.0);

        assert_eq!(cic_flow.active_max, 100.0);
        assert_eq!(cic_flow.active_min, 50.0);
        assert_eq!(cic_flow.active_mean, 75.0);
        assert_eq!(cic_flow.active_std, 25.0);
        assert_eq!(cic_flow.active_count, 2);

        cic_flow.update_active_flow(0.0);

        assert_eq!(cic_flow.active_max, 100.0);
        assert_eq!(cic_flow.active_min, 0.0);
        assert_eq!(cic_flow.active_mean, 50.0);
        assert_eq!(cic_flow.active_std, 40.824829046386306);
        assert_eq!(cic_flow.active_count, 3);
    }

    #[test]
    fn test_update_idle_flow() {
        let mut cic_flow = setup_cic_flow();

        cic_flow.update_idle_flow(100.0);

        assert_eq!(cic_flow.idle_max, 100.0);
        assert_eq!(cic_flow.idle_min, 100.0);
        assert_eq!(cic_flow.idle_mean, 100.0);
        assert_eq!(cic_flow.idle_std, 0.0);
        assert_eq!(cic_flow.idle_count, 1);

        cic_flow.update_idle_flow(50.0);

        assert_eq!(cic_flow.idle_max, 100.0);
        assert_eq!(cic_flow.idle_min, 50.0);
        assert_eq!(cic_flow.idle_mean, 75.0);
        assert_eq!(cic_flow.idle_std, 25.0);
        assert_eq!(cic_flow.idle_count, 2);

        cic_flow.update_idle_flow(0.0);

        assert_eq!(cic_flow.idle_max, 100.0);
        assert_eq!(cic_flow.idle_min, 0.0);
        assert_eq!(cic_flow.idle_mean, 50.0);
        assert_eq!(cic_flow.idle_std, 40.824829046386306);
        assert_eq!(cic_flow.idle_count, 3);
    }

    #[test]
    fn test_update_active_idle_time() {
        let mut cic_flow = setup_cic_flow();

        let threshold = 60_000_000.0;

        let timestamp = Instant::now();
        let timestamp_2 = timestamp + Duration::new(30, 0); // 30 seconds later
        let timestamp_3 = timestamp + Duration::new(91, 0); // 90 seconds later

        cic_flow.update_active_idle_time(&timestamp, threshold);

        assert_eq!(cic_flow.end_active, timestamp);
        assert_ne!(cic_flow.start_active, timestamp);
        assert_eq!(cic_flow.active_count, 0);
        assert_eq!(cic_flow.active_max, 0.0);
        assert_eq!(cic_flow.active_min, f64::MAX);
        assert_eq!(cic_flow.active_mean, 0.0);
        assert_eq!(cic_flow.active_std, 0.0);
        assert_eq!(cic_flow.idle_count, 0);
        assert_eq!(cic_flow.idle_max, 0.0);
        assert_eq!(cic_flow.idle_min, f64::MAX);
        assert_eq!(cic_flow.idle_mean, 0.0);
        assert_eq!(cic_flow.idle_std, 0.0);

        cic_flow.update_active_idle_time(&timestamp_2, threshold);

        assert_eq!(cic_flow.end_active, timestamp_2);
        assert_ne!(cic_flow.start_active, timestamp_2);
        assert_eq!(cic_flow.active_count, 0);
        assert_eq!(cic_flow.active_max, 0.0);
        assert_eq!(cic_flow.active_min, f64::MAX);
        assert_eq!(cic_flow.active_mean, 0.0);
        assert_eq!(cic_flow.active_std, 0.0);
        assert_eq!(cic_flow.idle_count, 0);
        assert_eq!(cic_flow.idle_max, 0.0);
        assert_eq!(cic_flow.idle_min, f64::MAX);
        assert_eq!(cic_flow.idle_mean, 0.0);
        assert_eq!(cic_flow.idle_std, 0.0);

        cic_flow.update_active_idle_time(&timestamp_3, threshold);
        assert_eq!(cic_flow.end_active, timestamp_3);
        assert_eq!(cic_flow.start_active, timestamp_3);
        assert_eq!(cic_flow.active_count, 1);
        assert_ne!(cic_flow.active_max, 0.0);
        assert_ne!(cic_flow.active_min, f64::MAX);
        assert_ne!(cic_flow.active_mean, 0.0);
        assert_eq!(cic_flow.active_std, 0.0);
        assert_eq!(cic_flow.idle_count, 1);
        assert_ne!(cic_flow.idle_max, 0.0);
        assert_ne!(cic_flow.idle_min, f64::MAX);
        assert_ne!(cic_flow.idle_mean, 0.0);
        assert_eq!(cic_flow.idle_std, 0.0);
    }

    #[test]
    fn test_get_flow_iat_mean() {
        let mut cic_flow = setup_cic_flow();

        //let forward_iat = [1.0, 2.0, 3.0, 4.0, 5.0];
        //let backward_iat = [1.5, 2.5, 3.5];

        cic_flow.fwd_iat_mean = 3.0;
        cic_flow.bwd_iat_mean = 2.5;

        cic_flow.basic_flow.fwd_packet_count = 5;
        cic_flow.basic_flow.bwd_packet_count = 3;

        assert_eq!(cic_flow.get_flow_iat_mean(), 2.8125);
    }

    #[test]
    fn test_get_flow_iat_std() {
        let mut cic_flow = setup_cic_flow();
        let epsilon = 1e-2; // floating-point arithmetic is not exact, here we have a lot of casting and the formula is also an approximation

        //let forward_iat = [1.0, 2.0, 3.0, 4.0, 5.0];
        //let backward_iat = [1.5, 2.5, 3.5];

        cic_flow.fwd_iat_mean = 3.0;
        cic_flow.bwd_iat_mean = 2.5;

        cic_flow.basic_flow.fwd_packet_count = 5;
        cic_flow.basic_flow.bwd_packet_count = 3;

        cic_flow.fwd_iat_std = 1.4142135623731;
        cic_flow.bwd_iat_std = 0.81649658092773;

        assert!(
            (cic_flow.get_flow_iat_std() - 1.2484365222149).abs() < epsilon,
            "get_flow_iat_std is not within the expected range"
        );
    }

    #[test]
    fn test_get_flow_iat_max() {
        let mut cic_flow = setup_cic_flow();

        cic_flow.fwd_iat_max = 5.0;
        cic_flow.bwd_iat_max = 3.0;

        assert_eq!(cic_flow.get_flow_iat_max(), 5.0);
    }

    #[test]
    fn test_get_flow_iat_min() {
        let mut cic_flow = setup_cic_flow();

        assert_eq!(cic_flow.get_flow_iat_min(), 0.0);

        cic_flow.fwd_iat_min = 1.0;
        cic_flow.bwd_iat_min = 2.0;

        assert_eq!(cic_flow.get_flow_iat_min(), 1.0);
    }

    #[test]
    fn test_get_fwd_iat_min() {
        let mut cic_flow = setup_cic_flow();

        assert_eq!(cic_flow.get_fwd_iat_min(), 0.0);

        cic_flow.fwd_iat_min = 1.0;

        assert_eq!(cic_flow.get_fwd_iat_min(), 1.0);
    }

    #[test]
    fn test_get_bwd_iat_min() {
        let mut cic_flow = setup_cic_flow();

        assert_eq!(cic_flow.get_bwd_iat_min(), 0.0);

        cic_flow.bwd_iat_min = 2.0;

        assert_eq!(cic_flow.get_bwd_iat_min(), 2.0);
    }

    #[test]
    fn test_get_flow_packet_length_min() {
        let mut cic_flow = setup_cic_flow();

        assert_eq!(cic_flow.get_flow_packet_length_min(), 0);

        cic_flow.fwd_pkt_len_min = 50;
        cic_flow.bwd_pkt_len_min = 100;

        assert_eq!(cic_flow.get_flow_packet_length_min(), 50);
    }

    #[test]
    fn test_get_fwd_packet_length_min() {
        let mut cic_flow = setup_cic_flow();

        assert_eq!(cic_flow.get_fwd_packet_length_min(), 0);

        cic_flow.fwd_pkt_len_min = 50;

        assert_eq!(cic_flow.get_fwd_packet_length_min(), 50);
    }

    #[test]
    fn test_get_bwd_packet_length_min() {
        let mut cic_flow = setup_cic_flow();

        assert_eq!(cic_flow.get_bwd_packet_length_min(), 0);

        cic_flow.bwd_pkt_len_min = 100;

        assert_eq!(cic_flow.get_bwd_packet_length_min(), 100);
    }

    #[test]
    fn test_get_flow_packet_length_max() {
        let mut cic_flow = setup_cic_flow();

        cic_flow.fwd_pkt_len_max = 100;
        cic_flow.bwd_pkt_len_max = 50;

        assert_eq!(cic_flow.get_flow_packet_length_max(), 100);
    }

    #[test]
    fn test_get_flow_packet_length_mean() {
        let mut cic_flow = setup_cic_flow();

        //let forward_iat = [10, 20, 30, 40, 50];
        //let backward_iat = [15, 25, 35];

        cic_flow.fwd_pkt_len_mean = 30.0;
        cic_flow.bwd_pkt_len_mean = 25.0;

        cic_flow.basic_flow.fwd_packet_count = 5;
        cic_flow.basic_flow.bwd_packet_count = 3;

        assert_eq!(cic_flow.get_flow_packet_length_mean(), 28.125);
    }

    #[test]
    fn test_get_flow_packet_length_variance() {
        let mut cic_flow = setup_cic_flow();

        //let forward_iat = [10, 20, 30, 40, 50];
        //let backward_iat = [15, 25, 35];

        cic_flow.fwd_pkt_len_std = 14.142135623731;
        cic_flow.bwd_pkt_len_std = 8.1649658092773;

        cic_flow.basic_flow.fwd_packet_count = 5;
        cic_flow.basic_flow.bwd_packet_count = 3;

        assert_eq!(cic_flow.get_flow_packet_length_variance() as u32, 155); // removing everything behind the comma because of arithmetic errors
    }

    #[test]
    fn test_get_flow_packet_length_std() {
        let mut cic_flow = setup_cic_flow();
        let epsilon = 1e-1; // floating-point arithmetic is not exact, here we have a lot of casting and the formula is also an approximation

        //let forward_iat = [10, 20, 30, 40, 50];
        //let backward_iat = [15, 25, 35];

        cic_flow.fwd_pkt_len_std = 14.142135623731;
        cic_flow.bwd_pkt_len_std = 8.1649658092773;

        cic_flow.basic_flow.fwd_packet_count = 5;
        cic_flow.basic_flow.bwd_packet_count = 3;

        assert!(
            (cic_flow.get_flow_packet_length_std() - 12.484365222149).abs() < epsilon,
            "get_flow_packet_length_std is not within the expected range"
        );
    }

    #[test]
    fn test_get_up_down_ratio() {
        let mut cic_flow = setup_cic_flow();

        cic_flow.basic_flow.fwd_packet_count = 5;
        cic_flow.basic_flow.bwd_packet_count = 3;

        assert_eq!(cic_flow.get_down_up_ratio(), 5 as f64 / 3 as f64);
    }

    #[test]
    fn test_get_fwd_segment_length_mean() {
        let mut cic_flow = setup_cic_flow();

        cic_flow.fwd_seg_len_tot = 100;
        cic_flow.basic_flow.fwd_packet_count = 5;

        assert_eq!(cic_flow.get_fwd_segment_length_mean(), 20.0);
    }

    #[test]
    fn test_get_bwd_segment_length_mean() {
        let mut cic_flow = setup_cic_flow();

        cic_flow.bwd_seg_len_tot = 100;
        cic_flow.basic_flow.bwd_packet_count = 5;

        assert_eq!(cic_flow.get_bwd_segment_length_mean(), 20.0);
    }

    #[test]
    fn test_get_duration() {
        let start = chrono::Utc::now();
        let end = start + chrono::Duration::try_seconds(5).unwrap();

        assert_eq!(get_duration(start, end), 5_000_000.0);
    }

    #[test]
    fn test_get_flow_bytes_s() {
        let mut cic_flow = setup_cic_flow();

        cic_flow.basic_flow.first_timestamp = chrono::Utc::now();
        cic_flow.basic_flow.last_timestamp =
            chrono::Utc::now() + chrono::Duration::try_seconds(5).unwrap();

        cic_flow.fwd_pkt_len_tot = 100;
        cic_flow.bwd_pkt_len_tot = 100;

        assert_eq!(cic_flow.get_flow_bytes_s(), 40.0);
    }

    #[test]
    fn test_get_flow_packets_s() {
        let mut cic_flow = setup_cic_flow();

        cic_flow.basic_flow.first_timestamp = chrono::Utc::now();
        cic_flow.basic_flow.last_timestamp =
            chrono::Utc::now() + chrono::Duration::try_seconds(5).unwrap();

        cic_flow.basic_flow.fwd_packet_count = 5;
        cic_flow.basic_flow.bwd_packet_count = 5;

        assert_eq!(cic_flow.get_flow_packets_s(), 2.0);
    }

    #[test]
    fn test_get_fwd_packets_s() {
        let mut cic_flow = setup_cic_flow();

        cic_flow.basic_flow.first_timestamp = chrono::Utc::now();
        cic_flow.basic_flow.last_timestamp =
            chrono::Utc::now() + chrono::Duration::try_seconds(5).unwrap();

        cic_flow.basic_flow.fwd_packet_count = 5;

        assert_eq!(cic_flow.get_fwd_packets_s(), 1.0);
    }

    #[test]
    fn test_get_bwd_packets_s() {
        let mut cic_flow = setup_cic_flow();

        cic_flow.basic_flow.first_timestamp = chrono::Utc::now();
        cic_flow.basic_flow.last_timestamp =
            chrono::Utc::now() + chrono::Duration::try_seconds(5).unwrap();

        cic_flow.basic_flow.bwd_packet_count = 5;

        assert_eq!(cic_flow.get_bwd_packets_s(), 1.0);
    }

    #[test]
    fn test_get_fwd_bytes_bulk() {
        let mut cic_flow = setup_cic_flow();

        assert_eq!(cic_flow.get_fwd_bytes_bulk(), 0.0);

        cic_flow.fwd_bulk_size_total = 100;
        cic_flow.fwd_bulk_state_count = 5;

        assert_eq!(cic_flow.get_fwd_bytes_bulk(), 20.0);
    }

    #[test]
    fn test_get_fwd_packets_bulk() {
        let mut cic_flow = setup_cic_flow();

        assert_eq!(cic_flow.get_fwd_packets_bulk(), 0.0);

        cic_flow.fwd_bulk_packet_count = 100;
        cic_flow.fwd_bulk_state_count = 5;

        assert_eq!(cic_flow.get_fwd_packets_bulk(), 20.0);
    }

    #[test]
    fn test_get_fwd_bulk_rate() {
        let mut cic_flow = setup_cic_flow();

        assert_eq!(cic_flow.get_fwd_bulk_rate(), 0.0);

        cic_flow.fwd_bulk_size_total = 100;
        cic_flow.fwd_bulk_duration = 5_000_000.0;

        assert_eq!(cic_flow.get_fwd_bulk_rate(), 20.0);
    }

    #[test]
    fn test_get_bwd_bytes_bulk() {
        let mut cic_flow = setup_cic_flow();

        assert_eq!(cic_flow.get_bwd_bytes_bulk(), 0.0);

        cic_flow.bwd_bulk_size_total = 100;
        cic_flow.bwd_bulk_state_count = 5;

        assert_eq!(cic_flow.get_bwd_bytes_bulk(), 20.0);
    }

    #[test]
    fn test_get_bwd_packets_bulk() {
        let mut cic_flow = setup_cic_flow();

        assert_eq!(cic_flow.get_bwd_packets_bulk(), 0.0);

        cic_flow.bwd_bulk_packet_count = 100;
        cic_flow.bwd_bulk_state_count = 5;

        assert_eq!(cic_flow.get_bwd_packets_bulk(), 20.0);
    }

    #[test]
    fn test_get_bwd_bulk_rate() {
        let mut cic_flow = setup_cic_flow();

        assert_eq!(cic_flow.get_bwd_bulk_rate(), 0.0);

        cic_flow.bwd_bulk_size_total = 100;
        cic_flow.bwd_bulk_duration = 5_000_000.0;

        assert_eq!(cic_flow.get_bwd_bulk_rate(), 20.0);
    }

    #[test]
    fn test_update_flow_first_with_fwd_packet() {
        let mut cic_flow = CicFlow::new(
            "".to_string(),
            IpAddr::V4(Ipv4Addr::from(1)),
            80,
            IpAddr::V4(Ipv4Addr::from(2)),
            8080,
            6,
            chrono::Utc::now(),
        );
        let packet = BasicFeatures {
            fin_flag: 1,
            syn_flag: 0,
            rst_flag: 0,
            psh_flag: 0,
            ack_flag: 1,
            urg_flag: 0,
            cwe_flag: 0,
            ece_flag: 1,
            data_length: 25,
            header_length: 40,
            length: 80,
            window_size: 500,
        };
        let timestamp = Instant::now();

        cic_flow.update_flow(&packet, &timestamp, chrono::Utc::now() , true);

        assert_eq!(cic_flow.basic_flow.fwd_packet_count, 1);
        assert_eq!(cic_flow.basic_flow.bwd_packet_count, 0);
        assert_eq!(cic_flow.fwd_pkt_len_max, 25);
        assert_eq!(cic_flow.fwd_pkt_len_min, 25);
        assert_eq!(cic_flow.fwd_pkt_len_mean, 25.0);
        assert_eq!(cic_flow.fwd_pkt_len_std, 0.0);
        assert_eq!(cic_flow.fwd_pkt_len_tot, 25);
        assert_eq!(cic_flow.fwd_iat_max, 0.0);
        assert_eq!(cic_flow.fwd_iat_min, f64::MAX);
        assert_eq!(cic_flow.fwd_iat_mean, 0.0);
        assert_eq!(cic_flow.fwd_iat_std, 0.0);
        assert_eq!(cic_flow.fwd_iat_total, 0.0);
        assert_eq!(cic_flow.fwd_bulk_state_count, 0);
        assert_eq!(cic_flow.fwd_bulk_packet_count, 0);
        assert_eq!(cic_flow.fwd_bulk_size_total, 0);
        assert_eq!(cic_flow.fwd_bulk_duration, 0.0);
        assert_eq!(cic_flow.fwd_bulk_packet_count_help, 1);
        assert_eq!(cic_flow.fwd_bulk_start_help, Some(timestamp));
        assert_eq!(cic_flow.fwd_bulk_size_help, 25);
        assert_eq!(cic_flow.fwd_last_bulk_timestamp, Some(timestamp));
        assert_eq!(cic_flow.fwd_header_length, 40);
        assert_eq!(cic_flow.fwd_last_timestamp, Some(timestamp));
        assert_eq!(cic_flow.fwd_init_win_bytes, 500);
        assert_eq!(cic_flow.bwd_header_length, 0);
        assert_eq!(cic_flow.bwd_last_timestamp, None);
        assert_eq!(cic_flow.bwd_pkt_len_max, 0);
        assert_eq!(cic_flow.bwd_pkt_len_min, u32::MAX);
        assert_eq!(cic_flow.bwd_pkt_len_mean, 0.0);
        assert_eq!(cic_flow.bwd_pkt_len_std, 0.0);
        assert_eq!(cic_flow.bwd_pkt_len_tot, 0);
        assert_eq!(cic_flow.bwd_iat_max, 0.0);
        assert_eq!(cic_flow.bwd_iat_min, f64::MAX);
        assert_eq!(cic_flow.bwd_iat_mean, 0.0);
        assert_eq!(cic_flow.bwd_iat_std, 0.0);
        assert_eq!(cic_flow.bwd_iat_total, 0.0);
        assert_eq!(cic_flow.bwd_bulk_state_count, 0);
        assert_eq!(cic_flow.bwd_bulk_packet_count, 0);
        assert_eq!(cic_flow.bwd_bulk_size_total, 0);
        assert_eq!(cic_flow.bwd_bulk_duration, 0.0);
        assert_eq!(cic_flow.bwd_bulk_packet_count_help, 0);
        assert_eq!(cic_flow.bwd_bulk_start_help, None);
        assert_eq!(cic_flow.bwd_bulk_size_help, 0);
        assert_eq!(cic_flow.bwd_last_bulk_timestamp, None);
        assert_eq!(cic_flow.bwd_init_win_bytes, 0);
    }

    #[test]
    fn test_update_flow_first_with_bwd_packet() {
        let mut cic_flow = CicFlow::new(
            "".to_string(),
            IpAddr::V4(Ipv4Addr::from(1)),
            80,
            IpAddr::V4(Ipv4Addr::from(2)),
            8080,
            6,
            chrono::Utc::now(),
        );
        let packet = BasicFeatures {
            fin_flag: 1,
            syn_flag: 0,
            rst_flag: 0,
            psh_flag: 0,
            ack_flag: 1,
            urg_flag: 0,
            cwe_flag: 0,
            ece_flag: 1,
            data_length: 25,
            header_length: 40,
            length: 80,
            window_size: 500,
        };
        let timestamp = Instant::now();

        cic_flow.update_flow(&packet, &timestamp, chrono::Utc::now(), false);

        assert_eq!(cic_flow.basic_flow.fwd_packet_count, 0);
        assert_eq!(cic_flow.basic_flow.bwd_packet_count, 1);
        assert_eq!(cic_flow.fwd_pkt_len_max, 0);
        assert_eq!(cic_flow.fwd_pkt_len_min, u32::MAX);
        assert_eq!(cic_flow.fwd_pkt_len_mean, 0.0);
        assert_eq!(cic_flow.fwd_pkt_len_std, 0.0);
        assert_eq!(cic_flow.fwd_pkt_len_tot, 0);
        assert_eq!(cic_flow.fwd_iat_max, 0.0);
        assert_eq!(cic_flow.fwd_iat_min, f64::MAX);
        assert_eq!(cic_flow.fwd_iat_mean, 0.0);
        assert_eq!(cic_flow.fwd_iat_std, 0.0);
        assert_eq!(cic_flow.fwd_iat_total, 0.0);
        assert_eq!(cic_flow.fwd_bulk_state_count, 0);
        assert_eq!(cic_flow.fwd_bulk_packet_count, 0);
        assert_eq!(cic_flow.fwd_bulk_size_total, 0);
        assert_eq!(cic_flow.fwd_bulk_duration, 0.0);
        assert_eq!(cic_flow.fwd_bulk_packet_count_help, 0);
        assert_eq!(cic_flow.fwd_bulk_start_help, None);
        assert_eq!(cic_flow.fwd_bulk_size_help, 0);
        assert_eq!(cic_flow.fwd_last_bulk_timestamp, None);
        assert_eq!(cic_flow.fwd_header_length, 0);
        assert_eq!(cic_flow.fwd_last_timestamp, None);
        assert_eq!(cic_flow.fwd_init_win_bytes, 0);
        assert_eq!(cic_flow.bwd_header_length, 40);
        assert_eq!(cic_flow.bwd_last_timestamp, Some(timestamp));
        assert_eq!(cic_flow.bwd_pkt_len_max, 25);
        assert_eq!(cic_flow.bwd_pkt_len_min, 25);
        assert_eq!(cic_flow.bwd_pkt_len_mean, 25.0);
        assert_eq!(cic_flow.bwd_pkt_len_std, 0.0);
        assert_eq!(cic_flow.bwd_pkt_len_tot, 25);
        assert_eq!(cic_flow.bwd_iat_max, 0.0);
        assert_eq!(cic_flow.bwd_iat_min, f64::MAX);
        assert_eq!(cic_flow.bwd_iat_mean, 0.0);
        assert_eq!(cic_flow.bwd_iat_std, 0.0);
        assert_eq!(cic_flow.bwd_iat_total, 0.0);
        assert_eq!(cic_flow.bwd_bulk_state_count, 0);
        assert_eq!(cic_flow.bwd_bulk_packet_count, 0);
        assert_eq!(cic_flow.bwd_bulk_size_total, 0);
        assert_eq!(cic_flow.bwd_bulk_duration, 0.0);
        assert_eq!(cic_flow.bwd_bulk_packet_count_help, 1);
        assert_eq!(cic_flow.bwd_bulk_start_help, Some(timestamp));
        assert_eq!(cic_flow.bwd_bulk_size_help, 25);
        assert_eq!(cic_flow.bwd_last_bulk_timestamp, Some(timestamp));
        assert_eq!(cic_flow.bwd_init_win_bytes, 500);
    }

    #[test]
    fn test_update_flow_with_fwd_packet() {
        let mut cic_flow = CicFlow::new(
            "".to_string(),
            IpAddr::V4(Ipv4Addr::from(1)),
            80,
            IpAddr::V4(Ipv4Addr::from(2)),
            8080,
            6,
            chrono::Utc::now(),
        );
        let packet_1 = BasicFeatures {
            fin_flag: 1,
            syn_flag: 0,
            rst_flag: 0,
            psh_flag: 0,
            ack_flag: 1,
            urg_flag: 0,
            cwe_flag: 0,
            ece_flag: 1,
            data_length: 25,
            header_length: 40,
            length: 80,
            window_size: 500,
        };
        let timestamp_1 = Instant::now();

        cic_flow.update_flow(&packet_1, &timestamp_1, chrono::Utc::now(), true);

        std::thread::sleep(std::time::Duration::from_secs(1));

        let packet_2 = BasicFeatures {
            fin_flag: 1,
            syn_flag: 0,
            rst_flag: 0,
            psh_flag: 0,
            ack_flag: 1,
            urg_flag: 0,
            cwe_flag: 0,
            ece_flag: 1,
            data_length: 50,
            header_length: 40,
            length: 100,
            window_size: 100,
        };
        let timestamp_2 = Instant::now();

        cic_flow.update_flow(&packet_2, &timestamp_2, chrono::Utc::now(), true);

        assert_eq!(cic_flow.basic_flow.fwd_packet_count, 2);
        assert_eq!(cic_flow.basic_flow.bwd_packet_count, 0);
        assert_eq!(cic_flow.fwd_pkt_len_max, 50);
        assert_eq!(cic_flow.fwd_pkt_len_min, 25);
        assert_eq!(cic_flow.fwd_pkt_len_mean, 37.5);
        assert_eq!(cic_flow.fwd_pkt_len_std, 12.5);
        assert_eq!(cic_flow.fwd_pkt_len_tot, 75);
        assert_eq!(
            cic_flow.fwd_iat_max,
            timestamp_2.duration_since(timestamp_1).as_micros() as f64
        );
        assert_eq!(
            cic_flow.fwd_iat_min,
            timestamp_2.duration_since(timestamp_1).as_micros() as f64
        );
        assert_eq!(
            cic_flow.fwd_iat_mean,
            timestamp_2.duration_since(timestamp_1).as_micros() as f64
        );
        assert_eq!(cic_flow.fwd_iat_std, 0.0);
        assert_eq!(
            cic_flow.fwd_iat_total,
            timestamp_2.duration_since(timestamp_1).as_micros() as f64
        );
        assert_eq!(cic_flow.fwd_bulk_state_count, 0);
        assert_eq!(cic_flow.fwd_bulk_packet_count, 0);
        assert_eq!(cic_flow.fwd_bulk_size_total, 0);
        assert_eq!(cic_flow.fwd_bulk_duration, 0.0);
        assert_eq!(cic_flow.fwd_bulk_packet_count_help, 1);
        assert_eq!(cic_flow.fwd_bulk_start_help, Some(timestamp_2));
        assert_eq!(cic_flow.fwd_bulk_size_help, 50);
        assert_eq!(cic_flow.fwd_last_bulk_timestamp, Some(timestamp_2));
        assert_eq!(cic_flow.fwd_header_length, 80);
        assert_eq!(cic_flow.fwd_last_timestamp, Some(timestamp_2));
        assert_eq!(cic_flow.fwd_init_win_bytes, 500);
        assert_eq!(cic_flow.bwd_header_length, 0);
        assert_eq!(cic_flow.bwd_last_timestamp, None);
        assert_eq!(cic_flow.bwd_pkt_len_max, 0);
        assert_eq!(cic_flow.bwd_pkt_len_min, u32::MAX);
        assert_eq!(cic_flow.bwd_pkt_len_mean, 0.0);
        assert_eq!(cic_flow.bwd_pkt_len_std, 0.0);
        assert_eq!(cic_flow.bwd_pkt_len_tot, 0);
        assert_eq!(cic_flow.bwd_iat_max, 0.0);
        assert_eq!(cic_flow.bwd_iat_min, f64::MAX);
        assert_eq!(cic_flow.bwd_iat_mean, 0.0);
        assert_eq!(cic_flow.bwd_iat_std, 0.0);
        assert_eq!(cic_flow.bwd_iat_total, 0.0);
        assert_eq!(cic_flow.bwd_bulk_state_count, 0);
        assert_eq!(cic_flow.bwd_bulk_packet_count, 0);
        assert_eq!(cic_flow.bwd_bulk_size_total, 0);
        assert_eq!(cic_flow.bwd_bulk_duration, 0.0);
        assert_eq!(cic_flow.bwd_bulk_packet_count_help, 0);
        assert_eq!(cic_flow.bwd_bulk_start_help, None);
        assert_eq!(cic_flow.bwd_bulk_size_help, 0);
        assert_eq!(cic_flow.bwd_last_bulk_timestamp, None);
        assert_eq!(cic_flow.bwd_init_win_bytes, 0);
    }

    #[test]
    fn test_update_flow_with_bwd_packet() {
        let mut cic_flow = CicFlow::new(
            "".to_string(),
            IpAddr::V4(Ipv4Addr::from(1)),
            80,
            IpAddr::V4(Ipv4Addr::from(2)),
            8080,
            6,
            chrono::Utc::now(),
        );
        let packet_1 = BasicFeatures {
            fin_flag: 1,
            syn_flag: 0,
            rst_flag: 0,
            psh_flag: 0,
            ack_flag: 1,
            urg_flag: 0,
            cwe_flag: 0,
            ece_flag: 1,
            data_length: 25,
            header_length: 40,
            length: 80,
            window_size: 500,
        };
        let timestamp_1 = Instant::now();

        cic_flow.update_flow(&packet_1, &timestamp_1, chrono::Utc::now(), false);

        std::thread::sleep(std::time::Duration::from_secs(1));

        let packet_2 = BasicFeatures {
            fin_flag: 1,
            syn_flag: 0,
            rst_flag: 0,
            psh_flag: 0,
            ack_flag: 1,
            urg_flag: 0,
            cwe_flag: 0,
            ece_flag: 1,
            data_length: 50,
            header_length: 40,
            length: 100,
            window_size: 100,
        };
        let timestamp_2 = Instant::now();

        cic_flow.update_flow(&packet_2, &timestamp_2, chrono::Utc::now(), false);

        assert_eq!(cic_flow.basic_flow.fwd_packet_count, 0);
        assert_eq!(cic_flow.basic_flow.bwd_packet_count, 2);
        assert_eq!(cic_flow.fwd_pkt_len_max, 0);
        assert_eq!(cic_flow.fwd_pkt_len_min, u32::MAX);
        assert_eq!(cic_flow.fwd_pkt_len_mean, 0.0);
        assert_eq!(cic_flow.fwd_pkt_len_std, 0.0);
        assert_eq!(cic_flow.fwd_pkt_len_tot, 0);
        assert_eq!(cic_flow.fwd_iat_max, 0.0);
        assert_eq!(cic_flow.fwd_iat_min, f64::MAX);
        assert_eq!(cic_flow.fwd_iat_mean, 0.0);
        assert_eq!(cic_flow.fwd_iat_std, 0.0);
        assert_eq!(cic_flow.fwd_iat_total, 0.0);
        assert_eq!(cic_flow.fwd_bulk_state_count, 0);
        assert_eq!(cic_flow.fwd_bulk_packet_count, 0);
        assert_eq!(cic_flow.fwd_bulk_size_total, 0);
        assert_eq!(cic_flow.fwd_bulk_duration, 0.0);
        assert_eq!(cic_flow.fwd_bulk_packet_count_help, 0);
        assert_eq!(cic_flow.fwd_bulk_start_help, None);
        assert_eq!(cic_flow.fwd_bulk_size_help, 0);
        assert_eq!(cic_flow.fwd_last_bulk_timestamp, None);
        assert_eq!(cic_flow.fwd_header_length, 0);
        assert_eq!(cic_flow.fwd_last_timestamp, None);
        assert_eq!(cic_flow.fwd_init_win_bytes, 0);
        assert_eq!(cic_flow.bwd_header_length, 80);
        assert_eq!(cic_flow.bwd_last_timestamp, Some(timestamp_2));
        assert_eq!(cic_flow.bwd_pkt_len_max, 50);
        assert_eq!(cic_flow.bwd_pkt_len_min, 25);
        assert_eq!(cic_flow.bwd_pkt_len_mean, 37.5);
        assert_eq!(cic_flow.bwd_pkt_len_std, 12.5);
        assert_eq!(cic_flow.bwd_pkt_len_tot, 75);
        assert_eq!(
            cic_flow.bwd_iat_max,
            timestamp_2.duration_since(timestamp_1).as_micros() as f64
        );
        assert_eq!(
            cic_flow.bwd_iat_min,
            timestamp_2.duration_since(timestamp_1).as_micros() as f64
        );
        assert_eq!(
            cic_flow.bwd_iat_mean,
            timestamp_2.duration_since(timestamp_1).as_micros() as f64
        );
        assert_eq!(cic_flow.bwd_iat_std, 0.0);
        assert_eq!(
            cic_flow.bwd_iat_total,
            timestamp_2.duration_since(timestamp_1).as_micros() as f64
        );
        assert_eq!(cic_flow.bwd_bulk_state_count, 0);
        assert_eq!(cic_flow.bwd_bulk_packet_count, 0);
        assert_eq!(cic_flow.bwd_bulk_size_total, 0);
        assert_eq!(cic_flow.bwd_bulk_duration, 0.0);
        assert_eq!(cic_flow.bwd_bulk_packet_count_help, 1);
        assert_eq!(cic_flow.bwd_bulk_start_help, Some(timestamp_2));
        assert_eq!(cic_flow.bwd_bulk_size_help, 50);
        assert_eq!(cic_flow.bwd_last_bulk_timestamp, Some(timestamp_2));
        assert_eq!(cic_flow.bwd_init_win_bytes, 500);
    }
}
