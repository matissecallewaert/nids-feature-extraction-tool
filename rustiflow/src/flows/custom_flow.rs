use chrono::{DateTime, Utc};
use std::{net::IpAddr, time::Instant};

use crate::utils::utils::BasicFeatures;

use super::{basic_flow::BasicFlow, flow::Flow};

/// Represents a Custom Flow, encapsulating various metrics and states of a network flow.
///
/// This struct is made so you can define your own features.
pub struct CustomFlow {
    /// Choose here for an existing flow type or leave the basic flow.
    pub basic_flow: BasicFlow,
}

impl CustomFlow {
    // Define here the custom flow functions that calculate the additional features.
}

impl Flow for CustomFlow {
    fn new(
        flow_id: String,
        ipv4_source: IpAddr,
        port_source: u16,
        ipv4_destination: IpAddr,
        port_destination: u16,
        protocol: u8,
        ts_date: DateTime<Utc>,
    ) -> Self {
        CustomFlow {
            basic_flow: BasicFlow::new(
                flow_id,
                ipv4_source,
                port_source,
                ipv4_destination,
                port_destination,
                protocol,
                ts_date
            ),
            // Add here the initialization of the additional features.
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

        // Add here the update of the additional features.

        if self.basic_flow.flow_end_of_flow_ack > 0
            || self.basic_flow.fwd_rst_flag_count > 0
            || self.basic_flow.bwd_rst_flag_count > 0
        {
            return Some(self.dump());
        }

        None
    }

    fn dump(&self) -> String {
        // Add here the dump of the custom flow.
        format!("")
    }

    fn get_features() -> String {
        // Add here the features of the custom flow.
        format!("")
    }

    fn dump_without_contamination(&self) -> String {
        // Add here the dump of the custom flow without contaminant features.
        format!("")
    }

    fn get_features_without_contamination() -> String {
        // Add here the features of the custom flow without contaminant features.
        format!("")
    }

    fn get_first_timestamp(&self) -> DateTime<Utc> {
        self.basic_flow.get_first_timestamp()
    }
}

#[cfg(test)]
mod tests {
    // use std::net::{IpAddr, Ipv4Addr};

    // use crate::flows::flow::Flow;

    // use super::CustomFlow;

    // fn setup_customflow() -> CustomFlow {
    //     CustomFlow::new(
    //         "".to_string(),
    //         IpAddr::V4(Ipv4Addr::from(1)),
    //         80,
    //         IpAddr::V4(Ipv4Addr::from(2)),
    //         8080,
    //         6,
    //     )
    // }

    // Add here the tests for the custom flow, if you want to test the custom flow.
}
