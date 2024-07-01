use chrono::{DateTime, Utc};
use std::{net::IpAddr, time::Instant};

use crate::utils::utils::BasicFeatures;

/// `Flow` defines the behavior of a network flow.
///
/// This trait should be implemented by structures that represent
/// a network flow, providing mechanisms to update the flow state
/// and to dump its current state into a string format.
pub trait Flow {
    /// Constructs a new `Flow`.
    ///
    /// Initializes a `Flow` instance with the provided parameters, setting up
    /// the basic flow and initializing all other metrics to their default values.
    ///
    /// ### Arguments
    ///
    /// * `flow_id` - A unique identifier for the flow.
    /// * `ipv4_source` - The source IPv4 address.
    /// * `port_source` - The source port.
    /// * `ipv4_destination` - The destination IPv4 address.
    /// * `port_destination` - The destination port.
    /// * `protocol` - The protocol number.
    ///
    /// ### Returns
    ///
    /// Returns a new instance of `Flow`.
    fn new(
        flow_id: String,
        ipv4_source: IpAddr,
        port_source: u16,
        ipv4_destination: IpAddr,
        port_destination: u16,
        protocol: u8,
        ts_date: DateTime<Utc>,
    ) -> Self;

    /// Updates the flow with a new packet.
    ///
    /// This method processes a packet and updates the internal state of the flow
    /// based on the packet's features and the timestamp.
    ///
    /// ### Arguments
    ///
    /// * `packet` - A `BasicFeatures` instance representing the packet to be processed.
    /// * `timestamp` - The timestamp at which the packet is received.
    /// * `fwd` - A boolean flag indicating the direction of the flow (forward or not).
    ///
    /// ### Returns
    ///
    /// Returns an `Option<String>` which might contain a result after processing the packet.
    /// If the flow is terminated, you will get a dump of all features of the flow.
    fn update_flow(
        &mut self,
        packet: &BasicFeatures,
        timestamp: &Instant,
        ts_date: DateTime<Utc>,
        fwd: bool,
    ) -> Option<String>;

    /// Dumps the current state of the flow.
    ///
    /// This method returns a string representation of the current state of the flow.
    ///
    /// ### Returns
    ///
    /// Returns a `String` that represents the current state of the flow.
    fn dump(&self) -> String;

    /// Dumps the current state of the flow without contaminant features.
    ///
    /// This method returns a string representation of the current state of the flow without contaminant features.
    ///
    /// ### Returns
    ///
    /// Returns a `String` that represents the current state of the flow without contaminant features.
    fn dump_without_contamination(&self) -> String;

    /// Returns the first timestamp of the flow.
    ///
    /// This method returns the first timestamp of the flow.
    ///
    /// ### Returns
    ///
    /// Returns a `DateTime<Utc>` representing the first timestamp of the flow.
    fn get_first_timestamp(&self) -> DateTime<Utc>;

    /// Returns a first record with the features of the flow.
    ///
    /// This method returns a string representation of the features of the flow.
    ///
    /// ### Returns
    ///
    /// Returns a `String` that represents the features of the flow.
    fn get_features() -> String;

    /// Returns a first record with the features of the flow without contaminant features.
    ///
    /// This method returns a string representation of the features of the flow without contaminant features.
    ///
    /// ### Returns
    ///
    /// Returns a `String` that represents the features of the flow without contaminant features.
    fn get_features_without_contamination() -> String;
}
