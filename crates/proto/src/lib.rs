//! Protobuf message types and gRPC service definitions for operator-to-operator communication.
//!
//! Uses prost derive macros for message encoding and tonic for gRPC transport.
//! No protoc or build.rs required.

pub mod messages;
pub mod service;

pub use messages::*;
pub use service::*;
