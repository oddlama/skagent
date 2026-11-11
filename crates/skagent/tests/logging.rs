//! The redaction rule for the protocol library's log output.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

use skagent::logging::is_redacted;
use tracing::Level;

#[test]
fn protocol_library_debug_and_trace_are_redacted() {
    for target in [
        "ssh_agent_lib",
        "ssh_agent_lib::agent",
        "ssh_agent_lib::proto::message",
    ] {
        assert!(is_redacted(target, Level::DEBUG), "{target} debug passes");
        assert!(is_redacted(target, Level::TRACE), "{target} trace passes");
    }
}

#[test]
fn protocol_library_info_and_above_pass() {
    for level in [Level::INFO, Level::WARN, Level::ERROR] {
        assert!(
            !is_redacted("ssh_agent_lib::agent", level),
            "{level} is redacted"
        );
    }
}

#[test]
fn other_targets_are_never_redacted() {
    for target in [
        "skagent",
        "skagent::serve",
        "ssh_agent_libx",
        "tokio",
        "ssh_key",
    ] {
        assert!(!is_redacted(target, Level::TRACE), "{target} is redacted");
    }
}
