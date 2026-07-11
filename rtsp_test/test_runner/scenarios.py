"""
Test Scenarios Module

Defines different test scenarios for RTSP connections and protocol testing.
Each scenario encapsulates a unique sequence of RTSP operations.
"""

try:
    from scenario_utils import (
        make_client,
        close_client,
        options_describe_get_control_url,
        parse_sdp_control_urls,
        setup_udp_stream,
    )
    from scenario_cseq import (
        RTSPClientCSeqAlways1,
        RTSPClientCSeqSkip,
        RTSPClientCSeqDecrement,
        scenario_wrong_cseq_always_1,
        scenario_wrong_cseq_skip,
        scenario_wrong_cseq_decrement,
    )
    from scenario_parameters import (
        scenario_get_parameter_with_params,
        scenario_set_parameter,
    )
    from scenario_streaming import (
        scenario_legitimate_stream,
        scenario_pause,
        scenario_pause_twice,
        scenario_pause_loop,
        scenario_incomplete_get_parameter,
        scenario_pause_no_keepalive,
        scenario_play_loop,
        scenario_options_describe,
    )
    from scenario_transport import (
        scenario_random_ports,
        scenario_setup_loop,
        scenario_no_udp_ports,
        scenario_play_immediately,
    )
    from scenario_teardown import (
        scenario_teardown_and_reuse_connection,
        scenario_cross_client_teardown,
    )
    from scenario_auth import (
        scenario_describe_unauthenticated_retry,
        scenario_repeat_options_same_nonce,
    )
    from scenario_reolink import scenario_reolink_stop_legitimate_streaming
    from scenario_reolink_only_stop_streaming import (
        scenario_reolink_only_stop_streaming,
    )
except ImportError:
    from .scenario_utils import (
        make_client,
        close_client,
        options_describe_get_control_url,
        parse_sdp_control_urls,
        setup_udp_stream,
    )
    from .scenario_cseq import (
        RTSPClientCSeqAlways1,
        RTSPClientCSeqSkip,
        RTSPClientCSeqDecrement,
        scenario_wrong_cseq_always_1,
        scenario_wrong_cseq_skip,
        scenario_wrong_cseq_decrement,
    )
    from .scenario_parameters import (
        scenario_get_parameter_with_params,
        scenario_set_parameter,
    )
    from .scenario_streaming import (
        scenario_legitimate_stream,
        scenario_pause,
        scenario_pause_twice,
        scenario_pause_loop,
        scenario_incomplete_get_parameter,
        scenario_pause_no_keepalive,
        scenario_play_loop,
        scenario_options_describe,
    )
    from .scenario_transport import (
        scenario_random_ports,
        scenario_setup_loop,
        scenario_no_udp_ports,
        scenario_play_immediately,
    )
    from .scenario_teardown import (
        scenario_teardown_and_reuse_connection,
        scenario_cross_client_teardown,
    )
    from .scenario_auth import (
        scenario_describe_unauthenticated_retry,
        scenario_repeat_options_same_nonce,
    )
    from .scenario_reolink import scenario_reolink_stop_legitimate_streaming
    from .scenario_reolink_only_stop_streaming import (
        scenario_reolink_only_stop_streaming,
    )


# Scenario registry: maps scenario names to functions

SCENARIOS = {
    "legitimate": scenario_legitimate_stream,
    "pause": scenario_pause,
    "pause_no_keepalive": scenario_pause_no_keepalive,
    "pause_twice": scenario_pause_twice,
    "pause_loop": scenario_pause_loop,
    "play_loop": scenario_play_loop,
    "incomplete_get_parameter": scenario_incomplete_get_parameter,
    "random_ports": scenario_random_ports,
    "no_udp_ports": scenario_no_udp_ports,
    "setup_loop": scenario_setup_loop,
    "wrong_cseq_always_1": scenario_wrong_cseq_always_1,
    "wrong_cseq_skip": scenario_wrong_cseq_skip,
    "wrong_cseq_decrement": scenario_wrong_cseq_decrement,
    "teardown_and_reuse_connection": scenario_teardown_and_reuse_connection,
    "cross_client_teardown": scenario_cross_client_teardown,
    "describe_unauthenticated_retry": scenario_describe_unauthenticated_retry,
    "repeat_options_same_nonce": scenario_repeat_options_same_nonce,
    "options_describe": scenario_options_describe,
    "get_parameter_with_params": scenario_get_parameter_with_params,
    "set_parameter": scenario_set_parameter,
    "reolink_stop_legitimate_streaming": scenario_reolink_stop_legitimate_streaming,
    "reolink_only_stop_streaming": scenario_reolink_only_stop_streaming,
    "play_immediately": scenario_play_immediately,
}


_HELPER_EXPORTS = [
    "make_client",
    "close_client",
    "options_describe_get_control_url",
    "parse_sdp_control_urls",
    "setup_udp_stream",
]

_CSEQ_CLIENT_EXPORTS = [
    "RTSPClientCSeqAlways1",
    "RTSPClientCSeqSkip",
    "RTSPClientCSeqDecrement",
]

_SCENARIO_EXPORTS = [scenario_func.__name__ for scenario_func in SCENARIOS.values()]

__all__ = (
    _HELPER_EXPORTS
    + _CSEQ_CLIENT_EXPORTS
    + _SCENARIO_EXPORTS
    + [
        "SCENARIOS",
        "get_available_scenarios",
        "get_scenario",
    ]
)


def get_available_scenarios():
    """Return list of available scenario names."""
    return list(SCENARIOS.keys())


def get_scenario(name):
    """Get scenario function by name.
    
    Args:
        name: Scenario name
    
    Returns:
        Scenario function or None if not found
    """
    return SCENARIOS.get(name)
