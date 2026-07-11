"""Shared compatibility imports for scenario modules."""

try:
    from rtsp_client import RTSPClient, monitor_stream, monitor_stream_no_get_param
except ImportError:
    from .rtsp_client import RTSPClient, monitor_stream, monitor_stream_no_get_param

try:
    from scenario_utils import (
        make_client,
        close_client,
        options_describe_get_control_url,
        parse_sdp_control_urls,
        setup_udp_stream,
    )
except ImportError:
    from .scenario_utils import (
        make_client,
        close_client,
        options_describe_get_control_url,
        parse_sdp_control_urls,
        setup_udp_stream,
    )
