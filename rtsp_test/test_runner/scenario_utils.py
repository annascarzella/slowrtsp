"""Shared helpers for RTSP test scenarios."""


def make_client(client_cls, client_id, server, port, path, user, password, timeout, *, udp_ports=True):
    """
    Helper function to create and configure an RTSP client instance.
    If udp_ports is True, assigns unique RTP/RTCP ports based on client_id.
    """
    client = client_cls(server, port, path, user, password, timeout)

    if udp_ports:
        client.rtp_port = 20000 + (client_id * 2)
        client.rtcp_port = 20001 + (client_id * 2)

    return client


def close_client(client):
    for attr in ("rtp_socket", "rtcp_socket"):
        sock = getattr(client, attr, None)
        if sock:
            try:
                sock.close()
            except Exception:
                pass

    try:
        client.close()
    except Exception:
        pass


def options_describe_get_control_url(client):
    client.send_options()
    status, headers, sdp = client.send_describe()

    control_urls = parse_sdp_control_urls(sdp)

    if not control_urls:
        raise RuntimeError("No media streams in SDP")

    return control_urls[0]


def setup_udp_stream(client):
    client.connect()
    client.setup_udp_sockets()

    control_url = options_describe_get_control_url(client)

    client.send_setup(control_url, transport_mode="UDP")

    return control_url


def parse_sdp_control_urls(sdp):
    """
    Parse SDP to extract media control URLs.
    
    Handles multiple SDP formats:
    - Standard: a=control:rtsp://...&stream=1
    - Simple: a=control:track1, a=control:track2
    
    Args:
        sdp: SDP string
    
    Returns:
        List of control URLs (e.g., ['track1', 'track2'])
    """
    # First try to find URLs with &stream= parameter (standard format)
    control_urls = [line.split(':', 1)[1].strip() 
                   for line in sdp.split('\n') 
                   if line.startswith('a=control:') and '&stream=' in line]
    
    # If not found, accept any a=control: line with non-empty, non-wildcard value
    if not control_urls:
        control_urls = [line.split(':', 1)[1].strip() 
                       for line in sdp.split('\n') 
                       if line.startswith('a=control:') and line.split(':', 1)[1].strip() not in ['*', '']]
    
    return control_urls
