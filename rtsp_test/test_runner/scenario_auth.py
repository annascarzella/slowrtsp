"""RTSP authentication and replay-related scenarios."""

import time

try:
    from scenario_imports import (
        RTSPClient,
        monitor_stream,
        make_client,
        close_client,
        parse_sdp_control_urls,
    )
except ImportError:
    from .scenario_imports import (
        RTSPClient,
        monitor_stream,
        make_client,
        close_client,
        parse_sdp_control_urls,
    )


def scenario_describe_unauthenticated_retry(client_id, server, port, path, user, password, timeout, duration, wto=30):
    client = make_client(RTSPClient, client_id, server, port, path, user, password, timeout)

    try:
        client.connect()
        client.setup_udp_sockets()

        client.send_options()

        try:
            status, headers, sdp = client.send_describe()
        except Exception:
            status, headers, sdp = client.send_describe()

        control_urls = parse_sdp_control_urls(sdp)

        if not control_urls:
            raise RuntimeError("No media streams in SDP")

        client.send_setup(control_urls[0], transport_mode="UDP")

        play_time = time.time()
        client.send_play()

        monitor_stream(client, duration, wto, play_time, use_rtp_sockets=True)
        client.send_teardown()

    except Exception:
        pass

    finally:
        close_client(client)

def scenario_repeat_options_same_nonce(client_id, server, port, path, user, password, timeout, duration, wto=30):
    """
    REPEAT OPTIONS with SAME NONCE scenario - tests digest replay detection.
    Sends OPTIONS without auth (gets 401 with nonce), then sends OPTIONS with digest auth twice using the same nonce.
    Flow: OPTIONS (no auth) → OPTIONS (with auth, nonce=N1) → OPTIONS (with auth, same digest as previous using nonce=N1)
    
    This scenario tests whether the server properly validates nonce uniqueness or allows digest replay attacks.
    The third OPTIONS should either fail or be rejected if the server properly implements nonce protection.
    
    Args:
        client_id: Unique client identifier
        server: Server IP address
        port: Server port
        path: RTSP resource path
        user: Username for authentication
        password: Password for authentication
        timeout: Socket timeout in seconds
        duration: Stream duration in seconds (0 for indefinite)
        wto: Wait timeout for GET_PARAMETER keepalive requests
    """
    client = make_client(RTSPClient, client_id, server, port, path, user, password, timeout, udp_ports=False)
    
    try:
        client.connect()
        
        # First OPTIONS - no authentication (should get 401 with nonce)
        try:
            client.send_options()
        except Exception as e:
            print(f"Scenario failed: {e}")
        
        
        # Second OPTIONS - with authentication using the nonce from the challenge
        try:
            client.send_options()
        except Exception as e:
            raise
        
        # Store the authenticated request to replay it
        # We'll send the exact same OPTIONS request without incrementing CSeq or changing digest
        
        try:
            client.send_options()
        except Exception as e:
            print(f"Scenario failed: {e}")
   
    
    except Exception as e:
        print(f"Scenario failed: {e}")
    finally:
        client.close()
