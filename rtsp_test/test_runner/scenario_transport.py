"""RTSP transport and repeated request scenarios."""

import time

try:
    from scenario_imports import (
        RTSPClient,
        monitor_stream,
        make_client,
        close_client,
        options_describe_get_control_url,
    )
except ImportError:
    from .scenario_imports import (
        RTSPClient,
        monitor_stream,
        make_client,
        close_client,
        options_describe_get_control_url,
    )


def scenario_random_ports(client_id, server, port, path, user, password, timeout, duration, wto=30):
    """
    RANDOM PORTS scenario - sends SETUP with fixed unused port numbers but does NOT open UDP sockets.
    Server tries to send RTP to those ports, but nothing is listening (packets get dropped).
    Flow: OPTIONS → DESCRIBE → SETUP (with fixed unused ports, no sockets open) → PLAY → TEARDOWN
    
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
    client = RTSPClient(server, port, path, user, password, timeout)
    
    # Use fixed unused ports (not random - same for all connections)
    client.rtp_port = 55555   # Rarely used port
    client.rtcp_port = 55556  # Rarely used port
    
    
    try:
        client.connect()
        
        # NOTE: Intentionally NOT opening UDP sockets
        # Server will send RTP to these ports, but client isn't listening
        # Packets will be dropped by the OS
        
        control_url = options_describe_get_control_url(client)
        
        client.send_setup(control_url, transport_mode="UDP")
        
        play_time = time.time()
        client.send_play()
        
        monitor_stream(client, duration, wto, play_time, use_rtp_sockets=False)
        client.send_teardown()
        
    
    except Exception as e:
        print(f"Scenario failed: {e}")
   
    finally:
        close_client(client)


def scenario_setup_loop(client_id, server, port, path, user, password, timeout, duration, wto=30):
    """
    SETUP LOOP scenario - sends OPTIONS → DESCRIBE once, then SETUP every 55 seconds.
    Flow: OPTIONS → DESCRIBE → [Loop: SETUP (every 55s)] → TEARDOWN
    
    Args:
        client_id: Unique client identifier
        server: Server IP address
        port: Server port
        path: RTSP resource path
        user: Username for authentication
        password: Password for authentication
        timeout: Socket timeout in seconds
        duration: Total session duration in seconds (0 for indefinite)
    """
    client = make_client(RTSPClient, client_id, server, port, path, user, password, timeout)
    
    try:
        client.connect()
        client.setup_udp_sockets()
        
        control_url = options_describe_get_control_url(client)
        
        # SETUP loop - send SETUP every wto seconds
        setup_count = 0
        start_time = time.time()
        next_setup_time = start_time
        
        while True:
            # Check if duration limit exceeded
            if duration > 0 and (time.time() - start_time) >= duration:
                break
            
            current_time = time.time()
            
            if current_time >= next_setup_time:
                setup_count += 1
                elapsed = current_time - start_time
                
                try:
                    client.send_setup(control_url, transport_mode="UDP")
                except Exception as e:
                    print(f"Scenario failed: {e}")
                
                
                # Schedule next SETUP in wto seconds
                next_setup_time = current_time + wto
            
            # Sleep briefly to avoid busy-waiting
            time.sleep(0.1)
        
        client.send_teardown()
        
    
    except Exception as e:
        print(f"Scenario failed: {e}")
   
    
    finally:
        close_client(client)


def scenario_no_udp_ports(client_id, server, port, path, user, password, timeout, duration, wto=30):
    """
    NO PORTS scenario - does NOT specify ports to server or open UDP sockets.
    Uses the NO_PORTS transport mode (bare RTP/AVP;unicast without specifying ports).
    Flow: OPTIONS → DESCRIBE → SETUP (NO_PORTS mode) → PLAY → GET_PARAMETER every WTO → TEARDOWN
    
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
        
        # NOTE: Intentionally NOT opening UDP sockets
        # Server will be told to send RTP to these ports via NO_PORTS mode, but client isn't listening
        
        control_url = options_describe_get_control_url(client)
        
        client.send_setup(control_url, transport_mode="NO_PORTS")
        
        play_time = time.time()
        client.send_play()
        
        monitor_stream(client, duration, wto, play_time, use_rtp_sockets=False)
        client.send_teardown()
        
    
    except Exception as e:
        pass
   
    
    finally:
        close_client(client)

def scenario_play_immediately(client_id, server, port, path, user, password, timeout, duration, wto=30):
    """
    Send PLAY immediately as first request, with a randomly generated session ID. 
    This tests how the server handles a PLAY request without a prior SETUP.
    """
    client = make_client(RTSPClient, client_id, server, port, path, user, password, timeout)
    
    try:
        client.connect()
        
        # Generate a random session ID for the PLAY request
        random_session_id = f"session_{int(time.time())}_{client_id}"
        client.session_id = random_session_id
        
        # Send PLAY immediately without prior SETUP
        client.send_play()
        
        # Monitor the stream for the specified duration
        play_time = time.time()
        monitor_stream(client, duration, wto, play_time)
        
        # Send TEARDOWN to clean up
        client.send_teardown()
        
    except Exception as e:
        print(f"Scenario failed: {e}")
    
    finally:
        close_client(client)