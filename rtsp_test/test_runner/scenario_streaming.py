"""Standard RTSP streaming and playback scenarios."""

import time

try:
    from scenario_imports import (
        RTSPClient,
        monitor_stream,
        monitor_stream_no_get_param,
        make_client,
        close_client,
        options_describe_get_control_url,
        setup_udp_stream,
    )
except ImportError:
    from .scenario_imports import (
        RTSPClient,
        monitor_stream,
        monitor_stream_no_get_param,
        make_client,
        close_client,
        options_describe_get_control_url,
        setup_udp_stream,
    )


def scenario_legitimate_stream(client_id, server, port, path, user, password, timeout, duration, wto=30):
    """
    Standard legitimate RTSP stream scenario.
    Flow: OPTIONS → DESCRIBE → SETUP (with UDP ports) → PLAY → TEARDOWN
    
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
    client = make_client(RTSPClient, client_id, server, port, path, user, password, timeout)
    
    try:
        setup_udp_stream(client)
        
        play_time = time.time()
        client.send_play()
        
        monitor_stream(client, duration, wto, play_time, use_rtp_sockets=True)
        
        # After monitoring, send TEARDOWN to cleanly close the session
        client.send_teardown()
    
    except Exception as e:
        print(f"Scenario failed: {e}")
    
    finally:
        close_client(client)


def scenario_pause(client_id, server, port, path, user, password, timeout, duration, wto=30):
    """
    PAUSE scenario - pauses stream immediately after SETUP.
    Flow: OPTIONS → DESCRIBE → SETUP → PAUSE → TEARDOWN
    
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
    client = make_client(RTSPClient, client_id, server, port, path, user, password, timeout)
    
    try:
        setup_udp_stream(client)
        
        pause_time = time.time()
        client.send_pause()
        
        monitor_stream(client, duration, wto, pause_time, use_rtp_sockets=True)
        client.send_teardown()
    
    except Exception as e:
        print(f"Scenario failed: {e}")
    
    finally:
        close_client(client)


def scenario_pause_twice(client_id, server, port, path, user, password, timeout, duration, wto=30):
    """
    PAUSE TWICE scenario - sends PAUSE request twice in a row.
    Flow: OPTIONS → DESCRIBE → SETUP → PAUSE → PAUSE → TEARDOWN
    
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
    client = make_client(RTSPClient, client_id, server, port, path, user, password, timeout)
    
    try:
        setup_udp_stream(client)
        
        pause_time = time.time()
        client.send_pause()
        client.send_pause()  # Send PAUSE again
        
        monitor_stream(client, duration, wto, pause_time, use_rtp_sockets=True)
        client.send_teardown()
    
    except Exception as e:
        print(f"Scenario failed: {e}")
    
    finally:
        close_client(client)


def scenario_pause_loop(client_id, server, port, path, user, password, timeout, duration):
    """
    PAUSE/PLAY LOOP scenario - repeatedly pauses and plays the stream.
    Each iteration monitors for 50 seconds without GET_PARAMETER keepalive.
    
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
        setup_udp_stream(client)
        
        # PLAY/PAUSE loop
        loop_count = 0
        start_time = time.time()
        
        while True:
            # Check if duration limit exceeded
            if duration > 0 and (time.time() - start_time) >= duration:
                break
            
            loop_count += 1
            
            play_time = time.time()
            client.send_play()
            client.send_pause()
            
            # Small delay to let the server process PAUSE before monitoring
            time.sleep(1)
            
            monitor_stream_no_get_param(client, duration=50, play_time=play_time, use_rtp_sockets=True)
        
        client.send_teardown()
    
    except Exception as e:
        print(f"Scenario failed: {e}")
    
    finally:
        close_client(client)


def scenario_incomplete_get_parameter(
    client_id, server, port, path, user, password, timeout, duration, wto=2
):
    """
    Sends an incomplete GET_PARAMETER request, then appends one space
    every wto seconds without completing the RTSP request.
    """
    client = make_client(
        RTSPClient, client_id, server, port, path, user, password, timeout, udp_ports=False
    )

    try:
        client.connect()
        control_url = options_describe_get_control_url(client)
        client.send_setup(control_url, transport_mode="NO_PORTS")

        client.send_play()
        client.send_incomplete_get_parameter()

        start_time = time.monotonic()

        while duration <= 0 or (time.monotonic() - start_time) < duration:
            time.sleep(wto)
            client.socket.sendall(b" ")

    except Exception as e:
        print(f"Scenario failed: {e}")

    finally:
        # Do not send TEARDOWN: it would be appended to the still-incomplete
        # GET_PARAMETER request on the same TCP connection.
        close_client(client)
        
def scenario_pause_no_keepalive(client_id, server, port, path, user, password, timeout, duration):
    """
    PAUSE (no keepalive) scenario - sends PAUSE after SETUP and monitors without GET_PARAMETER.
    Flow: OPTIONS → DESCRIBE → SETUP → PAUSE → Monitor (no keepalive) → TEARDOWN
    
    Args:
        client_id: Unique client identifier
        server: Server IP address
        port: Server port
        path: RTSP resource path
        user: Username for authentication
        password: Password for authentication
        timeout: Socket timeout in seconds
        duration: Stream duration in seconds (0 for indefinite)
    """
    client = make_client(RTSPClient, client_id, server, port, path, user, password, timeout)
    
    try:
        setup_udp_stream(client)
        
        pause_time = time.time()
        client.send_pause()
        
        monitor_stream_no_get_param(client, duration, pause_time, use_rtp_sockets=True)
        
        client.send_teardown()
        
    
    except Exception as e:
        print(f"Scenario failed: {e}")
   
    
    finally:
        close_client(client)


def scenario_play_loop(client_id, server, port, path, user, password, timeout, duration, wto=30):
    """
    PLAY LOOP scenario - sends OPTIONS → DESCRIBE → SETUP once, then sends PLAY every wto seconds.
    Flow: OPTIONS → DESCRIBE → SETUP → [Loop: PLAY (every wto seconds)] → TEARDOWN
    
    Args:
        client_id: Unique client identifier
        server: Server IP address
        port: Server port
        path: RTSP resource path
        user: Username for authentication
        password: Password for authentication
        timeout: Socket timeout in seconds
        duration: Total session duration in seconds (0 for indefinite)
        wto: Wait timeout - interval in seconds between PLAY commands
    """
    client = make_client(RTSPClient, client_id, server, port, path, user, password, timeout, udp_ports=False)
    
    try:
        client.connect()
        
        # Initial OPTIONS and DESCRIBE
        control_url = options_describe_get_control_url(client)
        
        # Initial SETUP
        client.send_setup(control_url, transport_mode="NO_PORTS")
        
        # PLAY loop - send PLAY every wto seconds
        play_count = 0
        start_time = time.time()
        next_play_time = start_time
        
        while True:
            # Check if duration limit exceeded
            if duration > 0 and (time.time() - start_time) >= duration:
                break
            
            current_time = time.time()
            
            if current_time >= next_play_time:
                play_count += 1
                elapsed = current_time - start_time
                
                try:
                    client.send_play()
                except Exception as e:
                    print(f"Scenario failed: {e}")
                
                
                # Schedule next PLAY in wto seconds
                next_play_time = current_time + wto
            
            # Sleep briefly to avoid busy-waiting
            time.sleep(0.1)
        
        client.send_teardown()
        
    
    except Exception as e:
        pass
   
    
    finally:
        close_client(client)


def scenario_options_describe(client_id, server, port, path, user, password, timeout, duration, wto=30):
    """
    OPTIONS and DESCRIBE only scenario - sends OPTIONS and DESCRIBE, then monitors the connection.
    Flow: OPTIONS → DESCRIBE → Monitor connection
    
    Args:
        client_id: Unique client identifier
        server: Server IP address
        port: Server port
        path: RTSP resource path
        user: Username for authentication
        password: Password for authentication
        timeout: Socket timeout in seconds
        duration: Stream duration in seconds (0 for indefinite)
        wto: Wait timeout (not used for keepalive in this scenario)
    """
    client = make_client(RTSPClient, client_id, server, port, path, user, password, timeout, udp_ports=False)
    
    try:
        client.connect()
        
        options_describe_get_control_url(client)  # Just for validation
        
        monitor_time = time.time()
        monitor_stream_no_get_param(client, duration, monitor_time, use_rtp_sockets=False)
        
    
    except Exception as e:
        print(f"Scenario failed: {e}")
   
    
    finally:
        close_client(client)
