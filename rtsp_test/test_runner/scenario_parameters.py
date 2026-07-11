"""RTSP scenarios for GET_PARAMETER and SET_PARAMETER requests."""

import socket

try:
    from scenario_imports import RTSPClient, make_client, close_client
except ImportError:
    from .scenario_imports import RTSPClient, make_client, close_client


def scenario_get_parameter_with_params(client_id, server, port, path, user, password, timeout, duration, wto=30):
    """
    GET_PARAMETER with COMPREHENSIVE PARAMETER QUERIES scenario - sends GET_PARAMETER request 
    with a body that asks for ALL possible RTSP parameters to discover server capabilities.
    Flow: OPTIONS → DESCRIBE → GET_PARAMETER (with comprehensive params, NO UDP streaming) → TEARDOWN
    
    This scenario tests how the server handles GET_PARAMETER requests with actual parameter 
    bodies that query for multiple server parameters. Does NOT open UDP sockets or stream RTP.
    Useful for discovering what parameters the server supports without setting up actual streaming.
    
    Args:
        client_id: Unique client identifier
        server: Server IP address
        port: Server port
        path: RTSP resource path
        user: Username for authentication
        password: Password for authentication
        timeout: Socket timeout in seconds
        duration: Stream duration in seconds (0 for indefinite) - not used in this scenario
        wto: Wait timeout (not used in this scenario)
    """
    client = make_client(RTSPClient, client_id, server, port, path, user, password, timeout, udp_ports=False)
    
    try:
        client.connect()
        
        client.send_options()
        
        status, headers, sdp = client.send_describe()
        
        # Build comprehensive parameter query body with all possible parameters
        # Standard RTSP parameters
        params = [
            "Scale",
            "Speed",
            "Range",
            "Position",
            "media-range",
            "seek-style",
            "accept-ranges",
            "rtpinfo",
            "medias",
            "recorders",
            "notify-reason",
            "play.media",
            "dates",
            "control",
            "mode",
            "url",
            "charset",
            "allow",
            "public",
        ]
        
        param_body = "\n".join(params) + "\n"
        url = client._get_request_url()
        
        # Send GET_PARAMETER with parameter queries
        
        # Manually construct the GET_PARAMETER request with body
        request = f"GET_PARAMETER {url} RTSP/1.0\r\n"
        request += f"CSeq: {client._get_cseq()}\r\n"
        request += f"User-Agent: RTSPStreamingClient\r\n"
        
        # Add authentication if available
        if client.digest_auth:
            auth_header = client._compute_digest_response("GET_PARAMETER", url, client.digest_auth)
            request += f"Authorization: {auth_header}\r\n"
        elif client.username and client.password:
            import base64
            credentials = base64.b64encode(f"{client.username}:{client.password}".encode()).decode()
            request += f"Authorization: Basic {credentials}\r\n"
        
        # Note: No Session ID needed since we didn't SETUP
        
        # Add content headers for parameter body
        request += f"Content-Type: text/parameters\r\n"
        request += f"Content-Length: {len(param_body)}\r\n"
        request += "\r\n"
        request += param_body
        
        try:
            client.socket.sendall(request.encode())
            
            # Receive response
            response = b""
            while True:
                try:
                    chunk = client.socket.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    if b"\r\n\r\n" in response:
                        break
                except socket.timeout:
                    break
            
            response_str = response.decode(errors='ignore')
            response_lines = response_str.split('\r\n')
            status_line = response_lines[0]
        
        except Exception as e:
            print(f"Scenario failed: {e}")
        
        
        # Send TEARDOWN to close session cleanly
        try:
            client.send_teardown()
        except Exception as e:
            print(f"Scenario failed: {e}")
   
    
    except Exception as e:
        print(f"Scenario failed: {e}")
    finally:
        close_client(client)


def scenario_set_parameter(client_id, server, port, path, user, password, timeout, duration, wto=30):
    """
    SET_PARAMETER with INVALID PARAMETER TEST - sends SET_PARAMETER with invalid/unsupported 
    parameters to test if server properly rejects them with 451 status code.
    Flow: OPTIONS → DESCRIBE → SET_PARAMETER (invalid params) → SET_PARAMETER (valid params)
    
    Tests whether the server properly validates parameters and responds with:
    - 200 OK for valid parameters
    - 451 Invalid Parameter for unsupported parameters (as per RTSP spec RFC 2326)
    
    Args:
        client_id: Unique client identifier
        server: Server IP address
        port: Server port
        path: RTSP resource path
        user: Username for authentication
        password: Password for authentication
        timeout: Socket timeout in seconds
        duration: Stream duration in seconds (0 for indefinite) - not used in this scenario
        wto: Wait timeout (not used in this scenario)
    """
    client = make_client(RTSPClient, client_id, server, port, path, user, password, timeout, udp_ports=False)
    
    try:
        client.connect()
        
        client.send_options()
        
        status, headers, sdp = client.send_describe()
        
        url = client._get_request_url()
        
        # ===== TEST 1: INVALID PARAMETERS =====
        
        invalid_params = [
            "InvalidParameter=123",
            "UnknownSetting=xyz",
            "FakeMode=test",
        ]
        
        param_body = "\n".join(invalid_params) + "\n"
        
        
        # Construct SET_PARAMETER request
        request = f"SET_PARAMETER {url} RTSP/1.0\r\n"
        request += f"CSeq: {client._get_cseq()}\r\n"
        request += f"User-Agent: RTSPStreamingClient\r\n"
        
        # Add authentication if available
        if client.digest_auth:
            auth_header = client._compute_digest_response("SET_PARAMETER", url, client.digest_auth)
            request += f"Authorization: {auth_header}\r\n"
        elif client.username and client.password:
            import base64
            credentials = base64.b64encode(f"{client.username}:{client.password}".encode()).decode()
            request += f"Authorization: Basic {credentials}\r\n"
        
        request += f"Content-Type: text/parameters\r\n"
        request += f"Content-Length: {len(param_body)}\r\n"
        request += "\r\n"
        request += param_body
        
        try:
            client.socket.sendall(request.encode())
            
            # Receive response
            response = b""
            while True:
                try:
                    chunk = client.socket.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    if b"\r\n\r\n" in response:
                        break
                except socket.timeout:
                    break
            
            response_str = response.decode(errors='ignore')
            response_lines = response_str.split('\r\n')
            status_line = response_lines[0]
        
        except Exception as e:
            print(f"Scenario failed: {e}")
        
        # ===== TEST 2: VALID PARAMETERS =====
        
        valid_params = [
            "Scale=1.0",
            "Speed=1.0",
            "mode=play",
        ]
        
        param_body = "\n".join(valid_params) + "\n"
        
        
        # Construct SET_PARAMETER request
        request = f"SET_PARAMETER {url} RTSP/1.0\r\n"
        request += f"CSeq: {client._get_cseq()}\r\n"
        request += f"User-Agent: RTSPStreamingClient\r\n"
        
        # Add authentication if available
        if client.digest_auth:
            auth_header = client._compute_digest_response("SET_PARAMETER", url, client.digest_auth)
            request += f"Authorization: {auth_header}\r\n"
        elif client.username and client.password:
            import base64
            credentials = base64.b64encode(f"{client.username}:{client.password}".encode()).decode()
            request += f"Authorization: Basic {credentials}\r\n"
        
        request += f"Content-Type: text/parameters\r\n"
        request += f"Content-Length: {len(param_body)}\r\n"
        request += "\r\n"
        request += param_body
        
        try:
            client.socket.sendall(request.encode())
            
            # Receive response
            response = b""
            while True:
                try:
                    chunk = client.socket.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    if b"\r\n\r\n" in response:
                        break
                except socket.timeout:
                    break
            
            response_str = response.decode(errors='ignore')
            response_lines = response_str.split('\r\n')
            status_line = response_lines[0]
        
        except Exception as e:
            print(f"Scenario failed: {e}")
   
    
    except Exception as e:
        print(f"Scenario failed: {e}")
    finally:
        close_client(client)
