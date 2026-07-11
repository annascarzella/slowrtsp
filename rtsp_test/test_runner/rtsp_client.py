"""
RTSP Client Module

Provides RTSPClient class and utility functions for RTSP streaming clients.
Implements basic RTSP protocol flow:
OPTIONS → DESCRIBE → SETUP (with UDP ports) → PLAY → (receive UDP RTP) → TEARDOWN
"""

import socket
import re
import time
import hashlib

class RTSPClient:
    """Simple RTSP client for streaming connections."""
    
    def __init__(self, server_ip, server_port, resource_path, username=None, password=None, timeout=300):
        """
        Initialize RTSP client.
        
        Args:
            server_ip: Server IP address
            server_port: Server port (default 554)
            resource_path: Resource path (e.g., "rtsp_tunnel" or "stream1")
            username: Username for authentication (optional)
            password: Password for authentication (optional)
            timeout: Socket timeout in seconds
        """
        self.server_ip = server_ip
        self.server_port = server_port
        self.resource_path = resource_path
        self.username = username
        self.password = password
        self.timeout = timeout
        
        # Build RTSP URL
        url_base = f"rtsp://{server_ip}:{server_port}"
        if resource_path:
            url_base = f"{url_base}/{resource_path}"
        
        if username and password:
            self.rtsp_url = f"rtsp://{username}:{password}@{server_ip}:{server_port}"
            if resource_path:
                self.rtsp_url = f"{self.rtsp_url}/{resource_path}"
        else:
            self.rtsp_url = url_base
        
        # Connection state
        self.socket = None
        self.cseq = 0
        self.session_id = None
        self.connected = False
        self.digest_auth = None  # Store digest auth info for subsequent requests
        self.basic_auth_attempted = False  # Track if we've already tried basic auth
        
        # UDP RTP sockets
        self.rtp_socket = None
        self.rtcp_socket = None
        self.rtp_port = 12345  # Local RTP port
        self.rtcp_port = 12346  # Local RTCP port
    
    def _get_cseq(self):
        """Get next CSeq number."""
        self.cseq += 1
        return self.cseq
    
    def _parse_digest_challenge(self, www_authenticate):
        """
        Parse WWW-Authenticate header for Digest auth.
        
        Args:
            www_authenticate: WWW-Authenticate header value
        
        Returns:
            Dict with realm, nonce, algorithm, opaque, qop, etc.
        """
        auth_dict = {}
        # Extract digest parameters - handle both quoted and unquoted values
        # Pattern: key="quoted value" or key=unquoted_value
        pattern = r'(\w+)=(?:"([^"]*)"|([^,\s]+))'
        for match in re.finditer(pattern, www_authenticate):
            key = match.group(1)
            # Value is either in group 2 (quoted) or group 3 (unquoted)
            value = match.group(2) if match.group(2) is not None else match.group(3)
            auth_dict[key] = value
        
        
        return auth_dict
    
    def _compute_digest_response(self, method, uri, auth_dict):
        """
        Compute digest authentication response.
        
        Supports both standard digest (RFC 2617) with and without qop parameter.
        
        Args:
            method: RTSP method
            uri: Request URI (full URL)
            auth_dict: Parsed WWW-Authenticate dict
        
        Returns:
            Digest auth header value
        """
        realm = auth_dict.get('realm', '')
        nonce = auth_dict.get('nonce', '')
        algorithm = auth_dict.get('algorithm', 'MD5').upper()
        opaque = auth_dict.get('opaque', '')
        qop = auth_dict.get('qop', '')  # Can be 'auth', 'auth-int', or comma-separated list
        
        include_algorithm = 'algorithm' in auth_dict
        
        # Hash function based on algorithm
        if algorithm == 'MD5':
            hash_func = hashlib.md5
        else:
            hash_func = hashlib.md5  # Default to MD5

        digest_uri = uri
        
        ha1_input = f"{self.username}:{realm}:{self.password}"
        ha1 = hash_func(ha1_input.encode()).hexdigest()
        
        ha2_input = f"{method}:{digest_uri}"
        ha2 = hash_func(ha2_input.encode()).hexdigest()

        # Build Authorization header
        auth_header = f'Digest username="{self.username}", realm="{realm}", nonce="{nonce}", uri="{digest_uri}"'
        
        # Compute response based on qop
        if qop:
            # Use qop (Quality of Protection)
            # Pick 'auth' if available (it's more common than 'auth-int')
            if ',' in qop:
                qop_value = 'auth' if 'auth' in qop else qop.split(',')[0].strip()
            else:
                qop_value = qop.strip()
            
            # Generate nonce count and client nonce
            nc = "00000001"
            import uuid
            cnonce = hashlib.md5(str(uuid.uuid4()).encode()).hexdigest()[:16]
            
            # response = hash(HA1:nonce:nc:cnonce:qop:HA2)
            response_input = f"{ha1}:{nonce}:{nc}:{cnonce}:{qop_value}:{ha2}"
            response = hash_func(response_input.encode()).hexdigest()
            
            # Add response and qop parameters
            auth_header += f', response="{response}", opaque="{opaque}"' if opaque else f', response="{response}"'
            auth_header += f', qop={qop_value}, nc={nc}, cnonce="{cnonce}"'
        else:
            # No qop - standard digest
            # response = hash(HA1:nonce:HA2)
            response_input = f"{ha1}:{nonce}:{ha2}"
            response = hash_func(response_input.encode()).hexdigest()
            
            # Add response parameter
            auth_header += f', response="{response}"'
            if opaque:
                auth_header += f', opaque="{opaque}"'
        
        # Only include algorithm if it was explicitly sent in the challenge
        # Dahua cameras (this server) don't send it, so we shouldn't echo it back
        # But other servers might send it and expect it in the response
        if include_algorithm:
            auth_header += f', algorithm={algorithm}'

        return auth_header
    
    def _get_request_url(self):
        """Get RTSP URL without credentials for use in request line."""
        if self.resource_path:
            return f"rtsp://{self.server_ip}:{self.server_port}/{self.resource_path}"
        else:
            # ffplay uses a trailing slash for root RTSP resources.
            return f"rtsp://{self.server_ip}:{self.server_port}/"

    def _build_setup_url(self, track_uri):
        """Build a SETUP URL from an absolute or relative SDP control URI."""
        if track_uri.lower().startswith('rtsp://'):
            return track_uri

        return f"{self._get_request_url().rstrip('/')}/{track_uri.lstrip('/')}"
    
    def _build_request(self, method, url, headers=None, include_auth=True, auth_type=None):
        """
        Build RTSP request.
        
        Args:
            method: RTSP method (OPTIONS, DESCRIBE, SETUP, PLAY, TEARDOWN)
            url: RTSP URL (without credentials in the request line)
            headers: Dict of additional headers
            include_auth: Whether to include authentication headers
            auth_type: Type of auth to use ('digest', 'basic', or None for auto)
        
        Returns:
            Request string
        """
        if headers is None:
            headers = {}
        
        # Build request line - use the base URL without credentials
        request = f"{method} {url} RTSP/1.0\r\n"
        request += f"CSeq: {self._get_cseq()}\r\n"
        # todo inserted this for testing purposes. check if we need to change it / the meaning
        request += f"User-Agent: Lavf/60.16.100\r\n"
        
        # Add authentication if available and requested
        if include_auth:
            if auth_type == 'digest' or (auth_type is None and self.digest_auth):
                # Use cached digest auth
                auth_header = self._compute_digest_response(method, url, self.digest_auth)
                request += f"Authorization: {auth_header}\r\n"
            elif auth_type == 'basic' or (auth_type is None and self.basic_auth_attempted and self.username and self.password):
                # Use basic auth
                import base64
                credentials = base64.b64encode(f"{self.username}:{self.password}".encode()).decode()
                request += f"Authorization: Basic {credentials}\r\n"
        
        # Add custom headers
        for key, value in headers.items():
            request += f"{key}: {value}\r\n"
        
        # Session ID (after first response)
        if self.session_id and method != "DESCRIBE":
            request += f"Session: {self.session_id}\r\n"
        
        request += "\r\n"
        return request

    def _receive_response(self):
        """Receive an RTSP response, including the body when Content-Length is present."""
        response = b""

        while True:
            try:
                chunk = self.socket.recv(4096)
                if not chunk:
                    break
                response += chunk
                
                # Check if we have complete response (simple heuristic)
                if b"\r\n\r\n" in response:
                    # For responses with body (DESCRIBE), check content-length
                    response_str = response.decode(errors='ignore')
                    if "Content-Length:" in response_str:
                        # Has body, might need more data
                        match = re.search(r'Content-Length:\s*(\d+)', response_str)
                        if match:
                            content_length = int(match.group(1))
                            header_end = response.find(b"\r\n\r\n") + 4
                            body_received = len(response) - header_end
                            if body_received >= content_length:
                                break
                    else:
                        # No body, response is complete
                        break
            except socket.timeout:
                break

        return response.decode(errors='ignore')
    
    def _send_request(self, method, url=None, headers=None, retry_count=0):
        """
        Send RTSP request and receive response.
        
        Handles authentication by:
        1. First sending request without auth
        2. If 401 received, checking for auth challenge (Digest or Basic)
        3. For Digest: caching challenge and retrying with computed response
        4. For Basic: retrying with base64-encoded credentials
        5. This allows both OPTIONS and DESCRIBE to independently request authentication
        
        Args:
            method: RTSP method
            url: RTSP URL (optional, uses default without credentials)
            headers: Dict of additional headers
            retry_count: Internal counter for retries with auth
        
        Returns:
            Tuple of (status_code, headers_dict, body)
        """
        if url is None:
            url = self._get_request_url()
        
        # On first attempt, only include auth if we already have it cached or flagged
        include_auth = (self.digest_auth is not None) or (self.basic_auth_attempted and self.username and self.password) or (retry_count > 0)
        request = self._build_request(method, url, headers, include_auth=include_auth)
        
        
        try:
            self.socket.sendall(request.encode())

            response_str = self._receive_response()
            status_code, resp_headers, body = self._parse_response(response_str)
            
            # Handle 401 Unauthorized with auth challenge
            # This can happen on any method (OPTIONS, DESCRIBE, SETUP, etc.)
            if status_code == 401 and "WWW-Authenticate" in resp_headers and retry_count == 0:
                www_auth = resp_headers["WWW-Authenticate"]
                
                if "Digest" in www_auth:
                    # Parse digest challenge and cache it
                    self.digest_auth = self._parse_digest_challenge(www_auth)
                    # Retry the same request with cached digest auth
                    return self._send_request(method, url, headers, retry_count=retry_count + 1)
                
                elif "Basic" in www_auth:
                    if self.username and self.password:
                        # Set flag to include basic auth on retry
                        self.basic_auth_attempted = True
                        # Retry the same request with basic auth
                        return self._send_request(method, url, headers, retry_count=retry_count + 1)
                    else:
                        return status_code, resp_headers, body
                else:
                    return status_code, resp_headers, body
            elif status_code == 401 and retry_count > 0:
                # Already retried once, give up
                return status_code, resp_headers, body
            
            return status_code, resp_headers, body
        
        except Exception as e:
            raise
    
    def _parse_response(self, response_str):
        """
        Parse RTSP response.
        
        Args:
            response_str: Response string
        
        Returns:
            Tuple of (status_code, headers_dict, body)
        """
        lines = response_str.split('\r\n')
        
        # Parse status line
        status_line = lines[0]
        match = re.match(r'RTSP/\d\.\d (\d+)', status_line)
        if not match:
            # If we can't parse status line, might be binary data (RTP packets)
            raise ValueError(f"Invalid status line: {status_line}")
        
        status_code = int(match.group(1))
        
        # Parse headers
        headers = {}
        body_start = 0
        for i, line in enumerate(lines[1:], 1):
            if line == "":
                body_start = i + 1
                break
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip()] = value.strip()
        
        # Get body
        body = '\r\n'.join(lines[body_start:])
        
        return status_code, headers, body
    
    def connect(self):
        """Establish TCP connection to RTSP server."""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(self.timeout)
            self.socket.connect((self.server_ip, self.server_port))
            self.connected = True
        except Exception as e:
            raise
    
    def setup_udp_sockets(self):
        """Create UDP sockets for RTP/RTCP streams."""
        try:
            # RTP socket (even port)
            self.rtp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.rtp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.rtp_socket.bind(('0.0.0.0', self.rtp_port))
            self.rtp_socket.settimeout(self.timeout)
            
            # RTCP socket (odd port, RTP+1)
            self.rtcp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.rtcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.rtcp_socket.bind(('0.0.0.0', self.rtcp_port))
            self.rtcp_socket.settimeout(self.timeout)
        except Exception as e:
            raise
    
    def send_options(self):
        """Send OPTIONS request to discover server capabilities."""
        status_code, headers, body = self._send_request("OPTIONS")
        
        if status_code != 200:
            raise RuntimeError(f"OPTIONS failed with status {status_code}")
        
        return status_code, headers, body
    
    def send_describe(self):
        """Send DESCRIBE request to get media description (SDP)."""
        headers = {"Accept": "application/sdp"}
        status_code, headers_resp, body = self._send_request("DESCRIBE", headers=headers)
        
        if status_code != 200:
            raise RuntimeError(f"DESCRIBE failed with status {status_code}")
        
        # Extract and store session ID if present
        if "Session" in headers_resp:
            self.session_id = headers_resp["Session"].split(';')[0]
        
        return status_code, headers, body
    
    def send_setup(self, track_uri, transport_mode="UDP"):
        """
        Send SETUP request to establish media session.
        
        Args:
            track_uri: Track control URI (can be relative or full URL from SDP)
            transport_mode: "UDP", "TCP", or "NO_PORTS" (bare RTP/AVP without ports)
        
        Returns:
            Session ID
        """
        setup_url = self._build_setup_url(track_uri)
        
        # Build transport header based on mode
        if transport_mode == "UDP":
            transport = f"RTP/AVP;unicast;client_port={self.rtp_port}-{self.rtcp_port}"
        elif transport_mode == "NO_PORTS":
            transport = "RTP/AVP;unicast"
        else:
            transport = "RTP/AVP/TCP;unicast;interleaved=0-1"
        
        headers = {"Transport": transport}
        status_code, response_headers, body = self._send_request("SETUP", setup_url, headers)
        
        if status_code not in [200, 201]:
            raise RuntimeError(f"SETUP failed with status {status_code}")
        
        # Extract session ID from response
        if "Session" in response_headers:
            self.session_id = response_headers["Session"].split(';')[0]
        
        return status_code, response_headers, body
    
    def send_play(self):
        """Send PLAY request to start streaming."""
        status_code, headers, body = self._send_request("PLAY")
        
        if status_code != 200:
            raise RuntimeError(f"PLAY failed with status {status_code}")
    
        return status_code, headers, body
    
    def send_pause(self):
        """Send PAUSE request to pause streaming."""
        status_code, headers, body = self._send_request("PAUSE")
        
        if status_code != 200:
            raise RuntimeError(f"PAUSE failed with status {status_code}")
        
        return status_code, headers, body
    
    def send_get_parameter(self):
        """Send GET_PARAMETER request to keep connection alive (keepalive)."""
        try:
            status_code, headers, body = self._send_request("GET_PARAMETER")
            
            if status_code == 200:
                # Success - connection is still alive
                return True
            else:
                return False
        except Exception as e:
            return False
    
    def send_incomplete_get_parameter(self):
        """
        Send incomplete GET_PARAMETER request.
        Does not include Session header and lacks the double newline that marks end of request.
        """
        try:
            url = self._get_request_url()
            
            # Build incomplete request manually
            request = f"GET_PARAMETER {url} RTSP/1.0\r\n"
            request += f"CSeq: {self._get_cseq()}\r\n"
            request += f"User-Agent: RTSPStreamingClient\r\n"
            
            # Add authentication if available (but NOT Session header)
            # Only add digest auth if cached; don't preemptively send Basic auth
            if self.digest_auth:
                auth_header = self._compute_digest_response("GET_PARAMETER", url, self.digest_auth)
                request += f"Authorization: {auth_header}\r\n"
            
            # INTENTIONALLY OMIT: Session header and final \r\n\r\n
            # This makes the request incomplete
            
            # Send incomplete request
            self.socket.sendall(request.encode())
            
            return True
        except Exception as e:
            raise
        
    def send_teardown(self):
        """Send TEARDOWN request to close session."""
        try:
            status_code, headers, body = self._send_request("TEARDOWN")
            
            if status_code not in [200, 456]:  # 456 = Session Not Found is also acceptable
                # Only raise if we got a real error response (not just RTP data)
                if status_code and status_code >= 400:
                    raise RuntimeError(f"TEARDOWN failed with status {status_code}")
            
            return status_code, headers, body
        except ValueError:
            # This happens when RTP data is mixed with response
            return 200, {}, ""
    
    def close(self):
        """Close socket connection."""
        if self.socket:
            self.socket.close()


def monitor_stream(client, duration, wto=30, play_time=None, use_rtp_sockets=True):
    """
    Monitor stream for specified duration and optionally receive UDP RTP packets.
    
    Args:
        client: RTSPClient instance
        duration: Duration to stream (0 for indefinite)
        wto: Wait timeout for GET_PARAMETER requests in seconds
        play_time: Time when PLAY was sent (defaults to now)
        use_rtp_sockets: Whether to attempt receiving RTP packets via UDP (True if sockets were set up)
    """
    _monitor_stream(
        client,
        duration,
        play_time=play_time,
        use_rtp_sockets=use_rtp_sockets,
        send_keepalive=True,
        wto=wto,
    )


def monitor_stream_no_get_param(client, duration, play_time=None, use_rtp_sockets=True):
    """
    Monitor stream for specified duration without sending GET_PARAMETER keepalive requests.
    Only receives UDP RTP packets.
    
    Args:
        client: RTSPClient instance
        duration: Duration to stream (0 for indefinite)
        play_time: Time when PLAY was sent (defaults to now)
        use_rtp_sockets: Whether to attempt receiving RTP packets via UDP (True if sockets were set up)
    """
    _monitor_stream(
        client,
        duration,
        play_time=play_time,
        use_rtp_sockets=use_rtp_sockets,
        send_keepalive=False,
    )


def _monitor_stream(client, duration, play_time=None, use_rtp_sockets=True, send_keepalive=False, wto=30):
    if play_time is None:
        play_time = time.time()  # Fallback if not provided
    
    if duration <= 0:
        try:
            while True:
                if use_rtp_sockets:
                    try:
                        # Try to receive RTP packet (non-blocking with timeout)
                        client.rtp_socket.recvfrom(4096)
                    except socket.timeout:
                        pass
                
                if send_keepalive and time.time() - play_time >= wto:
                    client.send_get_parameter()
                    play_time = time.time()  # Reset timer
                
                time.sleep(0.1)
        except KeyboardInterrupt:
            pass
    else:
        start_time = time.time()
        
        while time.time() - start_time < duration:
            if use_rtp_sockets:
                try:
                    # Try to receive RTP packet with timeout
                    client.rtp_socket.recvfrom(4096)
                except socket.timeout:
                    pass
            
            if send_keepalive and time.time() - play_time >= wto:
                client.send_get_parameter()
                play_time = time.time()  # Reset timer
            
            time.sleep(0.01)
