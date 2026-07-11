"""
Unified Connection Handler Module

Handles individual TCP connections with support for different sending modes,
TCP keepalive socket options, and monitoring for server-initiated closures.
Can send raw bytes or formatted RTSP requests.
"""

import socket
import threading
import time

# Configuration constants
RECV_TIMEOUT = 5

# Global counters for connection tracking
connections_open = 0
connections_closed = 0
connections_closed_by_server = 0
total_bytes_sent = 0
total_connections_created = 0
lock = threading.Lock()


class ConnectionHandler:
    """Manages a single TCP connection with sending and monitoring."""
    
    def __init__(self, server_ip, server_port, packet_data=None, send_duration_seconds=0, keepalive_after_seconds=0):
        """
        Initialize connection handler.
        
        Args:
            server_ip: Server IP address
            server_port: Server port
            packet_data: Data to send (bytes or callable). If callable, will be called each time to get fresh data.
            send_duration_seconds: How long to send packets (0 for unlimited)
            keepalive_after_seconds: Enable TCP keepalive with TCP_KEEPIDLE set to this value in seconds (0 to disable)
        """
        self.server_ip = server_ip
        self.server_port = server_port
        self.packet_data = packet_data or b"a"
        self.socket = None
        self.connection_start_time = None
        self.fin_received_time = None
        self.send_duration_seconds = send_duration_seconds
        self.send_start_time = None
        self.keepalive_after_seconds = keepalive_after_seconds
        self.keepalive_sent = False
        self.server_closed_counted = False
    
    def connect(self):
        """Establish connection to server."""
        global connections_open, total_connections_created
        
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connection_start_time = time.time()
        self.socket.connect((self.server_ip, self.server_port))
        self.socket.settimeout(RECV_TIMEOUT)
        
        # Enable TCP keepalive if configured
        if self.keepalive_after_seconds > 0:
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, int(self.keepalive_after_seconds))
            self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)  # Probe every 10 seconds
            self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 9)      # 9 probes
        
        with lock:
            connections_open += 1
            total_connections_created += 1
    
    def send_packets(self, count=1):
        """Send one or more packets.
        
        Args:
            count: Number of packets to send (default: 1)
        """
        global total_bytes_sent
        
        for _ in range(count):
            try:
                # If packet_data is callable, call it to get fresh data each time
                if callable(self.packet_data):
                    data = self.packet_data()
                else:
                    data = self.packet_data
                self.socket.sendall(data)
            except (socket.error, BrokenPipeError, ConnectionResetError) as e:
                raise ConnectionResetError(f"Failed to send: {e}")
        
        with lock:
            total_bytes_sent += count
    
    def wait_preparing_phase(self, preparing_phase_ms):
        """Wait for the preparing phase before sending initial packet.
        
        Args:
            preparing_phase_ms: Milliseconds to wait. If negative, skip initial packet.
        
        Returns:
            True if initial packet should be sent, False otherwise.
        """
        if preparing_phase_ms < 0:
            return False  # Skip initial packet
        
        if preparing_phase_ms > 0:
            time.sleep(preparing_phase_ms / 1000.0)
        
        return True  # Send initial packet
    
    def periodic_send_loop(self, wto, packet_count=1, send_duration_seconds=0):
        """Keep sending packets at regular intervals.
        
        First packet(s) sent after wto seconds, then continues every wto seconds.
        Stops sending after send_duration_seconds if specified (then monitors connection).
        
        Args:
            wto: Wait timeout - interval in seconds between sends
            packet_count: Number of packets to send each time (default: 1)
            send_duration_seconds: Duration to send packets (0 for unlimited)
        """
        self.send_start_time = time.time()
        
        while True:
            try:
                time.sleep(wto)
                
                # Check if we've exceeded send duration
                if send_duration_seconds > 0:
                    elapsed_send_time = time.time() - self.send_start_time
                    if elapsed_send_time >= send_duration_seconds:
                        # Send duration expired - switch to monitoring mode
                        self.monitor_connection()
                        return
                
                self.send_packets(packet_count)
            except (socket.error, BrokenPipeError, ConnectionResetError) as e:
                raise ConnectionResetError(f"Failed to send: {e}")
            except socket.timeout:
                continue
    
    def check_fin(self):
        """Check if server sent FIN (graceful close)."""
        global connections_closed_by_server
        
        try:
            data = self.socket.recv(1024)
            if not data:
                # Empty data means server sent FIN
                if self.fin_received_time is None:
                    self.fin_received_time = time.time()
                    if not self.server_closed_counted:
                        with lock:
                            connections_closed_by_server += 1
                        self.server_closed_counted = True
                return True  # FIN received
            return False
        except socket.timeout:
            return False  # No FIN yet, timeout is normal
        except (socket.error, OSError) as e:
            # Actual connection error (RST or other)
            if self.fin_received_time:
                raise ConnectionResetError(f"Actual closure after FIN: {e}")
            else:
                if not self.server_closed_counted:
                    with lock:
                        connections_closed_by_server += 1
                    self.server_closed_counted = True
                raise ConnectionResetError(f"Server closed connection: {e}")
    
    def monitor_connection(self):
        """Keep connection open and monitor for server-initiated closure."""
        while True:
            self.check_fin()
    
    def close(self):
        """Close the socket and update stats."""
        global connections_open, connections_closed
        
        if self.socket:
            self.socket.close()
        
        with lock:
            connections_open -= 1
            connections_closed += 1
    
    def _elapsed(self):
        """Get elapsed time since connection opened."""
        return time.time() - self.connection_start_time
    
    def _log(self, message):
        """Print log message."""
        print(message)
