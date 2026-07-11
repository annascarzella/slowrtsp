"""RTSP scenarios that intentionally use invalid CSeq behavior."""

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


class RTSPClientCSeqAlways1(RTSPClient):
    """RTSPClient that always sends CSeq: 1 (wrong behavior)."""
    def _get_cseq(self):
        """Always return 1 instead of incrementing."""
        return 1


class RTSPClientCSeqSkip(RTSPClient):
    """RTSPClient that skips CSeq values (1, 4, 7, 10... - skipping 2, 3, 5, 6, etc.)."""
    def _get_cseq(self):
        """Return: 1, 4, 7, 10, 13... (skipping 2, 3, 5, 6, 8, 9, etc.)."""
        self.cseq += 1
        # On first call return 1, then keep adding 3 each time
        if self.cseq == 1:
            return 1
        # For subsequent calls, if cseq would be 2 or 3, jump to 4
        # Actually, let's use a pattern: 1, 4, 7, 10...
        # So we increment by 3 each time after the first
        return (self.cseq - 1) * 3 + 1


class RTSPClientCSeqDecrement(RTSPClient):
    """RTSPClient that decrements CSeq instead of incrementing."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.cseq_start = 10  # Start at 10 and count down
    
    def _get_cseq(self):
        """Decrement CSeq: 10, 9, 8, 7..."""
        value = self.cseq_start
        self.cseq_start -= 1
        return value


def scenario_wrong_cseq_always_1(client_id, server, port, path, user, password, timeout, duration, wto=30):
    """
    WRONG CSEQ (Always 1) scenario - sends every request with CSeq: 1.
    Flow: OPTIONS → DESCRIBE → SETUP → PLAY → TEARDOWN (all with CSeq: 1)
    
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
    client = make_client(RTSPClientCSeqAlways1, client_id, server, port, path, user, password, timeout)
    
    try:
        client.connect()
        client.setup_udp_sockets()
        
        control_url = options_describe_get_control_url(client)
        
        client.send_setup(control_url, transport_mode="UDP")
        
        play_time = time.time()
        client.send_play()
        
        monitor_stream(client, duration, wto, play_time, use_rtp_sockets=True)
        client.send_teardown()
        
    
    except Exception as e:
        print(f"Scenario failed: {e}")
  
    
    finally:
        close_client(client)


def scenario_wrong_cseq_skip(client_id, server, port, path, user, password, timeout, duration, wto=30):
    """
    WRONG CSEQ (Skip values) scenario - sends CSeq: 1, 4, 7, 10... (skipping 2, 3, 5, 6, etc.).
    Flow: OPTIONS → DESCRIBE → SETUP → PLAY → TEARDOWN (with skipped CSeq values)
    
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
    client = make_client(RTSPClientCSeqSkip, client_id, server, port, path, user, password, timeout)
    
    try:
        client.connect()
        client.setup_udp_sockets()
        
        control_url = options_describe_get_control_url(client)
        
        client.send_setup(control_url, transport_mode="UDP")
        
        play_time = time.time()
        client.send_play()
        
        monitor_stream(client, duration, wto, play_time, use_rtp_sockets=True)
        client.send_teardown()
        
    
    except Exception as e:
        pass
  
    
    finally:
        close_client(client)


def scenario_wrong_cseq_decrement(client_id, server, port, path, user, password, timeout, duration, wto=30):
    """
    WRONG CSEQ (Decrement) scenario - sends CSeq: 10, 9, 8, 7... (decrementing instead of incrementing).
    Flow: OPTIONS → DESCRIBE → SETUP → PLAY → TEARDOWN (with decreasing CSeq)
    
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
    client = make_client(RTSPClientCSeqDecrement, client_id, server, port, path, user, password, timeout)
    
    try:
        client.connect()
        client.setup_udp_sockets()
        
        control_url = options_describe_get_control_url(client)
        
        client.send_setup(control_url, transport_mode="UDP")
        
        play_time = time.time()
        client.send_play()
        
        monitor_stream(client, duration, wto, play_time, use_rtp_sockets=True)
        client.send_teardown()
        
    
    except Exception as e:
        print(f"Scenario failed: {e}")
  
    
    finally:
        close_client(client)
