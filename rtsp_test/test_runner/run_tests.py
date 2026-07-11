"""
Unified RTSP Test Suite

Single entry point for running all RTSP test scenarios and connection tests.
Supports:
  - RTSP protocol tests with various scenarios (legitimate, pause, pause_twice, pause_loop, incomplete_get_parameter, random_ports)
  - Low-level connection tests (raw bytes, OPTIONS requests)

Usage:
    # RTSP legitimate stream test with 10 concurrent connections
    python3 test_runner/run_tests.py --type rtsp --scenario legitimate --num 10 --delay 1 --duration 30
    
    # RTSP pause test with 64 connections
    python3 test_runner/run_tests.py --type rtsp --scenario pause --num 64 --delay 5 --duration 30
    
    # RTSP pause loop test
    python3 test_runner/run_tests.py --type rtsp --scenario pause_loop --num 10 --delay 5 --duration 120
    
    # RTSP incomplete GET_PARAMETER test
    python3 test_runner/run_tests.py --type rtsp --scenario incomplete_get_parameter --num 10 --duration 30
    
    # RTSP random ports test
    python3 test_runner/run_tests.py --type rtsp --scenario random_ports --num 10 --duration 30
    
    # Low-level raw bytes test (one byte per interval)
    python3 test_runner/run_tests.py --type raw_bytes --num 20 --preparing-phase 0 --send-mode periodic --wto 1
    
    # Low-level OPTIONS request test
    python3 test_runner/run_tests.py --type options --num 20 --preparing-phase 0 --send-mode periodic --wto 1
"""

import argparse
import os
import signal
import subprocess
import threading
import time
import sys
from contextlib import contextmanager
from pathlib import Path
from dotenv import load_dotenv

import connection_handler as connection_handler
from connection_handler import ConnectionHandler
import scenarios as scenarios

# Load environment variables from rtsp_test/.env regardless of the current working directory.
RTSP_TEST_DIR = Path(__file__).resolve().parents[1]
load_dotenv(RTSP_TEST_DIR / ".env")

# Track program start time for elapsed time calculations
program_start_time = None
TCPDUMP_CAPTURE_FILE = "capture.pcap"
TCPDUMP_STARTUP_DELAY = 1


def camera_profile_prefix(profile):
    """Return the environment variable prefix for a camera profile name."""
    if not profile:
        return ""
    return "".join(char if char.isalnum() else "_" for char in profile.strip().upper())


def get_camera_env(profile, key, default=None):
    """Read a profile-specific RTSP setting, falling back to the generic key."""
    prefix = camera_profile_prefix(profile)
    if prefix:
        value = os.getenv(f"{prefix}_{key}")
        if value is not None:
            return value
    return os.getenv(key, default)


def get_camera_config(profile):
    """Build the camera configuration selected by the active profile."""
    return {
        "server": get_camera_env(profile, "RTSP_SERVER"),
        "source_ip": get_camera_env(profile, "RTSP_SOURCE_IP"),
        "port": get_camera_env(profile, "RTSP_PORT", "554"),
        "path": get_camera_env(profile, "RTSP_PATH", "rtsp_tunnel"),
        "user": get_camera_env(profile, "RTSP_USER"),
        "password": get_camera_env(profile, "RTSP_PASSWORD"),
    }


def parse_port(value, default=554):
    """Convert a port value from the environment into an integer."""
    if value in (None, ""):
        return default
    try:
        return int(value)
    except ValueError as exc:
        raise ValueError(f"Invalid RTSP port value: {value}") from exc


def apply_camera_defaults(args):
    """Fill missing command-line values from the selected camera profile."""
    config = get_camera_config(args.camera_profile)

    if args.server is None:
        args.server = config["server"]
    if args.server_ip is None:
        args.server_ip = config["server"]
    if args.port is None:
        args.port = parse_port(config["port"])
    if args.server_port is None:
        args.server_port = args.port
    if args.path is None:
        args.path = config["path"]
    if args.user is None:
        args.user = config["user"]
    if args.password is None:
        args.password = config["password"]


# ============================================================================
# RTSP Scenario Tests
# ============================================================================

def rtsp_worker(scenario_func, client_id, server, port, path, user, password, timeout, duration, **kwargs):
    """Worker thread function for RTSP scenario tests."""
    try:
        scenario_func(client_id, server, port, path, user, password, timeout, duration, **kwargs)
    except Exception as e:
        pass


def run_rtsp_test(args):
    """Run RTSP protocol test with specified scenario."""
    scenario_func = scenarios.get_scenario(args.scenario)
    if not scenario_func:
        return False
    
    if args.duration:
        pass
    
    # Build kwargs for scenario function
    scenario_kwargs = {}
    if args.scenario not in ["pause_loop", "pause_no_keepalive"]:
        scenario_kwargs['wto'] = args.wto
    
    # Create and start threads for each client
    threads = []
    for i in range(args.num):
        thread = threading.Thread(
            target=rtsp_worker,
            args=(scenario_func, i, args.server, args.port, args.path, 
                  args.user, args.password, args.timeout, args.duration),
            kwargs=scenario_kwargs,
            daemon=False
        )
        thread.start()
        threads.append(thread)
        
        if i < args.num - 1:
            time.sleep(args.delay)
    
    # Wait for all threads to complete
    for i, thread in enumerate(threads):
        thread.join()
    
    return True


# ============================================================================
# Low-level Connection Tests
# ============================================================================

def raw_bytes_worker(server_ip, server_port, send_mode, wto, preparing_phase_ms, packet_count, 
                     send_duration_seconds, keepalive_after_seconds):
    """Worker thread for raw bytes connection test."""
    handler = ConnectionHandler(server_ip, server_port, packet_data=b"a", 
                               send_duration_seconds=send_duration_seconds,
                               keepalive_after_seconds=keepalive_after_seconds)
    
    try:
        handler.connect()
        
        should_send_initial = handler.wait_preparing_phase(preparing_phase_ms)
        if should_send_initial:
            handler.send_packets(packet_count)
        
        if send_mode == "periodic":
            handler.periodic_send_loop(wto, packet_count, send_duration_seconds)
        elif send_mode == "none":
            handler.monitor_connection()
    
    except Exception as e:
        error_type = type(e).__name__
        pass
    finally:
        handler.close()


def options_request_worker(server_ip, server_port, send_mode, wto, preparing_phase_ms, packet_count,
                          send_duration_seconds, keepalive_after_seconds):
    """Worker thread for OPTIONS request connection test."""
    # Dynamically build OPTIONS request with proper server IP
    packet_data = f"OPTIONS rtsp://{server_ip}:{server_port}/ RTSP/1.1\r\nCSeq: 1\r\nUser-Agent: RTSPTestClient\r\n\r\n".encode()
    
    handler = ConnectionHandler(server_ip, server_port, packet_data=packet_data,
                               send_duration_seconds=send_duration_seconds,
                               keepalive_after_seconds=keepalive_after_seconds)
    
    try:
        handler.connect()
        
        should_send_initial = handler.wait_preparing_phase(preparing_phase_ms)
        if should_send_initial:
            handler.send_packets(packet_count)
        
        if send_mode == "periodic":
            handler.periodic_send_loop(wto, packet_count, send_duration_seconds)
        elif send_mode == "none":
            handler.monitor_connection()
    
    except Exception as e:
        error_type = type(e).__name__
        pass
    finally:
        handler.close()


def run_connection_test(args, test_type):
    """Run low-level connection test (raw bytes or OPTIONS requests)."""
    if test_type == "raw_bytes":
        worker_func = raw_bytes_worker
        test_name = "Raw Bytes"
    else:  # options
        worker_func = options_request_worker
        test_name = "OPTIONS Requests"
    
    if args.send_mode == "periodic":
        if args.send_duration > 0:
            pass
    else:
        pass
    
    if args.preparing_phase >= 0:
        pass
    
    if args.keepalive_after > 0:
        pass
    
    # Create and start worker threads
    threads = []
    for _ in range(args.num):
        t = threading.Thread(
            target=worker_func,
            args=(
                args.server_ip,
                args.server_port,
                args.send_mode,
                args.wto,
                args.preparing_phase * 1000,
                args.packet_count,
                args.send_duration * 60,
                args.keepalive_after
            ),
            daemon=True
        )
        t.start()
        threads.append(t)
        if args.delay > 0:
            time.sleep(args.delay)
    
    # Wait for all connections to establish
    time.sleep(5)
    
    # Print statistics
    print_stats(5)



def print_stats(stats_interval=1):
    """Print connection statistics at regular intervals."""
    while True:
        with connection_handler.lock:
            open_count = connection_handler.connections_open
            closed_by_server_count = connection_handler.connections_closed_by_server
            packets_sent = connection_handler.total_bytes_sent
            total_connections = connection_handler.total_connections_created
        
        elapsed_time = time.time() - program_start_time
        packets_per_connection = packets_sent / total_connections if total_connections > 0 else 0
        
        # print(f"[{elapsed_time:.0f}s] Connections open: {open_count}")
        # print(f"[{elapsed_time:.0f}s] Connections closed by server: {closed_by_server_count}")
        # print(f"[{elapsed_time:.0f}s] Packets per connection: {int(packets_per_connection)}")
        # print("-" * 40)
        time.sleep(stats_interval)


# ============================================================================
# Optional tcpdump Capture
# ============================================================================

def get_tcpdump_target(args):
    """Return the target host for the tcpdump filter."""
    if args.type == "rtsp":
        return args.server
    return args.server_ip


def start_tcpdump(args):
    """Start tcpdump when requested and return its process handle."""
    if not args.tcpdump:
        return None

    target = get_tcpdump_target(args)
    capture_path = os.path.abspath(TCPDUMP_CAPTURE_FILE)
    command = [
        "tcpdump",
        "-i",
        args.tcpdump_interface,
        "-s",
        "0",
        "-U",
        "-w",
        capture_path,
        "host",
        target,
        "and",
        "(",
        "tcp",
        "or",
        "udp",
        ")",
    ]

    print(f"[+] Starting tcpdump on {args.tcpdump_interface} for traffic to/from {target}")
    print(f"[+] Writing packet capture to {capture_path}")

    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("tcpdump executable not found") from exc

    time.sleep(TCPDUMP_STARTUP_DELAY)
    if process.poll() is not None:
        _, stderr = process.communicate()
        details = stderr.strip() if stderr else "tcpdump exited immediately"
        raise RuntimeError(f"tcpdump failed to start: {details}")

    return process


def stop_tcpdump(process):
    """Stop tcpdump gracefully so the pcap is finalized."""
    if not process:
        return

    print("[+] Stopping tcpdump")
    _, stderr = "", ""
    if process.poll() is None:
        process.send_signal(signal.SIGINT)
        try:
            _, stderr = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            _, stderr = process.communicate()
    else:
        _, stderr = process.communicate()
    if stderr:
        print(stderr.strip())
    print(f"[+] Packet capture saved to {os.path.abspath(TCPDUMP_CAPTURE_FILE)}")


@contextmanager
def optional_tcpdump_capture(args):
    """Run the enclosed test while tcpdump is active, when enabled."""
    process = start_tcpdump(args)
    try:
        yield
    finally:
        stop_tcpdump(process)


# ============================================================================
# Argument Parsing
# ============================================================================

def parse_arguments():
    """Parse and return command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Unified RTSP Test Suite - Run RTSP protocol tests and low-level connection tests",
        epilog="Examples:\n"
               "  python3 test_runner/run_tests.py --type rtsp --scenario legitimate --num 10\n"
               "  python3 test_runner/run_tests.py --type rtsp --scenario pause_loop --num 10 --duration 120\n"
               "  python3 test_runner/run_tests.py --type raw_bytes --num 20 --send-mode periodic --wto 1",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        "--type",
        choices=["rtsp", "raw_bytes", "options"],
        required=True,
        help="Test type: 'rtsp' for protocol tests, 'raw_bytes' or 'options' for low-level connection tests"
    )
    
    parser.add_argument(
        "--scenario",
        choices=scenarios.get_available_scenarios(),
        help="RTSP scenario (only used with --type rtsp)"
    )
    
    parser.add_argument(
        "--num",
        type=int,
        required=True,
        help="Number of connections to open"
    )
    
    parser.add_argument(
        "--camera-profile",
        default=os.getenv("RTSP_CAMERA_PROFILE"),
        help="Camera profile to load from .env, such as bosch or reolink"
    )

    # RTSP test arguments
    parser.add_argument(
        "--server",
        default=None,
        help="RTSP server IP address (default: selected camera profile)"
    )
    
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="Server port (default: selected camera profile or 554)"
    )
    
    parser.add_argument(
        "--path",
        default=None,
        help="RTSP resource path (default: selected camera profile or rtsp_tunnel)"
    )
    
    parser.add_argument(
        "--user",
        default=None,
        help="Username for authentication (default: selected camera profile)"
    )
    
    parser.add_argument(
        "--pass",
        dest="password",
        default=None,
        help="Password for authentication (default: selected camera profile)"
    )
    
    parser.add_argument(
        "--timeout",
        type=int,
        default=300,
        help="Socket timeout in seconds (default: 300)"
    )
    
    parser.add_argument(
        "--duration",
        type=int,
        default=0,
        help="Stream duration in seconds (0 for indefinite, default: 0)"
    )
    
    parser.add_argument(
        "--delay",
        type=float,
        default=5,
        help="Delay between opening connections in seconds (default: 5)"
    )
    
    parser.add_argument(
        "--wto",
        type=float,
        default=50,
        help="Wait timeout for GET_PARAMETER requests in seconds (RTSP tests only, default: 50)"
    )
    
    # Low-level connection test arguments
    parser.add_argument(
        "--send-mode",
        choices=["periodic", "none"],
        default="periodic",
        help="Send mode (low-level tests only): periodic or none (default: periodic)"
    )
    
    parser.add_argument(
        "--preparing-phase",
        type=float,
        default=-1,
        help="Seconds to wait before sending initial packet (0 for immediate, -1 to skip, default: -1)"
    )
    
    parser.add_argument(
        "--packet-count",
        type=int,
        default=1,
        help="Number of packets to send each time (default: 1)"
    )
    
    parser.add_argument(
        "--send-duration",
        type=float,
        default=0,
        help="Duration in minutes to send data (0 for unlimited, default: 0)"
    )
    
    parser.add_argument(
        "--keepalive-after",
        type=float,
        default=0,
        help="Enable TCP keepalive after this many seconds (0 to disable, default: 0)"
    )
    
    parser.add_argument(
        "--server-ip",
        default=None,
        help="Server IP address for low-level tests (default: selected camera profile)"
    )
    
    parser.add_argument(
        "--server-port",
        type=int,
        default=None,
        help="Server port for low-level tests (default: selected camera profile or 554)"
    )

    parser.add_argument(
        "--tcpdump",
        default=None,
        metavar="INTERFACE",
        help=f"Start tcpdump on INTERFACE before the test and write {TCPDUMP_CAPTURE_FILE}"
    )
    
    args = parser.parse_args()
    apply_camera_defaults(args)
    if args.tcpdump:
        args.tcpdump_interface = args.tcpdump

    return args


def validate_arguments(args):
    """Validate command-line arguments."""
    if args.type == "rtsp":
        if not args.scenario:
            raise ValueError("--scenario is required for RTSP tests")
        if args.scenario not in scenarios.get_available_scenarios():
            raise ValueError(f"Invalid scenario: {args.scenario}")
    
    if args.send_mode == "periodic" and args.wto <= 0:
        raise ValueError("--wto must be positive for periodic send mode")
    
    if args.packet_count < 1:
        raise ValueError("--packet-count must be at least 1")

    target_server = args.server if args.type == "rtsp" else args.server_ip
    if not target_server:
        raise ValueError("A target server is required. Set --server/--server-ip or select a camera profile in .env.")

    if args.tcpdump:
        if not args.tcpdump_interface:
            raise ValueError("--tcpdump requires a network interface, for example: --tcpdump en0")
        if not get_tcpdump_target(args):
            raise ValueError("--tcpdump requires a target server (--server/--server-ip or selected camera profile)")


# ============================================================================
# Main Entry Point
# ============================================================================

def main():
    """Main entry point."""
    global program_start_time
    program_start_time = time.time()
    
    args = parse_arguments()
    
    try:
        validate_arguments(args)
    except ValueError as e:
        # print(f"Error: {e}")
        pass
        return 1
    
    try:
        with optional_tcpdump_capture(args):
            # Route to appropriate test type
            if args.type == "rtsp":
                success = run_rtsp_test(args)
                return 0 if success else 1
            else:
                run_connection_test(args, args.type)
                return 0
    except KeyboardInterrupt:
        return 130
    except RuntimeError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
