"""RTSP scenarios for teardown and session ownership behavior."""

import select
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


def _monitor_stream_with_play_loop(
    client,
    duration,
    wto,
    play_time=None,
    use_rtp_sockets=True,
    continue_on_play_error=False,
    play_error_label=None,
    next_play_time=None,
):
    """
    Monitor the stream while sending PLAY every `wto` seconds.
    """
    if play_time is None:
        play_time = time.time()

    start_time = time.time()

    if next_play_time is None:
        next_play_time = play_time + wto

    try:
        while duration <= 0 or time.time() - start_time < duration:
            current_time = time.time()

            if current_time >= next_play_time:
                try:
                    client.send_play()
                except Exception as exc:
                    if not continue_on_play_error:
                        raise
                    if play_error_label:
                        print(f"{play_error_label}: PLAY failed, continuing loop: {exc}")

                next_play_time = current_time + wto

            if use_rtp_sockets and client.rtp_socket:
                readable, _, _ = select.select([client.rtp_socket], [], [], 0)
                if readable:
                    client.rtp_socket.recvfrom(4096)

            sleep_time = 0.1

            if wto > 0:
                sleep_time = min(sleep_time, max(0.0, next_play_time - time.time()))

            if duration > 0:
                remaining_time = duration - (time.time() - start_time)
                if remaining_time <= 0:
                    break
                sleep_time = min(sleep_time, remaining_time)

            time.sleep(max(0.01, sleep_time))

    except KeyboardInterrupt:
        pass

    return next_play_time


def scenario_teardown_and_reuse_connection(client_id, server, port, path, user, password, timeout, duration, wto=30):
    """
    TEARDOWN and REUSE CONNECTION scenario - opens connection, sends TEARDOWN, then reuses the same TCP connection.
    Flow: 
      Session 1: OPTIONS → DESCRIBE → SETUP → TEARDOWN
      Session 2 (on same connection): OPTIONS → DESCRIBE → SETUP → PLAY → TEARDOWN
    
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
        client.connect()
        client.setup_udp_sockets()
        
        # ===== SESSION 1: SETUP then immediate TEARDOWN =====
        control_url = options_describe_get_control_url(client)
        
        client.send_setup(control_url, transport_mode="UDP")
        
        client.send_teardown()
        
        # NOTE: TCP connection is still open, but RTSP session is closed
        
        # ===== SESSION 2: Reuse the same connection =====
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


def scenario_cross_client_teardown(
    client_id,
    server,
    port,
    path,
    user,
    password,
    timeout,
    duration,
    wto=30,
    teardown_delay=30,
    post_teardown_observation=10,
):
    """
    CROSS-CLIENT TEARDOWN scenario.

    Flow:
      Connection A:
        OPTIONS -> DESCRIBE -> SETUP (UDP) -> PLAY, then PLAY every `wto` seconds.
      Wait `teardown_delay` seconds while Connection A keeps sending PLAY.
      Connection B:
        TEARDOWN using Connection A's Session identifier.
      Connection A:
        Keep sending PLAY every `wto` seconds and observe whether the RTP stream stops.

    `duration` is measured from the completion of Connection A's PLAY request.
    Set duration=0 to keep the process alive indefinitely after the test.
    """
    client1 = make_client(
        RTSPClient, client_id, server, port, path, user, password, timeout
    )

    # Client 2 creates a separate TCP control connection only.
    client2 = make_client(
        RTSPClient, client_id + 50, server, port, path, user, password, timeout
    )

    try:
        # ===== CONNECTION A: establish session and start UDP streaming =====
        client1.connect()
        client1.setup_udp_sockets()

        control_url = options_describe_get_control_url(client1)
        client1.send_setup(control_url, transport_mode="UDP")

        session_id_1 = client1.session_id
        if not session_id_1:
            raise RuntimeError("Connection A did not receive an RTSP Session identifier.")

        client1.send_play()
        play_time = time.time()
        stream_start_time = time.monotonic()

        print(
            f"Connection A streaming started. "
            f"Waiting {teardown_delay} seconds before Connection B TEARDOWN."
        )

        # Keep Connection A's RTP stream active before the test with PLAY requests.
        next_play_time = _monitor_stream_with_play_loop(
            client1,
            teardown_delay,
            wto,
            play_time,
            use_rtp_sockets=True,
        )

        # ===== CONNECTION B: attempt to terminate Connection A's session =====
        client2.connect()
        client2.session_id = session_id_1

        print("Connection B sending TEARDOWN using Connection A's Session identifier.")

        try:
            client2.send_teardown()
            print("Connection B TEARDOWN sent.")
        except Exception as exc:
            print(f"Connection B TEARDOWN failed: {exc}")

        # ===== CONNECTION A: observe the expected RTP interruption =====
        print(
            f"Observing Connection A for {post_teardown_observation} seconds "
            "after the TEARDOWN."
        )

        try:
            next_play_time = _monitor_stream_with_play_loop(
                client1,
                post_teardown_observation,
                wto,
                time.time(),
                use_rtp_sockets=True,
                continue_on_play_error=True,
                play_error_label="Connection A after TEARDOWN",
                next_play_time=next_play_time,
            )
        except Exception as exc:
            # A timeout or stream interruption is expected if TEARDOWN succeeded.
            print(f"Connection A stream stopped or became unavailable: {exc}")

        # ===== Keep the process alive for the requested total duration =====
        if duration > 0:
            elapsed = time.monotonic() - stream_start_time
            remaining_time = max(0, duration - elapsed)

            print(
                f"Elapsed time since PLAY: {elapsed:.1f} s. "
                f"Keeping the scenario alive for {remaining_time:.1f} s."
            )

            next_play_time = _monitor_stream_with_play_loop(
                client1,
                remaining_time,
                wto,
                time.time(),
                use_rtp_sockets=True,
                continue_on_play_error=True,
                play_error_label="Connection A after TEARDOWN",
                next_play_time=next_play_time,
            )

        else:
            print("Scenario remains active indefinitely. Press Ctrl+C to stop.")

            _monitor_stream_with_play_loop(
                client1,
                0,
                wto,
                time.time(),
                use_rtp_sockets=True,
                continue_on_play_error=True,
                play_error_label="Connection A after TEARDOWN",
                next_play_time=next_play_time,
            )

    except KeyboardInterrupt:
        print("Scenario interrupted by user.")

    except Exception as exc:
        print(f"Scenario failed unexpectedly: {exc}")

    finally:
        # Connection A's RTSP session may already have been terminated by
        # Connection B, so no additional TEARDOWN is required here.
        try:
            close_client(client2)
        except Exception as exc:
            print(f"Failed to close Connection B: {exc}")

        try:
            close_client(client1)
        except Exception as exc:
            print(f"Failed to close Connection A: {exc}")
