#!/usr/bin/env bash
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RTSP_TEST_DIR="${SCRIPT_DIR}"
while [ "${RTSP_TEST_DIR}" != "/" ] && [ ! -f "${RTSP_TEST_DIR}/test_runner/run_tests.py" ]; do
    RTSP_TEST_DIR="$(dirname "${RTSP_TEST_DIR}")"
done

if [ ! -f "${RTSP_TEST_DIR}/test_runner/run_tests.py" ]; then
    echo "[!] Could not locate rtsp_test/test_runner/run_tests.py from ${SCRIPT_DIR}" >&2
    exit 1
fi

cd "${SCRIPT_DIR}"


source "${RTSP_TEST_DIR}/test_runner/camera_env.sh"
load_camera_env "reolink"


TARGET_IP="${RTSP_SERVER}"
TCPDUMP_INTERFACE="${RTSP_TCPDUMP_INTERFACE:-en10}"
DURATION=5200
ATTEMPTED_CONNECTIONS=1016

PCAP_FILE="output/capture.pcap"
TCPDUMP_OUT="output/tcpdump_output.txt"
TCPDUMP_ERR="output/tcpdump_output.err"
TEST_OUT="output/run_tests_output.txt"
TEST_ERR="output/run_tests_output.err"

echo "[+] Starting tcpdump for traffic to/from ${TARGET_IP}"
tcpdump -i "${TCPDUMP_INTERFACE}" -s 0 -U host "${TARGET_IP}" and \(tcp or udp or icmp\) -w "${PCAP_FILE}" > "${TCPDUMP_OUT}" 2> "${TCPDUMP_ERR}" &
PID_DUMP=$!

# Give tcpdump time to initialize before starting the burst.
sleep 1

echo "[+] Starting attack test"
python3 "${RTSP_TEST_DIR}/test_runner/run_tests.py" \
    --type rtsp \
    --scenario random_ports \
    --num "${ATTEMPTED_CONNECTIONS}" \
    --wto 60 \
    --delay 5 \
    > "${TEST_OUT}" 2> "${TEST_ERR}" &
PID_ATTACK=$!

echo "[+] Running for ${DURATION} seconds"
sleep "${DURATION}"

echo "[+] Stopping tcpdump"
kill -2 "${PID_DUMP}" 2>/dev/null || true
sleep 1

echo "[+] Stopping attack test"
kill "${PID_ATTACK}" 2>/dev/null || true
sleep 2


# If either process is still alive, force-kill it.
kill -0 "${PID_DUMP}" 2>/dev/null && kill -9 "${PID_DUMP}" 2>/dev/null || true
kill -0 "${PID_ATTACK}" 2>/dev/null && kill -9 "${PID_ATTACK}" 2>/dev/null || true

echo "[+] Done"
echo "[+] Files created:"
echo "    ${PCAP_FILE}"
echo "    ${TCPDUMP_OUT}"
echo "    ${TCPDUMP_ERR}"
echo "    ${TEST_OUT}"
echo "    ${TEST_ERR}"
