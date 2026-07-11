#!/usr/bin/env bash

# Shared camera profile loader for launch_test.sh scripts.
# Usage: source this file after RTSP_TEST_DIR is set, then call load_camera_env "bosch" or "reolink".

get_profile_value() {
    local name="$1"
    local fallback="${2-}"

    if [ "${!name+x}" = "x" ]; then
        printf "%s" "${!name}"
    else
        printf "%s" "${fallback}"
    fi
}

load_camera_env() {
    local profile="${1:-${RTSP_CAMERA_PROFILE:-}}"
    local env_file="${RTSP_TEST_DIR}/.env"

    if [ -z "${RTSP_TEST_DIR:-}" ]; then
        echo "[!] RTSP_TEST_DIR is not set before loading camera_env.sh" >&2
        exit 1
    fi

    if [ -f "${env_file}" ]; then
        set -a
        source "${env_file}"
        set +a
    else
        echo "[-] .env file not found at ${env_file}" >&2
        exit 1
    fi

    profile="${profile:-${RTSP_CAMERA_PROFILE:-}}"
    if [ -z "${profile}" ]; then
        echo "[!] Missing camera profile. Set RTSP_CAMERA_PROFILE or pass a profile to load_camera_env." >&2
        exit 1
    fi

    local prefix
    prefix="$(printf "%s" "${profile}" | tr "[:lower:]" "[:upper:]" | tr -c "[:alnum:]_" "_")"

    RTSP_CAMERA_PROFILE="${profile}"
    RTSP_SERVER="$(get_profile_value "${prefix}_RTSP_SERVER" "${RTSP_SERVER:-}")"
    RTSP_SOURCE_IP="$(get_profile_value "${prefix}_RTSP_SOURCE_IP" "${RTSP_SOURCE_IP:-}")"
    RTSP_PORT="$(get_profile_value "${prefix}_RTSP_PORT" "${RTSP_PORT:-554}")"
    RTSP_PATH="$(get_profile_value "${prefix}_RTSP_PATH" "${RTSP_PATH:-rtsp_tunnel}")"
    RTSP_USER="$(get_profile_value "${prefix}_RTSP_USER" "${RTSP_USER:-}")"
    RTSP_PASSWORD="$(get_profile_value "${prefix}_RTSP_PASSWORD" "${RTSP_PASSWORD:-}")"
    RTSP_TCPDUMP_INTERFACE="$(get_profile_value "${prefix}_RTSP_TCPDUMP_INTERFACE" "${RTSP_TCPDUMP_INTERFACE:-}")"

    if [ -z "${RTSP_SERVER}" ]; then
        echo "[!] Missing ${prefix}_RTSP_SERVER in ${env_file}" >&2
        exit 1
    fi

    export RTSP_CAMERA_PROFILE RTSP_SERVER RTSP_SOURCE_IP RTSP_PORT RTSP_PATH RTSP_USER RTSP_PASSWORD RTSP_TCPDUMP_INTERFACE
}
