# RTSP Testbed

This repository contains the RTSP test runner, executed test data, launch scripts, and analysis code used to study RTSP behavior and slow DoS scenarios against two camera testbeds.

The supported camera profiles are:

- `bosch`: Bosch camera for the professional industrial scenario.
- `reolink`: Reolink camera for the general-purpose scenario.

These tests must be ran against cameras and networks personally own or explicitly authorized to test.

## Repository Layout

```text
rtsp_test/
  test_runner/          Reusable Python RTSP runner, client, and scenarios
  test_runs/
    bosch/              Bosch executed runs, numbered 1-12
    reolink/            Reolink executed runs, numbered 1-12 plus MacBook
  analysis/
    plots/              Plotting scripts and curated plot inputs/outputs
  requirements.txt      Python dependencies
```

Each camera folder under `rtsp_test/test_runs/` also contains a `test_statistics/` folder for post-processing scripts and computed statistics.

## Setup

From the repository root:

```bash
cd rtsp_test
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Some tests and analysis scripts also need system tools:

- `tcpdump` for packet capture during launch scripts or runner-level captures.
- `tshark` for scripts that analyze packet captures.

## Camera Configuration

Camera settings are loaded from `rtsp_test/.env`. The code uses profile-specific environment variables, so scripts can select a camera without hardcoding IP addresses, credentials, or RTSP paths.

Known profile prefixes:

- `BOSCH_RTSP_*` for the Bosch camera.
- `REOLINK_RTSP_*` for the Reolink camera.

Common keys are:

```text
<PROFILE>_RTSP_SERVER
<PROFILE>_RTSP_SOURCE_IP
<PROFILE>_RTSP_PORT
<PROFILE>_RTSP_PATH
<PROFILE>_RTSP_USER
<PROFILE>_RTSP_PASSWORD
<PROFILE>_RTSP_TCPDUMP_INTERFACE
```

To add another camera later, add a new uppercase prefix group in `.env`, then run the test runner with `--camera-profile <name>` or update a launch script to call `load_camera_env "<name>"`.

## Running Tests

The reusable runner is `rtsp_test/test_runner/run_tests.py`. See README.md inside `test_runner` folder to get more informations.

## Launch Scripts

Historical and repeatable experiment launchers live inside the executed run folders, for example:

```bash
cd rtsp_test/test_runs/bosch/12/1_find-server-timeout
mkdir -p output
bash launch_test.sh
```

The launch scripts write fixed filenames under their local `output/` folder, such as `capture.pcap`, `tcpdump_output.txt`, and `run_tests_output.txt`. To preserve previous captures, create a new run folder or copy the launcher before running it.

## Analysis and Plots

General plot code and curated plot data live in `rtsp_test/analysis/plots/`.

## Development Notes

- Install Python packages from `rtsp_test/requirements.txt`.
- Keep camera-specific values in `.env` and pass `--camera-profile` instead of hardcoding them in scripts.
- Treat existing run folders as historical data unless intentionally regenerating them.
- For new experiments, create a new numbered run folder under the correct camera profile.

