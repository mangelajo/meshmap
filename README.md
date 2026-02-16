# meshmap

A tool for scanning and mapping [meshcore](https://github.com/ripplebiz/MeshCore) radio networks. It discovers nearby nodes, logs in to each reachable repeater to enumerate its neighbours, and builds a graph of the network — including GPS coordinates where available.

## Install

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/).

```sh
# Install uv (if not already installed)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Clone and install
git clone https://github.com/mangelajo/meshmap
cd meshmap
uv sync
```

The `meshmap` command is then available via `uv run meshmap`.

## Usage

All commands require `-p` to specify the serial port of your connected device.

```
meshmap -p PORT [OPTIONS] COMMAND
```

**Global options** (apply to all commands):

| Flag | Description |
|------|-------------|
| `-p, --serial-port` | Serial port (e.g. `/dev/ttyUSB0`, `COM3`) |
| `--sniff` | Print decoded RF packets in real time |
| `--sniff-key PATH` | Private key file for decryption (repeatable) |
| `-d, --debug` | Low-level meshcore debug output |

## Commands

### `explore` — map the network graph

The main command. Discovers 0-hop repeaters, then recursively logs in to each one to fetch its neighbour list, building a full network graph. Saves to a JSON file after each node so it can be paused and resumed.

```sh
# First scan
uv run meshmap -p /dev/ttyUSB0 explore

# Resume a previous scan, open live visualisation in browser
uv run meshmap -p /dev/ttyUSB0 explore --resume --serve

# Re-visit already-explored nodes to refresh SNR data
uv run meshmap -p /dev/ttyUSB0 explore --resume --refresh

# Retry nodes that failed on the last run
uv run meshmap -p /dev/ttyUSB0 explore --resume --retry

# Limit exploration to 3 hops, save to a custom file
uv run meshmap -p /dev/ttyUSB0 explore --depth 3 -o my-network.json

# Full run with live packet sniffing and web visualisation
uv run meshmap -p /dev/ttyUSB0 --sniff --sniff-key mykey.txt explore --serve --resume
```

The web visualisation (`--serve`) is available at `http://localhost:8080` and auto-refreshes every 3 seconds while the scan runs.

| Option | Default | Description |
|--------|---------|-------------|
| `-o, --output` | `meshmap-graph.json` | Output file |
| `--resume` | off | Load existing graph, skip already-visited nodes |
| `--refresh` | off | Re-queue already-visited nodes (oldest first) |
| `--retry` | off | Re-queue nodes whose last visit failed |
| `--serve` | off | Start web visualisation server |
| `--port` | `8080` | Web server port |
| `--depth` | `5` | Max BFS hop depth |
| `-w, --wait-time` | `10.0` | Seconds to wait for 0-hop discovery responses |

### `discover-repeaters` — list nearby repeaters

```sh
uv run meshmap -p /dev/ttyUSB0 discover-repeaters
```

### `get-neighbours` — inspect a single repeater

Log in to one repeater and print its neighbour list.

```sh
uv run meshmap -p /dev/ttyUSB0 get-neighbours
```

### `sniff` — decode RF packets

Listen and decode raw RF traffic for a given duration.

```sh
uv run meshmap -p /dev/ttyUSB0 sniff 30
uv run meshmap -p /dev/ttyUSB0 sniff 60 --key mykey.txt
```

### `contacts` — list known contacts

```sh
uv run meshmap -p /dev/ttyUSB0 contacts
```

### `scan` — quick 0-hop node scan

```sh
uv run meshmap -p /dev/ttyUSB0 scan
```

## Graph file format

The graph is saved as JSON and can be loaded by external tools:

```json
{
  "version": 1,
  "last_updated": "2026-02-17T12:00:00+00:00",
  "nodes": {
    "<pubkey>": {
      "public_key": "...", "name": "My Repeater",
      "node_type": "repeater", "lat": 40.4, "lon": -3.7,
      "depth": 1, "last_visited": "...", "visit_failed": false
    }
  },
  "edges": [
    { "node_a": "...", "node_b": "...", "snr_a_hears_b": 12.5, "snr_b_hears_a": 9.0, "last_seen": "..." }
  ]
}
```
