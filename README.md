```
██╗██████╗ ███████╗██╗      ██████╗ ██╗    ██╗    ███╗   ███╗ ██████╗██████╗ 
██║██╔══██╗██╔════╝██║     ██╔═══██╗██║    ██║    ████╗ ████║██╔════╝██╔══██╗
██║██████╔╝█████╗  ██║     ██║   ██║██║ █╗ ██║    ██╔████╔██║██║     ██████╔╝
██║██╔══██╗██╔══╝  ██║     ██║   ██║██║███╗██║    ██║╚██╔╝██║██║     ██╔═══╝ 
██║██║  ██║██║     ███████╗╚██████╔╝╚███╔███╔╝    ██║ ╚═╝ ██║╚██████╗██║     
╚═╝╚═╝  ╚═╝╚═╝     ╚══════╝ ╚═════╝  ╚══╝╚══╝     ╚═╝     ╚═╝ ╚═════╝╚═╝     
```

> **An MCP server that brings IRFlow Timeline forensic data directly into your LLM conversations.**

---

## What is this?

`mcp-irflow-timeline` is a [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server that bridges **IRFlow Timeline** — a forensic artifact viewer — with any MCP-compatible LLM (Claude, GPT-4o, Gemini, etc.).

When you open logs in IRFlow Timeline (EVTX, MFT, USN Journal, etc.), this server exposes them as callable tools so your AI assistant can query, filter, search, and analyze the data in natural language — no copy-pasting, no manual exports.

---

## Features

- **Live manifest sync** — automatically picks up tabs as you open/close them in IRFlow
- **Read-only SQLite access** — safe, no writes to your forensic data
- **8 built-in tools** for DFIR workflows (see below)
- **Cross-platform** — Windows, macOS, Linux
- **Works with Claude Desktop** via stdio transport

---

## Tools

| Tool | Description |
|---|---|
| `list_sessions` | List all tabs currently loaded in IRFlow Timeline |
| `get_columns` | Return column names + 5 sample values for a tab |
| `get_event_stats` | DFIR-oriented summary: date range, top EventIDs, users, hosts, IPs |
| `query_events` | Filter rows by column values, date range, and limit |
| `search_events` | Full-text search across all columns (FTS5 or LIKE fallback) |
| `run_sql` | Run any read-only `SELECT` directly against a tab's SQLite DB |
| `get_lateral_movement_summary` | RDP/logon analysis: source→target pairs, logon types, failed logons |
| `get_process_execution_summary` | Process execution analysis: parent→child pairs, suspicious cmdlines |

---

## Installation

```bash
git clone https://github.com/L3ndzsec/mcp-irflow-timeline.git
cd mcp-irflow-timeline
npm install
```

---

## Usage

### With Claude Desktop

Add this to your Claude Desktop MCP config (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "irflow": {
      "command": "node",
      "args": ["C:\\path\\to\\mcp-irflow-timeline\\index.js"]
    }
  }
}
```

### Manual (stdio)

```bash
node index.js
```

### Custom manifest path

```bash
IRFLOW_MANIFEST="C:\custom\path\mcp-manifest.json" node index.js
```

---

## Manifest Location

IRFlow Timeline writes a live manifest when tabs are opened. The server reads it automatically:

| Platform | Path |
|---|---|
| Windows | `%APPDATA%\irflow-timeline\mcp-manifest.json` |
| macOS | `~/Library/Application Support/irflow-timeline/mcp-manifest.json` |
| Linux | `~/.config/irflow-timeline/mcp-manifest.json` |

Override with the `IRFLOW_MANIFEST` environment variable.

---

## Supported Artifact Types

- Windows Event Logs (`.evtx`) — Security, System, TerminalServices, WinRM, etc.
- Master File Table (`$MFT`)
- USN Change Journal (`$UsnJrnl`)
- Any other source IRFlow Timeline parses into SQLite

---

## Requirements

- [Node.js](https://nodejs.org/) v18+
- [IRFlow Timeline](https://irflow.io/) with MCP manifest export enabled

---

## License

MIT
