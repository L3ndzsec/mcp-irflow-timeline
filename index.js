/**
 * IRFlow Timeline MCP Server
 *
 * Exposes parsed forensic timeline data to any MCP-compatible LLM (Claude,
 * GPT-4o, Gemini, etc.) as callable tools. Works by reading the live manifest
 * IRFlow writes to userData whenever tabs are opened or closed, then opening
 * each per-tab SQLite database read-only.
 *
 * Manifest location (auto-detected):
 *   Windows : %APPDATA%\IRFlow Timeline\mcp-manifest.json
 *   macOS   : ~/Library/Application Support/IRFlow Timeline/mcp-manifest.json
 *   Linux   : ~/.config/IRFlow Timeline/mcp-manifest.json
 *
 * Override: set IRFLOW_MANIFEST env var to an absolute path.
 *
 * Usage (stdio transport, works with Claude Desktop):
 *   node index.js
 *
 * Claude Desktop config (~/.config/claude/claude_desktop_config.json):
 *   {
 *     "mcpServers": {
 *       "irflow": {
 *         "command": "node",
 *         "args": ["D:\\My Project\\IRFlow-Timeline\\mcp-server\\index.js"]
 *       }
 *     }
 *   }
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import Database from "better-sqlite3";
import fs from "fs";
import os from "os";
import path from "path";

// ── Manifest discovery ────────────────────────────────────────────────────────

function getManifestPath() {
  if (process.env.IRFLOW_MANIFEST) return process.env.IRFLOW_MANIFEST;
  const appName = "irflow-timeline";
  if (process.platform === "win32")
    return path.join(process.env.APPDATA || os.homedir(), appName, "mcp-manifest.json");
  if (process.platform === "darwin")
    return path.join(os.homedir(), "Library", "Application Support", appName, "mcp-manifest.json");
  return path.join(process.env.XDG_CONFIG_HOME || path.join(os.homedir(), ".config"), appName, "mcp-manifest.json");
}

function loadManifest() {
  const p = getManifestPath();
  try {
    return JSON.parse(fs.readFileSync(p, "utf8"));
  } catch {
    return { tabs: [], updatedAt: null };
  }
}

// ── DB helpers ────────────────────────────────────────────────────────────────

const _dbCache = new Map(); // dbPath -> Database instance

function getDb(dbPath) {
  if (_dbCache.has(dbPath)) {
    const cached = _dbCache.get(dbPath);
    if (cached.open) return cached;
    _dbCache.delete(dbPath);
  }
  const db = new Database(dbPath, { readonly: true, fileMustExist: true });
  _dbCache.set(dbPath, db);
  return db;
}

function tabByIdOrName(tabIdOrName) {
  const manifest = loadManifest();
  return manifest.tabs.find(
    (t) => t.tabId === tabIdOrName || t.fileName === tabIdOrName
  ) || null;
}

function requireTab(tabIdOrName) {
  const tab = tabByIdOrName(tabIdOrName);
  if (!tab) throw new Error(`No loaded tab matching "${tabIdOrName}". Use list_sessions to see available tabs.`);
  return tab;
}

// Build a safe SELECT with optional WHERE/LIMIT
function buildSelect(columns, where, limit) {
  const cols = (columns && columns.length) ? columns.map((c) => `"${c}"`).join(", ") : "*";
  let sql = `SELECT ${cols} FROM data`;
  const params = [];
  if (where) { sql += ` WHERE ${where}`; }
  sql += ` LIMIT ${Math.min(Number(limit) || 200, 1000)}`;
  return { sql, params };
}

// ── Tool definitions ──────────────────────────────────────────────────────────

const TOOLS = [
  {
    name: "list_sessions",
    description:
      "List all tabs currently loaded in IRFlow Timeline. Returns tabId, fileName, row count, column names, and detected timestamp columns for each tab.",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "get_columns",
    description:
      "Return the column names and 5 sample values per column for a loaded tab. Use this before querying to understand the schema.",
    inputSchema: {
      type: "object",
      required: ["tab"],
      properties: {
        tab: { type: "string", description: "tabId or fileName from list_sessions" },
      },
    },
  },
  {
    name: "get_event_stats",
    description:
      "Return a DFIR-oriented summary of a loaded tab: row count, date range, top event IDs, top source/target hosts, top users, and top channels. Essential first step for any investigation.",
    inputSchema: {
      type: "object",
      required: ["tab"],
      properties: {
        tab: { type: "string", description: "tabId or fileName from list_sessions" },
        limit: { type: "number", description: "Top-N for each category (default 20)" },
      },
    },
  },
  {
    name: "query_events",
    description:
      "Query the timeline data for a specific tab. Supports column filters (exact match or LIKE), a date range, and a row limit. Returns matching rows as JSON.",
    inputSchema: {
      type: "object",
      required: ["tab"],
      properties: {
        tab: { type: "string", description: "tabId or fileName from list_sessions" },
        filters: {
          type: "object",
          description:
            "Column filters as {columnName: value}. Use % wildcards for LIKE matching (e.g. '%Administrator%').",
        },
        date_from: { type: "string", description: "ISO 8601 start time (inclusive)" },
        date_to: { type: "string", description: "ISO 8601 end time (inclusive)" },
        columns: {
          type: "array",
          items: { type: "string" },
          description: "Specific columns to return (default: all)",
        },
        limit: { type: "number", description: "Max rows to return (default 200, max 1000)" },
      },
    },
  },
  {
    name: "search_events",
    description:
      "Full-text search across all text columns in a tab. Returns matching rows ordered by relevance. Falls back to LIKE search if FTS index is not available.",
    inputSchema: {
      type: "object",
      required: ["tab", "query"],
      properties: {
        tab: { type: "string", description: "tabId or fileName from list_sessions" },
        query: { type: "string", description: "Search term (supports FTS5 syntax: phrase, AND, OR, NOT, prefix*)" },
        limit: { type: "number", description: "Max rows to return (default 100)" },
      },
    },
  },
  {
    name: "run_sql",
    description:
      "Run a read-only SQL SELECT statement directly against a tab's SQLite database. The main table is called 'data'. Use get_columns first to learn column names. Only SELECT statements are allowed.",
    inputSchema: {
      type: "object",
      required: ["tab", "sql"],
      properties: {
        tab: { type: "string", description: "tabId or fileName from list_sessions" },
        sql: { type: "string", description: "SQL SELECT statement (read-only)" },
        limit: { type: "number", description: "Safety cap on rows returned (default 500)" },
      },
    },
  },
  {
    name: "get_lateral_movement_summary",
    description:
      "Summarise lateral movement indicators from a Security/TerminalServices tab: unique source→target pairs, top users, RDP session counts, logon type distribution, and failed logon patterns.",
    inputSchema: {
      type: "object",
      required: ["tab"],
      properties: {
        tab: { type: "string", description: "tabId or fileName from list_sessions" },
      },
    },
  },
  {
    name: "get_process_execution_summary",
    description:
      "Summarise process execution data from a Sysmon/4688 tab: top parent→child process pairs, suspicious command-line patterns, top accounts running processes, and execution timeline.",
    inputSchema: {
      type: "object",
      required: ["tab"],
      properties: {
        tab: { type: "string", description: "tabId or fileName from list_sessions" },
      },
    },
  },
];

// ── Tool handlers ─────────────────────────────────────────────────────────────

function handleListSessions() {
  const manifest = loadManifest();
  if (!manifest.tabs.length)
    return "No tabs are currently loaded in IRFlow Timeline. Open a log file first.";
  return JSON.stringify({
    updatedAt: manifest.updatedAt,
    tabs: manifest.tabs.map((t) => ({
      tabId: t.tabId,
      fileName: t.fileName,
      filePath: t.filePath,
      sourceFormat: t.sourceFormat,
      rowCount: t.rowCount,
      columns: t.headers,
      timestampColumns: t.tsColumns,
    })),
  }, null, 2);
}

function handleGetColumns({ tab }) {
  const t = requireTab(tab);
  const db = getDb(t.dbPath);
  const result = {};
  for (const col of t.headers.slice(0, 40)) {
    try {
      const rows = db.prepare(`SELECT "${col}" FROM data WHERE "${col}" IS NOT NULL LIMIT 5`).all();
      result[col] = rows.map((r) => r[col]);
    } catch { result[col] = []; }
  }
  return JSON.stringify({ tabId: t.tabId, fileName: t.fileName, columns: result }, null, 2);
}

function handleGetEventStats({ tab, limit = 20 }) {
  const t = requireTab(tab);
  const db = getDb(t.dbPath);
  const n = Math.min(Number(limit) || 20, 100);
  const stats = { tabId: t.tabId, fileName: t.fileName, rowCount: t.rowCount };

  // Date range — try timestamp columns
  for (const tsCol of (t.tsColumns || []).slice(0, 1)) {
    try {
      const r = db.prepare(`SELECT MIN("${tsCol}") AS first, MAX("${tsCol}") AS last FROM data`).get();
      if (r?.first) { stats.dateRange = { first: r.first, last: r.last }; break; }
    } catch {}
  }

  // Top values for likely important columns
  const colNames = (t.headers || []).map((h) => h.toLowerCase());
  const tryTop = (candidates, label) => {
    const col = t.headers.find((h) => candidates.some((c) => h.toLowerCase().includes(c)));
    if (!col) return;
    try {
      const rows = db.prepare(`SELECT "${col}" AS val, COUNT(*) AS cnt FROM data WHERE "${col}" IS NOT NULL AND "${col}" != '' GROUP BY "${col}" ORDER BY cnt DESC LIMIT ${n}`).all();
      if (rows.length) stats[label] = rows;
    } catch {}
  };

  tryTop(["eventid", "event_id", "event id", "id"], "topEventIds");
  tryTop(["channel", "source"], "topChannels");
  tryTop(["computername", "computer", "hostname", "host", "workstation"], "topHosts");
  tryTop(["targetusername", "username", "user", "accountname", "account name"], "topUsers");
  tryTop(["ipaddress", "sourceip", "sourceaddress", "ip address", "logonip"], "topSourceIPs");
  tryTop(["logontype"], "topLogonTypes");
  tryTop(["newprocessname", "process", "processname", "image"], "topProcesses");

  return JSON.stringify(stats, null, 2);
}

function handleQueryEvents({ tab, filters = {}, date_from, date_to, columns, limit = 200 }) {
  const t = requireTab(tab);
  const db = getDb(t.dbPath);

  const conditions = [];
  const params = [];

  for (const [col, val] of Object.entries(filters)) {
    if (!t.headers.includes(col)) continue;
    if (String(val).includes("%")) {
      conditions.push(`"${col}" LIKE ?`); params.push(val);
    } else {
      conditions.push(`"${col}" = ?`); params.push(val);
    }
  }

  // Date range — use first timestamp column
  const tsCol = (t.tsColumns || [])[0];
  if (tsCol) {
    if (date_from) { conditions.push(`"${tsCol}" >= ?`); params.push(date_from); }
    if (date_to)   { conditions.push(`"${tsCol}" <= ?`); params.push(date_to); }
  }

  const where = conditions.length ? conditions.join(" AND ") : null;
  const { sql } = buildSelect(columns, where, limit);
  const rows = db.prepare(sql).all(...params);
  return JSON.stringify({ rowCount: rows.length, rows }, null, 2);
}

function handleSearchEvents({ tab, query, limit = 100 }) {
  const t = requireTab(tab);
  const db = getDb(t.dbPath);
  const n = Math.min(Number(limit) || 100, 500);

  // Try FTS5 table first
  try {
    const hasFts = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='fts'").get();
    if (hasFts) {
      const rows = db.prepare(`SELECT data.* FROM data JOIN fts ON data.rowid = fts.rowid WHERE fts MATCH ? ORDER BY rank LIMIT ${n}`).all(query);
      return JSON.stringify({ method: "fts5", rowCount: rows.length, rows }, null, 2);
    }
  } catch {}

  // Fallback: LIKE search across first 10 text columns
  const textCols = t.headers.slice(0, 10);
  const conditions = textCols.map((c) => `"${c}" LIKE ?`).join(" OR ");
  const params = textCols.map(() => `%${query}%`);
  try {
    const rows = db.prepare(`SELECT * FROM data WHERE ${conditions} LIMIT ${n}`).all(...params);
    return JSON.stringify({ method: "like", rowCount: rows.length, rows }, null, 2);
  } catch (err) {
    throw new Error(`Search failed: ${err.message}`);
  }
}

function handleRunSql({ tab, sql, limit = 500 }) {
  const t = requireTab(tab);
  const trimmed = sql.trim().toUpperCase();
  if (!trimmed.startsWith("SELECT") && !trimmed.startsWith("WITH"))
    throw new Error("Only SELECT (and WITH … SELECT) statements are permitted.");
  const db = getDb(t.dbPath);
  const n = Math.min(Number(limit) || 500, 2000);
  const safeSql = /LIMIT\s+\d+/i.test(sql) ? sql : `${sql} LIMIT ${n}`;
  const rows = db.prepare(safeSql).all();
  return JSON.stringify({ rowCount: rows.length, rows }, null, 2);
}

function handleGetLateralMovementSummary({ tab }) {
  const t = requireTab(tab);
  const db = getDb(t.dbPath);

  const find = (...candidates) =>
    t.headers.find((h) => candidates.some((c) => h.toLowerCase().includes(c)));

  const evtIdCol  = find("eventid", "event_id", "event id");
  const tsCol     = (t.tsColumns || [])[0];
  const userCol   = find("targetusername", "username", "user", "accountname");
  const srcCol    = find("ipaddress", "sourceip", "workstationname", "sourceaddress");
  const hostCol   = find("computername", "computer", "hostname");
  const logonCol  = find("logontype");

  const result = { tabId: t.tabId, fileName: t.fileName };

  if (tsCol) {
    try {
      const r = db.prepare(`SELECT MIN("${tsCol}") AS first, MAX("${tsCol}") AS last FROM data`).get();
      result.dateRange = r;
    } catch {}
  }

  if (evtIdCol) {
    try {
      result.eventIdCounts = db.prepare(`SELECT "${evtIdCol}" AS eventId, COUNT(*) AS cnt FROM data GROUP BY "${evtIdCol}" ORDER BY cnt DESC LIMIT 20`).all();
    } catch {}
  }

  if (userCol && hostCol) {
    try {
      result.topUserHostPairs = db.prepare(`SELECT "${userCol}" AS user, "${hostCol}" AS host, COUNT(*) AS cnt FROM data WHERE "${userCol}" IS NOT NULL AND "${userCol}" != '' GROUP BY "${userCol}", "${hostCol}" ORDER BY cnt DESC LIMIT 20`).all();
    } catch {}
  }

  if (srcCol && hostCol) {
    try {
      result.topSourceTargetPairs = db.prepare(`SELECT "${srcCol}" AS source, "${hostCol}" AS target, COUNT(*) AS cnt FROM data WHERE "${srcCol}" IS NOT NULL AND "${srcCol}" != '' GROUP BY "${srcCol}", "${hostCol}" ORDER BY cnt DESC LIMIT 20`).all();
    } catch {}
  }

  if (logonCol) {
    try {
      result.logonTypeBreakdown = db.prepare(`SELECT "${logonCol}" AS logonType, COUNT(*) AS cnt FROM data WHERE "${logonCol}" IS NOT NULL GROUP BY "${logonCol}" ORDER BY cnt DESC`).all();
    } catch {}
  }

  // Failed logons (event 4625)
  if (evtIdCol) {
    try {
      const failedRows = db.prepare(`SELECT * FROM data WHERE "${evtIdCol}" = '4625' LIMIT 100`).all();
      result.failedLogonCount = failedRows.length;
      if (userCol) {
        const topFailed = {};
        for (const r of failedRows) {
          const u = r[userCol]; if (u) topFailed[u] = (topFailed[u] || 0) + 1;
        }
        result.topFailedLogonUsers = Object.entries(topFailed).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([user, cnt]) => ({ user, cnt }));
      }
    } catch {}
  }

  return JSON.stringify(result, null, 2);
}

function handleGetProcessExecutionSummary({ tab }) {
  const t = requireTab(tab);
  const db = getDb(t.dbPath);

  const find = (...candidates) =>
    t.headers.find((h) => candidates.some((c) => h.toLowerCase().includes(c)));

  const processCol  = find("newprocessname", "processname", "image", "process");
  const parentCol   = find("parentprocessname", "parentimage", "parentprocesspath");
  const cmdlineCol  = find("commandline", "command", "cmdline");
  const userCol     = find("subjectusername", "user", "username", "accountname");
  const hostCol     = find("computername", "computer", "hostname");
  const tsCol       = (t.tsColumns || [])[0];

  const result = { tabId: t.tabId, fileName: t.fileName };

  if (tsCol) {
    try {
      const r = db.prepare(`SELECT MIN("${tsCol}") AS first, MAX("${tsCol}") AS last FROM data`).get();
      result.dateRange = r;
    } catch {}
  }

  if (processCol) {
    try {
      result.topProcesses = db.prepare(`SELECT "${processCol}" AS process, COUNT(*) AS cnt FROM data WHERE "${processCol}" IS NOT NULL GROUP BY "${processCol}" ORDER BY cnt DESC LIMIT 20`).all();
    } catch {}
  }

  if (parentCol && processCol) {
    try {
      result.topParentChildPairs = db.prepare(`SELECT "${parentCol}" AS parent, "${processCol}" AS child, COUNT(*) AS cnt FROM data WHERE "${parentCol}" IS NOT NULL GROUP BY "${parentCol}", "${processCol}" ORDER BY cnt DESC LIMIT 20`).all();
    } catch {}
  }

  if (cmdlineCol) {
    try {
      // Flag suspicious patterns
      const suspicious = [
        "powershell", "cmd.exe /c", "wscript", "cscript", "mshta", "rundll32",
        "regsvr32", "certutil", "bitsadmin", "wmic", "psexec", "mimikatz",
        "base64", "-enc", "-encodedcommand", "invoke-expression", "iex(",
        "downloadstring", "bypass", "-nop ", "-w hidden", "whoami", "net user",
      ];
      const patterns = suspicious.map((s) =>
        `"${cmdlineCol}" LIKE '%${s}%'`
      ).join(" OR ");
      result.suspiciousCommandLines = db.prepare(
        `SELECT "${cmdlineCol}" AS cmdline, "${processCol || 'rowid'}" AS process, COUNT(*) AS cnt FROM data WHERE ${patterns} GROUP BY "${cmdlineCol}" ORDER BY cnt DESC LIMIT 30`
      ).all();
    } catch {}
  }

  if (userCol) {
    try {
      result.topExecutingUsers = db.prepare(`SELECT "${userCol}" AS user, COUNT(*) AS cnt FROM data WHERE "${userCol}" IS NOT NULL AND "${userCol}" != '' GROUP BY "${userCol}" ORDER BY cnt DESC LIMIT 15`).all();
    } catch {}
  }

  return JSON.stringify(result, null, 2);
}

// ── Server setup ──────────────────────────────────────────────────────────────

const server = new Server(
  { name: "irflow-timeline", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args = {} } = request.params;
  try {
    let text;
    switch (name) {
      case "list_sessions":                text = handleListSessions(); break;
      case "get_columns":                  text = handleGetColumns(args); break;
      case "get_event_stats":              text = handleGetEventStats(args); break;
      case "query_events":                 text = handleQueryEvents(args); break;
      case "search_events":               text = handleSearchEvents(args); break;
      case "run_sql":                      text = handleRunSql(args); break;
      case "get_lateral_movement_summary": text = handleGetLateralMovementSummary(args); break;
      case "get_process_execution_summary":text = handleGetProcessExecutionSummary(args); break;
      default: throw new Error(`Unknown tool: ${name}`);
    }
    return { content: [{ type: "text", text }] };
  } catch (err) {
    return { content: [{ type: "text", text: `Error: ${err.message}` }], isError: true };
  }
});

const transport = new StdioServerTransport();
await server.connect(transport);
