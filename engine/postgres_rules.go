package engine

import "regexp"

// DefaultPostgresRules returns security rules for PostgreSQL connections.
// SQL injection patterns largely overlap with MySQL; PostgreSQL-specific
// dangerous functions are added on top.
func DefaultPostgresRules() []*Rule {
	return []*Rule{

		// ── SQL Injection ─────────────────────────────────────────────────────

		{
			Name:   "sqli-or-always-true",
			Action: ActionBlock,
			SQLPattern: regexp.MustCompile(
				`(?i)\bOR\b\s+(` +
					`1\s*=\s*1` +
					`|'[^']*'\s*=\s*'[^']*'` +
					`|"[^"]*"\s*=\s*"[^"]*"` +
					`|\btrue\b` +
					`)`,
			),
		},

		{
			Name:       "sqli-union-select",
			Action:     ActionBlock,
			SQLPattern: regexp.MustCompile(`(?i)\bUNION\b\s+(ALL\s+)?\bSELECT\b`),
		},

		{
			Name:       "sqli-stacked-queries",
			Action:     ActionBlock,
			SQLPattern: regexp.MustCompile(`(?i);\s*(DROP|INSERT|UPDATE|DELETE|CREATE|ALTER|TRUNCATE)\b`),
		},

		// ── PostgreSQL-Specific Time-Based Blind Injection ────────────────────

		// pg_sleep() is the PostgreSQL equivalent of MySQL SLEEP()
		{
			Name:       "sqli-time-based-pg",
			Action:     ActionBlock,
			SQLPattern: regexp.MustCompile(`(?i)\bpg_sleep\s*\(`),
		},

		// ── File System Access ────────────────────────────────────────────────

		// pg_read_file / pg_ls_dir: read arbitrary server files
		{
			Name:       "exfil-pg-file-read",
			Action:     ActionBlock,
			SQLPattern: regexp.MustCompile(`(?i)\bpg_(read_file|read_binary_file|ls_dir)\s*\(`),
		},

		// COPY TO/FROM FILE: read or write server filesystem
		{
			Name:       "exfil-copy-file",
			Action:     ActionBlock,
			SQLPattern: regexp.MustCompile(`(?i)\bCOPY\b.+\b(TO|FROM)\b.+('|E')`),
		},

		// Large object file ops (lo_import / lo_export)
		{
			Name:       "exfil-large-object",
			Action:     ActionBlock,
			SQLPattern: regexp.MustCompile(`(?i)\b(lo_import|lo_export)\s*\(`),
		},

		// ── Remote Code Execution ─────────────────────────────────────────────

		// pg_execute_server_program (superuser-only, but block just in case)
		{
			Name:       "rce-server-program",
			Action:     ActionBlock,
			SQLPattern: regexp.MustCompile(`(?i)\bpg_execute_server_program\s*\(`),
		},

		// ── DDL Protection ────────────────────────────────────────────────────

		{
			Name:       "ddl-drop",
			Action:     ActionBlock,
			SQLPattern: regexp.MustCompile(`(?i)\bDROP\s+(TABLE|DATABASE|SCHEMA|INDEX|VIEW|FUNCTION|PROCEDURE|SEQUENCE)\b`),
		},

		{
			Name:       "ddl-truncate",
			Action:     ActionBlock,
			SQLPattern: regexp.MustCompile(`(?i)^\s*TRUNCATE\s+`),
		},

		// ── Privilege Escalation ──────────────────────────────────────────────

		// GRANT permissions
		{
			Name:       "privesc-grant",
			Action:     ActionBlock,
			SQLPattern: regexp.MustCompile(`(?i)\bGRANT\b.+\bTO\b`),
		},

		// CREATE / ALTER ROLE or USER
		{
			Name:       "privesc-role-mgmt",
			Action:     ActionBlock,
			SQLPattern: regexp.MustCompile(`(?i)\b(CREATE|ALTER)\s+(ROLE|USER)\b`),
		},

		// ── Reconnaissance (alert, don't block) ───────────────────────────────

		// Browsing information_schema / pg_catalog to map the database
		{
			Name:       "recon-information-schema",
			Action:     ActionAlert,
			SQLPattern: regexp.MustCompile(`(?i)\binformation_schema\b`),
		},

		{
			Name:       "recon-pg-catalog",
			Action:     ActionAlert,
			SQLPattern: regexp.MustCompile(`(?i)\bpg_catalog\b`),
		},

		// Reading pg_shadow / pg_authid (password hashes)
		{
			Name:       "recon-pg-shadow",
			Action:     ActionAlert,
			SQLPattern: regexp.MustCompile(`(?i)\b(pg_shadow|pg_authid)\b`),
		},
	}
}
