package engine

import "regexp"

// DefaultRules returns a base rule set covering the most common database
// attack categories. Rules are evaluated in order; highest-priority first.
func DefaultRules() []*Rule {
	return []*Rule{

		// ── SQL Injection ─────────────────────────────────────────────────────

		// Boolean OR bypass variants:
		//   numeric:  OR 1=1,  OR 1 = 1
		//   string:   OR '1'='1',  OR 'a'='a',  OR ''=''
		//   keyword:  OR true
		{
			Name:   "sqli-or-always-true",
			Action: ActionBlock,
			SQLPattern: regexp.MustCompile(
				`(?i)\bOR\b\s+(` +
					`1\s*=\s*1` + // OR 1=1
					`|'[^']*'\s*=\s*'[^']*'` + // OR 'x'='x'
					`|"[^"]*"\s*=\s*"[^"]*"` + // OR "x"="x"
					`|\btrue\b` + // OR true
					`)`,
			),
		},

		// UNION-based data extraction: "UNION SELECT", "UNION ALL SELECT"
		{
			Name:       "sqli-union-select",
			Action:     ActionBlock,
			SQLPattern: regexp.MustCompile(`(?i)\bUNION\b\s+(ALL\s+)?\bSELECT\b`),
		},

		// Stacked queries via semicolon: "; DROP TABLE", "; INSERT ..."
		{
			Name:       "sqli-stacked-queries",
			Action:     ActionBlock,
			SQLPattern: regexp.MustCompile(`(?i);\s*(DROP|INSERT|UPDATE|DELETE|CREATE|ALTER|TRUNCATE|EXEC)\b`),
		},

		// Time-based blind injection: SLEEP(), BENCHMARK()
		{
			Name:       "sqli-time-based",
			Action:     ActionBlock,
			SQLPattern: regexp.MustCompile(`(?i)\b(SLEEP|BENCHMARK)\s*\(`),
		},

		// ── Data Exfiltration ─────────────────────────────────────────────────

		// File read/write operations: LOAD_FILE, INTO OUTFILE, INTO DUMPFILE
		{
			Name:       "exfil-file-ops",
			Action:     ActionBlock,
			SQLPattern: regexp.MustCompile(`(?i)\b(LOAD_FILE\s*\(|INTO\s+OUTFILE\b|INTO\s+DUMPFILE\b)`),
		},

		// ── DDL Protection ────────────────────────────────────────────────────

		// DROP on structural objects
		{
			Name:       "ddl-drop",
			Action:     ActionBlock,
			SQLPattern: regexp.MustCompile(`(?i)\bDROP\s+(TABLE|DATABASE|SCHEMA|INDEX|VIEW|PROCEDURE|FUNCTION)\b`),
		},

		// TRUNCATE (mass delete without WHERE)
		{
			Name:       "ddl-truncate",
			Action:     ActionBlock,
			SQLPattern: regexp.MustCompile(`(?i)^\s*TRUNCATE\s+`),
		},

		// ── Privilege Escalation ──────────────────────────────────────────────

		// GRANT permissions to users
		{
			Name:       "privesc-grant",
			Action:     ActionBlock,
			SQLPattern: regexp.MustCompile(`(?i)\bGRANT\b.+\bTO\b`),
		},

		// CREATE / ALTER USER
		{
			Name:       "privesc-user-mgmt",
			Action:     ActionBlock,
			SQLPattern: regexp.MustCompile(`(?i)\b(CREATE|ALTER)\s+USER\b`),
		},

		// ── Reconnaissance (alert, don't block) ───────────────────────────────

		// Browsing information_schema to map the database
		{
			Name:       "recon-information-schema",
			Action:     ActionAlert,
			SQLPattern: regexp.MustCompile(`(?i)\binformation_schema\b`),
		},

		// Reading mysql.user (credential harvesting)
		{
			Name:       "recon-mysql-user",
			Action:     ActionAlert,
			SQLPattern: regexp.MustCompile(`(?i)\bmysql\s*\.\s*user\b`),
		},
	}
}
