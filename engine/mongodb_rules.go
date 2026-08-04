package engine

import "regexp"

// DefaultMongoDBRules returns security rules for MongoDB connections.
// Rules match against CommandInfo.ToRuleString() which has the form:
//
//	CMD:<command> DB:<db> COLL:<collection> [HAS:<op>] [EMPTY_FILTER]
func DefaultMongoDBRules() []*Rule {
	return []*Rule{

		// ── JavaScript Execution (critical — enables code execution) ──────────

		// $where runs arbitrary JS in query predicates
		{
			Name:       "nosqli-where-js",
			Action:     ActionBlock,
			SQLPattern: regexp.MustCompile(`HAS:\$where`),
		},

		// $function / $accumulator run arbitrary JS in aggregation pipelines
		{
			Name:       "nosqli-function-js",
			Action:     ActionBlock,
			SQLPattern: regexp.MustCompile(`HAS:\$(function|accumulator)`),
		},

		// ── DDL / Destructive Commands ────────────────────────────────────────

		{
			Name:       "ddl-drop-collection",
			Action:     ActionBlock,
			SQLPattern: regexp.MustCompile(`(?i)^CMD:drop\b`),
		},

		{
			Name:       "ddl-drop-database",
			Action:     ActionBlock,
			SQLPattern: regexp.MustCompile(`(?i)^CMD:dropDatabase\b`),
		},

		// ── Mass Operations Without Filter ────────────────────────────────────

		// delete {} or update {} with empty filter touches every document
		{
			Name:       "mass-operation-no-filter",
			Action:     ActionBlock,
			SQLPattern: regexp.MustCompile(`\bEMPTY_FILTER\b`),
		},

		// ── Privilege Escalation ──────────────────────────────────────────────

		{
			Name:       "privesc-user-mgmt",
			Action:     ActionBlock,
			SQLPattern: regexp.MustCompile(`(?i)^CMD:(createUser|dropUser|updateUser)\b`),
		},

		{
			Name:       "privesc-grant-roles",
			Action:     ActionBlock,
			SQLPattern: regexp.MustCompile(`(?i)^CMD:(grantRolesToUser|revokeRolesFromUser)\b`),
		},

		// ── Reconnaissance (alert, don't block) ───────────────────────────────

		{
			Name:       "recon-list-databases",
			Action:     ActionAlert,
			SQLPattern: regexp.MustCompile(`(?i)^CMD:listDatabases\b`),
		},

		{
			Name:       "recon-list-collections",
			Action:     ActionAlert,
			SQLPattern: regexp.MustCompile(`(?i)^CMD:listCollections\b`),
		},

		// mapReduce executes JavaScript server-side
		{
			Name:       "mapreduce-js",
			Action:     ActionAlert,
			SQLPattern: regexp.MustCompile(`(?i)^CMD:mapReduce\b`),
		},
	}
}
