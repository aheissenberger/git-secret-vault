#!/usr/bin/env node
/// <reference types="node" />
import { getArg, printErrorsAndExit, runGit } from "./common.ts";

const baseRef = getArg("--base", process.env.VALIDATION_MERGE_BASE || "origin/main");
const range = `${baseRef}...HEAD`;
const errors = [];

let output = "";
try {
	output = runGit(["diff", "--name-status", range], { allowSkipOutsideCi: true });
} catch (error) {
  errors.push(`git diff failed: ${error instanceof Error ? error.message : String(error)}`);
  printErrorsAndExit(errors, "");
}

for (const line of output.split(/\r?\n/)) {
	if (!line.trim()) {
		continue;
	}

	const [status, ...pathParts] = line.split(/\t+/);
	const filePath = pathParts[pathParts.length - 1];
	if (!status || !filePath) {
		continue;
	}

	const isTraceHistory = filePath.startsWith("spec/trace/events/") || filePath.startsWith("spec/trace/claims/");
	if (!isTraceHistory) {
		continue;
	}

	if (!status.startsWith("A")) {
		errors.push(`${filePath}: immutable trace history allows only added files (found status ${status})`);
	}
}

printErrorsAndExit(errors, "validate-trace-immutability: OK");
