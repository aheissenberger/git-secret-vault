#!/usr/bin/env node
/// <reference types="node" />
import path from "node:path";
import { REQ_ID_PATTERN } from "./constants.ts";
import { getArg, parseFrontmatter, printErrorsAndExit, readUtf8, runGit } from "./common.ts";

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

const changedReqIds = new Set();
const newTraceEventReqIds = new Set();

for (const line of output.split(/\r?\n/)) {
	if (!line.trim()) {
		continue;
	}

	const [status, ...pathParts] = line.split(/\t+/);
	const filePath = pathParts[pathParts.length - 1];
	if (!status || !filePath) {
		continue;
	}

	if (filePath.match(/^spec\/requirements\/(FR|NFR|SEC)-\d{3}\.md$/) && ["A", "M", "R", "C"].some((s) => status.startsWith(s))) {
		const id = path.basename(filePath, ".md");
		changedReqIds.add(id);
	}

	if (filePath.startsWith("spec/trace/events/") && status.startsWith("A")) {
		const content = await readUtf8(filePath).catch(() => null);
		if (!content) {
			continue;
		}
		const { data } = parseFrontmatter(content);
		if (REQ_ID_PATTERN.test(String(data.req_id || ""))) {
			newTraceEventReqIds.add(String(data.req_id));
		}
	}
}

let indexDiff = "";
try {
	indexDiff = runGit(["diff", "--unified=0", range, "--", "spec/requirements/index.md"], { allowSkipOutsideCi: true });
} catch (error) {
  errors.push(`git diff index failed: ${error instanceof Error ? error.message : String(error)}`);
  printErrorsAndExit(errors, "");
}

for (const line of indexDiff.split(/\r?\n/)) {
	if (!line.startsWith("+") || line.startsWith("+++")) {
		continue;
	}
	const entry = line.slice(1).trim();
	const match = entry.match(/^-\s+((FR|NFR|SEC)-\d{3})\s*\|/);
	if (match) {
		changedReqIds.add(match[1]);
	}
}

for (const reqId of changedReqIds) {
	if (!newTraceEventReqIds.has(reqId)) {
		errors.push(`Missing new trace event for changed requirement ${reqId}`);
	}
}

printErrorsAndExit(errors, "validate-req-trace-coverage: OK");
