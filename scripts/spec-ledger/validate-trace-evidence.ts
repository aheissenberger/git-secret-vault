#!/usr/bin/env node
/// <reference types="node" />
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

const changedFiles = new Set();
const addedEventFiles = [];

for (const line of output.split(/\r?\n/)) {
	if (!line.trim()) {
		continue;
	}

	const [status, ...pathParts] = line.split(/\t+/);
	const filePath = pathParts[pathParts.length - 1];
	if (!status || !filePath) {
		continue;
	}

	changedFiles.add(filePath);
	if (status.startsWith("A") && filePath.startsWith("spec/trace/events/")) {
		addedEventFiles.push(filePath);
	}
}

for (const eventPath of addedEventFiles) {
	const content = await readUtf8(eventPath).catch((error) => {
		errors.push(`${eventPath}: cannot read (${error.message})`);
		return null;
	});
	if (!content) {
		continue;
	}

	const { data, body } = parseFrontmatter(content);
  const typedData = data as Record<string, unknown>;
  const files = Array.isArray(typedData.files) ? (typedData.files as unknown[]).map(String) : [];
	const intersects = files.some((file) => changedFiles.has(file));
	const metadataOnly = /metadata-only/i.test(body);

	if (!intersects && !metadataOnly) {
		errors.push(`${eventPath}: files[] has no overlap with changed files; add matching file or include 'metadata-only' in body`);
	}
}

printErrorsAndExit(errors, "validate-trace-evidence: OK");
