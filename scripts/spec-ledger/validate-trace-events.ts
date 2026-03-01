#!/usr/bin/env node
/// <reference types="node" />
import path from "node:path";
import { ALLOWED_CHANGE_TYPE, EVENT_FILE_PATTERN, REQ_ID_PATTERN } from "./constants.ts";
import { listFiles, parseFrontmatter, printErrorsAndExit, readUtf8 } from "./common.ts";

const eventsDir = "spec/trace/events";
const requiredKeys = ["req_id", "change_type", "files", "tests", "docs", "author", "timestamp"];
const errors = [];

const files = await listFiles(eventsDir).catch((error) => {
	errors.push(`${eventsDir}: cannot read (${error.message})`);
	return [];
});

for (const filePath of files) {
	const basename = path.basename(filePath);
	if (!EVENT_FILE_PATTERN.test(basename)) {
		errors.push(`${filePath}: invalid filename pattern`);
	}

	const content = await readUtf8(filePath).catch((error) => {
		errors.push(`${filePath}: cannot read (${error.message})`);
		return null;
	});
	if (!content) {
		continue;
	}

	const { data, hasFrontmatter } = parseFrontmatter(content);
	if (!hasFrontmatter) {
		errors.push(`${filePath}: missing YAML frontmatter`);
		continue;
	}

	for (const key of requiredKeys) {
		if (!(key in data)) {
			errors.push(`${filePath}: missing frontmatter key '${key}'`);
		}
	}

	if (!REQ_ID_PATTERN.test(String(data.req_id || ""))) {
		errors.push(`${filePath}: invalid req_id '${data.req_id}'`);
	}

	if (data.req_id && !basename.includes(`-${data.req_id}.md`)) {
		errors.push(`${filePath}: filename req ID must match frontmatter req_id`);
	}

	if (!ALLOWED_CHANGE_TYPE.has(String(data.change_type || ""))) {
		errors.push(`${filePath}: invalid change_type '${data.change_type}'`);
	}

	if (!Array.isArray(data.files)) {
		errors.push(`${filePath}: 'files' must be an array`);
	}
	if (!Array.isArray(data.tests)) {
		errors.push(`${filePath}: 'tests' must be an array`);
	}
	if (!Array.isArray(data.docs)) {
		errors.push(`${filePath}: 'docs' must be an array`);
	}

	const parsedTimestamp = Date.parse(String(data.timestamp || ""));
	if (Number.isNaN(parsedTimestamp)) {
		errors.push(`${filePath}: invalid timestamp '${data.timestamp}'`);
	}
}

printErrorsAndExit(errors, "validate-trace-events: OK");
