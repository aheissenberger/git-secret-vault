#!/usr/bin/env node
/// <reference types="node" />
import path from "node:path";
import { writeFile } from "node:fs/promises";
import { REQ_FILE_PATTERN } from "./constants.ts";
import { listFiles, parseFrontmatter, readUtf8 } from "./common.ts";

const requirementsDir = "spec/requirements";
const indexPath = "spec/requirements/index.md";

const files = await listFiles(requirementsDir);
const entries = [];

for (const filePath of files) {
	const basename = path.basename(filePath);
	if (!REQ_FILE_PATTERN.test(basename)) {
		continue;
	}

	const content = await readUtf8(filePath);
	const { data, body } = parseFrontmatter(content);
  const typedData = data as Record<string, unknown>;
  const id = String(typedData.id || basename.replace(/\.md$/, ""));
  const status = String(typedData.status || "Proposed");
const summaryMatch = body.match(/## Summary\n+([^\n]+)/);
  const summary = summaryMatch ? summaryMatch[1].trim() : "";

	entries.push({ id, status, summary });
}

entries.sort((a, b) => a.id.localeCompare(b.id));

const output = [
	"# Requirement Index",
	"",
	"Generated file. Do not edit manually.",
	"Source of truth: `spec/requirements/*.md`",
	"",
	...entries.map((entry) => `- ${entry.id} | ${entry.status} | ${entry.summary}`),
	"",
].join("\n");

await writeFile(indexPath, output, "utf8");
console.log(`generate-req-index: wrote ${indexPath}`);
