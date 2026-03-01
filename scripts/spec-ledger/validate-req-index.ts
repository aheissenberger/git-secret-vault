#!/usr/bin/env node
/// <reference types="node" />
import path from "node:path";
import { REQ_FILE_PATTERN, REQ_ID_PATTERN } from "./constants.ts";
import { listFiles, parseFrontmatter, printErrorsAndExit, readUtf8 } from "./common.ts";

const indexPath = "spec/requirements/index.md";
const requirementsDir = "spec/requirements";
const errors = [];

const indexContent = await readUtf8(indexPath).catch((error) => {
  errors.push(`${indexPath}: cannot read (${error.message})`);
  return null;
});

const reqFiles = await listFiles(requirementsDir).catch((error) => {
  errors.push(`${requirementsDir}: cannot read (${error.message})`);
  return [];
});

if (indexContent) {
  const lines = indexContent
    .split("\n")
    .map((line: string) => line.trim())
    .filter((line: string) => line.startsWith("- "));

  const ids = lines.map((line: string) => line.slice(2).split("|")[0].trim());
  const seen = new Set();

  for (const id of ids) {
    if (!REQ_ID_PATTERN.test(id)) {
      errors.push(`Invalid requirement ID in ${indexPath}: ${id}`);
    }
    if (seen.has(id)) {
      errors.push(`Duplicate requirement ID in ${indexPath}: ${id}`);
    }
    seen.add(id);
  }

  const sorted = [...ids].sort();
  if (JSON.stringify(ids) !== JSON.stringify(sorted)) {
    errors.push(`${indexPath}: requirement IDs are not sorted`);
  }
}

const expectedLines = [];
for (const filePath of reqFiles) {
  const basename = path.basename(filePath);
  if (!REQ_FILE_PATTERN.test(basename)) {
    continue;
  }

  const content = await readUtf8(filePath).catch((error) => {
    errors.push(`${filePath}: cannot read (${error.message})`);
    return null;
  });
  if (!content) {
    continue;
  }

  const { data } = parseFrontmatter(content);
  const reqId = String(data.id || basename.replace(/\.md$/, ""));
  const status = String(data.status || "Proposed");

  const summaryMatch = content.match(/\n## Summary\n\n([^\n]+)/);
  const summary = summaryMatch ? summaryMatch[1].trim() : "";
  expectedLines.push(`- ${reqId} | ${status} | ${summary}`);
}

expectedLines.sort((a, b) => a.localeCompare(b));

if (indexContent) {
  const actualLines = indexContent
    .split("\n")
    .filter((line: string) => line.trim().startsWith("- "))
    .map((line: string) => line.trim());

  if (JSON.stringify(actualLines) !== JSON.stringify(expectedLines)) {
    errors.push(`${indexPath}: does not match generated output from ${requirementsDir}/*.md`);
  }
}

printErrorsAndExit(errors, "validate-req-index: OK");
