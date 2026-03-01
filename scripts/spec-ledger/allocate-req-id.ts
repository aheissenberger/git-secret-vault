#!/usr/bin/env node
/// <reference types="node" />
import path from "node:path";
import { REQ_FILE_PATTERN } from "./constants.ts";
import { getArg, listFiles, parseFrontmatter, readUtf8 } from "./common.ts";

const requirementsDir = "spec/requirements";
const prefix = (getArg("--type", "FR") || "FR").toUpperCase();

if (!["FR", "NFR", "SEC"].includes(prefix)) {
	console.error(`Invalid --type '${prefix}'. Use FR, NFR, or SEC.`);
	process.exit(1);
}

const files = await listFiles(requirementsDir);
let maxNumber = 0;

for (const filePath of files) {
	const basename = path.basename(filePath);
	if (!REQ_FILE_PATTERN.test(basename)) {
		continue;
	}

	const content = await readUtf8(filePath);
	const { data } = parseFrontmatter(content);
  const typedData = data as Record<string, unknown>;
  const id = String(typedData.id || basename.replace(/\.md$/, ""));
	const match = id.match(/^(FR|NFR|SEC)-(\d{3})$/);
	if (!match) {
		continue;
	}

	if (match[1] !== prefix) {
		continue;
	}

	maxNumber = Math.max(maxNumber, Number(match[2]));
}

const next = maxNumber + 1;
const allocated = `${prefix}-${String(next).padStart(3, "0")}`;
console.log(allocated);
