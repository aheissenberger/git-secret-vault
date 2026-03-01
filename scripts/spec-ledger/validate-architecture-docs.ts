#!/usr/bin/env node
/// <reference types="node" />
import { access } from "node:fs/promises";
import { constants as fsConstants } from "node:fs";
import { REQUIRED_ARCHITECTURE_DOCS } from "./constants.ts";
import { printErrorsAndExit, readUtf8 } from "./common.ts";

const errors = [];

for (const filePath of REQUIRED_ARCHITECTURE_DOCS) {
	try {
		await access(filePath, fsConstants.F_OK);
	} catch {
		errors.push(`${filePath}: missing required architecture/decision file`);
	}
}

if (errors.length === 0) {
	const infraPath = "spec/ARCHITECTURE/current-infrastructure.md";
	const content = await readUtf8(infraPath).catch((error) => {
		errors.push(`${infraPath}: cannot read (${error.message})`);
		return null;
	});

	if (content) {
		const requiredHeadings = ["## System Context", "## Boundaries", "## Ownership Map"];
		for (const heading of requiredHeadings) {
			if (!content.includes(heading)) {
				errors.push(`${infraPath}: missing required section '${heading}'`);
			}
		}
	}
}

printErrorsAndExit(errors, "validate-architecture-docs: OK");
