#!/usr/bin/env node
/// <reference types="node" />
import path from "node:path";
import { ALLOWED_REQ_STATUS, PACKAGE_SCOPE_PATTERN, REQ_FILE_PATTERN, REQ_ID_PATTERN } from "./constants.ts";
import { listFiles, parseFrontmatter, printErrorsAndExit, readUtf8 } from "./common.ts";

const requirementsDir = "spec/requirements";
const requiredFrontmatterKeys = ["id", "type", "status", "owner", "depends_on", "acceptance_refs", "implementation_pointers"];
const requiredSections = ["## Summary", "## Acceptance Criteria", "## Verification", "## Notes"];
const errors = [];

const files = await listFiles(requirementsDir).catch((error) => {
	errors.push(`${requirementsDir}: cannot read (${error.message})`);
	return [];
});

for (const filePath of files) {
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

	const { data, body, hasFrontmatter } = parseFrontmatter(content);
	if (!hasFrontmatter) {
		errors.push(`${filePath}: missing YAML frontmatter`);
		continue;
	}

	for (const key of requiredFrontmatterKeys) {
		if (!(key in data)) {
			errors.push(`${filePath}: missing frontmatter key '${key}'`);
		}
	}

	const id = String(data.id || "");
	const type = String(data.type || "");
	const expectedId = basename.replace(/\.md$/, "");

	if (!REQ_ID_PATTERN.test(id)) {
		errors.push(`${filePath}: invalid id '${id}'`);
	}

	if (id && expectedId !== id) {
		errors.push(`${filePath}: filename '${expectedId}' must match id '${id}'`);
	}

	if (id && type && !id.startsWith(`${type}-`)) {
		errors.push(`${filePath}: id '${id}' prefix must match type '${type}'`);
	}

  const status = String((data as Record<string, unknown>).status || "");
	if (!ALLOWED_REQ_STATUS.has(status)) {
		errors.push(`${filePath}: invalid status '${status}'`);
	}

	if ("depends_on" in data && !Array.isArray(data.depends_on)) {
		errors.push(`${filePath}: 'depends_on' must be an array`);
	}
	if ("acceptance_refs" in data && !Array.isArray(data.acceptance_refs)) {
		errors.push(`${filePath}: 'acceptance_refs' must be an array`);
	}
	if ("implementation_pointers" in data && !Array.isArray(data.implementation_pointers)) {
		errors.push(`${filePath}: 'implementation_pointers' must be an array`);
	}

	const hasParentReqId = "parent_req_id" in data;
	const hasPackageScope = "package_scope" in data;
	const parentReqIdValue = hasParentReqId ? (data as Record<string, unknown>).parent_req_id : null;
	const packageScopeValue = hasPackageScope ? (data as Record<string, unknown>).package_scope : null;

	if (hasParentReqId && parentReqIdValue !== null) {
		const parentReqId = String(parentReqIdValue || "");
		if (!REQ_ID_PATTERN.test(parentReqId)) {
			errors.push(`${filePath}: invalid parent_req_id '${parentReqIdValue}'`);
		}
		if (parentReqId && parentReqId === id) {
			errors.push(`${filePath}: parent_req_id cannot reference itself`);
		}
	}

	if (hasPackageScope && packageScopeValue !== null) {
		const packageScope = String(packageScopeValue || "");
		if (!PACKAGE_SCOPE_PATTERN.test(packageScope)) {
			errors.push(`${filePath}: invalid package_scope '${packageScopeValue}'`);
		}
	}

	if (parentReqIdValue !== null && (!hasPackageScope || packageScopeValue === null)) {
		errors.push(`${filePath}: child requirement must define non-null package_scope when parent_req_id is set`);
	}

	if (parentReqIdValue === null && packageScopeValue !== null) {
		errors.push(`${filePath}: parent requirement must keep package_scope null when parent_req_id is null`);
	}

	let previousIndex = -1;
	for (const section of requiredSections) {
		const idx = body.indexOf(`\n${section}\n`);
		if (idx === -1) {
			errors.push(`${filePath}: missing section '${section}'`);
			continue;
		}
		if (idx < previousIndex) {
			errors.push(`${filePath}: section order is invalid around '${section}'`);
		}
		previousIndex = idx;
	}
}

printErrorsAndExit(errors, "validate-req-files: OK");
