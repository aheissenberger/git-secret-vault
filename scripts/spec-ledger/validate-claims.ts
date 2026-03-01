#!/usr/bin/env node
/// <reference types="node" />
import path from "node:path";
import { ALLOWED_CLAIM_ACTION, CLAIM_FILE_PATTERN, REQ_ID_PATTERN } from "./constants.ts";
import { listFiles, parseFrontmatter, printErrorsAndExit, readUtf8 } from "./common.ts";

const claimsDir = "spec/trace/claims";
const requiredKeys = ["req_id", "action", "scope", "owner", "worktree", "timestamp", "lease_expires_at"];
const errors = [];

const files = await listFiles(claimsDir).catch((error) => {
	errors.push(`${claimsDir}: cannot read (${error.message})`);
	return [];
});

const recordsByReq = new Map();

for (const filePath of files) {
	const basename = path.basename(filePath);
	if (!CLAIM_FILE_PATTERN.test(basename)) {
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

	const reqId = String(data.req_id || "");
	if (!REQ_ID_PATTERN.test(reqId)) {
		errors.push(`${filePath}: invalid req_id '${data.req_id}'`);
	}
	if (reqId && !basename.includes(`-claim-${reqId}.md`)) {
		errors.push(`${filePath}: filename req ID must match frontmatter req_id`);
	}

	const action = String(data.action || "");
	if (!ALLOWED_CLAIM_ACTION.has(action)) {
		errors.push(`${filePath}: invalid action '${data.action}'`);
	}

	const ts = Date.parse(String(data.timestamp || ""));
	if (Number.isNaN(ts)) {
		errors.push(`${filePath}: invalid timestamp '${data.timestamp}'`);
		continue;
	}

	const leaseExpiresAt = Date.parse(String(data.lease_expires_at || ""));
	if (Number.isNaN(leaseExpiresAt)) {
		errors.push(`${filePath}: invalid lease_expires_at '${data.lease_expires_at}'`);
	}

	if (action === "override") {
		const reason = typeof data.reason === "string" ? data.reason.trim() : "";
		if (!reason) {
			errors.push(`${filePath}: override action requires non-empty reason`);
		}
	}

	if (!recordsByReq.has(reqId)) {
		recordsByReq.set(reqId, []);
	}
	recordsByReq.get(reqId).push({ ts, action, filePath, owner: String(data.owner || "") });
}

const allowMultiClaim = process.env.ALLOW_MULTI_CLAIM === "1";
	for (const [reqId, events] of recordsByReq.entries()) {
	events.sort((a: typeof events[0], b: typeof events[0]) => a.ts - b.ts || a.filePath.localeCompare(b.filePath));
	let activeOwner = null;
	for (const event of events) {
		if (event.action === "claim") {
			if (!allowMultiClaim && activeOwner && activeOwner !== event.owner) {
				errors.push(`${event.filePath}: overlapping active claim for ${reqId}`);
				continue;
			}
			activeOwner = event.owner;
		} else if (event.action === "heartbeat") {
			if (!activeOwner) {
				errors.push(`${event.filePath}: heartbeat without active claim for ${reqId}`);
				continue;
			}
			if (activeOwner !== event.owner) {
				errors.push(`${event.filePath}: heartbeat owner '${event.owner}' does not match active owner '${activeOwner}'`);
			}
		} else if (event.action === "release") {
			if (!activeOwner) {
				errors.push(`${event.filePath}: release without active claim for ${reqId}`);
			} else {
				if (activeOwner !== event.owner) {
					errors.push(`${event.filePath}: release owner '${event.owner}' does not match active owner '${activeOwner}'`);
					continue;
				}
				activeOwner = null;
			}
		} else if (event.action === "override") {
			activeOwner = event.owner;
		}
	}
}

printErrorsAndExit(errors, "validate-claims: OK");
