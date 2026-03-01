#!/usr/bin/env node
/// <reference types="node" />
import { getArg, printErrorsAndExit, runGit } from "./common.ts";

const baseRef = getArg("--base", process.env.VALIDATION_MERGE_BASE || "origin/main");
const maxBehind = Number(process.env.WORKTREE_MAX_BEHIND ?? 20);
const maxAgeHours = Number(process.env.WORKTREE_MAX_BASE_AGE_HOURS ?? 24);
const errors = [];

let behindRaw = "0";
try {
	behindRaw = runGit(["rev-list", "--count", `HEAD..${baseRef}`], { allowSkipOutsideCi: true }).trim();
} catch (error) {
  errors.push(`git rev-list failed: ${error instanceof Error ? error.message : String(error)}`);
  printErrorsAndExit(errors, "");
}

const behind = Number(behindRaw);
if (!Number.isFinite(behind)) {
	errors.push(`Invalid behind count '${behindRaw}'`);
}

let mergeBase: string = "";
try {
	mergeBase = runGit(["merge-base", "HEAD", baseRef], { allowSkipOutsideCi: true }).trim();
} catch (error) {
  errors.push(`git merge-base failed: ${error instanceof Error ? error.message : String(error)}`);
  printErrorsAndExit(errors, "");
}

let mergeBaseTimeRaw = "0";
try {
	mergeBaseTimeRaw = runGit(["show", "-s", "--format=%ct", mergeBase], { allowSkipOutsideCi: true }).trim();
} catch (error) {
  errors.push(`git show merge-base failed: ${error instanceof Error ? error.message : String(error)}`);
  printErrorsAndExit(errors, "");
}

const mergeBaseEpoch = Number(mergeBaseTimeRaw);
if (!Number.isFinite(mergeBaseEpoch)) {
	errors.push(`Invalid merge-base timestamp '${mergeBaseTimeRaw}'`);
}

const nowEpoch = Math.floor(Date.now() / 1000);
const ageHours = (nowEpoch - mergeBaseEpoch) / 3600;

if (Number.isFinite(behind) && behind > maxBehind) {
	errors.push(`Branch is ${behind} commits behind ${baseRef}; max allowed is ${maxBehind}`);
}

if (Number.isFinite(ageHours) && ageHours > maxAgeHours) {
	errors.push(`Merge-base age is ${ageHours.toFixed(1)}h; max allowed is ${maxAgeHours}h`);
}

printErrorsAndExit(errors, "validate-worktree-fresh: OK");
