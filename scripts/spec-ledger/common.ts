/// <reference types="node" />
import { execFileSync } from "node:child_process";
import { readFile, readdir } from "node:fs/promises";
import path from "node:path";

const MAX_ERRORS = 20;

export function getArg(flag: string, fallback?: string): string | undefined {
  const index = process.argv.indexOf(flag);
  if (index === -1 || index + 1 >= process.argv.length) {
    return fallback;
  }
  return process.argv[index + 1];
}

export async function readUtf8(filePath: string): Promise<string> {
  return readFile(filePath, "utf8");
}

export async function listFiles(dirPath: string): Promise<string[]> {
  const entries = await readdir(dirPath, { withFileTypes: true });
  return entries.filter((entry: any) => entry.isFile()).map((entry: any) => path.join(dirPath, entry.name));
}

export function printErrorsAndExit(errors: string[], okMessage?: string): void {
  if (errors.length > 0) {
    const visible = errors.slice(0, MAX_ERRORS);
    for (const error of visible) {
      console.error(`- ${error}`);
    }
    if (errors.length > MAX_ERRORS) {
      console.error(`...and ${errors.length - MAX_ERRORS} more errors`);
    }
    process.exit(1);
  }

  if (okMessage) {
    console.log(okMessage);
  }
}

export function parseFrontmatter(content: string): { data: Record<string, unknown>; body: string; hasFrontmatter: boolean } {
  const normalized = content.replace(/\r\n/g, "\n");
  if (!normalized.startsWith("---\n")) {
    return { data: {}, body: normalized, hasFrontmatter: false };
  }

  const end = normalized.indexOf("\n---\n", 4);
  if (end === -1) {
    return { data: {}, body: normalized, hasFrontmatter: false };
  }

  const raw = normalized.slice(4, end);
  const body = normalized.slice(end + 5);
  const lines = raw.split("\n");

  const data: Record<string, unknown> = {};
  let currentArrayKey = null;

  for (const line of lines as string[]) {
    if (!line.trim()) {
      continue;
    }

    const arrayMatch = line.match(/^\s*-\s+(.*)$/);
    if (currentArrayKey && arrayMatch) {
      (data[currentArrayKey] as any[]).push(parseScalar(arrayMatch[1]));
      continue;
    }

    const keyValue = line.match(/^([a-zA-Z0-9_]+):\s*(.*)$/);
    if (!keyValue) {
      currentArrayKey = null;
      continue;
    }

    const [, key, value] = keyValue;
    if (value === "") {
      data[key] = [];
      currentArrayKey = key;
      continue;
    }

    data[key] = parseScalar(value);
    currentArrayKey = null;
  }

  return { data, body, hasFrontmatter: true };
}

function parseScalar(value: string): unknown {
  const trimmed = value.trim();

  if (trimmed === "null") {
    return null;
  }

  if (trimmed === "[]") {
    return [];
  }

  if ((trimmed.startsWith('"') && trimmed.endsWith('"')) || (trimmed.startsWith("'") && trimmed.endsWith("'"))) {
    return trimmed.slice(1, -1);
  }

  if (trimmed === "true") {
    return true;
  }

  if (trimmed === "false") {
    return false;
  }

  return trimmed;
}

export function runGit(args: string[], { allowSkipOutsideCi = false } = {}): string {
  try {
    return execFileSync("git", args, { encoding: "utf8" });
  } catch (error) {
    if (allowSkipOutsideCi && !process.env.CI) {
      console.warn(`Skipping: git ${args.join(" ")} failed outside CI (${error instanceof Error ? error.message : String(error)})`);
      process.exit(0);
    }
    throw error;
  }
}
