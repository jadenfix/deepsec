import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";

const WORKLOAD_KINDS = new Set([
  "CronJob",
  "DaemonSet",
  "Deployment",
  "DeploymentConfig",
  "Job",
  "Pod",
  "PodTemplate",
  "ReplicaSet",
  "ReplicationController",
  "Rollout",
  "StatefulSet",
]);

// Kubernetes decodes manifests as YAML 1.1 (sigs.k8s.io/yaml), so `yes`, `on` and `y` are true too.
const TRUE = "(?:y|Y|yes|Yes|YES|true|True|TRUE|on|On|ON)";

// Quoted, these are strings, which Kubernetes rejects for boolean and integer fields.
const QUOTED_NON_STRING = new RegExp(String.raw`^(?:${TRUE}|[-+]?\d+)$`);

// Matches `key: value` as a block mapping entry or inside a flow map such as `{key: value}`.
function field(key: string, value: string): RegExp {
  return new RegExp(String.raw`(?:^\s*(?:-\s+)?|[{,]\s*)${key}\s*:\s*${value}\s*(?:[,}]|$)`);
}

const PATTERNS = [
  { regex: field("privileged", TRUE), label: "privileged container" },
  { regex: field("allowPrivilegeEscalation", TRUE), label: "privilege escalation allowed" },
  { regex: field("host(?:IPC|Network|PID)", TRUE), label: "host namespace shared" },
  { regex: field("hostProcess", TRUE), label: "Windows host process container" },
  { regex: field("runAsUser", "0"), label: "container runs as root UID" },
  { regex: field("hostPath", ".*"), label: "host filesystem mount" },
  { regex: field("procMount", "Unmasked"), label: "unmasked proc mount" },
];

const CAPABILITY_LABEL = "dangerous Linux capability";
const LABELS = [...PATTERNS.map(({ label }) => label), CAPABILITY_LABEL];

const DANGEROUS_CAPABILITY =
  /(?:^|[,\s])(?:ALL|BPF|DAC_READ_SEARCH|NET_ADMIN|SYS_ADMIN|SYS_MODULE|SYS_PTRACE|SYS_RAWIO)(?=$|[,\s])/;

const BLOCK_SCALAR = /^(\s*)(?:\S.*:|-)\s*[|>](?:[1-9][+-]?|[+-][1-9]?)?\s*$/;
const BLOCK_METADATA = /^(\s*(?:-\s+)?)metadata\s*:\s*$/;

type Document = { lines: string[]; lineOffset: number; kind: string };

// Unquotes simple quoted tokens, empties other quoted scalars, and drops comments, so text
// inside strings or comments can't pass for a mapping entry. A quoted `"true"` or `"0"` is
// emptied too, so a label like `privileged: "true"` isn't read as the boolean setting.
function structuralText(line: string): string {
  return line
    .replace(/"(?:[^"\\]|\\.)*"|'(?:[^']|'')*'/g, (quoted) => {
      const text = quoted.slice(1, -1);
      return /^[\w./-]+$/.test(text) && !QUOTED_NON_STRING.test(text) ? text : '""';
    })
    .replace(/(?:^|\s)#.*$/, "");
}

function leadingIndent(line: string): number {
  return line.match(/^\s*/)?.[0].length ?? 0;
}

function isStructuralLine(line: string): boolean {
  return Boolean(line.trim()) && !/^\s*{{.*}}\s*$/.test(line);
}

function topLevelIndent(lines: string[]): number | undefined {
  let indent: number | undefined;
  for (const line of lines) {
    if (isStructuralLine(line)) indent = Math.min(indent ?? Infinity, leadingIndent(line));
  }
  return indent;
}

function topLevelLines(lines: string[]): string[] {
  const rootIndent = topLevelIndent(lines);
  return lines.filter((line) => isStructuralLine(line) && leadingIndent(line) === rootIndent);
}

function isFlowDocument(lines: string[]): boolean {
  return lines.find(isStructuralLine)?.trimStart().startsWith("{") ?? false;
}

// Top-level `key: value` entries of a flow document such as `{kind: Pod, spec: {...}}`.
function flowEntries(text: string): string[] {
  let depth = 0;
  let topLevel = "";
  for (const char of text) {
    if (char === "{" || char === "[") depth++;
    else if (char === "}" || char === "]") depth--;
    else if (depth === 1) topLevel += char;
  }
  return topLevel.split(",");
}

function documentKind(lines: string[]): string | undefined {
  const entries = isFlowDocument(lines) ? flowEntries(lines.join("\n")) : topLevelLines(lines);
  if (!entries.some((entry) => /^\s*apiVersion\s*:/.test(entry))) return undefined;
  return entries
    .map((entry) => entry.match(/^\s*kind\s*:\s*([\w.-]+)\s*$/)?.[1])
    .find((kind) => kind !== undefined);
}

function listItems(lines: string[]): Omit<Document, "kind">[] {
  const rootIndent = topLevelIndent(lines);
  const itemsIndex = lines.findIndex(
    (line) => leadingIndent(line) === rootIndent && /^\s*items\s*:\s*$/.test(line),
  );
  if (itemsIndex === -1) return [];

  const starts: number[] = [];
  let end = lines.length;
  let itemIndent: number | undefined;
  for (let i = itemsIndex + 1; i < lines.length; i++) {
    if (!isStructuralLine(lines[i])) continue;
    const indent = leadingIndent(lines[i]);
    const isEntry = /^\s*-(?:\s|$)/.test(lines[i]);
    itemIndent ??= indent;
    if (indent < itemIndent || (indent === itemIndent && !isEntry)) {
      end = i;
      break;
    }
    if (indent === itemIndent) starts.push(i);
  }

  return starts.map((start, index) => {
    const itemLines = lines.slice(start, starts[index + 1] ?? end);
    itemLines[0] = itemLines[0].replace(/^(\s*)-/, "$1 ");
    return { lines: itemLines, lineOffset: start };
  });
}

// Items of a typed list such as PodList may omit apiVersion and kind, so they inherit one.
function workloads(lines: string[], lineOffset: number, itemKind?: string): Document[] {
  const kind = documentKind(lines) ?? itemKind;
  if (kind?.endsWith("List")) {
    return listItems(lines).flatMap((item) =>
      workloads(item.lines, lineOffset + item.lineOffset, kind.slice(0, -4) || undefined),
    );
  }
  return kind !== undefined && WORKLOAD_KINDS.has(kind) ? [{ lines, lineOffset, kind }] : [];
}

function workloadDocuments(lines: string[]): Document[] {
  const documents: Document[] = [];
  let start = 0;
  for (let i = 0; i <= lines.length; i++) {
    if (i < lines.length && !/^---\s*$/.test(lines[i])) continue;
    documents.push(...workloads(lines.slice(start, i), start));
    start = i + 1;
  }
  return documents;
}

// A PodTemplate keeps its pod settings under top-level `template` instead of `spec`.
function podSettingLines({ lines, kind }: Document): string[] {
  if (isFlowDocument(lines)) return lines;

  const rootIndent = topLevelIndent(lines);
  const rootKey = new RegExp(String.raw`^\s*${kind === "PodTemplate" ? "template" : "spec"}\s*:`);
  const specIndex = lines.findIndex(
    (line) => leadingIndent(line) === rootIndent && rootKey.test(line),
  );
  if (specIndex === -1) return lines.map(() => "");

  let inSpec = true;
  return lines.map((line, index) => {
    if (index < specIndex || !inSpec) return "";
    if (index === specIndex || !isStructuralLine(line)) return line;
    if (leadingIndent(line) <= rootIndent!) {
      inSpec = false;
      return "";
    }
    return line;
  });
}

// Blanks the lines nested under each line matching `opener`, whose first group is the parent indent.
function withoutNested(lines: string[], opener: RegExp): string[] {
  let parentIndent: number | undefined;
  return lines.map((line) => {
    if (parentIndent !== undefined) {
      if (!isStructuralLine(line) || leadingIndent(line) > parentIndent) return "";
      parentIndent = undefined;
    }
    parentIndent = line.match(opener)?.[1].length;
    return line;
  });
}

function withoutFlowMetadata(lines: string[]): string[] {
  const text = lines.join("\n");
  const metadata = /(?:^|[\s{,])metadata\s*:\s*\{/g;
  let result = "";
  let copied = 0;
  for (let match = metadata.exec(text); match; match = metadata.exec(text)) {
    const open = match.index + match[0].length - 1;
    let close = open;
    for (let depth = 0; close < text.length; close++) {
      if (text[close] === "{") depth++;
      else if (text[close] === "}" && --depth === 0) break;
    }
    result += text.slice(copied, open + 1) + text.slice(open + 1, close).replace(/[^\n]/g, " ");
    copied = close;
    metadata.lastIndex = close;
  }
  return (result + text.slice(copied)).split("\n");
}

function parentIsCapabilities(lines: string[], lineIndex: number, indent: number): boolean {
  for (let i = lineIndex - 1; i >= 0; i--) {
    if (!isStructuralLine(lines[i]) || leadingIndent(lines[i]) >= indent) continue;
    return /^\s*capabilities\s*:\s*$/.test(lines[i]);
  }
  return false;
}

function dangerousCapabilityLines(lines: string[]): number[] {
  const hitLines: number[] = [];

  for (let i = 0; i < lines.length; i++) {
    const flow = lines[i].match(/\bcapabilities\s*:\s*\{.*?\badd\s*:\s*\[([^\]]*)\]/);
    if (flow) {
      if (DANGEROUS_CAPABILITY.test(flow[1])) hitLines.push(i + 1);
      continue;
    }

    const add = lines[i].match(/^(\s*)add\s*:\s*(.*)$/);
    if (!add || !parentIsCapabilities(lines, i, add[1].length)) continue;

    const value = add[2].trim();
    const inline = value.match(/^\[([^\]]*)\]/);
    if (inline) {
      if (DANGEROUS_CAPABILITY.test(inline[1])) hitLines.push(i + 1);
    } else if (!value) {
      for (let j = i + 1; j < lines.length; j++) {
        if (!isStructuralLine(lines[j])) continue;
        const indent = leadingIndent(lines[j]);
        const isSequenceEntry = /^\s*-/.test(lines[j]);
        if (indent < add[1].length) break;
        if (indent === add[1].length && !isSequenceEntry) break;
        const entry = lines[j].match(/^\s*-\s*(.*)/);
        if (entry && DANGEROUS_CAPABILITY.test(entry[1])) hitLines.push(j + 1);
      }
    }
  }

  return hitLines;
}

export const k8sPrivilegedWorkloadMatcher: MatcherPlugin = {
  noiseTier: "precise" as const,
  slug: "k8s-privileged-workload",
  description:
    "Kubernetes workload enabling privileged execution, host access, or dangerous capabilities",
  filePatterns: ["**/*.yaml", "**/*.yml"],
  examples: [
    `apiVersion: v1\nkind: Pod\nspec:\n  containers:\n    - securityContext:\n        privileged: true`,
    `apiVersion: v1\nkind: Pod\nspec:\n  containers:\n    - securityContext: {privileged: true}`,
    `apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      hostNetwork: true`,
    `apiVersion: v1\nkind: Pod\nspec:\n  hostPID: true`,
    `{apiVersion: v1, kind: Pod, spec: {hostIPC: true}}`,
    `apiVersion: v1\nkind: PodTemplate\ntemplate:\n  spec:\n    hostNetwork: true`,
    `apiVersion: v1\nkind: Pod\nspec:\n  containers:\n    - securityContext:\n        allowPrivilegeEscalation: true`,
    `apiVersion: v1\nkind: Pod\nspec:\n  securityContext:\n    windowsOptions:\n      hostProcess: true`,
    `apiVersion: v1\nkind: Pod\nspec:\n  securityContext:\n    runAsUser: 0`,
    `apiVersion: v1\nkind: Pod\nspec:\n  volumes:\n    - hostPath:\n        path: /`,
    `apiVersion: v1\nkind: Pod\nspec:\n  containers:\n    - securityContext:\n        procMount: Unmasked`,
    `apiVersion: v1\nkind: Pod\nspec:\n  containers:\n    - securityContext:\n        capabilities:\n          add: ["SYS_ADMIN"]`,
    `apiVersion: v1\nkind: Pod\nspec:\n  containers:\n    - securityContext:\n        capabilities:\n          add:\n            - SYS_MODULE`,
  ],
  match(content, filePath) {
    // Helm dependency charts are vendored; first-party charts/<name>/templates are still scanned.
    if (/(?:^|\/)(?:node_modules|vendor|\.github|charts\/[^/]+\/charts)\//.test(filePath)) {
      return [];
    }

    const lines = content.split("\n");
    const hits = new Map<string, number[]>();
    const record = (label: string, lineNumber: number) => {
      const lineNumbers = hits.get(label);
      if (lineNumbers) lineNumbers.push(lineNumber);
      else hits.set(label, [lineNumber]);
    };

    for (const document of workloadDocuments(lines.map(structuralText))) {
      const scanLines = withoutFlowMetadata(
        withoutNested(withoutNested(podSettingLines(document), BLOCK_SCALAR), BLOCK_METADATA),
      );
      scanLines.forEach((line, index) => {
        for (const { regex, label } of PATTERNS) {
          if (regex.test(line)) record(label, document.lineOffset + index + 1);
        }
      });
      for (const lineNumber of dangerousCapabilityLines(scanLines)) {
        record(CAPABILITY_LABEL, document.lineOffset + lineNumber);
      }
    }

    return LABELS.flatMap((label): CandidateMatch[] => {
      const lineNumbers = hits.get(label);
      if (!lineNumbers) return [];
      const first = lineNumbers[0];
      return [
        {
          vulnSlug: "k8s-privileged-workload",
          lineNumbers,
          snippet: lines.slice(Math.max(0, first - 3), first + 2).join("\n"),
          matchedPattern: label,
        },
      ];
    });
  },
};
