import type { CandidateMatch } from "@deepsec/core";
import type { Alias, Document, Node } from "yaml";
import { isAlias, isMap, isScalar, isSeq, LineCounter, parseAllDocuments } from "yaml";
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
const LABELS = [
  "privileged container",
  "privilege escalation allowed",
  "host namespace shared",
  "Windows host process container",
  "container runs as root UID",
  "host filesystem mount",
  "unmasked proc mount",
  "dangerous Linux capability",
];
const DANGEROUS_CAPABILITIES = new Set([
  "ALL",
  "BPF",
  "DAC_READ_SEARCH",
  "NET_ADMIN",
  "SYS_ADMIN",
  "SYS_MODULE",
  "SYS_PTRACE",
  "SYS_RAWIO",
]);
const MAX_CONTENT_LENGTH = 1024 * 1024;
const MAX_LOCATIONS = 64;
const MAX_WORKLOADS = 100_000;

// Resolve aliases once in source order without expanding their object graphs.
function aliasTargets(document: Document): WeakMap<Alias, Node> {
  const targets = new WeakMap<Alias, Node>();
  const anchors = new Map<string, Node>();
  const pending: unknown[] = [document.contents];
  let examined = 0;
  while (pending.length && examined++ < 1_000_000) {
    const node = pending.pop();
    if (isAlias(node)) {
      const target = anchors.get(node.source);
      if (target) targets.set(node, target);
    } else if (isMap(node) || isSeq(node) || isScalar(node)) {
      if (node.anchor) anchors.set(node.anchor, node);
      if (isMap(node)) {
        for (let i = node.items.length - 1; i >= 0; i--) {
          pending.push(node.items[i].value, node.items[i].key);
        }
      } else if (isSeq(node)) {
        for (let i = node.items.length - 1; i >= 0; i--) pending.push(node.items[i]);
      }
    }
  }
  return targets;
}

function resolve(node: unknown, targets: WeakMap<Alias, Node>): Node | undefined {
  if (isAlias(node)) return targets.get(node);
  return isMap(node) || isSeq(node) || isScalar(node) ? node : undefined;
}

function field(node: unknown, key: string, targets: WeakMap<Alias, Node>): Node | undefined {
  const map = resolve(node, targets);
  if (!isMap(map)) return undefined;
  for (let i = map.items.length - 1; i >= 0; i--) {
    const entry = map.items[i];
    if (isScalar(entry.key) && entry.key.value === key) return resolve(entry.value, targets);
  }
  return undefined;
}

function scalar(node: unknown): unknown {
  return isScalar(node) ? node.value : undefined;
}

export const k8sPrivilegedWorkloadMatcher: MatcherPlugin = {
  noiseTier: "precise" as const,
  slug: "k8s-privileged-workload",
  description:
    "Kubernetes workload enabling privileged execution, host access, or dangerous capabilities",
  filePatterns: ["**/*.yaml", "**/*.yml", "**/*.json"],
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
    if (/(?:^|\/)(?:node_modules|vendor|\.github|charts\/[^/]+\/charts)\//.test(filePath))
      return [];
    if (content.length > MAX_CONTENT_LENGTH) return [];

    const lineCounter = new LineCounter();
    let documents: Document[];
    try {
      // Kubernetes uses YAML 1.1 scalars, including yes/on and alternative integer spellings.
      documents = parseAllDocuments(content, {
        version: "1.1",
        lineCounter,
        prettyErrors: false,
        uniqueKeys: false,
      });
    } catch {
      return [];
    }
    const hits = new Map<string, Set<number>>();
    const record = (label: string, node: Node) => {
      let locations = hits.get(label);
      if (!locations) {
        locations = new Set();
        hits.set(label, locations);
      }
      if (locations.size < MAX_LOCATIONS && node.range)
        locations.add(lineCounter.linePos(node.range[0]).line);
    };

    for (const document of documents) {
      if (document.errors.length) continue;
      const targets = aliasTargets(document);
      const get = (node: unknown, key: string) => field(node, key, targets);
      const check = (node: unknown, key: string, value: unknown, label: string) => {
        const found = get(node, key);
        if (found && scalar(found) === value) record(label, found);
      };
      const securityContext = (node: unknown) => {
        check(node, "privileged", true, LABELS[0]);
        check(node, "allowPrivilegeEscalation", true, LABELS[1]);
        check(get(node, "windowsOptions"), "hostProcess", true, LABELS[3]);
        check(node, "runAsUser", 0, LABELS[4]);
        check(node, "procMount", "Unmasked", LABELS[6]);
        const add = get(get(node, "capabilities"), "add");
        if (isSeq(add)) {
          for (const item of add.items) {
            const value = resolve(item, targets);
            if (value && DANGEROUS_CAPABILITIES.has(String(scalar(value))))
              record(LABELS[7], value);
          }
        }
      };
      const pending: { node: unknown; inheritedKind?: string }[] = [{ node: document.contents }];
      const visited = new Set<Node>();
      let examined = 0;
      while (pending.length && examined++ < MAX_WORKLOADS) {
        const { node, inheritedKind } = pending.pop()!;
        const resource = resolve(node, targets);
        if (!resource || visited.has(resource)) continue;
        visited.add(resource);
        const kind = scalar(get(resource, "kind")) ?? inheritedKind;
        if (typeof kind !== "string") continue;
        if (!inheritedKind && typeof scalar(get(resource, "apiVersion")) !== "string") continue;
        if (kind.endsWith("List")) {
          const items = get(resource, "items");
          if (isSeq(items)) {
            const itemKind = kind.slice(0, -4) || undefined;
            for (let i = items.items.length - 1; i >= 0 && pending.length < MAX_WORKLOADS; i--) {
              pending.push({ node: items.items[i], inheritedKind: itemKind });
            }
          }
          continue;
        }
        if (!WORKLOAD_KINDS.has(kind)) continue;
        let spec = get(resource, "spec");
        if (kind === "PodTemplate") spec = get(get(resource, "template"), "spec");
        else if (kind === "CronJob")
          spec = get(get(get(get(spec, "jobTemplate"), "spec"), "template"), "spec");
        else if (kind !== "Pod") spec = get(get(spec, "template"), "spec");
        for (const key of ["hostIPC", "hostNetwork", "hostPID"]) check(spec, key, true, LABELS[2]);
        securityContext(get(spec, "securityContext"));
        for (const key of ["containers", "initContainers", "ephemeralContainers"]) {
          const containers = get(spec, key);
          if (isSeq(containers))
            for (const container of containers.items)
              securityContext(get(container, "securityContext"));
        }
        const volumes = get(spec, "volumes");
        if (isSeq(volumes)) {
          for (const volume of volumes.items) {
            const hostPath = get(volume, "hostPath");
            if (isMap(hostPath)) record(LABELS[5], hostPath);
          }
        }
      }
    }
    const lines = content.split("\n");
    return LABELS.flatMap((label): CandidateMatch[] => {
      const locations = hits.get(label);
      if (!locations?.size) return [];
      const lineNumbers = [...locations].sort((a, b) => a - b);
      const first = lineNumbers[0];
      return [
        {
          vulnSlug: "k8s-privileged-workload",
          lineNumbers,
          snippet: lines
            .slice(Math.max(0, first - 3), first + 2)
            .join("\n")
            .slice(0, 2048),
          matchedPattern: label,
        },
      ];
    });
  },
};
