import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { authBypassMatcher } from "../matchers/auth-bypass.js";
import { insecureCryptoMatcher } from "../matchers/insecure-crypto.js";
import { k8sPrivilegedWorkloadMatcher } from "../matchers/k8s-privileged-workload.js";
import { missingAuthMatcher } from "../matchers/missing-auth.js";
import { openRedirectMatcher } from "../matchers/open-redirect.js";
import { pathTraversalMatcher } from "../matchers/path-traversal.js";
import { rceMatcher } from "../matchers/rce.js";
import { secretsExposureMatcher } from "../matchers/secrets-exposure.js";
import { sqlInjectionMatcher } from "../matchers/sql-injection.js";
import { ssrfMatcher } from "../matchers/ssrf.js";
import { xssMatcher } from "../matchers/xss.js";

const FIXTURES_ROOT = path.resolve(import.meta.dirname, "../../../../fixtures/vulnerable-app/src");

function readFixture(relativePath: string): string {
  return fs.readFileSync(path.join(FIXTURES_ROOT, relativePath), "utf-8");
}

describe("auth-bypass matcher", () => {
  it("detects auth patterns in admin.ts", () => {
    const content = readFixture("api/admin.ts");
    const matches = authBypassMatcher.match(content, "src/api/admin.ts");
    expect(matches.length).toBeGreaterThan(0);
    expect(matches.some((m) => m.vulnSlug === "auth-bypass")).toBe(true);
  });
});

describe("missing-auth matcher", () => {
  it("flags all HTTP entry points in users.ts as weak candidates", () => {
    const content = readFixture("api/users.ts");
    const matches = missingAuthMatcher.match(content, "src/api/users.ts");
    expect(matches.length).toBeGreaterThan(0);
    expect(matches[0].vulnSlug).toBe("missing-auth");
    expect(matches[0].matchedPattern).toContain("weak candidate");
  });

  it("also flags admin.ts — all entry points are candidates", () => {
    const content = readFixture("api/admin.ts");
    const matches = missingAuthMatcher.match(content, "src/api/admin.ts");
    // Now flags all entry points regardless of auth presence
    expect(matches.length).toBeGreaterThan(0);
    expect(matches[0].matchedPattern).toContain("weak candidate");
  });

  it("does not flag non-handler files", () => {
    const content = readFixture("lib/db.ts");
    const matches = missingAuthMatcher.match(content, "src/lib/db.ts");
    expect(matches.length).toBe(0);
  });
});

describe("xss matcher", () => {
  it("detects dangerouslySetInnerHTML", () => {
    const content = readFixture("components/comment.tsx");
    const matches = xssMatcher.match(content, "src/components/comment.tsx");
    expect(matches.length).toBeGreaterThan(0);
    const slugs = matches.map((m) => m.matchedPattern);
    expect(slugs).toContain("dangerouslySetInnerHTML");
  });
});

describe("rce matcher", () => {
  it("detects exec/eval patterns", () => {
    const content = readFixture("utils/exec-helper.ts");
    const matches = rceMatcher.match(content, "src/utils/exec-helper.ts");
    expect(matches.length).toBeGreaterThan(0);
    const patterns = matches.map((m) => m.matchedPattern);
    expect(patterns.some((p) => p.includes("exec") || p.includes("eval"))).toBe(true);
  });
});

describe("sql-injection matcher", () => {
  it("detects interpolated SQL", () => {
    const content = readFixture("lib/db.ts");
    const matches = sqlInjectionMatcher.match(content, "src/lib/db.ts");
    expect(matches.length).toBeGreaterThan(0);
  });
});

describe("ssrf matcher", () => {
  it("detects fetch with user-controlled URL", () => {
    const content = readFixture("lib/fetch-proxy.ts");
    const matches = ssrfMatcher.match(content, "src/lib/fetch-proxy.ts");
    expect(matches.length).toBeGreaterThan(0);
  });
});

describe("path-traversal matcher", () => {
  it("detects file operations with user input", () => {
    const content = readFixture("api/upload.ts");
    const matches = pathTraversalMatcher.match(content, "src/api/upload.ts");
    expect(matches.length).toBeGreaterThan(0);
  });
});

describe("secrets-exposure matcher", () => {
  it("detects hardcoded secrets", () => {
    const content = readFixture("config.ts");
    const matches = secretsExposureMatcher.match(content, "src/config.ts");
    expect(matches.length).toBeGreaterThan(0);
  });
});

describe("insecure-crypto matcher", () => {
  it("detects MD5 and Math.random", () => {
    const content = readFixture("lib/crypto.ts");
    const matches = insecureCryptoMatcher.match(content, "src/lib/crypto.ts");
    expect(matches.length).toBeGreaterThan(0);
    const patterns = matches.map((m) => m.matchedPattern);
    expect(patterns.some((p) => p.includes("MD5"))).toBe(true);
    expect(patterns.some((p) => p.includes("Math.random"))).toBe(true);
  });
});

describe("open-redirect matcher", () => {
  it("detects redirect with user input", () => {
    const content = readFixture("utils/redirect.ts");
    const matches = openRedirectMatcher.match(content, "src/utils/redirect.ts");
    expect(matches.length).toBeGreaterThan(0);
  });
});

describe("k8s-privileged-workload matcher", () => {
  it("detects privileged Kubernetes workload settings", () => {
    const content = `apiVersion: v1
kind: Pod
spec:
  hostPID: true
  containers:
    - securityContext:
        privileged: true
        allowPrivilegeEscalation: true`;
    const matches = k8sPrivilegedWorkloadMatcher.match(content, "deploy/pod.yaml");
    expect(matches.map((match) => match.matchedPattern)).toEqual([
      "privileged container",
      "privilege escalation allowed",
      "host namespace shared",
    ]);
  });

  it("detects settings written as inline flow maps", () => {
    const content = `apiVersion: v1
kind: Pod
spec: {hostNetwork: true}
---
apiVersion: v1
kind: Pod
spec:
  containers:
    - securityContext: {privileged: true, capabilities: {drop: [ALL], add: [SYS_ADMIN]}}
    - {name: sidecar, securityContext: {privileged: false, capabilities: {add: [CHOWN]}}}`;
    const matches = k8sPrivilegedWorkloadMatcher.match(content, "deploy/pod.yaml");
    expect(matches.map((match) => [match.matchedPattern, match.lineNumbers])).toEqual([
      ["privileged container", [9]],
      ["host namespace shared", [3]],
      ["dangerous Linux capability", [9]],
    ]);
  });

  it("detects Windows host process containers", () => {
    const content = `apiVersion: v1
kind: Pod
spec:
  securityContext:
    windowsOptions:
      hostProcess: true`;
    const matches = k8sPrivilegedWorkloadMatcher.match(content, "deploy/pod.yaml");
    expect(matches.map((match) => match.matchedPattern)).toEqual([
      "Windows host process container",
    ]);
  });

  it("detects workloads inside a List", () => {
    const content = `apiVersion: v1
kind: List
items:
  - apiVersion: v1
    kind: ConfigMap
    data:
      privileged: true
  - apiVersion: v1
    kind: Pod
    spec:
      containers:
        - securityContext:
            privileged: true`;
    const matches = k8sPrivilegedWorkloadMatcher.match(content, "deploy/list.yaml");
    expect(matches.map((match) => match.matchedPattern)).toEqual(["privileged container"]);
    expect(matches[0].lineNumbers).toEqual([13]);
  });

  it("does not flag hardened workloads or non-Kubernetes YAML", () => {
    const hardened = `apiVersion: v1
kind: Pod
spec:
  hostPID: false
  containers:
    - securityContext:
        privileged: false
        allowPrivilegeEscalation: false
        runAsNonRoot: true
        capabilities:
          drop: ["ALL"]`;
    expect(k8sPrivilegedWorkloadMatcher.match(hardened, "deploy/pod.yaml")).toEqual([]);
    expect(k8sPrivilegedWorkloadMatcher.match("hostNetwork: true", "config/settings.yaml")).toEqual(
      [],
    );
  });

  it("detects block-list capabilities and first-party Helm charts", () => {
    const content = `apiVersion: v1
kind: Pod
spec:
  containers:
    - securityContext:
        capabilities:
          add:
            - SYS_ADMIN`;
    const matches = k8sPrivilegedWorkloadMatcher.match(content, "charts/app/templates/pod.yaml");
    expect(matches.map((match) => match.matchedPattern)).toEqual(["dangerous Linux capability"]);
    expect(matches[0].lineNumbers).toEqual([8]);
  });

  it("supports indentationless capability sequences without scanning sibling lists", () => {
    const dangerous = `apiVersion: v1
kind: Pod
spec:
  containers:
    - securityContext:
        capabilities:
          add:
          - SYS_ADMIN`;
    const matches = k8sPrivilegedWorkloadMatcher.match(dangerous, "deploy/pod.yaml");
    expect(matches.map((match) => match.matchedPattern)).toEqual(["dangerous Linux capability"]);
    expect(matches[0].lineNumbers).toEqual([8]);

    const dropped = `apiVersion: v1
kind: Pod
spec:
  containers:
    - securityContext:
        capabilities:
          add:
          - CHOWN
          drop:
          - SYS_ADMIN`;
    expect(k8sPrivilegedWorkloadMatcher.match(dropped, "deploy/pod.yaml")).toEqual([]);
  });

  it("ignores non-workload documents and capabilities being dropped", () => {
    const content = `apiVersion: v1
kind: ConfigMap
data:
  settings.yaml: |
    privileged: true
---
apiVersion: v1
kind: Pod
spec:
  containers:
    - securityContext:
        capabilities:
          drop:
            - SYS_ADMIN`;
    expect(k8sPrivilegedWorkloadMatcher.match(content, "deploy/resources.yaml")).toEqual([]);
  });

  it("reports global line numbers from workload documents only", () => {
    const content = `apiVersion: v1
kind: ConfigMap
data:
  privileged: true
---
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      hostNetwork: true`;
    const matches = k8sPrivilegedWorkloadMatcher.match(content, "deploy/resources.yaml");
    expect(matches.map((match) => match.matchedPattern)).toEqual(["host namespace shared"]);
    expect(matches[0].lineNumbers).toEqual([11]);
  });

  it("does not split a document on an indented YAML block scalar", () => {
    const content = `apiVersion: v1
kind: Pod
metadata:
  annotations:
    example.com/config: |
      ---
      nested: content
spec:
  hostPID: true`;
    const matches = k8sPrivilegedWorkloadMatcher.match(content, "deploy/pod.yaml");
    expect(matches.map((match) => match.matchedPattern)).toEqual(["host namespace shared"]);
    expect(matches[0].lineNumbers).toEqual([9]);
  });

  it("ignores YAML-looking text outside the workload spec or inside scalar data", () => {
    const content = `apiVersion: v1
kind: Pod
metadata:
  annotations:
    hostPID: true
spec:
  containers:
    - name: app
      env:
        - name: CONFIG
          value: |
            privileged: true
            capabilities:
              add:
                - SYS_ADMIN`;
    expect(k8sPrivilegedWorkloadMatcher.match(content, "deploy/pod.yaml")).toEqual([]);
  });

  it("handles very large manifests", () => {
    const containers = Array.from({ length: 200_000 }, (_, i) => `    - name: c${i}`);
    const content = ["apiVersion: v1", "kind: Pod", "spec:", "  containers:", ...containers]
      .concat("  hostPID: true")
      .join("\n");
    const matches = k8sPrivilegedWorkloadMatcher.match(content, "deploy/pod.yaml");
    expect(matches.map((match) => match.matchedPattern)).toEqual(["host namespace shared"]);
    expect(matches[0].lineNumbers).toEqual([200_005]);
  });

  it("ignores settings that only appear inside quoted values or comments", () => {
    const content = `apiVersion: v1
kind: Pod
spec:
  containers:
    - name: app
      args: ["--flags", "{privileged: true}"]
      env:
        - {name: A, value: "{privileged: true}"}
        - name: B
          value: '{"hostPID": true}'
        - name: C
          value: plain # {hostNetwork: true}
      # securityContext: {allowPrivilegeEscalation: true}`;
    expect(k8sPrivilegedWorkloadMatcher.match(content, "deploy/pod.yaml")).toEqual([]);
  });

  it("detects flow maps with quoted keys and quoted text before a comment marker", () => {
    const content = `apiVersion: v1
kind: Pod
spec:
  containers:
    - securityContext: {"privileged": true}
    - {name: "a # b", securityContext: {'allowPrivilegeEscalation': true}}
    - securityContext:
        "runAsUser": 0 # root`;
    const matches = k8sPrivilegedWorkloadMatcher.match(content, "deploy/pod.yaml");
    expect(matches.map((match) => [match.matchedPattern, match.lineNumbers])).toEqual([
      ["privileged container", [5]],
      ["privilege escalation allowed", [6]],
      ["container runs as root UID", [8]],
    ]);
  });

  it("ignores pod template labels and annotations", () => {
    const content = `apiVersion: apps/v1
kind: StatefulSet
spec:
  template:
    metadata:
      labels:
        privileged: true
      annotations:
        hostPath: /cache
    spec:
      hostNetwork: true
  volumeClaimTemplates:
    - metadata:
        annotations:
          hostPID: true
      spec:
        accessModes: [ReadWriteOnce]`;
    const matches = k8sPrivilegedWorkloadMatcher.match(content, "deploy/sts.yaml");
    expect(matches.map((match) => [match.matchedPattern, match.lineNumbers])).toEqual([
      ["host namespace shared", [11]],
    ]);
  });

  it("skips Helm dependency charts but scans first-party chart templates", () => {
    const content = `apiVersion: v1
kind: Pod
spec:
  hostPID: true`;
    expect(
      k8sPrivilegedWorkloadMatcher.match(content, "charts/app/charts/redis/templates/pod.yaml"),
    ).toEqual([]);
    expect(
      k8sPrivilegedWorkloadMatcher.match(content, "charts/app/templates/pod.yaml"),
    ).toHaveLength(1);
  });

  it("accepts capitalized true but not other YAML 1.1 booleans", () => {
    const content = `apiVersion: v1
kind: Pod
spec:
  hostNetwork: TRUE
  hostPID: yes
  containers:
    - securityContext:
        privileged: True
        allowPrivilegeEscalation: on`;
    const matches = k8sPrivilegedWorkloadMatcher.match(content, "deploy/pod.yaml");
    expect(matches.map((match) => [match.matchedPattern, match.lineNumbers])).toEqual([
      ["privileged container", [8]],
      ["host namespace shared", [4]],
    ]);
  });

  it("detects pod settings in a PodTemplate", () => {
    const content = `apiVersion: v1
kind: PodTemplate
metadata:
  name: node-monitor
template:
  metadata:
    annotations:
      hostPID: true
  spec:
    hostPID: true`;
    const matches = k8sPrivilegedWorkloadMatcher.match(content, "deploy/template.yaml");
    expect(matches.map((match) => [match.matchedPattern, match.lineNumbers])).toEqual([
      ["host namespace shared", [10]],
    ]);
  });

  it("detects workloads inside typed lists", () => {
    const content = `apiVersion: v1
kind: PodList
items:
- metadata:
    name: node-monitor
  spec:
    hostNetwork: true
---
apiVersion: apps/v1
kind: DeploymentList
items:
  - apiVersion: apps/v1
    kind: Deployment
    spec:
      template:
        spec:
          hostIPC: true
---
apiVersion: v1
kind: ServiceList
items:
- spec:
    hostNetwork: true`;
    const matches = k8sPrivilegedWorkloadMatcher.match(content, "deploy/list.yaml");
    expect(matches.map((match) => [match.matchedPattern, match.lineNumbers])).toEqual([
      ["host namespace shared", [7, 17]],
    ]);
  });

  it("detects module loading, raw I/O, DAC bypass, and BPF capabilities", () => {
    for (const capability of ["SYS_MODULE", "SYS_RAWIO", "DAC_READ_SEARCH", "BPF"]) {
      const content = `apiVersion: v1
kind: Pod
spec:
  containers:
    - securityContext:
        capabilities:
          add: [CHOWN, "${capability}"]`;
      const matches = k8sPrivilegedWorkloadMatcher.match(content, "deploy/pod.yaml");
      expect(matches.map((match) => match.matchedPattern)).toEqual(["dangerous Linux capability"]);
    }
  });

  it("builds snippets from the original manifest lines", () => {
    const content = `apiVersion: v1
kind: Pod
spec:
  hostPID: true # node monitor`;
    const [match] = k8sPrivilegedWorkloadMatcher.match(content, "deploy/pod.yaml");
    expect(match.snippet).toBe("kind: Pod\nspec:\n  hostPID: true # node monitor");
  });

  it("detects documents written entirely in flow style", () => {
    const content = `{apiVersion: v1, kind: Pod, metadata: {annotations: {hostPath: /x}}, spec: {hostPID: true}}
---
{
  "apiVersion": "v1",
  "kind": "Pod",
  "metadata": {"annotations": {"privileged": "true"}},
  "spec": {"hostNetwork": true}
}
---
{apiVersion: v1, kind: ConfigMap, data: {privileged: true}}`;
    const matches = k8sPrivilegedWorkloadMatcher.match(content, "deploy/pods.yaml");
    expect(matches.map((match) => [match.matchedPattern, match.lineNumbers])).toEqual([
      ["host namespace shared", [1, 7]],
    ]);
  });
});
