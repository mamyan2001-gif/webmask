import { isGenericSpaOrHomepage } from "../utils/validation.js";

const CSRF_FIELD_NAMES = [
  "csrf", "csrf_token", "csrftoken", "_csrf", "authenticity_token", "__requestverificationtoken",
  "_token", "anticsrf", "csrfmiddlewaretoken",
];

const ERROR_SIGNATURES = [
  { id: "stack-trace", pattern: /(?:Exception|Error)[:\s][^\n]+\n\s+at\s+[\w.$]+\([^)]+\)/i, title: "Stack trace in response" },
  { id: "python-trace", pattern: /Traceback \(most recent call last\):[\s\S]{0,400}File "/i, title: "Python traceback exposed" },
  { id: "php-error", pattern: /(?:Fatal error|Parse error|Warning):\s+.*\s+in\s+\/[^\s]+\s+on line\s+\d+/i, title: "PHP error message exposed" },
  { id: "asp-net", pattern: /Server Error in '\/' Application|ASP\.NET(?:\s+\w+)?\s+version/i, title: "ASP.NET exception page" },
  { id: "sql-error", pattern: /(?:SQL syntax.*MySQL|mysql_fetch|ORA-\d{5}|PostgreSQL.*ERROR|SQLite3::queryException)/i, title: "SQL error message exposed" },
  { id: "java-trace", pattern: /java\.lang\.\w+Exception:[^\n]+\n\s+at\s+[\w.$]+\(/i, title: "Java exception in response" },
  { id: "laravel-ignition", pattern: /laravel-ignition|Ignition\s+\|\s+Laravel|ignition-debug/i, title: "Laravel Ignition debug page" },
  { id: "rails-error", pattern: /ActionController::\w+Error|ActiveRecord::\w+Error/i, title: "Ruby on Rails error exposed" },
];

export function checkFormSecurity(body) {
  const findings = [];
  const html = body || "";
  const forms = [...html.matchAll(/<form\b[^>]*>([\s\S]*?)<\/form>/gi)];

  if (forms.length === 0) {
    findings.push({
      id: "forms-none",
      severity: "info",
      category: "forms",
      title: "No HTML forms detected",
      description: "The homepage did not contain classic HTML form elements.",
      evidence: "0 forms parsed",
      remediation: "No action required.",
    });
    return findings;
  }

  let postForms = 0;
  let postWithoutCsrf = 0;
  let passwordFields = 0;
  let passwordAutocomplete = 0;

  for (const match of forms) {
    const tag = match[0];
    const inner = match[1] || "";
    const method = (tag.match(/\bmethod=["']?(\w+)["']?/i)?.[1] || "get").toLowerCase();
    if (method !== "post") continue;

    postForms += 1;
    const hasCsrf = CSRF_FIELD_NAMES.some((name) =>
      new RegExp(`<input[^>]+name=["']${name}["']`, "i").test(inner),
    );
    if (!hasCsrf) postWithoutCsrf += 1;

    if (/<input[^>]+type=["']password["']/i.test(inner)) {
      passwordFields += 1;
      if (/autocomplete=["'](?:current-password|new-password|off)["']/i.test(inner)) {
        passwordAutocomplete += 1;
      }
    }
  }

  if (postWithoutCsrf > 0) {
    findings.push({
      id: "forms-missing-csrf",
      severity: "medium",
      category: "forms",
      title: "POST form(s) without CSRF token field",
      description: `${postWithoutCsrf} of ${postForms} POST form(s) lack a recognizable CSRF hidden input.`,
      evidence: `Expected one of: ${CSRF_FIELD_NAMES.slice(0, 5).join(", ")}, …`,
      remediation: "Add server-validated CSRF tokens to all state-changing forms.",
    });
  }

  if (passwordFields > 0 && passwordAutocomplete < passwordFields) {
    findings.push({
      id: "forms-password-autocomplete",
      severity: "low",
      category: "forms",
      title: "Password field allows browser autocomplete",
      description: "Password inputs do not use autocomplete=\"current-password\" or \"off\".",
      evidence: `${passwordFields - passwordAutocomplete} password field(s) without restrictive autocomplete`,
      remediation: "Set autocomplete=\"current-password\" or \"off\" on login forms as appropriate.",
    });
  }

  if (postForms > 0 && postWithoutCsrf === 0) {
    findings.push({
      id: "forms-csrf-present",
      severity: "info",
      category: "forms",
      title: "POST forms include CSRF token fields",
      description: "Recognizable CSRF hidden inputs were found in POST forms.",
      evidence: `${postForms} POST form(s) checked`,
      remediation: "Ensure tokens are validated server-side, not only present in markup.",
    });
  }

  return findings;
}

export async function checkErrorDisclosure(targetUrl, fetchTarget) {
  const findings = [];
  const origin = new URL(targetUrl).origin;
  const token = `sfprobe${Date.now().toString(36)}`;

  const probes = [
    `${origin}/webmask-probe-${token}`,
    `${origin}/?id=${encodeURIComponent("1'")}&q=${token}`,
    `${origin}/%25%30%30`,
  ];

  const seen = new Set();

  for (const probeUrl of probes) {
    try {
      const { res, body } = await fetchTarget(probeUrl, { followRedirects: false, timeout: 8000 });
      const contentType = res.headers.get("content-type") || "";
      if (res.status < 400 && !body.includes(token) && body.length < 500) continue;
      if (isGenericSpaOrHomepage(body) && res.status < 500) continue;

      for (const sig of ERROR_SIGNATURES) {
        if (seen.has(sig.id)) continue;
        sig.pattern.lastIndex = 0;
        if (sig.pattern.test(body)) {
          seen.add(sig.id);
          findings.push({
            id: `error-${sig.id}`,
            severity: sig.id.includes("sql") ? "high" : "medium",
            category: "errors",
            title: sig.title,
            description: "Error or debug output appears in the HTTP response body.",
            evidence: `${probeUrl} → HTTP ${res.status}, matched ${sig.id}`,
            remediation: "Disable debug mode in production; use generic error pages.",
          });
        }
      }
    } catch {
      /* skip */
    }
  }

  if (findings.length === 0) {
    findings.push({
      id: "errors-none",
      severity: "info",
      category: "errors",
      title: "No verbose error signatures detected",
      description: "Probing did not reveal stack traces or database errors in responses.",
      evidence: `${probes.length} error-inducing requests tested`,
      remediation: "No action required.",
    });
  }

  return findings;
}
