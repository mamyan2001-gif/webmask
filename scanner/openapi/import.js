import { fetchTarget } from "../utils/http.js";
import { assertSafeTarget } from "../utils/url.js";

const HTTP_METHODS = new Set(["get", "post", "put", "patch", "delete", "head", "options"]);

function parseSpecRaw(raw) {
  if (typeof raw === "object" && raw !== null) return raw;
  if (typeof raw !== "string") throw new Error("OpenAPI spec must be JSON text or an object");
  const trimmed = raw.trim();
  if (!trimmed) throw new Error("OpenAPI spec is empty");
  return JSON.parse(trimmed);
}

function resolveServerOrigin(doc, fallbackBaseUrl) {
  const servers = doc.servers || [];
  if (servers[0]?.url) {
    const srv = servers[0].url;
    if (srv.startsWith("http")) return new URL(srv).origin;
    return new URL(srv, fallbackBaseUrl).origin;
  }
  return new URL(fallbackBaseUrl).origin;
}

function extractRequestBody(op) {
  const content = op.requestBody?.content || {};
  const jsonSchema = content["application/json"]?.schema
    || content["application/*+json"]?.schema
    || null;
  const formSchema = content["application/x-www-form-urlencoded"]?.schema || null;
  return {
    jsonSchema,
    formSchema,
    hasBody: Boolean(jsonSchema || formSchema),
    contentType: jsonSchema ? "application/json" : formSchema ? "application/x-www-form-urlencoded" : null,
  };
}

export async function loadOpenApiSpec(specInput, baseUrl) {
  let doc = specInput;

  if (typeof specInput === "string" && /^https?:\/\//i.test(specInput)) {
    await assertSafeTarget(specInput);
    const { body } = await fetchTarget(specInput, { timeout: 12000 });
    doc = body;
  }

  doc = parseSpecRaw(doc);
  const origin = resolveServerOrigin(doc, baseUrl);
  const operations = [];

  for (const [pathTemplate, pathItem] of Object.entries(doc.paths || {})) {
    if (!pathItem || typeof pathItem !== "object") continue;

    const sharedParams = pathItem.parameters || [];

    for (const [method, op] of Object.entries(pathItem)) {
      if (!HTTP_METHODS.has(method) || !op || typeof op !== "object") continue;

      const parameters = [...sharedParams, ...(op.parameters || [])];
      const requestBody = extractRequestBody(op);

      operations.push({
        method: method.toUpperCase(),
        path: pathTemplate,
        operationId: op.operationId || `${method}-${pathTemplate}`,
        parameters,
        requestBody,
        summary: op.summary || "",
        urlTemplate: `${origin}${pathTemplate.startsWith("/") ? pathTemplate : `/${pathTemplate}`}`,
      });
    }
  }

  return {
    operations,
    title: doc.info?.title || "OpenAPI",
    version: doc.info?.version || doc.openapi || doc.swagger,
    origin,
  };
}

export function resolveOperationUrl(urlTemplate, paramValues = {}) {
  let path = urlTemplate;
  for (const [name, value] of Object.entries(paramValues)) {
    path = path.replaceAll(`{${name}}`, encodeURIComponent(String(value)));
  }
  path = path.replace(/\{([^}]+)\}/g, (_, name) => encodeURIComponent(paramValues[name] ?? "webmask"));
  return path;
}

export function buildJsonBodyFromSchema(schema, injectField, injectValue, fallback = {}) {
  if (!schema || schema.type !== "object" || !schema.properties) {
    return { ...fallback, [injectField || "payload"]: injectValue };
  }

  const body = {};
  for (const [key, prop] of Object.entries(schema.properties)) {
    if (key === injectField) {
      body[key] = injectValue;
    } else if (prop.type === "string") {
      body[key] = prop.example || "test";
    } else if (prop.type === "number" || prop.type === "integer") {
      body[key] = prop.example ?? 1;
    } else if (prop.type === "boolean") {
      body[key] = prop.example ?? true;
    } else if (prop.type === "array") {
      body[key] = [];
    } else if (prop.type === "object") {
      body[key] = {};
    }
  }

  if (injectField && !(injectField in body)) {
    body[injectField] = injectValue;
  }

  return body;
}
