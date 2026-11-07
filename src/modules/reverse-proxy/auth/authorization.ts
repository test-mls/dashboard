import type { Group } from "@/interfaces/Group";
import type {
  AuthorizationForwarding,
  AuthorizationJwtHeader,
  HeaderAuthConfig,
  ServiceAuthorizationConfig,
} from "@/interfaces/ReverseProxy";

// These rules mirror the management server's validation in
// proxy/appauthz/validate.go so the form can explain a problem before save.
const ROLE_NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$/;
const TOOL_PATTERN = /^[A-Za-z0-9_.*/:-]{1,128}$/;
const MAX_STARS_PER_TOOL = 4;
export const MAX_ROLES = 64;
export const MAX_TOOLS_PER_ROLE = 256;

export const JWT_HEADER_DEFAULT: AuthorizationJwtHeader = "X-NetBird-Identity";
export const JWKS_PATH = "/.well-known/netbird/jwks.json";

export interface RoleDraft {
  id: string;
  name: string;
  groups: Group[];
  /** Comma or whitespace separated MCP tool names or patterns. */
  tools: string;
}

export interface AuthorizationDraft {
  roles: RoleDraft[];
  apiKeyRoles: string[];
  enforceMcp: boolean;
  forwarding: AuthorizationForwarding;
  jwtHeader: AuthorizationJwtHeader;
}

export interface AuthorizationErrors {
  /** Per-role message, aligned with draft.roles. */
  roles: (string | undefined)[];
  apiKeyRoles?: string;
  jwtHeader?: string;
  form?: string;
}

let roleCounter = 0;

export function newRoleDraft(overrides?: Partial<RoleDraft>): RoleDraft {
  roleCounter += 1;
  return {
    id: `role-${roleCounter}`,
    name: "",
    groups: [],
    tools: "",
    ...overrides,
  };
}

export function emptyAuthorizationDraft(): AuthorizationDraft {
  return {
    roles: [newRoleDraft()],
    apiKeyRoles: [],
    enforceMcp: false,
    forwarding: "headers",
    jwtHeader: JWT_HEADER_DEFAULT,
  };
}

/** Splits a tools field into unique, trimmed entries. */
export function parseTools(text: string): string[] {
  const seen = new Set<string>();
  for (const part of text.split(/[\s,]+/)) {
    const tool = part.trim();
    if (tool) seen.add(tool);
  }
  return [...seen];
}

export function isValidToolPattern(tool: string): boolean {
  if (!TOOL_PATTERN.test(tool)) return false;
  return (tool.match(/\*/g) ?? []).length <= MAX_STARS_PER_TOOL;
}

/**
 * Reports whether an enabled header auth checks the Authorization header.
 * The proxy strips that header before forwarding, so a JWT placed in it
 * would never arrive.
 */
export function headerAuthUsesAuthorization(
  headers: HeaderAuthConfig[] | undefined,
): boolean {
  return (headers ?? []).some(
    (h) => h.enabled && h.header.toLowerCase() === "authorization",
  );
}

export function validateAuthorization(
  draft: AuthorizationDraft,
  opts: { headerAuthUsesAuthorization: boolean },
): AuthorizationErrors {
  const errors: AuthorizationErrors = { roles: [] };
  const names = new Map<string, number>();

  if (draft.roles.length > MAX_ROLES) {
    errors.form = `At most ${MAX_ROLES} roles are allowed.`;
  }

  draft.roles.forEach((role, i) => {
    errors.roles[i] = validateRole(role, names, i);
  });

  const defined = new Set(draft.roles.map((r) => r.name.trim()));
  const unknown = draft.apiKeyRoles.find((r) => !defined.has(r));
  if (unknown !== undefined) {
    errors.apiKeyRoles = `"${unknown}" is not a role defined above.`;
  }

  if (
    draft.forwarding === "jwt" &&
    draft.jwtHeader === "Authorization" &&
    opts.headerAuthUsesAuthorization
  ) {
    errors.jwtHeader =
      "Header auth already checks Authorization, and the proxy removes that header before forwarding. Send the JWT in X-NetBird-Identity instead.";
  }
  return errors;
}

function validateRole(
  role: RoleDraft,
  names: Map<string, number>,
  index: number,
): string | undefined {
  const name = role.name.trim();
  if (!ROLE_NAME_PATTERN.test(name)) {
    return name
      ? "Use letters, digits, '_', '.', ':' or '-', starting with a letter or digit (max 64)."
      : "Give the role a name.";
  }
  if (names.has(name)) return `"${name}" is already used by another role.`;
  names.set(name, index);

  const tools = parseTools(role.tools);
  if (tools.length > MAX_TOOLS_PER_ROLE) {
    return `At most ${MAX_TOOLS_PER_ROLE} MCP tools per role.`;
  }
  const badTool = tools.find((t) => !isValidToolPattern(t));
  if (badTool !== undefined) return `"${badTool}" is not a valid MCP tool name.`;
  return undefined;
}

export function hasAuthorizationErrors(errors: AuthorizationErrors): boolean {
  return (
    !!errors.form ||
    !!errors.apiKeyRoles ||
    !!errors.jwtHeader ||
    errors.roles.some((e) => !!e)
  );
}

/** Builds a draft from the saved config, resolving group IDs to groups. */
export function draftFromConfig(
  config: ServiceAuthorizationConfig | undefined,
  allGroups: Group[] | undefined,
): AuthorizationDraft {
  if (!config) return emptyAuthorizationDraft();
  const roles = (config.roles ?? []).map((r) =>
    newRoleDraft({
      name: r.name,
      groups: (r.groups ?? []).map(
        (id) => allGroups?.find((g) => g.id === id) ?? { id, name: id },
      ),
      tools: (r.mcp_tools ?? []).join(", "),
    }),
  );
  return {
    roles: roles.length > 0 ? roles : [newRoleDraft()],
    apiKeyRoles: config.api_key_roles ?? [],
    enforceMcp: config.enforce_mcp ?? false,
    forwarding: config.forwarding ?? "headers",
    jwtHeader: config.jwt_header ?? JWT_HEADER_DEFAULT,
  };
}

/**
 * Builds the API payload. groupIds resolves a role's groups to IDs once new
 * groups have been created; read-only fields are never sent back.
 */
export function draftToConfig(
  draft: AuthorizationDraft,
  groupIds: (role: RoleDraft) => string[],
): ServiceAuthorizationConfig {
  const config: ServiceAuthorizationConfig = {
    roles: draft.roles.map((r) => ({
      name: r.name.trim(),
      groups: groupIds(r),
      mcp_tools: parseTools(r.tools),
    })),
    api_key_roles: draft.apiKeyRoles,
    enforce_mcp: draft.enforceMcp,
    forwarding: draft.forwarding,
  };
  if (draft.forwarding === "jwt") config.jwt_header = draft.jwtHeader;
  return config;
}

export function jwksUrl(domain: string): string {
  return `https://${domain}${JWKS_PATH}`;
}

/** Describes what the upstream receives, for the read-only preview. */
export function upstreamPreview(
  forwarding: AuthorizationForwarding,
  jwtHeader: AuthorizationJwtHeader,
): { label: string; items: string[] } {
  if (forwarding === "jwt") {
    return {
      label:
        jwtHeader === "Authorization"
          ? "Authorization: Bearer <JWT> with claims"
          : `${jwtHeader}: <JWT> with claims`,
      items: [
        "sub",
        "email",
        "groups",
        "roles",
        "mcp_tools",
        "auth_method",
        "iss",
        "aud",
        "exp",
      ],
    };
  }
  return {
    label: "Headers",
    items: [
      "X-NetBird-User",
      "X-NetBird-User-Id",
      "X-NetBird-Groups",
      "X-NetBird-Roles",
      "X-NetBird-Auth-Method",
    ],
  };
}
