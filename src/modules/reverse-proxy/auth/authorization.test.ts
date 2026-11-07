import { describe, expect, it } from "vitest";
import {
  type AuthorizationDraft,
  draftFromConfig,
  draftToConfig,
  emptyAuthorizationDraft,
  hasAuthorizationErrors,
  headerAuthUsesAuthorization,
  isValidToolPattern,
  jwksUrl,
  newRoleDraft,
  parseTools,
  upstreamPreview,
  validateAuthorization,
} from "./authorization";

function draft(overrides?: Partial<AuthorizationDraft>): AuthorizationDraft {
  return {
    ...emptyAuthorizationDraft(),
    roles: [
      newRoleDraft({ name: "admin", tools: "*" }),
      newRoleDraft({ name: "viewer", tools: "list_*, get_ticket" }),
    ],
    ...overrides,
  };
}

const noHeaderAuth = { headerAuthUsesAuthorization: false };

describe("parseTools", () => {
  it("splits on commas and whitespace, trims and dedupes", () => {
    expect(parseTools(" list_*, get_ticket\nget_ticket  delete ")).toEqual([
      "list_*",
      "get_ticket",
      "delete",
    ]);
    expect(parseTools("  ,  ")).toEqual([]);
  });
});

describe("isValidToolPattern", () => {
  it("accepts names, globs and namespaced tools", () => {
    expect(isValidToolPattern("list_tickets")).toBe(true);
    expect(isValidToolPattern("*")).toBe(true);
    expect(isValidToolPattern("git/*/read")).toBe(true);
  });

  it("rejects spaces, other characters and too many stars", () => {
    expect(isValidToolPattern("bad tool")).toBe(false);
    expect(isValidToolPattern("tool;rm")).toBe(false);
    expect(isValidToolPattern("*a*b*c*d*")).toBe(false);
    expect(isValidToolPattern("a".repeat(129))).toBe(false);
  });
});

describe("validateAuthorization", () => {
  it("accepts a valid draft", () => {
    const errors = validateAuthorization(draft(), noHeaderAuth);
    expect(hasAuthorizationErrors(errors)).toBe(false);
  });

  it("flags missing, malformed and duplicate role names on the right row", () => {
    const errors = validateAuthorization(
      draft({
        roles: [
          newRoleDraft({ name: "" }),
          newRoleDraft({ name: "admin,viewer" }),
          newRoleDraft({ name: "ops" }),
          newRoleDraft({ name: "ops" }),
        ],
      }),
      noHeaderAuth,
    );
    expect(errors.roles[0]).toMatch(/name/);
    expect(errors.roles[1]).toMatch(/letters, digits/);
    expect(errors.roles[2]).toBeUndefined();
    expect(errors.roles[3]).toMatch(/already used/);
    expect(hasAuthorizationErrors(errors)).toBe(true);
  });

  it("flags an invalid tool pattern", () => {
    const errors = validateAuthorization(
      draft({ roles: [newRoleDraft({ name: "a", tools: "ok, not ok!" })] }),
      noHeaderAuth,
    );
    expect(errors.roles[0]).toMatch(/"ok!"|"not"/);
  });

  it("requires API key roles to be defined roles", () => {
    const errors = validateAuthorization(
      draft({ apiKeyRoles: ["ghost"] }),
      noHeaderAuth,
    );
    expect(errors.apiKeyRoles).toMatch(/ghost/);
  });

  it("rejects a JWT in Authorization when header auth checks Authorization", () => {
    const jwtInAuthorization = draft({
      forwarding: "jwt",
      jwtHeader: "Authorization",
    });
    expect(
      validateAuthorization(jwtInAuthorization, {
        headerAuthUsesAuthorization: true,
      }).jwtHeader,
    ).toBeDefined();
    expect(
      validateAuthorization(jwtInAuthorization, noHeaderAuth).jwtHeader,
    ).toBeUndefined();
    expect(
      validateAuthorization(draft({ forwarding: "jwt" }), {
        headerAuthUsesAuthorization: true,
      }).jwtHeader,
    ).toBeUndefined();
  });
});

describe("headerAuthUsesAuthorization", () => {
  it("only counts enabled Authorization headers, case-insensitively", () => {
    expect(
      headerAuthUsesAuthorization([
        { enabled: true, header: "authorization", value: "" },
      ]),
    ).toBe(true);
    expect(
      headerAuthUsesAuthorization([
        { enabled: false, header: "Authorization", value: "" },
        { enabled: true, header: "X-Api-Key", value: "" },
      ]),
    ).toBe(false);
    expect(headerAuthUsesAuthorization(undefined)).toBe(false);
  });
});

describe("config conversion", () => {
  it("round-trips through the API shape without read-only fields", () => {
    const config = draftToConfig(
      draft({ apiKeyRoles: ["viewer"], enforceMcp: true, forwarding: "jwt" }),
      (role) => (role.name === "admin" ? ["grp-ops"] : ["grp-eng"]),
    );
    expect(config).toEqual({
      roles: [
        { name: "admin", groups: ["grp-ops"], mcp_tools: ["*"] },
        { name: "viewer", groups: ["grp-eng"], mcp_tools: ["list_*", "get_ticket"] },
      ],
      api_key_roles: ["viewer"],
      enforce_mcp: true,
      forwarding: "jwt",
      jwt_header: "X-NetBird-Identity",
    });

    const back = draftFromConfig(
      { ...config, public_key_pem: "PEM", key_id: "kid" },
      [{ id: "grp-ops", name: "ops" }],
    );
    expect(back.roles.map((r) => r.name)).toEqual(["admin", "viewer"]);
    expect(back.roles[0].groups).toEqual([{ id: "grp-ops", name: "ops" }]);
    expect(back.roles[1].groups).toEqual([{ id: "grp-eng", name: "grp-eng" }]);
    expect(back.roles[1].tools).toBe("list_*, get_ticket");
    expect(back.forwarding).toBe("jwt");
    expect(back.enforceMcp).toBe(true);
  });

  it("omits jwt_header in headers mode", () => {
    const config = draftToConfig(draft(), () => []);
    expect(config.jwt_header).toBeUndefined();
    expect(config.forwarding).toBe("headers");
  });

  it("starts with one empty role when there is no config", () => {
    const d = draftFromConfig(undefined, []);
    expect(d.roles).toHaveLength(1);
    expect(d.forwarding).toBe("headers");
  });
});

describe("display helpers", () => {
  it("builds the JWKS URL on the service domain", () => {
    expect(jwksUrl("tickets.acme.io")).toBe(
      "https://tickets.acme.io/.well-known/netbird/jwks.json",
    );
  });

  it("describes what the upstream receives", () => {
    expect(upstreamPreview("headers", "X-NetBird-Identity").items).toContain(
      "X-NetBird-Roles",
    );
    const jwt = upstreamPreview("jwt", "Authorization");
    expect(jwt.label).toMatch(/Bearer/);
    expect(jwt.items).toContain("mcp_tools");
  });
});
