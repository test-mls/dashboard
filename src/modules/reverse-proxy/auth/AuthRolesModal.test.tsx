import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import {
  type AuthorizationDraft,
  emptyAuthorizationDraft,
  newRoleDraft,
} from "@/modules/reverse-proxy/auth/authorization";
import AuthRolesModal from "@/modules/reverse-proxy/auth/AuthRolesModal";

vi.mock("@/contexts/UsersProvider", () => ({
  useUsers: () => ({ users: [] }),
}));

// The real selector needs the groups and peers providers; the modal only
// needs it to render and report changes.
vi.mock("@components/PeerGroupSelector", () => ({
  PeerGroupSelector: () => <div data-testid="group-selector" />,
}));

beforeAll(() => {
  vi.stubGlobal(
    "ResizeObserver",
    class {
      observe() {}
      unobserve() {}
      disconnect() {}
    },
  );
});

afterEach(() => cleanup());

function renderModal(
  props: Partial<React.ComponentProps<typeof AuthRolesModal>> = {},
) {
  const onSave = vi.fn();
  const current: AuthorizationDraft = {
    ...emptyAuthorizationDraft(),
    roles: [newRoleDraft({ name: "admin", tools: "*" })],
  };
  render(
    <AuthRolesModal
      open={true}
      onOpenChange={() => {}}
      current={current}
      isEnabled={false}
      headerAuthEnabled={false}
      headerAuthUsesAuthorization={false}
      onSave={onSave}
      onRemove={() => {}}
      {...props}
    />,
  );
  return { onSave };
}

describe("AuthRolesModal", () => {
  it("saves the edited draft", () => {
    const { onSave } = renderModal();
    fireEvent.click(screen.getByTestId("authz-add-role"));
    fireEvent.change(screen.getByTestId("authz-role-name-1"), {
      target: { value: "viewer" },
    });
    fireEvent.change(screen.getByTestId("authz-role-tools-1"), {
      target: { value: "list_*, get_ticket" },
    });
    fireEvent.click(screen.getByTestId("submit-roles"));

    expect(onSave).toHaveBeenCalledTimes(1);
    const saved = onSave.mock.calls[0][0] as AuthorizationDraft;
    expect(saved.roles.map((r) => r.name)).toEqual(["admin", "viewer"]);
    expect(saved.roles[1].tools).toBe("list_*, get_ticket");
  });

  it("blocks saving and explains an invalid role", () => {
    const { onSave } = renderModal();
    fireEvent.change(screen.getByTestId("authz-role-name-0"), {
      target: { value: "bad name" },
    });
    expect(screen.getByText(/letters, digits/)).toBeTruthy();
    const submit = screen.getByTestId("submit-roles") as HTMLButtonElement;
    expect(submit.disabled).toBe(true);
    fireEvent.click(submit);
    expect(onSave).not.toHaveBeenCalled();
  });

  it("offers API key roles only when header auth is enabled", () => {
    renderModal();
    expect(screen.queryByTestId("authz-api-key-roles")).toBeNull();
    cleanup();

    const { onSave } = renderModal({ headerAuthEnabled: true });
    fireEvent.click(screen.getByRole("button", { name: "admin" }));
    fireEvent.click(screen.getByTestId("submit-roles"));
    const saved = onSave.mock.calls[0][0] as AuthorizationDraft;
    expect(saved.apiKeyRoles).toEqual(["admin"]);
  });

  it("shows the JWKS URL and public key for a saved JWT service", () => {
    renderModal({
      current: {
        ...emptyAuthorizationDraft(),
        roles: [newRoleDraft({ name: "admin" })],
        forwarding: "jwt",
      },
      isEnabled: true,
      domain: "tickets.acme.io",
      publicKeyPem: "-----BEGIN PUBLIC KEY-----\nAAA\n-----END PUBLIC KEY-----\n",
      keyId: "kid1",
    });
    expect(
      screen.getByText(
        "https://tickets.acme.io/.well-known/netbird/jwks.json",
      ),
    ).toBeTruthy();
    expect(screen.getByText(/kid kid1/)).toBeTruthy();
    expect(screen.getByTestId("authz-preview").textContent).toMatch(
      /mcp_tools/,
    );
  });
});
