import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import type { Group } from "@/interfaces/Group";
import {
  type AuthorizationDraft,
  emptyAuthorizationDraft,
  newRoleDraft,
} from "@/modules/reverse-proxy/auth/authorization";
import AuthRolesModal from "@/modules/reverse-proxy/auth/AuthRolesModal";

vi.mock("@/contexts/UsersProvider", () => ({
  useUsers: () => ({ users: [] }),
}));

// Each selector instance gets buttons that add a group the way the real
// PeerGroupSelector does: through a functional update.
vi.mock("@components/PeerGroupSelector", () => ({
  PeerGroupSelector: ({
    onChange,
    values,
  }: {
    values: Group[];
    onChange: React.Dispatch<React.SetStateAction<Group[]>>;
  }) => (
    <div>
      <span data-testid="selected">{values.map((g) => g.name).join(",")}</span>
      {["Users", "Coders"].map((name) => (
        <button
          key={name}
          data-testid={`pick-${name}`}
          onClick={() => onChange((prev) => [...prev, { name } as Group])}
        />
      ))}
    </div>
  ),
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

describe("AuthRolesModal role groups", () => {
  it("keeps each role's groups separate", () => {
    const onSave = vi.fn();
    const current: AuthorizationDraft = {
      ...emptyAuthorizationDraft(),
      roles: [newRoleDraft({ name: "Admins" })],
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
      />,
    );
    fireEvent.click(screen.getAllByTestId("pick-Coders")[0]);
    fireEvent.click(screen.getByTestId("authz-add-role"));
    fireEvent.change(screen.getByTestId("authz-role-name-1"), {
      target: { value: "Users" },
    });
    fireEvent.click(screen.getAllByTestId("pick-Users")[1]);
    fireEvent.click(screen.getByTestId("submit-roles"));

    const saved = onSave.mock.calls[0][0] as AuthorizationDraft;
    expect(saved.roles.map((r) => r.groups.map((g) => g.name))).toEqual([
      ["Coders"],
      ["Users"],
    ]);
  });
});
