import Button from "@components/Button";
import { Callout } from "@components/Callout";
import CopyToClipboardText from "@components/CopyToClipboardText";
import FancyToggleSwitch from "@components/FancyToggleSwitch";
import HelpText from "@components/HelpText";
import { Input } from "@components/Input";
import { Label } from "@components/Label";
import { Modal, ModalClose, ModalContent } from "@components/modal/Modal";
import ModalHeader from "@components/modal/ModalHeader";
import { PeerGroupSelector } from "@components/PeerGroupSelector";
import { RadioGroup, RadioGroupItem } from "@components/RadioGroup";
import { cn } from "@utils/helpers";
import {
  KeyRoundIcon,
  MinusCircleIcon,
  PlusIcon,
  ShieldCheckIcon,
} from "lucide-react";
import React, { useMemo, useReducer } from "react";
import { useUsers } from "@/contexts/UsersProvider";
import { useHasChanges } from "@/hooks/useHasChanges";
import type { Group } from "@/interfaces/Group";
import type { AuthorizationJwtHeader } from "@/interfaces/ReverseProxy";
import {
  type AuthorizationDraft,
  hasAuthorizationErrors,
  jwksUrl,
  newRoleDraft,
  type RoleDraft,
  upstreamPreview,
  validateAuthorization,
} from "@/modules/reverse-proxy/auth/authorization";

type Action =
  | { type: "addRole" }
  | { type: "removeRole"; index: number }
  | { type: "updateRole"; index: number; updates: Partial<RoleDraft> }
  | { type: "set"; updates: Partial<Omit<AuthorizationDraft, "roles">> };

function reducer(
  state: AuthorizationDraft,
  action: Action,
): AuthorizationDraft {
  switch (action.type) {
    case "addRole":
      return { ...state, roles: [...state.roles, newRoleDraft()] };
    case "removeRole": {
      const removed = state.roles[action.index]?.name.trim();
      const roles =
        state.roles.length === 1
          ? [newRoleDraft()]
          : state.roles.filter((_, i) => i !== action.index);
      return {
        ...state,
        roles,
        apiKeyRoles: state.apiKeyRoles.filter((r) => r !== removed),
      };
    }
    case "updateRole": {
      const previous = state.roles[action.index]?.name.trim();
      const roles = state.roles.map((r, i) =>
        i === action.index ? { ...r, ...action.updates } : r,
      );
      const renamed = action.updates.name?.trim();
      const apiKeyRoles =
        renamed !== undefined && previous && renamed !== previous
          ? state.apiKeyRoles.map((r) => (r === previous ? renamed : r))
          : state.apiKeyRoles;
      return { ...state, roles, apiKeyRoles };
    }
    case "set":
      return { ...state, ...action.updates };
  }
}

type Props = {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  current: AuthorizationDraft;
  isEnabled: boolean;
  /** Whether header (API key) auth is enabled on the service. */
  headerAuthEnabled: boolean;
  /** Whether an enabled header auth checks the Authorization header. */
  headerAuthUsesAuthorization: boolean;
  /** The saved service domain, used for the JWKS URL. */
  domain?: string;
  /** Read-only key material returned by the API for a saved JWT service. */
  publicKeyPem?: string;
  keyId?: string;
  onSave: (draft: AuthorizationDraft) => void;
  onRemove: () => void;
};

export default function AuthRolesModal({
  open,
  onOpenChange,
  current,
  isEnabled,
  headerAuthEnabled,
  headerAuthUsesAuthorization,
  domain,
  publicKeyPem,
  keyId,
  onSave,
  onRemove,
}: Readonly<Props>) {
  const [draft, dispatch] = useReducer(reducer, current);
  const { hasChanges } = useHasChanges([draft]);
  const errors = useMemo(
    () => validateAuthorization(draft, { headerAuthUsesAuthorization }),
    [draft, headerAuthUsesAuthorization],
  );
  const canSave = !hasAuthorizationErrors(errors);
  const roleNames = draft.roles.map((r) => r.name.trim()).filter(Boolean);

  const handleSave = () => {
    if (!canSave) return;
    onOpenChange(false);
    onSave(draft);
  };

  const handleRemove = () => {
    onOpenChange(false);
    onRemove();
  };

  return (
    <Modal open={open} onOpenChange={onOpenChange}>
      <ModalContent maxWidthClass="max-w-2xl">
        <ModalHeader
          title="Roles & Authorization"
          description="Map groups to roles, limit which MCP tools each role may call, and choose how the identity reaches your service."
        />

        <div className="px-8 flex flex-col gap-6">
          <div>
            <Label>Roles</Label>
            <HelpText>
              A user gets every role whose groups include one of their groups.
              MCP tools accept exact names or patterns such as{" "}
              <code>list_*</code>; <code>*</code> allows every tool.
            </HelpText>
            <div className="flex flex-col gap-3" data-testid="authz-roles">
              {draft.roles.map((role, index) => (
                <RoleRow
                  key={role.id}
                  role={role}
                  index={index}
                  error={errors.roles[index]}
                  showRemove={draft.roles.length > 1}
                  onChange={(updates) =>
                    dispatch({ type: "updateRole", index, updates })
                  }
                  onRemove={() => dispatch({ type: "removeRole", index })}
                />
              ))}
            </div>
            <Button
              variant="dotted"
              className="w-full mt-3"
              size="sm"
              onClick={() => dispatch({ type: "addRole" })}
              data-testid="authz-add-role"
            >
              <PlusIcon size={14} />
              Add Role
            </Button>
            {errors.form && (
              <p className="text-xs text-red-500 mt-2">{errors.form}</p>
            )}
          </div>

          {headerAuthEnabled && (
            <div>
              <Label>API Key Roles</Label>
              <HelpText>
                Callers that authenticate with an HTTP header have no groups.
                Pick the roles they get.
              </HelpText>
              <RoleChips
                roles={roleNames}
                selected={draft.apiKeyRoles}
                onChange={(apiKeyRoles) =>
                  dispatch({ type: "set", updates: { apiKeyRoles } })
                }
              />
              {errors.apiKeyRoles && (
                <p className="text-xs text-red-500 mt-2">
                  {errors.apiKeyRoles}
                </p>
              )}
            </div>
          )}

          <FancyToggleSwitch
            value={draft.enforceMcp}
            onChange={(enforceMcp) =>
              dispatch({ type: "set", updates: { enforceMcp } })
            }
            data-testid="authz-enforce-mcp"
            label={
              <>
                <ShieldCheckIcon size={15} />
                Enforce MCP Tool Permissions
              </>
            }
            helpText="The proxy blocks MCP tool calls the caller's roles do not allow, before they reach your server."
          />

          <ForwardingSection
            draft={draft}
            jwtHeaderError={errors.jwtHeader}
            domain={domain}
            publicKeyPem={publicKeyPem}
            keyId={keyId}
            onChange={(updates) => dispatch({ type: "set", updates })}
          />
        </div>

        <div className="px-8 flex gap-3 w-full justify-between mt-6">
          {isEnabled ? (
            <Button
              variant="danger-text"
              data-testid="remove-roles"
              onClick={handleRemove}
            >
              Remove
            </Button>
          ) : (
            <div />
          )}
          <div className="flex gap-3">
            <ModalClose asChild>
              <Button variant="secondary">Cancel</Button>
            </ModalClose>
            <Button
              variant="primary"
              onClick={handleSave}
              disabled={!canSave || (isEnabled && !hasChanges)}
              data-testid="submit-roles"
            >
              {isEnabled ? "Save" : "Add Roles"}
            </Button>
          </div>
        </div>
      </ModalContent>
    </Modal>
  );
}

type RoleRowProps = {
  role: RoleDraft;
  index: number;
  error?: string;
  showRemove: boolean;
  onChange: (updates: Partial<RoleDraft>) => void;
  onRemove: () => void;
};

function RoleRow({
  role,
  index,
  error,
  showRemove,
  onChange,
  onRemove,
}: Readonly<RoleRowProps>) {
  const { users } = useUsers();

  // PeerGroupSelector may pass a functional update; resolve it against this
  // row's groups so rows never overwrite each other.
  const setGroups: React.Dispatch<React.SetStateAction<Group[]>> = (next) =>
    onChange({
      groups: typeof next === "function" ? next(role.groups) : next,
    });

  return (
    <div
      className="rounded-md border border-nb-gray-900 bg-nb-gray-920/30 px-4 pt-2 pb-4 flex flex-col gap-2"
      data-testid={`authz-role-${index}`}
    >
      <div className="flex items-center justify-between h-6 mt-0.5">
        <span className="text-xs font-normal text-nb-gray-200 flex items-center gap-2">
          <KeyRoundIcon size={14} />
          {role.name.trim() ? role.name.trim() : `Role ${index + 1}`}
        </span>
        {showRemove && (
          <Button variant="danger-text" size="xs" onClick={onRemove}>
            <MinusCircleIcon size={12} />
            Remove
          </Button>
        )}
      </div>
      <Input
        customPrefix={<span className="min-w-[44px]">Name</span>}
        placeholder="e.g., admin"
        maxWidthClass="w-full"
        value={role.name}
        onChange={(e) => onChange({ name: e.target.value })}
        data-testid={`authz-role-name-${index}`}
      />
      <PeerGroupSelector
        values={role.groups}
        onChange={setGroups}
        users={users}
        hideAllGroup={true}
        placeholder="Groups that grant this role..."
      />
      <Input
        customPrefix={<span className="min-w-[44px]">Tools</span>}
        placeholder="e.g., list_*, get_ticket (empty: no MCP tools)"
        maxWidthClass="w-full"
        value={role.tools}
        onChange={(e) => onChange({ tools: e.target.value })}
        data-testid={`authz-role-tools-${index}`}
      />
      {error && <p className="text-xs text-red-500">{error}</p>}
    </div>
  );
}

type RoleChipsProps = {
  roles: string[];
  selected: string[];
  onChange: (selected: string[]) => void;
};

function RoleChips({ roles, selected, onChange }: Readonly<RoleChipsProps>) {
  if (roles.length === 0) {
    return (
      <p className="text-xs text-nb-gray-400">Name a role above first.</p>
    );
  }
  const toggle = (role: string) =>
    onChange(
      selected.includes(role)
        ? selected.filter((r) => r !== role)
        : [...selected, role],
    );
  return (
    <div className="flex flex-wrap gap-2" data-testid="authz-api-key-roles">
      {roles.map((role) => {
        const active = selected.includes(role);
        return (
          <button
            key={role}
            type="button"
            aria-pressed={active}
            onClick={() => toggle(role)}
            className={cn(
              "text-xs rounded-md border px-3 py-1.5 transition-all",
              active
                ? "border-netbird-400 bg-netbird-500/10 text-netbird-150"
                : "border-nb-gray-800 bg-nb-gray-920 text-nb-gray-300 hover:text-nb-gray-100",
            )}
          >
            {role}
          </button>
        );
      })}
    </div>
  );
}

type ForwardingSectionProps = {
  draft: AuthorizationDraft;
  jwtHeaderError?: string;
  domain?: string;
  publicKeyPem?: string;
  keyId?: string;
  onChange: (updates: Partial<Omit<AuthorizationDraft, "roles">>) => void;
};

function ForwardingSection({
  draft,
  jwtHeaderError,
  domain,
  publicKeyPem,
  keyId,
  onChange,
}: Readonly<ForwardingSectionProps>) {
  const preview = upstreamPreview(draft.forwarding, draft.jwtHeader);
  const isJwt = draft.forwarding === "jwt";

  return (
    <div className="flex flex-col gap-3">
      <div>
        <Label>Identity Forwarding</Label>
        <HelpText>How your service learns who is calling.</HelpText>
        <div data-testid="authz-forwarding">
          <RadioGroup
            value={draft.forwarding}
            onChange={(v) =>
              onChange({ forwarding: v as AuthorizationDraft["forwarding"] })
            }
          >
            <RadioGroupItem value="headers">Headers</RadioGroupItem>
            <RadioGroupItem value="jwt">Signed JWT</RadioGroupItem>
          </RadioGroup>
        </div>
      </div>

      {isJwt && (
        <div>
          <HelpText>JWT header</HelpText>
          <RadioGroup
            value={draft.jwtHeader}
            onChange={(v) => onChange({ jwtHeader: v as AuthorizationJwtHeader })}
          >
            <RadioGroupItem value="X-NetBird-Identity">
              X-NetBird-Identity
            </RadioGroupItem>
            <RadioGroupItem value="Authorization">
              Authorization: Bearer
            </RadioGroupItem>
          </RadioGroup>
          {jwtHeaderError && (
            <p className="text-xs text-red-500 mt-2">{jwtHeaderError}</p>
          )}
        </div>
      )}

      <div
        className="rounded-md border border-nb-gray-900 bg-nb-gray-920/30 px-4 py-3"
        data-testid="authz-preview"
      >
        <p className="text-xs text-nb-gray-300 mb-2">
          Your service receives: <span className="text-nb-gray-100">{preview.label}</span>
        </p>
        <div className="flex flex-wrap gap-1.5">
          {preview.items.map((item) => (
            <code
              key={item}
              className="text-[0.7rem] rounded bg-nb-gray-900 px-1.5 py-0.5 text-nb-gray-200"
            >
              {item}
            </code>
          ))}
        </div>
      </div>

      {isJwt && (
        <JwtKeyDetails domain={domain} publicKeyPem={publicKeyPem} keyId={keyId} />
      )}

      {!isJwt && (
        <Callout variant="warning">
          Headers can be forged by anyone who reaches your service without
          going through NetBird. Keep the service reachable only through the
          proxy, or use a signed JWT.
        </Callout>
      )}
    </div>
  );
}

function JwtKeyDetails({
  domain,
  publicKeyPem,
  keyId,
}: Readonly<{ domain?: string; publicKeyPem?: string; keyId?: string }>) {
  if (!publicKeyPem || !domain) {
    return (
      <Callout variant="info">
        The verification key is generated when you save the service. Reopen
        this dialog afterwards to copy the JWKS URL and public key.
      </Callout>
    );
  }
  return (
    <div className="flex flex-col gap-3" data-testid="authz-jwt-keys">
      <div>
        <HelpText>JWKS URL</HelpText>
        <KeyBlock value={jwksUrl(domain)} message="JWKS URL copied">
          {jwksUrl(domain)}
        </KeyBlock>
      </div>
      <div>
        <HelpText>Public key{keyId ? ` (kid ${keyId})` : ""}</HelpText>
        <KeyBlock value={publicKeyPem} message="Public key copied">
          <span className="whitespace-pre">{publicKeyPem.trim()}</span>
        </KeyBlock>
      </div>
    </div>
  );
}

function KeyBlock({
  value,
  message,
  children,
}: Readonly<{ value: string; message: string; children: React.ReactNode }>) {
  return (
    <div className="rounded-md border border-nb-gray-900 bg-nb-gray-920/30 px-4 py-3 font-mono text-xs text-nb-gray-200 overflow-x-auto">
      <CopyToClipboardText
        textToCopy={value}
        message={message}
        alwaysShowIcon={true}
      >
        {children}
      </CopyToClipboardText>
    </div>
  );
}
