import {
  AlertIncident,
  InventoryAsset,
  SecurityApiKey,
  WafRule,
  AuditLogRecord,
  VaultItem,
  VaultItemType,
  VaultDigestSummary,
} from '../types';

const AUTH_TOKEN_KEY = 'skyguard_auth_token';

export function getAuthToken(): string | null {
  if (typeof window === 'undefined') return null;
  return localStorage.getItem(AUTH_TOKEN_KEY) || sessionStorage.getItem(AUTH_TOKEN_KEY);
}

export function setAuthToken(token: string): void {
  if (typeof window === 'undefined') return;
  localStorage.setItem(AUTH_TOKEN_KEY, token);
  sessionStorage.setItem(AUTH_TOKEN_KEY, token);
}

export function clearAuthToken(): void {
  if (typeof window === 'undefined') return;
  localStorage.removeItem(AUTH_TOKEN_KEY);
  sessionStorage.removeItem(AUTH_TOKEN_KEY);
}

export function getAuthHeaders(extraHeaders?: HeadersInit): HeadersInit {
  const token = getAuthToken();
  return {
    'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...(extraHeaders || {}),
  };
}

export function authFetch(url: string, options?: RequestInit): Promise<Response> {
  return fetch(url, {
    ...options,
    headers: getAuthHeaders(options?.headers),
  });
}

async function apiRequest<T>(url: string, options?: RequestInit): Promise<T> {
  const res = await authFetch(url, options);
  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error || `API request failed (${res.status})`);
  }
  return data as T;
}

export const skyguardApi = {
  // Vault & File/Email Ingestion
  getVaultItems: () =>
    apiRequest<{
      success: boolean;
      count: number;
      items: VaultItem[];
      totalProtected: number;
      quarantinedCount: number;
    }>('/api/vault/items'),

  uploadVaultItem: (payload: {
    title?: string;
    type?: VaultItemType;
    content?: string;
    fileBase64?: string;
    fileName?: string;
    fileSize?: string;
    mimeType?: string;
    workspaceId?: string;
    uploadedBy?: string;
    monitoredChannels?: string[];
  }) =>
    apiRequest<{
      success: boolean;
      message: string;
      item: VaultItem;
      digestSummary: VaultDigestSummary;
    }>('/api/vault/upload', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  rescanVaultItem: (id: string) =>
    apiRequest<{
      success: boolean;
      message: string;
      item: VaultItem;
      digestSummary?: VaultDigestSummary;
    }>(`/api/vault/scan/${encodeURIComponent(id)}`, {
      method: 'POST',
    }),

  shredVaultItem: (id: string) =>
    apiRequest<{
      success: boolean;
      message: string;
      removedId: string;
    }>(`/api/vault/items/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    }),

  downloadVaultItem: async (id: string, fallbackFileName: string) => {
    const token = getAuthToken();
    const res = await fetch(`/api/vault/items/${encodeURIComponent(id)}/download`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    });
    if (!res.ok) {
      throw new Error(`Failed to download saved vault payload (${res.status})`);
    }
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = fallbackFileName || `${id}.txt`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  },

  // Platform API Keys
  createApiKey: (payload: { name: string; role: SecurityApiKey['role'] }) =>
    apiRequest<{ success: boolean; key: SecurityApiKey; rawSecret: string }>('/api/platform/apikeys', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  revokeApiKey: (id: string) =>
    apiRequest<{ success: boolean; keyId: string }>(`/api/platform/apikeys/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    }),

  // Security Center (WAF & Remediation)
  createWafRule: (payload: { name: string; type: WafRule['type']; action: WafRule['action'] }) =>
    apiRequest<{ success: boolean; rule: WafRule }>('/api/security/waf-rules', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  remediateFinding: (findingId: string, title: string) =>
    apiRequest<{ success: boolean; findingId: string; remediationHash: string }>('/api/security/remediate', {
      method: 'POST',
      body: JSON.stringify({ findingId, title }),
    }),

  // Alerts & Incident Operations
  createAlert: (payload: {
    title: string;
    severity: AlertIncident['severity'];
    status: AlertIncident['status'];
    source: string;
    affectedAsset: string;
    assignedTo: string | null;
  }) =>
    apiRequest<{ success: boolean; alert: AlertIncident }>('/api/alerts', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  updateAlertStatus: (id: string, status: AlertIncident['status'], action?: string) =>
    apiRequest<{ success: boolean; id: string; status: AlertIncident['status']; evidenceDigest: string }>(
      `/api/alerts/${encodeURIComponent(id)}`,
      {
        method: 'PATCH',
        body: JSON.stringify({ status, action }),
      }
    ),

  // Assets Inventory
  registerAsset: (payload: {
    name: string;
    category: InventoryAsset['category'];
    identifier: string;
    environment: InventoryAsset['environment'];
  }) =>
    apiRequest<{ success: boolean; asset: InventoryAsset }>('/api/assets', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  // Compliance Evidence Signing
  signComplianceEvidence: (payload: { frameworkId: string; frameworkName: string; version: string; score: number }) =>
    apiRequest<{ success: boolean; signature: string; generatedAt: string }>('/api/compliance/evidence', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  // White-Label Config & Proposal
  saveWhiteLabelConfig: (config: Record<string, any>) =>
    apiRequest<{ success: boolean; config: Record<string, any> }>('/api/whitelabel', {
      method: 'PUT',
      body: JSON.stringify(config),
    }),

  submitWhiteLabelProposal: (payload: {
    name: string;
    email: string;
    company: string;
    tier: 'base' | 'enterprise';
    addons: string[];
    notes: string;
    brandPreview: { brandName: string; customDomain: string; primaryColor: string };
  }) =>
    apiRequest<{ success: boolean; proposal: any }>('/api/whitelabel/proposal', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  // Workspaces & Audit Logs
  createWorkspace: (payload: {
    name: string;
    displayName: string;
    apexDomain: string;
    tier: string;
    environment: string;
    description: string;
  }) =>
    apiRequest<{ success: boolean; workspaceId: string }>('/api/workspaces', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  postAuditRecord: (payload: {
    workspaceId?: string;
    userId?: string;
    action: string;
    entity: string;
    entityId: string;
    metadata?: Record<string, any>;
  }) =>
    apiRequest<{ success: boolean; record: AuditLogRecord }>('/api/audit', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  toggleWafRule: (id: string, status: WafRule['status']) =>
    apiRequest<{ success: boolean; id: string; status: WafRule['status'] }>(
      `/api/security/waf-rules/${encodeURIComponent(id)}`,
      {
        method: 'PATCH',
        body: JSON.stringify({ status }),
      }
    ),

  createConsentRecord: (payload: {
    subjectEmail: string;
    subjectId?: string;
    purposes: string[];
    source: string;
    legalBasis: string;
  }) =>
    apiRequest<{ success: boolean; record: any }>('/api/privacy/consent', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  withdrawConsentRecord: (id: string, subjectEmail: string) =>
    apiRequest<{ success: boolean; id: string; status: string; timestamp: string; revocationHash: string }>(
      `/api/privacy/consent/${encodeURIComponent(id)}`,
      {
        method: 'PATCH',
        body: JSON.stringify({ status: 'withdrawn', subjectEmail }),
      }
    ),

  executeCryptoShred: (keyId: string) =>
    apiRequest<{
      success: boolean;
      certificateId: string;
      sha256Proof: string;
      message: string;
    }>('/api/privacy/shred', {
      method: 'POST',
      body: JSON.stringify({ keyId }),
    }),

  registerWebhookConnector: (payload: { name: string; url: string }) =>
    apiRequest<{ success: boolean; connector: any }>('/api/integrations/webhooks', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  getHealth: () =>
    apiRequest<any>('/api/health', {
      method: 'GET',
    }),
};
