import React, { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react';
import { useAuth } from '../auth/AuthContext';
import {
  initialSecurityFindings,
  initialProtectedAssets,
  initialWafRules,
  initialZeroTrustPolicies,
  initialDsarRequests,
  initialConsentRecords,
  initialFrameworks,
  initialAlerts,
  initialIntegrations,
  initialInventoryAssets,
  initialEnclaveActivityEvents,
  mockSecurityEvents,
} from '../../services/mockSecurityApi';
import {
  SecurityFinding,
  ProtectedAsset,
  WafRule,
  ZeroTrustPolicy,
  DsarRequest,
  ConsentRecord,
  ComplianceFramework,
  AlertIncident,
  IntegrationConnector,
  InventoryAsset,
  EnclaveActivityEvent,
} from '../../types';

export interface SecurityState {
  findings: SecurityFinding[];
  protectedAssets: ProtectedAsset[];
  wafRules: WafRule[];
  zeroTrustPolicies: ZeroTrustPolicy[];
  dsarRequests: DsarRequest[];
  consentRecords: ConsentRecord[];
  complianceFrameworks: ComplianceFramework[];
  alerts: AlertIncident[];
  integrations: IntegrationConnector[];
  inventoryAssets: InventoryAsset[];
  enclaveActivityEvents: EnclaveActivityEvent[];
  securityEvents: typeof mockSecurityEvents;
}

export type SecurityCollectionKey = keyof SecurityState;

type Updater<T> = T | ((previous: T) => T);

interface SecurityDataContextType {
  state: SecurityState;
  isLoading: boolean;
  error: string | null;
  refresh: () => Promise<void>;
  updateCollection: <K extends SecurityCollectionKey>(key: K, updater: Updater<SecurityState[K]>) => void;
}

const seedState: SecurityState = {
  findings: initialSecurityFindings,
  protectedAssets: initialProtectedAssets,
  wafRules: initialWafRules,
  zeroTrustPolicies: initialZeroTrustPolicies,
  dsarRequests: initialDsarRequests,
  consentRecords: initialConsentRecords,
  complianceFrameworks: initialFrameworks,
  alerts: initialAlerts,
  integrations: initialIntegrations,
  inventoryAssets: initialInventoryAssets,
  enclaveActivityEvents: initialEnclaveActivityEvents,
  securityEvents: mockSecurityEvents,
};

const SecurityDataContext = createContext<SecurityDataContextType | undefined>(undefined);

function authHeaders(): HeadersInit {
  const token = sessionStorage.getItem('skyguard_auth_token');
  return {
    'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  };
}

export const SecurityDataProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { isAuthenticated, isLoading: isAuthLoading } = useAuth();
  const [state, setState] = useState<SecurityState>(seedState);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const stateRef = useRef(state);

  const setCurrentState = useCallback((next: SecurityState) => {
    stateRef.current = next;
    setState(next);
  }, []);

  const refresh = useCallback(async () => {
    if (!sessionStorage.getItem('skyguard_auth_token')) return;
    setIsLoading(true);
    setError(null);
    try {
      const response = await fetch('/api/security/state', { headers: authHeaders() });
      if (!response.ok) throw new Error(`Security state request failed (${response.status})`);
      const payload = await response.json();
      if (!payload?.state) throw new Error('Security state response was empty');
      const next = { ...seedState };
      for (const key of Object.keys(seedState) as SecurityCollectionKey[]) {
        if (Array.isArray(payload.state[key])) {
          (next as any)[key] = payload.state[key];
        }
      }
      setCurrentState(next);
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : 'Unable to load security state');
    } finally {
      setIsLoading(false);
    }
  }, [setCurrentState]);

  useEffect(() => {
    if (!isAuthLoading && isAuthenticated) void refresh();
  }, [isAuthLoading, isAuthenticated, refresh]);

  const persistCollection = useCallback(async <K extends SecurityCollectionKey>(key: K, items: SecurityState[K]) => {
    try {
      const response = await fetch(`/api/security/${key}`, {
        method: 'PUT',
        headers: authHeaders(),
        body: JSON.stringify(items),
      });
      if (!response.ok) throw new Error(`Saving ${key} failed (${response.status})`);
    } catch (saveError) {
      setError(saveError instanceof Error ? saveError.message : `Unable to save ${key}`);
    }
  }, []);

  const updateCollection = useCallback(<K extends SecurityCollectionKey>(key: K, updater: Updater<SecurityState[K]>) => {
    const current = stateRef.current;
    const nextItems = typeof updater === 'function'
      ? (updater as (previous: SecurityState[K]) => SecurityState[K])(current[key])
      : updater;
    const nextState = { ...current, [key]: nextItems };
    setCurrentState(nextState);
    void persistCollection(key, nextItems);
  }, [persistCollection, setCurrentState]);

  const value = useMemo(() => ({ state, isLoading, error, refresh, updateCollection }), [state, isLoading, error, refresh, updateCollection]);

  return <SecurityDataContext.Provider value={value}>{children}</SecurityDataContext.Provider>;
};

export const useSecurityData = () => {
  const context = useContext(SecurityDataContext);
  if (!context) throw new Error('useSecurityData must be used within a SecurityDataProvider');
  return context;
};
