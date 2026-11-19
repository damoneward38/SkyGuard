import React, { createContext, useContext, useState, useEffect } from 'react';
import { UserProfile, UserRole, UserSession } from '../../types';
import {
  getAuthToken,
  setAuthToken,
  clearAuthToken,
  authFetch,
} from '../../services/skyguardApi';

interface AuthContextType {
  user: UserProfile | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  sessions: UserSession[];
  login: (email: string, password?: string, role?: UserRole) => Promise<boolean>;
  signup: (data: {
    name: string;
    email: string;
    company: string;
    password?: string;
    plan?: 'basic' | 'pro' | 'enterprise' | 'whitelabel';
    role?: UserRole;
  }) => Promise<boolean>;
  logout: () => void;
  switchRole: (role: UserRole) => void;
  updatePlan: (plan: 'basic' | 'pro' | 'enterprise' | 'whitelabel') => void;
  verifyEmail: (code: string) => Promise<boolean>;
  requestPasswordReset: (email: string) => Promise<boolean>;
  completePasswordReset: (token: string, newPassword: string) => Promise<boolean>;
  toggleMfa: (enabled: boolean) => Promise<boolean>;
  revokeSession: (sessionId: string) => void;
  terminateOtherSessions: () => void;
  canAccessModule: (module: 'security_config' | 'alerts_incidents' | 'privacy_governance' | 'full_admin' | 'read_only') => boolean;
  canPerformWriteAction: () => boolean;
}

const INITIAL_SESSIONS: UserSession[] = [
  {
    id: 'ses_curr_99182',
    device: 'Apple MacBook Pro (M3 Max / ARM64)',
    browser: 'Chrome 128.0.6613.85 (Zero-Trust Enclave)',
    ipAddress: '194.26.29.110 (Frankfurt DC-01, DE)',
    location: 'Frankfurt, Germany',
    lastActive: 'Just now (Active Session)',
    isCurrent: true,
    trustedStatus: 'Hardware Enclave',
  },
  {
    id: 'ses_mob_44102',
    device: 'Apple iPhone 15 Pro (iOS 18.0)',
    browser: 'SkyGuard Mobile SecEnclave v4.2',
    ipAddress: '82.112.44.89 (Rome, IT)',
    location: 'Rome, Italy',
    lastActive: '24 minutes ago',
    isCurrent: false,
    trustedStatus: 'WebAuthn Bound',
  },
  {
    id: 'ses_desk_11209',
    device: 'Dell Precision Tower (Ubuntu 24.04 LTS)',
    browser: 'Firefox Developer Edition 129.0',
    ipAddress: '212.58.244.70 (London, UK)',
    location: 'London, United Kingdom',
    lastActive: '3 hours ago',
    isCurrent: false,
    trustedStatus: 'Hardware Enclave',
  },
];

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<UserProfile | null>(() => {
    try {
      if (typeof window === 'undefined') return null;
      if (sessionStorage.getItem('skyguard_logged_out') === 'true') {
        return null;
      }
      if (!getAuthToken()) {
        localStorage.removeItem('skyguard_auth_user');
        return null;
      }
      const saved = localStorage.getItem('skyguard_auth_user');
      if (saved) {
        return JSON.parse(saved);
      }
    } catch {
      return null;
    }
    return null;
  });
  const [sessions, setSessions] = useState<UserSession[]>(INITIAL_SESSIONS);
  const [isLoading, setIsLoading] = useState<boolean>(() => Boolean(typeof window !== 'undefined' && getAuthToken()));

  // Validate persisted bearer session against server on boot
  useEffect(() => {
    const token = getAuthToken();
    if (!token) {
      setIsLoading(false);
      return;
    }
    let active = true;
    authFetch('/api/auth/session')
      .then(async (res) => {
        if (!active) return;
        if (!res.ok) {
          clearAuthToken();
          localStorage.removeItem('skyguard_auth_user');
          setUser(null);
          return;
        }
        const data = await res.json();
        if (data?.authenticated && data?.user) {
          setUser({ ...data.user, activeSessions: INITIAL_SESSIONS });
        } else {
          clearAuthToken();
          localStorage.removeItem('skyguard_auth_user');
          setUser(null);
        }
      })
      .catch(() => {
        // Keep optimistic saved state if transient network hiccup occurs during boot
      })
      .finally(() => {
        if (active) setIsLoading(false);
      });

    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    if (user) {
      localStorage.setItem('skyguard_auth_user', JSON.stringify(user));
      sessionStorage.removeItem('skyguard_logged_out');
    } else {
      localStorage.removeItem('skyguard_auth_user');
    }
  }, [user]);

  const login = async (email: string, password?: string, role: UserRole = 'owner'): Promise<boolean> => {
    setIsLoading(true);
    sessionStorage.removeItem('skyguard_logged_out');
    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password, role }),
      });
      const data = await res.json();
      if (!res.ok || !data.success || !data.token || !data.user) {
        throw new Error(data.error || `Authentication failed (${res.status})`);
      }
      setAuthToken(data.token);
      setUser({ ...data.user, activeSessions: INITIAL_SESSIONS });
      setSessions(INITIAL_SESSIONS);
      return true;
    } finally {
      setIsLoading(false);
    }
  };

  const signup = async (data: {
    name: string;
    email: string;
    company: string;
    password?: string;
    plan?: 'basic' | 'pro' | 'enterprise' | 'whitelabel';
    role?: UserRole;
  }): Promise<boolean> => {
    setIsLoading(true);
    sessionStorage.removeItem('skyguard_logged_out');
    try {
      const res = await fetch('/api/auth/signup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
      });
      const json = await res.json();
      if (res.ok && json.success && json.user) {
        if (json.token) {
          setAuthToken(json.token);
        }
        setUser({ ...json.user, activeSessions: INITIAL_SESSIONS });
        setSessions(INITIAL_SESSIONS);
        return true;
      }
      throw new Error(json.error || 'Failed to provision tenant enclave.');
    } finally {
      setIsLoading(false);
    }
  };

  const logout = () => {
    authFetch('/api/auth/logout', { method: 'POST' }).catch(() => {});
    clearAuthToken();
    localStorage.removeItem('skyguard_auth_user');
    sessionStorage.setItem('skyguard_logged_out', 'true');
    setUser(null);
  };

  const switchRole = (role: UserRole) => {
    if (user) {
      setUser({ ...user, role });
      authFetch('/api/auth/role', {
        method: 'POST',
        body: JSON.stringify({ role }),
      }).catch(() => {});
    }
  };

  const updatePlan = (plan: 'basic' | 'pro' | 'enterprise' | 'whitelabel') => {
    if (user) {
      setUser({ ...user, plan });
    }
  };

  const verifyEmail = async (code: string): Promise<boolean> => {
    setIsLoading(true);
    try {
      const res = await authFetch('/api/auth/verify-email', {
        method: 'POST',
        body: JSON.stringify({ code }),
      });
      const data = await res.json();
      if (res.ok && data.success) {
        if (user) {
          setUser({ ...user, emailVerified: true });
        }
        return true;
      }
      return false;
    } finally {
      setIsLoading(false);
    }
  };

  const requestPasswordReset = async (email: string): Promise<boolean> => {
    setIsLoading(true);
    try {
      const res = await fetch('/api/auth/forgot-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email }),
      });
      return res.ok;
    } finally {
      setIsLoading(false);
    }
  };

  const completePasswordReset = async (token: string, newPassword: string): Promise<boolean> => {
    setIsLoading(true);
    try {
      const res = await fetch('/api/auth/reset-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token, newPassword }),
      });
      return res.ok;
    } finally {
      setIsLoading(false);
    }
  };

  const toggleMfa = async (enabled: boolean): Promise<boolean> => {
    setIsLoading(true);
    try {
      const res = await authFetch('/api/auth/mfa', {
        method: 'POST',
        body: JSON.stringify({ enabled }),
      });
      if (res.ok && user) {
        setUser({ ...user, mfaEnabled: enabled });
      }
      return res.ok;
    } finally {
      setIsLoading(false);
    }
  };

  const revokeSession = (sessionId: string) => {
    setSessions((prev) => prev.filter((s) => s.id !== sessionId));
  };

  const terminateOtherSessions = () => {
    setSessions((prev) => prev.filter((s) => s.isCurrent));
  };

  const canAccessModule = (module: 'security_config' | 'alerts_incidents' | 'privacy_governance' | 'full_admin' | 'read_only'): boolean => {
    if (!user) return false;
    const role = user.role;

    if (role === 'owner') return true;

    switch (module) {
      case 'full_admin':
        return false;
      case 'security_config':
        return role === 'admin';
      case 'alerts_incidents':
        return role === 'admin' || role === 'security_analyst' || role === 'security_officer' || role === 'analyst';
      case 'privacy_governance':
        return role === 'admin' || role === 'privacy_officer' || role === 'compliance_auditor';
      case 'read_only':
        return true;
      default:
        return false;
    }
  };

  const canPerformWriteAction = (): boolean => {
    if (!user) return false;
    return user.role !== 'viewer';
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        isAuthenticated: !!user,
        isLoading,
        sessions,
        login,
        signup,
        logout,
        switchRole,
        updatePlan,
        verifyEmail,
        requestPasswordReset,
        completePasswordReset,
        toggleMfa,
        revokeSession,
        terminateOtherSessions,
        canAccessModule,
        canPerformWriteAction,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
