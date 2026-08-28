import React, { createContext, useContext, useState, useEffect } from 'react';
import { UserProfile, UserRole, UserSession } from '../../types';

interface AuthContextType {
  user: UserProfile | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  sessions: UserSession[];
  login: (email: string, password?: string, role?: UserRole) => Promise<boolean>;
  signup: (data: { name: string; email: string; company: string; plan?: 'basic' | 'pro' | 'enterprise' | 'whitelabel'; role?: UserRole }) => Promise<boolean>;
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
  }
];

const DEFAULT_DEMO_USER: UserProfile = {
  id: 'usr_sec_99182',
  name: 'Noam Almagor',
  email: 'chief.security@skyguard.mesh',
  role: 'owner',
  tenantId: 'tnt_sovereign_enclave_01',
  tenantName: 'SkyGuard Defense HQ',
  plan: 'enterprise',
  mfaEnabled: true,
  emailVerified: true,
  lastLogin: '2026-08-20T05:45:00Z',
  activeSessions: INITIAL_SESSIONS
};

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<UserProfile | null>(() => {
    const saved = localStorage.getItem('skyguard_auth_user');
    if (saved) {
      try {
        return JSON.parse(saved);
      } catch {
        return DEFAULT_DEMO_USER;
      }
    }
    return DEFAULT_DEMO_USER;
  });
  const [sessions, setSessions] = useState<UserSession[]>(INITIAL_SESSIONS);
  const [isLoading, setIsLoading] = useState(false);

  useEffect(() => {
    if (user) {
      localStorage.setItem('skyguard_auth_user', JSON.stringify(user));
    } else {
      localStorage.removeItem('skyguard_auth_user');
    }
  }, [user]);

  const login = async (email: string, _password?: string, role: UserRole = 'owner'): Promise<boolean> => {
    setIsLoading(true);
    // Simulate authentication verification handshake
    await new Promise((resolve) => setTimeout(resolve, 500));
    
    const newUser: UserProfile = {
      id: `usr_${Math.floor(Math.random() * 89999 + 10000)}`,
      name: email.split('@')[0].replace('.', ' ').replace(/^./, (s) => s.toUpperCase()),
      email: email,
      role: role,
      tenantId: 'tnt_sec_live_sandbox',
      tenantName: 'Global Cyber Operations',
      plan: 'enterprise',
      mfaEnabled: true,
      emailVerified: true,
      lastLogin: new Date().toISOString(),
      activeSessions: INITIAL_SESSIONS
    };
    setUser(newUser);
    setSessions(INITIAL_SESSIONS);
    setIsLoading(false);
    return true;
  };

  const signup = async (data: {
    name: string;
    email: string;
    company: string;
    plan?: 'basic' | 'pro' | 'enterprise' | 'whitelabel';
    role?: UserRole;
  }): Promise<boolean> => {
    setIsLoading(true);
    await new Promise((resolve) => setTimeout(resolve, 700));

    const newUser: UserProfile = {
      id: `usr_${Math.floor(Math.random() * 89999 + 10000)}`,
      name: data.name,
      email: data.email,
      role: data.role || 'owner',
      tenantId: `tnt_${data.company.toLowerCase().replace(/[^a-z0-9]/g, '_')}_${Math.floor(Math.random() * 900 + 100)}`,
      tenantName: data.company,
      plan: data.plan || 'pro',
      mfaEnabled: true,
      emailVerified: false,
      lastLogin: new Date().toISOString(),
      activeSessions: INITIAL_SESSIONS
    };
    setUser(newUser);
    setSessions(INITIAL_SESSIONS);
    setIsLoading(false);
    return true;
  };

  const logout = () => {
    setUser(null);
  };

  const switchRole = (role: UserRole) => {
    if (user) {
      setUser({ ...user, role });
    }
  };

  const updatePlan = (plan: 'basic' | 'pro' | 'enterprise' | 'whitelabel') => {
    if (user) {
      setUser({ ...user, plan });
    }
  };

  const verifyEmail = async (_code: string): Promise<boolean> => {
    setIsLoading(true);
    await new Promise((resolve) => setTimeout(resolve, 600));
    if (user) {
      setUser({ ...user, emailVerified: true });
    }
    setIsLoading(false);
    return true;
  };

  const requestPasswordReset = async (_email: string): Promise<boolean> => {
    setIsLoading(true);
    await new Promise((resolve) => setTimeout(resolve, 600));
    setIsLoading(false);
    return true;
  };

  const completePasswordReset = async (_token: string, _newPassword: string): Promise<boolean> => {
    setIsLoading(true);
    await new Promise((resolve) => setTimeout(resolve, 700));
    setIsLoading(false);
    return true;
  };

  const toggleMfa = async (enabled: boolean): Promise<boolean> => {
    setIsLoading(true);
    await new Promise((resolve) => setTimeout(resolve, 500));
    if (user) {
      setUser({ ...user, mfaEnabled: enabled });
    }
    setIsLoading(false);
    return true;
  };

  const revokeSession = (sessionId: string) => {
    setSessions((prev) => prev.filter((s) => s.id !== sessionId));
  };

  const terminateOtherSessions = () => {
    setSessions((prev) => prev.filter((s) => s.isCurrent));
  };

  // RBAC Permission Engine
  // OWNER: Full access
  // ADMIN: Security configuration
  // SECURITY ANALYST: Alerts, Incidents, Reports
  // PRIVACY OFFICER: GDPR, Consent, Data requests
  // VIEWER: Read-only
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
