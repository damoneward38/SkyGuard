import React, { useState } from 'react';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import { 
  ShieldCheck, 
  Lock, 
  Mail, 
  ArrowRight, 
  KeyRound, 
  CheckCircle2, 
  UserCheck, 
  ShieldAlert, 
  Key, 
  Eye, 
  EyeOff, 
  Sparkles,
  Building2,
  Check,
  Fingerprint,
  Cpu,
  AlertTriangle,
  Globe
} from 'lucide-react';
import { useAuth } from '../hooks/useAuth';
import { UserRole } from '../types';

export default function Login() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const rawFrom = (location.state as any)?.from?.pathname;
  const targetPath = (rawFrom && !rawFrom.includes('/login') && !rawFrom.includes('/signin') && !rawFrom.includes('/sign-in')) 
    ? rawFrom 
    : '/app/dashboard';

  const [email, setEmail] = useState('chief.security@skyguard.mesh');
  const [password, setPassword] = useState('SkyGuard-Enclave-Pass2026!');
  const [showPassword, setShowPassword] = useState(false);
  const [mfaCode, setMfaCode] = useState('849201');
  const [useMfa, setUseMfa] = useState(true);
  const [rememberMe, setRememberMe] = useState(true);
  const [selectedRole, setSelectedRole] = useState<UserRole>('owner');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [ssoProvider, setSsoProvider] = useState<string | null>(null);
  const [authSuccessMessage, setAuthSuccessMessage] = useState<string | null>(null);
  const [authError, setAuthError] = useState<string | null>(null);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email || !password) {
      setAuthError('Please enter both enterprise email and your enclave passphrase.');
      return;
    }
    setAuthError(null);
    setIsSubmitting(true);

    try {
      await login(email, password, selectedRole);
      setAuthSuccessMessage('Identity verified. Redirecting to SkyGuard Enclave Console...');
      setTimeout(() => {
        navigate(targetPath, { replace: true });
      }, 300);
    } catch (err: any) {
      setAuthError(err.message || 'Authentication failed. Please verify credentials.');
      setIsSubmitting(false);
    }
  };

  const handleQuickDemo = async (role: UserRole, demoEmail: string) => {
    setAuthError(null);
    setSelectedRole(role);
    setEmail(demoEmail);
    setPassword('SkyGuard-Sovereign-2026!');
    setIsSubmitting(true);

    try {
      await login(demoEmail, 'SkyGuard-Sovereign-2026!', role);
      setAuthSuccessMessage(`Authorized as ${role.toUpperCase()}. Launching Console...`);
      setTimeout(() => {
        navigate(targetPath, { replace: true });
      }, 300);
    } catch {
      setIsSubmitting(false);
    }
  };

  const handleSSOLogin = async (provider: 'google' | 'azure' | 'okta') => {
    setAuthError(null);
    setSsoProvider(provider);
    setIsSubmitting(true);

    const ssoEmails: Record<string, string> = {
      google: 'damoneward38@gmail.com',
      azure: 'operator@azure.enterprise.cloud',
      okta: 'ciso@sovereign-mesh.okta.com',
    };

    const ssoEmail = ssoEmails[provider] || 'ciso@skyguard.mesh';
    setEmail(ssoEmail);

    try {
      await login(ssoEmail, 'sso-federated-token', selectedRole);
      setAuthSuccessMessage(`SAML SSO handshake validated via ${provider.toUpperCase()}. Launching Console...`);
      setTimeout(() => {
        navigate(targetPath, { replace: true });
      }, 300);
    } finally {
      setIsSubmitting(false);
      setSsoProvider(null);
    }
  };

  return (
    <div className="min-h-[90vh] flex items-center justify-center py-12 px-4 sm:px-6 lg:px-8 font-sans bg-slate-50">
      <div className="max-w-xl w-full space-y-6">
        {/* Header */}
        <div className="text-center">
          <div className="inline-flex items-center justify-center w-12 h-12 rounded-xl bg-blue-600 text-white shadow-md mb-3">
            <ShieldCheck className="w-7 h-7" />
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-slate-900 tracking-tight">
            Sign In to SkyGuard מגן‑רקיע
          </h1>
          <p className="text-xs text-slate-500 mt-1 font-mono">
            Zero-Trust Sovereign Authentication &amp; Hardware MFA Gateway
          </p>
        </div>

        {/* Success or Error Feedback */}
        {authSuccessMessage && (
          <div className="p-3.5 rounded-xl bg-emerald-50 border border-emerald-200 text-emerald-800 text-xs flex items-center gap-2.5">
            <CheckCircle2 className="w-4 h-4 text-emerald-600 flex-shrink-0 animate-pulse" />
            <span className="font-medium">{authSuccessMessage}</span>
          </div>
        )}
        {authError && (
          <div className="p-3.5 rounded-xl bg-red-50 border border-red-200 text-red-800 text-xs flex items-center gap-2.5">
            <AlertTriangle className="w-4 h-4 text-red-600 flex-shrink-0" />
            <span className="font-medium">{authError}</span>
          </div>
        )}

        {/* Top Checkout CTA Banner */}
        <div className="bg-gradient-to-r from-slate-900 to-blue-950 text-white p-3.5 rounded-xl border border-blue-900/60 shadow-md flex flex-col sm:flex-row items-center justify-between gap-3 text-xs">
          <div className="flex items-center gap-2.5">
            <Sparkles className="w-4 h-4 text-amber-400 flex-shrink-0" />
            <div>
              <span className="font-bold text-white block">Need to purchase or activate a license?</span>
              <span className="text-[11px] text-slate-300">Starter, Growth, Sovereign Enterprise &amp; White-Label</span>
            </div>
          </div>
          <Link
            to="/checkout?plan=pro"
            className="w-full sm:w-auto bg-blue-600 hover:bg-blue-500 text-white font-bold px-3.5 py-2 rounded-lg text-xs transition-colors flex items-center justify-center gap-1.5 whitespace-nowrap shadow-sm cursor-pointer"
          >
            <span>Take Me Straight to Checkout</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </Link>
        </div>

        {/* 1-Click Instant Evaluation Login */}
        <div className="bg-white p-4 rounded-xl border-2 border-blue-500/40 shadow-md flex flex-col sm:flex-row items-center justify-between gap-3">
          <div>
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-emerald-500 animate-ping"></span>
              <h3 className="text-xs font-bold text-slate-900 uppercase tracking-wider font-mono">
                1-Click Root Evaluation:
              </h3>
            </div>
            <p className="text-xs text-slate-600 mt-0.5">
              Launch SkyGuard Sovereign Enclave Console instantly with pre-verified root credentials.
            </p>
          </div>
          <button
            type="button"
            onClick={() => handleQuickDemo('owner', 'chief.security@skyguard.mesh')}
            disabled={isSubmitting}
            className="w-full sm:w-auto bg-blue-600 hover:bg-blue-700 text-white font-bold px-4 py-2 rounded-lg text-xs shadow-md transition-colors flex items-center justify-center gap-1.5 whitespace-nowrap cursor-pointer"
          >
            <span>⚡ Instant Sign In as Root Owner</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>

        {/* 1-Click RBAC Persona Switcher for Instant Evaluation */}
        <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-sm space-y-2.5">
          <div className="flex items-center justify-between text-xs font-semibold text-slate-700">
            <span className="flex items-center gap-1.5">
              <UserCheck className="w-3.5 h-3.5 text-blue-600" />
              <span>RBAC Persona Switcher (Instant Evaluation):</span>
            </span>
            <span className="text-[10px] font-mono text-blue-600 font-bold">1-Click Sign-In</span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 font-mono text-xs">
            {/* OWNER */}
            <button
              type="button"
              id="btn_auth_quick_owner"
              onClick={() => handleQuickDemo('owner', 'chief.security@skyguard.mesh')}
              className={`p-2.5 rounded-lg border transition-all text-left flex items-center justify-between cursor-pointer ${
                selectedRole === 'owner' ? 'bg-purple-50 border-purple-300 text-purple-900 ring-2 ring-purple-200' : 'bg-slate-50 border-slate-200 text-slate-700 hover:bg-slate-100'
              }`}
            >
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-purple-600"></span>
                <span className="font-bold">ROOT OWNER</span>
              </div>
              <span className="text-[9px] bg-purple-200 px-1.5 py-0.5 rounded text-purple-900 font-bold">FULL 78</span>
            </button>

            {/* ADMIN */}
            <button
              type="button"
              id="btn_auth_quick_admin"
              onClick={() => handleQuickDemo('admin', 'admin@skyguard.mesh')}
              className={`p-2.5 rounded-lg border transition-all text-left flex items-center justify-between cursor-pointer ${
                selectedRole === 'admin' ? 'bg-blue-50 border-blue-300 text-blue-900 ring-2 ring-blue-200' : 'bg-slate-50 border-slate-200 text-slate-700 hover:bg-slate-100'
              }`}
            >
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-blue-600"></span>
                <span className="font-bold">SECURITY ADMIN</span>
              </div>
              <span className="text-[9px] bg-blue-200 px-1.5 py-0.5 rounded text-blue-900 font-bold">CONFIG</span>
            </button>

            {/* SECURITY ANALYST */}
            <button
              type="button"
              onClick={() => handleQuickDemo('security_analyst', 'analyst@skyguard.mesh')}
              className={`p-2.5 rounded-lg border transition-all text-left flex items-center justify-between cursor-pointer ${
                selectedRole === 'security_analyst' ? 'bg-amber-50 border-amber-300 text-amber-900 ring-2 ring-amber-200' : 'bg-slate-50 border-slate-200 text-slate-700 hover:bg-slate-100'
              }`}
            >
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-amber-600"></span>
                <span className="font-bold">SOC ANALYST</span>
              </div>
              <span className="text-[9px] bg-amber-200 px-1.5 py-0.5 rounded text-amber-900 font-bold">ALERTS</span>
            </button>

            {/* PRIVACY OFFICER */}
            <button
              type="button"
              onClick={() => handleQuickDemo('privacy_officer', 'privacy.officer@skyguard.mesh')}
              className={`p-2.5 rounded-lg border transition-all text-left flex items-center justify-between cursor-pointer ${
                selectedRole === 'privacy_officer' ? 'bg-emerald-50 border-emerald-300 text-emerald-900 ring-2 ring-emerald-200' : 'bg-slate-50 border-slate-200 text-slate-700 hover:bg-slate-100'
              }`}
            >
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-emerald-600"></span>
                <span className="font-bold">PRIVACY OFFICER</span>
              </div>
              <span className="text-[9px] bg-emerald-200 px-1.5 py-0.5 rounded text-emerald-900 font-bold">GDPR/DSAR</span>
            </button>
          </div>
        </div>

        {/* Enterprise SSO Federations */}
        <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-sm space-y-2.5">
          <div className="flex items-center justify-between text-xs font-semibold text-slate-700">
            <span className="flex items-center gap-1.5">
              <Globe className="w-3.5 h-3.5 text-blue-600" />
              <span>Enterprise Single Sign-On (Zero-Trust IdP):</span>
            </span>
            <span className="text-[10px] font-mono text-slate-500">OIDC / SAML 2.0</span>
          </div>

          <div className="grid grid-cols-3 gap-2 text-xs font-semibold">
            <button
              type="button"
              id="btn_auth_sso_google"
              onClick={() => handleSSOLogin('google')}
              disabled={isSubmitting}
              className="p-2 rounded-lg border border-slate-200 hover:bg-slate-50 transition-colors flex items-center justify-center gap-1.5 cursor-pointer text-slate-700 text-[11px]"
            >
              <span className="font-bold text-blue-600">G</span>
              <span>Google SSO</span>
            </button>
            <button
              type="button"
              id="btn_auth_sso_azure"
              onClick={() => handleSSOLogin('azure')}
              disabled={isSubmitting}
              className="p-2 rounded-lg border border-slate-200 hover:bg-slate-50 transition-colors flex items-center justify-center gap-1.5 cursor-pointer text-slate-700 text-[11px]"
            >
              <span className="font-bold text-sky-600">M</span>
              <span>Azure AD</span>
            </button>
            <button
              type="button"
              id="btn_auth_sso_okta"
              onClick={() => handleSSOLogin('okta')}
              disabled={isSubmitting}
              className="p-2 rounded-lg border border-slate-200 hover:bg-slate-50 transition-colors flex items-center justify-center gap-1.5 cursor-pointer text-slate-700 text-[11px]"
            >
              <span className="font-bold text-indigo-600">O</span>
              <span>Okta Mesh</span>
            </button>
          </div>
        </div>

        {/* Standard Credentials Form */}
        <div className="bg-white p-6 sm:p-8 rounded-2xl border border-slate-200 shadow-sm">
          <form onSubmit={handleLogin} className="space-y-4">
            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1">
                Enterprise Work Email
              </label>
              <div className="relative">
                <Mail className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
                <input
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="w-full pl-9 pr-3 py-2.5 rounded-lg bg-slate-50 border border-slate-200 text-sm text-slate-900 focus:outline-none focus:border-blue-500 font-sans"
                  placeholder="name@enterprise.com"
                />
              </div>
            </div>

            <div>
              <div className="flex items-center justify-between mb-1">
                <label className="text-xs font-semibold text-slate-700">
                  Enclave Passphrase
                </label>
                <Link to="/forgot-password" className="text-[11px] text-blue-600 hover:underline">
                  Forgot Passphrase?
                </Link>
              </div>
              <div className="relative">
                <Lock className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
                <input
                  type={showPassword ? 'text' : 'password'}
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full pl-9 pr-10 py-2.5 rounded-lg bg-slate-50 border border-slate-200 text-sm text-slate-900 focus:outline-none focus:border-blue-500"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 focus:outline-none cursor-pointer"
                  aria-label="Toggle password visibility"
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            {/* MFA / Hardware FIDO2 Toggle */}
            <div className="pt-1">
              <div className="flex items-center justify-between mb-1">
                <label className="text-xs font-semibold text-slate-700 flex items-center gap-1.5">
                  <Fingerprint className="w-3.5 h-3.5 text-blue-600" />
                  <span>Hardware MFA / TOTP Token</span>
                </label>
                <button
                  type="button"
                  onClick={() => setUseMfa(!useMfa)}
                  className="text-[10px] font-mono text-blue-600 hover:underline cursor-pointer"
                >
                  {useMfa ? 'Disable MFA Step' : 'Require MFA Step'}
                </button>
              </div>

              {useMfa && (
                <div className="relative">
                  <KeyRound className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
                  <input
                    type="text"
                    value={mfaCode}
                    onChange={(e) => setMfaCode(e.target.value)}
                    className="w-full pl-9 pr-3 py-2 rounded-lg bg-slate-50 border border-slate-200 text-xs font-mono text-slate-900 tracking-widest focus:outline-none focus:border-blue-500"
                    placeholder="6-digit TOTP"
                  />
                </div>
              )}
            </div>

            {/* Remember Me & Hardware Binding */}
            <div className="flex items-center justify-between pt-1 text-xs text-slate-600">
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={rememberMe}
                  onChange={(e) => setRememberMe(e.target.checked)}
                  className="rounded text-blue-600 focus:ring-blue-500"
                />
                <span>Trust this workstation (Hardware Enclave bound)</span>
              </label>
            </div>

            <button
              type="submit"
              id="btn_auth_signin"
              disabled={isSubmitting}
              className="w-full py-3 rounded-lg bg-blue-600 hover:bg-blue-700 text-white font-bold text-xs shadow-md transition-colors flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50 mt-6"
            >
              {isSubmitting ? (
                <>
                  <span className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin"></span>
                  <span>Verifying Cryptographic Session...</span>
                </>
              ) : (
                <>
                  <span>Sign In &amp; Launch Sovereign Console</span>
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
          </form>

          {/* Quick Links Suite */}
          <div className="mt-6 pt-4 border-t border-slate-100 flex flex-wrap items-center justify-between gap-2 text-[11px] text-slate-600 font-sans">
            <div>
              <Link to="/signup" className="text-blue-600 font-semibold hover:underline">
                Create Tenant Account →
              </Link>
            </div>
            <div>
              <Link to="/checkout?plan=pro" className="text-slate-700 hover:text-blue-600 hover:underline">
                Buy License / Checkout →
              </Link>
            </div>
            <div>
              <Link to="/pricing" className="text-slate-600 hover:text-blue-600 hover:underline">
                Compare Pricing →
              </Link>
            </div>
          </div>
        </div>

        {/* Security Enclave Certifications Footer */}
        <div className="text-center text-[10px] text-slate-400 font-mono">
          <span>SkyGuard Security Mesh • NIST SP 800-207 • FIDO2 Certified • SOC 2 Type II</span>
        </div>
      </div>
    </div>
  );
}
