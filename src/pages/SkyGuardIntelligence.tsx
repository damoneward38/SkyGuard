import React, { useState, useRef, useEffect } from 'react';
import { useLocation } from 'react-router-dom';
import {
  Shield,
  Sparkles,
  Mail,
  Activity,
  FileText,
  Cpu,
  GitBranch,
  TrendingUp,
  Server,
  BarChart3,
  Plug,
  Settings,
  Mic,
  Square,
  Volume2,
  VolumeX,
  Send,
  Upload,
  Plus,
  Trash2,
  RefreshCw,
  CheckCircle2,
  AlertTriangle,
  Download,
  PanelLeftClose,
  PanelLeftOpen,
  X,
} from 'lucide-react';
import { getAuthToken } from '../services/skyguardApi';
import { useSecurityData } from '../features/security/SecurityDataContext';
import {
  initGmailAuth,
  connectGmailWithPopup,
  getGmailAccessToken,
  getConnectedGoogleUser,
  disconnectGmail,
} from '../services/googleWorkspaceAuth';

type Page =
  | 'command'
  | 'assistant'
  | 'email'
  | 'threats'
  | 'files'
  | 'intelligence'
  | 'pipelines'
  | 'business'
  | 'monitoring'
  | 'reports'
  | 'integrations'
  | 'settings';

interface Finding {
  id: string;
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  description: string;
  source: string;
  resource?: string;
  remediation?: string;
  status: string;
  discoveredAt?: string;
}

interface PipelineNode {
  id: string;
  name: string;
  type: string;
  enabled: boolean;
}

interface SavedPipeline {
  id: string;
  name: string;
  nodes: PipelineNode[];
  createdAt: string;
  createdBy: string;
}

interface ScannedEmail {
  id: string;
  provider: 'gmail' | 'manual_eml';
  messageId: string;
  from: string;
  subject: string;
  date: string;
  snippet: string;
  dlpStatus: string;
  dlpFindings: string[];
  vaultItemId: string;
  scannedAt: string;
}

interface InventoryReport {
  scannedAt: string;
  componentCount: number;
  summary: {
    sourceFiles: number;
    pagesCount: number;
    componentsCount: number;
    servicesCount: number;
    apiRoutesCount: number;
    dependenciesCount: number;
  };
  routes: Array<{ method: string; path: string }>;
  dependencies: Array<{ name: string; version: string }>;
  files: Array<{ path: string; bytes: number; lines: number }>;
  verificationMatrix: Array<{
    component: string;
    status: string;
    evidence: string;
  }>;
}

const API = '/api/skyguard';

const navigation: { id: Page; label: string; icon: React.ComponentType<{ className?: string }> }[] = [
  { id: 'command', label: 'Command Center', icon: Shield },
  { id: 'assistant', label: 'AI Assistant', icon: Sparkles },
  { id: 'email', label: 'Email Protection', icon: Mail },
  { id: 'threats', label: 'Threat Intelligence', icon: Activity },
  { id: 'files', label: 'File Intelligence', icon: FileText },
  { id: 'intelligence', label: 'Application Intelligence', icon: Cpu },
  { id: 'pipelines', label: 'Pipeline Builder', icon: GitBranch },
  { id: 'business', label: 'Business Intelligence', icon: TrendingUp },
  { id: 'monitoring', label: 'System Monitoring', icon: Server },
  { id: 'reports', label: 'Reports & Analytics', icon: BarChart3 },
  { id: 'integrations', label: 'Integrations', icon: Plug },
  { id: 'settings', label: 'Settings', icon: Settings },
];

async function skyguardRequest<T>(path: string, options: RequestInit = {}): Promise<T> {
  const token = getAuthToken();
  const isFormData = options.body instanceof FormData;
  const headers: Record<string, string> = {};

  if (!isFormData) {
    headers['Content-Type'] = 'application/json';
  }
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  if (options.headers) {
    const incoming = new Headers(options.headers);
    incoming.forEach((value, key) => {
      headers[key] = value;
    });
  }

  const response = await fetch(`${API}${path}`, {
    ...options,
    headers,
  });

  const text = await response.text();
  let parsed: any = null;
  try {
    parsed = text ? JSON.parse(text) : {};
  } catch {
    parsed = { error: text };
  }

  if (!response.ok) {
    throw new Error(parsed?.error || `Server error ${response.status}`);
  }
  return parsed as T;
}

function Metric({ label, value, note }: { label: string; value: string; note: string }) {
  return (
    <div className="bg-[#0d192a] border border-[#1c3049] rounded-xl p-4 sm:p-5">
      <div className="text-[11px] font-mono tracking-wider text-[#8398b5] uppercase">{label}</div>
      <div className="text-2xl sm:text-[27px] font-bold font-mono tabular-nums text-[#e8eef9] mt-2.5 mb-1">
        {value}
      </div>
      <div className="text-[11px] text-[#8196b2]">{note}</div>
    </div>
  );
}

function severityPillClasses(severity: string): string {
  switch (severity.toUpperCase()) {
    case 'CRITICAL':
    case 'SUSPICIOUS_PHISHING':
    case 'FAILED':
      return 'bg-[#54202a] text-[#ff9da8] border border-[#773449]';
    case 'HIGH':
    case 'SECRETS_DETECTED':
      return 'bg-[#492e1d] text-[#ffc38c] border border-[#734a2f]';
    case 'MEDIUM':
    case 'FLAGGED_PII':
    case 'NOT CONFIGURED':
    case 'PARTIALLY VERIFIED':
      return 'bg-[#493d20] text-[#f5d58a] border border-[#6e5c31]';
    default:
      return 'bg-[#193b34] text-[#8be1bd] border border-[#2a5c51]';
  }
}

export default function SkyGuardIntelligence() {
  const location = useLocation();
  const { state: securityState, refresh: refreshSecurityData } = useSecurityData();

  const initialPage: Page = location.pathname.includes('/intelligence') ? 'intelligence' : 'command';
  const [page, setPage] = useState<Page>(initialPage);
  const [collapsed, setCollapsed] = useState(false);

  const [messages, setMessages] = useState<{ role: 'user' | 'assistant'; content: string }[]>([
    {
      role: 'assistant',
      content:
        'SkyGuard Business Protection Intelligence initialized. Ask about open security findings, saved vault documents, email scan results, compliance posture, or saved pipelines.',
    },
  ]);
  const [prompt, setPrompt] = useState('');
  const [busy, setBusy] = useState(false);

  const [files, setFiles] = useState<File[]>([]);
  const [fileResults, setFileResults] = useState<any[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [nodes, setNodes] = useState<PipelineNode[]>([
    { id: '1', name: 'Incoming Event', type: 'trigger', enabled: true },
    { id: '2', name: 'AI Analysis', type: 'ai', enabled: true },
    { id: '3', name: 'Security Inspection', type: 'security', enabled: true },
    { id: '4', name: 'Human Approval', type: 'approval', enabled: true },
  ]);
  const [pipelineName, setPipelineName] = useState('Business Protection Workflow');
  const [savedPipelines, setSavedPipelines] = useState<SavedPipeline[]>([]);

  const [health, setHealth] = useState<any>(null);
  const [integrations, setIntegrations] = useState<any[]>([]);
  const [scannedEmails, setScannedEmails] = useState<ScannedEmail[]>([]);
  const [inventoryReport, setInventoryReport] = useState<InventoryReport | null>(null);

  const [googleEmail, setGoogleEmail] = useState<string | null>(() => getConnectedGoogleUser()?.email || null);
  const [gmailTokenPresent, setGmailTokenPresent] = useState<boolean>(() => Boolean(getGmailAccessToken()));
  const [gmailSyncSummary, setGmailSyncSummary] = useState<string>('');

  const [manualEmailFrom, setManualEmailFrom] = useState('');
  const [manualEmailSubject, setManualEmailSubject] = useState('');
  const [manualEmailBody, setManualEmailBody] = useState('');

  const [notice, setNotice] = useState('');
  const [error, setError] = useState('');
  const [listening, setListening] = useState(false);
  const [speaking, setSpeaking] = useState(false);

  const recognition = useRef<any>(null);
  const chatEnd = useRef<HTMLDivElement>(null);

  useEffect(() => {
    setPage(location.pathname.includes('/intelligence') ? 'intelligence' : 'command');
  }, [location.pathname]);

  useEffect(() => {
    chatEnd.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  useEffect(() => {
    refreshHealth();
    refreshIntegrations();
    refreshFindings();
    refreshPipelines();
    refreshScannedEmails();

    const unsubscribe = initGmailAuth(
      (user, token) => {
        setGoogleEmail(user.email || user.displayName || 'Connected Google Account');
        setGmailTokenPresent(Boolean(token));
      },
      () => {
        setGmailTokenPresent(Boolean(getGmailAccessToken()));
      }
    );
    return () => {
      if (typeof unsubscribe === 'function') unsubscribe();
    };
  }, []);

  async function refreshHealth() {
    try {
      setHealth(await skyguardRequest('/health'));
    } catch (e: any) {
      setHealth({ status: 'ERROR', error: e.message });
    }
  }

  async function refreshIntegrations() {
    try {
      const result = await skyguardRequest<any>('/integrations');
      setIntegrations(result.integrations || []);
    } catch {
      setIntegrations([]);
    }
  }

  async function refreshFindings() {
    try {
      const result = await skyguardRequest<any>('/security/findings');
      setFindings(result.findings || []);
    } catch {
      setFindings([]);
    }
  }

  async function refreshPipelines() {
    try {
      const result = await skyguardRequest<any>('/pipelines');
      setSavedPipelines(result.pipelines || []);
    } catch {
      setSavedPipelines([]);
    }
  }

  async function refreshScannedEmails() {
    try {
      const result = await skyguardRequest<any>('/email/scanned');
      setScannedEmails(result.emails || []);
    } catch {
      setScannedEmails([]);
    }
  }

  async function toggleFindingStatus(finding: Finding) {
    setError('');
    setNotice('');
    try {
      const nextStatus = finding.status === 'resolved' ? 'open' : 'resolved';
      await skyguardRequest(`/security/findings/${encodeURIComponent(finding.id)}`, {
        method: 'PATCH',
        body: JSON.stringify({ status: nextStatus }),
      });
      setNotice(`Finding "${finding.title}" updated to ${nextStatus}.`);
      await Promise.all([refreshFindings(), refreshSecurityData()]);
    } catch (e: any) {
      setError(e.message);
    }
  }

  async function sendMessage() {
    if (!prompt.trim() || busy) return;
    const question = prompt.trim();
    setPrompt('');
    setMessages((prev) => [...prev, { role: 'user', content: question }]);
    setBusy(true);
    setError('');
    try {
      const result = await skyguardRequest<any>('/assistant/chat', {
        method: 'POST',
        body: JSON.stringify({
          message: question,
          history: messages.slice(-16),
        }),
      });
      setMessages((prev) => [
        ...prev,
        {
          role: 'assistant',
          content: result.response || 'The AI service returned no response.',
        },
      ]);
    } catch (e: any) {
      setError(e.message);
      setMessages((prev) => [
        ...prev,
        {
          role: 'assistant',
          content: `AI service error: ${e.message}`,
        },
      ]);
    } finally {
      setBusy(false);
    }
  }

  function startVoice() {
    const SpeechRecognition =
      (window as any).SpeechRecognition || (window as any).webkitSpeechRecognition;
    if (!SpeechRecognition) {
      setError('Speech recognition is not supported in this browser.');
      return;
    }
    if (listening) {
      recognition.current?.stop();
      setListening(false);
      return;
    }
    const instance = new SpeechRecognition();
    instance.lang = navigator.language || 'en-US';
    instance.continuous = false;
    instance.interimResults = false;
    instance.onresult = (event: any) => {
      setPrompt((prev) => `${prev} ${event.results[0][0].transcript}`.trim());
    };
    instance.onerror = () => {
      setError('Microphone recognition failed. Check microphone permissions.');
      setListening(false);
    };
    instance.onend = () => setListening(false);
    recognition.current = instance;
    instance.start();
    setListening(true);
  }

  function speak(text: string) {
    if (!('speechSynthesis' in window)) {
      setError('Speech synthesis is unavailable in this browser.');
      return;
    }
    window.speechSynthesis.cancel();
    const utterance = new SpeechSynthesisUtterance(text);
    utterance.onstart = () => setSpeaking(true);
    utterance.onend = () => setSpeaking(false);
    utterance.onerror = () => setSpeaking(false);
    window.speechSynthesis.speak(utterance);
  }

  function stopSpeaking() {
    window.speechSynthesis?.cancel();
    setSpeaking(false);
  }

  async function uploadFiles() {
    if (!files.length) return;
    setBusy(true);
    setError('');
    setNotice('');
    try {
      const data = new FormData();
      files.forEach((file) => data.append('files', file));
      const result = await skyguardRequest<any>('/files/analyze', {
        method: 'POST',
        body: data,
      });
      setFileResults((prev) => [...(result.results || []), ...prev]);
      setFiles([]);
      setNotice(
        `Analyzed and persisted ${result.count || result.results?.length || 0} file(s) across Vault, Alerts, Findings, and Dashboard.`
      );
      await Promise.all([refreshFindings(), refreshHealth(), refreshSecurityData()]);
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  async function createPipeline() {
    setBusy(true);
    setError('');
    setNotice('');
    try {
      const result = await skyguardRequest<any>('/pipelines', {
        method: 'POST',
        body: JSON.stringify({
          name: pipelineName.trim() || 'Business Protection Workflow',
          nodes,
        }),
      });
      setSavedPipelines(result.pipelines || []);
      setNotice(`Pipeline saved to persistent disk store: "${result.name}" (${result.id}).`);
      await refreshHealth();
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  async function removeSavedPipeline(id: string) {
    setError('');
    try {
      const result = await skyguardRequest<any>(`/pipelines/${encodeURIComponent(id)}`, {
        method: 'DELETE',
      });
      setSavedPipelines(result.pipelines || []);
      setNotice(`Removed pipeline ${id}.`);
      await refreshHealth();
    } catch (e: any) {
      setError(e.message);
    }
  }

  async function handleConnectGmail() {
    setBusy(true);
    setError('');
    setNotice('');
    try {
      await skyguardRequest('/integrations/gmail/authorize');
      const { user, accessToken } = await connectGmailWithPopup();
      const label = user.email || user.displayName || 'Connected Google Account';
      setGoogleEmail(label);
      setGmailTokenPresent(Boolean(accessToken));
      setNotice(`Authorized Gmail read-only session for ${label}. Ready to sync messages.`);
      await refreshIntegrations();
    } catch (e: any) {
      setError(e?.message || 'Google sign-in popup was closed or failed.');
    } finally {
      setBusy(false);
    }
  }

  async function handleSyncGmailMessages() {
    const token = getGmailAccessToken();
    if (!token) {
      setError('Connect your Gmail account first to issue a fresh in-memory read-only access token.');
      return;
    }
    setBusy(true);
    setError('');
    setNotice('');
    try {
      const result = await skyguardRequest<any>('/email/sync-gmail', {
        method: 'POST',
        headers: {
          'X-Google-Access-Token': token,
        },
      });
      setScannedEmails(result.emails || []);
      setGmailSyncSummary(
        `Scanned ${result.scannedCount || 0} message(s) from ${result.profileEmail || 'Gmail'} and saved all artifacts into the Vault.`
      );
      setNotice(`Gmail inbox sync completed for ${result.profileEmail}.`);
      await Promise.all([refreshFindings(), refreshHealth(), refreshIntegrations(), refreshSecurityData()]);
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  async function handleDisconnectGmail() {
    await disconnectGmail();
    setGoogleEmail(null);
    setGmailTokenPresent(false);
    setNotice('Disconnected Gmail OAuth session from memory.');
    await refreshIntegrations();
  }

  async function handleAnalyzeManualEmail(e: React.FormEvent) {
    e.preventDefault();
    if (!manualEmailSubject.trim() && !manualEmailBody.trim()) return;
    setBusy(true);
    setError('');
    setNotice('');
    try {
      const result = await skyguardRequest<any>('/email/analyze', {
        method: 'POST',
        body: JSON.stringify({
          from: manualEmailFrom.trim(),
          subject: manualEmailSubject.trim(),
          body: manualEmailBody,
        }),
      });
      setScannedEmails(result.emails || []);
      setManualEmailFrom('');
      setManualEmailSubject('');
      setManualEmailBody('');
      setNotice(
        `Email "${result.email?.subject}" inspected (${result.email?.dlpStatus}) and persisted in Vault (${result.email?.vaultItemId}).`
      );
      await Promise.all([refreshFindings(), refreshHealth(), refreshSecurityData()]);
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  async function loadApplicationInventory() {
    setBusy(true);
    setError('');
    setNotice('');
    try {
      const result = await skyguardRequest<InventoryReport>('/application/inventory', {
        method: 'POST',
      });
      setInventoryReport(result);
      setNotice(
        `Application discovery completed: ${result.summary.sourceFiles} source files, ${result.summary.apiRoutesCount} Express routes, ${result.summary.dependenciesCount} runtime dependencies.`
      );
      await refreshHealth();
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  function addNode() {
    setNodes((prev) => [
      ...prev,
      {
        id: crypto.randomUUID ? crypto.randomUUID() : `node_${Date.now()}`,
        name: 'New Processing Step',
        type: 'processing',
        enabled: true,
      },
    ]);
  }

  function updateNode(id: string, changes: Partial<PipelineNode>) {
    setNodes((prev) => prev.map((node) => (node.id === id ? { ...node, ...changes } : node)));
  }

  function exportJsonReport() {
    const payload = {
      generatedAt: new Date().toISOString(),
      health,
      findings,
      scannedEmails,
      fileResults,
      vaultItemsCount: securityState.vaultItems.length,
      pipelines: savedPipelines,
      inventorySummary: inventoryReport?.summary || null,
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'skyguard-intelligence-report.json';
    a.click();
    URL.revokeObjectURL(url);
  }

  function renderFindingsList() {
    if (!findings.length) {
      return (
        <div className="bg-[#0d192a] border border-[#1c3049] rounded-xl p-7 text-center text-[#7186a2] text-xs">
          No findings returned. Connect security monitoring sources or upload documents for inspection.
        </div>
      );
    }
    return (
      <div className="flex flex-col gap-2.5">
        {findings.map((f) => (
          <div
            key={f.id}
            className="bg-[#101e31] border border-[#243850] rounded-lg p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3"
          >
            <div className="space-y-1">
              <div className="flex items-center gap-2.5 flex-wrap">
                <strong className="text-sm text-[#e8eef9]">{f.title}</strong>
                <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full font-semibold ${severityPillClasses(f.severity)}`}>
                  {f.severity}
                </span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#1b3048] text-[#9fcfff] uppercase">
                  {f.status}
                </span>
              </div>
              <p className="text-xs text-[#8295b0] leading-relaxed">{f.description}</p>
              <div className="text-[11px] font-mono text-[#7388a5]">
                Source: {f.source} {f.resource ? `· Asset: ${f.resource}` : ''}
              </div>
            </div>
            <button
              onClick={() => toggleFindingStatus(f)}
              className="shrink-0 px-3 py-1.5 rounded-lg border border-[#2a4b6b] bg-[#142943] hover:bg-[#1a3454] text-[#b9e2ff] text-xs font-medium transition-colors cursor-pointer"
            >
              {f.status === 'resolved' ? 'Reopen Finding' : 'Mark Resolved'}
            </button>
          </div>
        ))}
      </div>
    );
  }

  function renderCommand() {
    const connectedCount = integrations.filter(
      (x) => x.status === 'connected' || x.status === 'configured_ready'
    ).length;

    return (
      <>
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3.5 my-5">
          <Metric
            label="SECURITY FINDINGS"
            value={String(findings.length)}
            note={`${findings.filter((f) => f.status !== 'resolved').length} open findings`}
          />
          <Metric
            label="INTEGRATIONS"
            value={String(connectedCount)}
            note="Connected & OAuth-ready connectors"
          />
          <Metric
            label="VAULT ARTIFACTS"
            value={String(securityState.vaultItems.length)}
            note={`${fileResults.length} analyzed this session`}
          />
          <Metric
            label="SYSTEM STATUS"
            value={health?.status || 'CHECKING'}
            note={health?.geminiConfigured ? 'Gemini 4 AI Ready' : 'Server runtime health'}
          />
        </div>

        <div className="bg-[#0d192a] border border-[#1c3049] rounded-xl p-5 space-y-3">
          <h3 className="text-sm font-semibold text-[#e8eef9]">Executive Intelligence Briefing</h3>
          <p className="text-xs text-[#8295b0] leading-relaxed">
            Review verified business intelligence, security findings, saved Vault documents, Gmail message scans, and
            live backend health across the SkyGuard Sovereign Enclave.
          </p>
          <div className="flex flex-wrap gap-2.5 pt-1">
            <button
              onClick={() => setPage('assistant')}
              className="px-4 py-2 rounded-lg bg-[#087bc4] hover:bg-[#0989db] text-white text-xs font-medium cursor-pointer"
            >
              Open AI Business Assistant
            </button>
            <button
              onClick={() => setPage('email')}
              className="px-4 py-2 rounded-lg border border-[#2a4b6b] bg-[#142943] hover:bg-[#1a3454] text-[#b9e2ff] text-xs font-medium cursor-pointer"
            >
              Email Protection &amp; Gmail
            </button>
            <button
              onClick={refreshHealth}
              className="px-4 py-2 rounded-lg border border-[#2a4b6b] bg-[#142943] hover:bg-[#1a3454] text-[#b9e2ff] text-xs font-medium cursor-pointer"
            >
              Refresh Health
            </button>
          </div>
        </div>

        <div className="text-[15px] font-bold text-[#e8eef9] mt-6 mb-3">Security Findings</div>
        {renderFindingsList()}
      </>
    );
  }

  function renderAssistant() {
    return (
      <div className="space-y-3">
        <div className="flex items-center justify-between text-xs text-[#8295b0] bg-[#0d192a] border border-[#1c3049] rounded-xl px-4 py-2.5">
          <span>
            Provider:{' '}
            <strong className="text-[#e8eef9] font-mono">
              {health?.geminiConfigured ? 'Server-Side Gemini 4 AI (gemini-4-hydrogen)' : 'Server AI Provider Not Configured'}
            </strong>
          </span>
          <span className="font-mono text-[11px] tabular-nums">
            Grounded Telemetry: {findings.length} Findings · {securityState.vaultItems.length} Vault Files
          </span>
        </div>

        <div className="h-[430px] overflow-y-auto bg-[#081321] border border-[#20344e] rounded-xl p-4 flex flex-col gap-3.5">
          {messages.map((m, i) => (
            <div
              key={i}
              className={`max-w-[85%] px-4 py-3 rounded-xl text-[13px] leading-relaxed whitespace-pre-wrap ${
                m.role === 'user' ? 'self-end bg-[#123c60] text-[#eaf3ff]' : 'self-start bg-[#142338] text-[#e8eef9]'
              }`}
            >
              {m.content}
              {m.role === 'assistant' && (
                <div className="mt-2.5 flex gap-2">
                  <button
                    onClick={() => speak(m.content)}
                    className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded border border-[#2a4b6b] bg-[#142943] hover:bg-[#1b3556] text-[#b9e2ff] text-[11px] cursor-pointer"
                  >
                    <Volume2 className="w-3 h-3" />
                    Listen
                  </button>
                </div>
              )}
            </div>
          ))}
          <div ref={chatEnd} />
        </div>

        <div className="flex flex-wrap sm:flex-nowrap gap-2">
          <button
            onClick={startVoice}
            className={`inline-flex items-center gap-1.5 px-3.5 py-2.5 rounded-lg border text-xs font-medium cursor-pointer ${
              listening
                ? 'bg-[#351c26] border-[#773449] text-[#ff9eae]'
                : 'bg-[#142943] border-[#2a4b6b] text-[#b9e2ff]'
            }`}
          >
            {listening ? <Square className="w-3.5 h-3.5" /> : <Mic className="w-3.5 h-3.5" />}
            {listening ? 'Stop Mic' : 'Mic'}
          </button>
          <input
            className="flex-1 bg-[#081321] border border-[#263c57] text-[#eaf3ff] rounded-lg px-3.5 py-2.5 text-sm outline-none focus:border-[#35aaff]"
            value={prompt}
            onChange={(e) => setPrompt(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && sendMessage()}
            placeholder="Ask SkyGuard about your findings, files, emails, or operational posture..."
          />
          <button
            disabled={busy}
            onClick={sendMessage}
            className="inline-flex items-center gap-1.5 px-4 py-2.5 rounded-lg bg-[#087bc4] hover:bg-[#0989db] disabled:opacity-45 text-white text-xs font-medium cursor-pointer"
          >
            <Send className="w-3.5 h-3.5" />
            {busy ? 'Thinking...' : 'Send'}
          </button>
          <button
            disabled={!speaking}
            onClick={stopSpeaking}
            className="inline-flex items-center gap-1.5 px-3.5 py-2.5 rounded-lg border border-[#2a4b6b] bg-[#142943] disabled:opacity-40 text-[#b9e2ff] text-xs font-medium cursor-pointer"
          >
            <VolumeX className="w-3.5 h-3.5" />
            Stop Audio
          </button>
        </div>
      </div>
    );
  }

  function renderGoogleSignInButton(label = 'Connect Gmail (Google Workspace)') {
    return (
      <button
        type="button"
        disabled={busy}
        onClick={handleConnectGmail}
        className="inline-flex items-center gap-2.5 px-4 py-2 rounded-lg bg-white hover:bg-slate-100 text-[#1f1f1f] border border-[#747775] text-xs font-semibold shadow-sm transition-colors cursor-pointer disabled:opacity-50"
      >
        <svg className="w-4 h-4 shrink-0" viewBox="0 0 48 48" aria-hidden="true">
          <path
            fill="#EA4335"
            d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"
          />
          <path
            fill="#4285F4"
            d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"
          />
          <path
            fill="#FBBC05"
            d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"
          />
          <path
            fill="#34A853"
            d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"
          />
        </svg>
        <span>{label}</span>
      </button>
    );
  }

  function renderEmailProtection() {
    return (
      <div className="space-y-4">
        <div className="bg-[#0d192a] border border-[#1c3049] rounded-xl p-5 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div>
              <h3 className="text-sm font-semibold text-[#e8eef9]">Google Workspace Gmail Protection</h3>
              <p className="text-xs text-[#8295b0] mt-1">
                Authorize read-only Gmail access via Google Workspace OAuth (`gmail.readonly`), fetch recent messages,
                run phishing &amp; DLP inspection, and persist .eml artifacts inside the enclave Vault.
              </p>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              {renderGoogleSignInButton(googleEmail ? `Re-Auth (${googleEmail})` : 'Sign in with Google')}
              {gmailTokenPresent && (
                <button
                  type="button"
                  disabled={busy}
                  onClick={handleSyncGmailMessages}
                  className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg bg-[#087bc4] hover:bg-[#0989db] text-white text-xs font-medium cursor-pointer disabled:opacity-50"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${busy ? 'animate-spin' : ''}`} />
                  Sync &amp; Scan Inbox
                </button>
              )}
              {googleEmail && (
                <button
                  type="button"
                  onClick={handleDisconnectGmail}
                  className="px-3 py-2 rounded-lg bg-[#351c26] border border-[#773449] text-[#ff9eae] text-xs cursor-pointer"
                >
                  Disconnect
                </button>
              )}
            </div>
          </div>

          {googleEmail && (
            <div className="rounded-lg bg-[#081321] border border-[#20344e] px-3.5 py-2.5 text-xs text-[#9fcfff] flex items-center justify-between">
              <span>
                Connected Workspace Mailbox: <strong className="font-mono text-white">{googleEmail}</strong> (in-memory
                read-only token active: {gmailTokenPresent ? 'YES' : 'EXPIRED/RE-AUTH NEEDED'})
              </span>
            </div>
          )}

          {gmailSyncSummary && (
            <div className="rounded-lg bg-[#193b34]/60 border border-[#2a5c51] px-3.5 py-2.5 text-xs text-[#8be1bd]">
              {gmailSyncSummary}
            </div>
          )}
        </div>

        <form
          onSubmit={handleAnalyzeManualEmail}
          className="bg-[#0d192a] border border-[#1c3049] rounded-xl p-5 space-y-3"
        >
          <h3 className="text-sm font-semibold text-[#e8eef9]">Manual Email / Phishing Payload Sandbox</h3>
          <p className="text-xs text-[#8295b0]">
            Paste any forwarded email headers or body content to run instant DLP &amp; phishing inspection and persist
            an .eml record into Vault, Alerts, Findings, and Dashboard.
          </p>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <input
              type="text"
              value={manualEmailFrom}
              onChange={(e) => setManualEmailFrom(e.target.value)}
              placeholder="From address (e.g. billing@external-audit.net)"
              className="bg-[#081321] border border-[#263c57] text-[#eaf3ff] rounded-lg px-3 py-2 text-xs outline-none focus:border-[#35aaff]"
            />
            <input
              type="text"
              value={manualEmailSubject}
              onChange={(e) => setManualEmailSubject(e.target.value)}
              placeholder="Email Subject (e.g. URGENT: Wire transfer update)"
              className="bg-[#081321] border border-[#263c57] text-[#eaf3ff] rounded-lg px-3 py-2 text-xs outline-none focus:border-[#35aaff]"
            />
          </div>
          <textarea
            value={manualEmailBody}
            onChange={(e) => setManualEmailBody(e.target.value)}
            rows={4}
            placeholder="Paste raw email body, links, or credentials to test DLP & phishing quarantine..."
            className="w-full bg-[#081321] border border-[#263c57] text-[#eaf3ff] rounded-lg px-3 py-2 text-xs outline-none focus:border-[#35aaff]"
          />
          <button
            type="submit"
            disabled={busy || (!manualEmailSubject.trim() && !manualEmailBody.trim())}
            className="px-4 py-2 rounded-lg bg-[#087bc4] hover:bg-[#0989db] disabled:opacity-45 text-white text-xs font-medium cursor-pointer"
          >
            Inspect &amp; Digest Email
          </button>
        </form>

        <div className="space-y-2.5">
          <div className="text-sm font-bold text-[#e8eef9]">
            Scanned Emails ({scannedEmails.length})
          </div>
          {scannedEmails.length === 0 ? (
            <div className="bg-[#0d192a] border border-[#1c3049] rounded-xl p-6 text-center text-xs text-[#7186a2]">
              No emails scanned in this enclave yet. Connect Gmail above or submit an email into the manual sandbox.
            </div>
          ) : (
            scannedEmails.map((em) => (
              <div key={em.id} className="bg-[#101e31] border border-[#243850] rounded-lg p-4 space-y-1.5">
                <div className="flex items-center justify-between gap-2 flex-wrap">
                  <strong className="text-sm text-[#e8eef9]">{em.subject}</strong>
                  <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full font-semibold ${severityPillClasses(em.dlpStatus)}`}>
                    {em.dlpStatus}
                  </span>
                </div>
                <div className="text-[11px] font-mono text-[#9fcfff]">
                  From: {em.from} · Provider: {em.provider} · Vault ID: {em.vaultItemId}
                </div>
                <p className="text-xs text-[#8295b0]">{em.snippet}</p>
                {em.dlpFindings?.length > 0 && (
                  <div className="text-[11px] text-[#8be1bd] pt-1">
                    Findings: {em.dlpFindings.join(' · ')}
                  </div>
                )}
              </div>
            ))
          )}
        </div>
      </div>
    );
  }

  function renderFiles() {
    return (
      <div className="space-y-4">
        <div className="bg-[#0d192a] border border-[#1c3049] rounded-xl p-5 space-y-3">
          <h3 className="text-sm font-semibold text-[#e8eef9]">Secure Document Intelligence</h3>
          <p className="text-xs text-[#8295b0]">
            Upload business documents, source code, spreadsheets, emails, and reports for multipart server-side DLP
            inspection, persistent enclave storage (`data/uploads/*.bin`), and cross-screen digestion.
          </p>
          <input
            type="file"
            multiple
            className="w-full bg-[#081321] border border-[#263c57] text-[#eaf3ff] rounded-lg px-3 py-2.5 text-xs"
            accept=".pdf,.doc,.docx,.txt,.csv,.xlsx,.xls,.json,.xml,.html,.zip,.png,.jpg,.jpeg,.webp,.eml,.env,.js,.ts,.tsx,.py,.go,.java,.rs,.cs"
            onChange={(e) => setFiles(Array.from(e.target.files || []))}
          />
          <div className="flex items-center justify-between gap-3">
            <span className="text-xs text-[#8295b0] font-mono tabular-nums">{files.length} file(s) selected</span>
            <button
              disabled={!files.length || busy}
              onClick={uploadFiles}
              className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg bg-[#087bc4] hover:bg-[#0989db] disabled:opacity-45 text-white text-xs font-medium cursor-pointer"
            >
              <Upload className="w-3.5 h-3.5" />
              {busy ? 'Analyzing...' : 'Analyze & Persist Files'}
            </button>
          </div>
        </div>

        <div className="text-[15px] font-bold text-[#e8eef9]">Analysis Results</div>
        {fileResults.length > 0 ? (
          <div className="flex flex-col gap-2.5">
            {fileResults.map((r, i) => (
              <div key={r.id || i} className="bg-[#101e31] border border-[#243850] rounded-lg p-4 space-y-2">
                <div className="flex items-center justify-between gap-2 flex-wrap">
                  <strong className="text-sm text-[#e8eef9]">{r.filename}</strong>
                  <div className="flex items-center gap-2">
                    <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full font-semibold ${severityPillClasses(r.dlpStatus || 'CLEAN')}`}>
                      {r.dlpStatus}
                    </span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#1b3048] text-[#9fcfff]">
                      {r.sizeLabel}
                    </span>
                  </div>
                </div>
                <p className="text-xs text-[#8295b0]">{r.summary || 'Analysis completed.'}</p>
                <div className="text-[11px] font-mono text-[#7388a5]">
                  SHA-256: {r.sha256Hash} · Vault ID: {r.id}
                </div>
                <pre className="whitespace-pre-wrap text-[11px] font-mono text-[#9fcfff] bg-[#081321] border border-[#20344e] rounded-lg p-2.5">
                  {JSON.stringify(r.findings || [], null, 2)}
                </pre>
              </div>
            ))}
          </div>
        ) : (
          <div className="bg-[#0d192a] border border-[#1c3049] rounded-xl p-7 text-center text-xs text-[#7186a2]">
            No new files analyzed in this view yet. ({securityState.vaultItems.length} files currently stored in Vault.)
          </div>
        )}
      </div>
    );
  }

  function renderPipeline() {
    return (
      <div className="space-y-4">
        <div className="bg-[#0d192a] border border-[#1c3049] rounded-xl p-5 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div>
              <h3 className="text-sm font-semibold text-[#e8eef9]">Workflow Designer</h3>
              <p className="text-xs text-[#8295b0] mt-1">
                Configure workflow stages and persist them to disk in `skyguard-state.json`.
              </p>
            </div>
            <button
              onClick={addNode}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg border border-[#2a4b6b] bg-[#142943] hover:bg-[#1a3454] text-[#b9e2ff] text-xs font-medium cursor-pointer"
            >
              <Plus className="w-3.5 h-3.5" />
              Add Node
            </button>
          </div>

          <div className="max-w-xl">
            <label className="block text-[11px] font-mono text-[#8398b5] mb-1">PIPELINE NAME</label>
            <input
              value={pipelineName}
              onChange={(e) => setPipelineName(e.target.value)}
              className="w-full bg-[#081321] border border-[#263c57] text-[#eaf3ff] rounded-lg px-3 py-2 text-xs outline-none focus:border-[#35aaff]"
            />
          </div>

          <div className="flex flex-col gap-3 max-w-2xl">
            {nodes.map((node, index) => (
              <div
                key={node.id}
                className="p-3.5 border border-[#315477] bg-[#11243b] rounded-lg flex flex-col sm:flex-row sm:items-center gap-3"
              >
                <div className="flex-1 space-y-1.5">
                  <div className="text-[11px] font-mono text-[#8295b0]">
                    STEP {index + 1} · {node.type.toUpperCase()}
                  </div>
                  <input
                    className="w-full bg-[#081321] border border-[#263c57] text-[#eaf3ff] rounded-lg px-3 py-2 text-xs outline-none"
                    value={node.name}
                    onChange={(e) => updateNode(node.id, { name: e.target.value })}
                  />
                </div>
                <label className="inline-flex items-center gap-2 text-xs text-[#8295b0] cursor-pointer">
                  <input
                    type="checkbox"
                    checked={node.enabled}
                    onChange={(e) => updateNode(node.id, { enabled: e.target.checked })}
                  />
                  Enabled
                </label>
                <button
                  onClick={() => setNodes((prev) => prev.filter((n) => n.id !== node.id))}
                  className="px-2.5 py-1.5 rounded-lg bg-[#351c26] border border-[#773449] text-[#ff9eae] text-xs cursor-pointer"
                  aria-label="Remove pipeline node"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              </div>
            ))}
          </div>

          <button
            disabled={busy}
            onClick={createPipeline}
            className="px-4 py-2 rounded-lg bg-[#087bc4] hover:bg-[#0989db] disabled:opacity-45 text-white text-xs font-medium cursor-pointer"
          >
            Save Pipeline
          </button>
        </div>

        <div className="bg-[#0d192a] border border-[#1c3049] rounded-xl p-5 space-y-3">
          <h3 className="text-sm font-semibold text-[#e8eef9]">
            Persisted Pipelines ({savedPipelines.length})
          </h3>
          {savedPipelines.length === 0 ? (
            <div className="text-xs text-[#7186a2]">No saved pipelines yet.</div>
          ) : (
            <div className="space-y-2.5">
              {savedPipelines.map((p) => (
                <div
                  key={p.id}
                  className="bg-[#101e31] border border-[#243850] rounded-lg p-3.5 flex items-center justify-between gap-3"
                >
                  <div>
                    <div className="text-sm font-semibold text-[#e8eef9]">{p.name}</div>
                    <div className="text-[11px] font-mono text-[#8295b0]">
                      {p.id} · {p.nodes.filter((n) => n.enabled).length}/{p.nodes.length} stages active · by{' '}
                      {p.createdBy}
                    </div>
                  </div>
                  <button
                    onClick={() => removeSavedPipeline(p.id)}
                    className="px-3 py-1.5 rounded-lg bg-[#351c26] border border-[#773449] text-[#ff9eae] text-xs cursor-pointer"
                  >
                    Delete
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    );
  }

  function renderIntelligence() {
    return (
      <div className="space-y-4">
        <div className="bg-[#0d192a] border border-[#1c3049] rounded-xl p-5 space-y-3">
          <h3 className="text-sm font-semibold text-[#e8eef9]">Application Discovery Engine</h3>
          <p className="text-xs text-[#8295b0]">
            Inspects the real workspace filesystem, TypeScript frontend pages/components, Express API routes, npm
            dependencies, and active integrations on disk.
          </p>
          <button
            disabled={busy}
            onClick={loadApplicationInventory}
            className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg bg-[#087bc4] hover:bg-[#0989db] disabled:opacity-45 text-white text-xs font-medium cursor-pointer"
          >
            <Cpu className="w-3.5 h-3.5" />
            {busy ? 'Discovering...' : 'Run Application Inventory'}
          </button>

          {inventoryReport && (
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 pt-2">
              <Metric
                label="COMPONENTS DISCOVERED"
                value={String(inventoryReport.componentCount)}
                note="Source files + Express routes"
              />
              <Metric
                label="FRONTEND SOURCE FILES"
                value={String(inventoryReport.summary.sourceFiles)}
                note={`${inventoryReport.summary.pagesCount} pages · ${inventoryReport.summary.componentsCount} components`}
              />
              <Metric
                label="EXPRESS API ROUTES"
                value={String(inventoryReport.summary.apiRoutesCount)}
                note="Extracted live from server.ts"
              />
              <Metric
                label="RUNTIME DEPENDENCIES"
                value={String(inventoryReport.summary.dependenciesCount)}
                note="From package.json"
              />
            </div>
          )}
        </div>

        <div className="text-[15px] font-bold text-[#e8eef9]">Verification Standards</div>
        <div className="flex flex-col gap-2.5">
          {(inventoryReport?.verificationMatrix ||
            ['VERIFIED', 'PARTIALLY VERIFIED', 'UNVERIFIED', 'FAILED', 'NOT CONFIGURED'].map((status) => ({
              component: 'Discovery Pending',
              status,
              evidence: 'Run Application Inventory above to evaluate live repository evidence.',
            }))
          ).map((row, idx) => (
            <div
              key={`${row.component}-${idx}`}
              className="bg-[#101e31] border border-[#243850] rounded-lg p-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-2"
            >
              <div>
                <div className="text-xs font-semibold text-[#e8eef9]">{row.component}</div>
                <div className="text-[11px] font-mono text-[#8295b0] mt-0.5">{row.evidence}</div>
              </div>
              <span className={`text-[10px] font-mono px-2.5 py-1 rounded-full font-semibold ${severityPillClasses(row.status)}`}>
                {row.status}
              </span>
            </div>
          ))}
        </div>

        {inventoryReport && (
          <div className="bg-[#0d192a] border border-[#1c3049] rounded-xl p-5 overflow-x-auto">
            <h3 className="text-sm font-semibold text-[#e8eef9] mb-3">
              Discovered API Endpoints ({inventoryReport.routes.length})
            </h3>
            <table className="w-full border-collapse text-xs font-mono tabular-nums">
              <thead>
                <tr className="border-b border-[#22354d] text-[#8298b4]">
                  <th className="py-2.5 px-3 text-left font-medium">Method</th>
                  <th className="py-2.5 px-3 text-left font-medium">Route Path</th>
                </tr>
              </thead>
              <tbody>
                {inventoryReport.routes.slice(0, 30).map((r, i) => (
                  <tr key={`${r.method}-${r.path}-${i}`} className="border-b border-[#22354d]/60">
                    <td className="py-2 px-3 text-[#49aaff] font-semibold">{r.method}</td>
                    <td className="py-2 px-3 text-[#e8eef9]">{r.path}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    );
  }

  function renderIntegrations() {
    return (
      <div className="flex flex-col gap-3">
        <div className="bg-[#0d192a] border border-[#1c3049] rounded-xl p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h3 className="text-sm font-semibold text-[#e8eef9]">Google Gmail (Google Workspace OAuth)</h3>
            <p className="text-xs text-[#8295b0] mt-1">
              {googleEmail
                ? `Connected as ${googleEmail} (gmail.readonly scope)`
                : 'Client-side OAuth authorization and email security integration'}
            </p>
          </div>
          <div className="flex items-center gap-2">
            {renderGoogleSignInButton(googleEmail ? 'Re-Authorize Gmail' : 'Sign in with Google')}
            {gmailTokenPresent && (
              <button
                onClick={handleSyncGmailMessages}
                className="px-3.5 py-2 rounded-lg bg-[#087bc4] hover:bg-[#0989db] text-white text-xs font-medium cursor-pointer"
              >
                Sync Now
              </button>
            )}
          </div>
        </div>

        <div className="bg-[#0d192a] border border-[#1c3049] rounded-xl p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h3 className="text-sm font-semibold text-[#e8eef9]">Microsoft Outlook (.eml / Header Inspection)</h3>
            <p className="text-xs text-[#8295b0] mt-1">
              Upload `.eml` files or paste suspicious message payloads into the Email Protection sandbox.
            </p>
          </div>
          <button
            onClick={() => setPage('email')}
            className="px-4 py-2 rounded-lg border border-[#2a4b6b] bg-[#142943] hover:bg-[#1a3454] text-[#b9e2ff] text-xs font-medium cursor-pointer"
          >
            Open Email Sandbox
          </button>
        </div>

        {integrations.map((item, i) => (
          <div
            key={item.id || i}
            className="bg-[#0d192a] border border-[#1c3049] rounded-xl px-5 py-3.5 flex items-center justify-between gap-3"
          >
            <div>
              <strong className="text-xs text-[#e8eef9]">{item.name || item.provider}</strong>
              {item.category && (
                <div className="text-[11px] text-[#8295b0]">{item.category}</div>
              )}
            </div>
            <span className="text-[10px] font-mono px-2.5 py-1 rounded-full bg-[#1b3048] text-[#9fcfff] uppercase">
              {item.status}
            </span>
          </div>
        ))}
      </div>
    );
  }

  function renderMonitoring() {
    return (
      <div className="bg-[#0d192a] border border-[#1c3049] rounded-xl p-5 space-y-3">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-semibold text-[#e8eef9]">System Health</h3>
          <button
            onClick={refreshHealth}
            className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg border border-[#2a4b6b] bg-[#142943] text-[#b9e2ff] text-xs cursor-pointer"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Refresh
          </button>
        </div>
        <pre className="whitespace-pre-wrap text-xs font-mono tabular-nums text-[#9fcfff] bg-[#081321] border border-[#20344e] rounded-lg p-4">
          {JSON.stringify(health, null, 2)}
        </pre>
        <p className="text-xs text-[#8295b0]">
          Live server runtime telemetry: process uptime, memory heap usage, disk persistence verification, and
          real-time state counters.
        </p>
      </div>
    );
  }

  function renderBusiness() {
    return (
      <div className="space-y-4">
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3.5">
          <Metric
            label="COMPLIANCE FRAMEWORKS"
            value={String(securityState.complianceFrameworks.length)}
            note="Continuously monitored frameworks"
          />
          <Metric
            label="PROTECTED ASSETS"
            value={String(securityState.inventoryAssets.length)}
            note="Registered enterprise assets"
          />
          <Metric
            label="SAVED WORKFLOWS"
            value={String(savedPipelines.length)}
            note="Persisted protection pipelines"
          />
          <Metric
            label="SCANNED EMAILS"
            value={String(scannedEmails.length)}
            note="Gmail & manual .eml checks"
          />
        </div>
        <div className="bg-[#0d192a] border border-[#1c3049] rounded-xl p-5 space-y-3">
          <h3 className="text-sm font-semibold text-[#e8eef9]">Business Intelligence</h3>
          <p className="text-xs text-[#8295b0]">
            Analyze operational performance, uploaded business documents, compliance readiness, workflows, and security
            posture using authorized connected backend data and server-side Gemini AI.
          </p>
          <button
            onClick={() => setPage('assistant')}
            className="px-4 py-2 rounded-lg bg-[#087bc4] hover:bg-[#0989db] text-white text-xs font-medium cursor-pointer"
          >
            Ask AI to Analyze Business
          </button>
        </div>
      </div>
    );
  }

  function renderReports() {
    return (
      <div className="bg-[#0d192a] border border-[#1c3049] rounded-xl p-5 space-y-3">
        <h3 className="text-sm font-semibold text-[#e8eef9]">Security &amp; Business Reports</h3>
        <p className="text-xs text-[#8295b0]">
          Generate downloadable JSON audit snapshots directly from verified backend findings, scanned emails, saved
          workflows, and runtime health.
        </p>
        <div className="flex flex-wrap gap-2.5 pt-1">
          <button
            onClick={refreshFindings}
            className="px-4 py-2 rounded-lg border border-[#2a4b6b] bg-[#142943] hover:bg-[#1a3454] text-[#b9e2ff] text-xs font-medium cursor-pointer"
          >
            Refresh Findings
          </button>
          <button
            onClick={exportJsonReport}
            className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg bg-[#087bc4] hover:bg-[#0989db] text-white text-xs font-medium cursor-pointer"
          >
            <Download className="w-3.5 h-3.5" />
            Export Current Data (.json)
          </button>
        </div>
      </div>
    );
  }

  function renderSettings() {
    return (
      <div className="bg-[#0d192a] border border-[#1c3049] rounded-xl p-5 space-y-3">
        <h3 className="text-sm font-semibold text-[#e8eef9]">Security Configuration</h3>
        <p className="text-xs text-[#8295b0]">
          Bearer token authentication, scrypt password hashing, enclave disk persistence, and server-side Gemini API key
          isolation are enforced by the Express backend.
        </p>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs font-mono pt-1">
          <div className="bg-[#081321] border border-[#20344e] rounded-lg p-3">
            <div className="text-[#8295b0]">Disk State Persistence</div>
            <div className="text-[#8be1bd] mt-1">
              {health?.diskPersistence ? 'ACTIVE (data/skyguard-state.json)' : 'CHECKING'}
            </div>
          </div>
          <div className="bg-[#081321] border border-[#20344e] rounded-lg p-3">
            <div className="text-[#8295b0]">Google Workspace OAuth Config</div>
            <div className="text-[#8be1bd] mt-1">
              {health?.gmailOAuthConfigured ? 'CONFIGURED (gmail.readonly)' : 'NOT CONFIGURED'}
            </div>
          </div>
          <div className="bg-[#081321] border border-[#20344e] rounded-lg p-3">
            <div className="text-[#8295b0]">Server-Side Gemini AI Provider</div>
            <div className="text-[#9fcfff] mt-1">
              {health?.geminiConfigured ? 'CONFIGURED (gemini-4-hydrogen)' : 'NOT CONFIGURED'}
            </div>
          </div>
          <div className="bg-[#081321] border border-[#20344e] rounded-lg p-3">
            <div className="text-[#8295b0]">Google OAuth Token Storage</div>
            <div className="text-[#8be1bd] mt-1">STRICT MEMORY ONLY</div>
          </div>
        </div>
        <button
          onClick={refreshHealth}
          className="px-4 py-2 rounded-lg border border-[#2a4b6b] bg-[#142943] text-[#b9e2ff] text-xs font-medium cursor-pointer"
        >
          Check Backend
        </button>
      </div>
    );
  }

  const pageInfo: Record<Page, { title: string; description: string }> = {
    command: {
      title: 'Executive Command Center',
      description: 'Business protection, intelligence, and operational oversight.',
    },
    assistant: {
      title: 'AI Business Assistant',
      description: 'Server-side Gemini business and security operations assistant.',
    },
    email: {
      title: 'Email Protection Center',
      description: 'Authorize Gmail or inspect suspicious messages with DLP quarantine.',
    },
    threats: {
      title: 'Threat Intelligence',
      description: 'Investigate verified security findings and emerging threats.',
    },
    files: {
      title: 'File Intelligence',
      description: 'Upload, save permanently, analyze, and digest business documents and code.',
    },
    intelligence: {
      title: 'Application Intelligence',
      description: 'Discover application architecture, dependencies, and API routes.',
    },
    pipelines: {
      title: 'Automated Pipeline Builder',
      description: 'Design, inspect, and persist business protection workflows.',
    },
    business: {
      title: 'Business Intelligence',
      description: 'Understand operations and prioritize business improvements.',
    },
    monitoring: {
      title: 'System Health Monitoring',
      description: 'Inspect live service health and connected infrastructure.',
    },
    reports: {
      title: 'Reports & Analytics',
      description: 'Export verified findings and operational snapshots.',
    },
    integrations: {
      title: 'Integrations & Connections',
      description: 'Authorize and manage Google Workspace and security connectors.',
    },
    settings: {
      title: 'Settings & Security',
      description: 'Verify backend security posture and storage guarantees.',
    },
  };

  function renderPage() {
    switch (page) {
      case 'command':
        return renderCommand();
      case 'assistant':
        return renderAssistant();
      case 'email':
        return renderEmailProtection();
      case 'threats':
        return renderFindingsList();
      case 'files':
        return renderFiles();
      case 'intelligence':
        return renderIntelligence();
      case 'pipelines':
        return renderPipeline();
      case 'business':
        return renderBusiness();
      case 'monitoring':
        return renderMonitoring();
      case 'reports':
        return renderReports();
      case 'integrations':
        return renderIntegrations();
      case 'settings':
        return renderSettings();
      default:
        return renderCommand();
    }
  }

  return (
    <div className="bg-[#080e19] text-[#e8eef9] rounded-2xl border border-[#1c2b42] overflow-hidden flex flex-col md:flex-row min-h-[760px]">
      {/* Dark Command Sidebar */}
      <aside
        className={`bg-[#0b1423] border-b md:border-b-0 md:border-r border-[#1c2b42] p-3.5 flex flex-col shrink-0 transition-all ${
          collapsed ? 'md:w-[74px]' : 'md:w-[248px]'
        }`}
      >
        <div className="px-2.5 pt-1 pb-3 flex items-center justify-between">
          {!collapsed && (
            <div>
              <div className="text-lg font-extrabold tracking-widest text-white">
                SKY<span className="text-[#35aaff]">GUARD</span>
              </div>
              <div className="text-[9px] font-mono tracking-[0.18em] text-[#7086a4] mt-0.5">
                BUSINESS PROTECTION INTEL
              </div>
            </div>
          )}
          <button
            onClick={() => setCollapsed(!collapsed)}
            className="p-1.5 rounded-lg border border-[#25405d] bg-[#102138] text-[#91a4c0] hover:text-white cursor-pointer"
            title={collapsed ? 'Expand Navigation' : 'Collapse Navigation'}
          >
            {collapsed ? <PanelLeftOpen className="w-4 h-4" /> : <PanelLeftClose className="w-4 h-4" />}
          </button>
        </div>

        <nav className="grid grid-cols-2 sm:grid-cols-3 md:flex md:flex-col gap-1">
          {navigation.map((item) => {
            const Icon = item.icon;
            const isActive = page === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setPage(item.id)}
                title={item.label}
                className={`flex items-center gap-2.5 px-3 py-2.5 rounded-lg text-left text-xs font-medium transition-colors cursor-pointer ${
                  isActive
                    ? 'bg-[#142945] text-[#55b8ff]'
                    : 'text-[#91a4c0] hover:bg-[#142945]/60 hover:text-[#e8eef9]'
                }`}
              >
                <Icon className="w-4 h-4 shrink-0" />
                {!collapsed && <span className="truncate">{item.label}</span>}
              </button>
            );
          })}
        </nav>

        {!collapsed && (
          <div className="hidden md:block mt-auto border-t border-[#203047] pt-4 px-2 text-[11px] text-[#7f91ac]">
            <div className="font-mono font-semibold text-[#91a4c0]">SKYGUARD ENTERPRISE</div>
            <div className="mt-1">Business first. Security always.</div>
          </div>
        )}
      </aside>

      {/* Main Intelligence Viewport */}
      <section className="flex-1 min-w-0 p-5 sm:p-7 flex flex-col">
        <header className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-5 border-b border-[#1c2b42]/80">
          <div>
            <div className="text-[10px] font-mono tracking-[0.2em] text-[#49aaff] uppercase">
              SKYGUARD / ENTERPRISE INTELLIGENCE
            </div>
            <h1 className="text-xl sm:text-2xl font-bold text-white mt-1">{pageInfo[page].title}</h1>
            <p className="text-xs text-[#8295b0] mt-0.5">{pageInfo[page].description}</p>
          </div>
          <div className="self-start sm:self-center inline-flex items-center gap-2 border border-[#25405d] bg-[#102138] rounded-full px-3.5 py-1.5 text-[11px] font-mono text-[#67c1ff]">
            <CheckCircle2 className="w-3.5 h-3.5" />
            <span>{health?.status || 'CHECKING'}</span>
          </div>
        </header>

        {error && (
          <div className="mt-4 rounded-xl bg-[#351c26] border border-[#773449] px-4 py-3 flex items-center justify-between gap-3 text-xs text-[#ff9eae]">
            <div className="flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              <span>{error}</span>
            </div>
            <button onClick={() => setError('')} className="p-1 hover:text-white cursor-pointer" aria-label="Dismiss error">
              <X className="w-4 h-4" />
            </button>
          </div>
        )}

        {notice && (
          <div className="mt-4 rounded-xl bg-[#193b34] border border-[#2a5c51] px-4 py-3 flex items-center justify-between gap-3 text-xs text-[#8be1bd]">
            <div className="flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 shrink-0" />
              <span>{notice}</span>
            </div>
            <button onClick={() => setNotice('')} className="p-1 hover:text-white cursor-pointer" aria-label="Dismiss notice">
              <X className="w-4 h-4" />
            </button>
          </div>
        )}

        <div className="mt-4 flex-1">{renderPage()}</div>

        <footer className="text-[#7388a5] text-[11px] font-mono mt-6 pt-4 border-t border-[#1c2b42]/60">
          SkyGuard · Evidence-based business protection · Authorized operations only
        </footer>
      </section>
    </div>
  );
}
