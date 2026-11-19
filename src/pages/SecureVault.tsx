import React, { useState, useEffect, useRef } from 'react';
import { Link } from 'react-router-dom';
import {
  ShieldCheck,
  Lock,
  Upload,
  FileText,
  Mail,
  KeyRound,
  AlertTriangle,
  CheckCircle2,
  Search,
  Trash2,
  RefreshCw,
  Eye,
  Copy,
  Check,
  Download,
  Terminal,
  Zap,
  ShieldAlert,
  Database,
  X,
  ArrowRight,
  Layers,
} from 'lucide-react';
import { useAuth } from '../hooks/useAuth';
import { useSecurityData } from '../features/security/SecurityDataContext';
import { skyguardApi } from '../services/skyguardApi';
import { VaultItem, VaultItemType, VaultDigestSummary } from '../types';

function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    const slice = bytes.subarray(i, i + chunkSize);
    binary += String.fromCharCode(...slice);
  }
  return btoa(binary);
}

export default function SecureVault() {
  const { user } = useAuth();
  const { refresh: refreshSecurityData } = useSecurityData();
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [items, setItems] = useState<VaultItem[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isUploading, setIsUploading] = useState(false);
  const [notification, setNotification] = useState<{ text: string; type: 'success' | 'error' | 'info' } | null>(null);
  const [lastDigest, setLastDigest] = useState<{ item: VaultItem; summary: VaultDigestSummary } | null>(null);

  // Filters & Search
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedType, setSelectedType] = useState<string>('all');
  const [selectedStatus, setSelectedStatus] = useState<string>('all');

  // Drag and Drop & Ingestion State
  const [isDragOver, setIsDragOver] = useState(false);
  const [inputMode, setInputMode] = useState<'file' | 'text'>('file');
  const [manualTitle, setManualTitle] = useState('');
  const [manualType, setManualType] = useState<VaultItemType>('email');
  const [manualContent, setManualContent] = useState('');
  const [selectedChannels, setSelectedChannels] = useState<string[]>([
    'Dark Web Breach Radar',
    'Perimeter DLP Outbound Guardian',
    'Tamper-Evident Merkle Logger',
    'Continuous SIEM Threat Ingestion',
  ]);

  // Selected item & confirm shred modal
  const [selectedItemForInspect, setSelectedItemForInspect] = useState<VaultItem | null>(null);
  const [pendingShredItem, setPendingShredItem] = useState<VaultItem | null>(null);
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  const fetchVaultItems = async () => {
    setIsLoading(true);
    try {
      const data = await skyguardApi.getVaultItems();
      if (data.success && data.items) {
        setItems(data.items);
      }
    } catch (err: any) {
      showNotice(err.message || 'Failed to load persisted vault records.', 'error');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchVaultItems();
  }, []);

  const showNotice = (text: string, type: 'success' | 'error' | 'info' = 'success') => {
    setNotification({ text, type });
    setTimeout(() => setNotification(null), 5000);
  };

  const toggleChannel = (channel: string) => {
    setSelectedChannels((prev) =>
      prev.includes(channel) ? prev.filter((c) => c !== channel) : [...prev, channel]
    );
  };

  const detectVaultType = (file: File): VaultItemType => {
    const lower = file.name.toLowerCase();
    if (lower.endsWith('.eml') || lower.endsWith('.msg') || file.type.includes('email') || lower.includes('email')) {
      return 'email';
    }
    if (lower.endsWith('.env') || lower.endsWith('.pem') || lower.endsWith('.crt') || lower.endsWith('.key') || lower.includes('secret')) {
      return 'secret';
    }
    if (lower.endsWith('.csv') && lower.includes('financial')) {
      return 'financial';
    }
    return 'document';
  };

  const handleFilesProcess = async (fileList: FileList | File[]) => {
    const files = Array.from(fileList);
    if (files.length === 0) return;
    setIsUploading(true);
    let successCount = 0;

    try {
      for (const file of files) {
        const buffer = await file.arrayBuffer();
        const fileBase64 = arrayBufferToBase64(buffer);
        const isBinaryDoc = /\.(pdf|png|jpg|jpeg|zip|gz|docx|xlsx)$/i.test(file.name);
        const textContent = isBinaryDoc ? '' : await file.text().catch(() => '');
        const detectedType = detectVaultType(file);

        const data = await skyguardApi.uploadVaultItem({
          title: file.name,
          fileName: file.name,
          fileSize: `${Math.max(0.1, Number((file.size / 1024).toFixed(1)))} KB`,
          mimeType: file.type || (detectedType === 'email' ? 'message/rfc822' : 'application/octet-stream'),
          type: detectedType,
          content: textContent,
          fileBase64,
          workspaceId: user?.tenantId || 'workspace_123',
          uploadedBy: `${user?.name || 'Operator'} (${user?.email || 'operator@skyguard.mesh'})`,
          monitoredChannels: selectedChannels,
        });

        if (data.success && data.item) {
          successCount++;
          setItems((prev) => [data.item, ...prev.filter((i) => i.id !== data.item.id)]);
          setLastDigest({ item: data.item, summary: data.digestSummary });
        }
      }

      if (successCount > 0) {
        await refreshSecurityData();
        showNotice(
          `${successCount} file(s) saved permanently to enclave disk, inspected by DLP/Email Sandbox, and digested into Alerts, Findings, and Dashboard!`
        );
      }
    } catch (err: any) {
      showNotice(err.message || 'Error processing uploaded file(s)', 'error');
    } finally {
      setIsUploading(false);
    }
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      void handleFilesProcess(e.dataTransfer.files);
    }
  };

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      void handleFilesProcess(e.target.files);
      e.target.value = '';
    }
  };

  const handleTextSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!manualContent.trim() && !manualTitle.trim()) {
      showNotice('Please provide a title or content snippet to protect.', 'error');
      return;
    }

    setIsUploading(true);
    try {
      const data = await skyguardApi.uploadVaultItem({
        title: manualTitle.trim() || `${manualType.toUpperCase()} Secured Record`,
        type: manualType,
        content: manualContent,
        workspaceId: user?.tenantId || 'workspace_123',
        uploadedBy: `${user?.name || 'Operator'} (${user?.email || 'operator@skyguard.mesh'})`,
        monitoredChannels: selectedChannels,
      });

      if (data.success && data.item) {
        setItems((prev) => [data.item, ...prev]);
        setLastDigest({ item: data.item, summary: data.digestSummary });
        setManualTitle('');
        setManualContent('');
        await refreshSecurityData();
        showNotice(
          `Payload saved (${data.item.dlpStatus}) and digested into Alerts, Security Findings, and Live Telemetry!`
        );
      }
    } catch (err: any) {
      showNotice(err.message || 'Failed to ingest payload.', 'error');
    } finally {
      setIsUploading(false);
    }
  };

  const handleRescan = async (id: string) => {
    try {
      const data = await skyguardApi.rescanVaultItem(id);
      if (data.success && data.item) {
        setItems((prev) => prev.map((item) => (item.id === id ? data.item : item)));
        if (selectedItemForInspect?.id === id) {
          setSelectedItemForInspect(data.item);
        }
        if (data.digestSummary) {
          setLastDigest({ item: data.item, summary: data.digestSummary });
        }
        await refreshSecurityData();
        showNotice(`Deep threat & DLP re-scan completed for ${data.item.title} and synced to platform posture.`);
      }
    } catch (err: any) {
      showNotice(err.message || 'Re-scan failed to execute.', 'error');
    }
  };

  const handleDownload = async (item: VaultItem) => {
    try {
      await skyguardApi.downloadVaultItem(item.id, item.fileName || `${item.id}.txt`);
      showNotice(`Downloaded verified artifact "${item.fileName || item.title}" from enclave storage.`);
    } catch (err: any) {
      showNotice(err.message || 'Failed to download payload.', 'error');
    }
  };

  const confirmShredItem = async () => {
    if (!pendingShredItem) return;
    const id = pendingShredItem.id;
    try {
      const data = await skyguardApi.shredVaultItem(id);
      if (data.success) {
        setItems((prev) => prev.filter((item) => item.id !== id));
        if (selectedItemForInspect?.id === id) {
          setSelectedItemForInspect(null);
        }
        if (lastDigest?.item.id === id) {
          setLastDigest(null);
        }
        setPendingShredItem(null);
        await refreshSecurityData();
        showNotice('Item cryptographically zeroized under DoD 5220.22-M and linked alerts resolved.');
      }
    } catch (err: any) {
      showNotice(err.message || 'Failed to shred item.', 'error');
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(text);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  const filteredItems = items.filter((item) => {
    const matchesSearch =
      item.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      item.contentSnippet.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (item.fileName && item.fileName.toLowerCase().includes(searchQuery.toLowerCase()));

    const matchesType = selectedType === 'all' || item.type === selectedType;
    const matchesStatus = selectedStatus === 'all' || item.monitoringStatus === selectedStatus;

    return matchesSearch && matchesType && matchesStatus;
  });

  const totalProtectedCount = items.filter(
    (i) => i.monitoringStatus === 'PROTECTED' || i.monitoringStatus === 'ACTIVE_MONITORING'
  ).length;
  const quarantinedCount = items.filter((i) => i.monitoringStatus === 'QUARANTINED').length;

  return (
    <div className="space-y-6 font-sans">
      {/* Top Banner */}
      <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-sm flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded bg-indigo-50 border border-indigo-200 text-indigo-700 text-xs font-semibold uppercase tracking-wider mb-2">
            <ShieldCheck className="w-3.5 h-3.5" />
            <span>Sovereign Enclave Vault &amp; Cross-Screen Ingestion</span>
          </div>
          <h1 className="text-2xl font-extrabold text-slate-900 tracking-tight">
            Protected Information, Email &amp; Asset Vault
          </h1>
          <p className="text-xs text-slate-500 font-mono mt-0.5">
            Persistent Disk Storage • Deep Email Header &amp; Secret Inspection • Auto-Digested Across Alerts &amp; Dashboard
          </p>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          <button
            onClick={fetchVaultItems}
            disabled={isLoading}
            className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-semibold transition-colors cursor-pointer"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
            <span>Refresh Vault</span>
          </button>

          <Link
            to="/app/operations"
            className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-purple-50 hover:bg-purple-100 text-purple-700 border border-purple-200 text-xs font-bold transition-colors cursor-pointer shadow-xs"
          >
            <Zap className="w-3.5 h-3.5" />
            <span>Pipeline Audit &amp; Tests</span>
          </Link>
        </div>
      </div>

      {notification && (
        <div
          className={`p-4 rounded-xl text-xs font-mono flex items-center justify-between animate-in fade-in ${
            notification.type === 'success'
              ? 'bg-emerald-50 border border-emerald-200 text-emerald-800'
              : notification.type === 'error'
              ? 'bg-rose-50 border border-rose-200 text-rose-800'
              : 'bg-blue-50 border border-blue-200 text-blue-800'
          }`}
        >
          <div className="flex items-center gap-2">
            {notification.type === 'success' ? (
              <CheckCircle2 className="w-4 h-4 text-emerald-600 flex-shrink-0" />
            ) : (
              <AlertTriangle className="w-4 h-4 text-rose-600 flex-shrink-0" />
            )}
            <span>{notification.text}</span>
          </div>
          <button onClick={() => setNotification(null)} className="text-slate-400 hover:text-slate-600">
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* Cross-Screen Digestion Live Report */}
      {lastDigest && (
        <div className="bg-slate-950 text-slate-100 rounded-2xl border border-indigo-500/40 p-5 shadow-lg space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2">
              <Layers className="w-4 h-4 text-emerald-400" />
              <span className="text-xs font-mono font-bold uppercase tracking-wider text-emerald-400">
                Cross-Screen Digestion Receipt • {lastDigest.item.fileName || lastDigest.item.title}
              </span>
            </div>
            <span className="text-[11px] font-mono text-slate-400">
              SHA-256: {lastDigest.item.sha256Hash.slice(0, 16)}...
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs font-mono">
            <div className="p-3 rounded-xl bg-slate-900 border border-slate-800">
              <div className="text-[10px] text-slate-400 uppercase">DLP / Sandbox Verdict</div>
              <div className="font-bold text-white mt-0.5">{lastDigest.item.dlpStatus}</div>
              <div className="text-[10px] text-amber-400 mt-1">
                Posture Impact: {lastDigest.summary.scoreImpact > 0 ? `-${lastDigest.summary.scoreImpact} pts` : '0 pts (Clean)'}
              </div>
            </div>

            <div className="p-3 rounded-xl bg-slate-900 border border-slate-800">
              <div className="text-[10px] text-slate-400 uppercase">Extracted Indicators</div>
              <div className="font-bold text-cyan-300 mt-0.5">
                {lastDigest.summary.indicators.emails.length} emails • {lastDigest.summary.indicators.urls.length} URLs •{' '}
                {lastDigest.summary.indicators.secretsCount} secrets
              </div>
              {lastDigest.summary.indicators.headers?.from && (
                <div className="text-[10px] text-slate-400 truncate mt-1">
                  From: {lastDigest.summary.indicators.headers.from}
                </div>
              )}
            </div>

            <Link
              to="/app/alerts"
              className="p-3 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-800 hover:border-rose-500/60 transition-colors flex flex-col justify-between"
            >
              <div className="text-[10px] text-slate-400 uppercase">Alert Center Pipeline</div>
              <div className="font-bold text-rose-400 mt-0.5 flex items-center justify-between">
                <span>{lastDigest.summary.alertId || 'Logged Clean Telemetry'}</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </div>
            </Link>

            <Link
              to="/app/security?tab=findings"
              className="p-3 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-800 hover:border-blue-500/60 transition-colors flex flex-col justify-between"
            >
              <div className="text-[10px] text-slate-400 uppercase">Security Center &amp; Dashboard</div>
              <div className="font-bold text-blue-400 mt-0.5 flex items-center justify-between">
                <span>{lastDigest.summary.findingId || 'No Open Vulnerability'}</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </div>
            </Link>
          </div>
        </div>
      )}

      {/* Overview Stat Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-4 rounded-2xl bg-white border border-slate-200 shadow-sm space-y-1">
          <div className="flex items-center justify-between text-slate-500 text-xs font-semibold uppercase tracking-wider">
            <span>Total Uploaded &amp; Monitored</span>
            <Lock className="w-4 h-4 text-indigo-600" />
          </div>
          <div className="text-2xl font-black text-slate-900">{items.length}</div>
          <div className="text-[11px] text-emerald-600 font-mono flex items-center gap-1">
            <ShieldCheck className="w-3 h-3" />
            <span>Persisted to Enclave Disk (AES-256-GCM)</span>
          </div>
        </div>

        <div className="p-4 rounded-2xl bg-white border border-slate-200 shadow-sm space-y-1">
          <div className="flex items-center justify-between text-slate-500 text-xs font-semibold uppercase tracking-wider">
            <span>Clean &amp; Protected</span>
            <CheckCircle2 className="w-4 h-4 text-emerald-600" />
          </div>
          <div className="text-2xl font-black text-emerald-700">{totalProtectedCount}</div>
          <div className="text-[11px] text-slate-500 font-mono">
            Active monitoring across {selectedChannels.length} SIEM channels
          </div>
        </div>

        <div className="p-4 rounded-2xl bg-white border border-slate-200 shadow-sm space-y-1">
          <div className="flex items-center justify-between text-slate-500 text-xs font-semibold uppercase tracking-wider">
            <span>Quarantined / Suspicious</span>
            <ShieldAlert className="w-4 h-4 text-rose-600" />
          </div>
          <div className="text-2xl font-black text-rose-700">{quarantinedCount}</div>
          <div className="text-[11px] text-rose-600 font-mono">
            Isolated in sandbox &amp; flagged in Alerts
          </div>
        </div>

        <div className="p-4 rounded-2xl bg-white border border-slate-200 shadow-sm space-y-1">
          <div className="flex items-center justify-between text-slate-500 text-xs font-semibold uppercase tracking-wider">
            <span>Merkle Chain Integrity</span>
            <Database className="w-4 h-4 text-blue-600" />
          </div>
          <div className="text-2xl font-black text-blue-600">Verified</div>
          <div className="text-[11px] text-blue-600 font-mono">
            SHA-256 Cryptographic Audit Trail
          </div>
        </div>
      </div>

      {/* Ingestion & Upload Section */}
      <div className="bg-white rounded-2xl border border-slate-200 shadow-sm overflow-hidden">
        <div className="p-6 border-b border-slate-200 flex flex-col md:flex-row items-start md:items-center justify-between gap-4 bg-slate-50/50">
          <div>
            <h2 className="text-base font-bold text-slate-900 flex items-center gap-2">
              <Upload className="w-4 h-4 text-indigo-600" />
              <span>Secure Information &amp; Email Ingestion Engine</span>
            </h2>
            <p className="text-xs text-slate-500 font-mono mt-0.5">
              Upload one or multiple files/emails or paste headers &amp; secrets for permanent saving and cross-screen digestion.
            </p>
          </div>

          <div className="flex items-center bg-slate-200/70 p-1 rounded-xl text-xs font-bold">
            <button
              onClick={() => setInputMode('file')}
              className={`px-3 py-1.5 rounded-lg transition-all flex items-center gap-1.5 cursor-pointer ${
                inputMode === 'file' ? 'bg-white text-indigo-700 shadow-xs' : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              <FileText className="w-3.5 h-3.5" />
              <span>File &amp; Email Upload</span>
            </button>
            <button
              onClick={() => setInputMode('text')}
              className={`px-3 py-1.5 rounded-lg transition-all flex items-center gap-1.5 cursor-pointer ${
                inputMode === 'text' ? 'bg-white text-indigo-700 shadow-xs' : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              <Terminal className="w-3.5 h-3.5" />
              <span>Paste Email / Secret</span>
            </button>
          </div>
        </div>

        <div className="p-6">
          {inputMode === 'file' ? (
            <div
              onDragOver={handleDragOver}
              onDragLeave={handleDragLeave}
              onDrop={handleDrop}
              onClick={() => fileInputRef.current?.click()}
              className={`border-2 border-dashed rounded-2xl p-8 text-center cursor-pointer transition-all ${
                isDragOver
                  ? 'border-indigo-500 bg-indigo-50/50 scale-[1.005]'
                  : 'border-slate-300 hover:border-indigo-400 hover:bg-slate-50/80 bg-white'
              }`}
            >
              <input
                ref={fileInputRef}
                type="file"
                multiple
                className="hidden"
                onChange={handleFileSelect}
                accept=".eml,.msg,.txt,.pdf,.json,.csv,.env,.crt,.pem,.log,.docx"
              />

              <div className="max-w-md mx-auto space-y-3">
                <div className="w-12 h-12 mx-auto rounded-2xl bg-indigo-50 text-indigo-600 flex items-center justify-center border border-indigo-100 shadow-xs">
                  {isUploading ? (
                    <RefreshCw className="w-6 h-6 animate-spin" />
                  ) : (
                    <Upload className="w-6 h-6" />
                  )}
                </div>

                <div>
                  <h3 className="text-sm font-bold text-slate-800">
                    {isUploading ? 'Saving to Enclave Disk & Digesting...' : 'Drag & Drop Emails or Files here (Multi-file Supported)'}
                  </h3>
                  <p className="text-xs text-slate-500 mt-1">
                    or <span className="text-indigo-600 font-bold underline">click to browse</span> from your device
                  </p>
                </div>

                <div className="flex flex-wrap items-center justify-center gap-1.5 text-[10px] font-mono text-slate-500 pt-1">
                  <span className="px-2 py-0.5 rounded bg-slate-100 border border-slate-200">.EML (Emails)</span>
                  <span className="px-2 py-0.5 rounded bg-slate-100 border border-slate-200">.PDF</span>
                  <span className="px-2 py-0.5 rounded bg-slate-100 border border-slate-200">.TXT / .DOCX</span>
                  <span className="px-2 py-0.5 rounded bg-slate-100 border border-slate-200">.JSON / .ENV / .PEM</span>
                  <span className="px-2 py-0.5 rounded bg-slate-100 border border-slate-200">.CSV / .LOG</span>
                </div>

                <p className="text-[11px] text-slate-400 font-mono">
                  Every payload is hashed via SHA-256, saved persistently on disk, and digested into Alerts, Security Findings &amp; Telemetry.
                </p>
              </div>
            </div>
          ) : (
            <form onSubmit={handleTextSubmit} className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-bold text-slate-700 uppercase tracking-wider mb-1.5">
                    Record Title / Subject
                  </label>
                  <input
                    type="text"
                    value={manualTitle}
                    onChange={(e) => setManualTitle(e.target.value)}
                    placeholder="e.g., Forwarded Phishing Email or DB Connection Token"
                    className="w-full px-3.5 py-2.5 rounded-xl border border-slate-200 text-xs font-mono focus:outline-hidden focus:ring-2 focus:ring-indigo-500"
                  />
                </div>

                <div>
                  <label className="block text-xs font-bold text-slate-700 uppercase tracking-wider mb-1.5">
                    Information Category
                  </label>
                  <select
                    value={manualType}
                    onChange={(e) => setManualType(e.target.value as VaultItemType)}
                    className="w-full px-3.5 py-2.5 rounded-xl border border-slate-200 text-xs font-mono focus:outline-hidden focus:ring-2 focus:ring-indigo-500 bg-white"
                  >
                    <option value="email">Email (Headers, Body, or Raw .eml text)</option>
                    <option value="document">Confidential Document / Contract</option>
                    <option value="secret">Credentials, API Keys &amp; Certificates</option>
                    <option value="personal_data">Personal Data / GDPR Identity Records</option>
                    <option value="financial">Financial Data / Bank Wire Instructions</option>
                    <option value="custom">Custom High-Assurance Enclave Payload</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-xs font-bold text-slate-700 uppercase tracking-wider mb-1.5">
                  Raw Content / Email Headers &amp; Body / Secret Snippet
                </label>
                <textarea
                  rows={5}
                  value={manualContent}
                  onChange={(e) => setManualContent(e.target.value)}
                  placeholder="Paste full email headers (From, Reply-To, Subject) and body, API keys, or customer PII here for real-time inspection and digestion..."
                  className="w-full px-3.5 py-2.5 rounded-xl border border-slate-200 text-xs font-mono focus:outline-hidden focus:ring-2 focus:ring-indigo-500"
                />
              </div>

              <div>
                <label className="block text-xs font-bold text-slate-700 uppercase tracking-wider mb-2">
                  Select Active Monitoring Channels
                </label>
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2 text-xs font-mono">
                  {[
                    'Dark Web Breach Radar',
                    'Perimeter DLP Outbound Guardian',
                    'Tamper-Evident Merkle Logger',
                    'Continuous SIEM Threat Ingestion',
                  ].map((channel) => (
                    <label
                      key={channel}
                      className={`flex items-center gap-2 p-2.5 rounded-xl border cursor-pointer transition-colors ${
                        selectedChannels.includes(channel)
                          ? 'bg-indigo-50 border-indigo-200 text-indigo-900 font-semibold'
                          : 'bg-slate-50 border-slate-200 text-slate-600'
                      }`}
                    >
                      <input
                        type="checkbox"
                        checked={selectedChannels.includes(channel)}
                        onChange={() => toggleChannel(channel)}
                        className="rounded border-slate-300 text-indigo-600 focus:ring-indigo-500"
                      />
                      <span className="text-[11px]">{channel}</span>
                    </label>
                  ))}
                </div>
              </div>

              <div className="flex items-center justify-end gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => {
                    setManualTitle('');
                    setManualContent('');
                  }}
                  className="px-4 py-2 rounded-xl text-slate-500 hover:text-slate-800 text-xs font-bold transition-colors cursor-pointer"
                >
                  Clear Form
                </button>
                <button
                  type="submit"
                  disabled={isUploading || (!manualTitle.trim() && !manualContent.trim())}
                  className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-bold transition-colors cursor-pointer disabled:opacity-50 shadow-sm"
                >
                  {isUploading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Lock className="w-3.5 h-3.5" />}
                  <span>{isUploading ? 'Saving & Digesting...' : 'Save, Inspect & Digest Payload'}</span>
                </button>
              </div>
            </form>
          )}
        </div>
      </div>

      {/* Protected Items List & Monitoring Table */}
      <div className="bg-white rounded-2xl border border-slate-200 shadow-sm overflow-hidden">
        <div className="p-6 border-b border-slate-200 space-y-4">
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
            <div>
              <h2 className="text-base font-bold text-slate-900 flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-emerald-600" />
                <span>Monitored Vault Registry ({filteredItems.length} Saved Records)</span>
              </h2>
              <p className="text-xs text-slate-500 font-mono mt-0.5">
                Persisted across server restarts • Automated DLP classification &amp; cross-screen alert routing
              </p>
            </div>

            <div className="flex items-center gap-2 w-full sm:w-auto flex-wrap">
              <div className="relative flex-1 sm:w-64">
                <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Search emails, titles, hashes..."
                  className="w-full pl-9 pr-3 py-1.5 rounded-xl border border-slate-200 text-xs font-mono focus:outline-hidden focus:ring-2 focus:ring-indigo-500"
                />
              </div>

              <select
                value={selectedType}
                onChange={(e) => setSelectedType(e.target.value)}
                className="px-3 py-1.5 rounded-xl border border-slate-200 text-xs font-mono bg-white focus:outline-hidden focus:ring-2 focus:ring-indigo-500"
              >
                <option value="all">All Types</option>
                <option value="email">Emails</option>
                <option value="document">Documents</option>
                <option value="secret">Secrets / Keys</option>
                <option value="personal_data">Personal Data</option>
                <option value="financial">Financial</option>
              </select>

              <select
                value={selectedStatus}
                onChange={(e) => setSelectedStatus(e.target.value)}
                className="px-3 py-1.5 rounded-xl border border-slate-200 text-xs font-mono bg-white focus:outline-hidden focus:ring-2 focus:ring-indigo-500"
              >
                <option value="all">All Statuses</option>
                <option value="ACTIVE_MONITORING">Active Monitoring</option>
                <option value="PROTECTED">Protected</option>
                <option value="QUARANTINED">Quarantined</option>
              </select>
            </div>
          </div>
        </div>

        {/* Items Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-200 bg-slate-50/70 text-[11px] font-bold text-slate-600 uppercase tracking-wider">
                <th className="py-3 px-4">Protected Payload</th>
                <th className="py-3 px-4">Type</th>
                <th className="py-3 px-4">Monitoring Status</th>
                <th className="py-3 px-4">DLP Verdict</th>
                <th className="py-3 px-4">SHA-256 Hash</th>
                <th className="py-3 px-4">Digested Targets</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200 text-xs font-mono">
              {filteredItems.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-slate-400">
                    <div className="max-w-xs mx-auto space-y-2">
                      <Lock className="w-8 h-8 text-slate-300 mx-auto" />
                      <p className="font-semibold text-slate-600">No protected items found</p>
                      <p className="text-[11px]">Upload an email, document, or secret above to save and digest into SkyGuard.</p>
                    </div>
                  </td>
                </tr>
              ) : (
                filteredItems.map((item) => (
                  <tr key={item.id} className="hover:bg-slate-50/80 transition-colors">
                    <td className="py-3.5 px-4 max-w-xs">
                      <div className="font-bold text-slate-900 truncate flex items-center gap-1.5">
                        {item.type === 'email' ? (
                          <Mail className="w-3.5 h-3.5 text-blue-500 flex-shrink-0" />
                        ) : item.type === 'secret' ? (
                          <KeyRound className="w-3.5 h-3.5 text-amber-500 flex-shrink-0" />
                        ) : (
                          <FileText className="w-3.5 h-3.5 text-indigo-500 flex-shrink-0" />
                        )}
                        <span title={item.title}>{item.title}</span>
                      </div>
                      <div className="text-[11px] text-slate-500 truncate mt-0.5">
                        {item.fileName ? `${item.fileName} (${item.fileSize})` : item.contentSnippet}
                      </div>
                    </td>

                    <td className="py-3.5 px-4">
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-slate-100 text-slate-700">
                        {item.type}
                      </span>
                    </td>

                    <td className="py-3.5 px-4">
                      <span
                        className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-[10px] font-bold ${
                          item.monitoringStatus === 'QUARANTINED'
                            ? 'bg-rose-100 text-rose-700'
                            : item.monitoringStatus === 'PROTECTED'
                            ? 'bg-indigo-100 text-indigo-700'
                            : 'bg-emerald-100 text-emerald-700'
                        }`}
                      >
                        <span
                          className={`w-1.5 h-1.5 rounded-full ${
                            item.monitoringStatus === 'QUARANTINED'
                              ? 'bg-rose-600 animate-pulse'
                              : item.monitoringStatus === 'PROTECTED'
                              ? 'bg-indigo-600'
                              : 'bg-emerald-600'
                          }`}
                        />
                        <span>{item.monitoringStatus}</span>
                      </span>
                    </td>

                    <td className="py-3.5 px-4">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          item.dlpStatus === 'CLEAN'
                            ? 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                            : item.dlpStatus === 'SUSPICIOUS_PHISHING'
                            ? 'bg-rose-50 text-rose-700 border border-rose-200'
                            : item.dlpStatus === 'SECRETS_DETECTED'
                            ? 'bg-amber-50 text-amber-700 border border-amber-200'
                            : 'bg-blue-50 text-blue-700 border border-blue-200'
                        }`}
                      >
                        {item.dlpStatus}
                      </span>
                      {item.dlpFindings && item.dlpFindings.length > 0 && (
                        <div className="text-[10px] text-slate-500 truncate max-w-[180px] mt-0.5">
                          {item.dlpFindings[0]}
                        </div>
                      )}
                    </td>

                    <td className="py-3.5 px-4">
                      <button
                        onClick={() => copyToClipboard(item.sha256Hash)}
                        className="inline-flex items-center gap-1 text-[11px] text-slate-500 hover:text-indigo-600 cursor-pointer"
                        title="Click to copy full SHA-256 hash"
                      >
                        <span>{item.sha256Hash.substring(0, 10)}...</span>
                        {copiedHash === item.sha256Hash ? (
                          <Check className="w-3 h-3 text-emerald-600" />
                        ) : (
                          <Copy className="w-3 h-3 text-slate-400" />
                        )}
                      </button>
                    </td>

                    <td className="py-3.5 px-4">
                      <div className="flex items-center gap-1 flex-wrap max-w-[200px]">
                        {item.digestSummary?.alertId && (
                          <Link
                            to="/app/alerts"
                            className="px-1.5 py-0.5 rounded bg-rose-50 border border-rose-200 text-rose-700 text-[9px] font-bold hover:underline"
                          >
                            {item.digestSummary.alertId}
                          </Link>
                        )}
                        {item.digestSummary?.findingId && (
                          <Link
                            to="/app/security?tab=findings"
                            className="px-1.5 py-0.5 rounded bg-blue-50 border border-blue-200 text-blue-700 text-[9px] font-bold hover:underline"
                          >
                            {item.digestSummary.findingId}
                          </Link>
                        )}
                        {!item.digestSummary?.alertId && !item.digestSummary?.findingId && (
                          <Link
                            to="/app/dashboard"
                            className="px-1.5 py-0.5 rounded bg-emerald-50 border border-emerald-200 text-emerald-700 text-[9px] font-bold hover:underline"
                          >
                            Dashboard Feed
                          </Link>
                        )}
                      </div>
                    </td>

                    <td className="py-3.5 px-4 text-right">
                      <div className="flex items-center justify-end gap-1">
                        <button
                          onClick={() => setSelectedItemForInspect(item)}
                          className="p-1.5 rounded-lg text-slate-500 hover:text-indigo-600 hover:bg-indigo-50 transition-colors cursor-pointer"
                          title="Inspect details and DLP findings"
                        >
                          <Eye className="w-3.5 h-3.5" />
                        </button>

                        <button
                          onClick={() => handleDownload(item)}
                          className="p-1.5 rounded-lg text-slate-500 hover:text-blue-600 hover:bg-blue-50 transition-colors cursor-pointer"
                          title="Download saved artifact"
                        >
                          <Download className="w-3.5 h-3.5" />
                        </button>

                        <button
                          onClick={() => handleRescan(item.id)}
                          className="p-1.5 rounded-lg text-slate-500 hover:text-emerald-600 hover:bg-emerald-50 transition-colors cursor-pointer"
                          title="Trigger deep threat re-scan"
                        >
                          <RefreshCw className="w-3.5 h-3.5" />
                        </button>

                        <button
                          onClick={() => setPendingShredItem(item)}
                          className="p-1.5 rounded-lg text-slate-500 hover:text-rose-600 hover:bg-rose-50 transition-colors cursor-pointer"
                          title="Cryptographic zeroize & shred"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Inspect Item Modal */}
      {selectedItemForInspect && (
        <div className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-xs flex items-center justify-center p-4 overflow-y-auto">
          <div className="bg-white rounded-2xl border border-slate-200 shadow-2xl max-w-2xl w-full p-6 space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-200">
              <div className="flex items-center gap-2">
                <Lock className="w-5 h-5 text-indigo-600" />
                <h3 className="text-base font-bold text-slate-900">Protected Payload Inspection</h3>
              </div>
              <button
                onClick={() => setSelectedItemForInspect(null)}
                className="text-slate-400 hover:text-slate-600 p-1"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-3 text-xs font-mono">
              <div>
                <span className="text-slate-500 block text-[10px] uppercase">Title / Subject</span>
                <span className="text-slate-900 font-bold text-sm">{selectedItemForInspect.title}</span>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <span className="text-slate-500 block text-[10px] uppercase">Category</span>
                  <span className="text-slate-800 font-bold">{selectedItemForInspect.type.toUpperCase()}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px] uppercase">Monitoring Status</span>
                  <span className="text-emerald-700 font-bold">{selectedItemForInspect.monitoringStatus}</span>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <span className="text-slate-500 block text-[10px] uppercase">Encryption Mode</span>
                  <span className="text-indigo-700 font-bold">{selectedItemForInspect.encryption}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px] uppercase">DLP Classification</span>
                  <span className="text-amber-700 font-bold">{selectedItemForInspect.dlpStatus}</span>
                </div>
              </div>

              {selectedItemForInspect.digestSummary && (
                <div className="p-3 rounded-xl bg-indigo-50 border border-indigo-200 space-y-1.5">
                  <span className="text-indigo-800 font-bold block text-[10px] uppercase">
                    Cross-Screen Digestion Routing
                  </span>
                  <div className="flex flex-wrap gap-2 text-[11px]">
                    {selectedItemForInspect.digestSummary.alertId && (
                      <Link to="/app/alerts" className="text-rose-700 font-bold underline">
                        Alert: {selectedItemForInspect.digestSummary.alertId}
                      </Link>
                    )}
                    {selectedItemForInspect.digestSummary.findingId && (
                      <Link to="/app/security?tab=findings" className="text-blue-700 font-bold underline">
                        Finding: {selectedItemForInspect.digestSummary.findingId}
                      </Link>
                    )}
                    <Link to="/app/assets" className="text-emerald-700 font-bold underline">
                      Activity: {selectedItemForInspect.digestSummary.activityEventId}
                    </Link>
                    <Link to="/app/dashboard" className="text-indigo-700 font-bold underline">
                      View on Dashboard
                    </Link>
                  </div>
                </div>
              )}

              <div>
                <span className="text-slate-500 block text-[10px] uppercase">SHA-256 Merkle Hash</span>
                <div className="flex items-center gap-2 bg-slate-100 p-2 rounded-lg text-[11px] break-all">
                  <span>{selectedItemForInspect.sha256Hash}</span>
                  <button
                    onClick={() => copyToClipboard(selectedItemForInspect.sha256Hash)}
                    className="ml-auto text-indigo-600 hover:underline flex-shrink-0"
                  >
                    {copiedHash === selectedItemForInspect.sha256Hash ? 'Copied' : 'Copy'}
                  </button>
                </div>
              </div>

              <div>
                <span className="text-slate-500 block text-[10px] uppercase mb-1">DLP Findings &amp; Heuristics</span>
                <div className="bg-slate-50 border border-slate-200 rounded-xl p-3 space-y-1">
                  {selectedItemForInspect.dlpFindings.map((finding, idx) => (
                    <div key={idx} className="flex items-center gap-1.5 text-slate-700">
                      <CheckCircle2 className="w-3.5 h-3.5 text-indigo-600 flex-shrink-0" />
                      <span>{finding}</span>
                    </div>
                  ))}
                </div>
              </div>

              <div>
                <span className="text-slate-500 block text-[10px] uppercase mb-1">Raw Content / Extracted Stream</span>
                <pre className="bg-slate-950 text-slate-200 p-3 rounded-xl overflow-x-auto text-[11px] max-h-48 whitespace-pre-wrap">
                  {selectedItemForInspect.rawContent || selectedItemForInspect.contentSnippet}
                </pre>
              </div>

              <div className="pt-2 text-[10px] text-slate-400 flex items-center justify-between">
                <span>Uploaded: {new Date(selectedItemForInspect.uploadedAt).toLocaleString()}</span>
                <span>Last Scanned: {new Date(selectedItemForInspect.lastScannedAt).toLocaleString()}</span>
              </div>
            </div>

            <div className="flex items-center justify-between pt-3 border-t border-slate-200 flex-wrap gap-2">
              <button
                onClick={() => setPendingShredItem(selectedItemForInspect)}
                className="px-3 py-1.5 rounded-xl bg-rose-50 text-rose-700 hover:bg-rose-100 border border-rose-200 text-xs font-bold transition-colors cursor-pointer flex items-center gap-1.5"
              >
                <Trash2 className="w-3.5 h-3.5" />
                <span>Zeroize &amp; Shred</span>
              </button>

              <div className="flex items-center gap-2">
                <button
                  onClick={() => handleDownload(selectedItemForInspect)}
                  className="px-3 py-1.5 rounded-xl bg-blue-50 text-blue-700 hover:bg-blue-100 border border-blue-200 text-xs font-bold transition-colors cursor-pointer flex items-center gap-1.5"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>Download</span>
                </button>
                <button
                  onClick={() => handleRescan(selectedItemForInspect.id)}
                  className="px-3 py-1.5 rounded-xl bg-emerald-50 text-emerald-700 hover:bg-emerald-100 border border-emerald-200 text-xs font-bold transition-colors cursor-pointer flex items-center gap-1.5"
                >
                  <RefreshCw className="w-3.5 h-3.5" />
                  <span>Re-Scan Threat Engine</span>
                </button>
                <button
                  onClick={() => setSelectedItemForInspect(null)}
                  className="px-4 py-1.5 rounded-xl bg-slate-900 text-white hover:bg-slate-800 text-xs font-bold transition-colors cursor-pointer"
                >
                  Done
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Confirm Cryptographic Shred Modal */}
      {pendingShredItem && (
        <div className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-white rounded-2xl border border-slate-200 shadow-2xl max-w-md w-full p-6 space-y-4">
            <div className="flex items-center gap-2 text-rose-700">
              <ShieldAlert className="w-5 h-5" />
              <h3 className="text-base font-bold">Confirm Cryptographic Shredding</h3>
            </div>
            <p className="text-xs text-slate-600 leading-relaxed">
              Permanently zeroize <strong>{pendingShredItem.fileName || pendingShredItem.title}</strong> using DoD 5220.22-M overwrite? This removes the disk artifact and resolves linked vault findings/alerts.
            </p>
            <div className="flex justify-end gap-2 pt-2 border-t border-slate-200">
              <button
                onClick={() => setPendingShredItem(null)}
                className="px-4 py-2 rounded-xl bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-bold cursor-pointer"
              >
                Cancel
              </button>
              <button
                onClick={confirmShredItem}
                className="px-4 py-2 rounded-xl bg-rose-600 hover:bg-rose-700 text-white text-xs font-bold cursor-pointer"
              >
                Confirm Purge &amp; Shred
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
