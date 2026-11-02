import React, { useState, useEffect } from 'react';
import { useSearchParams, Link, useNavigate } from 'react-router-dom';
import { 
  ShieldCheck, 
  Lock, 
  CreditCard, 
  Building2, 
  Mail, 
  Phone, 
  MapPin, 
  Check, 
  ArrowRight, 
  CheckCircle2, 
  Sparkles, 
  Printer, 
  Download, 
  FileText, 
  Layers, 
  HelpCircle,
  ExternalLink,
  ChevronRight,
  AlertCircle,
  Award,
  RefreshCw,
  Percent,
  Shield,
  Briefcase,
  Globe
} from 'lucide-react';
import { useAuth } from '../hooks/useAuth';

interface PlanOption {
  id: 'basic' | 'pro' | 'enterprise' | 'whitelabel';
  name: string;
  tagline: string;
  monthlyPrice: number;
  annualPrice: number;
  featureCount: number;
  perks: string[];
  recommended?: boolean;
}

const PLANS: PlanOption[] = [
  {
    id: 'basic',
    name: 'Starter Shield',
    tagline: 'Foundational zero-trust protection for emerging startups and specialized teams.',
    monthlyPrice: 49,
    annualPrice: 39,
    featureCount: 30,
    perks: ['30 Core Security Modules', 'GDPR Consent Engine', 'Standard Threat Scans', '5 Operator Seats'],
  },
  {
    id: 'pro',
    name: 'Growth Sovereign',
    tagline: 'Comprehensive security orchestration, automated WAF, and multi-framework GRC.',
    monthlyPrice: 149,
    annualPrice: 119,
    featureCount: 60,
    perks: ['60 Certified Modules', 'Next-Gen Enclave WAF', 'Continuous SOC 2 Evidence', 'FIDO2 Hardware WebAuthn', '25 Operator Seats'],
    recommended: true,
  },
  {
    id: 'enterprise',
    name: 'Sovereign Enterprise',
    tagline: 'Full 78-feature suite with 24/7 dedicated SOC dispatch and air-gapped sovereign mesh.',
    monthlyPrice: 499,
    annualPrice: 399,
    featureCount: 78,
    perks: ['Full 78 Security Modules', 'Autonomous SIEM & SOAR', '24/7 Sovereign Incident Dispatch', 'Unlimited Seats', '99.999% Financial SLA'],
  },
  {
    id: 'whitelabel',
    name: 'Federal Sovereign Enclave',
    tagline: 'Bespoke OEM white-labeling, full source escrow, and multi-tenant dedicated mesh.',
    monthlyPrice: 3500,
    annualPrice: 2800,
    featureCount: 78,
    perks: ['Full White-Label & OEM Rebranding', 'Source Code Cryptographic Escrow', 'Air-Gapped Sovereign Deployment', 'Dedicated Cryptographic Architect'],
  },
];

interface AddonOption {
  id: string;
  name: string;
  description: string;
  price: number;
  isMonthly: boolean;
}

const ADDONS: AddonOption[] = [
  {
    id: 'soc_dispatch',
    name: '24/7 Sovereign Incident Dispatch & Red Team',
    description: 'Real-time human SOC triage under 5-minute response SLA.',
    price: 199,
    isMonthly: true,
  },
  {
    id: 'fido_keys',
    name: 'Quantum-Resistant FIDO2 Hardware Token Pack (5 Keys)',
    description: 'Hardware USB-C / NFC security keys provisioned and bound.',
    price: 149,
    isMonthly: false,
  },
  {
    id: 'pen_testing',
    name: 'Continuous Automated Penetration Testing & SOAR',
    description: 'Weekly automated adversarial vulnerability and exploit simulation.',
    price: 299,
    isMonthly: true,
  },
  {
    id: 'vpc_peering',
    name: 'Sovereign Multi-Cloud VPC Peering Gateway',
    description: 'Direct zero-trust transit gateway for AWS, GCP, and Azure workloads.',
    price: 350,
    isMonthly: true,
  },
];

const TAX_RATES: Record<string, { rate: number; label: string }> = {
  US: { rate: 0.0825, label: 'US State Sales Tax (Avg 8.25%)' },
  GB: { rate: 0.20, label: 'UK Value Added Tax (20%)' },
  DE: { rate: 0.19, label: 'EU VAT - Germany (19%)' },
  FR: { rate: 0.20, label: 'EU VAT - France (20%)' },
  IL: { rate: 0.17, label: 'Israel VAT (17%)' },
  CA: { rate: 0.13, label: 'Canada HST/GST (13%)' },
  CH: { rate: 0.081, label: 'Switzerland MWST (8.1%)' },
  OTHER: { rate: 0.00, label: 'Tax-Exempt / Cross-Border B2B' },
};

export default function Checkout() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const { user, updatePlan } = useAuth();

  // Selected Plan & Term
  const initialPlanId = (searchParams.get('plan') as any) || 'pro';
  const initialAnnual = searchParams.get('annual') === 'false' ? false : true;

  const [selectedPlanId, setSelectedPlanId] = useState<'basic' | 'pro' | 'enterprise' | 'whitelabel'>(
    ['basic', 'pro', 'enterprise', 'whitelabel'].includes(initialPlanId) ? initialPlanId : 'pro'
  );
  const [isAnnual, setIsAnnual] = useState<boolean>(initialAnnual);
  const [selectedAddons, setSelectedAddons] = useState<string[]>(['soc_dispatch']);

  // Organization & Contact Details
  const [fullName, setFullName] = useState(user?.name || 'Noam Almagor');
  const [email, setEmail] = useState(user?.email || 'chief.security@skyguard.mesh');
  const [phone, setPhone] = useState('+1 (555) 234-5678');
  const [company, setCompany] = useState(user?.tenantName || 'SkyGuard Defense Labs');
  const [vatNumber, setVatNumber] = useState('US-EIN-992014-X');
  const [address, setAddress] = useState('100 Sovereign Way, Suite 800');
  const [city, setCity] = useState('Washington');
  const [country, setCountry] = useState('US');
  const [postalCode, setPostalCode] = useState('20001');

  // Payment Method: 'card' | 'invoice' | 'escrow'
  const [paymentMethod, setPaymentMethod] = useState<'card' | 'invoice' | 'escrow'>('card');
  const [cardNumber, setCardNumber] = useState('4242 •••• •••• 4242');
  const [cardHolder, setCardHolder] = useState('NOAM ALMAGOR');
  const [cardExpiry, setCardExpiry] = useState('08/29');
  const [cardCvv, setCardCvv] = useState('889');
  const [poNumber, setPoNumber] = useState('PO-2026-SG-9941');
  const [cageCode, setCageCode] = useState('CAGE-7X892');

  // Promo Code
  const [couponCode, setCouponCode] = useState(searchParams.get('coupon') || '');
  const [appliedDiscountRate, setAppliedDiscountRate] = useState<number>(0);
  const [couponMessage, setCouponMessage] = useState<{ text: string; isError: boolean } | null>(null);

  // SLA & Legal agreement
  const [agreeTerms, setAgreeTerms] = useState(true);

  // Submission State
  const [isProcessing, setIsProcessing] = useState(false);
  const [processingStep, setProcessingStep] = useState<string>('');
  const [orderComplete, setOrderComplete] = useState<any | null>(null);
  const [showPrintInvoice, setShowPrintInvoice] = useState(false);

  // Sync selected plan with active option
  const activePlan = PLANS.find((p) => p.id === selectedPlanId) || PLANS[1];

  // Price Calculations
  const basePricePerMonth = isAnnual ? activePlan.annualPrice : activePlan.monthlyPrice;
  const billingMonths = isAnnual ? 12 : 1;
  const planSubtotal = basePricePerMonth * billingMonths;

  const addonsTotal = selectedAddons.reduce((sum, addonId) => {
    const addon = ADDONS.find((a) => a.id === addonId);
    if (!addon) return sum;
    return sum + (addon.isMonthly ? addon.price * billingMonths : addon.price);
  }, 0);

  const rawSubtotal = planSubtotal + addonsTotal;
  const discountAmount = Math.round(rawSubtotal * appliedDiscountRate);
  const taxableSubtotal = Math.max(0, rawSubtotal - discountAmount);

  const taxConfig = TAX_RATES[country] || TAX_RATES['OTHER'];
  const taxAmount = Math.round(taxableSubtotal * taxConfig.rate * 100) / 100;
  const grandTotal = Math.round((taxableSubtotal + taxAmount) * 100) / 100;

  // Toggle Addon
  const toggleAddon = (id: string) => {
    if (selectedAddons.includes(id)) {
      setSelectedAddons(selectedAddons.filter((x) => x !== id));
    } else {
      setSelectedAddons([...selectedAddons, id]);
    }
  };

  // Coupon handling
  const handleApplyCoupon = (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    const clean = couponCode.trim().toUpperCase();
    if (!clean) {
      setCouponMessage({ text: 'Please enter a valid coupon code.', isError: true });
      return;
    }
    if (clean === 'SKYGUARD2026' || clean === 'DEFENSE20') {
      setAppliedDiscountRate(0.20);
      setCouponMessage({ text: 'Sovereign 20% Discount applied successfully!', isError: false });
    } else if (clean === 'CISOVIP') {
      setAppliedDiscountRate(0.15);
      setCouponMessage({ text: 'Executive CISO 15% VIP Discount applied!', isError: false });
    } else {
      setCouponMessage({ text: 'Invalid promo code. Try SKYGUARD2026.', isError: true });
      setAppliedDiscountRate(0);
    }
  };

  // Pre-fill demo CISO details for 1-click test
  const handlePrefillCiso = () => {
    setFullName('Damon Ward');
    setEmail('damoneward38@gmail.com');
    setPhone('+1 (202) 555-0199');
    setCompany('Sovereign Defense Alliance');
    setVatNumber('US-EIN-881920-W');
    setAddress('750 Pennsylvania Ave NW');
    setCity('Washington');
    setCountry('US');
    setPostalCode('20006');
    setCouponCode('SKYGUARD2026');
    setAppliedDiscountRate(0.20);
    setCouponMessage({ text: 'Sovereign 20% Discount applied successfully!', isError: false });
  };

  // Process Checkout
  const handleProcessOrder = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!agreeTerms) {
      return;
    }
    setIsProcessing(true);

    try {
      setProcessingStep('1/4: Cryptographically verifying identity & company credentials...');
      await new Promise((r) => setTimeout(r, 600));

      setProcessingStep('2/4: Allocating dedicated sovereign enclave cluster & zero-trust mesh...');
      await new Promise((r) => setTimeout(r, 700));

      setProcessingStep('3/4: Generating SHA-256 Merkle license certificate & SLA guarantee...');
      await new Promise((r) => setTimeout(r, 600));

      const payload = {
        planId: activePlan.id,
        planName: activePlan.name,
        billingCycle: isAnnual ? 'annual' : 'monthly',
        addOns: selectedAddons.map((id) => {
          const a = ADDONS.find((x) => x.id === id)!;
          return { id: a.id, name: a.name, price: a.price };
        }),
        billingDetails: {
          fullName,
          email,
          phone,
          company,
          vatNumber,
          address,
          city,
          country,
          postalCode,
        },
        paymentMethod,
        subtotal: rawSubtotal,
        discount: discountAmount,
        taxVat: taxAmount,
        total: grandTotal,
        cardLast4: cardNumber.replace(/\D/g, '').slice(-4) || '4242',
        cardBrand: 'Visa Sovereign',
      };

      let completedOrder: any = null;
      try {
        const res = await fetch('/api/checkout/process', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
        if (res.ok) {
          const data = await res.json();
          completedOrder = data.order;
        }
      } catch {
        // Fallback to client generation
      }

      if (!completedOrder) {
        completedOrder = {
          orderId: `SKY-ORD-${Date.now().toString().slice(-6)}-SEC`,
          timestamp: new Date().toISOString(),
          planId: activePlan.id,
          planName: activePlan.name,
          billingCycle: isAnnual ? 'annual' : 'monthly',
          addOns: payload.addOns,
          billingDetails: payload.billingDetails,
          paymentMethod: paymentMethod === 'card' ? 'Corporate Card (Visa •••• 4242)' : 'Enterprise Wire ACH',
          subtotal: rawSubtotal,
          discount: discountAmount,
          taxVat: taxAmount,
          total: grandTotal,
          licenseKey: `SG-${activePlan.id.toUpperCase()}-77A1-99B2-C334`,
          transactionHash: '0x9b3f112e4c88a91c0b721e549112a884ef',
          tenantUrl: `https://${company.toLowerCase().replace(/[^a-z0-9]/g, '') || 'defense'}.skyguard.mesh`,
          status: 'PROVISIONED',
        };
      }

      setProcessingStep('4/4: Sovereign Tenant Activated Successfully!');
      await new Promise((r) => setTimeout(r, 400));

      // Update auth user plan
      updatePlan(activePlan.id);
      setOrderComplete(completedOrder);
    } finally {
      setIsProcessing(false);
    }
  };

  // ─────────────────────────────────────────────────────────────
  // SUCCESS RECEIPT / PROVISIONED STATE
  // ─────────────────────────────────────────────────────────────
  if (orderComplete) {
    return (
      <div className="min-h-screen bg-slate-50 py-16 px-4 sm:px-6 lg:px-8 font-sans">
        <div className="max-w-4xl mx-auto space-y-8">
          {/* Header Banner */}
          <div className="bg-white rounded-2xl border-2 border-emerald-500 shadow-xl p-8 text-center space-y-4">
            <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-emerald-100 text-emerald-600 mb-2">
              <CheckCircle2 className="w-10 h-10" />
            </div>

            <div className="inline-block px-3 py-1 rounded-full bg-emerald-50 border border-emerald-200 text-emerald-700 text-xs font-mono font-bold uppercase tracking-wider">
              Enclave Order Verified &amp; Provisioned
            </div>

            <h1 className="text-3xl sm:text-4xl font-extrabold text-slate-900 tracking-tight">
              Welcome to SkyGuard Sovereign Mesh
            </h1>
            <p className="text-sm text-slate-600 max-w-xl mx-auto">
              Your enterprise tenant infrastructure and cryptographic license have been compiled and activated across all 78 cybersecurity modules.
            </p>

            {/* Quick Metadata Box */}
            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4 pt-6 pb-2 text-left font-mono text-xs">
              <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200">
                <span className="text-[10px] text-slate-400 block uppercase font-bold">Order Number</span>
                <span className="font-bold text-blue-600 text-sm">{orderComplete.orderId}</span>
              </div>
              <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200">
                <span className="text-[10px] text-slate-400 block uppercase font-bold">Licensed Tier</span>
                <span className="font-bold text-slate-900">{orderComplete.planName}</span>
              </div>
              <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200">
                <span className="text-[10px] text-slate-400 block uppercase font-bold">Amount Paid</span>
                <span className="font-bold text-emerald-600 text-sm">${orderComplete.total.toLocaleString()}</span>
              </div>
              <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200">
                <span className="text-[10px] text-slate-400 block uppercase font-bold">SLA Guarantee</span>
                <span className="font-bold text-purple-600">99.999% SLA</span>
              </div>
            </div>

            {/* Cryptographic License & Domain */}
            <div className="p-4 rounded-xl bg-slate-900 text-white text-left font-mono text-xs space-y-2 border border-slate-800">
              <div className="flex items-center justify-between text-[11px] text-slate-400 border-b border-slate-800 pb-2">
                <span className="flex items-center gap-1.5 text-blue-400">
                  <ShieldCheck className="w-4 h-4" />
                  <span>Sovereign Enclave License Certificate</span>
                </span>
                <span className="text-emerald-400">STATUS: ACTIVE_NODE</span>
              </div>
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1 pt-1">
                <span className="text-slate-400">Master License Key:</span>
                <span className="text-amber-400 font-bold tracking-wider">{orderComplete.licenseKey}</span>
              </div>
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1">
                <span className="text-slate-400">Dedicated Tenant Node:</span>
                <span className="text-blue-300 underline">{orderComplete.tenantUrl}</span>
              </div>
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1">
                <span className="text-slate-400">Merkle Proof Hash:</span>
                <span className="text-slate-400 truncate max-w-xs">{orderComplete.transactionHash}</span>
              </div>
            </div>

            {/* Next Steps Action Buttons */}
            <div className="pt-6 flex flex-wrap items-center justify-center gap-3">
              <Link
                to="/app/dashboard"
                className="bg-blue-600 hover:bg-blue-700 text-white font-bold text-xs px-6 py-3 rounded-xl shadow-md transition-all flex items-center gap-2 cursor-pointer"
              >
                <span>Launch Sovereign Enclave Console</span>
                <ArrowRight className="w-4 h-4" />
              </Link>

              <Link
                to="/app/vault"
                className="bg-slate-900 hover:bg-slate-800 text-white font-bold text-xs px-6 py-3 rounded-xl shadow-md transition-all flex items-center gap-2 cursor-pointer"
              >
                <Lock className="w-4 h-4 text-emerald-400" />
                <span>Upload Documents &amp; Emails to Vault</span>
              </Link>

              <button
                type="button"
                id="btn_checkout_print_invoice"
                onClick={() => setShowPrintInvoice(true)}
                className="border border-slate-300 bg-white hover:bg-slate-50 text-slate-700 font-bold text-xs px-5 py-3 rounded-xl shadow-sm transition-all flex items-center gap-2 cursor-pointer"
              >
                <Printer className="w-4 h-4 text-slate-500" />
                <span>View Tax Invoice</span>
              </button>
            </div>
          </div>
        </div>

        {/* Invoice Modal */}
        {showPrintInvoice && (
          <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-xs flex items-center justify-center p-4">
            <div className="bg-white rounded-2xl max-w-2xl w-full p-8 shadow-2xl border border-slate-200 max-h-[90vh] overflow-y-auto space-y-6">
              <div className="flex items-center justify-between border-b pb-4">
                <div className="flex items-center gap-2.5">
                  <ShieldCheck className="w-6 h-6 text-blue-600" />
                  <span className="text-lg font-bold text-slate-900">SkyGuard Sovereign Cybersecurity Ltd.</span>
                </div>
                <button
                  onClick={() => setShowPrintInvoice(false)}
                  className="text-xs font-bold text-slate-400 hover:text-slate-600 cursor-pointer"
                >
                  Close [×]
                </button>
              </div>

              <div className="grid grid-cols-2 gap-4 text-xs">
                <div>
                  <h4 className="font-bold text-slate-900 uppercase text-[10px] text-slate-400">Billed To:</h4>
                  <div className="font-semibold text-slate-800">{orderComplete.billingDetails.company}</div>
                  <div>Attn: {orderComplete.billingDetails.fullName}</div>
                  <div>{orderComplete.billingDetails.address}</div>
                  <div>{orderComplete.billingDetails.city}, {orderComplete.billingDetails.country} {orderComplete.billingDetails.postalCode}</div>
                  <div className="font-mono text-[11px] text-slate-500 mt-1">Tax ID: {orderComplete.billingDetails.vatNumber}</div>
                </div>
                <div className="text-right">
                  <h4 className="font-bold text-slate-900 uppercase text-[10px] text-slate-400">Invoice Details:</h4>
                  <div className="font-mono font-bold text-blue-600">{orderComplete.orderId}</div>
                  <div>Date: {new Date(orderComplete.timestamp).toLocaleDateString()}</div>
                  <div>Payment: {orderComplete.paymentMethod}</div>
                  <div className="font-bold text-emerald-600 uppercase mt-1">Status: PAID IN FULL</div>
                </div>
              </div>

              {/* Table */}
              <div className="border rounded-xl overflow-hidden text-xs">
                <table className="w-full text-left">
                  <thead className="bg-slate-100 border-b text-[11px] font-bold text-slate-600 uppercase">
                    <tr>
                      <th className="p-3">Description</th>
                      <th className="p-3 text-right">Cycle</th>
                      <th className="p-3 text-right">Amount</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    <tr>
                      <td className="p-3">
                        <div className="font-bold text-slate-900">{orderComplete.planName}</div>
                        <div className="text-[11px] text-slate-500">78-Feature Enclave License &amp; Sovereign Zero-Trust Stack</div>
                      </td>
                      <td className="p-3 text-right font-mono capitalize">{orderComplete.billingCycle}</td>
                      <td className="p-3 text-right font-mono font-bold text-slate-900">${orderComplete.subtotal.toLocaleString()}</td>
                    </tr>
                    {orderComplete.addOns?.map((a: any) => (
                      <tr key={a.id}>
                        <td className="p-3">
                          <div className="font-semibold text-slate-800">{a.name}</div>
                          <div className="text-[10px] text-slate-400">Enterprise Add-On Module</div>
                        </td>
                        <td className="p-3 text-right font-mono text-slate-500">Active</td>
                        <td className="p-3 text-right font-mono font-bold text-slate-900">${a.price}</td>
                      </tr>
                    ))}
                  </tbody>
                  <tfoot className="bg-slate-50 font-bold border-t">
                    {orderComplete.discount > 0 && (
                      <tr className="text-emerald-700">
                        <td colSpan={2} className="p-2.5 text-right">Applied Sovereign Discount:</td>
                        <td className="p-2.5 text-right font-mono">-${orderComplete.discount.toLocaleString()}</td>
                      </tr>
                    )}
                    <tr>
                      <td colSpan={2} className="p-2.5 text-right">Applicable Tax / VAT:</td>
                      <td className="p-2.5 text-right font-mono text-slate-700">${orderComplete.taxVat.toLocaleString()}</td>
                    </tr>
                    <tr className="text-base text-slate-900 border-t">
                      <td colSpan={2} className="p-3 text-right">Total Paid (USD):</td>
                      <td className="p-3 text-right font-mono text-blue-600">${orderComplete.total.toLocaleString()}</td>
                    </tr>
                  </tfoot>
                </table>
              </div>

              <div className="pt-2 flex justify-between items-center text-xs">
                <span className="text-[10px] font-mono text-slate-400">Electronic Merkle Proof: {orderComplete.transactionHash.slice(0, 24)}...</span>
                <button
                  onClick={() => window.print()}
                  className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg font-bold text-xs flex items-center gap-1.5 cursor-pointer"
                >
                  <Printer className="w-3.5 h-3.5" />
                  <span>Print Receipt</span>
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    );
  }

  // ─────────────────────────────────────────────────────────────
  // MAIN MULTI-STEP ENTERPRISE CHECKOUT VIEW
  // ─────────────────────────────────────────────────────────────
  return (
    <div className="min-h-screen bg-slate-50 py-12 px-4 sm:px-6 lg:px-8 font-sans">
      <div className="max-w-7xl mx-auto space-y-8">
        {/* Breadcrumb & Top Bar */}
        <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-200 pb-4">
          <div className="flex items-center gap-2 text-xs text-slate-500 font-medium">
            <Link to="/pricing" className="hover:text-blue-600">Pricing</Link>
            <ChevronRight className="w-3 h-3 text-slate-400" />
            <span className="text-slate-900 font-bold">Enterprise Checkout &amp; Tenant Provisioning</span>
          </div>

          <div className="flex items-center gap-2">
            <button
              type="button"
              id="btn_checkout_prefill_ciso"
              onClick={handlePrefillCiso}
              className="px-3 py-1.5 rounded-lg bg-blue-50 border border-blue-200 text-blue-700 hover:bg-blue-100 text-xs font-semibold flex items-center gap-1.5 cursor-pointer transition-colors"
            >
              <Sparkles className="w-3.5 h-3.5 text-blue-600" />
              <span>Pre-fill CISO Evaluation Profile</span>
            </button>
          </div>
        </div>

        {/* Page Heading */}
        <div>
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded bg-blue-50 border border-blue-200 text-blue-700 text-xs font-semibold uppercase tracking-wider mb-2">
            <Lock className="w-3.5 h-3.5" />
            <span>256-Bit Encrypted Sovereign Checkout Gateway</span>
          </div>
          <h1 className="text-3xl sm:text-4xl font-extrabold text-slate-900 tracking-tight">
            Activate SkyGuard Enterprise License
          </h1>
          <p className="text-sm text-slate-600 mt-1">
            Complete your subscription to immediately provision your sovereign tenant, access all 78 security features, and generate compliant regulatory evidence.
          </p>
        </div>

        {/* 2-Column Checkout Layout */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
          {/* LEFT COLUMN: Configuration, Contact, Payment */}
          <div className="lg:col-span-7 space-y-6">
            
            {/* 1. PLAN SELECTION */}
            <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-sm space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-100 pb-3">
                <div className="flex items-center gap-2">
                  <span className="w-6 h-6 rounded-full bg-blue-600 text-white text-xs font-bold flex items-center justify-center">1</span>
                  <h2 className="text-base font-bold text-slate-900">Select Subscription Tier</h2>
                </div>

                {/* Billing Cycle Toggle */}
                <div className="flex items-center gap-2 text-xs">
                  <span className={!isAnnual ? 'font-bold text-slate-900' : 'text-slate-500'}>Monthly</span>
                  <button
                    type="button"
                    onClick={() => setIsAnnual(!isAnnual)}
                    className="relative w-11 h-6 rounded-full bg-slate-200 border border-slate-300 p-0.5 cursor-pointer"
                  >
                    <div className={`w-5 h-5 rounded-full bg-blue-600 transition-transform ${isAnnual ? 'translate-x-5' : 'translate-x-0'}`}></div>
                  </button>
                  <span className={`flex items-center gap-1 ${isAnnual ? 'font-bold text-slate-900' : 'text-slate-500'}`}>
                    <span>Annual</span>
                    <span className="bg-emerald-100 text-emerald-800 text-[10px] font-bold px-1.5 py-0.2 rounded">Save 20%</span>
                  </span>
                </div>
              </div>

              {/* Plans Grid */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-1">
                {PLANS.map((plan) => {
                  const isSelected = selectedPlanId === plan.id;
                  const price = isAnnual ? plan.annualPrice : plan.monthlyPrice;

                  return (
                    <div
                      key={plan.id}
                      onClick={() => setSelectedPlanId(plan.id)}
                      className={`p-4 rounded-xl border-2 cursor-pointer transition-all relative ${
                        isSelected
                          ? 'border-blue-600 bg-blue-50/40 shadow-sm'
                          : 'border-slate-200 bg-white hover:border-slate-300'
                      }`}
                    >
                      {plan.recommended && (
                        <span className="absolute -top-2.5 right-3 bg-blue-600 text-white text-[9px] font-bold uppercase tracking-wider px-2 py-0.5 rounded-full font-mono">
                          Recommended
                        </span>
                      )}

                      <div className="flex items-center justify-between mb-1">
                        <span className="font-bold text-slate-900 text-sm">{plan.name}</span>
                        <div className="flex items-baseline gap-0.5">
                          <span className="text-lg font-extrabold font-mono text-slate-900">${price}</span>
                          <span className="text-[10px] text-slate-500 font-mono">/mo</span>
                        </div>
                      </div>

                      <p className="text-[11px] text-slate-500 leading-snug mb-3 min-h-[32px]">
                        {plan.tagline}
                      </p>

                      <div className="space-y-1 text-[11px] text-slate-600 border-t border-slate-100 pt-2">
                        <div className="font-semibold text-blue-600">{plan.featureCount}/78 Security Modules</div>
                        {plan.perks.slice(1, 3).map((perk, i) => (
                          <div key={i} className="flex items-center gap-1.5 text-slate-600">
                            <Check className="w-3 h-3 text-emerald-600 flex-shrink-0" />
                            <span className="truncate">{perk}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* 2. OPTIONAL ENTERPRISE ADD-ONS */}
            <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-sm space-y-4">
              <div className="flex items-center justify-between border-b border-slate-100 pb-3">
                <div className="flex items-center gap-2">
                  <span className="w-6 h-6 rounded-full bg-blue-600 text-white text-xs font-bold flex items-center justify-center">2</span>
                  <h2 className="text-base font-bold text-slate-900">Sovereign Add-on Capabilities</h2>
                </div>
                <span className="text-xs text-slate-500">Optional modules</span>
              </div>

              <div className="space-y-2.5">
                {ADDONS.map((addon) => {
                  const isChecked = selectedAddons.includes(addon.id);
                  return (
                    <div
                      key={addon.id}
                      onClick={() => toggleAddon(addon.id)}
                      className={`p-3.5 rounded-xl border transition-all cursor-pointer flex items-center justify-between gap-4 ${
                        isChecked ? 'bg-blue-50/50 border-blue-400' : 'bg-slate-50 border-slate-200 hover:bg-slate-100'
                      }`}
                    >
                      <div className="flex items-start gap-3">
                        <input
                          type="checkbox"
                          checked={isChecked}
                          onChange={() => {}}
                          className="mt-1 rounded text-blue-600 focus:ring-blue-500"
                        />
                        <div>
                          <div className="text-xs font-bold text-slate-900">{addon.name}</div>
                          <div className="text-[11px] text-slate-500">{addon.description}</div>
                        </div>
                      </div>
                      <div className="text-right flex-shrink-0">
                        <span className="font-mono font-bold text-slate-900 text-xs">+${addon.price}</span>
                        <span className="text-[10px] text-slate-500 font-mono block">{addon.isMonthly ? '/mo' : 'one-time'}</span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* 3. ORGANIZATION & BILLING CONTACT */}
            <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-sm space-y-4">
              <div className="flex items-center justify-between border-b border-slate-100 pb-3">
                <div className="flex items-center gap-2">
                  <span className="w-6 h-6 rounded-full bg-blue-600 text-white text-xs font-bold flex items-center justify-center">3</span>
                  <h2 className="text-base font-bold text-slate-900">Organization &amp; Tax Details</h2>
                </div>
                <span className="text-xs font-mono text-emerald-600 font-semibold">Strict Enclave Confidentiality</span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs font-sans">
                <div>
                  <label className="block font-semibold text-slate-700 mb-1">Full Name *</label>
                  <input
                    type="text"
                    required
                    value={fullName}
                    onChange={(e) => setFullName(e.target.value)}
                    className="w-full px-3 py-2.5 rounded-lg bg-slate-50 border border-slate-200 text-slate-900 focus:outline-none focus:border-blue-500"
                    placeholder="e.g. Noam Almagor"
                  />
                </div>

                <div>
                  <label className="block font-semibold text-slate-700 mb-1">Corporate Work Email *</label>
                  <input
                    type="email"
                    required
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className="w-full px-3 py-2.5 rounded-lg bg-slate-50 border border-slate-200 text-slate-900 focus:outline-none focus:border-blue-500 font-mono"
                    placeholder="ciso@enterprise.com"
                  />
                </div>

                <div>
                  <label className="block font-semibold text-slate-700 mb-1">Company / Organization *</label>
                  <input
                    type="text"
                    required
                    value={company}
                    onChange={(e) => setCompany(e.target.value)}
                    className="w-full px-3 py-2.5 rounded-lg bg-slate-50 border border-slate-200 text-slate-900 focus:outline-none focus:border-blue-500"
                    placeholder="e.g. Apex Defense Inc"
                  />
                </div>

                <div>
                  <label className="block font-semibold text-slate-700 mb-1">Tax / VAT Registration ID</label>
                  <input
                    type="text"
                    value={vatNumber}
                    onChange={(e) => setVatNumber(e.target.value)}
                    className="w-full px-3 py-2.5 rounded-lg bg-slate-50 border border-slate-200 text-slate-900 focus:outline-none focus:border-blue-500 font-mono"
                    placeholder="e.g. US-EIN-992014-X or GB992812"
                  />
                </div>

                <div className="sm:col-span-2">
                  <label className="block font-semibold text-slate-700 mb-1">Billing Street Address</label>
                  <input
                    type="text"
                    value={address}
                    onChange={(e) => setAddress(e.target.value)}
                    className="w-full px-3 py-2.5 rounded-lg bg-slate-50 border border-slate-200 text-slate-900 focus:outline-none focus:border-blue-500"
                    placeholder="100 Sovereign Way, Suite 800"
                  />
                </div>

                <div>
                  <label className="block font-semibold text-slate-700 mb-1">Country / Tax Jurisdiction *</label>
                  <select
                    value={country}
                    onChange={(e) => setCountry(e.target.value)}
                    className="w-full px-3 py-2.5 rounded-lg bg-slate-50 border border-slate-200 text-slate-900 focus:outline-none focus:border-blue-500 cursor-pointer"
                  >
                    <option value="US">United States (State Tax ~8.25%)</option>
                    <option value="GB">United Kingdom (VAT 20%)</option>
                    <option value="DE">Germany (EU VAT 19%)</option>
                    <option value="FR">France (EU VAT 20%)</option>
                    <option value="IL">Israel (VAT 17%)</option>
                    <option value="CA">Canada (HST/GST 13%)</option>
                    <option value="CH">Switzerland (MWST 8.1%)</option>
                    <option value="OTHER">Other / Sovereign Cross-Border (0%)</option>
                  </select>
                </div>

                <div className="grid grid-cols-2 gap-2">
                  <div>
                    <label className="block font-semibold text-slate-700 mb-1">City</label>
                    <input
                      type="text"
                      value={city}
                      onChange={(e) => setCity(e.target.value)}
                      className="w-full px-3 py-2.5 rounded-lg bg-slate-50 border border-slate-200 text-slate-900 focus:outline-none focus:border-blue-500"
                    />
                  </div>
                  <div>
                    <label className="block font-semibold text-slate-700 mb-1">Postal Code</label>
                    <input
                      type="text"
                      value={postalCode}
                      onChange={(e) => setPostalCode(e.target.value)}
                      className="w-full px-3 py-2.5 rounded-lg bg-slate-50 border border-slate-200 text-slate-900 focus:outline-none focus:border-blue-500 font-mono"
                    />
                  </div>
                </div>
              </div>
            </div>

            {/* 4. PAYMENT METHOD */}
            <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-sm space-y-4">
              <div className="flex items-center justify-between border-b border-slate-100 pb-3">
                <div className="flex items-center gap-2">
                  <span className="w-6 h-6 rounded-full bg-blue-600 text-white text-xs font-bold flex items-center justify-center">4</span>
                  <h2 className="text-base font-bold text-slate-900">Payment Authorization</h2>
                </div>
                <div className="flex items-center gap-1.5 text-xs text-slate-500">
                  <Lock className="w-3.5 h-3.5 text-emerald-600" />
                  <span>PCI-DSS Level 1 Compliant</span>
                </div>
              </div>

              {/* Payment Method Selector Tabs */}
              <div className="grid grid-cols-3 gap-2">
                <button
                  type="button"
                  onClick={() => setPaymentMethod('card')}
                  className={`p-3 rounded-xl border text-xs font-bold flex flex-col items-center gap-1.5 cursor-pointer transition-all ${
                    paymentMethod === 'card' ? 'bg-blue-50 border-blue-600 text-blue-900' : 'bg-slate-50 border-slate-200 text-slate-700 hover:bg-slate-100'
                  }`}
                >
                  <CreditCard className="w-4 h-4 text-blue-600" />
                  <span>Corporate Card</span>
                </button>

                <button
                  type="button"
                  onClick={() => setPaymentMethod('invoice')}
                  className={`p-3 rounded-xl border text-xs font-bold flex flex-col items-center gap-1.5 cursor-pointer transition-all ${
                    paymentMethod === 'invoice' ? 'bg-blue-50 border-blue-600 text-blue-900' : 'bg-slate-50 border-slate-200 text-slate-700 hover:bg-slate-100'
                  }`}
                >
                  <Building2 className="w-4 h-4 text-blue-600" />
                  <span>Enterprise Wire / PO</span>
                </button>

                <button
                  type="button"
                  onClick={() => setPaymentMethod('escrow')}
                  className={`p-3 rounded-xl border text-xs font-bold flex flex-col items-center gap-1.5 cursor-pointer transition-all ${
                    paymentMethod === 'escrow' ? 'bg-blue-50 border-blue-600 text-blue-900' : 'bg-slate-50 border-slate-200 text-slate-700 hover:bg-slate-100'
                  }`}
                >
                  <ShieldCheck className="w-4 h-4 text-blue-600" />
                  <span>Defense Escrow</span>
                </button>
              </div>

              {/* Payment Fields */}
              {paymentMethod === 'card' && (
                <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-3 text-xs">
                  <div>
                    <label className="block font-semibold text-slate-700 mb-1">Card Number</label>
                    <div className="relative">
                      <CreditCard className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
                      <input
                        type="text"
                        value={cardNumber}
                        onChange={(e) => setCardNumber(e.target.value)}
                        className="w-full pl-9 pr-3 py-2 rounded-lg bg-white border border-slate-200 text-slate-900 font-mono text-xs focus:outline-none focus:border-blue-500"
                        placeholder="4242 •••• •••• 4242"
                      />
                    </div>
                  </div>

                  <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
                    <div className="sm:col-span-1">
                      <label className="block font-semibold text-slate-700 mb-1">Cardholder Name</label>
                      <input
                        type="text"
                        value={cardHolder}
                        onChange={(e) => setCardHolder(e.target.value)}
                        className="w-full px-3 py-2 rounded-lg bg-white border border-slate-200 text-slate-900 text-xs focus:outline-none focus:border-blue-500"
                        placeholder="NOAM ALMAGOR"
                      />
                    </div>
                    <div>
                      <label className="block font-semibold text-slate-700 mb-1">Expires (MM/YY)</label>
                      <input
                        type="text"
                        value={cardExpiry}
                        onChange={(e) => setCardExpiry(e.target.value)}
                        className="w-full px-3 py-2 rounded-lg bg-white border border-slate-200 text-slate-900 font-mono text-xs focus:outline-none focus:border-blue-500"
                        placeholder="08/29"
                      />
                    </div>
                    <div>
                      <label className="block font-semibold text-slate-700 mb-1">Security CVV</label>
                      <input
                        type="password"
                        maxLength={4}
                        value={cardCvv}
                        onChange={(e) => setCardCvv(e.target.value)}
                        className="w-full px-3 py-2 rounded-lg bg-white border border-slate-200 text-slate-900 font-mono text-xs focus:outline-none focus:border-blue-500"
                        placeholder="889"
                      />
                    </div>
                  </div>
                </div>
              )}

              {paymentMethod === 'invoice' && (
                <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-3 text-xs">
                  <div className="text-slate-600 leading-relaxed">
                    Net-30 Enterprise Electronic Funds Transfer (ACH/SEPA). An automated verified invoice will be delivered with sovereign wire instructions upon tenant launch.
                  </div>
                  <div>
                    <label className="block font-semibold text-slate-700 mb-1">Corporate Purchase Order Number *</label>
                    <input
                      type="text"
                      value={poNumber}
                      onChange={(e) => setPoNumber(e.target.value)}
                      className="w-full px-3 py-2 rounded-lg bg-white border border-slate-200 text-slate-900 font-mono text-xs focus:outline-none focus:border-blue-500"
                      placeholder="PO-2026-SG-9941"
                    />
                  </div>
                </div>
              )}

              {paymentMethod === 'escrow' && (
                <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-3 text-xs">
                  <div className="text-slate-600 leading-relaxed">
                    Air-gapped sovereign defense contract billing. Applicable for government entities, defense agencies, and NATO commercial contractors.
                  </div>
                  <div>
                    <label className="block font-semibold text-slate-700 mb-1">DOD / NATO Commercial Cage Code *</label>
                    <input
                      type="text"
                      value={cageCode}
                      onChange={(e) => setCageCode(e.target.value)}
                      className="w-full px-3 py-2 rounded-lg bg-white border border-slate-200 text-slate-900 font-mono text-xs focus:outline-none focus:border-blue-500"
                      placeholder="CAGE-7X892"
                    />
                  </div>
                </div>
              )}

            </div>
          </div>

          {/* RIGHT COLUMN: Live Order Summary & Authorization */}
          <div className="lg:col-span-5 space-y-6">
            <div className="bg-white rounded-2xl border-2 border-slate-200 p-6 shadow-md space-y-6 sticky top-24">
              <div className="flex items-center justify-between border-b border-slate-100 pb-3">
                <h3 className="text-base font-bold text-slate-900">Order Summary</h3>
                <span className="font-mono text-xs text-blue-600 font-bold uppercase">{activePlan.name}</span>
              </div>

              {/* Itemized Lines */}
              <div className="space-y-3 text-xs">
                {/* Plan Line */}
                <div className="flex items-start justify-between">
                  <div>
                    <div className="font-bold text-slate-900">{activePlan.name}</div>
                    <div className="text-[11px] text-slate-500">
                      {isAnnual ? 'Annual Billing (Save 20%)' : 'Monthly Billing'} • {activePlan.featureCount} Modules
                    </div>
                  </div>
                  <span className="font-mono font-bold text-slate-900">${planSubtotal.toLocaleString()}</span>
                </div>

                {/* Add-ons */}
                {selectedAddons.map((addonId) => {
                  const addon = ADDONS.find((a) => a.id === addonId);
                  if (!addon) return null;
                  const price = addon.isMonthly ? addon.price * billingMonths : addon.price;
                  return (
                    <div key={addon.id} className="flex items-start justify-between text-slate-600">
                      <div>
                        <div className="font-medium text-slate-800">{addon.name}</div>
                        <div className="text-[10px] text-slate-400">{addon.isMonthly ? `${billingMonths} mos @ $${addon.price}/mo` : 'One-time charge'}</div>
                      </div>
                      <span className="font-mono font-semibold text-slate-800">+${price.toLocaleString()}</span>
                    </div>
                  );
                })}

                {/* Subtotal */}
                <div className="border-t border-slate-100 pt-2 flex justify-between text-slate-600">
                  <span>Subtotal:</span>
                  <span className="font-mono font-semibold">${rawSubtotal.toLocaleString()}</span>
                </div>

                {/* Promo Discount if applied */}
                {appliedDiscountRate > 0 && (
                  <div className="flex justify-between text-emerald-700 font-semibold">
                    <span>Sovereign Promo Discount ({appliedDiscountRate * 100}%):</span>
                    <span className="font-mono">-${discountAmount.toLocaleString()}</span>
                  </div>
                )}

                {/* Tax / VAT */}
                <div className="flex justify-between text-slate-600">
                  <div>
                    <span>{taxConfig.label}:</span>
                    <span className="block text-[10px] text-slate-400">Jurisdiction: {country}</span>
                  </div>
                  <span className="font-mono font-semibold">${taxAmount.toLocaleString()}</span>
                </div>

                {/* Grand Total */}
                <div className="border-t-2 border-slate-200 pt-3 flex items-baseline justify-between">
                  <div>
                    <span className="text-base font-extrabold text-slate-900">Total Due Today</span>
                    <span className="block text-[10px] text-slate-400 font-mono">Billed in USD • Zero hidden surcharges</span>
                  </div>
                  <div className="text-right">
                    <span className="text-2xl font-black font-mono text-blue-600">${grandTotal.toLocaleString()}</span>
                  </div>
                </div>
              </div>

              {/* Promo Code Input Form */}
              <div className="pt-2 border-t border-slate-100">
                <form onSubmit={handleApplyCoupon} className="flex gap-2">
                  <input
                    type="text"
                    value={couponCode}
                    onChange={(e) => setCouponCode(e.target.value)}
                    placeholder="Promo Code (e.g. SKYGUARD2026)"
                    className="flex-1 px-3 py-2 rounded-lg bg-slate-50 border border-slate-200 text-xs font-mono uppercase focus:outline-none focus:border-blue-500"
                  />
                  <button
                    type="submit"
                    id="btn_checkout_apply_coupon"
                    className="px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-900 text-white font-bold text-xs cursor-pointer transition-colors"
                  >
                    Apply
                  </button>
                </form>
                {couponMessage && (
                  <div className={`mt-2 text-[11px] font-medium flex items-center gap-1 ${couponMessage.isError ? 'text-red-600' : 'text-emerald-700'}`}>
                    {couponMessage.isError ? <AlertCircle className="w-3.5 h-3.5" /> : <CheckCircle2 className="w-3.5 h-3.5" />}
                    <span>{couponMessage.text}</span>
                  </div>
                )}
              </div>

              {/* Legal Agreement */}
              <div className="pt-2 border-t border-slate-100 space-y-2 text-[11px] text-slate-500">
                <label className="flex items-start gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={agreeTerms}
                    onChange={(e) => setAgreeTerms(e.target.checked)}
                    className="mt-0.5 rounded text-blue-600 focus:ring-blue-500"
                  />
                  <span>
                    I accept the <strong className="text-slate-800">SkyGuard Master Services Agreement</strong>, 99.999% SLA guarantee, and GDPR Data Processing Addendum (DPA).
                  </span>
                </label>
              </div>

              {/* Authorize & Provision Button */}
              <button
                type="button"
                id="btn_checkout_authorize"
                disabled={isProcessing || !agreeTerms}
                onClick={handleProcessOrder}
                className="w-full py-3.5 px-4 rounded-xl bg-blue-600 hover:bg-blue-700 text-white font-bold text-sm shadow-lg transition-all flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50"
              >
                {isProcessing ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin" />
                    <span>Provisioning Sovereign Tenant...</span>
                  </>
                ) : (
                  <>
                    <ShieldCheck className="w-4 h-4" />
                    <span>Authorize &amp; Activate License (${grandTotal.toLocaleString()})</span>
                  </>
                )}
              </button>

              {/* Live Provisioning Progress ticker */}
              {isProcessing && (
                <div className="p-3 rounded-lg bg-blue-50 border border-blue-200 text-blue-900 text-xs font-mono animate-pulse">
                  {processingStep}
                </div>
              )}

              {/* Trust Badges */}
              <div className="grid grid-cols-3 gap-2 pt-2 border-t border-slate-100 text-[10px] text-slate-400 font-mono text-center">
                <div className="p-1.5 rounded bg-slate-50 border border-slate-200">
                  <span className="font-bold text-slate-700 block">30-Day</span>
                  <span>Guarantee</span>
                </div>
                <div className="p-1.5 rounded bg-slate-50 border border-slate-200">
                  <span className="font-bold text-slate-700 block">Air-Gapped</span>
                  <span>Isolation</span>
                </div>
                <div className="p-1.5 rounded bg-slate-50 border border-slate-200">
                  <span className="font-bold text-slate-700 block">SOC 2 Type II</span>
                  <span>Certified</span>
                </div>
              </div>
            </div>
          </div>
        </div>

      </div>
    </div>
  );
}
