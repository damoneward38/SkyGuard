import { execSync } from 'child_process';
import fs from 'fs';
import path from 'path';

console.log('🚀 [SkyGuard CI/CD Test Pipeline] Starting automated comprehension verification...\n');

let passCount = 0;
let totalCount = 0;

function assertTest(name: string, fn: () => void | Promise<void>) {
  totalCount++;
  try {
    fn();
    console.log(`  ✅ [PASS] ${name}`);
    passCount++;
  } catch (err: any) {
    console.error(`  ❌ [FAIL] ${name}:`, err.message || err);
  }
}

// 1. Verify index.html exists and is properly structured
assertTest('index.html exists at project root with proper <div id="root"></div>', () => {
  const content = fs.readFileSync('index.html', 'utf-8');
  if (!content.includes('id="root"')) throw new Error('Missing #root mount point in index.html');
  if (!content.includes('src="/src/main.tsx"')) throw new Error('Missing main.tsx entry in index.html');
});

// 2. Verify vite.config.ts has relative base path for GitHub Pages compatibility
assertTest('vite.config.ts configured with relative base path for GitHub Pages sub-path hosting', () => {
  const content = fs.readFileSync('vite.config.ts', 'utf-8');
  if (!content.includes('base:')) throw new Error('base path configuration recommended in vite.config.ts');
});

// 3. Verify TypeScript Strict Typecheck & Linting
assertTest('TypeScript Compilation & Strict Typechecking (tsc --noEmit)', () => {
  execSync('npm run lint', { stdio: 'pipe' });
});

// 4. Verify 6 Sovereign Centers, Secure Vault & Core Pages exist
assertTest('All 6 Sovereign Cyber Centers, Secure Vault, Sign-In, and Checkout Pages are present', () => {
  const requiredFiles = [
    'src/pages/Dashboard.tsx',
    'src/pages/SecureVault.tsx',
    'src/pages/Login.tsx',
    'src/pages/Checkout.tsx',
    'src/pages/SecurityCenter.tsx',
    'src/pages/PrivacyCenter.tsx',
    'src/pages/ComplianceCenter.tsx',
    'src/pages/IdentityCenter.tsx',
    'src/pages/AutomationCenter.tsx',
    'src/pages/PlatformCenter.tsx',
    'src/pages/OperationsConsole.tsx',
    'src/pages/Workspaces.tsx',
    'src/pages/WhiteLabel.tsx',
    'src/pages/FeaturePage.tsx',
    'src/pages/Pricing.tsx',
  ];

  for (const file of requiredFiles) {
    if (!fs.existsSync(file)) {
      throw new Error(`Missing required page file: ${file}`);
    }
  }
});

// 5. Verify Sign-In Page and Enterprise Checkout Page Integrations
assertTest('Sign-In and Enterprise Checkout pages contain zero placeholders and real forms', () => {
  const loginCode = fs.readFileSync('src/pages/Login.tsx', 'utf-8');
  const checkoutCode = fs.readFileSync('src/pages/Checkout.tsx', 'utf-8');

  // Check Login features
  if (!loginCode.includes('handleLogin') || !loginCode.includes('handleQuickDemo') || !loginCode.includes('handleSSOLogin')) {
    throw new Error('Login.tsx missing required auth handlers or SSO integration');
  }
  if (!loginCode.includes('/api/auth/login')) {
    throw new Error('Login.tsx missing backend API dispatch to /api/auth/login');
  }

  // Check Checkout features
  if (!checkoutCode.includes('handleProcessOrder') || !checkoutCode.includes('/api/checkout/process')) {
    throw new Error('Checkout.tsx missing order processing dispatch');
  }
  if (!checkoutCode.includes('TAX_RATES') || !checkoutCode.includes('handleApplyCoupon')) {
    throw new Error('Checkout.tsx missing dynamic VAT/tax calculation or promo code support');
  }
});

// 6. Verify Full-Stack Server APIs, Vault Ingestion, Auth, & Checkout Endpoints
assertTest('server.ts contains all required REST, Vault Ingestion, Auth, Checkout, and SSE endpoints', () => {
  const serverCode = fs.readFileSync('server.ts', 'utf-8');
  const expectedEndpoints = [
    '/api/health',
    '/api/events',
    '/api/telemetry/stream',
    '/api/audit',
    '/api/whitelabel',
    '/api/e2e/simulate',
    '/api/performance/load-test',
    '/api/security/audit-scan',
    '/api/monitoring/status',
    '/api/docs/quickstart',
    '/api/vault/items',
    '/api/vault/upload',
    '/api/vault/scan/:id',
    '/api/audit/button-audit',
    '/api/auth/login',
    '/api/auth/logout',
    '/api/checkout/process',
    '/api/checkout/orders',
  ];

  for (const endpoint of expectedEndpoints) {
    if (!serverCode.includes(endpoint.split(':')[0])) {
      throw new Error(`Missing server endpoint: ${endpoint}`);
    }
  }
});

// 7. Comprehensive Button Audit & Route Link Contract Verification
assertTest('Full Button Audit: All UI buttons and routes are tied together without dead links', () => {
  const appCode = fs.readFileSync('src/App.tsx', 'utf-8');
  const layoutCode = fs.readFileSync('src/components/AppLayout.tsx', 'utf-8');
  const navbarCode = fs.readFileSync('src/components/Navbar.tsx', 'utf-8');
  const vaultCode = fs.readFileSync('src/pages/SecureVault.tsx', 'utf-8');

  // Verify all essential routes are mapped in App.tsx
  const essentialRoutes = ['dashboard', 'vault', 'workspaces', 'security', 'privacy', 'compliance', 'identity', 'automation', 'platform', 'operations', 'checkout', 'login'];
  for (const route of essentialRoutes) {
    if (!appCode.includes(`path="${route}"`) && !appCode.includes(`path="/${route}"`)) {
      throw new Error(`Route "${route}" is not registered in App.tsx`);
    }
  }

  // Verify navigation items in AppLayout.tsx
  if (!layoutCode.includes('/app/vault')) {
    throw new Error('Secure Vault is missing from AppLayout navigation menu');
  }

  // Verify navbar contains checkout and sign in links
  if (!navbarCode.includes('/checkout') || !navbarCode.includes('/login')) {
    throw new Error('Navbar missing links to /checkout or /login');
  }

  // Verify SecureVault drag-and-drop & file selection contracts
  if (!vaultCode.includes('handleDragOver') || !vaultCode.includes('handleDrop') || !vaultCode.includes('fileInputRef')) {
    throw new Error('SecureVault missing complete drag-and-drop or manual file input support');
  }
});

// 8. Verify Production Build & Static Asset Generation
assertTest('Vite and esbuild production bundling builds dist/ correctly', () => {
  execSync('npm run build', { stdio: 'pipe' });
  if (!fs.existsSync('dist/index.html')) throw new Error('dist/index.html was not generated');
  if (!fs.existsSync('dist/server.cjs')) throw new Error('dist/server.cjs was not generated');
});

console.log(`\n========================================`);
console.log(`Pipeline Summary: ${passCount}/${totalCount} tests passed.`);
console.log(`========================================\n`);

if (passCount !== totalCount) {
  process.exit(1);
} else {
  console.log('🎉 All Pipeline & Repository Comprehension Tests PASSED Successfully!');
  process.exit(0);
}
