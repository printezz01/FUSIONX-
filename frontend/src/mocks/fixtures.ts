// ═══════════════════════════════════════════════════
// Sentinel AI — Mock Data Fixtures
// Static JSON for all endpoints when VITE_USE_MOCKS=true
// ═══════════════════════════════════════════════════

import type {
  Finding, ScanStatusResponse, DashboardResponse,
  ChainResponse, ChatResponse,
} from '../types/api';

const MOCK_FINDINGS: Finding[] = [
  {
    id: 'f-001',
    layer: 'web',
    severity: 'critical',
    title: 'SQL Injection on /search Endpoint',
    description: 'The /search endpoint is vulnerable to SQL injection. User-supplied input is directly concatenated into SQL queries without sanitization, allowing an attacker to extract data, bypass authentication, and potentially gain internal network access.',
    cve_id: null,
    gives: 'internal_network_access, app_data_read',
    requires: 'internet_access',
  },
  {
    id: 'f-002',
    layer: 'code',
    severity: 'critical',
    title: 'Hardcoded Database Password in config.py',
    description: "A hardcoded database password was found in config.py. The credential 'postgres:password123@localhost:5432/appdb' is embedded directly in source code.",
    cve_id: null,
    gives: 'database_credentials',
    requires: 'code_read_access',
  },
  {
    id: 'f-003',
    layer: 'network',
    severity: 'critical',
    title: 'PostgreSQL 5432 Open — No Firewall',
    description: 'Port 5432 (PostgreSQL) is open and accessible without firewall restrictions. An attacker with valid credentials can connect directly to the database.',
    cve_id: null,
    gives: 'full_database_access, lateral_movement',
    requires: 'database_credentials, internal_network_access',
  },
  {
    id: 'f-004',
    layer: 'code',
    severity: 'critical',
    title: 'Leaked AWS Access Key in Environment File',
    description: 'An AWS Access Key ID was found committed in a .env file. This key could provide access to AWS cloud resources.',
    cve_id: null,
    gives: 'cloud_access, lateral_movement',
    requires: 'code_read_access',
  },
  {
    id: 'f-005',
    layer: 'code',
    severity: 'critical',
    title: 'SQL Injection via String Formatting',
    description: 'SQL query constructed using string formatting instead of parameterized queries.',
    cve_id: null,
    gives: 'app_data_read, app_data_write',
    requires: 'internet_access',
  },
  {
    id: 'f-006',
    layer: 'web',
    severity: 'high',
    title: 'Cross-Site Scripting (XSS) — Reflected',
    description: "Multiple parameters reflect user input without encoding. An attacker can inject malicious JavaScript that executes in victim's browser sessions.",
    cve_id: null,
    gives: 'session_hijack, credential_theft',
    requires: 'internet_access',
  },
  {
    id: 'f-007',
    layer: 'network',
    severity: 'high',
    title: 'SSH Service on Port 22 — Weak Configuration',
    description: 'OpenSSH 4.7p1 is running with outdated configuration. Supports weak ciphers and allows password-based authentication.',
    cve_id: 'CVE-2008-5161',
    gives: 'ssh_access, command_execution',
    requires: 'ssh_credentials, internal_network_access',
  },
  {
    id: 'f-008',
    layer: 'network',
    severity: 'high',
    title: 'FTP Service on Port 21 — Anonymous Access',
    description: 'vsftpd 2.3.4 is running with anonymous FTP access enabled. This version contains a known backdoor vulnerability.',
    cve_id: 'CVE-2011-2523',
    gives: 'file_read_access, code_read_access',
    requires: 'internal_network_access',
  },
  {
    id: 'f-009',
    layer: 'iot',
    severity: 'critical',
    title: 'Hikvision IP Camera — Remote Code Execution',
    description: 'Hikvision camera detected with firmware vulnerable to CVE-2021-36260 (CVSS 9.8). Command injection allows unauthenticated remote code execution.',
    cve_id: 'CVE-2021-36260',
    gives: 'camera_access, command_execution, lateral_movement',
    requires: 'internal_network_access',
  },
  {
    id: 'f-010',
    layer: 'iot',
    severity: 'high',
    title: 'Default Credentials on IP Camera',
    description: 'The Hikvision camera is accessible with default credentials (admin/12345).',
    cve_id: null,
    gives: 'camera_access, credential_theft',
    requires: 'internal_network_access',
  },
  {
    id: 'f-011',
    layer: 'code',
    severity: 'high',
    title: 'Insecure Use of eval()',
    description: 'Use of eval() function detected. An attacker who can control the input can execute arbitrary Python code.',
    cve_id: null,
    gives: 'command_execution',
    requires: 'app_data_write',
  },
  {
    id: 'f-012',
    layer: 'code',
    severity: 'high',
    title: 'GitHub Personal Access Token Leaked',
    description: 'A GitHub Personal Access Token (PAT) was found in a script file.',
    cve_id: null,
    gives: 'code_read_access, code_write_access',
    requires: 'code_read_access',
  },
  {
    id: 'f-013',
    layer: 'network',
    severity: 'high',
    title: 'MySQL on Port 3306 — Open Access',
    description: 'MySQL 5.0.51a is accessible on port 3306. Combined with database credentials, this allows full database access.',
    cve_id: null,
    gives: 'database_access',
    requires: 'database_credentials, internal_network_access',
  },
  {
    id: 'f-014',
    layer: 'web',
    severity: 'medium',
    title: 'Directory Listing Enabled',
    description: 'Apache directory listing is enabled, exposing internal file structure and potentially sensitive data.',
    cve_id: null,
    gives: 'information_disclosure',
    requires: 'internet_access',
  },
  {
    id: 'f-015',
    layer: 'code',
    severity: 'medium',
    title: 'Debug Mode Enabled in Production',
    description: 'Flask/Django debug mode is enabled. This exposes detailed error pages with stack traces.',
    cve_id: null,
    gives: 'information_disclosure',
    requires: 'internet_access',
  },
  {
    id: 'f-016',
    layer: 'code',
    severity: 'medium',
    title: 'Weak Cryptographic Hash (MD5)',
    description: 'MD5 is used for hashing passwords. MD5 is cryptographically broken.',
    cve_id: null,
    gives: 'credential_cracking',
    requires: 'database_access',
  },
  {
    id: 'f-017',
    layer: 'network',
    severity: 'medium',
    title: 'Telnet Service on Port 23 — Unencrypted',
    description: 'Telnet service is running. All communications are transmitted in plaintext.',
    cve_id: null,
    gives: 'credential_interception',
    requires: 'internal_network_access',
  },
  {
    id: 'f-018',
    layer: 'web',
    severity: 'low',
    title: 'Server Version Disclosure',
    description: 'The web server exposes its version in HTTP response headers (Apache/2.4.7).',
    cve_id: null,
    gives: 'information_disclosure',
    requires: 'internet_access',
  },
  {
    id: 'f-019',
    layer: 'web',
    severity: 'low',
    title: 'Missing Security Headers',
    description: 'Several security headers are missing: X-Frame-Options, X-Content-Type-Options, Content-Security-Policy.',
    cve_id: null,
    gives: 'information_disclosure',
    requires: 'internet_access',
  },
  {
    id: 'f-020',
    layer: 'code',
    severity: 'critical',
    title: 'Database Connection String with Credentials',
    description: 'A PostgreSQL connection string containing username and password was found in a configuration file.',
    cve_id: null,
    gives: 'database_credentials',
    requires: 'code_read_access',
  },
];

const SCAN_TOOLS = [
  'nmap', 'bandit', 'semgrep', 'trufflehog', 'nikto',
  'NVD lookup', 'CCTV check', 'attack chain build', 'embedding',
];

let mockElapsed = 0;
let mockToolIndex = 0;
let mockFindingsRevealed = 0;

export function resetMockState(): void {
  mockElapsed = 0;
  mockToolIndex = 0;
  mockFindingsRevealed = 0;
}

export function getMockScanStatus(scanId: string): ScanStatusResponse {
  mockElapsed += 1.5;
  mockFindingsRevealed = Math.min(
    MOCK_FINDINGS.length,
    Math.floor(mockElapsed / 3)
  );
  mockToolIndex = Math.min(
    SCAN_TOOLS.length - 1,
    Math.floor(mockElapsed / 5)
  );

  const isComplete = mockElapsed >= 42;

  return {
    scan_id: scanId,
    status: isComplete ? 'completed' : 'running',
    current_tool: isComplete ? null : SCAN_TOOLS[mockToolIndex],
    elapsed_seconds: Math.floor(mockElapsed),
    findings_so_far: MOCK_FINDINGS.slice(0, mockFindingsRevealed),
  };
}

export function getMockDashboard(): DashboardResponse {
  return {
    severity_breakdown: {
      critical: 7,
      high: 6,
      medium: 4,
      low: 2,
      info: 1,
    },
    findings: MOCK_FINDINGS,
    risk_score: {
      score: 18,
      breakdown: {
        starting_score: 100,
        critical_deduction: 45,
        high_deduction: 24,
        medium_deduction: 9,
        low_deduction: 2,
        chain_deduction: 10,
        secret_deduction: 5,
      },
    },
    owasp_mapping: [
      {
        category: 'A01:2021 Broken Access Control',
        findings: [],
      },
      {
        category: 'A02:2021 Cryptographic Failures',
        findings: [MOCK_FINDINGS[1], MOCK_FINDINGS[3], MOCK_FINDINGS[15], MOCK_FINDINGS[19]],
      },
      {
        category: 'A03:2021 Injection',
        findings: [MOCK_FINDINGS[0], MOCK_FINDINGS[4], MOCK_FINDINGS[5]],
      },
      {
        category: 'A04:2021 Insecure Design',
        findings: [],
      },
      {
        category: 'A05:2021 Security Misconfiguration',
        findings: [MOCK_FINDINGS[13], MOCK_FINDINGS[14], MOCK_FINDINGS[18]],
      },
      {
        category: 'A06:2021 Vulnerable & Outdated Components',
        findings: [MOCK_FINDINGS[6], MOCK_FINDINGS[7], MOCK_FINDINGS[8]],
      },
      {
        category: 'A07:2021 Identification & Auth Failures',
        findings: [MOCK_FINDINGS[9]],
      },
      {
        category: 'A08:2021 Software & Data Integrity Failures',
        findings: [],
      },
      {
        category: 'A09:2021 Security Logging & Monitoring Failures',
        findings: [],
      },
      {
        category: 'A10:2021 Server-Side Request Forgery',
        findings: [],
      },
    ],
  };
}

export function getMockChain(): ChainResponse {
  return {
    nodes: [
      { data: { id: 'f-001', label: 'SQL Injection on /search', layer: 'web', severity: 'critical', gives: 'internal_network_access, app_data_read', requires: 'internet_access' } },
      { data: { id: 'f-002', label: 'Hardcoded DB Password', layer: 'code', severity: 'critical', gives: 'database_credentials', requires: 'code_read_access' } },
      { data: { id: 'f-003', label: 'PostgreSQL 5432 Open', layer: 'network', severity: 'critical', gives: 'full_database_access, lateral_movement', requires: 'database_credentials, internal_network_access' } },
      { data: { id: 'f-004', label: 'AWS Key Leaked', layer: 'code', severity: 'critical', gives: 'cloud_access, lateral_movement', requires: 'code_read_access' } },
      { data: { id: 'f-005', label: 'SQL Injection in Code', layer: 'code', severity: 'critical', gives: 'app_data_read, app_data_write', requires: 'internet_access' } },
      { data: { id: 'f-006', label: 'Reflected XSS', layer: 'web', severity: 'high', gives: 'session_hijack, credential_theft', requires: 'internet_access' } },
      { data: { id: 'f-007', label: 'Weak SSH Config', layer: 'network', severity: 'high', gives: 'ssh_access, command_execution', requires: 'ssh_credentials, internal_network_access' } },
      { data: { id: 'f-008', label: 'FTP Anonymous Access', layer: 'network', severity: 'high', gives: 'file_read_access, code_read_access', requires: 'internal_network_access' } },
      { data: { id: 'f-009', label: 'Hikvision Camera RCE', layer: 'iot', severity: 'critical', gives: 'camera_access, command_execution, lateral_movement', requires: 'internal_network_access' } },
      { data: { id: 'f-010', label: 'Camera Default Creds', layer: 'iot', severity: 'high', gives: 'camera_access, credential_theft', requires: 'internal_network_access' } },
      { data: { id: 'f-011', label: 'Insecure eval()', layer: 'code', severity: 'high', gives: 'command_execution', requires: 'app_data_write' } },
      { data: { id: 'f-013', label: 'MySQL 3306 Open', layer: 'network', severity: 'high', gives: 'database_access', requires: 'database_credentials, internal_network_access' } },
      { data: { id: 'f-016', label: 'Weak MD5 Hash', layer: 'code', severity: 'medium', gives: 'credential_cracking', requires: 'database_access' } },
      { data: { id: 'f-020', label: 'DB Conn String Leaked', layer: 'code', severity: 'critical', gives: 'database_credentials', requires: 'code_read_access' } },
    ],
    edges: [
      { data: { source: 'f-001', target: 'f-003', reason: 'SQL injection provides internal_network_access needed to reach open PostgreSQL port' } },
      { data: { source: 'f-001', target: 'f-007', reason: 'SQL injection provides internal_network_access for SSH lateral movement' } },
      { data: { source: 'f-001', target: 'f-008', reason: 'SQL injection provides internal_network_access for FTP access' } },
      { data: { source: 'f-001', target: 'f-009', reason: 'SQL injection provides internal_network_access to reach IoT camera' } },
      { data: { source: 'f-001', target: 'f-010', reason: 'SQL injection provides internal_network_access to reach camera with default creds' } },
      { data: { source: 'f-001', target: 'f-013', reason: 'SQL injection provides internal_network_access for MySQL access' } },
      { data: { source: 'f-002', target: 'f-003', reason: 'Hardcoded password provides database_credentials for PostgreSQL' } },
      { data: { source: 'f-002', target: 'f-013', reason: 'Hardcoded password provides database_credentials for MySQL' } },
      { data: { source: 'f-020', target: 'f-003', reason: 'Leaked connection string provides database_credentials for PostgreSQL' } },
      { data: { source: 'f-020', target: 'f-013', reason: 'Leaked connection string provides database_credentials for MySQL' } },
      { data: { source: 'f-008', target: 'f-002', reason: 'FTP anonymous access provides code_read_access to find hardcoded passwords' } },
      { data: { source: 'f-008', target: 'f-004', reason: 'FTP anonymous access provides code_read_access to find AWS keys' } },
      { data: { source: 'f-008', target: 'f-020', reason: 'FTP anonymous access provides code_read_access for connection strings' } },
      { data: { source: 'f-005', target: 'f-011', reason: 'SQL injection provides app_data_write needed for eval() exploitation' } },
      { data: { source: 'f-003', target: 'f-016', reason: 'Full database access enables credential cracking via MD5 hashes' } },
    ],
  };
}

export function getMockChat(question: string): ChatResponse {
  const questionLower = question.toLowerCase();

  if (questionLower.includes('dangerous') || questionLower.includes('critical') || questionLower.includes('worst')) {
    return {
      answer: `The most dangerous finding is the **SQL Injection on /search Endpoint** (f-001). This is a critical-severity web vulnerability that serves as the entry point for the entire attack chain.\n\nHere's why it's the most dangerous:\n\n1. **Entry Point**: It requires only internet_access, meaning any external attacker can exploit it\n2. **Chain Enabler**: It provides internal_network_access, which unlocks 6 other vulnerabilities including the open PostgreSQL port, SSH, FTP, IoT cameras, and MySQL\n3. **Data Access**: Combined with the hardcoded database password (f-002), it creates a direct path to full database compromise\n4. **Lateral Movement**: Through the attack chain, it enables access to IoT devices, cloud resources (via leaked AWS keys), and command execution\n\n**Immediate Action**: Implement parameterized queries on the /search endpoint and deploy a WAF rule to block SQL injection patterns.`,
      sources: [MOCK_FINDINGS[0], MOCK_FINDINGS[2], MOCK_FINDINGS[1]],
    };
  }

  if (questionLower.includes('attack path') || questionLower.includes('chain')) {
    return {
      answer: `The attack chain tells a clear story of escalation:\n\n**Stage 1 — Web Entry**\nSQL Injection on /search (f-001) → provides internal_network_access\n\n**Stage 2 — Code Secrets**\nFTP Anonymous Access (f-008) → provides code_read_access → exposes:\n- Hardcoded DB Password (f-002)\n- Leaked AWS Key (f-004)\n- DB Connection String (f-020)\n\n**Stage 3 — Database Breach**\nInternal network access + database credentials → PostgreSQL 5432 (f-003) → full_database_access\nAlso enables MySQL 3306 access (f-013)\n\n**Stage 4 — Lateral Movement**\nFrom internal network: SSH (f-007), IoT Camera RCE (f-009), Camera Default Creds (f-010)\n\n**Stage 5 — Deep Exploitation**\nDatabase access → MD5 hash cracking (f-016) → credential reuse\nApp data write → eval() exploitation (f-011) → arbitrary code execution\n\nThis is a complete kill chain from external web access to full infrastructure compromise.`,
      sources: [MOCK_FINDINGS[0], MOCK_FINDINGS[7], MOCK_FINDINGS[1], MOCK_FINDINGS[2], MOCK_FINDINGS[8]],
    };
  }

  if (questionLower.includes('fix') || questionLower.includes('remediat') || questionLower.includes('first')) {
    return {
      answer: `Here's the prioritized remediation plan:\n\n**1. [CRITICAL] Fix SQL Injection — /search endpoint**\nReplace string concatenation with parameterized queries. This blocks the primary entry point for the entire attack chain.\n\n**2. [CRITICAL] Remove hardcoded credentials**\nRotate the database password in config.py (f-002) and the connection string in database.yml (f-020). Move all secrets to environment variables or a vault.\n\n**3. [CRITICAL] Revoke leaked AWS key**\nImmediately revoke the AWS Access Key found in .env (f-004). Rotate credentials and audit CloudTrail for unauthorized access.\n\n**4. [HIGH] Firewall PostgreSQL and MySQL**\nRestrict ports 5432 and 3306 to only authorized application servers. Deny all external access.\n\n**5. [HIGH] Update Hikvision camera firmware**\nPatch CVE-2021-36260 and change default credentials immediately.\n\n**6. [HIGH] Disable FTP anonymous access**\nDisable anonymous FTP on vsftpd or replace with SFTP.\n\n**7. [MEDIUM] Replace MD5 with bcrypt/argon2**\nRe-hash all passwords using a modern algorithm.`,
      sources: [MOCK_FINDINGS[0], MOCK_FINDINGS[1], MOCK_FINDINGS[3], MOCK_FINDINGS[2]],
    };
  }

  if (questionLower.includes('secret') || questionLower.includes('leaked') || questionLower.includes('credential')) {
    return {
      answer: `Found **4 leaked secrets** across the codebase:\n\n1. **Hardcoded Database Password** (f-002, CRITICAL)\n   - File: config.py, line 12\n   - Value: postgres:password123@localhost:5432/appdb\n   - Impact: Direct database access\n\n2. **AWS Access Key** (f-004, CRITICAL)\n   - File: .env, line 3\n   - Value: AKIA****XYZQ (redacted)\n   - Impact: Full AWS cloud access\n\n3. **Database Connection String** (f-020, CRITICAL)\n   - File: config/database.yml, line 8\n   - Impact: Database credentials exposure\n\n4. **GitHub Personal Access Token** (f-012, HIGH)\n   - File: scripts/deploy.sh, line 15\n   - Value: ghp_****mnop (redacted)\n   - Impact: Private repo access, CI/CD pipeline compromise\n\n**Immediate Actions**: Revoke all leaked credentials, rotate secrets, and implement pre-commit hooks with trufflehog to prevent future leaks.`,
      sources: [MOCK_FINDINGS[1], MOCK_FINDINGS[3], MOCK_FINDINGS[19], MOCK_FINDINGS[11]],
    };
  }

  return {
    answer: `Based on the scan findings, here's what I found related to your query:\n\nThe scan discovered **20 vulnerabilities** across 4 layers:\n- **7 Critical**: SQL injection, hardcoded credentials, leaked keys, camera RCE\n- **6 High**: XSS, weak SSH, FTP backdoor, eval() usage, default camera creds\n- **4 Medium**: Directory listing, debug mode, weak hashing, unencrypted telnet\n- **2 Low**: Server version disclosure, missing security headers\n\nThe risk score is **18/100** (critical), primarily due to the multi-step attack chain that goes from web SQL injection → code secrets → database compromise → lateral movement.\n\nWould you like me to elaborate on any specific finding or attack path?`,
    sources: [MOCK_FINDINGS[0], MOCK_FINDINGS[1], MOCK_FINDINGS[2]],
  };
}
