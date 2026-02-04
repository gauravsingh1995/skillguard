/**
 * Rust Analyzer
 * Pattern-based security analysis for Rust files
 */

import * as fs from 'fs';
import { Finding, LanguageAnalyzer, Language, RiskSeverity } from '../types';

interface RustPattern {
  name: string;
  severity: RiskSeverity;
  category: string;
  description: string;
  pattern: RegExp;
}

// Security patterns for Rust
const RUST_PATTERNS: RustPattern[] = [
  // CRITICAL: Unsafe & Shell Execution
  {
    name: 'unsafe block',
    severity: 'critical',
    category: 'Unsafe Code',
    description: 'Unsafe code block - bypasses Rust safety guarantees',
    pattern: /\bunsafe\s*\{/g,
  },
  {
    name: 'Command::new',
    severity: 'critical',
    category: 'Shell Execution',
    description: 'Executes shell commands - potential arbitrary code execution',
    pattern: /Command::new\s*\(/g,
  },

  // HIGH: File System Operations
  {
    name: 'fs::write',
    severity: 'high',
    category: 'File System Write',
    description: 'Writes to files - potential data tampering',
    pattern: /fs::(write|File::create|OpenOptions)/g,
  },
  {
    name: 'fs::remove',
    severity: 'high',
    category: 'File System Delete',
    description: 'Deletes files - potential data destruction',
    pattern: /fs::(remove_file|remove_dir|remove_dir_all)\s*\(/g,
  },
  {
    name: 'transmute',
    severity: 'high',
    category: 'Type Casting',
    description: 'Unsafe type transmutation - potential memory corruption',
    pattern: /\btransmute\s*</g,
  },
  {
    name: 'raw pointers',
    severity: 'high',
    category: 'Unsafe Pointers',
    description: 'Raw pointer dereferencing - potential memory unsafety',
    pattern: /\*(?:const|mut)\s+\w+/g,
  },

  // HIGH: Prompt Injection / LLM API Usage
  {
    name: 'OpenAI API',
    severity: 'high',
    category: 'Prompt Injection',
    description: 'OpenAI API usage - potential prompt injection if using untrusted input',
    pattern: /openai::|create_chat_completion|create_completion/g,
  },
  {
    name: 'LLM API generic',
    severity: 'high',
    category: 'Prompt Injection',
    description: 'Generic LLM API call - potential prompt injection if using untrusted input',
    pattern: /(generate_text|generate_content|send_message|prompt_model|llm_inference)/g,
  },

  // MEDIUM: Network Access
  {
    name: 'TcpStream',
    severity: 'medium',
    category: 'Network Access',
    description: 'Network connections - potential data exfiltration',
    pattern: /TcpStream::(connect|bind)/g,
  },
  {
    name: 'reqwest',
    severity: 'medium',
    category: 'Network Access',
    description: 'HTTP client - potential data exfiltration',
    pattern: /reqwest::(get|post|Client)/g,
  },
  {
    name: 'hyper',
    severity: 'medium',
    category: 'Network Access',
    description: 'HTTP library - potential data exfiltration',
    pattern: /hyper::/g,
  },

  // LOW: Environment Access
  {
    name: 'env::var',
    severity: 'low',
    category: 'Environment Access',
    description: 'Accesses environment variables - potential sensitive data exposure',
    pattern: /env::var\s*\(\s*"[A-Z_]*(?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|AUTH|PRIVATE)/gi,
  },

  // ===== CREDENTIAL THEFT PATTERNS =====
  
  {
    name: 'Hardcoded Secret',
    severity: 'critical',
    category: 'Credential Theft',
    description: 'Hardcoded API key or password detected',
    pattern: /(?:api_key|api_secret|password|secret_key|auth_token|access_token)\s*(?:=|:)\s*"[^"]{8,}"/gi,
  },
  {
    name: 'SSH Key Access',
    severity: 'high',
    category: 'Credential Theft',
    description: 'Accesses SSH keys - potential credential theft',
    pattern: /fs::read_to_string\s*\([^)]*(?:\.ssh|id_rsa|id_ed25519)/gi,
  },
  {
    name: 'Config File Access',
    severity: 'medium',
    category: 'Credential Theft',
    description: 'Accesses configuration files',
    pattern: /fs::read\s*\([^)]*(?:\.env|credentials|config|secrets)/gi,
  },
  {
    name: 'Keyring Access',
    severity: 'high',
    category: 'Credential Theft',
    description: 'System keyring access',
    pattern: /keyring::|secret_service::|libsecret::/gi,
  },

  // ===== CODE INJECTION PATTERNS =====
  
  {
    name: 'libloading',
    severity: 'critical',
    category: 'Code Injection',
    description: 'Dynamic library loading',
    pattern: /libloading::|Library::new|dlopen/gi,
  },
  {
    name: 'FFI Call',
    severity: 'high',
    category: 'Code Injection',
    description: 'Foreign function interface - native code',
    pattern: /extern\s+"C"|#\[link\(|std::ffi/gi,
  },
  {
    name: 'Inline Assembly',
    severity: 'critical',
    category: 'Code Injection',
    description: 'Inline assembly - direct CPU instructions',
    pattern: /asm!\s*\(|global_asm!/gi,
  },

  // ===== PROMPT MANIPULATION PATTERNS =====
  
  {
    name: 'Format Prompt',
    severity: 'high',
    category: 'Prompt Injection',
    description: 'Format macro in prompt - potential injection',
    pattern: /format!\s*\([^)]*(?:prompt|message|instruction)/gi,
  },
  {
    name: 'String Concat Prompt',
    severity: 'medium',
    category: 'Prompt Injection',
    description: 'String concatenation in prompt - validate input',
    pattern: /(?:prompt|message)\s*\+\s*&|\+\s*(?:prompt|message)/gi,
  },

  // ===== DATA EXFILTRATION PATTERNS =====
  
  {
    name: 'DNS Lookup',
    severity: 'high',
    category: 'Data Exfiltration',
    description: 'DNS resolution - potential exfiltration',
    pattern: /lookup_host|ToSocketAddrs|dns::/gi,
  },
  {
    name: 'Clipboard Access',
    severity: 'high',
    category: 'Data Exfiltration',
    description: 'Clipboard access - potential data theft',
    pattern: /arboard::|clipboard::|copypasta::/gi,
  },
  {
    name: 'Screenshot',
    severity: 'high',
    category: 'Data Exfiltration',
    description: 'Screen capture - potential data theft',
    pattern: /screenshots::|screen::|scrap::/gi,
  },
  {
    name: 'Keylogger Pattern',
    severity: 'critical',
    category: 'Data Exfiltration',
    description: 'Keyboard monitoring - potential keylogger',
    pattern: /rdev::|device_query::|inputbot::/gi,
  },
  {
    name: 'Email Send',
    severity: 'medium',
    category: 'Data Exfiltration',
    description: 'Email sending - potential exfiltration',
    pattern: /lettre::|mail_send::|smtp::/gi,
  },

  // ===== EVASION TECHNIQUE PATTERNS =====
  
  {
    name: 'Base64 Decode',
    severity: 'high',
    category: 'Evasion Technique',
    description: 'Base64 decoding - potential obfuscation',
    pattern: /base64::decode|STANDARD\.decode|URL_SAFE\.decode/gi,
  },
  {
    name: 'Anti-Debug',
    severity: 'high',
    category: 'Evasion Technique',
    description: 'Anti-debugging technique detected',
    pattern: /ptrace|IsDebuggerPresent|CheckRemoteDebuggerPresent/gi,
  },
  {
    name: 'Sandbox Detection',
    severity: 'high',
    category: 'Evasion Technique',
    description: 'VM/sandbox detection patterns',
    pattern: /(?:vmware|virtualbox|vbox|qemu|sandbox)/gi,
  },
  {
    name: 'Process Manipulation',
    severity: 'critical',
    category: 'Evasion Technique',
    description: 'Process manipulation patterns',
    pattern: /libc::ptrace|windows::Win32::System::Threading|CreateRemoteThread/gi,
  },
  {
    name: 'Memory Manipulation',
    severity: 'high',
    category: 'Evasion Technique',
    description: 'Direct memory manipulation',
    pattern: /std::ptr::write|std::ptr::read|MaybeUninit/gi,
  },
];

export class RustAnalyzer implements LanguageAnalyzer {
  readonly language: Language = 'rust';
  readonly fileExtensions = ['.rs'];

  canAnalyze(filePath: string): boolean {
    return this.fileExtensions.some((ext) => filePath.endsWith(ext));
  }

  analyzeFile(filePath: string): Finding[] {
    const findings: Finding[] = [];

    let source: string;
    try {
      source = fs.readFileSync(filePath, 'utf-8');
    } catch (_error) {
      return findings;
    }

    const lines = source.split('\n');

    for (const pattern of RUST_PATTERNS) {
      // Reset regex lastIndex
      pattern.pattern.lastIndex = 0;

      let match;
      while ((match = pattern.pattern.exec(source)) !== null) {
        const position = match.index;
        const lineNumber = source.substring(0, position).split('\n').length;
        const column = position - source.lastIndexOf('\n', position - 1) - 1;

        findings.push({
          file: filePath,
          line: lineNumber,
          column,
          severity: pattern.severity,
          category: pattern.category,
          description: pattern.description,
          codeSnippet: lines[lineNumber - 1]?.trim() || '',
          language: 'rust',
        });
      }
    }

    return findings;
  }
}
