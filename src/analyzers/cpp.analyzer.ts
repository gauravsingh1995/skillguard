/**
 * C/C++ Analyzer
 * Pattern-based security analysis for C/C++ files
 */

import * as fs from 'fs';
import { Finding, LanguageAnalyzer, Language, RiskSeverity } from '../types';

interface CppPattern {
  name: string;
  severity: RiskSeverity;
  category: string;
  description: string;
  pattern: RegExp;
}

// Security patterns for C/C++
const CPP_PATTERNS: CppPattern[] = [
  // CRITICAL: Shell Execution & Unsafe Functions
  {
    name: 'system',
    severity: 'critical',
    category: 'Shell Execution',
    description: 'Executes shell commands - potential arbitrary code execution',
    pattern: /\bsystem\s*\(/g,
  },
  {
    name: 'popen',
    severity: 'critical',
    category: 'Shell Execution',
    description: 'Opens process - potential arbitrary code execution',
    pattern: /\bpopen\s*\(/g,
  },
  {
    name: 'gets',
    severity: 'critical',
    category: 'Buffer Overflow',
    description: 'Unsafe function - buffer overflow risk',
    pattern: /\bgets\s*\(/g,
  },
  {
    name: 'strcpy',
    severity: 'critical',
    category: 'Buffer Overflow',
    description: 'Unsafe string copy - buffer overflow risk',
    pattern: /\bstrcpy\s*\(/g,
  },
  {
    name: 'strcat',
    severity: 'critical',
    category: 'Buffer Overflow',
    description: 'Unsafe string concatenation - buffer overflow risk',
    pattern: /\bstrcat\s*\(/g,
  },
  {
    name: 'sprintf',
    severity: 'critical',
    category: 'Buffer Overflow',
    description: 'Unsafe string formatting - buffer overflow risk',
    pattern: /\bsprintf\s*\(/g,
  },

  // HIGH: Memory & File Operations
  {
    name: 'malloc without check',
    severity: 'high',
    category: 'Memory Management',
    description: 'Dynamic memory allocation - check for NULL pointer',
    pattern: /\bmalloc\s*\(/g,
  },
  {
    name: 'free',
    severity: 'high',
    category: 'Memory Management',
    description: 'Memory deallocation - check for double-free',
    pattern: /\bfree\s*\(/g,
  },
  {
    name: 'memcpy',
    severity: 'high',
    category: 'Memory Operations',
    description: 'Memory copy - potential buffer overflow',
    pattern: /\bmemcpy\s*\(/g,
  },
  {
    name: 'fopen',
    severity: 'high',
    category: 'File Operations',
    description: 'File operations - review for security',
    pattern: /\bfopen\s*\(/g,
  },
  {
    name: 'remove/unlink',
    severity: 'high',
    category: 'File System Delete',
    description: 'Deletes files - potential data destruction',
    pattern: /\b(remove|unlink)\s*\(/g,
  },

  // HIGH: Prompt Injection / LLM API Usage
  {
    name: 'LLM API generic',
    severity: 'high',
    category: 'Prompt Injection',
    description: 'Generic LLM API call - potential prompt injection if using untrusted input',
    pattern: /(generate_text|generate_content|send_message|prompt_model|llm_inference|openai_)/g,
  },

  // MEDIUM: Format Strings & Network
  {
    name: 'printf with variable',
    severity: 'medium',
    category: 'Format String',
    description: 'Format string vulnerability risk',
    pattern: /\bprintf\s*\(\s*[^"']/g,
  },
  {
    name: 'socket',
    severity: 'medium',
    category: 'Network Access',
    description: 'Network socket operations - potential data exfiltration',
    pattern: /\bsocket\s*\(/g,
  },
  {
    name: 'connect',
    severity: 'medium',
    category: 'Network Access',
    description: 'Network connection - potential data exfiltration',
    pattern: /\bconnect\s*\(/g,
  },

  // LOW: Environment Access
  {
    name: 'getenv',
    severity: 'low',
    category: 'Environment Access',
    description: 'Accesses environment variables - potential sensitive data exposure',
    pattern: /\bgetenv\s*\(/g,
  },

  // ===== CREDENTIAL THEFT PATTERNS =====
  
  {
    name: 'Hardcoded Secret',
    severity: 'critical',
    category: 'Credential Theft',
    description: 'Hardcoded API key or password detected',
    pattern: /(?:api_key|api_secret|password|secret_key|auth_token|access_token)\s*=\s*"[^"]{8,}"/gi,
  },
  {
    name: 'SSH Key Access',
    severity: 'high',
    category: 'Credential Theft',
    description: 'Accesses SSH keys - potential credential theft',
    pattern: /fopen\s*\([^)]*(?:\.ssh|id_rsa|id_ed25519)/gi,
  },
  {
    name: 'Registry Credentials',
    severity: 'high',
    category: 'Credential Theft',
    description: 'Windows registry credential access',
    pattern: /RegOpenKeyEx|RegQueryValueEx|HKEY.*Password|HKEY.*Credential/gi,
  },
  {
    name: 'Config File Access',
    severity: 'medium',
    category: 'Credential Theft',
    description: 'Accesses configuration files',
    pattern: /fopen\s*\([^)]*(?:\.env|config|credentials|passwd)/gi,
  },

  // ===== CODE INJECTION PATTERNS =====
  
  {
    name: 'dlopen',
    severity: 'critical',
    category: 'Code Injection',
    description: 'Dynamic library loading - potential code injection',
    pattern: /\bdlopen\s*\(|\bLoadLibrary[AW]?\s*\(/gi,
  },
  {
    name: 'Shell Pipe',
    severity: 'high',
    category: 'Code Injection',
    description: 'Shell pipe command - potential injection',
    pattern: /_popen\s*\(|_wpopen\s*\(/g,
  },
  {
    name: 'WinExec',
    severity: 'critical',
    category: 'Code Injection',
    description: 'Windows execution functions',
    pattern: /\bWinExec\s*\(|\bShellExecute[AW]?\s*\(/gi,
  },

  // ===== PROMPT MANIPULATION PATTERNS =====
  
  {
    name: 'Sprintf Prompt',
    severity: 'high',
    category: 'Prompt Injection',
    description: 'Format string in prompt - potential injection',
    pattern: /sprintf\s*\([^)]*(?:prompt|message|instruction)/gi,
  },
  {
    name: 'String Concat Prompt',
    severity: 'medium',
    category: 'Prompt Injection',
    description: 'String concatenation in prompt - validate input',
    pattern: /strcat\s*\([^)]*(?:prompt|message)|(?:prompt|message).*strcat/gi,
  },

  // ===== DATA EXFILTRATION PATTERNS =====
  
  {
    name: 'DNS Query',
    severity: 'high',
    category: 'Data Exfiltration',
    description: 'DNS resolution - potential exfiltration',
    pattern: /\bgethostbyname\s*\(|\bgetaddrinfo\s*\(|DnsQuery/gi,
  },
  {
    name: 'Clipboard Windows',
    severity: 'high',
    category: 'Data Exfiltration',
    description: 'Windows clipboard access - potential data theft',
    pattern: /OpenClipboard|GetClipboardData|SetClipboardData/gi,
  },
  {
    name: 'Screenshot Windows',
    severity: 'high',
    category: 'Data Exfiltration',
    description: 'Screen capture - potential data theft',
    pattern: /BitBlt.*GetDC|CreateCompatibleDC.*Desktop|GetWindowDC/gi,
  },
  {
    name: 'Keylogger Hook',
    severity: 'critical',
    category: 'Data Exfiltration',
    description: 'Keyboard hook - potential keylogger',
    pattern: /SetWindowsHookEx.*WH_KEYBOARD|GetAsyncKeyState|GetKeyState/gi,
  },
  {
    name: 'Send Data',
    severity: 'medium',
    category: 'Data Exfiltration',
    description: 'Network send - potential exfiltration',
    pattern: /\bsend\s*\(|\bsendto\s*\(|WinHttpSendRequest/gi,
  },

  // ===== EVASION TECHNIQUE PATTERNS =====
  
  {
    name: 'XOR Obfuscation',
    severity: 'high',
    category: 'Evasion Technique',
    description: 'XOR operations - potential string obfuscation',
    pattern: /for\s*\([^)]*\)\s*\{[^}]*\^\s*0x[0-9a-f]+/gi,
  },
  {
    name: 'Anti-Debug Windows',
    severity: 'high',
    category: 'Evasion Technique',
    description: 'Anti-debugging techniques',
    pattern: /IsDebuggerPresent|CheckRemoteDebuggerPresent|NtQueryInformationProcess/gi,
  },
  {
    name: 'Anti-Debug Linux',
    severity: 'high',
    category: 'Evasion Technique',
    description: 'Linux anti-debugging',
    pattern: /ptrace\s*\(\s*PTRACE_TRACEME/gi,
  },
  {
    name: 'Sandbox Detection',
    severity: 'high',
    category: 'Evasion Technique',
    description: 'VM/sandbox detection patterns',
    pattern: /(?:vmware|virtualbox|vbox|qemu|sandbox|wine)/gi,
  },
  {
    name: 'Process Injection',
    severity: 'critical',
    category: 'Evasion Technique',
    description: 'Process injection patterns',
    pattern: /VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|NtCreateThreadEx/gi,
  },
  {
    name: 'Process Hollowing',
    severity: 'critical',
    category: 'Evasion Technique',
    description: 'Process hollowing technique',
    pattern: /NtUnmapViewOfSection|ZwUnmapViewOfSection|NtResumeThread/gi,
  },
  {
    name: 'Self-Delete',
    severity: 'high',
    category: 'Evasion Technique',
    description: 'Self-deletion capability',
    pattern: /MoveFileEx.*MOVEFILE_DELAY_UNTIL_REBOOT|DeleteFile.*argv\[0\]/gi,
  },
];

export class CppAnalyzer implements LanguageAnalyzer {
  readonly language: Language = 'cpp';
  readonly fileExtensions = ['.c', '.cpp', '.cc', '.cxx', '.h', '.hpp'];

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
    const language: Language = filePath.endsWith('.c') || filePath.endsWith('.h') ? 'c' : 'cpp';

    for (const pattern of CPP_PATTERNS) {
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
          language,
        });
      }
    }

    return findings;
  }
}
