/**
 * Go Analyzer
 * Pattern-based security analysis for Go files
 */

import * as fs from 'fs';
import { Finding, LanguageAnalyzer, Language, RiskSeverity } from '../types';

interface GoPattern {
  name: string;
  severity: RiskSeverity;
  category: string;
  description: string;
  pattern: RegExp;
}

// Security patterns for Go
const GO_PATTERNS: GoPattern[] = [
  // CRITICAL: Shell Execution
  {
    name: 'exec.Command',
    severity: 'critical',
    category: 'Shell Execution',
    description: 'Executes shell commands - potential arbitrary code execution',
    pattern: /exec\.Command\s*\(/g,
  },
  {
    name: 'syscall.Exec',
    severity: 'critical',
    category: 'Shell Execution',
    description: 'System call execution - potential arbitrary code execution',
    pattern: /syscall\.(Exec|ForkExec)\s*\(/g,
  },
  {
    name: 'eval package',
    severity: 'critical',
    category: 'Code Injection',
    description: 'Code evaluation - potential code injection',
    pattern: /eval\./g,
  },

  // HIGH: File System Operations
  {
    name: 'os.WriteFile',
    severity: 'high',
    category: 'File System Write',
    description: 'Writes to files - potential data tampering',
    pattern: /os\.(WriteFile|Create|OpenFile)\s*\(/g,
  },
  {
    name: 'os.Remove',
    severity: 'high',
    category: 'File System Delete',
    description: 'Deletes files - potential data destruction',
    pattern: /os\.(Remove|RemoveAll)\s*\(/g,
  },
  {
    name: 'os.Chmod',
    severity: 'high',
    category: 'File System Permissions',
    description: 'Modifies file permissions - potential privilege escalation',
    pattern: /os\.(Chmod|Chown)\s*\(/g,
  },
  {
    name: 'unsafe package',
    severity: 'high',
    category: 'Unsafe Operations',
    description: 'Uses unsafe package - bypasses type safety',
    pattern: /import\s+"unsafe"|unsafe\./g,
  },
  {
    name: 'reflect package',
    severity: 'high',
    category: 'Reflection',
    description: 'Uses reflection - potential security bypass',
    pattern: /reflect\./g,
  },

  // HIGH: Prompt Injection / LLM API Usage
  {
    name: 'OpenAI API',
    severity: 'high',
    category: 'Prompt Injection',
    description: 'OpenAI API usage - potential prompt injection if using untrusted input',
    pattern: /openai\.(CreateChatCompletion|CreateCompletion)/g,
  },
  {
    name: 'LLM API generic',
    severity: 'high',
    category: 'Prompt Injection',
    description: 'Generic LLM API call - potential prompt injection if using untrusted input',
    pattern: /(GenerateText|GenerateContent|SendMessage|PromptModel|LLMInference)/g,
  },

  // MEDIUM: Network Access
  {
    name: 'http.Get',
    severity: 'medium',
    category: 'Network Access',
    description: 'Makes HTTP requests - potential data exfiltration',
    pattern: /http\.(Get|Post|Head|Put|Delete)\s*\(/g,
  },
  {
    name: 'net.Dial',
    severity: 'medium',
    category: 'Network Access',
    description: 'Opens network connections - potential data exfiltration',
    pattern: /net\.(Dial|DialTCP|DialUDP)\s*\(/g,
  },
  {
    name: 'url.Parse',
    severity: 'medium',
    category: 'Network Access',
    description: 'URL operations - review for security',
    pattern: /url\.Parse\s*\(/g,
  },

  // LOW: Environment Access
  {
    name: 'os.Getenv',
    severity: 'low',
    category: 'Environment Access',
    description: 'Accesses environment variables - potential sensitive data exposure',
    pattern: /os\.Getenv\s*\(\s*"[A-Z_]*(?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|AUTH|PRIVATE)/gi,
  },

  // ===== CREDENTIAL THEFT PATTERNS =====
  
  {
    name: 'Hardcoded Secret',
    severity: 'critical',
    category: 'Credential Theft',
    description: 'Hardcoded API key or password detected',
    pattern: /(?:apiKey|apiSecret|password|secretKey|authToken|accessToken)\s*(?:=|:=)\s*"[^"]{8,}"/gi,
  },
  {
    name: 'SSH Key Access',
    severity: 'high',
    category: 'Credential Theft',
    description: 'Accesses SSH keys - potential credential theft',
    pattern: /ioutil\.ReadFile\s*\([^)]*(?:\.ssh|id_rsa|id_ed25519)/gi,
  },
  {
    name: 'AWS Config',
    severity: 'high',
    category: 'Credential Theft',
    description: 'Accesses AWS credentials',
    pattern: /aws\.Config|credentials\.NewStaticCredentials|AWS_ACCESS_KEY/gi,
  },
  {
    name: 'Config File Access',
    severity: 'medium',
    category: 'Credential Theft',
    description: 'Accesses configuration files',
    pattern: /ReadFile\s*\([^)]*(?:\.env|credentials|config\.yaml|secrets)/gi,
  },

  // ===== CODE INJECTION PATTERNS =====
  
  {
    name: 'Template Injection',
    severity: 'high',
    category: 'Code Injection',
    description: 'Template execution - potential injection if user input',
    pattern: /template\.(?:New|Must|Parse).*\.Execute/gi,
  },
  {
    name: 'Plugin Load',
    severity: 'critical',
    category: 'Code Injection',
    description: 'Dynamic plugin loading - potential code execution',
    pattern: /plugin\.Open\s*\(/g,
  },
  {
    name: 'CGO',
    severity: 'high',
    category: 'Code Injection',
    description: 'CGO usage - native code execution',
    pattern: /import\s+"C"|C\./g,
  },

  // ===== PROMPT MANIPULATION PATTERNS =====
  
  {
    name: 'String Format Prompt',
    severity: 'high',
    category: 'Prompt Injection',
    description: 'Format string in prompt - potential injection',
    pattern: /fmt\.Sprintf\s*\([^)]*(?:prompt|message|instruction)/gi,
  },
  {
    name: 'Prompt Concatenation',
    severity: 'medium',
    category: 'Prompt Injection',
    description: 'String concatenation in prompt - validate input',
    pattern: /(?:prompt|systemPrompt|userInput)\s*\+\s*|\+\s*(?:prompt|userInput)/gi,
  },

  // ===== DATA EXFILTRATION PATTERNS =====
  
  {
    name: 'DNS Lookup',
    severity: 'high',
    category: 'Data Exfiltration',
    description: 'DNS resolution - potential data exfiltration',
    pattern: /net\.LookupHost|net\.LookupIP|dns\.Exchange/gi,
  },
  {
    name: 'Clipboard Access',
    severity: 'high',
    category: 'Data Exfiltration',
    description: 'Clipboard access - potential data theft',
    pattern: /clipboard\.Read|clipboard\.Write|atotto\/clipboard/gi,
  },
  {
    name: 'Screenshot Capture',
    severity: 'high',
    category: 'Data Exfiltration',
    description: 'Screen capture - potential data theft',
    pattern: /screenshot\.CaptureScreen|kbinani\/screenshot/gi,
  },
  {
    name: 'Keyboard Hook',
    severity: 'critical',
    category: 'Data Exfiltration',
    description: 'Keyboard monitoring - potential keylogger',
    pattern: /hook\.Register|robotgo\.AddEvent|gohook/gi,
  },
  {
    name: 'Email Send',
    severity: 'medium',
    category: 'Data Exfiltration',
    description: 'Email sending - potential exfiltration',
    pattern: /smtp\.SendMail|gomail\.NewMessage/gi,
  },

  // ===== EVASION TECHNIQUE PATTERNS =====
  
  {
    name: 'Base64 Decode',
    severity: 'high',
    category: 'Evasion Technique',
    description: 'Base64 decoding - potential obfuscation',
    pattern: /base64\.StdEncoding\.Decode|base64\.RawStdEncoding/gi,
  },
  {
    name: 'Anti-Debug',
    severity: 'high',
    category: 'Evasion Technique',
    description: 'Anti-debugging technique detected',
    pattern: /syscall\.Ptrace|IsDebuggerPresent|CheckRemoteDebuggerPresent/gi,
  },
  {
    name: 'Sandbox Detection',
    severity: 'high',
    category: 'Evasion Technique',
    description: 'VM/sandbox detection patterns',
    pattern: /(?:vmware|virtualbox|vbox|qemu|sandbox)/gi,
  },
  {
    name: 'Time Delay',
    severity: 'medium',
    category: 'Evasion Technique',
    description: 'Long time delay - potential sandbox evasion',
    pattern: /time\.Sleep\s*\(\s*(?:\d+\s*\*\s*)?time\.(?:Minute|Hour)/g,
  },
  {
    name: 'Process Injection',
    severity: 'critical',
    category: 'Evasion Technique',
    description: 'Process injection patterns',
    pattern: /VirtualAllocEx|WriteProcessMemory|CreateRemoteThread/gi,
  },
];

export class GoAnalyzer implements LanguageAnalyzer {
  readonly language: Language = 'go';
  readonly fileExtensions = ['.go'];

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

    for (const pattern of GO_PATTERNS) {
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
          language: 'go',
        });
      }
    }

    return findings;
  }
}
