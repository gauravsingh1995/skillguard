/**
 * Ruby Analyzer
 * Pattern-based security analysis for Ruby files
 */

import * as fs from 'fs';
import { Finding, LanguageAnalyzer, Language, RiskSeverity } from '../types';

interface RubyPattern {
  name: string;
  severity: RiskSeverity;
  category: string;
  description: string;
  pattern: RegExp;
}

// Security patterns for Ruby
const RUBY_PATTERNS: RubyPattern[] = [
  // CRITICAL: Shell Execution
  {
    name: 'system',
    severity: 'critical',
    category: 'Shell Execution',
    description: 'Executes shell commands - potential arbitrary code execution',
    pattern: /\bsystem\s*\(/g,
  },
  {
    name: 'exec',
    severity: 'critical',
    category: 'Shell Execution',
    description: 'Executes shell commands - potential arbitrary code execution',
    pattern: /\bexec\s*\(/g,
  },
  {
    name: 'backticks',
    severity: 'critical',
    category: 'Shell Execution',
    description: 'Shell command execution via backticks - potential code execution',
    pattern: /`[^`]*`/g,
  },
  {
    name: 'eval',
    severity: 'critical',
    category: 'Code Injection',
    description: 'Evaluates arbitrary code - critical security risk',
    pattern: /\beval\s*\(/g,
  },
  {
    name: 'instance_eval',
    severity: 'critical',
    category: 'Code Injection',
    description: 'Instance evaluation - potential code injection',
    pattern: /\.instance_eval\s*\(/g,
  },
  {
    name: 'class_eval',
    severity: 'critical',
    category: 'Code Injection',
    description: 'Class evaluation - potential code injection',
    pattern: /\.class_eval\s*\(/g,
  },
  {
    name: 'send',
    severity: 'critical',
    category: 'Dynamic Method Call',
    description: 'Dynamic method invocation - potential security bypass',
    pattern: /\.send\s*\(/g,
  },

  // HIGH: File System Operations
  {
    name: 'File.write',
    severity: 'high',
    category: 'File System Write',
    description: 'Writes to files - potential data tampering',
    pattern: /File\.(write|open)\s*\(/g,
  },
  {
    name: 'File.delete',
    severity: 'high',
    category: 'File System Delete',
    description: 'Deletes files - potential data destruction',
    pattern: /File\.(delete|unlink)\s*\(/g,
  },
  {
    name: 'FileUtils',
    severity: 'high',
    category: 'File System Modification',
    description: 'File system operations - potential data tampering',
    pattern: /FileUtils\.(rm|rm_rf|mv|cp)\s*\(/g,
  },
  {
    name: 'File.chmod',
    severity: 'high',
    category: 'File System Permissions',
    description: 'Modifies file permissions - potential privilege escalation',
    pattern: /File\.(chmod|chown)\s*\(/g,
  },
  {
    name: 'Marshal.load',
    severity: 'high',
    category: 'Deserialization',
    description: 'Deserializes objects - potential code execution',
    pattern: /Marshal\.load\s*\(/g,
  },

  // HIGH: Prompt Injection / LLM API Usage
  {
    name: 'OpenAI API',
    severity: 'high',
    category: 'Prompt Injection',
    description: 'OpenAI API usage - potential prompt injection if using untrusted input',
    pattern: /OpenAI::Client|\.chat\(|\.completions\(/g,
  },
  {
    name: 'LangChain Ruby',
    severity: 'high',
    category: 'Prompt Injection',
    description: 'LangChain usage - potential prompt injection if using untrusted input',
    pattern: /Langchain::|\.call\(|\.predict\(/g,
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
    name: 'Net::HTTP',
    severity: 'medium',
    category: 'Network Access',
    description: 'Makes HTTP requests - potential data exfiltration',
    pattern: /Net::HTTP\.(get|post|start)/g,
  },
  {
    name: 'open-uri',
    severity: 'medium',
    category: 'Network Access',
    description: 'Opens URIs - potential data exfiltration',
    pattern: /require\s+['"]open-uri['"]|URI\.open/g,
  },
  {
    name: 'TCPSocket',
    severity: 'medium',
    category: 'Network Access',
    description: 'Creates network sockets - potential data exfiltration',
    pattern: /TCPSocket\.new\s*\(/g,
  },

  // LOW: Environment Access
  {
    name: 'ENV access',
    severity: 'low',
    category: 'Environment Access',
    description: 'Accesses environment variables - potential sensitive data exposure',
    pattern: /ENV\s*\[\s*['"][A-Z_]*(?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|AUTH|PRIVATE)/gi,
  },

  // ===== CREDENTIAL THEFT PATTERNS =====
  
  {
    name: 'Hardcoded Secret',
    severity: 'critical',
    category: 'Credential Theft',
    description: 'Hardcoded API key or password detected',
    pattern: /(?:api_key|api_secret|password|secret_key|auth_token|access_token)\s*=\s*['"][^'"]{8,}['"]/gi,
  },
  {
    name: 'SSH Key Access',
    severity: 'high',
    category: 'Credential Theft',
    description: 'Accesses SSH keys - potential credential theft',
    pattern: /File\.(read|open)\s*\([^)]*(?:\.ssh|id_rsa|id_ed25519)/gi,
  },
  {
    name: 'Rails Credentials',
    severity: 'high',
    category: 'Credential Theft',
    description: 'Rails credentials access',
    pattern: /Rails\.application\.credentials|Rails\.application\.secrets/gi,
  },
  {
    name: 'Config File Access',
    severity: 'medium',
    category: 'Credential Theft',
    description: 'Accesses configuration files',
    pattern: /File\.read\s*\([^)]*(?:\.env|credentials|secrets\.yml|database\.yml)/gi,
  },

  // ===== CODE INJECTION PATTERNS =====
  
  {
    name: 'module_eval',
    severity: 'critical',
    category: 'Code Injection',
    description: 'Module evaluation - potential injection',
    pattern: /\.module_eval\s*\(/g,
  },
  {
    name: 'define_method',
    severity: 'high',
    category: 'Code Injection',
    description: 'Dynamic method definition',
    pattern: /define_method\s*\(/g,
  },
  {
    name: 'ERB Injection',
    severity: 'critical',
    category: 'Code Injection',
    description: 'ERB template injection risk',
    pattern: /ERB\.new\s*\(|\.result\s*\(binding\)/gi,
  },
  {
    name: 'Constantize',
    severity: 'high',
    category: 'Code Injection',
    description: 'String to constant - potential injection',
    pattern: /\.constantize\s*$|\.safe_constantize/gi,
  },

  // ===== PROMPT MANIPULATION PATTERNS =====
  
  {
    name: 'String Interpolation Prompt',
    severity: 'high',
    category: 'Prompt Injection',
    description: 'Variable in prompt string - potential injection',
    pattern: /(?:prompt|message|system_prompt)\s*=\s*"[^"]*#\{/gi,
  },
  {
    name: 'Prompt Concatenation',
    severity: 'medium',
    category: 'Prompt Injection',
    description: 'String concatenation in prompt - validate input',
    pattern: /(?:prompt|message)\s*(?:<<|\+=|<<)|(?:prompt|message)\s*\+\s*\w/gi,
  },

  // ===== DATA EXFILTRATION PATTERNS =====
  
  {
    name: 'DNS Lookup',
    severity: 'high',
    category: 'Data Exfiltration',
    description: 'DNS resolution - potential exfiltration',
    pattern: /Resolv\.getaddress|Socket\.gethostbyname|DNS\.resolve/gi,
  },
  {
    name: 'Clipboard Access',
    severity: 'high',
    category: 'Data Exfiltration',
    description: 'Clipboard access - potential data theft',
    pattern: /Clipboard\.|pbcopy|pbpaste|xclip|xsel/gi,
  },
  {
    name: 'Screenshot',
    severity: 'high',
    category: 'Data Exfiltration',
    description: 'Screen capture - potential data theft',
    pattern: /screenshot|screencapture|import.*png/gi,
  },
  {
    name: 'Email Send',
    severity: 'medium',
    category: 'Data Exfiltration',
    description: 'Email sending - potential exfiltration',
    pattern: /ActionMailer|Mail\.deliver|Net::SMTP/gi,
  },

  // ===== EVASION TECHNIQUE PATTERNS =====
  
  {
    name: 'Base64 Eval',
    severity: 'high',
    category: 'Evasion Technique',
    description: 'Base64 decode with eval - obfuscation',
    pattern: /eval\s*\(\s*Base64\.decode|Base64\.decode.*eval/gi,
  },
  {
    name: 'Pack Unpack',
    severity: 'high',
    category: 'Evasion Technique',
    description: 'Binary packing - potential obfuscation',
    pattern: /\.pack\s*\(['""]H|\.unpack\s*\(['""]H/gi,
  },
  {
    name: 'Load',
    severity: 'high',
    category: 'Evasion Technique',
    description: 'Dynamic code loading',
    pattern: /\bload\s*\(|Kernel\.load/gi,
  },
  {
    name: 'Sandbox Detection',
    severity: 'high',
    category: 'Evasion Technique',
    description: 'VM/sandbox detection patterns',
    pattern: /(?:vmware|virtualbox|vbox|qemu|sandbox)/gi,
  },
  {
    name: 'Anti-Debug',
    severity: 'high',
    category: 'Evasion Technique',
    description: 'Anti-debugging technique detected',
    pattern: /TracePoint|set_trace_func|binding\.pry/gi,
  },
];

export class RubyAnalyzer implements LanguageAnalyzer {
  readonly language: Language = 'ruby';
  readonly fileExtensions = ['.rb'];

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

    for (const pattern of RUBY_PATTERNS) {
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
          language: 'ruby',
        });
      }
    }

    return findings;
  }
}
