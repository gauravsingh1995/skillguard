/**
 * PHP Analyzer
 * Pattern-based security analysis for PHP files
 */

import * as fs from 'fs';
import { Finding, LanguageAnalyzer, Language, RiskSeverity } from '../types';

interface PHPPattern {
  name: string;
  severity: RiskSeverity;
  category: string;
  description: string;
  pattern: RegExp;
}

// Security patterns for PHP
const PHP_PATTERNS: PHPPattern[] = [
  // CRITICAL: Shell Execution & Code Injection
  {
    name: 'exec',
    severity: 'critical',
    category: 'Shell Execution',
    description: 'Executes shell commands - potential arbitrary code execution',
    pattern: /\bexec\s*\(/g,
  },
  {
    name: 'shell_exec',
    severity: 'critical',
    category: 'Shell Execution',
    description: 'Executes shell commands - potential arbitrary code execution',
    pattern: /\bshell_exec\s*\(/g,
  },
  {
    name: 'system',
    severity: 'critical',
    category: 'Shell Execution',
    description: 'Executes shell commands - potential arbitrary code execution',
    pattern: /\bsystem\s*\(/g,
  },
  {
    name: 'passthru',
    severity: 'critical',
    category: 'Shell Execution',
    description: 'Executes shell commands - potential arbitrary code execution',
    pattern: /\bpassthru\s*\(/g,
  },
  {
    name: 'eval',
    severity: 'critical',
    category: 'Code Injection',
    description: 'Evaluates arbitrary PHP code - critical security risk',
    pattern: /\beval\s*\(/g,
  },
  {
    name: 'assert',
    severity: 'critical',
    category: 'Code Injection',
    description: 'Can execute code - potential code injection',
    pattern: /\bassert\s*\(/g,
  },
  {
    name: 'preg_replace /e',
    severity: 'critical',
    category: 'Code Injection',
    description: 'Deprecated /e modifier allows code execution',
    pattern: /preg_replace\s*\([^)]*['"]\/[^'"]*e/g,
  },
  {
    name: 'create_function',
    severity: 'critical',
    category: 'Code Injection',
    description: 'Creates functions dynamically - potential code injection',
    pattern: /\bcreate_function\s*\(/g,
  },

  // HIGH: File System Operations
  {
    name: 'file_put_contents',
    severity: 'high',
    category: 'File System Write',
    description: 'Writes to files - potential data tampering',
    pattern: /\bfile_put_contents\s*\(/g,
  },
  {
    name: 'fwrite',
    severity: 'high',
    category: 'File System Write',
    description: 'Writes to files - potential data tampering',
    pattern: /\bfwrite\s*\(/g,
  },
  {
    name: 'unlink',
    severity: 'high',
    category: 'File System Delete',
    description: 'Deletes files - potential data destruction',
    pattern: /\bunlink\s*\(/g,
  },
  {
    name: 'rmdir',
    severity: 'high',
    category: 'File System Delete',
    description: 'Removes directories - potential data destruction',
    pattern: /\brmdir\s*\(/g,
  },
  {
    name: 'chmod',
    severity: 'high',
    category: 'File System Permissions',
    description: 'Modifies file permissions - potential privilege escalation',
    pattern: /\bchmod\s*\(/g,
  },
  {
    name: 'unserialize',
    severity: 'high',
    category: 'Deserialization',
    description: 'Deserializes data - potential code execution',
    pattern: /\bunserialize\s*\(/g,
  },
  {
    name: 'include/require',
    severity: 'high',
    category: 'File Inclusion',
    description: 'Includes files - potential remote file inclusion',
    pattern: /\b(include|require|include_once|require_once)\s*\(/g,
  },

  // HIGH: Prompt Injection / LLM API Usage
  {
    name: 'OpenAI API',
    severity: 'high',
    category: 'Prompt Injection',
    description: 'OpenAI API usage - potential prompt injection if using untrusted input',
    pattern: /OpenAI\\|createChatCompletion|createCompletion/g,
  },
  {
    name: 'LLM API generic',
    severity: 'high',
    category: 'Prompt Injection',
    description: 'Generic LLM API call - potential prompt injection if using untrusted input',
    pattern: /(generateText|generateContent|sendMessage|promptModel|llmInference)/g,
  },

  // MEDIUM: Network Access & SQL
  {
    name: 'curl_exec',
    severity: 'medium',
    category: 'Network Access',
    description: 'Makes HTTP requests - potential data exfiltration',
    pattern: /\bcurl_exec\s*\(/g,
  },
  {
    name: 'file_get_contents URL',
    severity: 'medium',
    category: 'Network Access',
    description: 'Fetches remote content - potential data exfiltration',
    pattern: /\bfile_get_contents\s*\(\s*['"]https?:/g,
  },
  {
    name: 'fsockopen',
    severity: 'medium',
    category: 'Network Access',
    description: 'Opens network socket - potential data exfiltration',
    pattern: /\bfsockopen\s*\(/g,
  },
  {
    name: 'mysql_query',
    severity: 'medium',
    category: 'SQL Operations',
    description: 'SQL query - review for SQL injection',
    pattern: /\bmysql_query\s*\(/g,
  },
  {
    name: 'mysqli_query',
    severity: 'medium',
    category: 'SQL Operations',
    description: 'SQL query - review for SQL injection',
    pattern: /\bmysqli_query\s*\(/g,
  },

  // LOW: Environment & Globals
  {
    name: '$_SERVER access',
    severity: 'low',
    category: 'Server Variables',
    description: 'Accesses server variables - review for security',
    pattern: /\$_SERVER/g,
  },
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
    pattern: /(?:api_key|api_secret|password|secret_key|auth_token|access_token)\s*=\s*['"][^'"]{8,}['"]/gi,
  },
  {
    name: 'SSH Key Access',
    severity: 'high',
    category: 'Credential Theft',
    description: 'Accesses SSH keys - potential credential theft',
    pattern: /file_get_contents\s*\([^)]*(?:\.ssh|id_rsa|id_ed25519)/gi,
  },
  {
    name: 'Config File Access',
    severity: 'medium',
    category: 'Credential Theft',
    description: 'Accesses configuration files',
    pattern: /(?:file_get_contents|include|require)\s*\([^)]*(?:\.env|config\.php|credentials|secrets)/gi,
  },
  {
    name: 'Database Credentials',
    severity: 'high',
    category: 'Credential Theft',
    description: 'Database credentials in code',
    pattern: /\$(?:db_pass|db_password|mysql_password|pdo_password)\s*=/gi,
  },

  // ===== CODE INJECTION PATTERNS =====
  
  {
    name: 'Twig Injection',
    severity: 'critical',
    category: 'Code Injection',
    description: 'Twig template injection risk',
    pattern: /\$twig->render|Environment\s*\(|createTemplate/gi,
  },
  {
    name: 'Variable Variables',
    severity: 'high',
    category: 'Code Injection',
    description: 'Variable variables - potential injection',
    pattern: /\$\$\w+|\$\{\$/g,
  },
  {
    name: 'extract',
    severity: 'high',
    category: 'Code Injection',
    description: 'Extract function - overwrite variables',
    pattern: /\bextract\s*\(/g,
  },
  {
    name: 'SQL Injection',
    severity: 'critical',
    category: 'Code Injection',
    description: 'Potential SQL injection - use prepared statements',
    pattern: /\$(?:sql|query)\s*=\s*['""][^'"]*\.\s*\$/gi,
  },

  // ===== PROMPT MANIPULATION PATTERNS =====
  
  {
    name: 'String Interpolation Prompt',
    severity: 'high',
    category: 'Prompt Injection',
    description: 'Variable in prompt string - potential injection',
    pattern: /\$(?:prompt|message|system_prompt)\s*=\s*"[^"]*\$/gi,
  },
  {
    name: 'Prompt Concatenation',
    severity: 'medium',
    category: 'Prompt Injection',
    description: 'String concatenation in prompt - validate input',
    pattern: /(?:prompt|message)\s*\.=\s*|\.\s*\$(?:user_input|input)/gi,
  },

  // ===== DATA EXFILTRATION PATTERNS =====
  
  {
    name: 'DNS Lookup',
    severity: 'high',
    category: 'Data Exfiltration',
    description: 'DNS resolution - potential exfiltration',
    pattern: /\bgethostbyname\s*\(|\bdns_get_record\s*\(/gi,
  },
  {
    name: 'Email Send',
    severity: 'medium',
    category: 'Data Exfiltration',
    description: 'Email sending - potential exfiltration',
    pattern: /\bmail\s*\(|PHPMailer|SwiftMailer/gi,
  },
  {
    name: 'FTP Upload',
    severity: 'high',
    category: 'Data Exfiltration',
    description: 'FTP operations - potential exfiltration',
    pattern: /\bftp_(?:put|fput|connect)\s*\(/gi,
  },
  {
    name: 'Copy to Remote',
    severity: 'high',
    category: 'Data Exfiltration',
    description: 'File copy - potential exfiltration',
    pattern: /\bcopy\s*\([^)]*(?:ftp|http|https):/gi,
  },

  // ===== EVASION TECHNIQUE PATTERNS =====
  
  {
    name: 'Base64 Eval',
    severity: 'critical',
    category: 'Evasion Technique',
    description: 'Base64 decode with eval - obfuscation',
    pattern: /eval\s*\(\s*base64_decode|base64_decode.*eval/gi,
  },
  {
    name: 'Gzinflate Eval',
    severity: 'critical',
    category: 'Evasion Technique',
    description: 'Compressed code execution - obfuscation',
    pattern: /eval\s*\(\s*gzinflate|gzinflate.*eval/gi,
  },
  {
    name: 'Hex Escape',
    severity: 'high',
    category: 'Evasion Technique',
    description: 'Hex string obfuscation',
    pattern: /\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}/gi,
  },
  {
    name: 'Chr Obfuscation',
    severity: 'high',
    category: 'Evasion Technique',
    description: 'chr() based string obfuscation',
    pattern: /chr\s*\(\s*\d+\s*\)\s*\.\s*chr\s*\(\s*\d+/gi,
  },
  {
    name: 'Rot13',
    severity: 'high',
    category: 'Evasion Technique',
    description: 'Rot13 encoding - potential obfuscation',
    pattern: /str_rot13\s*\(/gi,
  },
  {
    name: 'Disable Functions',
    severity: 'high',
    category: 'Evasion Technique',
    description: 'Attempts to bypass disabled functions',
    pattern: /ini_set\s*\([^)]*disable_functions|dl\s*\(/gi,
  },
];

export class PHPAnalyzer implements LanguageAnalyzer {
  readonly language: Language = 'php';
  readonly fileExtensions = ['.php', '.phtml'];

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

    for (const pattern of PHP_PATTERNS) {
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
          language: 'php',
        });
      }
    }

    return findings;
  }
}
