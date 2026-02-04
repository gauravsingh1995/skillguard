/**
 * Python Analyzer
 * Pattern-based security analysis for Python files
 */

import * as fs from 'fs';
import { Finding, LanguageAnalyzer, Language, RiskSeverity } from '../types';

interface PythonPattern {
  name: string;
  severity: RiskSeverity;
  category: string;
  description: string;
  pattern: RegExp;
}

// Security patterns for Python
const PYTHON_PATTERNS: PythonPattern[] = [
  // CRITICAL: Shell Execution
  {
    name: 'os.system',
    severity: 'critical',
    category: 'Shell Execution',
    description: 'Executes shell commands - potential arbitrary code execution',
    pattern: /os\.system\s*\(/g,
  },
  {
    name: 'subprocess.call',
    severity: 'critical',
    category: 'Shell Execution',
    description: 'Executes shell commands via subprocess - potential code execution',
    pattern: /subprocess\.(call|run|Popen|check_output|check_call)\s*\(/g,
  },
  {
    name: 'eval',
    severity: 'critical',
    category: 'Code Injection',
    description: 'Evaluates arbitrary code - critical security risk',
    pattern: /\beval\s*\(/g,
  },
  {
    name: 'exec',
    severity: 'critical',
    category: 'Code Injection',
    description: 'Executes arbitrary Python code - critical security risk',
    pattern: /\bexec\s*\(/g,
  },
  {
    name: '__import__',
    severity: 'critical',
    category: 'Dynamic Import',
    description: 'Dynamic module import - potential code injection',
    pattern: /__import__\s*\(/g,
  },
  {
    name: 'compile',
    severity: 'critical',
    category: 'Code Injection',
    description: 'Compiles Python code dynamically - potential code injection',
    pattern: /\bcompile\s*\(/g,
  },

  // HIGH: File System Operations
  {
    name: 'open with write',
    severity: 'high',
    category: 'File System Write',
    description: 'Opens file for writing - potential data tampering',
    pattern: /open\s*\([^)]*['"]w|open\s*\([^)]*['"]a/g,
  },
  {
    name: 'os.remove',
    severity: 'high',
    category: 'File System Delete',
    description: 'Deletes files - potential data destruction',
    pattern: /os\.(remove|unlink|rmdir)\s*\(/g,
  },
  {
    name: 'shutil operations',
    severity: 'high',
    category: 'File System Modification',
    description: 'File system operations - potential data tampering',
    pattern: /shutil\.(rmtree|move|copy|copytree)\s*\(/g,
  },
  {
    name: 'os.chmod',
    severity: 'high',
    category: 'File System Permissions',
    description: 'Modifies file permissions - potential privilege escalation',
    pattern: /os\.(chmod|chown)\s*\(/g,
  },
  {
    name: 'pickle.loads',
    severity: 'high',
    category: 'Deserialization',
    description: 'Deserializes Python objects - potential code execution',
    pattern: /pickle\.(loads|load)\s*\(/g,
  },

  // HIGH: Prompt Injection / LLM API Usage
  {
    name: 'OpenAI API',
    severity: 'high',
    category: 'Prompt Injection',
    description: 'OpenAI API usage - potential prompt injection if using untrusted input',
    pattern: /openai\.(ChatCompletion|Completion)\.create|client\.chat\.completions\.create/g,
  },
  {
    name: 'Anthropic API',
    severity: 'high',
    category: 'Prompt Injection',
    description: 'Anthropic Claude API usage - potential prompt injection if using untrusted input',
    pattern: /anthropic\.(Anthropic|messages)\.create|client\.messages\.create/g,
  },
  {
    name: 'LangChain LLM',
    severity: 'high',
    category: 'Prompt Injection',
    description: 'LangChain LLM usage - potential prompt injection if using untrusted input',
    pattern: /\.(predict|invoke|generate|chat|complete)\s*\(/g,
  },
  {
    name: 'LLM API generic',
    severity: 'high',
    category: 'Prompt Injection',
    description: 'Generic LLM API call - potential prompt injection if using untrusted input',
    pattern: /(generate_text|generate_content|send_message|llm_call|prompt_model)\s*\(/g,
  },

  // MEDIUM: Network Access
  {
    name: 'requests',
    severity: 'medium',
    category: 'Network Access',
    description: 'Makes HTTP requests - potential data exfiltration',
    pattern: /requests\.(get|post|put|delete|patch)\s*\(/g,
  },
  {
    name: 'urllib',
    severity: 'medium',
    category: 'Network Access',
    description: 'URL requests - potential data exfiltration',
    pattern: /urllib\.request\.(urlopen|Request)/g,
  },
  {
    name: 'socket',
    severity: 'medium',
    category: 'Network Access',
    description: 'Network socket operations - potential data exfiltration',
    pattern: /socket\.socket\s*\(/g,
  },
  {
    name: 'httplib',
    severity: 'medium',
    category: 'Network Access',
    description: 'HTTP client - potential data exfiltration',
    pattern: /http\.client\.(HTTPConnection|HTTPSConnection)/g,
  },

  // LOW: Environment Access
  {
    name: 'os.environ',
    severity: 'low',
    category: 'Environment Access',
    description: 'Accesses environment variables - potential sensitive data exposure',
    pattern: /os\.environ\s*\[['"][A-Z_]*(?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|AUTH|PRIVATE)/gi,
  },
  {
    name: 'os.getenv',
    severity: 'low',
    category: 'Environment Access',
    description: 'Gets environment variables - potential sensitive data exposure',
    pattern: /os\.getenv\s*\(\s*['"][A-Z_]*(?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|AUTH|PRIVATE)/gi,
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
    pattern: /open\s*\([^)]*(?:\.ssh|id_rsa|id_ed25519|id_dsa)/gi,
  },
  {
    name: 'Keyring Access',
    severity: 'high',
    category: 'Credential Theft',
    description: 'Accesses system keyring/keychain',
    pattern: /keyring\.get_password|SecretService|gnomekeyring/gi,
  },
  {
    name: 'AWS Credentials',
    severity: 'critical',
    category: 'Credential Theft',
    description: 'Accesses AWS credential files',
    pattern: /open\s*\([^)]*\.aws\/credentials|boto3\.Session\(|aws_access_key_id/gi,
  },
  {
    name: 'Config File Access',
    severity: 'medium',
    category: 'Credential Theft',
    description: 'Accesses configuration files that may contain credentials',
    pattern: /open\s*\([^)]*(?:\.env|\.netrc|\.pgpass|\.my\.cnf)/gi,
  },

  // ===== CODE INJECTION PATTERNS =====
  
  {
    name: 'Template Injection',
    severity: 'critical',
    category: 'Code Injection',
    description: 'Jinja2/template injection risk',
    pattern: /Template\s*\(|render_template_string|jinja2\.Environment/g,
  },
  {
    name: 'YAML Unsafe Load',
    severity: 'critical',
    category: 'Code Injection',
    description: 'YAML unsafe load - arbitrary code execution',
    pattern: /yaml\.(?:load|unsafe_load)\s*\(/g,
  },
  {
    name: 'AST Literal Eval',
    severity: 'high',
    category: 'Code Injection',
    description: 'AST literal eval - potential code injection',
    pattern: /ast\.literal_eval\s*\(/g,
  },
  {
    name: 'importlib',
    severity: 'high',
    category: 'Code Injection',
    description: 'Dynamic module import - potential code injection',
    pattern: /importlib\.import_module\s*\(/g,
  },

  // ===== PROMPT MANIPULATION PATTERNS =====
  
  {
    name: 'F-String Prompt',
    severity: 'high',
    category: 'Prompt Injection',
    description: 'F-string in prompt - potential prompt injection',
    pattern: /(?:prompt|system_message|user_message)\s*=\s*f['"]|f['"][^'"]*(?:prompt|system|instruction)/gi,
  },
  {
    name: 'Prompt Format',
    severity: 'high',
    category: 'Prompt Injection',
    description: 'String formatting in prompt - validate input sanitization',
    pattern: /(?:prompt|message)\.format\s*\(/gi,
  },
  {
    name: 'Prompt Concatenation',
    severity: 'medium',
    category: 'Prompt Injection',
    description: 'String concatenation in prompt - potential injection',
    pattern: /(?:prompt|system_prompt|user_input)\s*\+\s*|\+\s*(?:prompt|user_input)/gi,
  },

  // ===== DATA EXFILTRATION PATTERNS =====
  
  {
    name: 'DNS Exfiltration',
    severity: 'high',
    category: 'Data Exfiltration',
    description: 'DNS resolution - potential DNS exfiltration',
    pattern: /socket\.gethostbyname|dns\.resolver|dns\.query/gi,
  },
  {
    name: 'Clipboard Access',
    severity: 'high',
    category: 'Data Exfiltration',
    description: 'Clipboard access - potential data theft',
    pattern: /pyperclip\.|clipboard\.|Gtk\.Clipboard|win32clipboard/gi,
  },
  {
    name: 'Screenshot Capture',
    severity: 'high',
    category: 'Data Exfiltration',
    description: 'Screen capture - potential visual data theft',
    pattern: /ImageGrab\.grab|pyautogui\.screenshot|mss\(\)|pyscreenshot/gi,
  },
  {
    name: 'Keylogger Pattern',
    severity: 'critical',
    category: 'Data Exfiltration',
    description: 'Keyboard monitoring - potential keylogger',
    pattern: /pynput\.keyboard|keyboard\.on_press|keyboard\.hook/gi,
  },
  {
    name: 'Webcam Access',
    severity: 'high',
    category: 'Data Exfiltration',
    description: 'Webcam capture - potential privacy breach',
    pattern: /cv2\.VideoCapture|pygame\.camera/gi,
  },
  {
    name: 'Email Data',
    severity: 'medium',
    category: 'Data Exfiltration',
    description: 'Email sending - potential data exfiltration',
    pattern: /smtplib\.SMTP|email\.mime|sendmail/gi,
  },

  // ===== EVASION TECHNIQUE PATTERNS =====
  
  {
    name: 'Base64 Execution',
    severity: 'high',
    category: 'Evasion Technique',
    description: 'Base64 decode with exec - obfuscation technique',
    pattern: /exec\s*\(\s*.*base64\.b64decode|base64\.b64decode.*exec/gi,
  },
  {
    name: 'Code Obfuscation',
    severity: 'high',
    category: 'Evasion Technique',
    description: 'Code obfuscation patterns detected',
    pattern: /getattr\s*\([^,]+,\s*['"][^'"]+['"]\s*\)|__builtins__\[|globals\(\)\[/gi,
  },
  {
    name: 'Anti-Debug',
    severity: 'high',
    category: 'Evasion Technique',
    description: 'Anti-debugging technique detected',
    pattern: /sys\.settrace\s*\(|ctypes.*ptrace|IsDebuggerPresent/gi,
  },
  {
    name: 'Sandbox Detection',
    severity: 'high',
    category: 'Evasion Technique',
    description: 'Virtual machine/sandbox detection',
    pattern: /(?:vmware|virtualbox|vbox|qemu|sandbox|analysis)/gi,
  },
  {
    name: 'Time Delay',
    severity: 'medium',
    category: 'Evasion Technique',
    description: 'Long time delay - potential sandbox evasion',
    pattern: /time\.sleep\s*\(\s*(?:[3-9]\d|[1-9]\d{2,})\s*\)/g,
  },
  {
    name: 'Process Hiding',
    severity: 'high',
    category: 'Evasion Technique',
    description: 'Process manipulation - potential evasion',
    pattern: /ctypes\.windll|win32api|CreateRemoteThread|VirtualAllocEx/gi,
  },
];

export class PythonAnalyzer implements LanguageAnalyzer {
  readonly language: Language = 'python';
  readonly fileExtensions = ['.py', '.pyw'];

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

    for (const pattern of PYTHON_PATTERNS) {
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
          language: 'python',
        });
      }
    }

    return findings;
  }
}
