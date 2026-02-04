/**
 * Java Analyzer
 * Pattern-based security analysis for Java files
 */

import * as fs from 'fs';
import { Finding, LanguageAnalyzer, Language, RiskSeverity } from '../types';

interface JavaPattern {
  name: string;
  severity: RiskSeverity;
  category: string;
  description: string;
  pattern: RegExp;
}

// Security patterns for Java
const JAVA_PATTERNS: JavaPattern[] = [
  // CRITICAL: Shell Execution
  {
    name: 'Runtime.exec',
    severity: 'critical',
    category: 'Shell Execution',
    description: 'Executes shell commands - potential arbitrary code execution',
    pattern: /Runtime\.getRuntime\(\)\.exec\s*\(/g,
  },
  {
    name: 'ProcessBuilder',
    severity: 'critical',
    category: 'Shell Execution',
    description: 'Creates processes - potential arbitrary code execution',
    pattern: /new\s+ProcessBuilder\s*\(/g,
  },
  {
    name: 'Script evaluation',
    severity: 'critical',
    category: 'Code Injection',
    description: 'Evaluates scripts dynamically - potential code injection',
    pattern: /ScriptEngine.*\.eval\s*\(/g,
  },
  {
    name: 'Reflection',
    severity: 'critical',
    category: 'Reflection',
    description: 'Uses reflection - potential security bypass',
    pattern: /Class\.forName\s*\(|Method\.invoke\s*\(/g,
  },

  // HIGH: File System Operations
  {
    name: 'File write',
    severity: 'high',
    category: 'File System Write',
    description: 'Writes to files - potential data tampering',
    pattern: /new\s+FileWriter\s*\(|new\s+FileOutputStream\s*\(|Files\.write\s*\(/g,
  },
  {
    name: 'File delete',
    severity: 'high',
    category: 'File System Delete',
    description: 'Deletes files - potential data destruction',
    pattern: /\.delete\s*\(\)|Files\.delete\s*\(/g,
  },
  {
    name: 'Deserialization',
    severity: 'high',
    category: 'Deserialization',
    description: 'Deserializes objects - potential code execution',
    pattern: /ObjectInputStream|readObject\s*\(/g,
  },
  {
    name: 'JNDI lookup',
    severity: 'high',
    category: 'JNDI Injection',
    description: 'JNDI lookup - potential remote code execution (Log4Shell)',
    pattern: /InitialContext.*\.lookup\s*\(/g,
  },

  // HIGH: Prompt Injection / LLM API Usage
  {
    name: 'OpenAI API',
    severity: 'high',
    category: 'Prompt Injection',
    description: 'OpenAI API usage - potential prompt injection if using untrusted input',
    pattern: /OpenAiService|createChatCompletion|createCompletion/g,
  },
  {
    name: 'LangChain4j',
    severity: 'high',
    category: 'Prompt Injection',
    description: 'LangChain4j usage - potential prompt injection if using untrusted input',
    pattern: /ChatLanguageModel|StreamingChatLanguageModel|\.chat\s*\(/g,
  },
  {
    name: 'LLM API generic',
    severity: 'high',
    category: 'Prompt Injection',
    description: 'Generic LLM API call - potential prompt injection if using untrusted input',
    pattern: /(generateText|generateContent|sendMessage|promptModel|llmInference)\s*\(/g,
  },

  // MEDIUM: Network Access
  {
    name: 'URL connection',
    severity: 'medium',
    category: 'Network Access',
    description: 'Opens network connections - potential data exfiltration',
    pattern: /new\s+URL\s*\(.*\.openConnection\s*\(/g,
  },
  {
    name: 'HTTP client',
    severity: 'medium',
    category: 'Network Access',
    description: 'HTTP client operations - potential data exfiltration',
    pattern: /HttpClient|HttpURLConnection/g,
  },
  {
    name: 'Socket',
    severity: 'medium',
    category: 'Network Access',
    description: 'Creates network sockets - potential data exfiltration',
    pattern: /new\s+Socket\s*\(|new\s+ServerSocket\s*\(/g,
  },

  // LOW: SQL Injection Risk
  {
    name: 'SQL Statement',
    severity: 'low',
    category: 'SQL Operations',
    description: 'SQL statement execution - review for SQL injection',
    pattern: /Statement.*\.execute(Query|Update)\s*\(/g,
  },
  {
    name: 'System properties',
    severity: 'low',
    category: 'Environment Access',
    description: 'Accesses system properties - potential sensitive data exposure',
    pattern: /System\.getProperty\s*\(/g,
  },

  // ===== CREDENTIAL THEFT PATTERNS =====
  
  {
    name: 'Hardcoded Secret',
    severity: 'critical',
    category: 'Credential Theft',
    description: 'Hardcoded API key or password detected',
    pattern: /(?:apiKey|apiSecret|password|secretKey|authToken|accessToken)\s*=\s*"[^"]{8,}"/gi,
  },
  {
    name: 'SSH Key Access',
    severity: 'high',
    category: 'Credential Theft',
    description: 'Accesses SSH keys - potential credential theft',
    pattern: /new\s+FileInputStream\s*\([^)]*(?:\.ssh|id_rsa|id_ed25519)/gi,
  },
  {
    name: 'Keystore Access',
    severity: 'high',
    category: 'Credential Theft',
    description: 'Java keystore access - credential store',
    pattern: /KeyStore\.getInstance|load\s*\([^)]*\.jks|\.keystore/gi,
  },
  {
    name: 'AWS Credentials',
    severity: 'critical',
    category: 'Credential Theft',
    description: 'Accesses AWS credentials',
    pattern: /BasicAWSCredentials|AWSStaticCredentialsProvider|aws\.auth/gi,
  },
  {
    name: 'Config File Access',
    severity: 'medium',
    category: 'Credential Theft',
    description: 'Accesses configuration files',
    pattern: /new\s+FileInputStream\s*\([^)]*(?:application\.properties|secrets|credentials)/gi,
  },

  // ===== CODE INJECTION PATTERNS =====
  
  {
    name: 'SpEL Injection',
    severity: 'critical',
    category: 'Code Injection',
    description: 'Spring Expression Language - potential injection',
    pattern: /SpelExpressionParser|ExpressionParser|parseExpression/g,
  },
  {
    name: 'Groovy Eval',
    severity: 'critical',
    category: 'Code Injection',
    description: 'Groovy script execution',
    pattern: /GroovyShell|evaluate\s*\(|Binding\(\)/g,
  },
  {
    name: 'OGNL Injection',
    severity: 'critical',
    category: 'Code Injection',
    description: 'OGNL expression injection',
    pattern: /OgnlContext|Ognl\.(getValue|setValue)/g,
  },
  {
    name: 'LDAP Injection',
    severity: 'high',
    category: 'Code Injection',
    description: 'LDAP query - potential injection',
    pattern: /InitialDirContext|search\s*\(.*filter/gi,
  },

  // ===== PROMPT MANIPULATION PATTERNS =====
  
  {
    name: 'String Format Prompt',
    severity: 'high',
    category: 'Prompt Injection',
    description: 'String format in prompt - potential injection',
    pattern: /String\.format\s*\([^)]*(?:prompt|message|instruction)/gi,
  },
  {
    name: 'Prompt Builder',
    severity: 'medium',
    category: 'Prompt Injection',
    description: 'String building for prompt - validate input',
    pattern: /StringBuilder.*(?:prompt|message)|(?:prompt|message).*append/gi,
  },

  // ===== DATA EXFILTRATION PATTERNS =====
  
  {
    name: 'DNS Lookup',
    severity: 'high',
    category: 'Data Exfiltration',
    description: 'DNS resolution - potential exfiltration',
    pattern: /InetAddress\.getByName|InetAddress\.getAllByName/gi,
  },
  {
    name: 'Clipboard Access',
    severity: 'high',
    category: 'Data Exfiltration',
    description: 'Clipboard access - potential data theft',
    pattern: /Toolkit\.getDefaultToolkit\(\)\.getSystemClipboard|Clipboard/gi,
  },
  {
    name: 'Screenshot Capture',
    severity: 'high',
    category: 'Data Exfiltration',
    description: 'Screen capture - potential data theft',
    pattern: /Robot\(\)\.createScreenCapture|BufferedImage.*screen/gi,
  },
  {
    name: 'Keylogger Pattern',
    severity: 'critical',
    category: 'Data Exfiltration',
    description: 'Key event monitoring - potential keylogger',
    pattern: /KeyListener|keyPressed|keyReleased|NativeKeyListener/gi,
  },
  {
    name: 'Email Send',
    severity: 'medium',
    category: 'Data Exfiltration',
    description: 'Email sending - potential exfiltration',
    pattern: /javax\.mail|Transport\.send|MimeMessage/gi,
  },

  // ===== EVASION TECHNIQUE PATTERNS =====
  
  {
    name: 'Base64 Decode',
    severity: 'high',
    category: 'Evasion Technique',
    description: 'Base64 decoding - potential obfuscation',
    pattern: /Base64\.getDecoder|Base64\.decode|DatatypeConverter\.parseBase64/gi,
  },
  {
    name: 'Anti-Debug',
    severity: 'high',
    category: 'Evasion Technique',
    description: 'Anti-debugging technique detected',
    pattern: /ManagementFactory\.getRuntimeMXBean|isDebuggerAttached/gi,
  },
  {
    name: 'Class Loading',
    severity: 'high',
    category: 'Evasion Technique',
    description: 'Dynamic class loading - potential evasion',
    pattern: /defineClass|URLClassLoader|ClassLoader\.loadClass/gi,
  },
  {
    name: 'Sandbox Detection',
    severity: 'high',
    category: 'Evasion Technique',
    description: 'VM/sandbox detection patterns',
    pattern: /(?:vmware|virtualbox|vbox|qemu|sandbox)/gi,
  },
  {
    name: 'JNI Native',
    severity: 'high',
    category: 'Evasion Technique',
    description: 'JNI native code - bypass Java security',
    pattern: /System\.loadLibrary|System\.load\s*\(|native\s+\w+\s*\(/gi,
  },
];

export class JavaAnalyzer implements LanguageAnalyzer {
  readonly language: Language = 'java';
  readonly fileExtensions = ['.java'];

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

    for (const pattern of JAVA_PATTERNS) {
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
          language: 'java',
        });
      }
    }

    return findings;
  }
}
