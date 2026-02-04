/**
 * JavaScript/TypeScript Analyzer
 * AST-based security analysis for JavaScript and TypeScript files
 */

import * as fs from 'fs';
import * as acorn from 'acorn';
import * as walk from 'acorn-walk';
import { Finding, RiskPattern, LanguageAnalyzer, Language } from '../types';
import { getConfigLoader } from '../config';

// Risk patterns for JavaScript/TypeScript
const JS_RISK_PATTERNS: RiskPattern[] = [
  // CRITICAL: Shell Execution
  {
    name: 'exec',
    severity: 'critical',
    category: 'Shell Execution',
    description: 'Executes shell commands - potential arbitrary code execution',
    nodeType: 'CallExpression',
    matcher: (node: any) => {
      return isCallToFunction(node, ['exec', 'execSync']);
    },
  },
  {
    name: 'spawn',
    severity: 'critical',
    category: 'Shell Execution',
    description: 'Spawns child processes - potential arbitrary code execution',
    nodeType: 'CallExpression',
    matcher: (node: any) => {
      return isCallToFunction(node, ['spawn', 'spawnSync']);
    },
  },
  {
    name: 'eval',
    severity: 'critical',
    category: 'Code Injection',
    description: 'Evaluates arbitrary code - critical security risk',
    nodeType: 'CallExpression',
    matcher: (node: any) => {
      return node.callee?.type === 'Identifier' && node.callee.name === 'eval';
    },
  },
  {
    name: 'Function constructor',
    severity: 'critical',
    category: 'Code Injection',
    description: 'Dynamic function creation - potential code injection',
    nodeType: 'NewExpression',
    matcher: (node: any) => {
      return node.callee?.type === 'Identifier' && node.callee.name === 'Function';
    },
  },

  // HIGH: File System Write/Delete
  {
    name: 'fs.writeFile',
    severity: 'high',
    category: 'File System Write',
    description: 'Writes files to disk - potential data tampering',
    nodeType: 'CallExpression',
    matcher: (node: any) => {
      return isCallToMemberFunction(node, 'fs', [
        'writeFile',
        'writeFileSync',
        'appendFile',
        'appendFileSync',
      ]);
    },
  },
  {
    name: 'fs.unlink',
    severity: 'high',
    category: 'File System Delete',
    description: 'Deletes files from disk - potential data destruction',
    nodeType: 'CallExpression',
    matcher: (node: any) => {
      return isCallToMemberFunction(node, 'fs', [
        'unlink',
        'unlinkSync',
        'rm',
        'rmSync',
        'rmdir',
        'rmdirSync',
      ]);
    },
  },
  {
    name: 'fs.chmod',
    severity: 'high',
    category: 'File System Permissions',
    description: 'Modifies file permissions - potential privilege escalation',
    nodeType: 'CallExpression',
    matcher: (node: any) => {
      return isCallToMemberFunction(node, 'fs', ['chmod', 'chmodSync', 'chown', 'chownSync']);
    },
  },
  {
    name: 'Deno.remove',
    severity: 'high',
    category: 'File System Delete',
    description: 'Deno file deletion - potential data destruction',
    nodeType: 'CallExpression',
    matcher: (node: any) => {
      return isCallToMemberFunction(node, 'Deno', ['remove', 'removeSync']);
    },
  },
  {
    name: 'Deno.writeFile',
    severity: 'high',
    category: 'File System Write',
    description: 'Deno file write - potential data tampering',
    nodeType: 'CallExpression',
    matcher: (node: any) => {
      return isCallToMemberFunction(node, 'Deno', [
        'writeFile',
        'writeTextFile',
        'writeTextFileSync',
      ]);
    },
  },

  // MEDIUM: Network Access
  {
    name: 'fetch',
    severity: 'medium',
    category: 'Network Access',
    description: 'Makes network requests - potential data exfiltration',
    nodeType: 'CallExpression',
    matcher: (node: any) => {
      return node.callee?.type === 'Identifier' && node.callee.name === 'fetch';
    },
  },
  {
    name: 'axios',
    severity: 'medium',
    category: 'Network Access',
    description: 'Axios HTTP client - potential data exfiltration',
    nodeType: 'CallExpression',
    matcher: (node: any) => {
      if (node.callee?.type === 'Identifier' && node.callee.name === 'axios') return true;
      if (node.callee?.type === 'MemberExpression') {
        const obj = node.callee.object;
        if (obj?.type === 'Identifier' && obj.name === 'axios') return true;
      }
      return false;
    },
  },
  {
    name: 'http.request',
    severity: 'medium',
    category: 'Network Access',
    description: 'HTTP request - potential data exfiltration',
    nodeType: 'CallExpression',
    matcher: (node: any) => {
      return (
        isCallToMemberFunction(node, 'http', ['request', 'get']) ||
        isCallToMemberFunction(node, 'https', ['request', 'get'])
      );
    },
  },
  {
    name: 'XMLHttpRequest',
    severity: 'medium',
    category: 'Network Access',
    description: 'XMLHttpRequest - potential data exfiltration',
    nodeType: 'NewExpression',
    matcher: (node: any) => {
      return node.callee?.type === 'Identifier' && node.callee.name === 'XMLHttpRequest';
    },
  },
  {
    name: 'WebSocket',
    severity: 'medium',
    category: 'Network Access',
    description: 'WebSocket connection - potential data exfiltration',
    nodeType: 'NewExpression',
    matcher: (node: any) => {
      return node.callee?.type === 'Identifier' && node.callee.name === 'WebSocket';
    },
  },

  // HIGH: Prompt Injection / LLM API Usage
  {
    name: 'OpenAI API',
    severity: 'high',
    category: 'Prompt Injection',
    description: 'OpenAI API usage - potential prompt injection if using untrusted input',
    nodeType: 'CallExpression',
    matcher: (node: any) => {
      // Detect openai.chat.completions.create, openai.completions.create
      if (node.callee?.type === 'MemberExpression') {
        const prop = node.callee.property;
        if (prop?.type === 'Identifier' && prop.name === 'create') {
          let obj = node.callee.object;
          // Check for chat.completions or completions
          if (obj?.type === 'MemberExpression') {
            const parentProp = obj.property;
            if (
              parentProp?.type === 'Identifier' &&
              (parentProp.name === 'completions' || parentProp.name === 'chat')
            ) {
              return true;
            }
          }
        }
      }
      return false;
    },
  },
  {
    name: 'Anthropic API',
    severity: 'high',
    category: 'Prompt Injection',
    description: 'Anthropic Claude API usage - potential prompt injection if using untrusted input',
    nodeType: 'CallExpression',
    matcher: (node: any) => {
      // Detect anthropic.messages.create
      if (node.callee?.type === 'MemberExpression') {
        const prop = node.callee.property;
        if (prop?.type === 'Identifier' && prop.name === 'create') {
          let obj = node.callee.object;
          if (obj?.type === 'MemberExpression') {
            const parentProp = obj.property;
            if (parentProp?.type === 'Identifier' && parentProp.name === 'messages') {
              return true;
            }
          }
        }
      }
      return false;
    },
  },
  {
    name: 'Google AI API',
    severity: 'high',
    category: 'Prompt Injection',
    description: 'Google AI API usage - potential prompt injection if using untrusted input',
    nodeType: 'CallExpression',
    matcher: (node: any) => {
      // Detect genAI.generateContent, model.generateContent
      return isCallToFunction(node, ['generateContent', 'generateText']);
    },
  },
  {
    name: 'LLM API generic',
    severity: 'high',
    category: 'Prompt Injection',
    description: 'Generic LLM API call - potential prompt injection if using untrusted input',
    nodeType: 'CallExpression',
    matcher: (node: any) => {
      // Detect common LLM method names
      return isCallToFunction(node, [
        'sendMessage',
        'chat',
        'complete',
        'prompt',
        'generate',
        'inference',
      ]);
    },
  },

  // LOW: Environment Variable Access
  {
    name: 'process.env',
    severity: 'low',
    category: 'Environment Access',
    description: 'Accesses environment variables - potential sensitive data exposure',
    nodeType: 'MemberExpression',
    matcher: (node: any) => {
      if (node.object?.type === 'MemberExpression') {
        const inner = node.object;
        if (
          inner.object?.type === 'Identifier' &&
          inner.object.name === 'process' &&
          inner.property?.type === 'Identifier' &&
          inner.property.name === 'env'
        ) {
          // Check for sensitive env var names
          const propName =
            node.property?.type === 'Identifier'
              ? node.property.name
              : node.property?.type === 'Literal'
                ? String(node.property.value)
                : '';
          const sensitivePatterns = [
            'KEY',
            'SECRET',
            'TOKEN',
            'PASSWORD',
            'CREDENTIAL',
            'AUTH',
            'PRIVATE',
          ];
          return sensitivePatterns.some((p) => propName.toUpperCase().includes(p));
        }
      }
      return false;
    },
  },

  // ===== CREDENTIAL THEFT PATTERNS =====
  
  // CRITICAL: Hardcoded credentials in code
  {
    name: 'Hardcoded Secret',
    severity: 'critical',
    category: 'Credential Theft',
    description: 'Hardcoded API key or secret detected - credential theft risk',
    nodeType: 'VariableDeclarator',
    matcher: (node: any) => {
      if (node.init?.type === 'Literal' && typeof node.init.value === 'string') {
        const val = node.init.value;
        const name = node.id?.name?.toUpperCase() || '';
        const sensitiveNames = ['KEY', 'SECRET', 'TOKEN', 'PASSWORD', 'API', 'AUTH', 'CREDENTIAL'];
        const hasSecretName = sensitiveNames.some(s => name.includes(s));
        const looksLikeKey = /^[a-zA-Z0-9_-]{20,}$/.test(val) || /^sk-[a-zA-Z0-9]{20,}$/.test(val);
        return hasSecretName && (val.length > 8 || looksLikeKey);
      }
      return false;
    },
  },
  {
    name: 'SSH Key Access',
    severity: 'high',
    category: 'Credential Theft',
    description: 'Accesses SSH keys - potential credential theft',
    nodeType: 'CallExpression',
    matcher: (node: any) => {
      if (isCallToMemberFunction(node, 'fs', ['readFile', 'readFileSync'])) {
        const arg = node.arguments?.[0];
        if (arg?.type === 'Literal' && typeof arg.value === 'string') {
          const path = arg.value.toLowerCase();
          return path.includes('.ssh') || path.includes('id_rsa') || path.includes('id_ed25519') || path.includes('id_dsa');
        }
        if (arg?.type === 'TemplateLiteral') {
          const str = arg.quasis?.map((q: any) => q.value.raw).join('') || '';
          return str.includes('.ssh') || str.includes('id_rsa');
        }
      }
      return false;
    },
  },
  {
    name: 'Keychain Access',
    severity: 'high',
    category: 'Credential Theft',
    description: 'Accesses system keychain or credential store',
    nodeType: 'CallExpression',
    matcher: (node: any) => {
      return isCallToFunction(node, ['getPassword', 'findCredentials', 'findPassword', 'getGenericPassword', 'getInternetPassword']);
    },
  },
  {
    name: 'Config File Access',
    severity: 'medium',
    category: 'Credential Theft',
    description: 'Accesses configuration files that may contain credentials',
    nodeType: 'CallExpression',
    matcher: (node: any) => {
      if (isCallToMemberFunction(node, 'fs', ['readFile', 'readFileSync'])) {
        const arg = node.arguments?.[0];
        if (arg?.type === 'Literal' && typeof arg.value === 'string') {
          const path = arg.value.toLowerCase();
          return path.includes('.env') || path.includes('credentials') || path.includes('.npmrc') || path.includes('.netrc') || path.includes('.aws');
        }
      }
      return false;
    },
  },

  // ===== CODE INJECTION PATTERNS =====
  
  {
    name: 'Template Injection',
    severity: 'critical',
    category: 'Code Injection',
    description: 'Server-side template injection (SSTI) risk',
    nodeType: 'CallExpression',
    matcher: (node: any) => {
      return isCallToFunction(node, ['compile', 'render', 'renderString', 'renderFile']);
    },
  },
  {
    name: 'vm Module',
    severity: 'critical',
    category: 'Code Injection',
    description: 'Node.js VM module - can execute arbitrary code',
    nodeType: 'CallExpression',
    matcher: (node: any) => {
      return isCallToMemberFunction(node, 'vm', ['runInContext', 'runInNewContext', 'runInThisContext', 'createScript', 'compileFunction']);
    },
  },
  {
    name: 'setTimeout/setInterval with string',
    severity: 'high',
    category: 'Code Injection',
    description: 'Timer with string argument - implicit eval',
    nodeType: 'CallExpression',
    matcher: (node: any) => {
      if (node.callee?.type === 'Identifier' && ['setTimeout', 'setInterval'].includes(node.callee.name)) {
        const arg = node.arguments?.[0];
        return arg?.type === 'Literal' && typeof arg.value === 'string';
      }
      return false;
    },
  },
  {
    name: 'import() dynamic',
    severity: 'high',
    category: 'Code Injection',
    description: 'Dynamic import - potential code injection if input is untrusted',
    nodeType: 'CallExpression',
    matcher: (node: any) => {
      return node.callee?.type === 'Import';
    },
  },

  // ===== PROMPT MANIPULATION PATTERNS =====
  
  {
    name: 'System Prompt Construction',
    severity: 'high',
    category: 'Prompt Injection',
    description: 'Dynamic system prompt construction - potential prompt injection',
    nodeType: 'CallExpression',
    matcher: (node: any) => {
      if (node.arguments?.length > 0) {
        const hasRole = node.arguments.some((arg: any) => {
          if (arg?.type === 'ObjectExpression') {
            return arg.properties?.some((p: any) => {
              const key = p.key?.name || p.key?.value;
              return key === 'role' || key === 'system' || key === 'systemPrompt';
            });
          }
          return false;
        });
        if (hasRole) return true;
      }
      return false;
    },
  },
  {
    name: 'Prompt Template Variable',
    severity: 'medium',
    category: 'Prompt Injection',
    description: 'User input in prompt template - validate input sanitization',
    nodeType: 'TemplateLiteral',
    matcher: (node: any) => {
      const raw = node.quasis?.map((q: any) => q.value.raw).join('') || '';
      return raw.includes('prompt') || raw.includes('instruction') || raw.includes('system');
    },
  },

  // ===== DATA EXFILTRATION PATTERNS =====
  
  {
    name: 'DNS Lookup',
    severity: 'high',
    category: 'Data Exfiltration',
    description: 'DNS lookup - potential DNS exfiltration',
    nodeType: 'CallExpression',
    matcher: (node: any) => {
      return isCallToMemberFunction(node, 'dns', ['lookup', 'resolve', 'resolve4', 'resolve6', 'resolveTxt']);
    },
  },
  {
    name: 'Clipboard Access',
    severity: 'high',
    category: 'Data Exfiltration',
    description: 'Clipboard access - potential data theft',
    nodeType: 'CallExpression',
    matcher: (node: any) => {
      return isCallToMemberFunction(node, 'clipboard', ['readText', 'writeText', 'read', 'write']) ||
             isCallToFunction(node, ['readClipboard', 'writeClipboard', 'getClipboard', 'setClipboard']);
    },
  },
  {
    name: 'Screenshot Capture',
    severity: 'high',
    category: 'Data Exfiltration',
    description: 'Screen capture - potential visual data theft',
    nodeType: 'CallExpression',
    matcher: (node: any) => {
      return isCallToFunction(node, ['screenshot', 'captureScreen', 'takeScreenshot', 'getDisplayMedia', 'desktopCapturer']);
    },
  },
  {
    name: 'Keylogger Pattern',
    severity: 'critical',
    category: 'Data Exfiltration',
    description: 'Keyboard event capture - potential keylogger',
    nodeType: 'CallExpression',
    matcher: (node: any) => {
      if (node.callee?.type === 'MemberExpression') {
        const method = node.callee.property?.name;
        if (method === 'addEventListener') {
          const arg = node.arguments?.[0];
          if (arg?.type === 'Literal') {
            const event = String(arg.value).toLowerCase();
            return event === 'keydown' || event === 'keyup' || event === 'keypress';
          }
        }
      }
      return false;
    },
  },
  {
    name: 'FormData Upload',
    severity: 'medium',
    category: 'Data Exfiltration',
    description: 'FormData creation - potential file/data upload',
    nodeType: 'NewExpression',
    matcher: (node: any) => {
      return node.callee?.type === 'Identifier' && node.callee.name === 'FormData';
    },
  },

  // ===== EVASION TECHNIQUE PATTERNS =====
  
  {
    name: 'Base64 Decode Execution',
    severity: 'high',
    category: 'Evasion Technique',
    description: 'Base64 decoding with execution - obfuscation technique',
    nodeType: 'CallExpression',
    matcher: (node: any) => {
      return isCallToFunction(node, ['atob', 'btoa']) ||
             isCallToMemberFunction(node, 'Buffer', ['from']);
    },
  },
  {
    name: 'Time-Delayed Execution',
    severity: 'medium',
    category: 'Evasion Technique',
    description: 'Delayed execution - potential sandbox evasion',
    nodeType: 'CallExpression',
    matcher: (node: any) => {
      if (node.callee?.type === 'Identifier' && ['setTimeout', 'setInterval'].includes(node.callee.name)) {
        const delay = node.arguments?.[1];
        if (delay?.type === 'Literal' && typeof delay.value === 'number') {
          return delay.value > 30000;
        }
      }
      return false;
    },
  },
  {
    name: 'Debugger Detection',
    severity: 'high',
    category: 'Evasion Technique',
    description: 'Anti-debugging technique detected',
    nodeType: 'DebuggerStatement',
    matcher: () => true,
  },
  {
    name: 'Process Detection',
    severity: 'medium',
    category: 'Evasion Technique',
    description: 'Process enumeration - potential sandbox detection',
    nodeType: 'CallExpression',
    matcher: (node: any) => {
      return isCallToFunction(node, ['getProcesses', 'findProcess', 'psList']);
    },
  },
  {
    name: 'String Obfuscation',
    severity: 'medium',
    category: 'Evasion Technique',
    description: 'String encoding/obfuscation - review for malicious intent',
    nodeType: 'CallExpression',
    matcher: (node: any) => {
      return isCallToFunction(node, ['charCodeAt', 'fromCharCode', 'encodeURIComponent', 'decodeURIComponent']);
    },
  },
  {
    name: 'Prototype Pollution',
    severity: 'critical',
    category: 'Evasion Technique',
    description: 'Potential prototype pollution - security bypass risk',
    nodeType: 'MemberExpression',
    matcher: (node: any) => {
      const prop = node.property?.name || node.property?.value;
      return prop === '__proto__' || prop === 'prototype' || prop === 'constructor';
    },
  },
];

/**
 * Helper: Check if node is a call to specific function names
 */
function isCallToFunction(node: any, functionNames: string[]): boolean {
  if (node.callee?.type === 'Identifier') {
    return functionNames.includes(node.callee.name);
  }
  if (node.callee?.type === 'MemberExpression') {
    const prop = node.callee.property;
    if (prop?.type === 'Identifier') {
      return functionNames.includes(prop.name);
    }
  }
  return false;
}

/**
 * Helper: Check if node is a call to object.method()
 */
function isCallToMemberFunction(node: any, objectName: string, methodNames: string[]): boolean {
  if (node.callee?.type === 'MemberExpression') {
    const obj = node.callee.object;
    const prop = node.callee.property;

    // Direct: fs.writeFile()
    if (obj?.type === 'Identifier' && obj.name === objectName) {
      if (prop?.type === 'Identifier' && methodNames.includes(prop.name)) {
        return true;
      }
    }

    // Promises: fs.promises.writeFile()
    if (obj?.type === 'MemberExpression') {
      const innerObj = obj.object;
      if (innerObj?.type === 'Identifier' && innerObj.name === objectName) {
        if (prop?.type === 'Identifier' && methodNames.includes(prop.name)) {
          return true;
        }
      }
    }
  }
  return false;
}

/**
 * Get source code lines from file content
 */
function getCodeSnippet(source: string, line: number): string {
  const lines = source.split('\n');
  const lineIndex = line - 1;
  if (lineIndex >= 0 && lineIndex < lines.length) {
    return lines[lineIndex].trim();
  }
  return '';
}

/**
 * Parse source code into AST
 */
function parseCode(source: string): acorn.Node | null {
  try {
    // Try parsing as module first, then as script
    return acorn.parse(source, {
      ecmaVersion: 'latest',
      sourceType: 'module',
      locations: true,
      allowHashBang: true,
      allowAwaitOutsideFunction: true,
      allowImportExportEverywhere: true,
      allowReserved: true,
    });
  } catch (_e) {
    try {
      return acorn.parse(source, {
        ecmaVersion: 'latest',
        sourceType: 'script',
        locations: true,
        allowHashBang: true,
        allowReserved: true,
      });
    } catch (_e2) {
      // Could not parse file - might be TypeScript with types
      return null;
    }
  }
}

export class JavaScriptAnalyzer implements LanguageAnalyzer {
  readonly language: Language = 'javascript';
  readonly fileExtensions = ['.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx'];

  canAnalyze(filePath: string): boolean {
    return this.fileExtensions.some((ext) => filePath.endsWith(ext)) && !filePath.endsWith('.d.ts');
  }

  analyzeFile(filePath: string): Finding[] {
    const findings: Finding[] = [];

    let source: string;
    try {
      source = fs.readFileSync(filePath, 'utf-8');
    } catch (_error) {
      return findings;
    }

    // Strip TypeScript type annotations for parsing (simple approach)
    const processedSource = source
      .replace(/:\s*[A-Za-z<>[\]|&\s,]+(?=\s*[=),;\n])/g, '') // Remove type annotations
      .replace(/as\s+[A-Za-z<>[\]|&\s]+/g, '') // Remove type assertions
      .replace(/<[A-Za-z<>[\]|&\s,]+>/g, ''); // Remove generics

    const ast = parseCode(processedSource);
    if (!ast) {
      return findings;
    }

    const language: Language =
      filePath.endsWith('.ts') || filePath.endsWith('.tsx') ? 'typescript' : 'javascript';
    const configLoader = getConfigLoader();

    // Walk the AST and check each pattern
    walk.simple(ast, {
      CallExpression(node: any) {
        for (const pattern of JS_RISK_PATTERNS) {
          if (pattern.nodeType === 'CallExpression' && pattern.matcher(node)) {
            if (!configLoader.isPatternEnabled(pattern.name, language)) continue;
            const severity = configLoader.getPatternSeverity(
              pattern.name,
              pattern.severity,
              language,
            );

            findings.push({
              file: filePath,
              line: node.loc?.start?.line || 0,
              column: node.loc?.start?.column || 0,
              severity,
              category: pattern.category,
              description: pattern.description,
              codeSnippet: getCodeSnippet(source, node.loc?.start?.line || 0),
              language,
            });
          }
        }
      },
      NewExpression(node: any) {
        for (const pattern of JS_RISK_PATTERNS) {
          if (pattern.nodeType === 'NewExpression' && pattern.matcher(node)) {
            if (!configLoader.isPatternEnabled(pattern.name, language)) continue;
            const severity = configLoader.getPatternSeverity(
              pattern.name,
              pattern.severity,
              language,
            );

            findings.push({
              file: filePath,
              line: node.loc?.start?.line || 0,
              column: node.loc?.start?.column || 0,
              severity,
              category: pattern.category,
              description: pattern.description,
              codeSnippet: getCodeSnippet(source, node.loc?.start?.line || 0),
              language,
            });
          }
        }
      },
      MemberExpression(node: any) {
        for (const pattern of JS_RISK_PATTERNS) {
          if (pattern.nodeType === 'MemberExpression' && pattern.matcher(node)) {
            if (!configLoader.isPatternEnabled(pattern.name, language)) continue;
            const severity = configLoader.getPatternSeverity(
              pattern.name,
              pattern.severity,
              language,
            );

            findings.push({
              file: filePath,
              line: node.loc?.start?.line || 0,
              column: node.loc?.start?.column || 0,
              severity,
              category: pattern.category,
              description: pattern.description,
              codeSnippet: getCodeSnippet(source, node.loc?.start?.line || 0),
              language,
            });
          }
        }
      },
      VariableDeclarator(node: any) {
        for (const pattern of JS_RISK_PATTERNS) {
          if (pattern.nodeType === 'VariableDeclarator' && pattern.matcher(node)) {
            if (!configLoader.isPatternEnabled(pattern.name, language)) continue;
            const severity = configLoader.getPatternSeverity(
              pattern.name,
              pattern.severity,
              language,
            );

            findings.push({
              file: filePath,
              line: node.loc?.start?.line || 0,
              column: node.loc?.start?.column || 0,
              severity,
              category: pattern.category,
              description: pattern.description,
              codeSnippet: getCodeSnippet(source, node.loc?.start?.line || 0),
              language,
            });
          }
        }
      },
      TemplateLiteral(node: any) {
        for (const pattern of JS_RISK_PATTERNS) {
          if (pattern.nodeType === 'TemplateLiteral' && pattern.matcher(node)) {
            if (!configLoader.isPatternEnabled(pattern.name, language)) continue;
            const severity = configLoader.getPatternSeverity(
              pattern.name,
              pattern.severity,
              language,
            );

            findings.push({
              file: filePath,
              line: node.loc?.start?.line || 0,
              column: node.loc?.start?.column || 0,
              severity,
              category: pattern.category,
              description: pattern.description,
              codeSnippet: getCodeSnippet(source, node.loc?.start?.line || 0),
              language,
            });
          }
        }
      },
      DebuggerStatement(node: any) {
        for (const pattern of JS_RISK_PATTERNS) {
          if (pattern.nodeType === 'DebuggerStatement' && pattern.matcher(node)) {
            if (!configLoader.isPatternEnabled(pattern.name, language)) continue;
            const severity = configLoader.getPatternSeverity(
              pattern.name,
              pattern.severity,
              language,
            );

            findings.push({
              file: filePath,
              line: node.loc?.start?.line || 0,
              column: node.loc?.start?.column || 0,
              severity,
              category: pattern.category,
              description: pattern.description,
              codeSnippet: getCodeSnippet(source, node.loc?.start?.line || 0),
              language,
            });
          }
        }
      },
    });

    return findings;
  }
}
