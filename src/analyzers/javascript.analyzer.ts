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
    });

    return findings;
  }
}
