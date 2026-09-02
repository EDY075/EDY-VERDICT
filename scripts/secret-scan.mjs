// Narrow local audit of this project's owned source/docs, not an engine or product scanner.
// This is a baseline heuristic, not a replacement for a later approved Gitleaks run.
import {readdirSync,readFileSync,statSync} from 'node:fs';
import {join} from 'node:path';
const excluded=new Set(['.git','.local','target','node_modules','dist','gen','.generated']);
const rules=[['private-key',/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/],['github-token',/\bgh[pousr]_[A-Za-z0-9]{30,}\b/],['aws-access-key',/\bAKIA[0-9A-Z]{16}\b/],['provider-assignment',/\b(?:api[_-]?key|access[_-]?token|client[_-]?secret)\s*[:=]\s*["'][A-Za-z0-9_+\/-]{24,}["']/i]];
let scanned=0;const findings=[];
function walk(dir){for(const e of readdirSync(dir,{withFileTypes:true})){if(excluded.has(e.name)||e.isSymbolicLink())continue;const path=join(dir,e.name);if(e.isDirectory()){walk(path);continue;}if(!/\.(rs|toml|json|ya?ml|mjs|cjs|js|ts|tsx|ps1|md|html|css|sql|txt)$/.test(e.name)||statSync(path).size>16*1024*1024)continue;const text=readFileSync(path,'utf8');scanned++;for(const [rule,re] of rules){if(re.test(text))findings.push({file:path,rule});}}}
walk('.');console.log(JSON.stringify({scope:'owned source/docs only; caches/dependencies/builds excluded',scanned,findings,secret_values_logged:false}));if(findings.length)process.exitCode=1;
