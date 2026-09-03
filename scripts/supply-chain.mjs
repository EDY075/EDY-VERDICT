// Generates preliminary inventory from locked metadata and physically installed packages.
// No package execution, provider call or engine download.
import { readFileSync, writeFileSync, readdirSync, existsSync, mkdirSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { projectRust } from './project-rust.mjs';
import { createHash } from 'node:crypto';
const root=process.cwd();
const output=join(root,'docs/security/generated');mkdirSync(output,{recursive:true});
const hash=(bytes,algorithm='sha256')=>createHash(algorithm).update(bytes).digest('hex');
const portable=p=>relative(root,p).replaceAll('\\','/');
const write=(name,data)=>writeFileSync(join(output,name),JSON.stringify(data,null,2)+'\n');
const meta=JSON.parse(projectRust('MetadataWindows'));
const active=new Set(meta.resolve.nodes.map(n=>n.id));
const lock=readFileSync('Cargo.lock','utf8');
const checksums=new Map(lock.split('[[package]]').slice(1).map(block=>{
 const field=name=>block.match(new RegExp('^'+name+' = "([^"\\r\\n]+)"','m'))?.[1];
 return [field('name')+'@'+field('version'),field('checksum')];
}));
const packages=[];
for(const p of meta.packages.filter(p=>active.has(p.id)&&p.source)){
 const dir=dirname(p.manifest_path);const licenses=readdirSync(dir).filter(n=>/^(license|licence|copying|notice)([-.]|$)/i.test(n));
 const checksum=checksums.get(p.name+'@'+p.version);
 const archive=join(root,'.local/cargo/registry/cache',dir.split(/[\\/]/).at(-2),`${p.name}-${p.version}.crate`);
 const actual=existsSync(archive)?hash(readFileSync(archive)):null;
 if(actual && actual!==checksum)throw Error('Crate integrity mismatch: '+p.name);
 packages.push({ecosystem:'cargo',name:p.name,version:p.version,license:p.license,source:p.repository||p.source,archive_sha256:checksum,archive_verified:actual===checksum,license_files:licenses.map(n=>portable(join(dir,n))),build_scripts:p.targets.filter(t=>t.kind.includes('custom-build')).map(t=>portable(t.src_path)),id:p.id});
}
const visited=new Set();
for(const entry of readdirSync('node_modules/.pnpm',{withFileTypes:true}).filter(d=>d.isDirectory())){
 const modules=join(root,'node_modules/.pnpm',entry.name,'node_modules');if(!existsSync(modules))continue;
 for(const directory of readdirSync(modules,{withFileTypes:true}).filter(d=>d.isDirectory())){
  const dirs=directory.name.startsWith('@')?readdirSync(join(modules,directory.name)).map(n=>join(modules,directory.name,n)):[join(modules,directory.name)];
  for(const dir of dirs){const file=join(dir,'package.json');if(!existsSync(file))continue;const p=JSON.parse(readFileSync(file));const key=p.name+'@'+p.version;if(visited.has(key))continue;visited.add(key);
   const licenses=readdirSync(dir).filter(n=>/^(license|licence|copying|notice)([-.]|$)/i.test(n));
   packages.push({ecosystem:'npm',name:p.name,version:p.version,license:typeof p.license==='string'?p.license:JSON.stringify(p.license??null),source:typeof p.repository==='string'?p.repository:p.repository?.url||`https://registry.npmjs.org/${p.name}/${p.version}`,package_json_sha256:hash(readFileSync(file)),integrity_evidence:'pnpm-lock.yaml + frozen install/store integrity verification',license_files:licenses.map(n=>portable(join(dir,n))),install_scripts:Object.fromEntries(Object.entries(p.scripts||{}).filter(([n])=>['preinstall','install','postinstall','prepare'].includes(n))),scripts_executed:false});
  }
 }
}
packages.sort((a,b)=>(a.ecosystem+a.name+a.version).localeCompare(b.ecosystem+b.name+b.version));
write('license-inventory.json',{scope:'preliminary Windows resolved graph and installed npm packages; not public release clearance',packages});
const refs=new Map(packages.filter(p=>p.id).map(p=>[p.id,`pkg:cargo/${p.name}@${p.version}`]));
write('sbom.cdx.json',{bomFormat:'CycloneDX',specVersion:'1.6',version:1,metadata:{timestamp:new Date().toISOString(),component:{type:'application',name:'EDY VERDICT Foundation',version:'0.1.0'},properties:[{name:'edy:status',value:'BLOCKED_NOT_RELEASED'},{name:'edy:scope',value:'Windows resolved Rust graph plus installed frontend packages; excludes unused platform packages and standalone dev tool transitive graphs'}]},components:packages.map(p=>({type:'library',name:p.name,version:p.version,'bom-ref':`pkg:${p.ecosystem}/${encodeURIComponent(p.name).replaceAll('%2F','/')}@${p.version}`,purl:`pkg:${p.ecosystem}/${encodeURIComponent(p.name).replaceAll('%2F','/')}@${p.version}`,...(p.license?{licenses:[{expression:p.license.replaceAll('/', ' OR ')}]}:{}),...(p.archive_sha256?{hashes:[{alg:'SHA-256',content:p.archive_sha256}]}:{})})),dependencies:meta.resolve.nodes.filter(n=>refs.has(n.id)).map(n=>({ref:refs.get(n.id),dependsOn:n.dependencies.filter(d=>refs.has(d)).map(d=>refs.get(d))}))});
write('dependency-graph.json',{target:'x86_64-pc-windows-msvc',workspace:meta.packages.filter(p=>meta.workspace_members.includes(p.id)).map(p=>({name:p.name,dependencies:p.dependencies.map(d=>({name:d.name,requirement:d.req,kind:d.kind,path:d.path?portable(d.path):undefined}))})),resolved_nodes:meta.resolve.nodes});
write('lock-hashes.json',{cargo_lock_sha256:hash(readFileSync('Cargo.lock')),pnpm_lock_sha256:hash(readFileSync('pnpm-lock.yaml'))});
const existingNotices=existsSync('THIRD_PARTY_NOTICES.md')?readFileSync('THIRD_PARTY_NOTICES.md','utf8'):'';
const cargoStart=existingNotices.indexOf('## cargo:');
const preservedPreamble=existingNotices.includes('## external engines:')&&cargoStart>0
 ? existingNotices.slice(0,cargoStart).trimEnd()
 : '# THIRD PARTY NOTICES — preliminary foundation inventory\n\nNot a redistribution clearance. No public installer/release exists. Full graph/license and missing text review remain release gates. Generated by scripts/supply-chain.mjs.';
const notices=[preservedPreamble,''];
for(const p of packages){notices.push(`## ${p.ecosystem}: ${p.name} ${p.version}`,`Declared license: ${p.license||'UNKNOWN'}`,`Source: ${p.source}`,'');for(const file of p.license_files){try{notices.push(`### ${file.split('/').at(-1)}`,'',readFileSync(resolve(root,file),'utf8'),'');}catch{notices.push('License path requires manual inspection.','');}}if(!p.license_files.length)notices.push('No root license text file found; metadata only, manual release review required.','');}
writeFileSync('THIRD_PARTY_NOTICES.md',notices.join('\n'));
console.log(JSON.stringify({cargo:packages.filter(p=>p.ecosystem==='cargo').length,npm:packages.filter(p=>p.ecosystem==='npm').length,missing_root_license_text:packages.filter(p=>!p.license_files.length).length,crate_integrity_verified:packages.filter(p=>p.archive_verified).length}));
