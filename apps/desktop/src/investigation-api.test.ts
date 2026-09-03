import { describe, expect, it } from "vitest";
import { parseCase, parseCluster, parseGraph } from "./investigation-api";

const hex="a".repeat(64);
const cluster={cluster_id:`cluster-v1-${hex}`,cluster_type:"shared_vulnerability",member_findings:["finding-a","finding-b"],member_entities:[`ent-v1-${hex}`],supporting_edges:[`RELATIONSHIP_ID_V1-${hex}`],target_count:2,evidence_count:2,first_seen:"2099-01-01T00:00:00Z",last_seen:"2099-01-02T00:00:00Z",explanation_safe:"Exact canonical CVE shared by observed targets."};
const investigationCase={case_id:`case-v1-${hex}`,title_safe:"Suggested cross-target investigation",status:"suggested",suggested:true,finding_ids:["finding-a","finding-b"],cluster_ids:[cluster.cluster_id],entity_ids:[`ent-v1-${hex}`],evidence_ids:["evidence-a"],blast_radius:{observed_only:true,unique_affected_targets:2,unique_affected_components:1,unique_findings:2,unique_vulnerability_ids:1,target_types_affected:["repository","installed_application"]},assessment:{risk:95,confidence:85,coverage:100,priority:"immediate",risk_reasons:["Observed signal"],confidence_reasons:["Exact identity"],coverage_reasons:["Observed scope"],priority_reasons:["Known exploited vulnerability signal"]},timeline:[{sequence:1,timestamp:"2099-01-02T00:00:00Z",event_type:"case_suggested",summary_safe:"Review suggested; no incident is claimed.",source:"correlation-rule-engine"}],transitions:[]};

describe("Level 5 untrusted IPC parsers",()=>{
  it("accepts bounded exact case and cluster contracts",()=>{expect(parseCluster(cluster).target_count).toBe(2);expect(parseCase(investigationCase).assessment.risk).toBe(95)});
  it("rejects unknown fields, secret-shaped control text and invalid scores",()=>{
    expect(()=>parseCluster({...cluster,unexpected:true})).toThrow("rejected");
    expect(()=>parseCase({...investigationCase,title_safe:"unsafe\nvalue"})).toThrow("rejected");
    expect(()=>parseCase({...investigationCase,title_safe:"safe\u202Eexe.txt"})).toThrow("rejected");
    expect(()=>parseCase({...investigationCase,assessment:{...investigationCase.assessment,risk:101}})).toThrow("rejected");
  });
  it("rejects extra or malformed nested graph fields",()=>{
    const graph={schema:"LEVEL5_INVESTIGATION_V1",state:"complete",limit_reached:false,nodes:[{entity_id:`ent-v1-${hex}`,schema:"ENTITY_ID_V1",kind:"finding",identity:{kind:"stable_finding",canonical_value:"finding-a"},label_safe:"Finding"}],edges:[{edge_id:`RELATIONSHIP_ID_V1-${hex}`,relationship:"finding_affects_entity",from_entity:`ent-v1-${hex}`,to_entity:`ent-v1-${hex}`,rule_id:"L5-RULE-STRUCTURAL-V1",rule_version:1,finding_ids:["finding-a"],evidence_ids:["evidence-a"],source_scans:["scan-a"],created_by:"correlation-rule-engine",confidence:100,reasoning_safe:"Exact identity.",schema_version:1}],clusters:[cluster],suggested_cases:[investigationCase],findings_preserved:2,rules_executed:["L5-RULE-STRUCTURAL-V1"]};
    expect(parseGraph(graph).nodes).toHaveLength(1);
    expect(()=>parseGraph({...graph,nodes:[{...graph.nodes[0],unexpected:true}]})).toThrow("rejected");
    expect(()=>parseGraph({...graph,edges:[{...graph.edges[0],confidence:101}]})).toThrow("rejected");
  });
});
