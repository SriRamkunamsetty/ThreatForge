export type ComponentType =
  | 'process'
  | 'data_store'
  | 'external_entity'
  | 'trust_boundary'
  | 'llm_provider'
  | 'rag_pipeline'
  | 'vector_store'
  | 'agent'
  | 'tool'
  | 'system_prompt'
  | 'untrusted_input';

export type DataClassification =
  | 'PUBLIC'
  | 'INTERNAL'
  | 'CONFIDENTIAL'
  | 'RESTRICTED'
  | 'PII'
  | 'PHI'
  | 'CREDENTIALS';

export type Applicability = 'APPLICABLE' | 'NOT_APPLICABLE' | 'NEEDS_REVIEW';
export type Confidence = 'HIGH' | 'MEDIUM' | 'LOW' | 'INSUFFICIENT_DATA';
export type MitigationStatus = 'PROPOSED' | 'ACCEPTED' | 'IMPLEMENTED' | 'VERIFIED' | 'FAILED' | 'STALE' | 'WONT_FIX';
export type TestStatus = 'PENDING' | 'PASSED' | 'FAILED' | 'STALE' | 'SKIPPED';

export interface ComponentProperties {
  authentication_required?: boolean;
  authorization_enforced?: boolean;
  auth_mechanism?: string;
  encrypted_at_rest?: boolean;
  encrypted_in_transit?: boolean;
  internet_facing?: boolean;
  allows_anonymous_access?: boolean;
  stores_pii?: boolean;
  stores_credentials?: boolean;
  accepts_untrusted_input?: boolean;
  has_human_in_the_loop?: boolean;
  tool_permissions?: string[];
  custom?: Record<string, any>;
  [key: string]: any;
}

export interface ArchitectureComponent {
  id: string;
  name: string;
  component_type: ComponentType;
  trust_zone?: string;
  description?: string;
  properties: ComponentProperties;
  position?: { x: number; y: number };
}

export interface DataFlowProperties {
  protocol?: string;
  port?: number;
  encrypted?: boolean;
  carries_credentials?: boolean;
  data_classification?: DataClassification;
  carries_pii?: boolean;
  custom?: Record<string, any>;
  [key: string]: any;
}

export interface ArchitectureFlow {
  id: string;
  source_component_id: string;
  target_component_id: string;
  name?: string;
  crosses_trust_boundary: boolean;
  source_trust_zone?: string;
  target_trust_zone?: string;
  properties: DataFlowProperties;
}

export interface ThreatSummary {
  threat_id: string;
  component_id: string;
  component_name: string;
  component_type: string;
  rule_id: string;
  rule_version: string;
  category: string;
  methodology: string;
  title: string;
  description: string;
  applicability: Applicability;
  confidence: Confidence;
  prerequisites_met: string[];
  missing_facts: string[];
  assumptions: string[];
  architecture_facts: Array<{
    fact_type: string;
    description: string;
    attribute?: string;
    value?: any;
  }>;
  mitigation_templates: Array<{
    template_id: string;
    title: string;
    description: string;
    control_type: string;
    verification_criteria: string[];
  }>;
  verification_criteria: string[];
  status: string;
}

export interface TestCaseSpecification {
  id: string;
  title: string;
  identity: string;
  action: string;
  expected_result: string;
  actual_result?: string;
  status: TestStatus;
  execution_notes?: string;
}

export interface EvidenceRecord {
  id: string;
  evidence_type: string;
  summary: string;
  commit_sha?: string;
  environment: string;
  test_run_url?: string;
  recorded_by: string;
  created_at: string;
}

export interface MitigationRecord {
  id: string;
  threat_instance_id: string;
  template_id: string;
  title: string;
  description: string;
  control_type: string;
  status: MitigationStatus;
  test_cases: TestCaseSpecification[];
  evidence_records: EvidenceRecord[];
}

export interface SecurityChange {
  change_type: string;
  entity_type: string;
  entity_id: string;
  entity_name: string;
  security_relevance: 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE';
  threat_impact: string;
  requires_review: boolean;
  attribute_deltas: Array<{
    attribute: string;
    old: any;
    new: any;
    relevance: string;
    rationale: string;
  }>;
}

export interface DriftReport {
  id: string;
  baseline_version_id?: string;
  current_version_id?: string;
  added_components: any[];
  removed_components: any[];
  modified_components: any[];
  added_flows: any[];
  removed_flows: any[];
  modified_flows: any[];
  new_boundary_crossings: any[];
  changes: SecurityChange[];
  security_relevance_score: number;
  requires_review: boolean;
  newly_applicable_threats: any[];
  invalidated_threats: any[];
}

export interface ProvenanceNode {
  node_id: string;
  node_type: string;
  label: string;
  metadata: Record<string, any>;
}

export interface ProvenanceEdge {
  source_id: string;
  target_id: string;
  relationship: string;
}

export interface ProvenanceGraphData {
  threat_id: string;
  nodes: ProvenanceNode[];
  edges: ProvenanceEdge[];
  node_count: number;
  edge_count: number;
}

export interface AttackStep {
  step_number: number;
  source_id: string;
  source_name: string;
  target_id: string;
  target_name: string;
  flow_id: string;
  crosses_boundary: boolean;
  encrypted?: boolean;
  protocol?: string;
}

export interface AttackPath {
  path_id: string;
  entry_point_id: string;
  entry_point_name: string;
  target_asset_id: string;
  target_asset_name: string;
  hop_count: number;
  risk_score: number;
  unencrypted_hops: number;
  boundary_crossings: number;
  description: string;
  steps: AttackStep[];
}
