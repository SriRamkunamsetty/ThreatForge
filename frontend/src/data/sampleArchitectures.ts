import type { ArchitectureComponent, ArchitectureFlow } from '../types/threatforge';

export interface ArchitectureScenario {
  id: string;
  name: string;
  description: string;
  category: 'web_application' | 'ai_system' | 'cloud_microservices';
  components: ArchitectureComponent[];
  flows: ArchitectureFlow[];
}

export const SAMPLE_ARCHITECTURES: ArchitectureScenario[] = [
  {
    id: 'ecommerce_insecure',
    name: 'E-Commerce: Unsecured API & Database (Insecure)',
    description: 'Direct internet traffic into an API without authentication, accessing cleartext customer database.',
    category: 'web_application',
    components: [
      {
        id: 'comp-ext-1',
        name: 'Public Web Shopper',
        component_type: 'external_entity',
        trust_zone: 'internet',
        position: { x: 50, y: 150 },
        properties: {},
      },
      {
        id: 'comp-api-1',
        name: 'Order Processing API',
        component_type: 'process',
        trust_zone: 'internal',
        position: { x: 380, y: 150 },
        properties: {
          authentication_required: false,
          authorization_enforced: false,
          internet_facing: true,
          custom: {
            rate_limiting_enabled: false,
            audit_logging_enabled: false,
          },
        },
      },
      {
        id: 'comp-db-1',
        name: 'Customer PII Database',
        component_type: 'data_store',
        trust_zone: 'internal',
        position: { x: 720, y: 150 },
        properties: {
          stores_pii: true,
          encrypted_at_rest: false,
          allows_anonymous_access: true,
        },
      },
    ],
    flows: [
      {
        id: 'flow-1',
        source_component_id: 'comp-ext-1',
        target_component_id: 'comp-api-1',
        name: 'Cleartext HTTP Request',
        crosses_trust_boundary: true,
        properties: {
          encrypted: false,
          data_classification: 'PII',
        },
      },
      {
        id: 'flow-2',
        source_component_id: 'comp-api-1',
        target_component_id: 'comp-db-1',
        name: 'Unencrypted SQL Query',
        crosses_trust_boundary: false,
        properties: {
          encrypted: false,
        },
      },
    ],
  },
  {
    id: 'ecommerce_secured',
    name: 'E-Commerce: Hardened Zero-Trust (Approved Baseline)',
    description: 'Zero-trust architecture with TLS 1.3, JWT auth, RBAC enforcement, rate limiting, and encrypted database.',
    category: 'web_application',
    components: [
      {
        id: 'comp-ext-1',
        name: 'Authenticated Shopper',
        component_type: 'external_entity',
        trust_zone: 'internet',
        position: { x: 50, y: 150 },
        properties: {},
      },
      {
        id: 'comp-api-1',
        name: 'Hardened API Gateway',
        component_type: 'process',
        trust_zone: 'internal',
        position: { x: 380, y: 150 },
        properties: {
          authentication_required: true,
          auth_mechanism: 'JWT',
          authorization_enforced: true,
          internet_facing: true,
          custom: {
            rate_limiting_enabled: true,
            audit_logging_enabled: true,
          },
        },
      },
      {
        id: 'comp-db-1',
        name: 'Encrypted Customer Vault',
        component_type: 'data_store',
        trust_zone: 'internal',
        position: { x: 720, y: 150 },
        properties: {
          stores_pii: true,
          encrypted_at_rest: true,
          allows_anonymous_access: false,
        },
      },
    ],
    flows: [
      {
        id: 'flow-1',
        source_component_id: 'comp-ext-1',
        target_component_id: 'comp-api-1',
        name: 'TLS 1.3 Encrypted HTTPS',
        crosses_trust_boundary: true,
        properties: {
          encrypted: true,
          data_classification: 'PII',
        },
      },
      {
        id: 'flow-2',
        source_component_id: 'comp-api-1',
        target_component_id: 'comp-db-1',
        name: 'mTLS Secure DB Link',
        crosses_trust_boundary: false,
        properties: {
          encrypted: true,
        },
      },
    ],
  },
  {
    id: 'ai_agent_insecure',
    name: 'AI System: Autonomous Agent + RAG Pipeline (High Risk)',
    description: 'Autonomous agent with destructive tool permissions, no HITL, ingesting external documents without injection guardrails.',
    category: 'ai_system',
    components: [
      {
        id: 'ai-user-1',
        name: 'Untrusted Chat User',
        component_type: 'untrusted_input',
        trust_zone: 'internet',
        position: { x: 50, y: 100 },
        properties: {},
      },
      {
        id: 'ai-agent-1',
        name: 'DevOps Autonomous Agent',
        component_type: 'agent',
        trust_zone: 'internal',
        position: { x: 380, y: 100 },
        properties: {
          accepts_untrusted_input: true,
          tool_permissions: ['execute_code', 'delete_record', 'send_email'],
          has_human_in_the_loop: false,
          custom: {
            prompt_injection_defenses: [],
          },
        },
      },
      {
        id: 'ai-rag-1',
        name: 'Support RAG Pipeline',
        component_type: 'rag_pipeline',
        trust_zone: 'internal',
        position: { x: 380, y: 280 },
        properties: {
          accepts_untrusted_input: true,
          custom: {
            prompt_injection_defenses: [],
            output_sanitization_enabled: false,
          },
        },
      },
      {
        id: 'ai-vector-1',
        name: 'Pinecone Vector Store',
        component_type: 'vector_store',
        trust_zone: 'internal',
        position: { x: 720, y: 280 },
        properties: {
          stores_pii: true,
          encrypted_at_rest: true,
        },
      },
    ],
    flows: [
      {
        id: 'ai-f-1',
        source_component_id: 'ai-user-1',
        target_component_id: 'ai-agent-1',
        name: 'User Prompt with Injection Risk',
        crosses_trust_boundary: true,
        properties: { encrypted: true },
      },
      {
        id: 'ai-f-2',
        source_component_id: 'ai-vector-1',
        target_component_id: 'ai-rag-1',
        name: 'Retrieved Chunks',
        crosses_trust_boundary: false,
        properties: { encrypted: true },
      },
      {
        id: 'ai-f-3',
        source_component_id: 'ai-rag-1',
        target_component_id: 'ai-agent-1',
        name: 'Augmented Context Flow',
        crosses_trust_boundary: false,
        properties: { encrypted: true },
      },
    ],
  },
  {
    id: 'ai_agent_secured',
    name: 'AI System: Governed Agent with HITL & Guardrails',
    description: 'Secure AI agent with human approval gating for high-impact actions, scoped tools, and multi-layer prompt injection filters.',
    category: 'ai_system',
    components: [
      {
        id: 'ai-user-1',
        name: 'Corporate Operator',
        component_type: 'external_entity',
        trust_zone: 'corporate',
        position: { x: 50, y: 150 },
        properties: {},
      },
      {
        id: 'ai-agent-1',
        name: 'Governed Assistant',
        component_type: 'agent',
        trust_zone: 'internal',
        position: { x: 380, y: 150 },
        properties: {
          accepts_untrusted_input: true,
          tool_permissions: ['search_kb', 'read_docs', 'format_response'],
          has_human_in_the_loop: true,
          custom: {
            prompt_injection_defenses: ['input_filtering', 'pydantic_schema_enforcement'],
          },
        },
      },
      {
        id: 'ai-rag-1',
        name: 'Sanitized RAG Pipeline',
        component_type: 'rag_pipeline',
        trust_zone: 'internal',
        position: { x: 720, y: 150 },
        properties: {
          accepts_untrusted_input: true,
          custom: {
            prompt_injection_defenses: ['dual_llm_checker'],
            output_sanitization_enabled: true,
          },
        },
      },
    ],
    flows: [
      {
        id: 'ai-f-1',
        source_component_id: 'ai-user-1',
        target_component_id: 'ai-agent-1',
        name: 'Validated Prompt Flow',
        crosses_trust_boundary: true,
        properties: { encrypted: true },
      },
      {
        id: 'ai-f-2',
        source_component_id: 'ai-agent-1',
        target_component_id: 'ai-rag-1',
        name: 'Sanitized Query Flow',
        crosses_trust_boundary: false,
        properties: { encrypted: true },
      },
    ],
  },
];
