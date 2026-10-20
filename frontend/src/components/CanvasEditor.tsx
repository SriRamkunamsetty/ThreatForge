import React, { useState, useCallback, useMemo } from 'react';
import {
  ReactFlow,
  MiniMap,
  Controls,
  Background,
  useNodesState,
  useEdgesState,
  addEdge,
  Handle,
  Position,
  BackgroundVariant,
} from '@xyflow/react';
import type { Connection, Edge, Node } from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import {
  Server,
  Database,
  Globe,
  Bot,
  BrainCircuit,
  Boxes,
  Play,
  ShieldCheck,
  Plus,
  Settings,
  X,
  Unlock,
} from 'lucide-react';
import type { ArchitectureComponent, ArchitectureFlow, ComponentType, ComponentProperties } from '../types/threatforge';
import { SAMPLE_ARCHITECTURES } from '../data/sampleArchitectures';
import type { ArchitectureScenario } from '../data/sampleArchitectures';

// Custom Node Components
const ProcessNode = ({ data }: { data: any }) => (
  <div className="rf-node-card rf-node-process">
    <Handle type="target" position={Position.Left} style={{ background: '#38bdf8' }} />
    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
      <Server size={18} color="#38bdf8" />
      <div>
        <div style={{ fontSize: '0.85rem', fontWeight: 600 }}>{data.label}</div>
        <div style={{ fontSize: '0.7rem', color: '#94a3b8' }}>Process | {data.trust_zone || 'internal'}</div>
      </div>
    </div>
    {data.properties?.authentication_required === false && (
      <div style={{ marginTop: '6px', fontSize: '0.68rem', color: '#fb7185', display: 'flex', alignItems: 'center', gap: '4px' }}>
        <Unlock size={12} /> No Auth Enforced
      </div>
    )}
    <Handle type="source" position={Position.Right} style={{ background: '#38bdf8' }} />
  </div>
);

const DataStoreNode = ({ data }: { data: any }) => (
  <div className="rf-node-card rf-node-data-store">
    <Handle type="target" position={Position.Left} style={{ background: '#34d399' }} />
    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
      <Database size={18} color="#34d399" />
      <div>
        <div style={{ fontSize: '0.85rem', fontWeight: 600 }}>{data.label}</div>
        <div style={{ fontSize: '0.7rem', color: '#94a3b8' }}>Data Store | {data.trust_zone || 'internal'}</div>
      </div>
    </div>
    {data.properties?.stores_pii && (
      <div style={{ marginTop: '6px', fontSize: '0.68rem', color: '#38bdf8' }}>
        PII Classified {data.properties?.encrypted_at_rest === false ? '• Cleartext' : '• Encrypted'}
      </div>
    )}
    <Handle type="source" position={Position.Right} style={{ background: '#34d399' }} />
  </div>
);

const ExternalNode = ({ data }: { data: any }) => (
  <div className="rf-node-card rf-node-external">
    <Handle type="target" position={Position.Left} style={{ background: '#a78bfa' }} />
    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
      <Globe size={18} color="#a78bfa" />
      <div>
        <div style={{ fontSize: '0.85rem', fontWeight: 600 }}>{data.label}</div>
        <div style={{ fontSize: '0.7rem', color: '#94a3b8' }}>External Ingress</div>
      </div>
    </div>
    <Handle type="source" position={Position.Right} style={{ background: '#a78bfa' }} />
  </div>
);

const AgentNode = ({ data }: { data: any }) => (
  <div className="rf-node-card rf-node-agent">
    <Handle type="target" position={Position.Left} style={{ background: '#f472b6' }} />
    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
      <Bot size={18} color="#f472b6" />
      <div>
        <div style={{ fontSize: '0.85rem', fontWeight: 600 }}>{data.label}</div>
        <div style={{ fontSize: '0.7rem', color: '#94a3b8' }}>AI Agent {data.properties?.has_human_in_the_loop ? '• HITL' : '• Autonomous'}</div>
      </div>
    </div>
    {data.properties?.has_human_in_the_loop === false && data.properties?.tool_permissions?.length > 0 && (
      <div style={{ marginTop: '6px', fontSize: '0.68rem', color: '#fb7185' }}>
        ⚠️ High Risk: Destructive tools without HITL
      </div>
    )}
    <Handle type="source" position={Position.Right} style={{ background: '#f472b6' }} />
  </div>
);

const RAGNode = ({ data }: { data: any }) => (
  <div className="rf-node-card rf-node-rag">
    <Handle type="target" position={Position.Left} style={{ background: '#fbbf24' }} />
    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
      <BrainCircuit size={18} color="#fbbf24" />
      <div>
        <div style={{ fontSize: '0.85rem', fontWeight: 600 }}>{data.label}</div>
        <div style={{ fontSize: '0.7rem', color: '#94a3b8' }}>RAG Pipeline</div>
      </div>
    </div>
    <Handle type="source" position={Position.Right} style={{ background: '#fbbf24' }} />
  </div>
);

const VectorNode = ({ data }: { data: any }) => (
  <div className="rf-node-card rf-node-vector">
    <Handle type="target" position={Position.Left} style={{ background: '#22d3ee' }} />
    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
      <Boxes size={18} color="#22d3ee" />
      <div>
        <div style={{ fontSize: '0.85rem', fontWeight: 600 }}>{data.label}</div>
        <div style={{ fontSize: '0.7rem', color: '#94a3b8' }}>Vector Store</div>
      </div>
    </div>
    <Handle type="source" position={Position.Right} style={{ background: '#22d3ee' }} />
  </div>
);

interface CanvasEditorProps {
  onAnalyze: (components: ArchitectureComponent[], flows: ArchitectureFlow[]) => void;
  onSetBaseline: (components: ArchitectureComponent[], flows: ArchitectureFlow[]) => void;
  baselineSet: boolean;
}

export const CanvasEditor: React.FC<CanvasEditorProps> = ({
  onAnalyze,
  onSetBaseline,
  baselineSet,
}) => {
  const nodeTypes = useMemo(
    () => ({
      process: ProcessNode,
      data_store: DataStoreNode,
      external_entity: ExternalNode,
      untrusted_input: ExternalNode,
      agent: AgentNode,
      rag_pipeline: RAGNode,
      vector_store: VectorNode,
    }),
    []
  );

  const scenarioToRF = (scenario: ArchitectureScenario) => {
    const rfNodes: Node[] = scenario.components.map((c) => ({
      id: c.id,
      type: c.component_type,
      position: c.position || { x: 100, y: 100 },
      data: {
        label: c.name,
        trust_zone: c.trust_zone,
        properties: c.properties,
        component_type: c.component_type,
      },
    }));

    const rfEdges: Edge[] = scenario.flows.map((f) => ({
      id: f.id,
      source: f.source_component_id,
      target: f.target_component_id,
      label: f.name || (f.crosses_trust_boundary ? 'Crosses Boundary' : 'Data Flow'),
      animated: f.crosses_trust_boundary,
      style: {
        stroke: f.properties?.encrypted === false ? '#f43f5e' : '#38bdf8',
        strokeWidth: 2,
      },
      data: f.properties as Record<string, unknown>,
    }));

    return { rfNodes, rfEdges };
  };

  const initial = scenarioToRF(SAMPLE_ARCHITECTURES[0]);
  const [nodes, setNodes, onNodesChange] = useNodesState(initial.rfNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initial.rfEdges);
  const [selectedNode, setSelectedNode] = useState<Node | null>(null);

  const onConnect = useCallback(
    (params: Connection) =>
      setEdges((eds) =>
        addEdge(
          {
            ...params,
            animated: true,
            style: { stroke: '#38bdf8', strokeWidth: 2 },
            data: { encrypted: true },
          },
          eds
        )
      ),
    [setEdges]
  );

  const onNodeClick = (_: React.MouseEvent, node: Node) => {
    setSelectedNode(node);
  };

  const loadScenario = (scenarioId: string) => {
    const sc = SAMPLE_ARCHITECTURES.find((s) => s.id === scenarioId);
    if (!sc) return;
    const { rfNodes, rfEdges } = scenarioToRF(sc);
    setNodes(rfNodes);
    setEdges(rfEdges);
    setSelectedNode(null);
  };

  const getCanvasData = (): { components: ArchitectureComponent[]; flows: ArchitectureFlow[] } => {
    const components: ArchitectureComponent[] = nodes.map((n) => {
      const data = n.data as Record<string, any>;
      return {
        id: n.id,
        name: (data.label as string) || n.id,
        component_type: (data.component_type || n.type || 'process') as ComponentType,
        trust_zone: data.trust_zone as string,
        properties: (data.properties || {}) as ComponentProperties,
        position: n.position,
      };
    });

    const flows: ArchitectureFlow[] = edges.map((e) => ({
      id: e.id,
      source_component_id: e.source,
      target_component_id: e.target,
      name: typeof e.label === 'string' ? e.label : undefined,
      crosses_trust_boundary: Boolean(e.animated),
      properties: (e.data || {}) as any,
    }));

    return { components, flows };
  };

  const handleRunAnalysis = () => {
    const { components, flows } = getCanvasData();
    onAnalyze(components, flows);
  };

  const handleSaveBaseline = () => {
    const { components, flows } = getCanvasData();
    onSetBaseline(components, flows);
  };

  const updateSelectedNodeProperty = (key: string, value: any) => {
    if (!selectedNode) return;
    setNodes((nds) =>
      nds.map((n) => {
        if (n.id === selectedNode.id) {
          const currentData = n.data as Record<string, any>;
          const updatedProps = { ...(currentData.properties || {}), [key]: value };
          const updatedNode = {
            ...n,
            data: {
              ...currentData,
              properties: updatedProps,
            },
          };
          setSelectedNode(updatedNode);
          return updatedNode;
        }
        return n;
      })
    );
  };

  const addNode = (type: ComponentType, label: string) => {
    const id = `node-${Date.now()}`;
    const newNode: Node = {
      id,
      type,
      position: { x: 250 + Math.random() * 80, y: 150 + Math.random() * 80 },
      data: {
        label,
        component_type: type,
        trust_zone: 'internal',
        properties: {
          authentication_required: true,
          authorization_enforced: true,
          encrypted_at_rest: true,
        },
      },
    };
    setNodes((nds) => [...nds, newNode]);
  };

  const selectedNodeData = selectedNode ? (selectedNode.data as Record<string, any>) : null;
  const selectedNodeProps = (selectedNodeData?.properties || {}) as ComponentProperties;

  return (
    <div style={{ display: 'flex', height: '100%', width: '100%', position: 'relative' }}>
      {/* Top Floating Control Bar */}
      <div
        className="glass-panel"
        style={{
          position: 'absolute',
          top: 16,
          left: 20,
          zIndex: 10,
          padding: '8px 14px',
          display: 'flex',
          alignItems: 'center',
          gap: '12px',
        }}
      >
        <span style={{ fontSize: '0.85rem', color: '#94a3b8', fontWeight: 500 }}>
          Architecture Presets:
        </span>
        <select
          onChange={(e) => loadScenario(e.target.value)}
          defaultValue="ecommerce_insecure"
          style={{
            background: '#090e1a',
            color: '#f8fafc',
            border: '1px solid var(--border-subtle)',
            borderRadius: '6px',
            padding: '6px 12px',
            fontSize: '0.85rem',
            outline: 'none',
            cursor: 'pointer',
          }}
        >
          {SAMPLE_ARCHITECTURES.map((s) => (
            <option key={s.id} value={s.id}>
              {s.name}
            </option>
          ))}
        </select>

        <div style={{ height: 20, width: 1, background: 'var(--border-subtle)' }} />

        {/* Add Nodes Palette */}
        <div style={{ display: 'flex', gap: '6px' }}>
          <button
            onClick={() => addNode('process', 'API Service')}
            className="btn-secondary"
            style={{ fontSize: '0.75rem', padding: '5px 10px' }}
            title="Add Process"
          >
            <Plus size={14} /> Service
          </button>
          <button
            onClick={() => addNode('data_store', 'PostgreSQL DB')}
            className="btn-secondary"
            style={{ fontSize: '0.75rem', padding: '5px 10px' }}
            title="Add Database"
          >
            <Plus size={14} /> Database
          </button>
          <button
            onClick={() => addNode('agent', 'Autonomous Agent')}
            className="btn-secondary"
            style={{ fontSize: '0.75rem', padding: '5px 10px' }}
            title="Add AI Agent"
          >
            <Plus size={14} /> AI Agent
          </button>
          <button
            onClick={() => addNode('rag_pipeline', 'RAG Engine')}
            className="btn-secondary"
            style={{ fontSize: '0.75rem', padding: '5px 10px' }}
            title="Add RAG Pipeline"
          >
            <Plus size={14} /> RAG
          </button>
        </div>

        <div style={{ height: 20, width: 1, background: 'var(--border-subtle)' }} />

        {/* Action Buttons */}
        <button onClick={handleRunAnalysis} className="btn-primary" style={{ padding: '7px 14px' }}>
          <Play size={15} fill="#fff" /> Run STRIDE & AI Analysis
        </button>

        <button
          onClick={handleSaveBaseline}
          className="btn-secondary"
          style={{
            padding: '7px 14px',
            borderColor: baselineSet ? '#10b981' : undefined,
            color: baselineSet ? '#34d399' : undefined,
          }}
          title="Save this architecture as baseline for drift comparison"
        >
          <ShieldCheck size={16} />
          {baselineSet ? 'Baseline Active' : 'Set as Approved Baseline'}
        </button>
      </div>

      {/* React Flow Canvas */}
      <div style={{ flex: 1, height: '100%', background: 'var(--bg-canvas)' }}>
        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          onConnect={onConnect}
          onNodeClick={onNodeClick}
          nodeTypes={nodeTypes}
          fitView
        >
          <Controls style={{ background: '#0f172a', border: '1px solid var(--border-subtle)' }} />
          <MiniMap
            nodeStrokeWidth={3}
            nodeColor="#38bdf8"
            style={{ background: '#090e1a', border: '1px solid var(--border-subtle)' }}
          />
          <Background variant={BackgroundVariant.Dots} gap={18} size={1} color="#1e293b" />
        </ReactFlow>
      </div>

      {/* Node Inspector Drawer */}
      {selectedNode && selectedNodeData && (
        <div
          className="glass-panel"
          style={{
            width: 320,
            borderLeft: '1px solid var(--border-subtle)',
            padding: '20px',
            overflowY: 'auto',
            display: 'flex',
            flexDirection: 'column',
            gap: '16px',
            zIndex: 20,
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontWeight: 600 }}>
              <Settings size={18} color="#38bdf8" />
              <span>Context Inspector</span>
            </div>
            <button
              onClick={() => setSelectedNode(null)}
              style={{ background: 'transparent', border: 'none', color: '#94a3b8', cursor: 'pointer' }}
            >
              <X size={18} />
            </button>
          </div>

          <div>
            <label style={{ fontSize: '0.75rem', color: '#94a3b8', textTransform: 'uppercase' }}>
              Component Name
            </label>
            <div style={{ fontSize: '1rem', fontWeight: 600, marginTop: '2px' }}>
              {String(selectedNodeData.label || selectedNode.id)}
            </div>
            <div style={{ fontSize: '0.8rem', color: '#38bdf8', marginTop: '2px' }}>
              Type: {String(selectedNodeData.component_type || selectedNode.type)}
            </div>
          </div>

          <div style={{ height: 1, background: 'var(--border-subtle)' }} />

          {/* Security Attribute Toggles */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            <span style={{ fontSize: '0.8rem', fontWeight: 600, color: '#f8fafc' }}>
              Security Posture Controls
            </span>

            <label style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', cursor: 'pointer' }}>
              <span style={{ fontSize: '0.82rem', color: '#cbd5e1' }}>Authentication Required</span>
              <input
                type="checkbox"
                checked={selectedNodeProps.authentication_required !== false}
                onChange={(e) => updateSelectedNodeProperty('authentication_required', e.target.checked)}
              />
            </label>

            <label style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', cursor: 'pointer' }}>
              <span style={{ fontSize: '0.82rem', color: '#cbd5e1' }}>Authorization Enforced (RBAC)</span>
              <input
                type="checkbox"
                checked={selectedNodeProps.authorization_enforced !== false}
                onChange={(e) => updateSelectedNodeProperty('authorization_enforced', e.target.checked)}
              />
            </label>

            <label style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', cursor: 'pointer' }}>
              <span style={{ fontSize: '0.82rem', color: '#cbd5e1' }}>Encrypted at Rest</span>
              <input
                type="checkbox"
                checked={selectedNodeProps.encrypted_at_rest !== false}
                onChange={(e) => updateSelectedNodeProperty('encrypted_at_rest', e.target.checked)}
              />
            </label>

            <label style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', cursor: 'pointer' }}>
              <span style={{ fontSize: '0.82rem', color: '#cbd5e1' }}>Stores PII</span>
              <input
                type="checkbox"
                checked={Boolean(selectedNodeProps.stores_pii)}
                onChange={(e) => updateSelectedNodeProperty('stores_pii', e.target.checked)}
              />
            </label>

            <label style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', cursor: 'pointer' }}>
              <span style={{ fontSize: '0.82rem', color: '#cbd5e1' }}>Allows Anonymous Access</span>
              <input
                type="checkbox"
                checked={Boolean(selectedNodeProps.allows_anonymous_access)}
                onChange={(e) => updateSelectedNodeProperty('allows_anonymous_access', e.target.checked)}
              />
            </label>

            {/* AI Agent Specific Toggles */}
            {(selectedNode.type === 'agent' || selectedNodeData.component_type === 'agent') && (
              <>
                <div style={{ height: 1, background: 'var(--border-subtle)', margin: '4px 0' }} />
                <span style={{ fontSize: '0.8rem', fontWeight: 600, color: '#f472b6' }}>
                  AI Agent Governance
                </span>

                <label style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', cursor: 'pointer' }}>
                  <span style={{ fontSize: '0.82rem', color: '#cbd5e1' }}>Human-in-the-Loop (HITL)</span>
                  <input
                    type="checkbox"
                    checked={Boolean(selectedNodeProps.has_human_in_the_loop)}
                    onChange={(e) => updateSelectedNodeProperty('has_human_in_the_loop', e.target.checked)}
                  />
                </label>

                <label style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', cursor: 'pointer' }}>
                  <span style={{ fontSize: '0.82rem', color: '#cbd5e1' }}>Accepts Untrusted Inputs</span>
                  <input
                    type="checkbox"
                    checked={Boolean(selectedNodeProps.accepts_untrusted_input)}
                    onChange={(e) => updateSelectedNodeProperty('accepts_untrusted_input', e.target.checked)}
                  />
                </label>
              </>
            )}
          </div>

          <div style={{ marginTop: 'auto', paddingTop: '12px' }}>
            <button
              onClick={handleRunAnalysis}
              className="btn-primary"
              style={{ width: '100%', justifyContent: 'center' }}
            >
              Analyze Live Changes
            </button>
          </div>
        </div>
      )}
    </div>
  );
};
