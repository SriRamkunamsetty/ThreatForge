import React, { useState } from 'react';
import {
  GitBranch,
  ShieldAlert,
  FileCheck2,
  CheckCircle,
  Layers,
  Terminal,
  Activity,
  UserCheck,
} from 'lucide-react';
import type { ProvenanceGraphData, ProvenanceNode } from '../types/threatforge';

interface ProvenanceGraphViewProps {
  graphData: ProvenanceGraphData | null;
}

export const ProvenanceGraphView: React.FC<ProvenanceGraphViewProps> = ({
  graphData,
}) => {
  const [selectedNode, setSelectedNode] = useState<ProvenanceNode | null>(null);

  if (!graphData) {
    return (
      <div style={{ padding: '60px 20px', textAlign: 'center', maxWidth: '700px', margin: '40px auto' }}>
        <div className="glass-panel" style={{ padding: '40px 30px' }}>
          <GitBranch size={48} color="#38bdf8" style={{ margin: '0 auto 16px', opacity: 0.8 }} />
          <h3 style={{ fontSize: '1.3rem', fontWeight: 700, color: '#f8fafc' }}>
            No Threat Selected for Provenance
          </h3>
          <p style={{ fontSize: '0.875rem', color: '#94a3b8', margin: '10px 0 20px', lineHeight: 1.6 }}>
            Select any threat in the <strong>Threat Register</strong> and click{' '}
            <strong style={{ color: '#38bdf8' }}>"Provenance"</strong> to view its complete audit lineage:
            from the underlying architecture facts down to verification test evidence.
          </p>
        </div>
      </div>
    );
  }

  const getNodeColor = (type: string) => {
    switch (type) {
      case 'architecture_fact':
        return '#38bdf8';
      case 'threat_instance':
        return '#f43f5e';
      case 'review_decision':
        return '#f59e0b';
      case 'mitigation':
        return '#10b981';
      case 'verification_test':
        return '#8b5cf6';
      case 'evidence':
        return '#06b6d4';
      case 'residual_risk':
        return '#ec4899';
      default:
        return '#94a3b8';
    }
  };

  const getNodeIcon = (type: string) => {
    switch (type) {
      case 'architecture_fact':
        return <Activity size={16} color="#38bdf8" />;
      case 'threat_instance':
        return <ShieldAlert size={16} color="#f43f5e" />;
      case 'review_decision':
        return <UserCheck size={16} color="#f59e0b" />;
      case 'mitigation':
        return <CheckCircle size={16} color="#10b981" />;
      case 'verification_test':
        return <FileCheck2 size={16} color="#8b5cf6" />;
      case 'evidence':
        return <Terminal size={16} color="#06b6d4" />;
      case 'residual_risk':
        return <Layers size={16} color="#ec4899" />;
      default:
        return <GitBranch size={16} color="#94a3b8" />;
    }
  };

  return (
    <div style={{ padding: '24px 32px', maxWidth: '1400px', margin: '0 auto' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '24px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <h2 style={{ fontSize: '1.5rem', fontWeight: 700, letterSpacing: '-0.02em', color: '#f8fafc' }}>
              Threat-to-Evidence Provenance Graph
            </h2>
            <span
              className="badge"
              style={{
                background: 'rgba(56, 189, 248, 0.15)',
                color: '#38bdf8',
                border: '1px solid var(--border-accent)',
              }}
            >
              Signature P1 Feature
            </span>
          </div>
          <p style={{ fontSize: '0.875rem', color: '#94a3b8', marginTop: '4px' }}>
            Auditable, typed lineage graph proving why the threat exists, who approved it, and what tests verify its mitigation.
          </p>
        </div>
      </div>

      {/* Main Layout: Node-Link Pipeline + Detail Inspector */}
      <div style={{ display: 'grid', gridTemplateColumns: selectedNode ? '1fr 340px' : '1fr', gap: '20px' }}>
        {/* Node Pipeline Column */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          {graphData.nodes.map((node) => {
            const isSelected = selectedNode?.node_id === node.node_id;
            const borderColor = getNodeColor(node.node_type);

            return (
              <div
                key={node.node_id}
                onClick={() => setSelectedNode(node)}
                className="glass-panel"
                style={{
                  padding: '16px 20px',
                  cursor: 'pointer',
                  borderLeft: `4px solid ${borderColor}`,
                  background: isSelected ? 'rgba(23, 36, 65, 0.95)' : undefined,
                  boxShadow: isSelected ? `0 0 16px -2px ${borderColor}40` : undefined,
                  transition: 'all 0.2s ease',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                    {getNodeIcon(node.node_type)}
                    <span
                      style={{
                        fontSize: '0.75rem',
                        fontWeight: 600,
                        textTransform: 'uppercase',
                        color: borderColor,
                        letterSpacing: '0.04em',
                      }}
                    >
                      {node.node_type.replace('_', ' ')}
                    </span>
                  </div>

                  <span style={{ fontSize: '0.75rem', color: '#64748b', fontFamily: 'var(--font-mono)' }}>
                    {node.node_id}
                  </span>
                </div>

                <div style={{ fontSize: '0.98rem', fontWeight: 600, color: '#f8fafc', marginTop: '8px' }}>
                  {node.label}
                </div>

                {/* Quick metadata preview */}
                <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', marginTop: '8px' }}>
                  {Object.entries(node.metadata || {}).map(([k, v]) => (
                    <span
                      key={k}
                      style={{
                        fontSize: '0.72rem',
                        background: 'rgba(255, 255, 255, 0.05)',
                        padding: '2px 8px',
                        borderRadius: '4px',
                        color: '#94a3b8',
                      }}
                    >
                      {k}: <strong style={{ color: '#cbd5e1' }}>{String(v)}</strong>
                    </span>
                  ))}
                </div>
              </div>
            );
          })}
        </div>

        {/* Node Inspector Drawer */}
        {selectedNode && (
          <div
            className="glass-panel-glow"
            style={{
              padding: '20px',
              height: 'fit-content',
              position: 'sticky',
              top: '80px',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px' }}>
              <div style={{ fontSize: '0.8rem', fontWeight: 700, color: '#38bdf8', textTransform: 'uppercase' }}>
                Provenance Node Inspector
              </div>
              <button
                onClick={() => setSelectedNode(null)}
                style={{ background: 'transparent', border: 'none', color: '#94a3b8', cursor: 'pointer' }}
              >
                ✕
              </button>
            </div>

            <h4 style={{ fontSize: '1rem', fontWeight: 600, color: '#f8fafc', marginBottom: '6px' }}>
              {selectedNode.label}
            </h4>
            <div style={{ fontSize: '0.78rem', color: '#94a3b8', marginBottom: '16px' }}>
              Type: {selectedNode.node_type}
            </div>

            <div style={{ fontSize: '0.8rem', fontWeight: 600, color: '#cbd5e1', marginBottom: '8px' }}>
              Node Metadata & Audit Fields
            </div>

            <div
              style={{
                background: '#090e1a',
                borderRadius: '8px',
                padding: '12px',
                fontSize: '0.75rem',
                fontFamily: 'var(--font-mono)',
                color: '#38bdf8',
                display: 'flex',
                flexDirection: 'column',
                gap: '6px',
              }}
            >
              {Object.entries(selectedNode.metadata || {}).map(([k, v]) => (
                <div key={k}>
                  <span style={{ color: '#94a3b8' }}>{k}:</span> {JSON.stringify(v)}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
