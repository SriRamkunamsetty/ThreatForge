import React from 'react';
import {
  Compass,
  ArrowRight,
  Unlock,
} from 'lucide-react';
import type { AttackPath } from '../types/threatforge';

interface AttackPathsViewProps {
  paths: AttackPath[];
}

export const AttackPathsView: React.FC<AttackPathsViewProps> = ({
  paths,
}) => {
  return (
    <div style={{ padding: '24px 32px', maxWidth: '1400px', margin: '0 auto' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '24px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <h2 style={{ fontSize: '1.5rem', fontWeight: 700, letterSpacing: '-0.02em', color: '#f8fafc' }}>
              Ingress-to-Asset Attack Path Analysis
            </h2>
            <span
              className="badge"
              style={{
                background: 'rgba(236, 72, 153, 0.15)',
                color: '#f472b6',
                border: '1px solid rgba(236, 72, 153, 0.3)',
              }}
            >
              NetworkX Graph Traversal
            </span>
          </div>
          <p style={{ fontSize: '0.875rem', color: '#94a3b8', marginTop: '4px' }}>
            Identifies directed graph traversal pathways from public entry points to high-value data stores and autonomous agents.
          </p>
        </div>
      </div>

      {paths.length === 0 ? (
        <div className="glass-panel" style={{ padding: '60px 20px', textAlign: 'center', color: '#94a3b8' }}>
          <Compass size={48} color="#06b6d4" style={{ margin: '0 auto 16px', opacity: 0.8 }} />
          <h3 style={{ fontSize: '1.2rem', color: '#f8fafc', fontWeight: 600 }}>No Attack Paths Found</h3>
          <p style={{ fontSize: '0.875rem', marginTop: '6px' }}>
            No viable directed paths from external entry points to sensitive stores were detected on the current canvas.
          </p>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          {paths.map((path) => (
            <div
              key={path.path_id}
              className="glass-panel"
              style={{
                padding: '20px 24px',
                borderLeft:
                  path.risk_score >= 80
                    ? '4px solid #f43f5e'
                    : path.risk_score >= 50
                    ? '4px solid #f59e0b'
                    : '4px solid #10b981',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                  <span
                    className="badge"
                    style={{
                      background:
                        path.risk_score >= 80
                          ? 'rgba(244, 63, 94, 0.2)'
                          : 'rgba(245, 158, 11, 0.2)',
                      color: path.risk_score >= 80 ? '#fb7185' : '#fbbf24',
                      fontWeight: 700,
                    }}
                  >
                    Risk Score: {path.risk_score} / 100
                  </span>

                  <span style={{ fontSize: '1rem', fontWeight: 600, color: '#f8fafc' }}>
                    {path.entry_point_name}
                  </span>
                  <ArrowRight size={16} color="#38bdf8" />
                  <span style={{ fontSize: '1rem', fontWeight: 600, color: '#38bdf8' }}>
                    {path.target_asset_name}
                  </span>
                </div>

                <div style={{ display: 'flex', gap: '16px', fontSize: '0.8rem', color: '#94a3b8' }}>
                  <span>{path.hop_count} Hops</span>
                  <span>{path.boundary_crossings} Boundary Crossings</span>
                  {path.unencrypted_hops > 0 && (
                    <span style={{ color: '#fb7185', display: 'flex', alignItems: 'center', gap: '4px' }}>
                      <Unlock size={13} /> {path.unencrypted_hops} Unencrypted
                    </span>
                  )}
                </div>
              </div>

              <p style={{ fontSize: '0.85rem', color: '#cbd5e1', marginTop: '10px' }}>
                {path.description}
              </p>

              {/* Step Sequence visualization */}
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  marginTop: '16px',
                  overflowX: 'auto',
                  paddingBottom: '6px',
                }}
              >
                {path.steps.map((step, idx) => (
                  <React.Fragment key={idx}>
                    <div
                      style={{
                        background: '#090e1a',
                        border: '1px solid var(--border-subtle)',
                        borderRadius: '6px',
                        padding: '8px 12px',
                        minWidth: '150px',
                      }}
                    >
                      <div style={{ fontSize: '0.68rem', color: '#94a3b8' }}>Step {step.step_number}</div>
                      <div style={{ fontSize: '0.82rem', fontWeight: 600, color: '#f8fafc', marginTop: '2px' }}>
                        {step.source_name}
                      </div>
                      <div style={{ fontSize: '0.7rem', color: step.encrypted === false ? '#fb7185' : '#34d399', marginTop: '4px' }}>
                        {step.encrypted === false ? '⚠️ Unencrypted' : '🔒 Encrypted'}
                      </div>
                    </div>
                    {idx < path.steps.length - 1 && <ArrowRight size={14} color="#64748b" />}
                  </React.Fragment>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
