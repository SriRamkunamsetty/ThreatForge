import React from 'react';
import {
  GitCompare,
  AlertOctagon,
  CheckCircle2,
  FileDiff,
  ArrowRight,
  TrendingUp,
} from 'lucide-react';
import type { DriftReport } from '../types/threatforge';

interface DriftDashboardProps {
  driftReport: DriftReport | null;
  hasBaseline: boolean;
  onRefreshDrift: () => void;
}

export const DriftDashboard: React.FC<DriftDashboardProps> = ({
  driftReport,
  hasBaseline,
  onRefreshDrift,
}) => {
  if (!hasBaseline) {
    return (
      <div style={{ padding: '60px 20px', textAlign: 'center', maxWidth: '700px', margin: '40px auto' }}>
        <div className="glass-panel" style={{ padding: '40px 30px' }}>
          <GitCompare size={48} color="#06b6d4" style={{ margin: '0 auto 16px', opacity: 0.8 }} />
          <h3 style={{ fontSize: '1.3rem', fontWeight: 700, color: '#f8fafc' }}>
            No Approved Baseline Established
          </h3>
          <p style={{ fontSize: '0.875rem', color: '#94a3b8', margin: '10px 0 20px', lineHeight: 1.6 }}>
            Architecture Drift Intelligence requires an approved baseline version snapshot to compare against.
            Head to the <strong>Architecture Canvas</strong>, set up your initial approved architecture, and click{' '}
            <strong style={{ color: '#38bdf8' }}>"Set as Approved Baseline"</strong>.
          </p>
        </div>
      </div>
    );
  }

  if (!driftReport) {
    return (
      <div style={{ padding: '40px 20px', textAlign: 'center', color: '#94a3b8' }}>
        <button onClick={onRefreshDrift} className="btn-primary">
          <GitCompare size={16} /> Compute Architecture Drift
        </button>
      </div>
    );
  }

  const scorePct = Math.round(driftReport.security_relevance_score * 100);

  return (
    <div style={{ padding: '24px 32px', maxWidth: '1400px', margin: '0 auto' }}>
      {/* Top Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '24px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <h2 style={{ fontSize: '1.5rem', fontWeight: 700, letterSpacing: '-0.02em', color: '#f8fafc' }}>
              Architecture Drift Intelligence
            </h2>
            <span
              className="badge"
              style={{
                background: 'rgba(6, 182, 212, 0.15)',
                color: '#38bdf8',
                border: '1px solid var(--border-accent)',
              }}
            >
              Signature P1 Feature
            </span>
          </div>
          <p style={{ fontSize: '0.875rem', color: '#94a3b8', marginTop: '4px' }}>
            Semantic graph diff tracking structural topology and attribute posture alterations between versions.
          </p>
        </div>

        <button onClick={onRefreshDrift} className="btn-secondary">
          <GitCompare size={15} /> Re-evaluate Drift
        </button>
      </div>

      {/* Security Relevance & Status Overview */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
          gap: '16px',
          marginBottom: '24px',
        }}
      >
        {/* Score Card */}
        <div className="glass-panel" style={{ padding: '20px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '0.85rem', color: '#94a3b8', fontWeight: 500 }}>
              Security Relevance Score
            </span>
            <TrendingUp size={18} color="#06b6d4" />
          </div>
          <div style={{ display: 'flex', alignItems: 'baseline', gap: '8px', marginTop: '10px' }}>
            <span
              style={{
                fontSize: '2.4rem',
                fontWeight: 800,
                color: scorePct > 60 ? '#f43f5e' : scorePct > 20 ? '#f59e0b' : '#10b981',
              }}
            >
              {scorePct}%
            </span>
            <span style={{ fontSize: '0.8rem', color: '#94a3b8' }}>
              {scorePct > 60 ? 'High Impact' : scorePct > 20 ? 'Moderate Impact' : 'Low Impact'}
            </span>
          </div>
        </div>

        {/* Review Requirement Card */}
        <div className="glass-panel" style={{ padding: '20px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '0.85rem', color: '#94a3b8', fontWeight: 500 }}>
              Review Requirement
            </span>
            {driftReport.requires_review ? (
              <AlertOctagon size={18} color="#f43f5e" />
            ) : (
              <CheckCircle2 size={18} color="#10b981" />
            )}
          </div>
          <div style={{ marginTop: '10px' }}>
            {driftReport.requires_review ? (
              <div
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '6px',
                  color: '#fb7185',
                  fontWeight: 700,
                  fontSize: '1.1rem',
                }}
              >
                MANDATORY SECURITY REVIEW REQUIRED
              </div>
            ) : (
              <div
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '6px',
                  color: '#34d399',
                  fontWeight: 700,
                  fontSize: '1.1rem',
                }}
              >
                AUTOMATIC GATING PASSED
              </div>
            )}
            <p style={{ fontSize: '0.78rem', color: '#94a3b8', marginTop: '4px' }}>
              {driftReport.requires_review
                ? 'Critical security attributes or boundary crossings modified.'
                : 'No high-risk posture changes detected.'}
            </p>
          </div>
        </div>

        {/* Threat Delta Summary */}
        <div className="glass-panel" style={{ padding: '20px' }}>
          <span style={{ fontSize: '0.85rem', color: '#94a3b8', fontWeight: 500 }}>
            Threat Delta Dynamics
          </span>
          <div style={{ display: 'flex', gap: '20px', marginTop: '12px' }}>
            <div>
              <div style={{ fontSize: '1.6rem', fontWeight: 700, color: '#f43f5e' }}>
                +{driftReport.newly_applicable_threats.length}
              </div>
              <div style={{ fontSize: '0.75rem', color: '#94a3b8' }}>Newly Applicable</div>
            </div>
            <div>
              <div style={{ fontSize: '1.6rem', fontWeight: 700, color: '#10b981' }}>
                -{driftReport.invalidated_threats.length}
              </div>
              <div style={{ fontSize: '0.75rem', color: '#94a3b8' }}>Invalidated Threats</div>
            </div>
          </div>
        </div>
      </div>

      {/* Semantic Changes List */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
        <h3 style={{ fontSize: '1.1rem', fontWeight: 600, color: '#f8fafc' }}>
          Semantic Graph Changes ({driftReport.changes.length})
        </h3>

        {driftReport.changes.length === 0 ? (
          <div className="glass-panel" style={{ padding: '30px', textAlign: 'center', color: '#94a3b8' }}>
            No structural or attribute drift detected. Canvas matches baseline snapshot.
          </div>
        ) : (
          driftReport.changes.map((change, idx) => (
            <div
              key={idx}
              className="glass-panel"
              style={{
                padding: '16px 20px',
                borderLeft:
                  change.security_relevance === 'HIGH'
                    ? '4px solid #f43f5e'
                    : change.security_relevance === 'MEDIUM'
                    ? '4px solid #f59e0b'
                    : '4px solid #10b981',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <span
                    className="badge"
                    style={{
                      background:
                        change.change_type === 'ADDED'
                          ? 'rgba(16, 185, 129, 0.2)'
                          : change.change_type === 'REMOVED'
                          ? 'rgba(244, 63, 94, 0.2)'
                          : 'rgba(56, 189, 248, 0.2)',
                      color:
                        change.change_type === 'ADDED'
                          ? '#34d399'
                          : change.change_type === 'REMOVED'
                          ? '#fb7185'
                          : '#38bdf8',
                    }}
                  >
                    {change.change_type}
                  </span>

                  <span style={{ fontSize: '0.95rem', fontWeight: 600, color: '#f8fafc' }}>
                    {change.entity_name} ({change.entity_type})
                  </span>

                  <span
                    className={`badge ${
                      change.security_relevance === 'HIGH'
                        ? 'badge-high'
                        : change.security_relevance === 'MEDIUM'
                        ? 'badge-medium'
                        : 'badge-low'
                    }`}
                  >
                    {change.security_relevance} RELEVANCE
                  </span>
                </div>

                {change.requires_review && (
                  <span
                    className="badge"
                    style={{ background: 'rgba(244, 63, 94, 0.2)', color: '#fb7185' }}
                  >
                    Requires Signoff
                  </span>
                )}
              </div>

              <p style={{ fontSize: '0.85rem', color: '#cbd5e1', marginTop: '8px' }}>
                {change.threat_impact}
              </p>

              {/* Attribute level deltas */}
              {change.attribute_deltas?.length > 0 && (
                <div
                  style={{
                    marginTop: '10px',
                    padding: '10px',
                    background: '#090e1a',
                    borderRadius: '6px',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '6px',
                  }}
                >
                  {change.attribute_deltas.map((ad, i) => (
                    <div
                      key={i}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        fontSize: '0.8rem',
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <FileDiff size={14} color="#f59e0b" />
                        <span style={{ color: '#cbd5e1', fontWeight: 500 }}>{ad.attribute}:</span>
                        <span style={{ color: '#fb7185', textDecoration: 'line-through' }}>
                          {String(ad.old)}
                        </span>
                        <ArrowRight size={12} color="#94a3b8" />
                        <span style={{ color: '#34d399', fontWeight: 600 }}>{String(ad.new)}</span>
                      </div>
                      <span style={{ color: '#94a3b8', fontSize: '0.75rem' }}>{ad.rationale}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          ))
        )}
      </div>
    </div>
  );
};
