import React, { useState } from 'react';
import {
  AlertTriangle,
  CheckCircle,
  HelpCircle,
  Shield,
  GitBranch,
  FileCheck2,
  Filter,
  Check,
  X,
} from 'lucide-react';
import type { ThreatSummary } from '../types/threatforge';

interface ThreatRegisterProps {
  threats: ThreatSummary[];
  onSelectThreatForProvenance: (threatId: string) => void;
  onNavigateToVerification: (threatId: string) => void;
  onReviewDecision: (threatId: string, decision: 'APPROVED' | 'REJECTED' | 'ACCEPTED_RISK', rationale: string) => void;
}

export const ThreatRegister: React.FC<ThreatRegisterProps> = ({
  threats,
  onSelectThreatForProvenance,
  onNavigateToVerification,
  onReviewDecision,
}) => {
  const [filterApplicability, setFilterApplicability] = useState<string>('ALL');
  const [filterCategory, setFilterCategory] = useState<string>('ALL');
  const [expandedThreatId, setExpandedThreatId] = useState<string | null>(null);
  const [reviewModalThreat, setReviewModalThreat] = useState<ThreatSummary | null>(null);
  const [reviewDecision, setReviewDecision] = useState<'APPROVED' | 'REJECTED' | 'ACCEPTED_RISK'>('APPROVED');
  const [reviewRationale, setReviewRationale] = useState<string>('');
  const [rationaleError, setRationaleError] = useState<string | null>(null);

  const categories = Array.from(new Set(threats.map((t) => t.category)));

  const filteredThreats = threats.filter((t) => {
    if (filterApplicability !== 'ALL' && t.applicability !== filterApplicability) {
      return false;
    }
    if (filterCategory !== 'ALL' && t.category !== filterCategory) {
      return false;
    }
    return true;
  });

  const handleOpenReview = (threat: ThreatSummary) => {
    setReviewModalThreat(threat);
    setReviewRationale('');
    setRationaleError(null);
  };

  const handleSubmitReview = () => {
    if (!reviewRationale || reviewRationale.trim().length < 5) {
      setRationaleError('A meaningful rationale (minimum 5 characters) is mandatory. No silent approvals.');
      return;
    }
    if (reviewModalThreat) {
      onReviewDecision(reviewModalThreat.threat_id, reviewDecision, reviewRationale.trim());
      setReviewModalThreat(null);
    }
  };

  return (
    <div style={{ padding: '24px 32px', maxWidth: '1400px', margin: '0 auto' }}>
      {/* Top Banner & Filters */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '20px' }}>
        <div>
          <h2 style={{ fontSize: '1.5rem', fontWeight: 700, letterSpacing: '-0.02em', color: '#f8fafc' }}>
            Explainable Threat Register
          </h2>
          <p style={{ fontSize: '0.875rem', color: '#94a3b8', marginTop: '4px' }}>
            Every threat carries verified architecture facts, confidence ratings, and testable mitigations.
          </p>
        </div>

        {/* Filter Bar */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <Filter size={15} color="#94a3b8" />
            <select
              value={filterApplicability}
              onChange={(e) => setFilterApplicability(e.target.value)}
              style={{
                background: '#090e1a',
                color: '#f8fafc',
                border: '1px solid var(--border-subtle)',
                borderRadius: '6px',
                padding: '6px 12px',
                fontSize: '0.85rem',
                outline: 'none',
              }}
            >
              <option value="ALL">All Statuses ({threats.length})</option>
              <option value="APPLICABLE">Applicable ({threats.filter((t) => t.applicability === 'APPLICABLE').length})</option>
              <option value="NEEDS_REVIEW">Needs Review ({threats.filter((t) => t.applicability === 'NEEDS_REVIEW').length})</option>
              <option value="NOT_APPLICABLE">Not Applicable ({threats.filter((t) => t.applicability === 'NOT_APPLICABLE').length})</option>
            </select>
          </div>

          <select
            value={filterCategory}
            onChange={(e) => setFilterCategory(e.target.value)}
            style={{
              background: '#090e1a',
              color: '#f8fafc',
              border: '1px solid var(--border-subtle)',
              borderRadius: '6px',
              padding: '6px 12px',
              fontSize: '0.85rem',
              outline: 'none',
            }}
          >
            <option value="ALL">All Categories</option>
            {categories.map((c) => (
              <option key={c} value={c}>
                {c}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Threat List */}
      {filteredThreats.length === 0 ? (
        <div
          className="glass-panel"
          style={{ padding: '60px 20px', textAlign: 'center', color: '#94a3b8' }}
        >
          <Shield size={48} color="#10b981" style={{ margin: '0 auto 16px', opacity: 0.8 }} />
          <h3 style={{ fontSize: '1.2rem', color: '#f8fafc', fontWeight: 600 }}>Zero Threats Found</h3>
          <p style={{ fontSize: '0.875rem', marginTop: '6px' }}>
            No threats match the current filters or the architecture has been fully mitigated.
          </p>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
          {filteredThreats.map((threat) => {
            const isExpanded = expandedThreatId === threat.threat_id;
            return (
              <div
                key={threat.threat_id}
                className="glass-panel"
                style={{
                  padding: '18px 22px',
                  transition: 'all 0.2s ease',
                  borderLeft:
                    threat.applicability === 'APPLICABLE'
                      ? '4px solid #f43f5e'
                      : threat.applicability === 'NEEDS_REVIEW'
                      ? '4px solid #f59e0b'
                      : '4px solid #10b981',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
                  <div style={{ flex: 1 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
                      <span
                        className={`badge ${
                          threat.applicability === 'APPLICABLE'
                            ? 'badge-applicable'
                            : threat.applicability === 'NEEDS_REVIEW'
                            ? 'badge-needs-review'
                            : 'badge-not-applicable'
                        }`}
                      >
                        {threat.applicability === 'APPLICABLE' && <AlertTriangle size={12} />}
                        {threat.applicability === 'NEEDS_REVIEW' && <HelpCircle size={12} />}
                        {threat.applicability === 'NOT_APPLICABLE' && <CheckCircle size={12} />}
                        {threat.applicability.replace('_', ' ')}
                      </span>

                      <span className="badge" style={{ background: 'rgba(56, 189, 248, 0.15)', color: '#38bdf8' }}>
                        {threat.rule_id}
                      </span>

                      <span className="badge" style={{ background: 'rgba(139, 92, 246, 0.15)', color: '#c084fc' }}>
                        {threat.category}
                      </span>

                      <span className="badge badge-high" style={{ fontSize: '0.7rem' }}>
                        Confidence: {threat.confidence}
                      </span>

                      <span style={{ fontSize: '0.8rem', color: '#94a3b8' }}>
                        Target: <strong style={{ color: '#f8fafc' }}>{threat.component_name}</strong>
                      </span>
                    </div>

                    <h3
                      style={{
                        fontSize: '1.05rem',
                        fontWeight: 600,
                        color: '#f8fafc',
                        margin: '10px 0 6px',
                        cursor: 'pointer',
                      }}
                      onClick={() => setExpandedThreatId(isExpanded ? null : threat.threat_id)}
                    >
                      {threat.title}
                    </h3>

                    <p style={{ fontSize: '0.875rem', color: '#cbd5e1', lineHeight: 1.5 }}>
                      {threat.description}
                    </p>
                  </div>

                  {/* Actions */}
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginLeft: '16px' }}>
                    <button
                      onClick={() => onSelectThreatForProvenance(threat.threat_id)}
                      className="btn-secondary"
                      style={{ fontSize: '0.75rem', padding: '6px 10px' }}
                      title="Inspect Threat-to-Evidence Provenance Graph"
                    >
                      <GitBranch size={14} color="#38bdf8" /> Provenance
                    </button>

                    <button
                      onClick={() => handleOpenReview(threat)}
                      className="btn-secondary"
                      style={{ fontSize: '0.75rem', padding: '6px 10px' }}
                      title="Review Decision Workflow"
                    >
                      <Shield size={14} color="#f59e0b" /> Review
                    </button>

                    {threat.mitigation_templates?.length > 0 && (
                      <button
                        onClick={() => onNavigateToVerification(threat.threat_id)}
                        className="btn-primary"
                        style={{ fontSize: '0.75rem', padding: '6px 10px' }}
                        title="View Mitigation Verification Tests"
                      >
                        <FileCheck2 size={14} /> Test Specs
                      </button>
                    )}
                  </div>
                </div>

                {/* Expanded Explainability Details */}
                {isExpanded && (
                  <div
                    style={{
                      marginTop: '16px',
                      paddingTop: '16px',
                      borderTop: '1px solid var(--border-subtle)',
                      display: 'grid',
                      gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
                      gap: '16px',
                    }}
                  >
                    {/* Architecture Facts */}
                    <div style={{ background: '#090e1a', padding: '12px 16px', borderRadius: '8px' }}>
                      <div style={{ fontSize: '0.8rem', fontWeight: 600, color: '#38bdf8', marginBottom: '8px' }}>
                        Architecture Facts (Justification)
                      </div>
                      {threat.architecture_facts.length === 0 ? (
                        <span style={{ fontSize: '0.75rem', color: '#64748b' }}>No direct facts recorded</span>
                      ) : (
                        <ul style={{ paddingLeft: '16px', fontSize: '0.78rem', color: '#cbd5e1', lineHeight: 1.6 }}>
                          {threat.architecture_facts.map((fact, i) => (
                            <li key={i}>{fact.description}</li>
                          ))}
                        </ul>
                      )}
                    </div>

                    {/* Missing Facts (What we don't know yet) */}
                    <div style={{ background: '#090e1a', padding: '12px 16px', borderRadius: '8px' }}>
                      <div style={{ fontSize: '0.8rem', fontWeight: 600, color: '#fbbf24', marginBottom: '8px' }}>
                        Missing Facts (Uncertainty)
                      </div>
                      {threat.missing_facts.length === 0 ? (
                        <span style={{ fontSize: '0.75rem', color: '#64748b' }}>No missing facts identified</span>
                      ) : (
                        <ul style={{ paddingLeft: '16px', fontSize: '0.78rem', color: '#fde68a', lineHeight: 1.6 }}>
                          {threat.missing_facts.map((mf, i) => (
                            <li key={i}>{mf}</li>
                          ))}
                        </ul>
                      )}
                    </div>

                    {/* Mitigations */}
                    <div style={{ background: '#090e1a', padding: '12px 16px', borderRadius: '8px' }}>
                      <div style={{ fontSize: '0.8rem', fontWeight: 600, color: '#34d399', marginBottom: '8px' }}>
                        Suggested Mitigations
                      </div>
                      {threat.mitigation_templates.length === 0 ? (
                        <span style={{ fontSize: '0.75rem', color: '#64748b' }}>No mitigation template attached</span>
                      ) : (
                        threat.mitigation_templates.map((m, i) => (
                          <div key={i} style={{ marginBottom: '8px' }}>
                            <div style={{ fontSize: '0.78rem', fontWeight: 600, color: '#f8fafc' }}>
                              [{m.template_id}] {m.title}
                            </div>
                            <div style={{ fontSize: '0.72rem', color: '#94a3b8', marginTop: '2px' }}>
                              {m.description}
                            </div>
                          </div>
                        ))
                      )}
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* Review Decision Modal */}
      {reviewModalThreat && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(0, 0, 0, 0.75)',
            backdropFilter: 'blur(6px)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 100,
          }}
        >
          <div
            className="glass-panel-glow"
            style={{ width: 520, padding: '24px', background: '#0d1527', border: '1px solid var(--border-accent)' }}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontWeight: 700, fontSize: '1.1rem' }}>
                <Shield size={20} color="#f59e0b" />
                <span>Review Decision Workflow</span>
              </div>
              <button
                onClick={() => setReviewModalThreat(null)}
                style={{ background: 'transparent', border: 'none', color: '#94a3b8', cursor: 'pointer' }}
              >
                <X size={18} />
              </button>
            </div>

            <div style={{ fontSize: '0.85rem', color: '#cbd5e1', marginBottom: '14px' }}>
              Reviewing: <strong>{reviewModalThreat.title}</strong> on{' '}
              <span style={{ color: '#38bdf8' }}>{reviewModalThreat.component_name}</span>
            </div>

            {/* Decision Radio Selector */}
            <div style={{ display: 'flex', gap: '10px', marginBottom: '16px' }}>
              {(['APPROVED', 'REJECTED', 'ACCEPTED_RISK'] as const).map((dec) => (
                <button
                  key={dec}
                  onClick={() => setReviewDecision(dec)}
                  style={{
                    flex: 1,
                    padding: '8px 12px',
                    borderRadius: '8px',
                    fontSize: '0.78rem',
                    fontWeight: 600,
                    border: reviewDecision === dec ? '1px solid #38bdf8' : '1px solid var(--border-subtle)',
                    background: reviewDecision === dec ? 'rgba(56, 189, 248, 0.2)' : 'rgba(255, 255, 255, 0.04)',
                    color: reviewDecision === dec ? '#38bdf8' : '#94a3b8',
                    cursor: 'pointer',
                  }}
                >
                  {dec.replace('_', ' ')}
                </button>
              ))}
            </div>

            {/* Mandatory Rationale Textarea */}
            <div style={{ marginBottom: '16px' }}>
              <label style={{ fontSize: '0.78rem', color: '#cbd5e1', fontWeight: 600, display: 'block', marginBottom: '6px' }}>
                Mandatory Decision Rationale <span style={{ color: '#f43f5e' }}>*</span>
              </label>
              <textarea
                value={reviewRationale}
                onChange={(e) => {
                  setReviewRationale(e.target.value);
                  setRationaleError(null);
                }}
                rows={3}
                placeholder="Provide architectural justification or risk acceptance reasoning (min 5 chars)..."
                style={{
                  width: '100%',
                  background: '#070b14',
                  color: '#f8fafc',
                  border: rationaleError ? '1px solid #f43f5e' : '1px solid var(--border-subtle)',
                  borderRadius: '6px',
                  padding: '10px',
                  fontSize: '0.85rem',
                  outline: 'none',
                  resize: 'vertical',
                }}
              />
              {rationaleError && (
                <div style={{ fontSize: '0.75rem', color: '#fb7185', marginTop: '4px' }}>
                  {rationaleError}
                </div>
              )}
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px' }}>
              <button onClick={() => setReviewModalThreat(null)} className="btn-secondary">
                Cancel
              </button>
              <button onClick={handleSubmitReview} className="btn-primary">
                <Check size={16} /> Submit Audited Decision
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
