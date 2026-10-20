import React, { useState } from 'react';
import {
  FileCheck2,
  Terminal,
  CheckCircle,
  XCircle,
  Send,
  ShieldCheck,
} from 'lucide-react';
import type { MitigationRecord } from '../types/threatforge';

interface VerificationTrackerProps {
  mitigations: MitigationRecord[];
  onExecuteTest: (mitigationId: string, testId: string, status: 'PASSED' | 'FAILED', notes: string) => void;
  onSubmitEvidence: (
    mitigationId: string,
    evidenceType: string,
    summary: string,
    environment: string,
    commitSha: string,
    logOutput: string
  ) => void;
}

export const VerificationTracker: React.FC<VerificationTrackerProps> = ({
  mitigations,
  onExecuteTest,
  onSubmitEvidence,
}) => {
  const [selectedMitigationId, setSelectedMitigationId] = useState<string | null>(
    mitigations.length > 0 ? mitigations[0].id : null
  );

  // Evidence modal state
  const [evidenceModalMitigation, setEvidenceModalMitigation] = useState<MitigationRecord | null>(null);
  const [evType, setEvType] = useState<string>('ci_pipeline');
  const [evSummary, setEvSummary] = useState<string>('Passed automated integration security tests in GitHub Actions');
  const [evEnv, setEvEnv] = useState<string>('staging');
  const [evCommit, setEvCommit] = useState<string>('c9f821b');
  const [evLog, setEvLog] = useState<string>('[INFO] Executing security verification suite...\n[PASS] HTTP 401 challenge verified on /checkout\n[PASS] Bearer token validation enforced\n[EXIT 0]');

  const activeMitigation = mitigations.find((m) => m.id === selectedMitigationId) || mitigations[0];

  const handleTestRun = (testId: string, result: 'PASSED' | 'FAILED') => {
    if (!activeMitigation) return;
    onExecuteTest(
      activeMitigation.id,
      testId,
      result,
      result === 'PASSED'
        ? 'Verified expected security control response in automated test runner'
        : 'Unexpected HTTP status code or assertion failure'
    );
  };

  const handleEvidenceSubmit = () => {
    if (!evidenceModalMitigation) return;
    onSubmitEvidence(
      evidenceModalMitigation.id,
      evType,
      evSummary,
      evEnv,
      evCommit,
      evLog
    );
    setEvidenceModalMitigation(null);
  };

  return (
    <div style={{ padding: '24px 32px', maxWidth: '1400px', margin: '0 auto' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '24px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <h2 style={{ fontSize: '1.5rem', fontWeight: 700, letterSpacing: '-0.02em', color: '#f8fafc' }}>
              Mitigation-to-Test Compiler & Evidence Tracker
            </h2>
            <span
              className="badge"
              style={{
                background: 'rgba(16, 185, 129, 0.15)',
                color: '#34d399',
                border: '1px solid rgba(16, 185, 129, 0.3)',
              }}
            >
              Signature P1 Feature
            </span>
          </div>
          <p style={{ fontSize: '0.875rem', color: '#94a3b8', marginTop: '4px' }}>
            Transforming abstract architectural mitigations into testable specifications with verifiable cryptographic evidence.
          </p>
        </div>
      </div>

      {mitigations.length === 0 ? (
        <div className="glass-panel" style={{ padding: '60px 20px', textAlign: 'center', color: '#94a3b8' }}>
          <FileCheck2 size={48} color="#10b981" style={{ margin: '0 auto 16px', opacity: 0.8 }} />
          <h3 style={{ fontSize: '1.2rem', color: '#f8fafc', fontWeight: 600 }}>No Mitigations Compiled Yet</h3>
          <p style={{ fontSize: '0.875rem', marginTop: '6px' }}>
            Run architecture analysis on the canvas to automatically compile mitigation specifications.
          </p>
        </div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: '320px 1fr', gap: '24px' }}>
          {/* Mitigations Sidebar */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            <div style={{ fontSize: '0.8rem', fontWeight: 600, color: '#94a3b8', textTransform: 'uppercase' }}>
              Compiled Mitigations ({mitigations.length})
            </div>

            {mitigations.map((mit) => {
              const isSelected = activeMitigation?.id === mit.id;
              return (
                <div
                  key={mit.id}
                  onClick={() => setSelectedMitigationId(mit.id)}
                  className="glass-panel"
                  style={{
                    padding: '14px 16px',
                    cursor: 'pointer',
                    background: isSelected ? 'rgba(6, 182, 212, 0.15)' : undefined,
                    borderLeft:
                      mit.status === 'VERIFIED'
                        ? '4px solid #10b981'
                        : mit.status === 'FAILED'
                        ? '4px solid #f43f5e'
                        : mit.status === 'STALE'
                        ? '4px solid #f59e0b'
                        : '4px solid #38bdf8',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <span style={{ fontSize: '0.72rem', color: '#94a3b8', fontFamily: 'var(--font-mono)' }}>
                      {mit.template_id}
                    </span>
                    <span
                      className="badge"
                      style={{
                        fontSize: '0.68rem',
                        background:
                          mit.status === 'VERIFIED'
                            ? 'rgba(16, 185, 129, 0.2)'
                            : mit.status === 'FAILED'
                            ? 'rgba(244, 63, 94, 0.2)'
                            : 'rgba(56, 189, 248, 0.2)',
                        color:
                          mit.status === 'VERIFIED'
                            ? '#34d399'
                            : mit.status === 'FAILED'
                            ? '#fb7185'
                            : '#38bdf8',
                      }}
                    >
                      {mit.status}
                    </span>
                  </div>

                  <div style={{ fontSize: '0.9rem', fontWeight: 600, color: '#f8fafc', marginTop: '6px' }}>
                    {mit.title}
                  </div>

                  <div style={{ fontSize: '0.75rem', color: '#94a3b8', marginTop: '6px' }}>
                    {mit.test_cases?.length || 0} Test Specs • {mit.evidence_records?.length || 0} Evidence
                  </div>
                </div>
              );
            })}
          </div>

          {/* Active Mitigation Details & Test Case Runner */}
          {activeMitigation && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
              {/* Header Box */}
              <div className="glass-panel" style={{ padding: '20px 24px' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <div>
                    <span className="badge" style={{ background: 'rgba(6, 182, 212, 0.2)', color: '#38bdf8' }}>
                      {activeMitigation.template_id} • {activeMitigation.control_type}
                    </span>
                    <h3 style={{ fontSize: '1.25rem', fontWeight: 700, color: '#f8fafc', margin: '8px 0 4px' }}>
                      {activeMitigation.title}
                    </h3>
                    <p style={{ fontSize: '0.85rem', color: '#cbd5e1' }}>
                      {activeMitigation.description}
                    </p>
                  </div>

                  <button
                    onClick={() => setEvidenceModalMitigation(activeMitigation)}
                    className="btn-primary"
                    style={{ whiteSpace: 'nowrap' }}
                  >
                    <Send size={15} /> Submit Verification Evidence
                  </button>
                </div>
              </div>

              {/* Generated Test Specifications */}
              <div>
                <h4 style={{ fontSize: '1rem', fontWeight: 600, color: '#f8fafc', marginBottom: '12px' }}>
                  Executable Test Specifications ({activeMitigation.test_cases.length})
                </h4>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                  {activeMitigation.test_cases.map((tc) => (
                    <div
                      key={tc.id}
                      className="glass-panel"
                      style={{
                        padding: '16px 20px',
                        borderLeft:
                          tc.status === 'PASSED'
                            ? '4px solid #10b981'
                            : tc.status === 'FAILED'
                            ? '4px solid #f43f5e'
                            : '4px solid #64748b',
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                          <span
                            style={{
                              fontSize: '0.75rem',
                              fontFamily: 'var(--font-mono)',
                              color: '#38bdf8',
                              fontWeight: 600,
                            }}
                          >
                            {tc.id}
                          </span>
                          <span style={{ fontSize: '0.95rem', fontWeight: 600, color: '#f8fafc' }}>
                            {tc.title}
                          </span>
                        </div>

                        {/* Status Badge */}
                        <span
                          className="badge"
                          style={{
                            background:
                              tc.status === 'PASSED'
                                ? 'rgba(16, 185, 129, 0.2)'
                                : tc.status === 'FAILED'
                                ? 'rgba(244, 63, 94, 0.2)'
                                : 'rgba(100, 116, 139, 0.2)',
                            color:
                              tc.status === 'PASSED'
                                ? '#34d399'
                                : tc.status === 'FAILED'
                                ? '#fb7185'
                                : '#94a3b8',
                          }}
                        >
                          {tc.status}
                        </span>
                      </div>

                      <div
                        style={{
                          display: 'grid',
                          gridTemplateColumns: '1fr 1fr',
                          gap: '12px',
                          marginTop: '12px',
                          background: '#090e1a',
                          padding: '10px 14px',
                          borderRadius: '6px',
                          fontSize: '0.8rem',
                        }}
                      >
                        <div>
                          <span style={{ color: '#94a3b8' }}>Caller Identity: </span>
                          <code style={{ color: '#38bdf8', fontFamily: 'var(--font-mono)' }}>{tc.identity}</code>
                          <div style={{ marginTop: '4px' }}>
                            <span style={{ color: '#94a3b8' }}>Action: </span>
                            <span style={{ color: '#cbd5e1' }}>{tc.action}</span>
                          </div>
                        </div>

                        <div>
                          <span style={{ color: '#94a3b8' }}>Expected Result: </span>
                          <span style={{ color: '#34d399', fontWeight: 500 }}>{tc.expected_result}</span>
                          {tc.actual_result && (
                            <div style={{ marginTop: '4px' }}>
                              <span style={{ color: '#94a3b8' }}>Actual: </span>
                              <span style={{ color: tc.status === 'PASSED' ? '#34d399' : '#fb7185' }}>
                                {tc.actual_result}
                              </span>
                            </div>
                          )}
                        </div>
                      </div>

                      {/* Simulate Test Buttons */}
                      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px', marginTop: '12px' }}>
                        <button
                          onClick={() => handleTestRun(tc.id, 'PASSED')}
                          className="btn-secondary"
                          style={{ fontSize: '0.75rem', padding: '5px 10px', color: '#34d399' }}
                        >
                          <CheckCircle size={14} /> Mark Test Passed
                        </button>
                        <button
                          onClick={() => handleTestRun(tc.id, 'FAILED')}
                          className="btn-secondary"
                          style={{ fontSize: '0.75rem', padding: '5px 10px', color: '#fb7185' }}
                        >
                          <XCircle size={14} /> Mark Test Failed
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Attached Evidence Records */}
              {activeMitigation.evidence_records?.length > 0 && (
                <div>
                  <h4 style={{ fontSize: '1rem', fontWeight: 600, color: '#f8fafc', marginBottom: '12px' }}>
                    Cryptographic Evidence Trail ({activeMitigation.evidence_records.length})
                  </h4>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                    {activeMitigation.evidence_records.map((ev, i) => (
                      <div
                        key={i}
                        className="glass-panel"
                        style={{ padding: '14px 18px', borderLeft: '4px solid #06b6d4' }}
                      >
                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                          <span style={{ fontWeight: 600, color: '#f8fafc', fontSize: '0.88rem' }}>
                            {ev.summary}
                          </span>
                          <span className="badge" style={{ background: 'rgba(6, 182, 212, 0.2)', color: '#38bdf8' }}>
                            {ev.environment}
                          </span>
                        </div>

                        <div style={{ display: 'flex', gap: '16px', fontSize: '0.75rem', color: '#94a3b8', marginTop: '6px' }}>
                          <span>Commit: <code style={{ color: '#38bdf8', fontFamily: 'var(--font-mono)' }}>{ev.commit_sha || 'N/A'}</code></span>
                          <span>Recorded by: {ev.recorded_by}</span>
                          <span>Timestamp: {new Date(ev.created_at).toLocaleString()}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Evidence Submission Modal */}
      {evidenceModalMitigation && (
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
            style={{ width: 560, padding: '24px', background: '#0d1527' }}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontWeight: 700, fontSize: '1.1rem' }}>
                <Terminal size={20} color="#06b6d4" />
                <span>Submit Verification Evidence</span>
              </div>
              <button
                onClick={() => setEvidenceModalMitigation(null)}
                style={{ background: 'transparent', border: 'none', color: '#94a3b8', cursor: 'pointer' }}
              >
                ✕
              </button>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
              <div>
                <label style={{ fontSize: '0.75rem', color: '#cbd5e1', fontWeight: 600, display: 'block', marginBottom: '4px' }}>
                  Evidence Type
                </label>
                <select
                  value={evType}
                  onChange={(e) => setEvType(e.target.value)}
                  style={{
                    width: '100%',
                    background: '#070b14',
                    color: '#f8fafc',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: '6px',
                    padding: '8px',
                    fontSize: '0.85rem',
                  }}
                >
                  <option value="ci_pipeline">Automated CI/CD Pipeline Artifact</option>
                  <option value="pen_test">Independent Penetration Test Signoff</option>
                  <option value="code_review">Peer Architecture Review</option>
                  <option value="production_telemetry">Live Production Telemetry / WAF Log</option>
                </select>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                <div>
                  <label style={{ fontSize: '0.75rem', color: '#cbd5e1', fontWeight: 600, display: 'block', marginBottom: '4px' }}>
                    Environment
                  </label>
                  <input
                    type="text"
                    value={evEnv}
                    onChange={(e) => setEvEnv(e.target.value)}
                    style={{
                      width: '100%',
                      background: '#070b14',
                      color: '#f8fafc',
                      border: '1px solid var(--border-subtle)',
                      borderRadius: '6px',
                      padding: '8px',
                      fontSize: '0.85rem',
                    }}
                  />
                </div>
                <div>
                  <label style={{ fontSize: '0.75rem', color: '#cbd5e1', fontWeight: 600, display: 'block', marginBottom: '4px' }}>
                    Commit SHA
                  </label>
                  <input
                    type="text"
                    value={evCommit}
                    onChange={(e) => setEvCommit(e.target.value)}
                    style={{
                      width: '100%',
                      background: '#070b14',
                      color: '#f8fafc',
                      border: '1px solid var(--border-subtle)',
                      borderRadius: '6px',
                      padding: '8px',
                      fontSize: '0.85rem',
                    }}
                  />
                </div>
              </div>

              <div>
                <label style={{ fontSize: '0.75rem', color: '#cbd5e1', fontWeight: 600, display: 'block', marginBottom: '4px' }}>
                  Execution Summary
                </label>
                <input
                  type="text"
                  value={evSummary}
                  onChange={(e) => setEvSummary(e.target.value)}
                  style={{
                    width: '100%',
                    background: '#070b14',
                    color: '#f8fafc',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: '6px',
                    padding: '8px',
                    fontSize: '0.85rem',
                  }}
                />
              </div>

              <div>
                <label style={{ fontSize: '0.75rem', color: '#cbd5e1', fontWeight: 600, display: 'block', marginBottom: '4px' }}>
                  Raw Test Log Output
                </label>
                <textarea
                  value={evLog}
                  onChange={(e) => setEvLog(e.target.value)}
                  rows={3}
                  style={{
                    width: '100%',
                    background: '#070b14',
                    color: '#34d399',
                    fontFamily: 'var(--font-mono)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: '6px',
                    padding: '8px',
                    fontSize: '0.75rem',
                  }}
                />
              </div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px', marginTop: '20px' }}>
              <button onClick={() => setEvidenceModalMitigation(null)} className="btn-secondary">
                Cancel
              </button>
              <button onClick={handleEvidenceSubmit} className="btn-primary">
                <ShieldCheck size={16} /> Attach Evidence & Verify
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
