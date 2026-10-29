import { useEffect, useMemo, useState } from 'react';
import {
  useGetCurrentIncident,
  getGetCurrentIncidentQueryKey,
  useGetIncidentRemediations,
  getGetIncidentRemediationsQueryKey,
  useSimulateContainment,
  useRunAiIncidentInvestigation,
} from '@workspace/api-client-react';
import type { AiInvestigationResponse, AuditEvent, AttackPath, IncidentSnapshot, RemediationAction, VerificationReport } from '@workspace/api-client-react';
import {
  Activity, AlertTriangle, ArrowDown, ArrowRight, Check, CheckCircle2,
  ChevronDown, CircleDot, Clock3, Database, Fingerprint, KeyRound,
  LockKeyhole, Network, RotateCcw, Shield, ShieldAlert, ShieldCheck,
  UserRound, Workflow, X, BrainCircuit, Cpu, FileSearch, FlaskConical,
  ListChecks, ScanSearch,
} from 'lucide-react';

type ActionId = 'revoke-user-session' | 'restrict-admin-role' | 'revoke-app-consent';

const actionOrder: ActionId[] = [
  'revoke-user-session',
  'restrict-admin-role',
  'revoke-app-consent',
];

function timeLabel(value: string) {
  const date = new Date(value);
  return Number.isNaN(date.valueOf())
    ? value
    : new Intl.DateTimeFormat('en', { dateStyle: 'medium', timeStyle: 'medium', timeZone: 'UTC' }).format(date) + ' UTC';
}

function Skeleton() {
  return <div className="shell"><aside className="sidebar"><div className="brand-mark">T</div><div className="skeleton-line wide" /><div className="skeleton-line" /></aside><main className="main"><div className="skeleton-hero" /><div className="skeleton-panel" /><div className="skeleton-panel" /></main></div>;
}

function NodeGlyph({ kind }: { kind: string }) {
  if (kind === 'user') return <UserRound size={17} />;
  if (kind === 'service') return <Fingerprint size={17} />;
  if (kind === 'role') return <KeyRound size={17} />;
  return <Database size={17} />;
}

function EvidenceGraph({ snapshot, activePath }: { snapshot: IncidentSnapshot; activePath: AttackPath | null }) {
  const { identities, roles, resources, edges } = snapshot;
  const nodeMap = useMemo(() => {
    const nodes = new Map<string, { type: string }>();
    identities.forEach((item) => nodes.set(item.id, { type: item.kind }));
    roles.forEach((item) => nodes.set(item.id, { type: 'role' }));
    resources.forEach((item) => nodes.set(item.id, { type: 'resource' }));
    return nodes;
  }, [identities, roles, resources]);
  const focusEdges = activePath ? new Set(activePath.edgeIds) : null;
  const groups: { id: string; name: string; type: string; compromised: boolean; subtitle: string }[][] = [
    identities.map((node) => ({ id: node.id, name: node.name, type: node.kind, compromised: node.compromised, subtitle: node.status })),
    roles.map((node) => ({ id: node.id, name: node.name, type: 'role', compromised: false, subtitle: node.privilege })),
    resources.map((node) => ({ id: node.id, name: node.name, type: 'resource', compromised: false, subtitle: node.sensitivity })),
  ];
  return (
    <div className="graph-wrap" data-testid="graph-incident-paths">
      <div className="graph-legend">
        <span><i className="legend-dot compromised" /> Compromised identity</span>
        <span><i className="legend-dot" /> Access relationship</span>
        <span><i className="legend-dot muted-dot" /> Disabled in source graph</span>
      </div>
      <div className="graph-columns">
        {groups.map((group, column) => (
          <div className={`graph-column graph-column-${column}`} key={column}>
            <span className="graph-column-label">{['IDENTITIES', 'PRIVILEGED ROLES', 'SENSITIVE RESOURCES'][column]}</span>
            {group.map((node) => {
              const involved = activePath?.nodeIds.includes(node.id);
              return <div key={node.id} className={`graph-node ${node.type} ${node.compromised ? 'is-compromised' : ''} ${involved ? 'node-focused' : ''}`} data-testid={`graph-node-${node.id}`}>
                <span className="node-icon"><NodeGlyph kind={node.type} /></span>
                <span className="node-copy"><strong>{node.name}</strong><small>{node.subtitle}</small></span>
                {node.compromised && <span className="node-alert">COMPROMISED</span>}
              </div>;
            })}
          </div>
        ))}
        <div className="graph-connections" aria-hidden="true">
          {edges.map((edge, index) => {
            const source = nodeMap.get(edge.sourceId);
            const target = nodeMap.get(edge.targetId);
            const sourceColumn = source?.type === 'user' || source?.type === 'service' ? 0 : source?.type === 'role' ? 1 : 2;
            const targetColumn = target?.type === 'user' || target?.type === 'service' ? 0 : target?.type === 'role' ? 1 : 2;
            return <div key={edge.id} className={`edge-label ${edge.enabled ? 'edge-on' : 'edge-off'} ${focusEdges?.has(edge.id) ? 'edge-focus' : ''}`} style={{ top: `${62 + index * 66}px`, left: `${sourceColumn * 33.33 + 25}%`, width: `${Math.max(28, (targetColumn - sourceColumn) * 33.33 - 18)}%` }}>
              <span className="edge-rule" /><span className="edge-text">{edge.relationship}</span>
            </div>;
          })}
        </div>
      </div>
      {activePath && <div className="path-focus-note"><CircleDot size={14} /> Highlighting: <strong>{activePath.label}</strong></div>}
    </div>
  );
}

function PathCard({ path, onFocus, focused }: { path: AttackPath; onFocus: () => void; focused: boolean }) {
  return <button className={`path-card ${focused ? 'path-selected' : ''}`} onClick={onFocus} data-testid={`button-path-${path.id}`}>
    <span className="path-icon"><Workflow size={16} /></span>
    <span className="path-text"><strong>{path.label}</strong><small>{path.nodeIds.length} entities · {path.edgeIds.length} relationships</small></span>
    <ArrowRight size={15} className="path-arrow" />
  </button>;
}

function ReportPanel({ report, reportId = 'verification-report', eyebrow = 'SIMULATION RESULT', testId = 'verification-report' }: { report: VerificationReport; reportId?: string; eyebrow?: string; testId?: string }) {
  const contained = report.status === 'verified-contained';
  return <section className={`report-panel ${contained ? 'report-contained' : 'report-incomplete'}`} id={reportId} data-testid={testId}>
    <div className="report-heading">
      <div className={`report-symbol ${contained ? '' : 'symbol-warning'}`}>{contained ? <ShieldCheck size={22} /> : <ShieldAlert size={22} />}</div>
      <div><span className="eyebrow">{eyebrow}</span><h2>{contained ? 'Reachability verified contained' : 'Containment remains incomplete'}</h2><p>{contained ? 'The altered graph has no reachable attack paths under the selected changes.' : 'At least one path to sensitive data is still reachable in the altered graph.'}</p></div>
    </div>
    <div className="report-grid">
      <div className="report-block closed"><span className="report-count">{report.verifiedClosedPaths.length}</span><span className="report-label">Closed paths</span><div className="report-list">{report.verifiedClosedPaths.length ? report.verifiedClosedPaths.map((path) => <span key={path.id}><Check size={13} />{path.label}</span>) : <span className="report-empty">No paths verified closed.</span>}</div></div>
      <div className="report-block remaining"><span className="report-count">{report.remainingReachablePaths.length}</span><span className="report-label">Remaining reachable</span><div className="report-list">{report.remainingReachablePaths.length ? report.remainingReachablePaths.map((path) => <span key={path.id}><ArrowRight size={13} />{path.label}</span>) : <span className="report-empty">No reachable paths reported.</span>}</div></div>
      <div className="report-block findings"><span className="report-count">{report.unresolvedFindings.length}</span><span className="report-label">Unresolved findings</span><div className="report-list">{report.unresolvedFindings.length ? report.unresolvedFindings.map((item, index) => <span key={`${index}-${item}`}><AlertTriangle size={13} />{item}</span>) : <span className="report-empty">No unresolved findings reported.</span>}</div></div>
    </div>
    <div className="report-assumptions"><strong>Simulation limitations</strong><p>These results describe only the copied synthetic graph and stated assumptions. No sessions, roles, consents, or cloud resources were changed.</p>{report.assumptions.length > 0 && <details><summary>Assumptions used ({report.assumptions.length}) <ChevronDown size={14} /></summary><ul>{report.assumptions.map((assumption, index) => <li key={`${index}-${assumption}`}>{assumption}</li>)}</ul></details>}</div>
  </section>;
}

function EvidenceIds({ ids }: { ids: string[] }) {
  return ids.length
    ? <div className="ai-evidence-ids" data-testid="ai-evidence-ids">{ids.map((id) => <code key={id}>{id}</code>)}</div>
    : <span className="ai-no-evidence">No evidence IDs returned</span>;
}

function AiAuditEvent({ event }: { event: AuditEvent }) {
  return <article className="ai-audit-event" data-testid={`ai-inspected-evidence-${event.id}`}>
    <div className="ai-audit-head"><span className="mono">{timeLabel(event.timestamp)}</span><span className={`result-chip ${event.result.toLowerCase().includes('success') || event.result.toLowerCase().includes('allow') ? 'result-success' : ''}`}>{event.result}</span></div>
    <strong>{event.action}</strong>
    <p>{event.summary}</p>
    <div className="ai-audit-meta"><span>Actor <b>{event.actorId}</b></span><span>Target <b>{event.targetId}</b></span><span>Source <b className="mono">{event.sourceIp}</b></span></div>
    <EvidenceIds ids={[event.id]} />
  </article>;
}

function AiInvestigationResults({ result }: { result: AiInvestigationResponse }) {
  return <div className="ai-results" data-testid="ai-investigation-results">
    <div className="ai-results-topline">
      <div><span className="ai-source-label"><BrainCircuit size={14} /> MODEL ANALYSIS</span><span className="ai-model-id" data-testid="ai-model-id">{result.modelId}</span></div>
      <span className="ai-engine-label"><ShieldCheck size={14} /> CONTAINMENT VERIFIED BY ENGINE</span>
    </div>

    <section className="ai-result-section" data-testid="ai-findings">
      <div className="ai-section-title"><div><ListChecks size={15} /><h3>Findings</h3></div><span>{result.findings.length} returned</span></div>
      {result.findings.length ? <div className="ai-findings-list">{result.findings.map((finding, index) => <article className="ai-finding" key={`${finding.kind}-${index}`} data-testid={`ai-finding-${index}`}>
        <span className={`finding-kind ${finding.kind === 'verified-fact' ? 'finding-fact' : 'finding-hypothesis'}`}>{finding.kind === 'verified-fact' ? 'VERIFIED FACT' : 'MODEL HYPOTHESIS'}</span>
        <p>{finding.text}</p><EvidenceIds ids={finding.evidenceIds} />
      </article>)}</div> : <div className="ai-empty-state" data-testid="ai-findings-empty">No findings were returned.</div>}
    </section>

    <section className="ai-result-section" data-testid="ai-external-intelligence">
      <div className="ai-section-title"><div><ShieldAlert size={15} /><h3>External threat intelligence</h3></div><span>{result.externalIntelligence.length} untrusted sources</span></div>
      <p className="ai-intel-warning">Tavily search results are untrusted external intelligence, not original incident evidence or proof that an indicator is malicious.</p>
      {result.externalIntelligence.length ? <div className="ai-intel-list">{result.externalIntelligence.map((source) => <article className="ai-intel-card" key={source.id} data-testid={`ai-external-source-${source.id}`}>
        <div className="ai-intel-meta"><code>{source.indicator}</code><span>{source.publishedAt ? `Published ${source.publishedAt}` : 'Publication date unavailable'}{source.relevanceScore !== null ? ` · relevance ${source.relevanceScore.toFixed(2)}` : ''}</span></div>
        <strong>{source.title}</strong>
        <p>{source.excerpt}</p>
        <a href={source.url} target="_blank" rel="noopener noreferrer">{source.url}</a>
        <EvidenceIds ids={[source.id]} />
      </article>)}</div> : <div className="ai-empty-state">No external threat-intelligence sources were returned.</div>}
    </section>

    <section className="ai-result-section" data-testid="ai-tool-executions">
      <div className="ai-section-title"><div><Workflow size={15} /><h3>Investigation trace</h3></div><span>{result.toolExecutions.length} tool executions</span></div>
      {result.toolExecutions.length ? <ol className="ai-tool-list">{result.toolExecutions.map((execution, index) => <li className="ai-tool-row" key={`${execution.toolName}-${index}`} data-testid={`ai-tool-execution-${index}`}>
        <span className={`ai-tool-status ${execution.status === 'success' ? 'tool-success' : 'tool-rejected'}`}>{execution.status === 'success' ? <Check size={13} /> : <X size={13} />}</span>
        <div className="ai-tool-copy"><code>{execution.toolName}</code><span>{execution.summary}</span><EvidenceIds ids={execution.evidenceIds} /></div>
        <span className={`tool-status-label ${execution.status === 'success' ? 'tool-success-text' : 'tool-rejected-text'}`}>{execution.status}</span>
      </li>)}</ol> : <div className="ai-empty-state" data-testid="ai-tools-empty">No tool executions were returned.</div>}
    </section>

    <section className="ai-result-section" data-testid="ai-inspected-evidence">
      <div className="ai-section-title"><div><FileSearch size={15} /><h3>Inspected evidence</h3></div><span>{result.inspectedEvidence.length} audit events</span></div>
      {result.inspectedEvidence.length ? <div className="ai-audit-grid">{result.inspectedEvidence.map((event) => <AiAuditEvent key={event.id} event={event} />)}</div> : <div className="ai-empty-state" data-testid="ai-evidence-empty">No audit evidence was inspected.</div>}
    </section>

    <section className="ai-result-section" data-testid="ai-candidate-actions">
      <div className="ai-section-title"><div><ScanSearch size={15} /><h3>Proposed containment candidates</h3></div><span>{result.candidateActions.length} candidates</span></div>
      {result.candidateActions.length ? <div className="ai-candidate-list">{result.candidateActions.map((action) => <article className="ai-candidate" key={action.id} data-testid={`ai-candidate-action-${action.id}`}>
        <div><span className="action-category">{action.category}</span><strong>{action.title}</strong><p>{action.description}</p><small><ArrowRight size={12} />{action.expectedEffect}</small></div>
        <span className="ai-edge-count">{action.edgeIds.length} {action.edgeIds.length === 1 ? 'edge' : 'edges'}<br />affected</span>
      </article>)}</div> : <div className="ai-empty-state" data-testid="ai-candidates-empty">No candidate actions were returned.</div>}
    </section>

    <section className="ai-result-section" data-testid="ai-simulations">
      <div className="ai-section-title"><div><FlaskConical size={15} /><h3>Action simulations</h3></div><span>{result.simulations.length} simulations</span></div>
      {result.simulations.length ? <div className="ai-simulation-list">{result.simulations.map((simulation, index) => <article className={`ai-simulation ${simulation.verification.status === 'verified-contained' ? 'simulation-contained' : 'simulation-incomplete'}`} key={`${simulation.action.id}-${index}`} data-testid={`ai-simulation-${index}`}>
        <div className="ai-simulation-heading"><div><span className="eyebrow">ENGINE SIMULATION</span><strong>{simulation.action.title}</strong></div><span className="ai-simulation-status">{simulation.verification.status === 'verified-contained' ? 'VERIFIED CONTAINED' : 'INCOMPLETE'}</span></div>
        <div className="ai-simulation-metrics"><span><b>{simulation.verification.verifiedClosedPaths.length}</b> paths closed</span><span><b>{simulation.verification.remainingReachablePaths.length}</b> still reachable</span><span><b>{simulation.verification.unresolvedFindings.length}</b> unresolved findings</span></div>
        {simulation.verification.remainingReachablePaths.length > 0 && <div className="ai-path-results">{simulation.verification.remainingReachablePaths.map((path) => <span key={path.id}><ArrowRight size={12} />{path.label}</span>)}</div>}
        {simulation.verification.unresolvedFindings.length > 0 && <ul className="ai-unresolved-list">{simulation.verification.unresolvedFindings.map((finding, findingIndex) => <li key={`${findingIndex}-${finding}`}>{finding}</li>)}</ul>}
      </article>)}</div> : <div className="ai-empty-state" data-testid="ai-simulations-empty">No action simulations were returned.</div>}
    </section>

    <section className="ai-explanation" data-testid="ai-model-explanation">
      <div className="ai-explanation-heading"><Cpu size={16} /><div><span className="eyebrow">MODEL EXPLANATION</span><strong>Analysis narrative</strong></div></div>
      <p>{result.explanation}</p>
      <span className="ai-boundary-note">Model analysis is advisory. Containment status below is independently recomputed by the deterministic verification engine.</span>
    </section>

    <ReportPanel report={result.verification} reportId="ai-final-verification" eyebrow="ENGINE VERIFIED · FINAL REPORT" testId="ai-final-verification-report" />
  </div>;
}

export default function Investigation() {
  const incidentQuery = useGetCurrentIncident({ query: { queryKey: getGetCurrentIncidentQueryKey() } });
  const remediationsQuery = useGetIncidentRemediations({ query: { queryKey: getGetIncidentRemediationsQueryKey() } });
  const simulation = useSimulateContainment();
  const aiInvestigation = useRunAiIncidentInvestigation();
  const [selected, setSelected] = useState<ActionId[]>([]);
  const [selectionInitialized, setSelectionInitialized] = useState(false);
  const [report, setReport] = useState<VerificationReport | null>(null);
  const [focusedPath, setFocusedPath] = useState<string | null>(null);
  const [investigated, setInvestigated] = useState(false);
  const snapshot = incidentQuery.data;
  const remediationItems: RemediationAction[] = remediationsQuery.data ?? snapshot?.remediations ?? [];

  useEffect(() => {
    if (remediationsQuery.data && !selectionInitialized) {
      setSelected(remediationsQuery.data.some((item) => item.id === 'revoke-user-session') ? ['revoke-user-session'] : []);
      setSelectionInitialized(true);
    }
  }, [remediationsQuery.data, selectionInitialized]);

  const focused = snapshot?.attackPaths.find((path) => path.id === focusedPath) ?? null;
  const toggleAction = (id: ActionId) => {
    setSelected((current) => current.includes(id) ? current.filter((item) => item !== id) : actionOrder.filter((item) => [...current, id].includes(item)));
    setReport(null);
  };
  const investigate = () => {
    setInvestigated(true);
    document.getElementById('evidence')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };
  const simulate = () => {
    if (!selected.length) return;
    simulation.mutate({ data: { actionIds: actionOrder.filter((id) => selected.includes(id)) } }, {
      onSuccess: (result) => {
        setReport(result);
        window.setTimeout(() => document.getElementById('verification-report')?.scrollIntoView({ behavior: 'smooth', block: 'start' }), 60);
      },
      onError: () => setReport(null),
    });
  };
  const runAiInvestigation = () => {
    aiInvestigation.reset();
    aiInvestigation.mutate();
  };

  if (incidentQuery.isLoading) return <Skeleton />;
  if (incidentQuery.isError || !snapshot) return <main className="load-error"><div className="error-icon"><RotateCcw size={22} /></div><span className="eyebrow">INCIDENT DATA UNAVAILABLE</span><h1>Unable to reconstruct this scenario.</h1><p>The synthetic incident feed could not be loaded. Try the request again.</p><button className="button-primary" onClick={() => incidentQuery.refetch()} data-testid="button-retry-incident"><RotateCcw size={15} /> Retry incident feed</button></main>;
  const { incident } = snapshot;
  const focusedEventIds = focused
    ? new Set(
        snapshot.edges
          .filter((edge) => focused.edgeIds.includes(edge.id))
          .flatMap((edge) => edge.eventIds),
      )
    : null;
  const visibleEvents = focusedEventIds
    ? snapshot.auditEvents.filter((event) => focusedEventIds.has(event.id))
    : snapshot.auditEvents;
  const sessionAlone = selected.length === 1 && selected[0] === 'revoke-user-session';

  return <div className="shell">
    <aside className="sidebar">
      <div className="brand"><div className="brand-mark"><Shield size={19} /></div><div><strong>TraceLock</strong><small>INCIDENT SIMULATOR</small></div></div>
      <div className="sidebar-divider" />
      <div className="sidebar-section-label">CURRENT INVESTIGATION</div>
      <div className="incident-nav active"><span className="nav-indicator" /><div><strong>{incident.id}</strong><small>{incident.title}</small></div></div>
      <div className="sidebar-rail">
        <div className="rail-step current"><span>01</span><div><strong>Investigate</strong><small>Evidence &amp; access graph</small></div></div>
        <div className="rail-line" />
        <div className={`rail-step ${selected.length ? 'current' : ''}`}><span>02</span><div><strong>Remediate</strong><small>Test containment choices</small></div></div>
        <div className="rail-line" />
        <div className={`rail-step ${report ? 'current' : ''}`}><span>03</span><div><strong>Verify</strong><small>Prove paths closed</small></div></div>
      </div>
      <div className="sidebar-bottom"><div className="synthetic-stamp"><Fingerprint size={15} /><span>SYNTHETIC SCENARIO</span></div><p>All identities, events, and resources shown are generated for simulation.</p></div>
    </aside>
    <main className="main">
      <header className="topbar"><div className="crumb"><span>Investigations</span><span className="crumb-slash">/</span><strong>{incident.id}</strong></div><div className="topbar-right"><span className="environment"><i /> SIMULATION ENVIRONMENT</span><span className="analyst-avatar">SA</span></div></header>
      <div className="content">
        <section className="incident-hero">
          <div className="hero-meta"><span className="eyebrow">IDENTITY INCIDENT</span><span className="status-pill"><i />{incident.status}</span><span className="severity-pill">{incident.severity} severity</span></div>
          <div className="hero-main"><div><h1>{incident.title}</h1><p>{incident.summary}</p></div><div className="hero-actions"><button className={`button-primary investigate-button ${investigated ? 'button-done' : ''}`} onClick={investigate} data-testid="button-investigate-incident">{investigated ? <CheckCircle2 size={16} /> : <ArrowDown size={16} />}{investigated ? 'Evidence in focus' : 'Investigate incident'}</button><button className="button-ai-investigate" onClick={runAiInvestigation} disabled={aiInvestigation.isPending} data-testid="button-ai-investigate"><BrainCircuit size={16} />{aiInvestigation.isPending ? 'Investigation running…' : 'AI Investigate'}<ArrowRight size={14} /></button></div></div>
          <div className="incident-facts"><span><span className="fact-label">INCIDENT</span><strong className="mono">{incident.id}</strong></span><span><span className="fact-label">DETECTED</span><strong><Clock3 size={13} />{timeLabel(incident.detectedAt)}</strong></span><span><span className="fact-label">IDENTITIES</span><strong>{snapshot.identities.length} observed</strong></span><span><span className="fact-label">ATTACK PATHS</span><strong>{snapshot.attackPaths.length} reconstructed</strong></span></div>
        </section>

        <section className="workspace-section" id="evidence">
          <div className="section-heading"><div><span className="section-index">01</span><div><span className="eyebrow">RECONSTRUCTION</span><h2>Evidence &amp; access graph</h2></div></div><span className="section-caption"><Activity size={14} /> Derived from synthetic audit evidence</span></div>
          <div className="evidence-layout">
            <div className="panel graph-panel"><div className="panel-heading"><div><h3>Identity reachability</h3><p>Relationships that form a route into sensitive resources</p></div><span className="live-tag"><i /> SOURCE GRAPH</span></div><EvidenceGraph snapshot={snapshot} activePath={focused} /><div className="graph-footnote"><LockKeyhole size={14} /> Paths are reconstructed from enabled relationships and observed evidence.</div></div>
            <div className="paths-panel"><div className="panel-heading"><div><h3>Reconstructed paths</h3><p>Select a path to trace it in the graph</p></div><span className="count-chip">{snapshot.attackPaths.length}</span></div><div className="path-list">{snapshot.attackPaths.length ? snapshot.attackPaths.map((path) => <PathCard key={path.id} path={path} focused={focusedPath === path.id} onFocus={() => setFocusedPath((current) => current === path.id ? null : path.id)} />) : <div className="empty-path"><Network size={18} /><p>No attack paths were returned for this scenario.</p></div>}</div><div className="path-callout"><AlertTriangle size={15} /><p><strong>Session revocation is not enough.</strong> The separate app-consent route can remain reachable until that relationship is also removed in the simulation.</p></div></div>
          </div>
        </section>

        <section className="ai-workspace workspace-section" id="ai-investigation" data-testid="ai-investigation-workspace">
          <div className="section-heading"><div><span className="section-index ai-index"><BrainCircuit size={15} /></span><div><span className="eyebrow">ASSISTED INVESTIGATION</span><h2>AI investigation trace</h2></div></div><span className="section-caption"><ShieldCheck size={14} /> Model analysis separated from engine verification</span></div>
          {!aiInvestigation.data && !aiInvestigation.isPending && !aiInvestigation.isError && <div className="ai-launch-panel" data-testid="ai-investigation-intro">
            <div className="ai-launch-mark"><BrainCircuit size={19} /></div><div><strong>Run a tool-backed investigation</strong><p>TraceLock will return model findings alongside allowlisted tool executions, inspected evidence, action simulations, and an independent containment report.</p></div>
            <button className="button-ai-investigate" onClick={runAiInvestigation} data-testid="button-ai-investigate-panel">Run investigation<ArrowRight size={14} /></button>
          </div>}
          {aiInvestigation.isPending && <div className="ai-loading-state" role="status" data-testid="ai-investigation-loading"><span className="ai-loading-mark"><BrainCircuit size={18} /></span><div><strong>Investigation request in progress</strong><p>Waiting for the investigation provider and verification engine to return a result. No progress is inferred before the response.</p></div><span className="ai-pending-tag">REQUEST PENDING</span></div>}
          {aiInvestigation.isError && <div className="ai-error-state" role="alert" data-testid="ai-investigation-error"><div><AlertTriangle size={17} /><span><strong>AI investigation could not be completed</strong><small>{aiInvestigation.error instanceof Error ? aiInvestigation.error.message : 'The provider or API returned an error. No investigation results are available.'}</small></span></div><button className="button-ai-investigate" onClick={runAiInvestigation} data-testid="button-retry-ai-investigation"><RotateCcw size={14} /> Retry investigation</button></div>}
          {aiInvestigation.data && !aiInvestigation.isPending && <AiInvestigationResults result={aiInvestigation.data} />}
        </section>

        <section className="workspace-section evidence-events">
          <div className="section-heading"><div><span className="section-index">02</span><div><span className="eyebrow">OBSERVED ACTIVITY</span><h2>Evidence timeline</h2></div></div><span className="section-caption">{focusedEventIds ? `${visibleEvents.length} events supporting selected path · ${snapshot.auditEvents.length} total` : `${snapshot.auditEvents.length} synthetic audit events`}</span></div>
          <div className="events-panel">
            {visibleEvents.length ? <div className="event-list">{visibleEvents.map((event, index) => {
              const actor = snapshot.identities.find((identity) => identity.id === event.actorId);
              const target = [...snapshot.identities, ...snapshot.roles, ...snapshot.resources].find((item) => item.id === event.targetId);
              const linked = snapshot.edges.some((edge) => edge.eventIds.includes(event.id));
              return <article className="event-row" key={event.id} data-testid={`event-row-${event.id}`}><div className="event-time">{timeLabel(event.timestamp)}</div><div className="event-track"><span className={`event-dot ${event.result.toLowerCase().includes('success') || event.result.toLowerCase().includes('allow') ? 'event-positive' : ''}`} />{index !== visibleEvents.length - 1 && <span className="event-line" />}</div><div className="event-detail"><div className="event-titleline"><strong>{event.action}</strong><span className={`result-chip ${event.result.toLowerCase().includes('success') || event.result.toLowerCase().includes('allow') ? 'result-success' : ''}`}>{event.result}</span></div><p>{event.summary}</p><div className="event-meta"><span>Actor <b>{actor?.name ?? event.actorId}</b></span><span>Target <b>{target?.name ?? event.targetId}</b></span><span>Source <b className="mono">{event.sourceIp}</b></span>{linked && <span className="linked-evidence"><Check size={11} /> {focusedEventIds ? 'supports selected path' : 'linked to graph'}</span>}</div></div></article>;
            })}</div> : <div className="empty-events"><Activity size={20} /><strong>No audit events returned</strong><span>This incident snapshot includes no timestamped synthetic evidence.</span></div>}
          </div>
        </section>

        <section className="workspace-section remediation-section">
          <div className="section-heading"><div><span className="section-index">03</span><div><span className="eyebrow">CONTAINMENT LAB</span><h2>Test remediation candidates</h2></div></div><span className="section-caption">Choose changes to apply to a copied graph only</span></div>
          <div className="remediation-shell">
            <div className="remediation-intro"><div><div className="intro-icon"><Workflow size={19} /></div><h3>Compose a containment test</h3><p>Actions are evaluated together, then reachability is recomputed independently. Nothing is executed in a cloud environment.</p></div><div className="selected-total"><strong>{selected.length.toString().padStart(2, '0')}</strong><span>SELECTED</span></div></div>
            {remediationsQuery.isLoading ? <div className="action-skeleton"><i /><i /><i /></div> : remediationsQuery.isError ? <div className="inline-error"><AlertTriangle size={16} /><span>Could not load candidate actions.</span><button onClick={() => remediationsQuery.refetch()} data-testid="button-retry-remediations">Retry</button></div> : remediationItems.length ? <div className="action-list">{actionOrder.map((id) => {
              const action = remediationItems.find((item) => item.id === id);
              if (!action) return null;
              const checked = selected.includes(action.id);
              return <button key={action.id} className={`action-card ${checked ? 'action-selected' : ''}`} onClick={() => toggleAction(action.id)} aria-pressed={checked} data-testid={`button-toggle-${action.id}`}><span className={`check-square ${checked ? 'checked' : ''}`}>{checked && <Check size={14} />}</span><span className="action-copy"><span className="action-category">{action.category}</span><strong>{action.title}</strong><span>{action.description}</span><small><ArrowRight size={12} />{action.expectedEffect}</small></span><span className="action-impact">{action.edgeIds.length} {action.edgeIds.length === 1 ? 'edge' : 'edges'}<br />affected</span></button>;
            })}</div> : <div className="empty-events small-empty">No remediation candidates were returned for this incident.</div>}
            {sessionAlone && <div className="session-warning"><AlertTriangle size={16} /><p><strong>One route remains.</strong> Revoking the user session closes only that path. Add <b>Revoke app consent</b> to test the independent application route too.</p></div>}
            <div className="simulate-footer"><div><span className="simulation-lock"><LockKeyhole size={14} /></span><span><strong>Simulation only</strong><small>No real identity or cloud changes will occur.</small></span></div><button className="button-primary simulate-button" onClick={simulate} disabled={selected.length === 0 || simulation.isPending || remediationsQuery.isLoading} data-testid="button-simulate-verify">{simulation.isPending ? <><span className="button-loader" />Recomputing paths…</> : <><ShieldCheck size={16} />Simulate and verify<ArrowRight size={15} /></>}</button></div>
            {simulation.isError && <div className="simulation-error" role="alert"><X size={14} /> Simulation could not be completed. Review your selection and try again.</div>}
          </div>
        </section>

        {report && <ReportPanel report={report} />}
        <footer className="page-footer"><span><Fingerprint size={14} /> Synthetic incident-response training data</span><span>TraceLock <b>·</b> Reachability is not proof of real-world execution</span></footer>
      </div>
    </main>
  </div>;
}
