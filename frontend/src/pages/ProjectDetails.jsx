import { useState, useEffect, useRef, useCallback } from "react";
import { useParams, useNavigate, Link } from "react-router-dom";
import { projectApi, scanApi } from "../api/client";

import { Badge, Spinner } from "../components/ui";

const SEV_ORDER = { CRITICAL:4, HIGH:3, MEDIUM:2, LOW:1, UNASSIGNED:0 };
const SEV_VARIANT = { CRITICAL: 'danger', HIGH: 'warning', MEDIUM: 'warning', LOW: 'info', UNASSIGNED: 'neutral' };

const StatusBadge = ({ status }) => {
  const vMap = {
    FAILED: 'danger', COMPLETED: 'success', SBOM_GENERATING: 'neutral',
    EXTRACTING: 'neutral', ANALYZING: 'info', INGESTING: 'info',
    VULNERABILITY_ANALYSIS: 'info', QUEUED: 'warning', CANCELLED: 'neutral'
  };
  return <Badge variant={vMap[status] || 'neutral'}>{status}</Badge>;
};

const SevBadge = ({ severity }) => (
  <Badge variant={SEV_VARIANT[severity] || 'neutral'}>{severity}</Badge>
);

// Scan History Table with Filtering and Sorting (Phase 12)
const ScanHistoryTable = ({ scans, selectedId, onSelect }) => {
  const [statusFilter, setStatusFilter] = useState("ALL");
  const [sourceFilter, setSourceFilter] = useState("ALL");
  const [search, setSearch] = useState("");
  const [sortBy, setSortBy] = useState("NEWEST");

  if (!scans || !scans.length) {
    return (
      <div style={s.emptyBox}>
        <p style={{margin:0,color:"#8c8c8c"}}>No scans recorded yet. Trigger a scan above to analyze your project dependencies.</p>
      </div>
    );
  }

  // Filter scans
  const filtered = scans.filter((scan) => {
    if (statusFilter !== "ALL") {
      if (statusFilter === "IN_PROGRESS") {
        if (!["QUEUED","INGESTING","ANALYZING","EXTRACTING","SBOM_GENERATING","VULNERABILITY_ANALYSIS"].includes(scan.status)) {
          return false;
        }
      } else if (scan.status !== statusFilter) {
        return false;
      }
    }
    if (sourceFilter !== "ALL" && (scan.source || "GITHUB") !== sourceFilter) {
      return false;
    }
    if (search.trim()) {
      const q = search.trim().toLowerCase();
      const matchId = scan.id.toLowerCase().includes(q);
      const matchStatus = scan.status.toLowerCase().includes(q);
      const matchErr = (scan.errorMessage || "").toLowerCase().includes(q);
      if (!matchId && !matchStatus && !matchErr) return false;
    }
    return true;
  });

  // Sort scans
  filtered.sort((a, b) => {
    switch (sortBy) {
      case "OLDEST":
        return new Date(a.createdAt) - new Date(b.createdAt);
      case "RISK_DESC":
        return (b.riskScore ?? -1) - (a.riskScore ?? -1);
      case "RISK_ASC":
        return (a.riskScore ?? 9999) - (b.riskScore ?? 9999);
      case "VULNS_DESC":
        return (b.vulnerabilityCount ?? 0) - (a.vulnerabilityCount ?? 0);
      case "DEPS_DESC":
        return (b.dependencyCount ?? 0) - (a.dependencyCount ?? 0);
      case "NEWEST":
      default:
        return new Date(b.createdAt) - new Date(a.createdAt);
    }
  });

  return (
    <div>
      <div style={s.controls}>
        <input
          type="text"
          placeholder="Filter by Scan ID or status..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="input"
        />
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="input"
        >
          <option value="ALL">All Statuses</option>
          <option value="COMPLETED">Completed</option>
          <option value="FAILED">Failed</option>
          <option value="IN_PROGRESS">In Progress</option>
          <option value="CANCELLED">Cancelled</option>
        </select>
        <select
          value={sourceFilter}
          onChange={(e) => setSourceFilter(e.target.value)}
          className="input"
        >
          <option value="ALL">All Sources</option>
          <option value="GITHUB">GitHub</option>
          <option value="ZIP">ZIP Upload</option>
        </select>
        <select
          value={sortBy}
          onChange={(e) => setSortBy(e.target.value)}
          className="input"
        >
          <option value="NEWEST">Newest First</option>
          <option value="OLDEST">Oldest First</option>
          <option value="RISK_DESC">Highest Risk</option>
          <option value="RISK_ASC">Lowest Risk</option>
          <option value="VULNS_DESC">Most Vulnerabilities</option>
          <option value="DEPS_DESC">Most Dependencies</option>
        </select>
        <span style={{fontSize:"0.8rem",color:"#8c8c8c",alignSelf:"center",marginLeft:"auto"}}>
          Showing {filtered.length} of {scans.length} scans
        </span>
      </div>

      {filtered.length === 0 ? (
        <div style={s.emptyBox}>
          <p style={{margin:0,color:"#8c8c8c"}}>No scans match the selected filters.</p>
        </div>
      ) : (
        <div className="table-container">
          <table className="table">
            <thead>
              <tr>
                <th style={s.th}>Scan ID</th>
                <th style={s.th}>Source</th>
                <th style={s.th}>Status</th>
                <th style={s.th}>Started</th>
                <th style={s.th}>Completed</th>
                <th style={{...s.th,textAlign:"center"}}>Dependencies</th>
                <th style={{...s.th,textAlign:"center"}}>Vulnerabilities</th>
                <th style={{...s.th,textAlign:"center"}}>Risk Index</th>
                <th style={{...s.th,textAlign:"center"}}>SBOM</th>
                <th style={s.th}></th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((scan) => {
                const isSelected = selectedId === scan.id;
                const isFailed = scan.status === "FAILED";

                return (
                  <tr
                    key={scan.id}
                    style={{
                      ...s.tr,
                      backgroundColor: isSelected ? "#1890ff12" : "transparent"
                    }}
                  >
                    <td style={{...s.td,fontFamily:"monospace",fontSize:"0.8rem"}} title={scan.id}>
                      {scan.id.slice(0, 8)}...
                    </td>
                    <td style={s.td}>
                      <span style={{
                        padding:"0.15rem 0.5rem",
                        borderRadius:"4px",
                        fontSize:"0.72rem",
                        fontWeight:600,
                        backgroundColor: scan.source === "ZIP" ? "#faad1422" : "#1890ff22",
                        color: scan.source === "ZIP" ? "#faad14" : "#40a9ff",
                        border: `1px solid ${scan.source === "ZIP" ? "#faad1444" : "#1890ff44"}`
                      }}>
                        {scan.source || "GITHUB"}
                      </span>
                    </td>
                    <td style={s.td} title={scan.errorMessage || undefined}>
                      <StatusBadge status={scan.status} />
                      {isFailed && scan.errorMessage && (
                        <div style={{fontSize:"0.7rem",color:"#ff4d4f",marginTop:"0.2rem",maxWidth:"180px",overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}} title={scan.errorMessage}>
                          {scan.errorMessage}
                        </div>
                      )}
                    </td>
                    <td style={{...s.td,fontSize:"0.8rem",color:"#a0aec0"}}>
                      {new Date(scan.createdAt).toLocaleString()}
                    </td>
                    <td style={{...s.td,fontSize:"0.8rem",color:"#a0aec0"}}>
                      {scan.completedAt
                        ? new Date(scan.completedAt).toLocaleString()
                        : isFailed
                        ? <span style={{color:"#ff4d4f"}}>Failed</span>
                        : <span style={{color:"#faad14"}}>In progress</span>}
                    </td>
                    <td style={{...s.td,textAlign:"center",fontWeight:600}}>
                      {scan.dependencyCount ?? 0}
                    </td>
                    <td style={{...s.td,textAlign:"center",fontWeight:700,color:scan.vulnerabilityCount>0?"#ff7a45":"#e2e8f0"}}>
                      {scan.status === "COMPLETED" ? (scan.vulnerabilityCount ?? 0) : "-"}
                    </td>
                    <td style={{
                      ...s.td,
                      textAlign:"center",
                      fontWeight:700,
                      color: scan.status === "COMPLETED"
                        ? (scan.riskScore > 0 ? "#ff7a45" : "#52c41a")
                        : "#8c8c8c"
                    }}>
                      {scan.status === "COMPLETED" && scan.riskScore != null ? scan.riskScore : (scan.status === "COMPLETED" ? 0 : "-")}
                    </td>
                    <td style={{...s.td,textAlign:"center",fontSize:"0.8rem",color:"#b37feb"}}>
                      {scan.sbomComponentCount != null ? scan.sbomComponentCount : "-"}
                    </td>
                    <td style={s.td}>
                      <button
                        onClick={() => onSelect(isSelected ? null : scan.id)}
                        style={isSelected ? s.btnActive : s.btnSecondary}
                        title={isSelected ? "Hide scan details" : "Inspect security dashboard and report"}
                      >
                        {isSelected ? "Hide" : (isFailed ? "View Error" : "View Details")}
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};

// Summary Cards
const SummaryCards = ({ summary }) => {
  const cards = [
    {label:"Total Risk Index", value:summary.totalRiskScore, color:summary.totalRiskScore>0?"#ff7a45":"#52c41a", large:true},
    {label:"Vulnerabilities Found", value:summary.totalFindings, color:"#e2e8f0"},
    {label:"Dependencies", value:summary.totalDependencies, color:"#e2e8f0"},
    {label:"Direct", value:summary.directDependencies, color:"#1890ff"},
    {label:"Transitive", value:summary.transitiveDependencies, color:"#8c8c8c"},
    {label:"SBOM Components", value:summary.sbomComponents??"-", color:"#722ed1"},
  ];
  return (
    <div style={s.cardGrid}>
      {cards.map(c=>(
        <div key={c.label} style={{...s.summaryCard,...(c.large?s.summaryCardLarge:{})}}>
          <div style={{fontSize:c.large?"2.2rem":"1.6rem",fontWeight:700,color:c.color,lineHeight:1}}>{c.value}</div>
          <div style={{fontSize:"0.78rem",color:"#8c8c8c",marginTop:"0.35rem",textTransform:"uppercase",letterSpacing:"0.05em"}}>{c.label}</div>
        </div>
      ))}
    </div>
  );
};

// Severity Breakdown
const SeverityBreakdown = ({ counts, total }) => {
  const SEVS = ["CRITICAL","HIGH","MEDIUM","LOW","UNASSIGNED"];
  return (
    <div style={s.sevBox}>
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:"0.75rem"}}>
        <h3 style={s.sectionTitle}>Severity Breakdown</h3>
        <span style={{fontSize:"0.8rem",color:"#8c8c8c"}}>{total} finding{total!==1?"s":""}</span>
      </div>
      {SEVS.map(sev=>{
        const count = counts[sev]||0;
        const pct = total>0?Math.round((count/total)*100):0;
        return (
          <div key={sev} style={{marginBottom:"0.5rem"}}>
            <div style={{display:"flex",justifyContent:"space-between",marginBottom:"0.2rem"}}>
              <span style={{color:`var(--${SEV_VARIANT[sev] || 'neutral'})`,fontSize:"0.82rem",fontWeight:600}}>{sev}</span>
              <span style={{color:"var(--text-h)",fontSize:"0.82rem"}}>{count}</span>
            </div>
            <div style={{height:"6px",borderRadius:"3px",backgroundColor:"var(--border)",overflow:"hidden"}}>
              <div style={{height:"100%",width:`${pct}%`,backgroundColor:`var(--${SEV_VARIANT[sev] || 'neutral'})`,borderRadius:"3px",transition:"width 0.4s ease"}} />
            </div>
          </div>
        );
      })}
      {total===0 && (
        <p style={{color:"#52c41a",fontSize:"0.85rem",marginTop:"0.5rem"}}>
          No matched vulnerabilities found.<br />
          <span style={{color:"#8c8c8c",fontSize:"0.78rem"}}>Zero findings reflect the NVD cache coverage, not a security guarantee.</span>
        </p>
      )}
    </div>
  );
};

const RiskFormulaNote = () => (
  <div style={s.formulaBox}>
    <span style={{color:"#8c8c8c",fontSize:"0.78rem",fontWeight:600,textTransform:"uppercase",letterSpacing:"0.05em"}}>Risk Formula</span>
    <p style={{margin:"0.35rem 0 0",fontSize:"0.82rem",color:"#b0b8c8",lineHeight:1.6}}>
      <code style={s.code}>Total Risk Index = Sum of (Severity Weight x Context Weight)</code><br />
      Critical=10 High=5 Medium=3 Low=1 Unassigned=0<br />
      Direct x1.5  Transitive x1.0
    </p>
  </div>
);

// Finding Detail Drawer
const FindingDetail = ({ finding, onClose }) => {
  if (!finding) return null;
  const verRanges = finding.affectedSoftware||[];
  return (
    <div style={s.drawerOverlay} onClick={onClose}>
      <div style={s.drawer} onClick={e=>e.stopPropagation()}>
        <div style={s.drawerHeader}>
          <div>
            <h3 style={{margin:0,color:"#e2e8f0",fontSize:"1.05rem"}}>{finding.cveId}</h3>
            <div style={{marginTop:"0.4rem",display:"flex",gap:"0.5rem",alignItems:"center"}}>
              <SevBadge severity={finding.severity} />
              {finding.cvssScore!=null && <span style={{fontSize:"0.8rem",color:"#8c8c8c"}}>CVSS {finding.cvssScore}</span>}
            </div>
          </div>
          <button onClick={onClose} style={s.closeBtn}>x</button>
        </div>
        <div style={s.drawerBody}>
          <div style={s.drawerSection}>
            <div style={s.drawerLabel}>Affected Package</div>
            <div style={{display:"flex",gap:"0.75rem",flexWrap:"wrap",marginTop:"0.3rem"}}>
              <span style={s.monoChip}>{finding.packageName}</span>
              <span style={s.monoChip}>v{finding.packageVersion}</span>
              <span style={finding.isDirect?s.directChip:s.transitiveChip}>{finding.isDirect?"Direct":"Transitive"}</span>
            </div>
            {finding.packagePurl && <div style={{marginTop:"0.4rem",fontSize:"0.75rem",color:"#8c8c8c",fontFamily:"monospace"}}>{finding.packagePurl}</div>}
          </div>
          <div style={s.drawerSection}>
            <div style={s.drawerLabel}>Risk Calculation</div>
            <div style={s.riskCalcRow}>
              <span style={{color:`var(--${SEV_VARIANT[finding.severity] || 'neutral'})`}}>{finding.severity} ({finding.severityWeight??"-"})</span>
              <span style={{color:"var(--text)"}}>x</span>
              <span>{finding.isDirect?"Direct":"Transitive"} ({finding.contextWeight??"-"})</span>
              <span style={{color:"var(--text)"}}>=</span>
              <strong style={{color:"var(--text-h)"}}>{finding.riskScore??"-"} risk points</strong>
            </div>
          </div>
          <div style={s.drawerSection}>
            <div style={s.drawerLabel}>Description</div>
            <p style={{margin:"0.3rem 0 0",fontSize:"0.85rem",color:"#b0b8c8",lineHeight:1.6}}>{finding.description||"No description available."}</p>
          </div>
          {verRanges.length>0 && (
            <div style={s.drawerSection}>
              <div style={s.drawerLabel}>Affected Version Ranges</div>
              {verRanges.map((r,i)=>(
                <div key={i} style={{fontSize:"0.8rem",color:"#b0b8c8",marginTop:"0.3rem",fontFamily:"monospace"}}>
                  {r.vendor&&<span>{r.vendor}/</span>}<span>{r.product}</span>
                  {r.versionStartIncluding&&<span> &gt;={r.versionStartIncluding}</span>}
                  {r.versionStartExcluding&&<span> &gt;{r.versionStartExcluding}</span>}
                  {r.versionEndIncluding&&<span> &lt;={r.versionEndIncluding}</span>}
                  {r.versionEndExcluding&&<span> &lt;{r.versionEndExcluding}</span>}
                </div>
              ))}
            </div>
          )}
          {finding.publishedAt && (
            <div style={s.drawerSection}>
              <div style={s.drawerLabel}>Published</div>
              <div style={{fontSize:"0.82rem",color:"#8c8c8c",marginTop:"0.3rem"}}>{new Date(finding.publishedAt).toLocaleDateString()}</div>
            </div>
          )}
          {Array.isArray(finding.references)&&finding.references.length>0 && (
            <div style={s.drawerSection}>
              <div style={s.drawerLabel}>References</div>
              <ul style={{margin:"0.3rem 0 0",paddingLeft:"1.25rem"}}>
                {finding.references.slice(0,6).map((ref,i)=>(
                  <li key={i} style={{fontSize:"0.78rem",marginBottom:"0.2rem"}}>
                    <a href={ref} target="_blank" rel="noreferrer" style={{color:"#1890ff",wordBreak:"break-all"}}>{ref}</a>
                  </li>
                ))}
                {finding.references.length>6&&<li style={{fontSize:"0.78rem",color:"#8c8c8c"}}>+{finding.references.length-6} more</li>}
              </ul>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

// Findings Table
const SORT_OPTIONS = [
  {value:"risk_desc",label:"Risk High-Low"},{value:"risk_asc",label:"Risk Low-High"},
  {value:"sev_desc",label:"Severity"},{value:"pkg_asc",label:"Package A-Z"},
];

const FindingsTable = ({ findings }) => {
  const [sevFilter, setSevFilter] = useState("ALL");
  const [typeFilter, setTypeFilter] = useState("ALL");
  const [sortBy, setSortBy] = useState("risk_desc");
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState(null);

  const filtered = findings
    .filter(f=>sevFilter==="ALL"||f.severity===sevFilter)
    .filter(f=>typeFilter==="ALL"||(typeFilter==="DIRECT"?f.isDirect:!f.isDirect))
    .filter(f=>!search||f.cveId.toLowerCase().includes(search.toLowerCase())||f.packageName.toLowerCase().includes(search.toLowerCase()))
    .sort((a,b)=>{
      if(sortBy==="risk_desc") return (b.riskScore||0)-(a.riskScore||0);
      if(sortBy==="risk_asc")  return (a.riskScore||0)-(b.riskScore||0);
      if(sortBy==="sev_desc")  return (SEV_ORDER[b.severity]||0)-(SEV_ORDER[a.severity]||0);
      if(sortBy==="pkg_asc")   return a.packageName.localeCompare(b.packageName);
      return 0;
    });

  if (!findings.length) return (
    <div style={s.emptyBox}>
      <p style={{margin:0,color:"#52c41a",fontWeight:600}}>No vulnerability matches found for this scan.</p>
      <p style={{margin:"0.5rem 0 0",fontSize:"0.8rem",color:"#8c8c8c"}}>
        This reflects the current local NVD cache and CPE matching. It does not guarantee absence of vulnerabilities.
      </p>
    </div>
  );

  return (
    <>
      <div style={s.controls}>
        <input type="text" placeholder="Search CVE or package..." value={search}
          onChange={e=>setSearch(e.target.value)} className="input" />
        <select value={sevFilter} onChange={e=>setSevFilter(e.target.value)} className="input">
          <option value="ALL">All Severities</option>
          {["CRITICAL","HIGH","MEDIUM","LOW","UNASSIGNED"].map(v=><option key={v} value={v}>{v}</option>)}
        </select>
        <select value={typeFilter} onChange={e=>setTypeFilter(e.target.value)} className="input">
          <option value="ALL">Direct + Transitive</option>
          <option value="DIRECT">Direct only</option>
          <option value="TRANSITIVE">Transitive only</option>
        </select>
        <select value={sortBy} onChange={e=>setSortBy(e.target.value)} className="input">
          {SORT_OPTIONS.map(o=><option key={o.value} value={o.value}>{o.label}</option>)}
        </select>
        <span style={{fontSize:"0.8rem",color:"#8c8c8c",whiteSpace:"nowrap"}}>{filtered.length} / {findings.length}</span>
      </div>
      <div className="table-container">
        <table className="table">
          <thead><tr>
            <th style={s.th}>CVE ID</th><th style={s.th}>Severity</th>
            <th style={s.th}>Package</th><th style={s.th}>Version</th>
            <th style={s.th}>Type</th><th style={s.th}>CVSS</th>
            <th style={s.th}>Risk</th><th style={s.th}>Description</th>
            <th style={s.th}></th>
          </tr></thead>
          <tbody>
            {filtered.length===0 ? (
              <tr><td colSpan={9} style={{...s.td,textAlign:"center",color:"#8c8c8c",padding:"2rem"}}>No findings match the current filters.</td></tr>
            ) : filtered.map(f=>(
              <tr key={f.matchId} style={s.tr}>
                <td style={{...s.td,fontFamily:"monospace",fontSize:"0.8rem",fontWeight:600}}>{f.cveId}</td>
                <td style={s.td}><SevBadge severity={f.severity} /></td>
                <td style={{...s.td,fontFamily:"monospace",fontSize:"0.82rem"}}>{f.packageName}</td>
                <td style={{...s.td,fontSize:"0.82rem",color:"#8c8c8c"}}>{f.packageVersion||"-"}</td>
                <td style={s.td}><span style={f.isDirect?s.directChip:s.transitiveChip}>{f.isDirect?"Direct":"Transitive"}</span></td>
                <td style={{...s.td,fontSize:"0.82rem"}}>{f.cvssScore??"-"}</td>
                <td style={{...s.td,fontWeight:700,color:f.riskScore>0?`var(--${SEV_VARIANT[f.severity] || 'neutral'})`:"#8c8c8c"}}>
                  <span title={`${f.severityWeight} x ${f.contextWeight}`}>{f.riskScore??"-"}</span>
                </td>
                <td style={s.td}>
                  <div style={{maxWidth:"220px",overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap",fontSize:"0.8rem",color:"#8c8c8c"}} title={f.description}>
                    {f.description||"-"}
                  </div>
                </td>
                <td style={s.td}><button onClick={()=>setSelected(f)} className="btn btn-outline text-xs">Details</button></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {selected && <FindingDetail finding={selected} onClose={()=>setSelected(null)} />}
    </>
  );
};

// ─── Phase 13: Dependency & SBOM Visualization ───────────────────────────────

/**
 * Package detail slide-in drawer for a single dependency.
 * Shows name, version, PURL, ecosystem, direct/transitive status.
 * If the package has findings in the dashboard data, links count is shown.
 */
const DepDetail = ({ dep, findingCount, onClose }) => {
  if (!dep) return null;
  return (
    <div style={s.drawerOverlay} onClick={onClose}>
      <div style={s.drawer} onClick={e => e.stopPropagation()}>
        <div style={s.drawerHeader}>
          <div>
            <h3 style={{ margin: 0, color: '#e2e8f0', fontSize: '1.05rem', fontFamily: 'monospace' }}>{dep.name}</h3>
            <div style={{ marginTop: '0.4rem', display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
              <span style={dep.isDirect ? s.directChip : s.transitiveChip}>{dep.isDirect ? 'Direct' : 'Transitive'}</span>
              <span style={{ fontSize: '0.78rem', color: '#8c8c8c' }}>{dep.ecosystem || 'npm'}</span>
            </div>
          </div>
          <button onClick={onClose} style={s.closeBtn}>x</button>
        </div>
        <div style={s.drawerBody}>
          <div style={s.drawerSection}>
            <div style={s.drawerLabel}>Version</div>
            <div style={{ fontFamily: 'monospace', fontSize: '0.9rem', color: '#e2e8f0', marginTop: '0.25rem' }}>{dep.version || 'unknown'}</div>
          </div>
          <div style={s.drawerSection}>
            <div style={s.drawerLabel}>Package URL (PURL)</div>
            <div style={{ fontFamily: 'monospace', fontSize: '0.75rem', color: '#b0b8c8', marginTop: '0.25rem', wordBreak: 'break-all' }}>{dep.purl}</div>
          </div>
          <div style={s.drawerSection}>
            <div style={s.drawerLabel}>Dependency Type</div>
            <div style={{ marginTop: '0.25rem', fontSize: '0.85rem', color: '#b0b8c8' }}>
              {dep.isDirect
                ? 'Direct — listed in package.json dependencies/devDependencies.'
                : 'Transitive — resolved by npm from a direct dependency.'}
            </div>
          </div>
          <div style={s.drawerSection}>
            <div style={s.drawerLabel}>Ecosystem</div>
            <div style={{ marginTop: '0.25rem', fontSize: '0.85rem', color: '#b0b8c8', textTransform: 'uppercase' }}>{dep.ecosystem || 'npm'}</div>
          </div>
          {findingCount > 0 && (
            <div style={{ background: '#ff4d4f18', border: '1px solid #ff4d4f44', borderRadius: '6px', padding: '0.75rem 1rem', marginTop: '0.5rem' }}>
              <div style={{ color: '#ff7a45', fontWeight: 700, fontSize: '0.85rem' }}>⚠️ {findingCount} Vulnerability Finding{findingCount !== 1 ? 's' : ''}</div>
              <div style={{ color: '#8c8c8c', fontSize: '0.78rem', marginTop: '0.3rem' }}>View the Security Report tab for detailed CVE information.</div>
            </div>
          )}
          {findingCount === 0 && (
            <div style={{ background: '#064e3b', border: '1px solid #059669', borderRadius: '6px', padding: '0.75rem 1rem', marginTop: '0.5rem' }}>
              <div style={{ color: '#52c41a', fontWeight: 600, fontSize: '0.85rem' }}>No vulnerability findings</div>
              <div style={{ color: '#8c8c8c', fontSize: '0.78rem', marginTop: '0.3rem' }}>No CVE matches found for this package in the local NVD cache.</div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

/**
 * Dependency and SBOM Visualization panel (Phase 13).
 *
 * Data sources:
 *   - /dependencies  → flat list with isDirect, name, version, purl, ecosystem
 *   - /sbom          → CycloneDX 1.5 JSON with metadata.timestamp, specVersion, components
 *   - /dashboard     → findings array used to compute per-package vulnerability counts
 *
 * Dependency graph limitation:
 *   Phase 6 extracts a flat dependency list from package.json + package-lock.json.
 *   Parent-child edges between transitive packages are NOT stored in the database.
 *   Therefore, a true dependency graph cannot be rendered without re-parsing the lockfile
 *   in the frontend, which is out of scope. A component-oriented visualization is provided
 *   instead, which accurately reflects the stored data.
 */
const DependencyVisualization = ({ projectId, scanId }) => {
  const [deps, setDeps] = useState(null);
  const [sbom, setSbom] = useState(null);
  const [vulnCountByName, setVulnCountByName] = useState({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [search, setSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState('ALL'); // ALL | DIRECT | TRANSITIVE
  const [selectedDep, setSelectedDep] = useState(null);
  const [sbomExpanded, setSbomExpanded] = useState(false);

  useEffect(() => {
    setDeps(null); setSbom(null); setLoading(true); setError('');
    setSearch(''); setTypeFilter('ALL'); setSelectedDep(null); setSbomExpanded(false);

    Promise.all([
      scanApi.getDependencies(projectId, scanId),
      scanApi.getSbom(projectId, scanId).catch(() => null), // SBOM may not exist yet
      scanApi.getDashboard(projectId, scanId).catch(() => null)
    ])
      .then(([depRes, sbomRes, dashRes]) => {
        setDeps(depRes.data.data || []);
        setSbom(sbomRes ? sbomRes.data.data : null);
        // Build per-package-name finding count from dashboard findings
        if (dashRes) {
          const counts = {};
          for (const f of (dashRes.data.data.findings || [])) {
            counts[f.packageName] = (counts[f.packageName] || 0) + 1;
          }
          setVulnCountByName(counts);
        }
      })
      .catch(e => setError(e.response?.data?.error?.message || 'Failed to load dependency data.'))
      .finally(() => setLoading(false));
  }, [projectId, scanId]);

  if (loading) return <div style={s.reportBox}><Spinner /></div>;
  if (error)   return <div style={s.reportBox}><p style={{ color: '#ff4d4f' }}>Error: {error}</p></div>;
  if (!deps)   return null;

  // Derived stats
  const totalDeps      = deps.length;
  const directDeps     = deps.filter(d => d.isDirect === true).length;
  const transitiveDeps = totalDeps - directDeps;
  const directPct      = totalDeps > 0 ? Math.round((directDeps / totalDeps) * 100) : 0;
  const transitivePct  = totalDeps > 0 ? 100 - directPct : 0;
  const vulnerableDeps = deps.filter(d => (vulnCountByName[d.name] || 0) > 0).length;

  // Filtered/searched list
  const visible = deps
    .filter(d => {
      if (typeFilter === 'DIRECT')     return d.isDirect === true;
      if (typeFilter === 'TRANSITIVE') return d.isDirect === false;
      return true;
    })
    .filter(d => {
      if (!search.trim()) return true;
      const q = search.toLowerCase();
      return (d.name || '').toLowerCase().includes(q) ||
             (d.version || '').toLowerCase().includes(q) ||
             (d.purl || '').toLowerCase().includes(q);
    });

  const downloadSbom = () => {
    const url = `${import.meta.env.VITE_API_URL || 'http://localhost:3000/api/v1'}/projects/${projectId}/scans/${scanId}/sbom?download=true`;
    window.open(url, '_blank');
  };

  return (
    <div style={s.reportBox}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.5rem', marginBottom: '1.25rem' }}>
        <h3 style={{ ...s.sectionTitle, margin: 0 }}>Dependencies &amp; SBOM</h3>
        {sbom && (
          <button onClick={downloadSbom} style={{ ...s.btnSecondary, borderColor: '#722ed1', color: '#b37feb' }} title="Download CycloneDX 1.5 SBOM">
            Download SBOM
          </button>
        )}
      </div>

      {/* Overview Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(130px, 1fr))', gap: '0.75rem', marginBottom: '1.25rem' }}>
        {[
          { label: 'Total', value: totalDeps,      color: '#e2e8f0' },
          { label: 'Direct',     value: directDeps,      color: '#1890ff' },
          { label: 'Transitive', value: transitiveDeps,  color: '#8c8c8c' },
          { label: 'Vulnerable', value: vulnerableDeps,  color: vulnerableDeps > 0 ? '#ff7a45' : '#52c41a' },
          { label: 'SBOM Components', value: sbom ? sbom.components?.length ?? 0 : '—', color: '#722ed1' },
        ].map(c => (
          <div key={c.label} style={s.summaryCard}>
            <div style={{ fontSize: '1.6rem', fontWeight: 700, color: c.color, lineHeight: 1 }}>{c.value}</div>
            <div style={{ fontSize: '0.76rem', color: '#8c8c8c', marginTop: '0.35rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>{c.label}</div>
          </div>
        ))}
      </div>

      {/* Direct vs Transitive breakdown bar */}
      {totalDeps > 0 && (
        <div style={{ marginBottom: '1.25rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.3rem', fontSize: '0.8rem' }}>
            <span style={{ color: '#1890ff', fontWeight: 600 }}>Direct {directPct}% ({directDeps})</span>
            <span style={{ color: '#8c8c8c' }}>Transitive {transitivePct}% ({transitiveDeps})</span>
          </div>
          <div style={{ height: '10px', borderRadius: '5px', backgroundColor: '#2d3748', overflow: 'hidden', display: 'flex' }}>
            <div style={{ width: `${directPct}%`, backgroundColor: '#1890ff', transition: 'width 0.4s ease' }} />
            <div style={{ width: `${transitivePct}%`, backgroundColor: '#4a5568', transition: 'width 0.4s ease' }} />
          </div>
          <div style={{ fontSize: '0.72rem', color: '#4a5568', marginTop: '0.3rem' }}>
            Ecosystem: npm. Relationships from package-lock.json — direct edges between transitive packages are not stored; see graph limitation note below.
          </div>
        </div>
      )}

      {/* SBOM Metadata Panel */}
      {sbom ? (
        <div style={{ ...s.sevBox, marginBottom: '1.25rem' }}>
          <div
            style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', cursor: 'pointer' }}
            onClick={() => setSbomExpanded(v => !v)}
          >
            <h3 style={{ ...s.sectionTitle, margin: 0 }}>SBOM Metadata <span style={{ color: '#722ed1' }}>CycloneDX {sbom.specVersion}</span></h3>
            <span style={{ color: '#8c8c8c', fontSize: '0.8rem' }}>{sbomExpanded ? '▲ Hide' : '▼ Show'}</span>
          </div>
          {sbomExpanded && (
            <div style={{ marginTop: '1rem', fontSize: '0.83rem', color: '#b0b8c8', lineHeight: 2 }}>
              <div>Format: <strong style={{ color: '#e2e8f0' }}>{sbom.bomFormat}</strong></div>
              <div>Spec Version: <strong style={{ color: '#722ed1' }}>{sbom.specVersion}</strong></div>
              <div>Serial Number: <code style={{ ...s.code, fontSize: '0.72rem' }}>{sbom.serialNumber}</code></div>
              <div>Generated: <strong style={{ color: '#e2e8f0' }}>{sbom.metadata?.timestamp ? new Date(sbom.metadata.timestamp).toLocaleString() : 'Unknown'}</strong></div>
              <div>Tool: <strong style={{ color: '#e2e8f0' }}>{sbom.metadata?.tools?.[0]?.name || 'DependShield Scanner'}</strong></div>
              <div>Component Count: <strong style={{ color: '#722ed1' }}>{sbom.components?.length ?? 0}</strong></div>
              <div style={{ marginTop: '0.5rem' }}>
                <button onClick={downloadSbom} style={{ ...s.btnSecondary, borderColor: '#722ed1', color: '#b37feb' }}>Download .cdx.json</button>
              </div>
            </div>
          )}
        </div>
      ) : (
        <div style={{ ...s.sevBox, marginBottom: '1.25rem', color: '#8c8c8c', fontSize: '0.85rem' }}>
          SBOM not yet generated for this scan.
        </div>
      )}

      {/* Dependency Table */}
      <div>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem', flexWrap: 'wrap', gap: '0.5rem' }}>
          <h3 style={{ ...s.sectionTitle, margin: 0 }}>Package List ({visible.length}{visible.length !== totalDeps ? ` of ${totalDeps}` : ''})</h3>
        </div>
        {totalDeps === 0 ? (
          <div style={s.emptyBox}>
            <p style={{ margin: 0, color: '#8c8c8c' }}>No dependencies extracted for this scan.</p>
          </div>
        ) : (
          <>
            {/* Filters */}
            <div style={{ ...s.controls, marginBottom: '0.75rem' }}>
              <input
                type="text"
                placeholder="Search package name, version, or PURL..."
                value={search}
                onChange={e => setSearch(e.target.value)}
                style={{ ...s.searchInput, flex: '1 1 200px' }}
                id="dep-search"
              />
              <select
                value={typeFilter}
                onChange={e => setTypeFilter(e.target.value)}
                className="input"
                id="dep-type-filter"
              >
                <option value="ALL">All Types</option>
                <option value="DIRECT">Direct only</option>
                <option value="TRANSITIVE">Transitive only</option>
              </select>
              <span style={{ fontSize: '0.78rem', color: '#8c8c8c', whiteSpace: 'nowrap' }}>{visible.length} shown</span>
            </div>

            {visible.length === 0 ? (
              <div style={s.emptyBox}><p style={{ margin: 0, color: '#8c8c8c' }}>No packages match the current filter.</p></div>
            ) : (
              <div className="table-container">
                <table className="table">
                  <thead>
                    <tr>
                      <th style={s.th}>Package</th>
                      <th style={s.th}>Version</th>
                      <th style={{ ...s.th, textAlign: 'center' }}>Type</th>
                      <th style={s.th}>Ecosystem</th>
                      <th style={{ ...s.th, textAlign: 'center' }}>Findings</th>
                      <th style={s.th}></th>
                    </tr>
                  </thead>
                  <tbody>
                    {visible.map(dep => {
                      const fCount = vulnCountByName[dep.name] || 0;
                      return (
                        <tr key={dep.id} style={s.tr}>
                          <td style={{ ...s.td, fontFamily: 'monospace', fontSize: '0.82rem', fontWeight: 600 }}>{dep.name}</td>
                          <td style={{ ...s.td, fontSize: '0.82rem', color: '#8c8c8c' }}>{dep.version || '—'}</td>
                          <td style={{ ...s.td, textAlign: 'center' }}>
                            <span style={dep.isDirect ? s.directChip : s.transitiveChip}>
                              {dep.isDirect ? 'Direct' : 'Transitive'}
                            </span>
                          </td>
                          <td style={{ ...s.td, fontSize: '0.8rem', color: '#8c8c8c', textTransform: 'uppercase' }}>{dep.ecosystem || 'npm'}</td>
                          <td style={{ ...s.td, textAlign: 'center', fontWeight: 700, color: fCount > 0 ? '#ff7a45' : '#52c41a' }}>
                            {fCount > 0 ? fCount : '✓'}
                          </td>
                          <td style={s.td}>
                            <button
                              onClick={() => setSelectedDep(dep)}
                              className="btn btn-outline text-xs"
                              title={`View details for ${dep.name}`}
                            >
                              Details
                            </button>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </>
        )}
      </div>

      {/* Graph Limitation Notice */}
      <div style={{ marginTop: '1.25rem', padding: '0.75rem 1rem', backgroundColor: '#0d1117', border: '1px solid #30363d', borderRadius: '6px', fontSize: '0.78rem', color: '#8c8c8c', lineHeight: 1.6 }}>
        <strong style={{ color: '#e2e8f0' }}>Dependency Graph Limitation:</strong> DependShield Phase 6 extracts a
        flat dependency list from <code style={s.code}>package.json</code> and <code style={s.code}>package-lock.json</code>.
        Parent-child edges between transitive packages (e.g., A → B → C) are determined by npm's resolver
        but are not persisted to the database as individual edges. Rendering a true dependency graph
        would require re-parsing the lockfile in the browser, which is outside the current scope.
        The table above accurately reflects all {totalDeps} resolved packages.
      </div>

      {/* Package Detail Drawer */}
      {selectedDep && (
        <DepDetail
          dep={selectedDep}
          findingCount={vulnCountByName[selectedDep.name] || 0}
          onClose={() => setSelectedDep(null)}
        />
      )}
    </div>
  );
};

// Scan Report Panel
const ScanReport = ({ projectId, scanId }) => {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  useEffect(()=>{
    setData(null); setLoading(true); setError("");
    scanApi.getDashboard(projectId, scanId)
      .then(res=>setData(res.data.data))
      .catch(e=>setError(e.response?.data?.error?.message||"Failed to load security report."))
      .finally(()=>setLoading(false));
  }, [projectId, scanId]);

  if (loading) return <div style={s.reportBox}><Spinner /></div>;
  if (error)   return <div style={s.reportBox}><p style={{color:"#ff4d4f"}}>Error: {error}</p></div>;
  if (!data)   return null;
  const { scan, summary, findings } = data;

  const downloadReport = (format) => {
    const url = `${import.meta.env.VITE_API_URL || "http://localhost:3000/api/v1"}/projects/${projectId}/scans/${scanId}/report?format=${format}&download=true`;
    window.open(url, "_blank");
  };

  const downloadSbom = () => {
    const url = `${import.meta.env.VITE_API_URL || "http://localhost:3000/api/v1"}/projects/${projectId}/scans/${scanId}/sbom?download=true`;
    window.open(url, "_blank");
  };

  return (
    <div style={s.reportBox}>
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",flexWrap:"wrap",gap:"0.5rem",marginBottom:"1rem"}}>
        <h3 style={{...s.sectionTitle,margin:0}}>Security Overview</h3>
        <div style={{display:"flex",gap:"0.5rem",flexWrap:"wrap"}}>
          <button onClick={()=>downloadReport('json')} className="btn btn-secondary" title="Download structured JSON report">Download Report (JSON)</button>
          <button onClick={()=>downloadReport('html')} className="btn btn-secondary" title="Download standalone HTML report">Download Report (HTML)</button>
          <button onClick={()=>downloadReport('markdown')} className="btn btn-secondary" title="Download Markdown report">Download Report (MD)</button>
          <button onClick={downloadSbom} className="btn btn-outline" style={{ borderColor: "var(--accent)", color: "var(--accent)" }} title="Download CycloneDX SBOM">Download SBOM</button>
        </div>
      </div>

      {scan && scan.status !== 'COMPLETED' && (
        <div style={{background:"#3b200b",border:"1px solid #d97706",color:"#fef3c7",padding:"0.75rem 1rem",borderRadius:"6px",marginBottom:"1rem",fontSize:"0.85rem"}}>
          ⚠️ <strong>Notice:</strong> Scan status is <strong>{scan.status}</strong>. {scan.errorMessage ? `Error: ${scan.errorMessage}` : "Results are preliminary until scan completes."}
        </div>
      )}

      {findings.length === 0 && (
        <div style={{background:"#064e3b",border:"1px solid #059669",color:"#d1fae5",padding:"0.75rem 1rem",borderRadius:"6px",marginBottom:"1rem",fontSize:"0.85rem"}}>
          <strong>Security Notice:</strong> Zero findings indicates no known vulnerabilities were detected in the local vulnerability database for the analyzed dependencies. It does not guarantee that the software is completely secure or free from unknown/zero-day vulnerabilities.
        </div>
      )}

      <SummaryCards summary={summary} />
      <RiskFormulaNote />
      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:"1rem",marginTop:"1rem"}}>
        <SeverityBreakdown counts={summary.severityCounts} total={summary.totalFindings} />
        <div style={s.sevBox}>
          <h3 style={{...s.sectionTitle,marginBottom:"0.75rem"}}>Dependency Context</h3>
          <div style={{fontSize:"0.85rem",color:"#b0b8c8",lineHeight:2}}>
            <div>Total: <strong style={{color:"#e2e8f0"}}>{summary.totalDependencies}</strong></div>
            <div>Direct: <strong style={{color:"#1890ff"}}>{summary.directDependencies}</strong></div>
            <div>Transitive: <strong style={{color:"#8c8c8c"}}>{summary.transitiveDependencies}</strong></div>
            <div style={{marginTop:"0.5rem"}}>SBOM components: <strong style={{color:"#722ed1"}}>{summary.sbomComponents!=null?summary.sbomComponents:"Not generated"}</strong></div>
            <div>SBOM format: <span style={{color:"#8c8c8c"}}>CycloneDX JSON v1.5</span></div>
            <div style={{marginTop:"0.75rem",display:"flex",gap:"0.5rem",flexWrap:"wrap"}}>
              <button onClick={downloadSbom} className="btn btn-secondary">Download SBOM</button>
              <button onClick={()=>downloadReport('json')} className="btn btn-secondary">Download Report (JSON)</button>
            </div>
          </div>
        </div>
      </div>
      <div style={{marginTop:"1.5rem"}}>
        <h3 style={{...s.sectionTitle,marginBottom:"0.75rem"}}>Vulnerability Findings ({findings.length})</h3>
        <FindingsTable findings={findings} />
      </div>
    </div>
  );
};

// Main Page
const ProjectDetails = () => {
  const { id } = useParams();
  const navigate = useNavigate();
  const [project, setProject] = useState(null);
  const [loading, setLoading] = useState(true);
  const [repoUrl, setRepoUrl] = useState("");
  const [repoError, setRepoError] = useState("");
  const [addingRepo, setAddingRepo] = useState(false);
  const [scans, setScans] = useState([]);
  const [scanError, setScanError] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [selectedScanId, setSelectedScanId] = useState(null);
  // Phase 13: tab state for scan detail section
  const [scanTab, setScanTab] = useState("security");
  const fileInputRef = useRef(null);
  const selectedScanIdRef = useRef(null);

  const fetchProjectData = useCallback(async () => {
    try {
      const [projRes, scansRes] = await Promise.all([projectApi.getProject(id), scanApi.getScans(id)]);
      setProject(projRes.data.data);
      const fetchedScans = scansRes.data.data;
      setScans(fetchedScans);
      if (!selectedScanIdRef.current) {
        const first = fetchedScans.find(s=>s.status==="COMPLETED");
        if (first) { setSelectedScanId(first.id); selectedScanIdRef.current = first.id; }
      }
    } catch (error) {
      if (error.response?.status===404) navigate("/");
    } finally { setLoading(false); }
  }, [id, navigate]);

  useEffect(()=>{ fetchProjectData(); }, [id]); // eslint-disable-line

  useEffect(()=>{
    const inProgress = scans.some(s=>["QUEUED","INGESTING","ANALYZING","EXTRACTING","SBOM_GENERATING","VULNERABILITY_ANALYSIS"].includes(s.status));
    if (!inProgress) return;
    const timer = setInterval(fetchProjectData, 5000);
    return ()=>clearInterval(timer);
  }, [scans, fetchProjectData]);

  const handleDeleteProject = async () => {
    if (!window.confirm("Delete this project?")) return;
    try { await projectApi.deleteProject(id); navigate("/"); } catch { alert("Failed"); }
  };
  const handleAddRepository = async (e) => {
    e.preventDefault(); setRepoError("");
    try {
      setAddingRepo(true);
      await projectApi.upsertRepository(id, repoUrl);
      const res = await projectApi.getProject(id);
      setProject(res.data.data); setRepoUrl("");
    } catch (error) {
      setRepoError(error.response?.data?.error?.details?.[0]?.message||error.response?.data?.error?.message||"Failed");
    } finally { setAddingRepo(false); }
  };
  const handleRemoveRepository = async () => {
    if (!window.confirm("Remove repository?")) return;
    try { await projectApi.deleteRepository(id); const res=await projectApi.getProject(id); setProject(res.data.data); }
    catch { alert("Failed"); }
  };
  const handleGithubScan = async () => {
    try { setIsScanning(true); setScanError(""); await scanApi.createGithubScan(id); await fetchProjectData(); }
    catch (error) { setScanError(error.response?.data?.error?.message||"Failed to start scan"); }
    finally { setIsScanning(false); }
  };
  const handleFileUpload = async (e) => {
    const file = e.target.files?.[0]; if (!file) return;
    try { setIsScanning(true); setScanError(""); await scanApi.uploadZipScan(id, file); await fetchProjectData(); }
    catch (error) { setScanError(error.response?.data?.error?.message||"Failed to upload ZIP"); }
    finally { setIsScanning(false); if (fileInputRef.current) fileInputRef.current.value=""; }
  };

  const handleSelectScan = (scanId) => { setSelectedScanId(scanId); selectedScanIdRef.current = scanId; setScanTab("security"); };

  if (loading) return <div style={s.page}><p style={{padding:"2rem",color:"#8c8c8c"}}>Loading project...</p></div>;
  if (!project) return null;

  return (
    <div style={s.page}>
      <header style={s.header}>
        <Link to="/" style={s.link}>Back to Dashboard</Link>
        <div style={{display:"flex",alignItems:"center",gap:"1rem"}}>
          <span style={{color:"#8c8c8c",fontSize:"0.85rem"}}>{project.name}</span>
          <button onClick={handleDeleteProject} className="btn btn-danger">Delete Project</button>
        </div>
      </header>
      <main style={s.main}>
        <div style={s.card}>
          <h1 style={{margin:0,color:"#e2e8f0",fontSize:"1.5rem"}}>{project.name}</h1>
          <p style={{margin:"0.5rem 0 0",color:"#8c8c8c"}}>{project.description||"No description provided."}</p>
          <small style={{color:"#4a5568"}}>Created {new Date(project.createdAt).toLocaleDateString()}</small>
        </div>
        <section style={s.section}>
          <h2 style={s.h2}>Source Repository</h2>
          {project.repository ? (
            <div style={s.card}>
              <div style={{display:"flex",justifyContent:"space-between",alignItems:"center"}}>
                <div>
                  <span style={{color:"#8c8c8c",fontSize:"0.8rem",marginRight:"0.5rem"}}>{project.repository.type}</span>
                  <a href={project.repository.url} target="_blank" rel="noreferrer" style={s.link}>{project.repository.url}</a>
                </div>
                <button onClick={handleRemoveRepository} className="btn btn-danger text-xs">Remove</button>
              </div>
            </div>
          ) : (
            <div style={s.card}>
              <p style={{color:"#8c8c8c",margin:"0 0 1rem"}}>No repository linked.</p>
              <form onSubmit={handleAddRepository} style={{display:"flex",gap:"0.75rem"}}>
                <input type="url" placeholder="https://github.com/owner/repo" value={repoUrl}
                  onChange={e=>setRepoUrl(e.target.value)} required className="input" />
                <button type="submit" disabled={addingRepo} className="btn btn-primary">{addingRepo?"Linking...":"Link Repository"}</button>
              </form>
              {repoError && <p style={{color:"#ff4d4f",marginTop:"0.5rem",fontSize:"0.85rem"}}>{repoError}</p>}
            </div>
          )}
        </section>
        <section style={s.section}>
          <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:"1rem"}}>
            <h2 style={s.h2}>Security Scans</h2>
            <div style={{display:"flex",gap:"0.75rem"}}>
              {project.repository?.type==="GITHUB" && (
                <button onClick={handleGithubScan} disabled={isScanning} className="btn btn-primary">
                  {isScanning?"Starting...":"Scan GitHub Repo"}
                </button>
              )}
              <input type="file" accept=".zip" style={{display:"none"}} ref={fileInputRef} onChange={handleFileUpload} />
              <button onClick={()=>fileInputRef.current?.click()} disabled={isScanning} className="btn btn-secondary">
                {isScanning?"Uploading...":"Upload ZIP"}
              </button>
            </div>
          </div>
          {scanError && <p style={{color:"#ff4d4f",marginBottom:"0.75rem",fontSize:"0.85rem"}}>Error: {scanError}</p>}
          <ScanHistoryTable scans={scans} selectedId={selectedScanId} onSelect={handleSelectScan} />
        </section>
        {selectedScanId && (
          <section style={s.section}>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:"0.75rem",flexWrap:"wrap",gap:"0.5rem"}}>
              <h2 style={{...s.h2,margin:0}}>Scan Details</h2>
              <span style={{fontFamily:"monospace",fontSize:"0.82rem",color:"#38bdf8"}}>
                Scan: {selectedScanId.slice(0, 8)}...
              </span>
            </div>
            {/* Phase 13: Tab bar */}
            <div style={{display:"flex",gap:0,marginBottom:"0",borderBottom:"2px solid var(--border)"}}>
              {[{id:"security",label:"Security Report"},{id:"deps",label:"Dependencies \u0026 SBOM"}].map(tab=>(
                <button
                  key={tab.id}
                  id={`scan-tab-${tab.id}`}
                  onClick={()=>setScanTab(tab.id)}
                  style={{
                    padding:"0.5rem 1.25rem",
                    border:"none",
                    borderBottom: scanTab===tab.id ? "2px solid var(--accent)" : "2px solid transparent",
                    marginBottom:"-2px",
                    backgroundColor:"transparent",
                    color: scanTab===tab.id ? "var(--accent)" : "#8c8c8c",
                    fontWeight: scanTab===tab.id ? 700 : 400,
                    cursor:"pointer",
                    fontSize:"0.88rem",
                    transition:"color 0.2s"
                  }}
                >{tab.label}</button>
              ))}
            </div>
            <div style={{marginTop:"1rem"}}>
              {scanTab==="security" && <ScanReport projectId={id} scanId={selectedScanId} />}
              {scanTab==="deps"     && <DependencyVisualization projectId={id} scanId={selectedScanId} />}
            </div>
          </section>
        )}
      </main>
    </div>
  );
};

const s = {
  page:{minHeight:"100vh",backgroundColor:"var(--bg)"},
  header:{display:"flex",justifyContent:"space-between",alignItems:"center",padding:"0.875rem 2rem",backgroundColor:"var(--code-bg)",borderBottom:"1px solid var(--border)"},
  link:{color:"var(--accent)",textDecoration:"none",fontSize:"0.9rem"},
  main:{maxWidth:"1100px",margin:"0 auto",padding:"2rem"},
  h2:{margin:"0 0 0.75rem",color:"#e2e8f0",fontSize:"1.15rem",fontWeight:600},
  sectionTitle:{margin:0,color:"#e2e8f0",fontSize:"0.95rem",fontWeight:600},
  section:{marginTop:"2rem"},
  card:{backgroundColor:"var(--code-bg)",padding:"1.5rem",borderRadius:"8px",border:"1px solid var(--border)",marginBottom:"0.75rem"},
  reportBox:{backgroundColor:"var(--code-bg)",padding:"1.5rem",borderRadius:"8px",border:"1px solid var(--border)"},
  emptyBox:{padding:"2rem",textAlign:"center",backgroundColor:"var(--code-bg)",borderRadius:"8px",border:"1px dashed var(--border)"},
  cardGrid:{display:"grid",gridTemplateColumns:"repeat(auto-fill, minmax(140px, 1fr))",gap:"0.75rem",marginBottom:"1rem"},
  summaryCard:{backgroundColor:"var(--bg)",padding:"1rem",borderRadius:"6px",border:"1px solid var(--border)",textAlign:"center"},
  summaryCardLarge:{border:"1px solid #ff7a4550"},
  sevBox:{backgroundColor:"var(--bg)",padding:"1rem",borderRadius:"6px",border:"1px solid var(--border)"},
  formulaBox:{backgroundColor:"#0d1117",padding:"0.75rem 1rem",borderRadius:"6px",border:"1px solid #30363d",marginTop:"1rem"},
  code:{fontFamily:"monospace",fontSize:"0.82rem",color:"#e2e8f0",backgroundColor:"#161b22",padding:"0.15rem 0.4rem",borderRadius:"3px"},
  tableWrap:{overflowX:"auto",borderRadius:"6px",border:"1px solid var(--border)"},
  table:{width:"100%",borderCollapse:"collapse",fontSize:"0.83rem"},
  th:{padding:"0.55rem 0.9rem",textAlign:"left",backgroundColor:"var(--bg)",color:"#8c8c8c",fontWeight:600,borderBottom:"1px solid var(--border)",whiteSpace:"nowrap"},
  td:{padding:"0.5rem 0.9rem",borderBottom:"1px solid var(--border)",color:"#e2e8f0",verticalAlign:"middle"},
  tr:{},
  controls:{display:"flex",gap:"0.6rem",marginBottom:"0.75rem",flexWrap:"wrap",alignItems:"center"},
  searchInput:{padding:"0.4rem 0.75rem",borderRadius:"4px",border:"1px solid var(--border)",backgroundColor:"var(--bg)",color:"var(--text-h)",fontSize:"0.82rem",flex:"1 1 160px"},
  selectInput:{padding:"0.4rem 0.6rem",borderRadius:"4px",border:"1px solid var(--border)",backgroundColor:"var(--bg)",color:"var(--text-h)",fontSize:"0.82rem"},
  input:{flex:1,padding:"0.5rem 0.75rem",borderRadius:"4px",border:"1px solid var(--border)",backgroundColor:"var(--bg)",color:"var(--text-h)"},
  btnPrimary:{padding:"0.45rem 1rem",backgroundColor:"var(--accent)",color:"#fff",border:"none",borderRadius:"4px",cursor:"pointer",fontWeight:600,fontSize:"0.85rem"},
  btnSecondary:{padding:"0.4rem 0.9rem",backgroundColor:"transparent",color:"var(--accent)",border:"1px solid var(--accent)",borderRadius:"4px",cursor:"pointer",fontSize:"0.82rem"},
  btnActive:{padding:"0.4rem 0.9rem",backgroundColor:"var(--accent)",color:"#fff",border:"none",borderRadius:"4px",cursor:"pointer",fontSize:"0.82rem"},
  btnDanger:{padding:"0.4rem 0.9rem",backgroundColor:"transparent",color:"#ff4d4f",border:"1px solid #ff4d4f",borderRadius:"4px",cursor:"pointer",fontSize:"0.82rem"},
  btnDangerSm:{padding:"0.25rem 0.6rem",backgroundColor:"transparent",color:"#ff4d4f",border:"1px solid #ff4d4f",borderRadius:"4px",cursor:"pointer",fontSize:"0.78rem"},
  detailBtn:{padding:"0.25rem 0.6rem",backgroundColor:"transparent",color:"var(--accent)",border:"1px solid var(--accent)",borderRadius:"4px",cursor:"pointer",fontSize:"0.75rem"},
  directChip:{padding:"0.1rem 0.45rem",borderRadius:"10px",fontSize:"0.72rem",fontWeight:700,backgroundColor:"#1890ff18",color:"#1890ff"},
  transitiveChip:{padding:"0.1rem 0.45rem",borderRadius:"10px",fontSize:"0.72rem",fontWeight:700,backgroundColor:"#ffffff10",color:"#8c8c8c"},
  monoChip:{fontFamily:"monospace",fontSize:"0.8rem",backgroundColor:"var(--bg)",padding:"0.1rem 0.4rem",borderRadius:"3px",color:"#e2e8f0"},
  drawerOverlay:{position:"fixed",inset:0,backgroundColor:"rgba(0,0,0,0.6)",zIndex:1000,display:"flex",justifyContent:"flex-end"},
  drawer:{width:"480px",maxWidth:"95vw",backgroundColor:"#161b22",borderLeft:"1px solid #30363d",overflowY:"auto",display:"flex",flexDirection:"column"},
  drawerHeader:{display:"flex",justifyContent:"space-between",alignItems:"flex-start",padding:"1.25rem 1.5rem",borderBottom:"1px solid #30363d",backgroundColor:"#0d1117"},
  drawerBody:{padding:"1.25rem 1.5rem",flex:1},
  drawerSection:{marginBottom:"1.25rem"},
  drawerLabel:{fontSize:"0.72rem",color:"#8c8c8c",textTransform:"uppercase",letterSpacing:"0.07em",fontWeight:600},
  riskCalcRow:{display:"flex",gap:"0.5rem",alignItems:"center",fontSize:"0.85rem",marginTop:"0.35rem",flexWrap:"wrap"},
  closeBtn:{background:"none",border:"none",color:"#8c8c8c",cursor:"pointer",fontSize:"1.1rem",padding:"0.2rem",lineHeight:1},
};

export default ProjectDetails;
