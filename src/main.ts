import './style.css';
import { invoke } from '@tauri-apps/api/core';
import { open, save } from '@tauri-apps/plugin-dialog';
import { writeTextFile, readTextFile } from '@tauri-apps/plugin-fs';

// Track last audit result for JSON export
let lastAuditResult: any = null;

// Expose handlers globally for inline onclick attributes
const closeDnsModal = () => document.getElementById('dns-modal')!.style.display = 'none';
const closeSslModal = () => document.getElementById('ssl-modal')!.style.display = 'none';
const closePortModal = () => document.getElementById('port-modal')!.style.display = 'none';

const openDnsModal = () => document.getElementById('dns-modal')!.style.display = 'flex';
const openSslModal = () => document.getElementById('ssl-modal')!.style.display = 'flex';
const openPortModal = () => document.getElementById('port-modal')!.style.display = 'flex';

window['closeDnsModal'] = closeDnsModal;
window['closeSslModal'] = closeSslModal;
window['closePortModal'] = closePortModal;
window['openDnsModal'] = openDnsModal;
window['openSslModal'] = openSslModal;
window['openPortModal'] = openPortModal;

const closeAll = () => {
  document.querySelectorAll('.modal-overlay').forEach(el => (el as HTMLElement).style.display = 'none');
};

// Display risk score card from backend result
const displayRiskScore = async (findings: any[]) => {
  const riskCard = document.getElementById('risk-score-card') as HTMLElement;
  if (!riskCard) return;

  try {
    const scoreData: any = await invoke('calculate_risk_score', { findings });
    riskCard.style.display = 'block';

    const scoreEl = document.getElementById('risk-score') as HTMLElement;
    const levelEl = document.getElementById('risk-level') as HTMLElement;
    const summaryEl = document.getElementById('risk-executive-summary') as HTMLElement;
    const breakdownEl = document.getElementById('severity-breakdown') as HTMLElement;

    // Set score
    scoreEl.textContent = `${scoreData.score}/100`;

    // Set level badge
    levelEl.textContent = `Risk: ${scoreData.level}`;
    levelEl.className = `risk-badge risk-${scoreData.level.toLowerCase()}`;

    // Set executive summary
    summaryEl.textContent = scoreData.executive_summary;

    // Build severity breakdown
    const severities = [
      { label: 'Critical', count: scoreData.critical_count },
      { label: 'High', count: scoreData.high_count },
      { label: 'Medium', count: scoreData.medium_count },
      { label: 'Low', count: scoreData.low_count },
      { label: 'Good', count: scoreData.good_count },
    ];
    breakdownEl.innerHTML = severities
      .filter(s => s.count > 0)
      .map(s => `<span class="severity-tag severity-${s.label.toLowerCase()}">${s.label}: ${s.count}</span>`)
      .join('');
  } catch (e: any) {
    console.error('Risk score calculation failed:', e);
    riskCard.style.display = 'none';
  }
};

// DNS Audit
const runDnsAudit = async () => {
  const domain = (document.getElementById('dns-input') as HTMLInputElement)!.value.trim();
  if (!domain) { alert('Please enter a domain'); return; }

  closeAll();
  const panel = document.getElementById('results-panel')!;
  document.getElementById('results-title')!.style.display = 'block';
  panel.style.display = 'block';
  panel.innerHTML = '<p>Running DNS audit...</p>';

  try {
    const envelope: any = await invoke('check_email_security', { domain });
    if (envelope.error || !envelope.success) throw new Error(envelope.message || 'DNS audit failed');
    const result = envelope.data;

    const recommendations = result.findings
      .filter((f: any) => f.recommendation)
      .map((f: any) => f.recommendation);

    // Calculate risk score from findings
    await displayRiskScore(result.findings);

    let html = `<h4>DNS & Email Security — ${domain}</h4>`;
    html += `<div style="margin:10px 0">${renderFindings(result.findings)}</div>`;
    if (recommendations.length > 0) {
      html += `<p><em>${recommendations.join(' ')}</em></p>`;
    }

    // Insert findings after risk score card
    const riskCard = document.getElementById('risk-score-card');
    if (riskCard && riskCard.style.display !== 'none') {
      const findingsContainer = document.createElement('div');
      findingsContainer.id = 'findings-container';
      findingsContainer.innerHTML = html;
      riskCard.after(findingsContainer);
    } else {
      panel.innerHTML = html;
    }

    lastAuditResult = { audit_type: 'dns', ...result };
  } catch (e: any) {
    panel.innerHTML = `<p style="color:#ef4444">Error: ${e.message || e}</p>`;
  }
};

// SSL Audit
const runSslAudit = async () => {
  let target = (document.getElementById('ssl-input') as HTMLInputElement)!.value.trim();
  if (!target) { alert('Please enter a URL'); return; }
  if (!target.startsWith('http')) target = 'https://' + target;

  closeAll();
  const panel = document.getElementById('results-panel')!;
  document.getElementById('results-title')!.style.display = 'block';
  panel.style.display = 'block';
  panel.innerHTML = '<p>Running SSL/TLS audit...</p>';

  try {
    const envelope: any = await invoke('check_ssl', { target });
    if (envelope.error || !envelope.success) throw new Error(envelope.message || 'SSL audit failed');
    const result = envelope.data;

    const recommendations = result.findings
      .filter((f: any) => f.recommendation)
      .map((f: any) => f.recommendation);

    // Calculate risk score from findings
    await displayRiskScore(result.findings);

    let html = `<h4>SSL/TLS Certificate — ${target}</h4>`;
    html += `<div style="margin:10px 0">${renderFindings(result.findings)}</div>`;
    if (recommendations.length > 0) {
      html += `<p><em>${recommendations.join(' ')}</em></p>`;
    }

    const riskCard = document.getElementById('risk-score-card');
    if (riskCard && riskCard.style.display !== 'none') {
      const findingsContainer = document.createElement('div');
      findingsContainer.id = 'findings-container';
      findingsContainer.innerHTML = html;
      riskCard.after(findingsContainer);
    } else {
      panel.innerHTML = html;
    }

    lastAuditResult = { audit_type: 'ssl', ...result };
  } catch (e: any) {
    panel.innerHTML = `<p style="color:#ef4444">Error: ${e.message || e}</p>`;
  }
};

// Firewall Audit
const runFirewallAudit = async () => {
  try {
    const file: any = await open({
      multiple: false,
      filters: [{ name: 'Config Files', extensions: ['conf', 'cfg', 'txt', 'rules', 'iptables', 'nftables'] }]
    });
    if (!file) return;

    const panel = document.getElementById('results-panel')!;
    document.getElementById('results-title')!.style.display = 'block';
    panel.style.display = 'block';
    panel.innerHTML = '<p>Analyzing firewall configuration...</p>';

    const content = await readTextFile(file);
    const envelope: any = await invoke('analyze_firewall', { content });
    if (envelope.error || !envelope.success) throw new Error(envelope.message || 'Firewall analysis failed');
    const result = envelope.data;

    // Calculate risk score from findings
    await displayRiskScore(result.findings);

    let html = `<h4>Firewall Configuration Analysis</h4>`;
    html += `<p>Rules analyzed: ${result.rules_count || 'N/A'}</p>`;
    html += `<div style="margin:10px 0">${renderFindings(result.findings)}</div>`;

    const riskCard = document.getElementById('risk-score-card');
    if (riskCard && riskCard.style.display !== 'none') {
      const findingsContainer = document.createElement('div');
      findingsContainer.id = 'findings-container';
      findingsContainer.innerHTML = html;
      riskCard.after(findingsContainer);
    } else {
      panel.innerHTML = html;
    }

    lastAuditResult = { audit_type: 'firewall', ...result };
    console.log('Firewall audit completed:', result);
  } catch (e: any) {
    const panel = document.getElementById('results-panel')!;
    panel.innerHTML = `<p style="color:#ef4444">Error: ${e.message || e}</p>`;
  }
};

// Port Scanner Audit
const runPortScan = async () => {
  const target = (document.getElementById('port-input') as HTMLInputElement)!.value.trim();
  if (!target) { alert('Please enter a target IP or domain'); return; }

  closeAll();
  const panel = document.getElementById('results-panel')!;
  document.getElementById('results-title')!.style.display = 'block';
  panel.style.display = 'block';
  panel.innerHTML = '<p>Scanning ports...</p>';

  try {
    const envelope: any = await invoke('scan_ports', { target });
    if (envelope.error || !envelope.success) throw new Error(envelope.message || 'Port scan failed');
    const result = envelope.data;

    // Calculate risk score from findings
    await displayRiskScore(result.findings);

    let html = `<h4>Network Port Scan — ${target}</h4>`;
    html += `<div style="margin:10px 0">${renderFindings(result.findings)}</div>`;

    const riskCard = document.getElementById('risk-score-card');
    if (riskCard && riskCard.style.display !== 'none') {
      const findingsContainer = document.createElement('div');
      findingsContainer.id = 'findings-container';
      findingsContainer.innerHTML = html;
      riskCard.after(findingsContainer);
    } else {
      panel.innerHTML = html;
    }

    lastAuditResult = { audit_type: 'port_scan', ...result };
  } catch (e: any) {
    panel.innerHTML = `<p style="color:#ef4444">Error: ${e.message || e}</p>`;
  }
};

// Render findings with severity badges
const renderFindings = (findings: any[]) => {
  if (!findings || findings.length === 0) return '<p>No issues found.</p>';
  return findings.map(f => {
    const color = getSeverityColor(f.severity);
    return `<div style="border-left:3px solid ${color};padding-left:10px;margin:5px 0">
      <span style="color:${color};font-weight:600">[${f.severity.toUpperCase()}]</span>
      <strong>${f.title}</strong><br/>
      ${f.description}</div>`;
  }).join('');
};

const getSeverityColor = (s: string) => {
  const c = s.toLowerCase();
  if (c.includes('critical') || c.includes('high')) return '#ef4444';
  if (c.includes('medium')) return '#f59e0b';
  return '#10b981';
};

// Export report
const openExportModal = () => {
  if (!lastAuditResult) {
    alert('No audit has been run yet. Run an audit first.');
    return;
  }
  document.getElementById('export-modal')!.style.display = 'flex';
};

const exportAsText = async () => {
  const textContent = document.getElementById('results-panel')!.innerText || 'No results to export.';
  try {
    const path = await save({
      title: 'Save Report as Text',
      filters: [{ name: 'Text Files', extensions: ['txt', 'md'] }],
      defaultPath: `ency-audit-report-${Date.now()}.txt`
    });
    if (path) {
      await writeTextFile(path, textContent);
      alert('Report saved!');
    }
  } catch (e: any) {
    console.error('[EXPORT] exportAsText error:', e);
    if (!e.message?.includes('cancelled')) alert(`Error: ${e.message || e}`);
  }
};

const exportAsJson = async () => {
  try {
    const path = await save({
      title: 'Save Report as JSON',
      filters: [{ name: 'JSON Files', extensions: ['json'] }],
      defaultPath: `ency-audit-report-${Date.now()}.json`
    });
    if (path) {
      await invoke('export_json_report', {
        path,
        data: JSON.stringify(lastAuditResult)
      });
      alert('JSON report saved!');
    }
  } catch (e: any) {
    console.error('[EXPORT] exportAsJson error:', e);
    if (!e.message?.includes('cancelled')) alert(`Error: ${e.message || e}`);
  }
};

// Export report button handler
const exportReport = () => openExportModal();

// Wire up event listeners
document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('run-dns-btn')!.addEventListener('click', openDnsModal);
  document.getElementById('run-ssl-btn')!.addEventListener('click', openSslModal);
  document.getElementById('run-fw-btn')!.addEventListener('click', runFirewallAudit);
  document.getElementById('run-port-btn')!.addEventListener('click', openPortModal);
  document.getElementById('export-btn')!.addEventListener('click', exportReport);
});

// Expose all handlers for inline onclick attributes
window['runDnsAudit'] = runDnsAudit;
window['runSslAudit'] = runSslAudit;
window['runFirewallAudit'] = runFirewallAudit;
window['runPortScan'] = runPortScan;
window['exportReport'] = exportReport;
window['exportAsText'] = exportAsText;
window['exportAsJson'] = exportAsJson;
window['closeModal'] = (id: string) => document.getElementById(id)!.style.display = 'none';
