/**
 * SentinelX — Web Security Auditor Client
 * Handles real-time scan polling, evidence rendering, interactive filtering,
 * AI remediation advisory, and report generation triggers.
 */

let currentScanId = null;
let currentFindings = [];
let activeSeverityFilter = "";
let currentSearchTerm = "";
let pollInterval = null;
let riskChartInstance = null;
let selectedHistoryIds = new Set();

document.addEventListener("DOMContentLoaded", () => {
    initApp();
    bindEvents();
});

async function initApp() {
    await checkEngineHealth();
    // Auto-refresh engine health every 30s
    setInterval(checkEngineHealth, 30000);
}

function bindEvents() {
    const scanForm = document.getElementById("scanForm");
    scanForm.addEventListener("submit", handleScanSubmit);

    document.getElementById("btnFillTestTarget").addEventListener("click", () => {
        document.getElementById("targetUrl").value = "http://127.0.0.1:5050";
        document.getElementById("authCheckbox").checked = true;
    });

    // Severity Filters
    const filterGroup = document.getElementById("severityFilterGroup");
    filterGroup.querySelectorAll("button").forEach(btn => {
        btn.addEventListener("click", () => {
            filterGroup.querySelectorAll("button").forEach(b => {
                b.classList.remove("active", "bg-cyan-600", "text-white");
                b.classList.add("bg-cyber-700", "text-slate-300");
            });
            btn.classList.add("active", "bg-cyan-600", "text-white");
            btn.classList.remove("bg-cyber-700", "text-slate-300");
            activeSeverityFilter = btn.dataset.severity;
            renderFindingsTable();
        });
    });

    // Search input
    document.getElementById("findingSearchInput").addEventListener("input", (e) => {
        currentSearchTerm = e.target.value.toLowerCase().trim();
        renderFindingsTable();
    });

    // Drawer Controls
    document.getElementById("btnCloseDrawer").addEventListener("click", closeDrawer);
    document.getElementById("findingDrawerBackdrop").addEventListener("click", (e) => {
        if (e.target.id === "findingDrawerBackdrop") closeDrawer();
    });

    // Drawer Tabs
    document.getElementById("tabBtnRemediation").addEventListener("click", () => switchDrawerTab("remediation"));
    document.getElementById("tabBtnAiAdvisory").addEventListener("click", () => switchDrawerTab("ai"));

    // Export buttons
    document.getElementById("btnExportPdf").addEventListener("click", () => {
        if (currentScanId) window.location.href = `/api/scans/${currentScanId}/export/pdf`;
    });
    document.getElementById("btnExportJson").addEventListener("click", () => {
        if (currentScanId) window.location.href = `/api/scans/${currentScanId}/export/json`;
    });

    // History Modal Controls
    document.getElementById("btnOpenHistory").addEventListener("click", openHistoryModal);
    document.getElementById("btnCloseHistory").addEventListener("click", closeHistoryModal);
    document.getElementById("btnCompareSelected").addEventListener("click", handleCompareScans);
}

// 1. Engine Health Status
async function checkEngineHealth() {
    try {
        const resp = await fetch("/api/status");
        if (!resp.ok) return;
        const data = await resp.json();
        
        const dot = document.getElementById("zapStatusDot");
        const txt = document.getElementById("zapStatusText");
        
        if (data.zap_engine && data.zap_engine.online) {
            dot.className = "pulse-dot bg-emerald-500 mr-2";
            txt.textContent = `OWASP ZAP Core v${data.zap_engine.version}: Connected`;
            txt.title = "Live connection established to OWASP ZAP daemon.";
        } else {
            dot.className = "pulse-dot pulse-dot-red bg-cyan-400 mr-2";
            txt.textContent = "ZAP Offline (Native Engine Active)";
            txt.title = data.zap_engine ? data.zap_engine.diagnostics : "Native auditor ready.";
        }
    } catch (e) {
        console.error("Health check error:", e);
    }
}

// 2. Scan Submission
async function handleScanSubmit(e) {
    e.preventDefault();
    const errBox = document.getElementById("formErrorMessage");
    const errText = document.getElementById("formErrorText");
    errBox.classList.add("hidden");

    const targetUrl = document.getElementById("targetUrl").value.trim();
    const selectedProfile = document.querySelector('input[name="scanProfile"]:checked').value;
    const isAuthorized = document.getElementById("authCheckbox").checked;

    if (!isAuthorized) {
        errText.textContent = "You must confirm explicit authorization certification.";
        errBox.classList.remove("hidden");
        return;
    }

    const btnSubmit = document.getElementById("btnStartScan");
    btnSubmit.disabled = true;
    btnSubmit.innerHTML = `<i class="fa-solid fa-spinner fa-spin mr-2"></i> Initializing...`;

    try {
        const resp = await fetch("/api/scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                url: targetUrl,
                profile: selectedProfile,
                authorized: true
            })
        });

        const result = await resp.json();
        if (!resp.ok) {
            errText.textContent = result.message || result.error || "Scan request rejected.";
            errBox.classList.remove("hidden");
            btnSubmit.disabled = false;
            btnSubmit.innerHTML = `<i class="fa-solid fa-play text-xs"></i> Launch Security Audit`;
            return;
        }

        // Scan started successfully
        currentScanId = result.scan_id;
        startScanTracking(result.scan_id, targetUrl, selectedProfile);

    } catch (err) {
        errText.textContent = "Network error communicating with SentinelX API.";
        errBox.classList.remove("hidden");
    } finally {
        btnSubmit.disabled = false;
        btnSubmit.innerHTML = `<i class="fa-solid fa-play text-xs"></i> Launch Security Audit`;
    }
}

// 3. Scan Tracking & Live Progress
function startScanTracking(scanId, targetUrl, profile) {
    // Show Progress Section
    const progressSection = document.getElementById("progressSection");
    progressSection.classList.remove("hidden");
    document.getElementById("resultsSection").classList.add("hidden");

    document.getElementById("activeScanTarget").textContent = targetUrl;
    document.getElementById("activeScanProfileTag").textContent = profile.toUpperCase();
    document.getElementById("activeScanPercentText").textContent = "5%";
    document.getElementById("activeProgressBar").style.width = "5%";
    document.getElementById("activeScanStage").textContent = "Validating Target & Initializing Engine...";

    const terminal = document.getElementById("liveTerminalLogs");
    terminal.innerHTML = "";

    if (pollInterval) clearInterval(pollInterval);
    pollInterval = setInterval(() => pollScanStatus(scanId), 1200);
}

async function pollScanStatus(scanId) {
    try {
        const [scanResp, logResp] = await Promise.all([
            fetch(`/api/scans/${scanId}`),
            fetch(`/api/scans/${scanId}/logs`)
        ]);

        if (!scanResp.ok) return;
        const scanData = (await scanResp.json()).scan;
        const logData = (await logResp.json()).logs || [];

        // Update Progress UI
        const percent = scanData.progress || 0;
        document.getElementById("activeScanPercentText").textContent = `${percent}%`;
        document.getElementById("activeProgressBar").style.width = `${percent}%`;
        document.getElementById("activeScanStage").textContent = scanData.stage || "Auditing...";

        // Update Terminal Logs
        document.getElementById("logCount").textContent = logData.length;
        const terminal = document.getElementById("liveTerminalLogs");
        terminal.innerHTML = logData.map(l => {
            const levelColor = l.level === "ERROR" ? "text-rose-400" : (l.level === "WARN" ? "text-amber-400" : "text-slate-400");
            const timeStr = l.timestamp.split("T")[1]?.slice(0, 8) || "";
            return `<div class="leading-relaxed"><span class="text-slate-600">[${timeStr}]</span> <span class="${levelColor} font-bold">[${l.level}]</span> ${escapeHtml(l.message)}</div>`;
        }).join("");
        terminal.scrollTop = terminal.scrollHeight;

        // Check completion or failure
        if (scanData.status === "completed") {
            clearInterval(pollInterval);
            pollInterval = null;
            setTimeout(() => {
                document.getElementById("progressSection").classList.add("hidden");
                loadScanResults(scanId);
            }, 800);
        } else if (scanData.status === "failed") {
            clearInterval(pollInterval);
            pollInterval = null;
            document.getElementById("activeScanStage").innerHTML = `<span class="text-rose-400 font-bold">Failed: ${escapeHtml(scanData.error_message || "Unknown error")}</span>`;
        }
    } catch (e) {
        console.error("Polling error:", e);
    }
}

// 4. Load & Display Scan Results
async function loadScanResults(scanId) {
    try {
        const [scanResp, findingsResp] = await Promise.all([
            fetch(`/api/scans/${scanId}`),
            fetch(`/api/scans/${scanId}/findings`)
        ]);

        if (!scanResp.ok || !findingsResp.ok) return;

        const scan = (await scanResp.json()).scan;
        const findingsData = await findingsResp.json();
        currentFindings = findingsData.findings || [];

        // Update Executive Metrics
        const riskScore = scan.risk_score;
        document.getElementById("metricRiskScore").textContent = riskScore;
        const gradeBadge = document.getElementById("metricRiskGrade");
        
        if (riskScore >= 95) {
            gradeBadge.textContent = "GRADE A (SECURE)";
            gradeBadge.className = "text-[11px] font-bold px-2 py-0.5 rounded mt-1.5 inline-block bg-emerald-950 text-emerald-400 border border-emerald-800";
        } else if (riskScore >= 80) {
            gradeBadge.textContent = "GRADE B (LOW RISK)";
            gradeBadge.className = "text-[11px] font-bold px-2 py-0.5 rounded mt-1.5 inline-block bg-blue-950 text-blue-400 border border-blue-800";
        } else if (riskScore >= 65) {
            gradeBadge.textContent = "GRADE C (MODERATE RISK)";
            gradeBadge.className = "text-[11px] font-bold px-2 py-0.5 rounded mt-1.5 inline-block bg-amber-950 text-amber-400 border border-amber-800";
        } else {
            gradeBadge.textContent = "GRADE F (CRITICAL RISK)";
            gradeBadge.className = "text-[11px] font-bold px-2 py-0.5 rounded mt-1.5 inline-block bg-rose-950 text-rose-400 border border-rose-800";
        }

        document.getElementById("metricTotalFindings").textContent = scan.total_findings;
        document.getElementById("metricHighCount").textContent = scan.high_count;
        document.getElementById("metricMediumCount").textContent = scan.medium_count;
        document.getElementById("metricLowCount").textContent = scan.low_count;
        document.getElementById("metricInfoCount").textContent = scan.info_count;

        // Update Filter Badge Counts
        document.getElementById("filterCountAll").textContent = scan.total_findings;
        document.getElementById("filterCountHigh").textContent = scan.high_count;
        document.getElementById("filterCountMedium").textContent = scan.medium_count;
        document.getElementById("filterCountLow").textContent = scan.low_count;
        document.getElementById("filterCountInfo").textContent = scan.info_count;

        // Render Doughnut Chart
        renderRiskMiniChart(scan.high_count, scan.medium_count, scan.low_count, scan.info_count);

        // Render Table
        renderFindingsTable();

        // Show Results Section
        document.getElementById("resultsSection").classList.remove("hidden");
        document.getElementById("resultsSection").scrollIntoView({ behavior: "smooth" });

    } catch (e) {
        console.error("Load results error:", e);
    }
}

// 5. Render Findings Table
function renderFindingsTable() {
    const tbody = document.getElementById("findingsTableBody");
    const emptyState = document.getElementById("findingsEmptyState");

    // Filter
    const filtered = currentFindings.filter(f => {
        if (activeSeverityFilter && f.severity !== activeSeverityFilter) return false;
        if (currentSearchTerm) {
            const corpus = `${f.name} ${f.description} ${f.affected_url} ${f.cwe_id}`.toLowerCase();
            if (!corpus.includes(currentSearchTerm)) return false;
        }
        return true;
    });

    if (filtered.length === 0) {
        tbody.innerHTML = "";
        emptyState.classList.remove("hidden");
        return;
    }

    emptyState.classList.add("hidden");
    tbody.innerHTML = filtered.map(f => {
        const sevClass = f.severity === "High" ? "badge-high" : (f.severity === "Medium" ? "badge-medium" : (f.severity === "Low" ? "badge-low" : "badge-info"));
        const cweLabel = f.cwe_id ? `<span class="font-mono text-[10px] text-cyan-400">${f.cwe_id}</span>` : `<span class="text-slate-500 font-mono text-[10px]">-</span>`;
        const statusLabel = f.status === "Confirmed Evidence" ? `<span class="text-emerald-400"><i class="fa-solid fa-check-double text-[10px] mr-1"></i>Evidence</span>` : `<span class="text-slate-400">Potential</span>`;
        
        return `
            <tr class="hover:bg-cyber-700/50 cursor-pointer transition" onclick="openFindingDetail('${f.id}')">
                <td class="py-3 px-4 whitespace-nowrap">
                    <span class="px-2 py-0.5 rounded text-[10px] font-bold ${sevClass}">${f.severity.toUpperCase()}</span>
                </td>
                <td class="py-3 px-4 font-semibold text-white">
                    ${escapeHtml(f.name)}
                </td>
                <td class="py-3 px-4 whitespace-nowrap">
                    ${cweLabel}
                </td>
                <td class="py-3 px-4 font-mono text-slate-300 max-w-xs truncate" title="${escapeHtml(f.affected_url)}">
                    ${escapeHtml(f.affected_url)}
                </td>
                <td class="py-3 px-4 whitespace-nowrap text-[11px]">
                    ${statusLabel}
                </td>
                <td class="py-3 px-4 text-right whitespace-nowrap">
                    <button class="px-2.5 py-1 rounded bg-cyber-700 hover:bg-cyber-600 text-cyan-400 text-xs font-semibold">
                        Details <i class="fa-solid fa-arrow-right text-[10px] ml-1"></i>
                    </button>
                </td>
            </tr>
        `;
    }).join("");
}

// 6. Finding Details Drawer & AI Advisory
let activeFinding = null;

function openFindingDetail(findingId) {
    const f = currentFindings.find(item => item.id === findingId);
    if (!f) return;
    activeFinding = f;

    const drawerSev = document.getElementById("drawerSeverityBadge");
    drawerSev.textContent = f.severity.toUpperCase();
    drawerSev.className = `text-xs px-2.5 py-0.5 rounded-full font-bold uppercase ${f.severity === "High" ? "badge-high" : (f.severity === "Medium" ? "badge-medium" : (f.severity === "Low" ? "badge-low" : "badge-info"))}`;

    document.getElementById("drawerCweBadge").textContent = f.cwe_id || "CWE-General";
    document.getElementById("drawerStatusBadge").textContent = f.status;
    document.getElementById("drawerTitle").textContent = f.name;
    document.getElementById("drawerUrl").textContent = f.affected_url;
    document.getElementById("drawerDescription").textContent = f.description || "No description provided.";
    document.getElementById("drawerImpact").textContent = f.impact || "Security exposure identified through dynamic assessment.";
    document.getElementById("drawerRemediation").textContent = f.remediation || "Follow security engineering best practices.";

    const evContainer = document.getElementById("drawerEvidenceContainer");
    if (f.evidence) {
        evContainer.classList.remove("hidden");
        document.getElementById("drawerEvidence").textContent = f.evidence;
    } else {
        evContainer.classList.add("hidden");
    }

    document.getElementById("drawerRequestSnippet").textContent = f.request_snippet || "No HTTP request trace recorded.";
    document.getElementById("drawerResponseSnippet").textContent = f.response_snippet || "No HTTP response headers recorded.";

    switchDrawerTab("remediation");
    document.getElementById("findingDrawerBackdrop").classList.remove("hidden");
}

function closeDrawer() {
    document.getElementById("findingDrawerBackdrop").classList.add("hidden");
}

function switchDrawerTab(tab) {
    const tabRem = document.getElementById("tabBtnRemediation");
    const tabAi = document.getElementById("tabBtnAiAdvisory");
    const paneRem = document.getElementById("paneRemediation");
    const paneAi = document.getElementById("paneAiAdvisory");

    if (tab === "remediation") {
        tabRem.className = "pb-2 text-xs font-bold text-cyan-400 border-b-2 border-cyan-400";
        tabAi.className = "pb-2 text-xs font-semibold text-slate-400 hover:text-slate-200 flex items-center gap-1.5";
        paneRem.classList.remove("hidden");
        paneAi.classList.add("hidden");
    } else {
        tabAi.className = "pb-2 text-xs font-bold text-cyan-400 border-b-2 border-cyan-400 flex items-center gap-1.5";
        tabRem.className = "pb-2 text-xs font-semibold text-slate-400 hover:text-slate-200";
        paneAi.classList.remove("hidden");
        paneRem.classList.add("hidden");
        loadAiAdvisory(activeFinding.id);
    }
}

async function loadAiAdvisory(findingId) {
    const sourceEl = document.getElementById("aiAdvisorySource");
    const threatEl = document.getElementById("aiThreatVector");
    const stepsEl = document.getElementById("aiRemediationSteps");
    const codeEl = document.getElementById("aiCodeSnippets");

    threatEl.textContent = "Analyzing threat vectors and synthesizing mitigation guidance...";
    stepsEl.innerHTML = "<li class='text-slate-500'>Querying advisory engine...</li>";
    codeEl.innerHTML = "";

    try {
        const resp = await fetch(`/api/findings/${findingId}/advisory`);
        if (!resp.ok) return;
        const data = (await resp.json()).advisory;

        sourceEl.textContent = data.source;
        threatEl.textContent = data.threat_vector || "Threat vector analyzed.";

        const steps = data.remediation_steps || [];
        stepsEl.innerHTML = steps.map(s => `<li>${escapeHtml(s)}</li>`).join("");

        const snippets = data.code_snippets || {};
        const snippetKeys = Object.keys(snippets);
        if (snippetKeys.length > 0) {
            codeEl.innerHTML = snippetKeys.map(k => `
                <div class="rounded border border-cyber-border overflow-hidden">
                    <div class="bg-cyber-900 px-3 py-1 text-[10px] font-bold text-cyan-300 font-mono">${escapeHtml(k)}</div>
                    <pre class="terminal-box p-2 text-[10px] text-slate-200 overflow-x-auto">${escapeHtml(snippets[k])}</pre>
                </div>
            `).join("");
        } else {
            codeEl.innerHTML = "<p class='text-xs text-slate-500'>No platform-specific code snippets available.</p>";
        }
    } catch (e) {
        threatEl.textContent = "Advisory engine temporarily unavailable.";
    }
}

// 7. Mini Doughnut Chart
function renderRiskMiniChart(high, med, low, info) {
    const ctx = document.getElementById("riskScoreMiniChart").getContext("2d");
    if (riskChartInstance) riskChartInstance.destroy();

    const data = (high === 0 && med === 0 && low === 0 && info === 0) ? [1] : [high, med, low, info];
    const colors = (high === 0 && med === 0 && low === 0 && info === 0)
        ? ["#10b981"]
        : ["#ef4444", "#f59e0b", "#3b82f6", "#64748b"];

    riskChartInstance = new Chart(ctx, {
        type: "doughnut",
        data: {
            datasets: [{
                data: data,
                backgroundColor: colors,
                borderWidth: 0,
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: "75%",
            plugins: { tooltip: { enabled: false } }
        }
    });
}

// 8. Scan History Modal
async function openHistoryModal() {
    selectedHistoryIds.clear();
    document.getElementById("historyCompareNote").textContent = "Check exactly 2 scans to run comparison.";
    document.getElementById("historyModalBackdrop").classList.remove("hidden");

    try {
        const resp = await fetch("/api/scans");
        if (!resp.ok) return;
        const scans = (await resp.json()).scans || [];
        const tbody = document.getElementById("historyTableBody");

        if (scans.length === 0) {
            tbody.innerHTML = `<tr><td colspan="8" class="p-6 text-center text-slate-500">No scan history recorded yet.</td></tr>`;
            return;
        }

        tbody.innerHTML = scans.map(s => {
            const dateStr = s.started_at ? s.started_at.replace("T", " ").slice(0, 16) : "-";
            return `
                <tr class="hover:bg-cyber-700/50 transition">
                    <td class="p-3">
                        <input type="checkbox" value="${s.id}" class="history-select-box rounded bg-cyber-900 border-cyber-border text-cyan-500 focus:ring-0">
                    </td>
                    <td class="p-3 font-mono text-[11px] text-slate-400 whitespace-nowrap">${dateStr}</td>
                    <td class="p-3 font-mono text-cyan-400 max-w-xs truncate" title="${escapeHtml(s.target_url)}">${escapeHtml(s.target_url)}</td>
                    <td class="p-3 text-[10px] font-mono uppercase">${s.profile}</td>
                    <td class="p-3 text-[10px] text-slate-400">${escapeHtml(s.scanner_type)}</td>
                    <td class="p-3 font-mono font-bold">${s.risk_score}</td>
                    <td class="p-3 font-mono">${s.total_findings}</td>
                    <td class="p-3 text-right">
                        <button onclick="loadHistoricalScan('${s.id}')" class="px-2 py-1 bg-cyber-700 hover:bg-cyan-600 rounded text-[11px] text-white transition">
                            View
                        </button>
                    </td>
                </tr>
            `;
        }).join("");

        tbody.querySelectorAll(".history-select-box").forEach(cb => {
            cb.addEventListener("change", (e) => {
                if (e.target.checked) selectedHistoryIds.add(e.target.value);
                else selectedHistoryIds.delete(e.target.value);
                const note = document.getElementById("historyCompareNote");
                note.textContent = `${selectedHistoryIds.size} of 2 scans selected for comparison.`;
            });
        });
    } catch (e) {
        console.error("History fetch error:", e);
    }
}

function closeHistoryModal() {
    document.getElementById("historyModalBackdrop").classList.add("hidden");
}

function loadHistoricalScan(scanId) {
    currentScanId = scanId;
    closeHistoryModal();
    loadScanResults(scanId);
}

async function handleCompareScans() {
    if (selectedHistoryIds.size !== 2) {
        alert("Please select exactly 2 scans to compare.");
        return;
    }
    const [id1, id2] = Array.from(selectedHistoryIds);
    try {
        const resp = await fetch(`/api/scans/compare/${id1}/${id2}`);
        if (!resp.ok) return;
        const diff = await resp.json();
        
        alert(
            `Scan Comparison Summary:\n` +
            `Resolved Findings: ${diff.resolved_findings.length}\n` +
            `New Findings: ${diff.new_findings.length}\n` +
            `Persistent Findings: ${diff.persistent_findings.length}`
        );
    } catch (e) {
        alert("Comparison request failed.");
    }
}

// Utility: HTML escape
function escapeHtml(text) {
    if (!text) return "";
    return text.toString()
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}
