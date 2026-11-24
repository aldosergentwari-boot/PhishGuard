
'use strict';

const API = {
    analyze: '/api/analyze',
    history: '/api/history',
    status: '/api/status',
    plans: '/api/billing/plans',
    subscription: '/api/billing/me',
    ads: '/api/ads/config',
    csrf: '/api/auth/csrf',
    authMe: '/api/auth/me',
    login: '/api/auth/login',
    register: '/api/auth/register',
    logout: '/api/auth/logout'
};

const MODE_STORAGE_KEY = 'phishguard.onlineMode';

const PAGE_NAMES = {
    overview: 'Overview',
    scanner: 'URL Scanner',
    history: 'Scan History',
    intelligence: 'Intelligence',
    about: 'About Project',
    pricing: 'Plans & Pricing',
    account: 'My Account'
};

const state = {
    historyPage: 0,
    pageSize: 10,
    historyTotal: 0,
    historySearch: '',
    historyFilter: 'all',
    searchTimer: null,
    lastHistoryRecords: [],
    lastOverviewRecords: [],
    onlineMode: false,      // Offline-first: online checks require an explicit choice
    internet: null,         // true / false once /api/status has answered
    authenticated: false,
    account: null
};

const $ = (id) => document.getElementById(id);

/* =========================================
   1. GENERAL HELPERS
========================================= */

function escapeHtml(value) {
    return String(value ?? '').replace(/[&<>"']/g, (character) => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;'
    })[character]);
}

function showToast(message, type = 'info') {
    const container = $('toastContainer');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;

    container.appendChild(toast);

    window.setTimeout(() => {
        toast.classList.add('toast-hide');

        window.setTimeout(() => toast.remove(), 300);
    }, 3500);
}

/* =========================================
   2. API REQUEST HANDLER
========================================= */

async function apiRequest(url, options = {}) {
    const response = await fetch(url, {
        credentials: 'same-origin',
        ...options,
        headers: {
            ...(options.body
                ? { 'Content-Type': 'application/json' }
                : {}),
            ...(options.headers || {})
        }
    });

    let payload;

    try {
        payload = await response.json();
    } catch {
        throw new Error(
            `Server returned an invalid response (HTTP ${response.status}).`
        );
    }

    if (!response.ok || payload?.success === false) {
        throw new Error(
            payload?.message ||
            payload?.error ||
            `Request failed (HTTP ${response.status}).`
        );
    }

    return payload;
}

function unwrapData(response) {
    return response?.data &&
        typeof response.data === 'object'
        ? response.data
        : response;
}

/* =========================================
   3. HISTORY DATA EXTRACTION
========================================= */

function extractHistory(response) {
    const payload = unwrapData(response);

    const records = Array.isArray(payload?.scans)
        ? payload.scans
        : Array.isArray(payload?.history)
            ? payload.history
            : Array.isArray(payload?.items)
                ? payload.items
                : Array.isArray(payload?.records)
                    ? payload.records
                    : [];

    const rawSummary = payload?.summary || {};

    const total = Number(
        payload?.total ??
        rawSummary.total ??
        records.length
    );

    const phishing = Number(
        rawSummary.phishing ??
        records.filter(isPhishing).length
    );

    const suspicious = Number(
        rawSummary.suspicious ??
        records.filter(isSuspicious).length
    );

    const legitimate = Number(
        rawSummary.legitimate ??
        records.filter(record =>
            getPrediction(record) === 'LEGITIMATE'
        ).length
    );

    return {
        records,
        total: Number.isFinite(total) ? total : records.length,

        summary: {
            total: Number.isFinite(Number(rawSummary.total))
                ? Number(rawSummary.total)
                : (Number.isFinite(total) ? total : records.length),

            phishing: Number.isFinite(phishing) ? phishing : 0,

            suspicious: Number.isFinite(suspicious) ? suspicious : 0,

            legitimate: Number.isFinite(legitimate)
                ? legitimate
                : 0
        }
    };
}

/* =========================================
   4. DATA FORMATTERS
========================================= */

function getPrediction(record) {
    const prediction =
        record?.final_prediction ??
        record?.prediction ??
        record?.ml_result?.prediction ??
        'UNKNOWN';

    return String(prediction).toUpperCase();
}

function isPhishing(record) {
    return getPrediction(record) === 'PHISHING';
}

function isSuspicious(record) {
    return getPrediction(record) === 'SUSPICIOUS';
}

function getRisk(record) {
    const value =
        record?.final_risk_score ??
        record?.risk_score ??
        record?.ml_result?.risk_score ??
        0;

    return Math.max(0, Math.min(100, Number(value) || 0));
}

function getConfidence(record) {
    const value = Number(
        record?.ml_confidence ??
        record?.confidence ??
        record?.model_confidence ??
        record?.ml_result?.confidence ??
        0
    );

    if (!Number.isFinite(value)) return 0;

    return Math.max(
        0,
        Math.min(100, value <= 1 ? value * 100 : value)
    );
}

function getUrl(record) {
    return (
        record?.url ??
        record?.submitted_url ??
        record?.original_url ??
        'Unknown URL'
    );
}

function getDomain(record) {
    if (record?.domain) return record.domain;

    try {
        return new URL(getUrl(record)).hostname;
    } catch {
        return getUrl(record);
    }
}

function getScanId(record) {
    return record?.id ?? record?.scan_id ?? '—';
}

function formatDate(value) {
    if (!value) return '—';

    const date = new Date(value);

    if (Number.isNaN(date.getTime())) {
        return String(value);
    }

    return date.toLocaleString();
}

function resultBadge(record) {
    const prediction = getPrediction(record);

    if (prediction === 'PHISHING') {
        return '<span class="result-badge phishing">PHISHING</span>';
    }

    if (prediction === 'SUSPICIOUS') {
        return '<span class="result-badge suspicious">SUSPICIOUS</span>';
    }

    if (prediction === 'LEGITIMATE') {
        return '<span class="result-badge legitimate">NO THREAT</span>';
    }

    return '<span class="result-badge">UNKNOWN</span>';
}

function riskMarkup(record) {
    const risk = getRisk(record);

    const riskClass = risk >= 80
        ? 'risk-high'
        : risk >= 35
            ? 'risk-medium'
            : 'risk-low';

    return `
        <span class="risk-value ${riskClass}">
            ${risk.toFixed(2)}%
        </span>
    `;
}


/* =========================================
   5. OVERVIEW - FIXED VERSION
========================================= */

// Get overview data from the backend
async function getOverviewData() {
    const response = await fetch('/api/history?limit=10&offset=0', {
    method: 'GET',
    credentials: 'same-origin',
    headers: { 'Accept': 'application/json' },
    cache: 'no-store'
    });

    if (!response.ok) {
        throw new Error(`HTTP Error: ${response.status}`);
    }

    const result = await response.json();

    if (result.success === false) {
        throw new Error(result.message || result.error || 'Unable to load overview data.');
    }

    const data = result.data ?? result;
    const records = Array.isArray(data.scans)
        ? data.scans
        : Array.isArray(data.history)
            ? data.history
            : Array.isArray(data.records)
                ? data.records
                : [];

    const summary = data.summary ?? {};

    const total = Number(summary.total ?? data.total ?? records.length);

    const phishing = Number(
        summary.phishing ?? records.filter(isPhishing).length
    );

    const suspicious = Number(
        summary.suspicious ?? records.filter(isSuspicious).length
    );

    const legitimate = Number(
        summary.legitimate ??
        records.filter(record => getPrediction(record) === 'LEGITIMATE').length
    );

    return {
        records,
        total,
        phishing,
        suspicious,
        legitimate
    };
}

// Update the four statistic cards
function updateOverviewCards(data) {
    const elements = {
        total: $('totalScans'),
        phishing: $('phishingCount'),
        suspicious: $('suspiciousCount'),
        legitimate: $('legitimateCount'),
        donutTotal: $('donutTotal'),
        legendPhishing: $('legendPhishing'),
        legendSuspicious: $('legendSuspicious'),
        legendLegitimate: $('legendLegitimate')
    };

    if (elements.total) {
        elements.total.textContent = data.total.toLocaleString();
    }

    if (elements.phishing) {
        elements.phishing.textContent = data.phishing.toLocaleString();
    }

    if (elements.suspicious) {
        elements.suspicious.textContent = data.suspicious.toLocaleString();
    }

    if (elements.legitimate) {
        elements.legitimate.textContent = data.legitimate.toLocaleString();
    }

    if (elements.donutTotal) {
        elements.donutTotal.textContent = data.total.toLocaleString();
    }

    if (elements.legendPhishing) {
        elements.legendPhishing.textContent = data.phishing.toLocaleString();
    }

    if (elements.legendSuspicious) {
        elements.legendSuspicious.textContent = data.suspicious.toLocaleString();
    }

    if (elements.legendLegitimate) {
        elements.legendLegitimate.textContent = data.legitimate.toLocaleString();
    }

    updateOverviewDonut(data);
}

// Update the threat distribution chart
function updateOverviewDonut(data) {
    const donut = $('donutChart');

    if (!donut) return;

    const phishing = Number(data.phishing) || 0;
    const suspicious = Number(data.suspicious) || 0;
    const legitimate = Number(data.legitimate) || 0;

    const total = phishing + suspicious + legitimate;

    if (total === 0) {
        donut.style.background = 'conic-gradient(#263449 0% 100%)';
        return;
    }

    const phishingPercentage = (phishing / total) * 100;
    const suspiciousPercentage = (suspicious / total) * 100;
    const legitimatePercentage = (legitimate / total) * 100;

    const phishingEnd = phishingPercentage;
    const suspiciousEnd = phishingEnd + suspiciousPercentage;

    donut.style.background = `
        conic-gradient(
            #ff6278 0% ${phishingEnd}%,
            #f59e0b ${phishingEnd}% ${suspiciousEnd}%,
            #35d69a ${suspiciousEnd}% 100%
        )
    `;
}

// Display latest five scans
function renderRecentScans(records) {
    const tbody = $('recentScans');

    if (!tbody) return;

    if (!records || records.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="4" class="empty-cell">
                    No scan records found.
                </td>
            </tr>
        `;
        return;
    }

    const latestRecords = [...records]
        .sort((a, b) => {
            const dateA = new Date(a.scanned_at ?? a.created_at ?? 0).getTime();
            const dateB = new Date(b.scanned_at ?? b.created_at ?? 0).getTime();
            return dateB - dateA;
        })
        .slice(0, 5);

    tbody.innerHTML = latestRecords.map(record => {
        const domain = getDomain(record);
        const url = getUrl(record);
        const risk = getRisk(record);
        const prediction = getPrediction(record);

        const badge = resultBadge(record);

        let riskClass = 'risk-low';

        if (risk >= 80) {
            riskClass = 'risk-high';
        } else if (risk >= 35) {
            riskClass = 'risk-medium';
        }

        return `
            <tr data-id="${escapeHtml(getScanId(record))}">
                <td>
                    <strong>${escapeHtml(domain)}</strong>
                    <small class="table-subtext">
                        ${escapeHtml(url)}
                    </small>
                </td>

                <td>${badge}</td>

                <td>
                    <span class="risk-value ${riskClass}">
                        ${risk.toFixed(2)}%
                    </span>
                </td>

                <td>
                    ${escapeHtml(formatDate(record.scanned_at ?? record.created_at))}
                </td>
            </tr>
        `;
    }).join('');

    labelTableCells(tbody, RECENT_COLUMNS);
}

// Main overview function
async function loadOverview() {
    console.log('[PhishGuard] Loading Overview...');

    const tbody = $('recentScans');

    if (tbody) {
        tbody.innerHTML = `
            <tr>
                <td colspan="4" class="empty-cell">
                    Loading scan history...
                </td>
            </tr>
        `;
    }

    try {
        const data = await getOverviewData();

        console.log('[PhishGuard] Overview data:', data);

        // Save loaded records
        state.lastOverviewRecords = data.records;

        // Update statistic cards
        updateOverviewCards(data);

        // Update recent activity table
        renderRecentScans(data.records);

        console.log('[PhishGuard] Overview updated successfully.');

    } catch (error) {
        console.error('[PhishGuard] Overview error:', error);

        if (tbody) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="4" class="empty-cell">
                        Failed to load scan activity:
                        ${escapeHtml(error.message)}
                    </td>
                </tr>
            `;
        }

        // Show error instead of leaving old numbers
        [
            'totalScans',
            'phishingCount',
            'legitimateCount'
        ].forEach(id => {
            if ($(id)) {
                $(id).textContent = '—';
            }
        });

        showToast(
            'Overview could not be loaded: ' + error.message,
            'error'
        );
    }
}

/* =========================================
   6. PAGE NAVIGATION
========================================= */

function setActivePage(pageName) {
    if (!PAGE_NAMES[pageName]) return;

    document.querySelectorAll('.page').forEach(page => {
        page.classList.remove('active');
    });

    const page = $(`page-${pageName}`);

    if (page) {
        page.classList.add('active');
    }

    document.querySelectorAll('.nav-link[data-page]').forEach(button => {
        button.classList.toggle(
            'active',
            button.dataset.page === pageName
        );
    });

    if ($('breadcrumbPage')) {
        $('breadcrumbPage').textContent = PAGE_NAMES[pageName];
    }

    setSidebar(false);

    if (pageName === 'overview') {
        loadOverview();
    }

    if (pageName === 'history') {
        loadHistory();
    }

    if (pageName === 'account') {
        loadAccount();
    }
}

function goToPage(pageName) {
    setActivePage(pageName);

    window.scrollTo({
        top: 0,
        behavior: 'smooth'
    });
}

/* =========================================
   7. SCAN HISTORY TABLE
========================================= */

function renderHistory(records) {
    const tbody = $('historyTable');

    if (!tbody) return;

    if (!records.length) {
        tbody.innerHTML = `
            <tr>
                <td colspan="7" class="empty-cell">
                    No matching scan records found.
                </td>
            </tr>
        `;

        return;
    }

    tbody.innerHTML = records.map(record => {
        const id = getScanId(record);

        return `
            <tr data-id="${escapeHtml(id)}">
                <td>#${escapeHtml(id)}</td>

                <td>
                    <strong>${escapeHtml(getDomain(record))}</strong>
                    <small class="table-subtext">
                        ${escapeHtml(getUrl(record))}
                    </small>
                </td>

                <td>${resultBadge(record)}</td>

                <td>${riskMarkup(record)}</td>

                <td>
                    ${escapeHtml(record.detection_mode ?? '—')}
                </td>

                <td>
                    ${escapeHtml(
                        formatDate(record.scanned_at ?? record.created_at)
                    )}
                </td>

                <td>
                    <div class="table-actions">
                        <button
                            class="text-button"
                            data-action="details"
                            data-id="${escapeHtml(id)}">
                            Details
                        </button>

                        <button
                            class="text-button"
                            data-action="delete"
                            data-id="${escapeHtml(id)}">
                            Delete
                        </button>
                    </div>
                </td>
            </tr>
        `;
    }).join('');

    labelTableCells(tbody, HISTORY_COLUMNS);
}

function updatePagination(total, currentCount) {
    const first = total === 0
        ? 0
        : state.historyPage * state.pageSize + 1;

    const last = Math.min(
        state.historyPage * state.pageSize + currentCount,
        total
    );

    if ($('paginationInfo')) {
        $('paginationInfo').textContent = `${first}–${last} of ${total}`;
    }

    if ($('historyCount')) {
        $('historyCount').textContent =
            `${total} record${total === 1 ? '' : 's'} found`;
    }

    if ($('prevPage')) {
        $('prevPage').disabled = state.historyPage <= 0;
    }

    if ($('nextPage')) {
        $('nextPage').disabled =
            (state.historyPage + 1) * state.pageSize >= total;
    }
}

async function loadHistory() {
    const tbody = $('historyTable');

    if (tbody) {
        tbody.innerHTML = `
            <tr>
                <td colspan="7" class="empty-cell">
                    Loading history...
                </td>
            </tr>
        `;
    }

    const params = new URLSearchParams({
        limit: String(state.pageSize),
        offset: String(state.historyPage * state.pageSize),
        search: state.historySearch,
        filter: state.historyFilter
    });

    try {
        const response = await apiRequest(
            `${API.history}?${params.toString()}`
        );

        const result = extractHistory(response);

        state.lastHistoryRecords = result.records;
        state.historyTotal = result.total;

        renderHistory(result.records);

        updatePagination(
            result.total,
            result.records.length
        );

    } catch (error) {
        console.error('History loading failed:', error);

        if (tbody) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="7" class="empty-cell">
                        Could not load history:
                        ${escapeHtml(error.message)}
                    </td>
                </tr>
            `;
        }

        if ($('historyCount')) {
            $('historyCount').textContent = 'Unable to load records';
        }

        if ($('paginationInfo')) {
            $('paginationInfo').textContent = '—';
        }

        showToast(
            `Scan history could not be loaded: ${error.message}`,
            'error'
        );
    }
}

/* =========================================
   8. SCAN DETAILS
========================================= */

function collectIndicators(record) {
    const indicators = record?.indicators;
    const entries = [];

    if (Array.isArray(indicators)) {
        return indicators.map(item =>
            typeof item === 'string'
                ? item
                : JSON.stringify(item)
        );
    }

    if (indicators && typeof indicators === 'object') {
        Object.entries(indicators).forEach(([group, values]) => {

            if (Array.isArray(values)) {
                values.forEach(value => {
                    entries.push(
                        `${group.replaceAll('_', ' ')}: ${
                            typeof value === 'string'
                                ? value
                                : JSON.stringify(value)
                        }`
                    );
                });

            } else if (values && typeof values === 'object') {

                Object.entries(values).forEach(([key, value]) => {
                    entries.push(
                        `${group}: ${key.replaceAll('_', ' ')} = ${String(value)}`
                    );
                });

            } else if (values) {
                entries.push(`${group}: ${String(values)}`);
            }
        });
    }

    if (!entries.length && Array.isArray(record?.decision_sources)) {
        record.decision_sources.forEach(source => {
            entries.push(String(source));
        });
    }

    return entries;
}

function renderDetails(record) {
    const content = $('detailsContent');

    if (!content) return;

    const indicators = collectIndicators(record);
    const prediction = getPrediction(record);

    content.innerHTML = `
        <div class="details-grid">

            <div>
                <span>SCAN ID</span>
                <strong>#${escapeHtml(getScanId(record))}</strong>
            </div>

            <div>
                <span>CLASSIFICATION</span>
                <strong>${escapeHtml(prediction)}</strong>
            </div>

            <div>
                <span>RISK SCORE</span>
                <strong>${getRisk(record).toFixed(2)}%</strong>
            </div>

            <div>
                <span>ML CONFIDENCE</span>
                <strong>${getConfidence(record).toFixed(2)}%</strong>
            </div>

            <div>
                <span>DETECTION MODE</span>
                <strong>${escapeHtml(record.detection_mode ?? '—')}</strong>
            </div>

            <div>
                <span>DATE</span>
                <strong>
                    ${escapeHtml(
                        formatDate(record.scanned_at ?? record.created_at)
                    )}
                </strong>
            </div>

        </div>

        <div class="details-url">
            <span>SUBMITTED URL</span>
            <p>${escapeHtml(getUrl(record))}</p>
        </div>

        <div class="details-url">
            <span>DOMAIN</span>
            <p>${escapeHtml(getDomain(record))}</p>
        </div>

        <div class="details-indicators">
            <h3>Detection sources & indicators</h3>

            ${
                indicators.length
                    ? `<ul>${indicators.map(item =>
                        `<li>${escapeHtml(item)}</li>`
                    ).join('')}</ul>`
                    : '<p>No additional indicators were recorded for this scan.</p>'
            }
        </div>
    `;

    const modal = $('detailsModal');

    if (modal) {
        modal.hidden = false;
    }
}

async function openDetails(id) {
    try {
        const response = await apiRequest(
            `${API.history}/${encodeURIComponent(id)}`
        );

        const payload = unwrapData(response);

        const record =
            payload?.scan ??
            payload?.record ??
            payload;

        if (!record || typeof record !== 'object') {
            throw new Error('Scan details were not found.');
        }

        renderDetails(record);

    } catch (error) {
        console.error('Could not open scan details:', error);

        showToast(
            `Could not open details: ${error.message}`,
            'error'
        );
    }
}

function closeDetails() {
    const modal = $('detailsModal');

    if (modal) {
        modal.hidden = true;
    }
}

/* =========================================
   9. DELETE HISTORY
========================================= */

async function deleteHistoryRecord(id) {
    if (!window.confirm(
        `Delete scan record #${id}? This action cannot be undone.`
    )) {
        return;
    }

    try {
        await apiRequest(
            `${API.history}/${encodeURIComponent(id)}`,
            { method: 'DELETE' }
        );

        showToast('Scan record deleted.', 'success');

        await loadHistory();
        await loadOverview();

    } catch (error) {
        console.error('Delete failed:', error);

        showToast(
            `Could not delete record: ${error.message}`,
            'error'
        );
    }
}

async function clearHistory() {
    if (!window.confirm(
        'Are you sure you want to delete ALL scan history? This action cannot be undone.'
    )) {
        return;
    }

    try {
        await apiRequest(API.history, {
            method: 'DELETE'
        });

        state.historyPage = 0;

        showToast(
            'All scan history has been cleared.',
            'success'
        );

        await loadHistory();
        await loadOverview();

    } catch (error) {
        console.error('Clear history failed:', error);

        showToast(
            `Could not clear history: ${error.message}`,
            'error'
        );
    }
}

/* =========================================
   10. URL SCANNER
========================================= */

function normalizeAnalysis(response) {
    const payload = unwrapData(response);

    return (
        payload?.result ??
        payload?.analysis ??
        payload?.scan ??
        payload
    );
}


function showScanResult(record) {
    const prediction = getPrediction(record);

    const phishing = prediction === 'PHISHING';
    const suspicious = prediction === 'SUSPICIOUS';
    const legitimate = prediction === 'LEGITIMATE';
    const unknown = !phishing && !suspicious && !legitimate;

    const risk = getRisk(record);
    const confidence = getConfidence(record);

    const panel = $('resultPanel');
    const summary = $('resultSummary');

    [panel, summary].forEach(element => {
        if (!element) return;

        element.classList.toggle('is-phishing', phishing);
        element.classList.toggle('is-suspicious', suspicious);
        element.classList.toggle('is-legitimate', legitimate);
        element.classList.toggle('is-unknown', unknown);
    });

    if (panel) {
        panel.hidden = false;
    }

    if ($('resultStatus')) {
        $('resultStatus').textContent = phishing
            ? 'THREAT DETECTED!'
            : suspicious
                ? 'WARNING: SUSPICIOUS WEBSITE'
                : legitimate
                    ? 'NO THREAT DETECTED'
                    : 'ANALYSIS COMPLETED';
    }

    if ($('resultSymbol')) {
        $('resultSymbol').textContent = phishing
            ? '!'
            : suspicious
                ? '⚠'
                : legitimate
                    ? '✓'
                    : '?';
    }

    if ($('resultPrediction')) {
        $('resultPrediction').textContent = phishing
            ? 'PHISHING — THREAT DETECTED'
            : suspicious
                ? 'SUSPICIOUS — REVIEW REQUIRED'
                : legitimate
                    ? 'LEGITIMATE'
                    : 'ANALYSIS COMPLETED';
    }

    if ($('resultMessage')) {
        $('resultMessage').textContent = record.message ?? (
            phishing
                ? 'This URL has strong indicators of phishing. Do not open it or enter personal information.'
                : suspicious
                    ? 'This URL has suspicious characteristics. Be careful and avoid entering sensitive information until it is verified.'
                    : legitimate
                        ? 'No threat was detected by the current checks. This does not guarantee that the website is safe.'
                        : 'The analysis could not determine the website status.'
        );
    }

    if ($('riskScore')) {
        $('riskScore').textContent = `${risk.toFixed(2)}%`;
    }

    if ($('mlConfidence')) {
        $('mlConfidence').textContent = `${confidence.toFixed(2)}%`;
    }

    if ($('detectionMode')) {
        $('detectionMode').textContent = record.detection_mode ?? '—';
    }

    if ($('scanId')) {
        $('scanId').textContent = record.scan_id ?? record.id ?? '—';
    }

    const indicatorsList = $('indicatorsList');

    if (indicatorsList) {
        const indicators = collectIndicators(record);

        indicatorsList.innerHTML = indicators.length
            ? indicators.map(item =>
                `<div class="indicator-item">${escapeHtml(item)}</div>`
            ).join('')
            : '<p>No additional indicators were reported.</p>';
    }

    panel?.scrollIntoView({
        behavior: 'smooth',
        block: 'start'
    });
}

async function handleScanSubmit(event) {
    event.preventDefault();

    const input = $('urlInput');
    const button = $('scanButton');
    const progress = $('scanProgress');
    const resultPanel = $('resultPanel');

    let url = input?.value.trim();

    if (url && !/^https?:\/\//i.test(url)) {
        url = `https://${url}`;
    }

    if (!url) {
        showToast('Enter a URL to analyze.', 'warning');
        input?.focus();
        return;
    }

    try {
        const parsed = new URL(url);

        if (!['http:', 'https:'].includes(parsed.protocol)) {
            throw new Error('Invalid protocol');
        }

        input.value = url;
    } catch {
        showToast('Enter a valid website address.', 'warning');
        input?.focus();
        return;
    }

    if (button) {
        button.disabled = true;
        button.textContent = 'Analyzing...';
    }

    if (progress) {
        progress.hidden = false;
    }

    if (resultPanel) {
        resultPanel.hidden = true;
    }

    try {
        const response = await apiRequest(API.analyze, {
            method: 'POST',
            body: JSON.stringify({
                url,
                mode: state.onlineMode ? 'online' : 'offline'
            })
        });

        const result = normalizeAnalysis(response);

        showScanResult(result);

        if (result?.detection_mode === 'OFFLINE_FALLBACK_NO_INTERNET') {
            // Online mode was on, but this computer has no internet.
            state.internet = false;
            renderModeUI();

            showToast(
                'No internet connection: analyzed with the offline engine.',
                'warning'
            );
        } else {
            showToast(
                result?.detection_mode === 'HYBRID_ONLINE_AND_OFFLINE'
                    ? 'URL analysis completed (online + offline checks).'
                    : 'URL analysis completed.',
                'success'
            );
        }

        // Refresh background panels without delaying the scan result or
        // making the scanner feel as if it navigated away from the result.
        state.historyPage = 0;
        void Promise.allSettled([
            loadOverview(),
            loadHistory()
        ]);

    } catch (error) {
        console.error('URL analysis failed:', error);

        showToast(
            `URL analysis failed: ${error.message}`,
            'error'
        );

    } finally {
        if (button) {
            button.disabled = false;
            button.innerHTML = 'Analyze URL <span>→</span>';
        }

        if (progress) {
            progress.hidden = true;
        }
    }
}

/* =========================================
   11. EXPORT HISTORY TO CSV
========================================= */

async function exportHistoryCsv() {
    try {
        const records = [];
        const pageSize = 100;
        let offset = 0;
        let total = null;

        // The API caps page size at 100, so export every page.
        do {
            const params = new URLSearchParams({
                limit: String(pageSize),
                offset: String(offset),
                search: state.historySearch,
                filter: state.historyFilter
            });

            const response = await apiRequest(
                `${API.history}?${params.toString()}`
            );

            const page = extractHistory(response);
            records.push(...page.records);
            total = page.total;
            offset += page.records.length;

            if (page.records.length === 0) {
                break;
            }
        } while (offset < total);

        if (!records.length) {
            showToast(
                'There are no records to export.',
                'warning'
            );

            return;
        }

        const columns = [
            'id',
            'url',
            'domain',
            'prediction',
            'risk_score',
            'confidence',
            'detection_mode',
            'scanned_at'
        ];

        const csvCell = value =>
            `"${String(value ?? '').replace(/"/g, '""')}"`;

        const lines = [
            columns.join(','),

            ...records.map(record =>
                columns.map(column =>
                    csvCell(
                        column === 'id'
                            ? getScanId(record)
                            : column === 'url'
                                ? getUrl(record)
                                : column === 'domain'
                                    ? getDomain(record)
                                    : column === 'prediction'
                                        ? getPrediction(record)
                                        : column === 'risk_score'
                                            ? getRisk(record)
                                            : column === 'confidence'
                                                ? getConfidence(record)
                                                : record[column]
                    )
                ).join(',')
            )
        ];

        const blob = new Blob(
            ['\uFEFF' + lines.join('\r\n')],
            { type: 'text/csv;charset=utf-8;' }
        );

        const url = URL.createObjectURL(blob);

        const link = document.createElement('a');

        link.href = url;

        link.download =
            `phishguard-scan-history-${new Date().toISOString().slice(0, 10)}.csv`;

        document.body.appendChild(link);

        link.click();

        link.remove();

        URL.revokeObjectURL(url);

        showToast(
            'CSV export created.',
            'success'
        );

    } catch (error) {
        console.error('CSV export failed:', error);

        showToast(
            `CSV export failed: ${error.message}`,
            'error'
        );
    }
}

/* =========================================
   12. EVENT LISTENERS
========================================= */

function bindEvents() {

    // Account access and authentication
    document.querySelectorAll('[data-auth-mode]').forEach(button => {
        button.addEventListener('click', () => setAuthMode(button.dataset.authMode));
    });
    $('loginForm')?.addEventListener('submit', event => submitAccountForm(event, 'login'));
    $('registerForm')?.addEventListener('submit', event => submitAccountForm(event, 'register'));
    $('accountLogout')?.addEventListener('click', signOutAccount);
    $('accountViewPlans')?.addEventListener('click', () => goToPage('pricing'));
    $('pricingGrid')?.addEventListener('click', event => {
        const button = event.target.closest('[data-plan]');
        if (button) void requestPlanUpgrade(button.dataset.plan);
    });

    // Sidebar navigation
    document.querySelectorAll('.nav-link[data-page]').forEach(button => {
        button.addEventListener('click', () => {
            goToPage(button.dataset.page);
        });
    });

    // Buttons that navigate to another page
    document.querySelectorAll('[data-goto]').forEach(button => {
        button.addEventListener('click', () => {
            goToPage(button.dataset.goto);
        });
    });

    // Overview buttons
    $('goScanner')?.addEventListener('click', () => {
        goToPage('scanner');
    });

    $('bannerScan')?.addEventListener('click', () => {
        goToPage('scanner');
    });

    $('refreshOverview')?.addEventListener('click', loadOverview);

    // Scanner
    $('scanForm')?.addEventListener(
        'submit',
        handleScanSubmit
    );

    $('scanAgain')?.addEventListener('click', () => {
        if ($('urlInput')) {
            $('urlInput').value = '';
        }

        if ($('resultPanel')) {
            $('resultPanel').hidden = true;
        }

        $('urlInput')?.focus();

        window.scrollTo({
            top: 0,
            behavior: 'smooth'
        });
    });

    // History buttons
    $('refreshHistory')?.addEventListener('click', loadHistory);

    $('clearHistory')?.addEventListener(
        'click',
        clearHistory
    );

    $('exportHistory')?.addEventListener(
        'click',
        exportHistoryCsv
    );

    // History search
    $('historySearch')?.addEventListener('input', event => {
        state.historySearch = event.target.value.trim();

        state.historyPage = 0;

        window.clearTimeout(state.searchTimer);

        state.searchTimer = window.setTimeout(
            loadHistory,
            300
        );
    });

    // History filter
    $('historyFilter')?.addEventListener('change', event => {
        state.historyFilter = event.target.value;

        state.historyPage = 0;

        loadHistory();
    });

    // Pagination
    $('prevPage')?.addEventListener('click', () => {
        if (state.historyPage > 0) {
            state.historyPage -= 1;
            loadHistory();
        }
    });

    $('nextPage')?.addEventListener('click', () => {
        if (
            (state.historyPage + 1) * state.pageSize <
            state.historyTotal
        ) {
            state.historyPage += 1;
            loadHistory();
        }
    });

    // History table actions
    $('historyTable')?.addEventListener('click', event => {
        const button = event.target.closest(
            'button[data-action]'
        );

        if (!button) {
            // Tapping anywhere on a row opens its details.
            const row = event.target.closest('tr[data-id]');

            if (row) openDetails(row.dataset.id);

            return;
        }

        const id = button.dataset.id;

        if (button.dataset.action === 'details') {
            openDetails(id);
        }

        if (button.dataset.action === 'delete') {
            deleteHistoryRecord(id);
        }
    });

    // Recent scans on the overview: tap a row to see its details.
    $('recentScans')?.addEventListener('click', event => {
        const row = event.target.closest('tr[data-id]');

        if (row) openDetails(row.dataset.id);
    });

    // Details modal
    $('closeModal')?.addEventListener(
        'click',
        closeDetails
    );

    $('detailsModal')?.addEventListener('click', event => {
        if (event.target === $('detailsModal')) {
            closeDetails();
        }
    });

    document.addEventListener('keydown', event => {
        if (event.key === 'Escape') {
            closeDetails();
            setSidebar(false);
        }
    });

    // Mobile sidebar: open with the menu button, close with the X button,
    // by tapping the dark area, with Escape, or after choosing a page.
    $('menuToggle')?.addEventListener('click', () => setSidebar(true));
    $('closeSidebar')?.addEventListener('click', () => setSidebar(false));
    $('sidebarBackdrop')?.addEventListener('click', () => setSidebar(false));

    window.matchMedia('(min-width: 801px)').addEventListener?.(
        'change',
        event => { if (event.matches) setSidebar(false); }
    );
}

/* =========================================
   13. APPLICATION INITIALIZATION
========================================= */

/* =========================================
   PHONE HELPERS
========================================= */

const HISTORY_COLUMNS = [
    'SCAN ID', 'URL / DOMAIN', 'CLASSIFICATION',
    'RISK SCORE', 'DETECTION MODE', 'DATE', 'ACTION'
];

const RECENT_COLUMNS = ['URL / DOMAIN', 'RESULT', 'RISK', 'TIME'];

// On a phone each table row becomes a card; the CSS prints these labels
// in front of every value (see .responsive-table in style.css).
function labelTableCells(tbody, labels) {
    tbody.querySelectorAll('tr').forEach(row => {
        row.querySelectorAll('td').forEach((cell, index) => {
            if (labels[index]) cell.dataset.label = labels[index];
        });
    });
}

function setSidebar(open) {
    const sidebar = $('sidebar');
    const toggle = $('menuToggle');

    document.body.classList.toggle('sidebar-open', open);
    toggle?.setAttribute('aria-expanded', String(open));

    if (open) {
        $('closeSidebar')?.focus({ preventScroll: true });
    } else if (sidebar?.contains(document.activeElement)) {
        toggle?.focus({ preventScroll: true });
    }
}

/* =========================================
   ONLINE / OFFLINE MODE
========================================= */

function loadModePreference() {
    try {
        const saved = window.localStorage.getItem(MODE_STORAGE_KEY);

        // Offline is the default; only an explicit "online" enables lookups.
        state.onlineMode = saved === 'online';
    } catch {
        state.onlineMode = false;
    }
}

function saveModePreference() {
    try {
        window.localStorage.setItem(
            MODE_STORAGE_KEY,
            state.onlineMode ? 'online' : 'offline'
        );
    } catch {
        /* storage can be blocked; the switch still works for this visit */
    }
}

function renderModeUI() {
    const button = $('modeToggle');
    const label = $('modeToggleText');
    const hint = $('modeHintText');
    const sidebar = $('sidebarMode');

    const online = state.onlineMode;
    const noInternet = online && state.internet === false;

    let text;
    let cssClass;
    let hintText;
    let sidebarText;

    if (!online) {
        text = 'OFFLINE MODE';
        cssClass = 'mode-offline';
        hintText = 'Offline mode: the URLs you scan are not sent anywhere. ' +
            'Only the local model, rules and lists are used.';
        sidebarText = 'Offline protection enabled';
    } else if (noInternet) {
        text = 'ONLINE MODE · NO INTERNET';
        cssClass = 'mode-fallback';
        hintText = 'Online mode is on, but no internet connection was found. ' +
            'Scans use the offline engine until you are connected.';
        sidebarText = 'No internet: offline protection active';
    } else {
        text = 'ONLINE MODE';
        cssClass = 'mode-online';
        hintText = 'Online mode: each scan also checks a live phishing feed ' +
            'and the domain\u2019s registration age (to catch brand-new sites). ' +
            'The page is never opened. Only the domain name is sent for the ' +
            'age check; if API keys are set, Google Safe Browsing and ' +
            'URLhaus receive the full URL.';
        sidebarText = 'Online + offline protection enabled';
    }

    if (button) {
        button.classList.remove('mode-online', 'mode-offline', 'mode-fallback');
        button.classList.add(cssClass);
        button.setAttribute('aria-pressed', String(online));
    }

    if (label) {
        // "ONLINE" always shows; " MODE" / "· NO INTERNET" are hidden on
        // narrow screens by CSS, where a warning sign is shown instead.
        const word = text.split(' ')[0];

        label.innerHTML =
            word +
            (noInternet ? '<span class="mode-warn"> ⚠</span>' : '') +
            '<span class="mode-long">' + text.slice(word.length) + '</span>';
    }

    button?.setAttribute('aria-label', text);
    if (hint) hint.textContent = hintText;
    if (sidebar) sidebar.textContent = sidebarText;
}

async function refreshInternetStatus() {
    // Do not even call the local status endpoint while Offline mode is active.
    if (!state.onlineMode) {
        state.internet = false;
        renderModeUI();
        return;
    }

    try {
        const response = await fetch(API.status, {
            credentials: 'same-origin'
        });
        const payload = await response.json();

        state.internet = payload?.internet === true;
    } catch {
        // The dashboard cannot reach its own server: treat as unknown.
        state.internet = null;
    }

    renderModeUI();
}

function toggleMode() {
    state.onlineMode = !state.onlineMode;

    saveModePreference();
    renderModeUI();

    showToast(
        state.onlineMode
            ? 'Online mode on: scans also use live online checks.'
            : 'Offline mode on: scanned URLs stay on this computer.',
        'info'
    );

    if (state.onlineMode) {
        void refreshInternetStatus();
    } else {
        state.internet = false;
        renderModeUI();
    }
}

/* =========================================
   ACCOUNT MANAGEMENT
========================================= */
async function csrfHeader() {
    const token = await apiRequest(API.csrf);
    return { 'X-CSRF-Token': token.csrf_token };
}

function setAuthMode(mode) {
    const loginMode = mode !== 'register';
    $('loginForm').hidden = !loginMode;
    $('registerForm').hidden = loginMode;
    document.querySelectorAll('[data-auth-mode]').forEach(button => {
        button.classList.toggle('active', button.dataset.authMode === (loginMode ? 'login' : 'register'));
    });
    if ($('accountFeedback')) $('accountFeedback').textContent = '';
}

async function loadAccount() {
    const signedOut = $('accountSignedOut');
    const signedIn = $('accountSignedIn');
    if (!signedOut || !signedIn) return;
    try {
        const [auth, billing] = await Promise.all([
            apiRequest(API.authMe),
            apiRequest(API.subscription)
        ]);
        state.authenticated = Boolean(auth.authenticated);
        state.account = auth.user || null;
        signedOut.hidden = state.authenticated;
        signedIn.hidden = !state.authenticated;
        if (!state.authenticated) {
            setAuthMode('login');
            return;
        }

        const plan = billing.plan || {};
        const usage = billing.usage || {};
        $('accountEmail').textContent = auth.user.email;
        $('accountPlanName').textContent = plan.name || 'Free';
        $('accountPlanStatus').textContent = String(plan.status || 'active').toUpperCase();
        $('accountUsageText').textContent = Number(usage.scans_used || 0) + ' / ' + Number(usage.scans_limit || 50);
        const percent = usage.scans_limit
            ? Math.min(100, (Number(usage.scans_used || 0) / Number(usage.scans_limit)) * 100)
            : 0;
        $('accountUsageBar').style.width = percent + '%';
        $('accountUsageNote').textContent =
            Number(usage.scans_remaining || 0) + ' scans remaining this month. Usage resets at the start of each UTC calendar month.';
        const end = plan.current_period_end
            ? new Date(plan.current_period_end).toLocaleDateString()
            : 'No paid renewal date';
        $('accountPlanDetails').innerHTML =
            '<div><span>Billing</span><strong>' +
            (plan.plan_id === 'business' ? '$19.99 every 7 months' :
                plan.plan_id === 'pro' ? '$4.99 per month' : 'Free plan') +
            '</strong></div><div><span>Plan period ends</span><strong>' +
            escapeHtml(end) + '</strong></div>';
    } catch (error) {
        showToast('Could not load account details: ' + error.message, 'error');
    }
}

async function submitAccountForm(event, mode) {
    event.preventDefault();
    const form = event.currentTarget;
    const email = form.elements.email.value.trim();
    const password = form.elements.password.value;
    const feedback = $('accountFeedback');
    feedback.textContent = mode === 'register' ? 'Creating your account…' : 'Signing in…';
    try {
        const headers = await csrfHeader();
        const response = await apiRequest(mode === 'register' ? API.register : API.login, {
            method: 'POST',
            headers,
            body: JSON.stringify({ email, password })
        });
        feedback.textContent = '';
        form.reset();
        await loadAccount();
        await loadOverview();
        await loadHistory();
        await loadAdPlacement();
        showToast(mode === 'register' ? 'Your Free account is ready.' : 'You are signed in.', 'success');
    } catch (error) {
        feedback.textContent = error.message;
        showToast(error.message, 'error');
    }
}

async function signOutAccount() {
    try {
        const headers = await csrfHeader();
        await apiRequest(API.logout, { method: 'POST', headers, body: '{}' });
        state.authenticated = false;
        state.account = null;
        await loadAccount();
        await loadOverview();
        await loadHistory();
        await loadAdPlacement();
        showToast('You have signed out.', 'success');
    } catch (error) {
        showToast('Sign out failed: ' + error.message, 'error');
    }
}

async function requestPlanUpgrade(planId) {
    if (planId === 'free') {
        goToPage('account');
        return;
    }
    if (!state.authenticated) {
        goToPage('account');
        showToast('Create a Free account or sign in before upgrading.', 'info');
        return;
    }

    const selected = window.prompt(
        'Choose payment method: enter 1 for international card (USD) or 2 for MTN/Airtel Mobile Money (RWF).',
        '1'
    );
    if (selected === null) return;
    const paymentMethod = selected.trim() === '1' ? 'card' :
        selected.trim() === '2' ? 'mobile_money' : null;
    if (!paymentMethod) {
        showToast('Choose 1 for card or 2 for Mobile Money.', 'error');
        return;
    }

    let phoneNumber;
    if (paymentMethod === 'mobile_money') {
        phoneNumber = window.prompt('Enter the MTN or Airtel Rwanda phone number used for payment:');
        if (!phoneNumber) return;
    }

    try {
        const headers = await csrfHeader();
        const result = await apiRequest('/api/billing/checkout', {
            method: 'POST',
            headers,
            body: JSON.stringify({
                plan_id: planId,
                payment_method: paymentMethod,
                phone_number: phoneNumber
            })
        });
        window.location.assign(result.checkout_url);
    } catch (error) {
        showToast(error.message, 'error');
    }
}

/* =========================================
   SUBSCRIPTION PLANS
========================================= */
async function loadAdPlacement() {
    const slot = $('overviewAd');
    if (!slot) return;
    slot.hidden = true;
    slot.replaceChildren();
    try {
        const [adConfig, account] = await Promise.all([
            apiRequest(API.ads),
            apiRequest(API.subscription)
        ]);
        const planId = account?.plan?.plan_id || 'free';
        if (!adConfig.enabled || planId !== 'free' || !navigator.onLine) return;

        slot.hidden = false;
        const ad = document.createElement('ins');
        ad.className = 'adsbygoogle';
        ad.style.display = 'block';
        ad.dataset.adClient = adConfig.client_id;
        ad.dataset.adSlot = adConfig.slot_id;
        ad.dataset.adFormat = 'auto';
        ad.dataset.fullWidthResponsive = 'true';
        slot.appendChild(ad);

        if (!document.querySelector('script[data-phishguard-adsense]')) {
            const script = document.createElement('script');
            script.async = true;
            script.crossOrigin = 'anonymous';
            script.dataset.phishguardAdsense = 'true';
            script.src = 'https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=' +
                encodeURIComponent(adConfig.client_id);
            script.onload = () => {
                try { (window.adsbygoogle = window.adsbygoogle || []).push({}); }
                catch { slot.hidden = true; }
            };
            document.head.appendChild(script);
        } else {
            try { (window.adsbygoogle = window.adsbygoogle || []).push({}); }
            catch { slot.hidden = true; }
        }
    } catch {
        // Ads are optional and must never affect offline scanning.
    }
}

async function loadPricing() {
    const grid = $('pricingGrid');
    if (!grid) return;
    try {
        const payload = await apiRequest(API.plans);
        const plans = payload.plans || {};
        const order = ['free', 'pro', 'business'];
        grid.innerHTML = order.filter(key => plans[key]).map(key => {
            const plan = plans[key];
            const interval = key === 'business' ? ' / 7 months' :
                key === 'pro' ? ' / month' : ' / forever';
            const price = Number(plan.price_usd).toFixed(2);
            const usageFeature = plan.limits?.scans_per_month
                ? [Number(plan.limits.scans_per_month).toLocaleString() + ' scans per month']
                : [];
            const features = [...usageFeature, ...(plan.features || [])].map(item =>
                '<li>' + escapeHtml(item) + '</li>'
            ).join('');
            return '<article class="panel pricing-card pricing-' + key + '">' +
                '<div class="eyebrow">' + escapeHtml(key.toUpperCase()) + ' PLAN</div>' +
                '<h2>' + escapeHtml(plan.name) + '</h2>' +
                '<div class="pricing-price">$' + price + '<span>' + interval + '</span></div>' +
                '<ul>' + features + '</ul>' +
                '<button class="secondary-button pricing-action" type="button" data-plan="' + key + '">' +
                (key === 'free' ? 'Included by default' : 'Choose payment method') + '</button>' +
                '</article>';
        }).join('');
    } catch {
        grid.textContent = 'Plans are temporarily unavailable. Please try again.';
    }
}

function handlePaymentReturn() {
    const params = new URLSearchParams(window.location.search);
    const paymentState = params.get('payment');
    if (!paymentState) return;

    const messages = {
        success: ['Payment verified. Your subscription is now active.', 'success'],
        not_completed: ['Payment was not completed. No plan change was made.', 'info'],
        verification_failed: ['We could not verify the payment yet. Please contact support before trying again.', 'error']
    };
    const message = messages[paymentState];
    if (message) {
        showToast(message[0], message[1]);
        if (paymentState === 'success' || paymentState === 'verification_failed') {
            void loadAccount();
        }
    }

    params.delete('payment');
    const cleanUrl = window.location.pathname +
        (params.toString() ? '?' + params.toString() : '') +
        window.location.hash;
    window.history.replaceState({}, document.title, cleanUrl);
}

document.addEventListener('DOMContentLoaded', () => {
    handlePaymentReturn();
    bindEvents();
    void loadPricing();
    void loadAdPlacement();
    void loadAccount();

    loadModePreference();
    renderModeUI();
    $('modeToggle')?.addEventListener('click', toggleMode);
    if (state.onlineMode) {
        void refreshInternetStatus();
    }
    window.setInterval(() => {
        if (state.onlineMode) void refreshInternetStatus();
    }, 30000);

    loadOverview();
});
