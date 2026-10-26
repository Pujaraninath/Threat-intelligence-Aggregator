document.addEventListener('DOMContentLoaded', () => {
    // DOM Elements
    const scanForm = document.getElementById('scanForm');
    const targetInput = document.getElementById('targetInput');
    const typeSelect = document.getElementById('typeSelect');
    const vtKeyInput = document.getElementById('vtKeyInput');
    const otxKeyInput = document.getElementById('otxKeyInput');
    const analyzeBtn = document.getElementById('analyzeBtn');
    const btnText = document.getElementById('btnText');
    const btnSpinner = document.getElementById('btnSpinner');
    const errorBox = document.getElementById('errorBox');
    const resultsContainer = document.getElementById('resultsContainer');
    const historyList = document.getElementById('historyList');
    const clearHistoryBtn = document.getElementById('clearHistoryBtn');
    const tableSearchInput = document.getElementById('tableSearchInput');

    // Display Elements
    const threatBadge = document.getElementById('threatBadge');
    const metricDetections = document.getElementById('metricDetections');
    const metricPulses = document.getElementById('metricPulses');
    const metricScore = document.getElementById('metricScore');
    const vtSummaryContent = document.getElementById('vtSummaryContent');
    const otxSummaryContent = document.getElementById('otxSummaryContent');
    const engineTableBody = document.getElementById('engineTableBody');

    // Load Search History on Startup
    loadHistory();

    // Event Listener: Form Submit
    scanForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const target = targetInput.value.trim();
        const type = typeSelect.value;
        const vtKey = vtKeyInput.value.trim();
        const otxKey = otxKeyInput.value.trim();

        if (!target) return;

        // UI Loading State
        setLoadingState(true);
        hideError();
        resultsContainer.classList.add('hidden');

        try {
            const response = await fetch('/api/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target, type, vt_key: vtKey, otx_key: otxKey })
            });

            const data = await response.json();

            if (!response.ok || data.status === 'error') {
                showError(data.message || 'An error occurred while fetching threat intelligence.');
            } else {
                renderDashboard(data);
                saveToHistory(data);
                resultsContainer.classList.remove('hidden');
            }
        } catch (err) {
            showError('Failed to connect to backend server. ' + err.message);
        } finally {
            setLoadingState(false);
        }
    });

    // Render Dashboard Results
    function renderDashboard(data) {
        const assessment = data.assessment;
        const vt = data.virustotal;
        const otx = data.alienvault_otx;

        // 1. Render Summary Cards
        threatBadge.textContent = assessment.threat_level;
        threatBadge.className = `badge ${assessment.badge_class}`;

        if (vt.status === 'success') {
            const totalEngines = (vt.stats.malicious + vt.stats.harmless + vt.stats.undetected + vt.stats.suspicious);
            metricDetections.textContent = `${vt.stats.malicious} / ${totalEngines}`;
        } else {
            metricDetections.textContent = 'N/A';
        }

        metricPulses.textContent = assessment.pulse_count;
        metricScore.textContent = `${assessment.threat_score} / 100`;

        // 2. Render VirusTotal Section
        if (vt.status === 'success') {
            const tagsHtml = vt.tags.length > 0 
                ? vt.tags.map(t => `<span class="tag">${t}</span>`).join('') 
                : '<span class="info-value">None</span>';

            vtSummaryContent.innerHTML = `
                <div class="info-row"><span class="info-label">ASN / Owner</span><span class="info-value">${vt.asn} (${vt.as_owner})</span></div>
                <div class="info-row"><span class="info-label">Country Code</span><span class="info-value">${vt.country}</span></div>
                <div class="info-row"><span class="info-label">Community Reputation</span><span class="info-value">${vt.reputation}</span></div>
                <div style="margin-top:0.75rem;">
                    <span class="info-label">Associated Tags:</span>
                    <div class="tag-cloud">${tagsHtml}</div>
                </div>
            `;
        } else {
            vtSummaryContent.innerHTML = `<p class="info-label">${vt.error || vt.message || 'No VirusTotal data available.'}</p>`;
        }

        // 3. Render AlienVault OTX Section
        if (otx.status === 'success') {
            const otxTags = otx.tags.length > 0 
                ? otx.tags.map(t => `<span class="tag">${t}</span>`).join('') 
                : '<span class="info-value">None</span>';

            const malwareFamilies = otx.malware_families.length > 0
                ? otx.malware_families.join(', ')
                : 'None detected';

            otxSummaryContent.innerHTML = `
                <div class="info-row"><span class="info-label">Active Pulses</span><span class="info-value">${otx.pulse_count}</span></div>
                <div class="info-row"><span class="info-label">Malware Families</span><span class="info-value">${malwareFamilies}</span></div>
                <div class="info-row"><span class="info-label">Country</span><span class="info-value">${otx.country_name}</span></div>
                <div style="margin-top:0.75rem;">
                    <span class="info-label">OTX Threat Tags:</span>
                    <div class="tag-cloud">${otxTags}</div>
                </div>
            `;
        } else {
            otxSummaryContent.innerHTML = `<p class="info-label">${otx.error || otx.message || 'No AlienVault OTX data available.'}</p>`;
        }

        // 4. Populate Vendor Table
        engineTableBody.innerHTML = '';
        if (vt.status === 'success' && vt.engines && vt.engines.length > 0) {
            vt.engines.forEach(eng => {
                const tr = document.createElement('tr');
                
                // Result style
                let resultColor = 'color: var(--text-muted);';
                if (eng.category === 'malicious') resultColor = 'color: var(--color-malicious); font-weight: 600;';
                if (eng.category === 'suspicious') resultColor = 'color: var(--color-suspicious); font-weight: 600;';
                if (eng.category === 'harmless') resultColor = 'color: var(--color-clean);';

                tr.innerHTML = `
                    <td style="font-weight:500;">${eng.engine}</td>
                    <td style="text-transform: capitalize;">${eng.category}</td>
                    <td style="${resultColor}">${eng.result}</td>
                    <td style="color: var(--text-muted);">${eng.method}</td>
                `;
                engineTableBody.appendChild(tr);
            });
        } else {
            engineTableBody.innerHTML = `<tr><td colspan="4" style="text-align:center; color: var(--text-muted);">No vendor detection table entries available.</td></tr>`;
        }
    }

    // Filter Table Entries
    tableSearchInput.addEventListener('input', (e) => {
        const query = e.target.value.toLowerCase();
        const rows = engineTableBody.querySelectorAll('tr');
        rows.forEach(row => {
            const text = row.textContent.toLowerCase();
            row.style.display = text.includes(query) ? '' : 'none';
        });
    });

    // History Storage Handling (localStorage)
    function saveToHistory(scanData) {
        let history = JSON.parse(localStorage.getItem('ioc_search_history') || '[]');
        
        // Prevent duplicate consecutive entries
        history = history.filter(item => item.target !== scanData.target);

        history.unshift({
            target: scanData.target,
            type: scanData.type,
            level: scanData.assessment.threat_level,
            timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
        });

        if (history.length > 10) history.pop(); // Keep top 10

        localStorage.setItem('ioc_search_history', JSON.stringify(history));
        loadHistory();
    }

    function loadHistory() {
        const history = JSON.parse(localStorage.getItem('ioc_search_history') || '[]');
        historyList.innerHTML = '';

        if (history.length === 0) {
            historyList.innerHTML = `<li class="empty-history">No recent searches recorded.</li>`;
            return;
        }

        history.forEach(item => {
            const li = document.createElement('li');
            li.className = 'history-item';
            li.innerHTML = `
                <span class="history-target">${item.target}</span>
                <div class="history-meta">
                    <span style="text-transform:uppercase;">${item.type}</span>
                    <span>${item.level} • ${item.timestamp}</span>
                </div>
            `;
            li.addEventListener('click', () => {
                targetInput.value = item.target;
                typeSelect.value = item.type;
                scanForm.dispatchEvent(new Event('submit'));
            });
            historyList.appendChild(li);
        });
    }

    clearHistoryBtn.addEventListener('click', () => {
        localStorage.removeItem('ioc_search_history');
        loadHistory();
    });

    // Helper Utilities
    function setLoadingState(isLoading) {
        analyzeBtn.disabled = isLoading;
        if (isLoading) {
            btnText.textContent = 'Scanning...';
            btnSpinner.classList.remove('hidden');
        } else {
            btnText.textContent = 'Analyze Threat';
            btnSpinner.classList.add('hidden');
        }
    }

    function showError(msg) {
        errorBox.textContent = msg;
        errorBox.classList.remove('hidden');
    }

    function hideError() {
        errorBox.classList.add('hidden');
    }
});