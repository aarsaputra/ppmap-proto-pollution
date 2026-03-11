document.addEventListener('DOMContentLoaded', () => {
    fetchReport();
});

async function fetchReport() {
    try {
        const response = await fetch('../reports/example-scan.json');
        const data = await response.json();
        renderReport(data);
    } catch (error) {
        console.error('Error loading report:', error);
        document.getElementById('report-container').innerHTML = '<p class="error">Error loading demo report.</p>';
    }
}

function renderReport(data) {
    const container = document.getElementById('findings-list');
    if (!container) return;

    // Update Header
    document.getElementById('target-url').textContent = data.target;
    document.getElementById('total-vulns').textContent = data.total_vulnerabilities;
    document.getElementById('scan-date').textContent = new Date(data.scan_time).toLocaleDateString();

    // Update New Metrics if they exist
    if (data.metrics) {
        if (document.getElementById('endpoints-scanned')) {
            document.getElementById('endpoints-scanned').textContent = data.metrics.endpoints_scanned;
        }
        if (document.getElementById('assets-filtered')) {
            document.getElementById('assets-filtered').textContent = data.metrics.assets_filtered;
        }
        if (document.getElementById('time-saved')) {
            document.getElementById('time-saved').textContent = data.metrics.time_saved_by_reuse;
        }
    }

    // Render Findings
    container.innerHTML = '';
    data.findings.forEach(finding => {
        const card = document.createElement('div');
        card.className = `finding-card ${finding.severity.toLowerCase()}`;

        card.innerHTML = `
            <div class="finding-header">
                <span class="severity-badge ${finding.severity.toLowerCase()}">${finding.severity}</span>
                <span class="finding-id">${finding.id}</span>
            </div>
            <h3>${finding.type}: ${finding.component}</h3>
            <p class="desc">${finding.description}</p>
            ${finding.cve ? `<div class="cve-tag">${finding.cve}</div>` : ''}
            
            <div class="expand-details">
                <div class="code-block">
                    <code>${finding.payload}</code>
                </div>
                <div class="steps">
                    <strong>Reproduction:</strong>
                    <pre>${finding.reproduction}</pre>
                </div>
            </div>
        `;
        container.appendChild(card);
    });
}
