document.getElementById('auditForm').addEventListener('submit', async (e) => {
    e.preventDefault();

    const runBtn = document.getElementById('runBtn');
    const btnText = document.getElementById('btnText');
    const spinner = document.getElementById('spinner');
    const resultsSection = document.getElementById('resultsSection');
    
    // UI State: Loading
    runBtn.disabled = true;
    btnText.style.display = 'none';
    spinner.style.display = 'block';
    resultsSection.style.display = 'none';

    // Gather data
    const payload = {
        target_url: document.getElementById('target_url').value,
        db_config: document.getElementById('db_config').value,
        log_file: document.getElementById('log_file').value,
        iam_config: document.getElementById('iam_config').value
    };

    try {
        const response = await fetch('/api/run-audit', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        const data = await response.json();

        if (data.status === 'success') {
            renderResults(data.findings, data.report_url);
        } else {
            alert('Error running audit: ' + data.message);
        }
    } catch (error) {
        alert('Network error: ' + error.message);
    } finally {
        // UI State: Reset
        runBtn.disabled = false;
        btnText.style.display = 'block';
        spinner.style.display = 'none';
    }
});

function renderResults(findings, reportUrl) {
    // Show section
    document.getElementById('resultsSection').style.display = 'block';

    // Calculate Summary
    let passCount = 0;
    let failCount = 0;
    let errorCount = 0;

    const tbody = document.getElementById('findingsBody');
    tbody.innerHTML = ''; // Clear old results

    findings.forEach(f => {
        if (f.status === 'PASS') passCount++;
        else if (f.status === 'FAIL') failCount++;
        else errorCount++;

        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td><span class="status-badge status-${f.status}">${f.status}</span></td>
            <td><strong>${f.component}</strong></td>
            <td>${f.finding}</td>
        `;
        tbody.appendChild(tr);
    });

    // Update Counters
    document.getElementById('passCount').innerText = passCount;
    document.getElementById('failCount').innerText = failCount;
    document.getElementById('errorCount').innerText = errorCount;

    // Update Download Button
    const dlBtn = document.getElementById('downloadBtn');
    dlBtn.href = reportUrl;
    dlBtn.style.display = 'inline-flex';
}
