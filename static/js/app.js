document.addEventListener("DOMContentLoaded", () => {
    fetchStats();
    fetchLogs();
});

const presets = {
    bank: "⚠️ ជូនដំណឹងបន្ទាន់ពីធនាគារ ABA Bank! គណនីរបស់អ្នកត្រូវបានផ្អាកបណ្តោះអាសន្ន ដោយសារបញ្ហាសុវត្ថិភាព។ សូមប្រញាប់ចុចតំណភ្ជាប់ https://aba-bank-verify.com/login ដើម្បីផ្ទៀងផ្ទាត់លេខកូដ OTP របស់អ្នកឱ្យបានមុនម៉ោង 5:00 ល្ងាច ដើម្បជៀសវាងការបិទគណនីរហូត!",
    threat: "⚠️ បទបញ្ជាបន្ទាន់ពីតុលាការ និងប៉ូលីស! គណនីរបស់អ្នកជាប់ពាក់ព័ន្ធករណីលាងលុយកខ្វក់។ ប្រសិនបើអ្នកមិនផ្ទេរប្រាក់ចំនួន $500 មកកាន់គណនីស៊ើបអង្កេត ក្នុងរយៈពេល 30 នាទីនេះទេ យើងនឹងចាត់វិធានការតាមផ្លូវច្បាប់ និងឃាត់ខ្លួនអ្នក!",
    apk: "📱 ទទួលបានកម្មវិធី Telegram VIP Special Edition ដោយឥតគិតថ្លៃ! ទាញយកឯកសារ Telegram_Security_Update.apk ឥឡូវនេះដើម្បីទទួលបាន Feature ពិសេសៗជាច្រើន https://telegram-apk-free.net/download",
    safe: "ជំរាបសួរមិត្តភក្តិ! តើថ្ងៃនេះទំនេរទេ? ពួកយើងអាចជួបគ្នាញ៉ាំកាហ្វេនៅហាង Cafe Amazon បានទេនៅម៉ោង 3 រសៀល?"
};

function loadPreset(type) {
    if (presets[type]) {
        document.getElementById("input-text").value = presets[type];
    }
}

async function fetchStats() {
    try {
        const res = await fetch("/api/stats");
        const data = await res.json();
        
        document.getElementById("stat-total").innerText = data.total_scans || 0;
        document.getElementById("stat-dangerous").innerText = data.dangerous_count || 0;
        document.getElementById("stat-suspicious").innerText = data.suspicious_count || 0;
        document.getElementById("stat-safe").innerText = data.safe_count || 0;
    } catch (e) {
        console.error("Error fetching stats:", e);
    }
}

async function fetchLogs() {
    try {
        const res = await fetch("/api/scans?limit=15");
        const logs = await res.json();
        const tbody = document.getElementById("logs-tbody");

        if (!logs || logs.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-muted);">មិនទាន់មានប្រវត្តិស្កេននៅឡើយ</td></tr>';
            return;
        }

        tbody.innerHTML = logs.map(log => `
            <tr>
                <td>#${log.id}</td>
                <td style="font-size: 0.8rem; color: var(--text-muted);">${log.timestamp}</td>
                <td><span class="chip" style="font-size: 0.75rem;">${log.scan_type}</span></td>
                <td style="max-width: 300px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">${escapeHtml(log.input_summary)}</td>
                <td><span class="badge ${log.risk_level}">${log.risk_level}</span></td>
                <td><strong>${log.risk_score}/100</strong></td>
            </tr>
        `).join("");
    } catch (e) {
        console.error("Error fetching logs:", e);
    }
}

async function simulateTextScan() {
    const text = document.getElementById("input-text").value.trim();
    if (!text) {
        alert("សូមបញ្ចូលសារ ឬ តំណភ្ជាប់ជាមុនសិន!");
        return;
    }

    const container = document.getElementById("result-container");
    container.innerHTML = '<div style="text-align:center;"><i class="fa-solid fa-spinner fa-spin" style="font-size: 2rem; color: var(--accent-blue);"></i><p style="margin-top:0.5rem;">កំពុងវិភាគសារ និងស្កេន VirusTotal v3...</p></div>';

    try {
        const res = await fetch("/api/scan/text", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ text })
        });
        const data = await res.json();
        renderReport(data);
        fetchStats();
        fetchLogs();
    } catch (e) {
        container.innerHTML = `<div style="color: var(--danger-red);">❌ បរាជ័យក្នុងការវិភាគ៖ ${e.message}</div>`;
    }
}

async function simulateFileScan() {
    const fileInput = document.getElementById("input-file");
    if (!fileInput.files || fileInput.files.length === 0) {
        alert("សូមជ្រើសរើសឯកសារ (.APK, .EXE, .ZIP, .PDF) ជាមុនសិន!");
        return;
    }

    const file = fileInput.files[0];
    const formData = new FormData();
    formData.append("file", file);

    const container = document.getElementById("result-container");
    container.innerHTML = '<div style="text-align:center;"><i class="fa-solid fa-spinner fa-spin" style="font-size: 2rem; color: var(--accent-blue);"></i><p style="margin-top:0.5rem;">កំពុងគណនា SHA-256 និងស្កេន VirusTotal v3...</p></div>';

    try {
        const res = await fetch("/api/scan/file", {
            method: "POST",
            body: formData
        });
        const data = await res.json();
        renderFileReport(data);
        fetchStats();
        fetchLogs();
    } catch (e) {
        container.innerHTML = `<div style="color: var(--danger-red);">❌ បរាជ័យក្នុងការស្កេនឯកសារ៖ ${e.message}</div>`;
    }
}

function renderReport(data) {
    const ai = data.ai_report;
    const vtList = data.vt_reports || [];
    const container = document.getElementById("result-container");

    let vtHtml = "";
    if (vtList.length > 0) {
        vtHtml = `
            <div style="margin-top: 1rem; background: rgba(0,0,0,0.2); padding: 0.85rem; border-radius: 8px;">
                <h5 style="color: var(--accent-blue); margin-bottom: 0.5rem;"><i class="fa-solid fa-network-wired"></i> VirusTotal v3 URL Scan</h5>
                ${vtList.map(v => `
                    <div style="font-size: 0.85rem; margin-bottom: 0.25rem;">
                        <code>${escapeHtml(v.target)}</code> ➔ 
                        <span class="badge ${v.status}">${v.status}</span> 
                        (${v.malicious_count}/${v.total_engines} engines flagged)
                    </div>
                `).join("")}
            </div>
        `;
    }

    let factorsHtml = "";
    if (ai.threat_factors && ai.threat_factors.length > 0) {
        factorsHtml = `
            <div style="margin-top: 0.75rem;">
                <strong style="color: var(--text-muted); font-size: 0.85rem;">កត្តាហានិភ័យ (Indicators):</strong>
                <ul style="margin-left: 1.25rem; font-size: 0.85rem; margin-top: 0.25rem;">
                    ${ai.threat_factors.map(f => `<li style="color: var(--danger-red);">${escapeHtml(f)}</li>`).join("")}
                </ul>
            </div>
        `;
    }

    let actionsHtml = "";
    if (ai.action_steps && ai.action_steps.length > 0) {
        actionsHtml = `
            <div style="margin-top: 0.75rem; background: rgba(255,255,255,0.03); padding: 0.85rem; border-radius: 8px;">
                <strong style="color: var(--accent-blue); font-size: 0.85rem;"><i class="fa-solid fa-list-check"></i> ជំហានអនុវត្តជាក់ស្តែង (Actionable Steps):</strong>
                <ul style="margin-left: 1.25rem; font-size: 0.85rem; margin-top: 0.35rem; line-height: 1.6;">
                    ${ai.action_steps.map(s => `<li>${escapeHtml(s).replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')}</li>`).join("")}
                </ul>
            </div>
        `;
    }

    container.innerHTML = `
        <div>
            <div class="result-badge ${data.highest_risk}">${ai.risk_badge} (Score: ${ai.risk_score}/100)</div>
            <h4 style="margin-bottom: 0.5rem;">${escapeHtml(ai.category)}</h4>
            <p style="font-size: 0.95rem; line-height: 1.5; color: #e5e7eb;">${escapeHtml(ai.summary_kh)}</p>
            ${factorsHtml}
            ${vtHtml}
            ${actionsHtml}
            <div style="margin-top: 1rem; padding: 0.75rem; background: rgba(0, 242, 254, 0.05); border-left: 3px solid var(--accent-blue); font-size: 0.85rem;">
                <strong>💡 ការណែនាំ៖</strong> ${escapeHtml(ai.recommendation)}
            </div>
        </div>
    `;

}

function renderFileReport(data) {
    const vt = data.virustotal;
    const container = document.getElementById("result-container");

    container.innerHTML = `
        <div>
            <div class="result-badge ${data.risk_level}">FILE ${data.risk_level}: ${escapeHtml(data.filename)}</div>
            <h4 style="margin-bottom: 0.5rem;">VirusTotal File Hash Scan</h4>
            <p style="font-size: 0.85rem; color: var(--text-muted);">SHA-256: <code>${vt.file_hash}</code></p>
            <p style="font-size: 0.9rem; margin-top: 0.5rem;"><strong>ប្រភេទឯកសារ៖</strong> ${vt.extension_description}</p>
            <div style="margin-top: 0.75rem; background: rgba(0,0,0,0.2); padding: 0.85rem; border-radius: 8px;">
                <p style="font-size: 0.9rem;"><strong>VirusTotal Detections:</strong> ${vt.malicious_count} / ${vt.total_engines} Engines Flagged Malicious</p>
            </div>
            <div style="margin-top: 1rem; padding: 0.75rem; background: rgba(0, 242, 254, 0.05); border-left: 3px solid var(--accent-blue); font-size: 0.85rem;">
                <strong>💡 ការណែនាំ៖</strong> ${data.risk_level === 'DANGEROUS' ? '⛔ ហាមបើក ឬដំឡើងឯកសារនេះដាច់ខាត!' : '✅ ឯកសារនេះត្រូវបានស្កេនយ៉ាងម៉ត់ចត់។'}
            </div>
        </div>
    `;
}

function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
