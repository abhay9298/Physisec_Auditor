// Data persistence simulation - retrieve from localStorage
const auditData = JSON.parse(localStorage.getItem('physisecAuditData')) || {
    devices: [],
    checks: {},
    images: [],
    metadata: { room: "Untitled Room", auditor: "Auditor", timestamp: new Date().toISOString() },
    coverage: 'full',
    nextCheckId: 100,
    apiKeys: {
        chatgpt: '',
        gemini: ''
    }
};

// Global state for processed data
let processedAuditData = {
    final_score: 0,
    breakdown: [],
    processedDevices: []
};
let destructTimerInterval;
const AUTO_DESTRUCT_TIMEOUT = 10 * 60; // 10 minutes in seconds

// --- Mock CVE Data/Scoring Logic (Client-Side) ---

// Mock CVE data simulation
const MOCK_CVES = [
    { id: 'CVE-2023-20198', cvss: 9.8, severity: 'CRITICAL', desc: 'Cisco IOS XE Web UI vulnerability. Critical vulnerability in an operating system that runs on routers.', url: '#', model: '2960-X' },
    { id: 'CVE-2023-44487', cvss: 7.5, severity: 'HIGH', desc: 'HTTP/2 Rapid Reset attack. Denial of Service vulnerability affecting web servers.', url: '#', model: 'AC-Pro' },
    { id: 'CVE-2023-0001', cvss: 3.5, severity: 'LOW', desc: 'Minor buffer overflow.', url: '#', model: 'UniFi' },
    { id: 'CVE-2023-0002', cvss: 9.0, severity: 'CRITICAL', desc: 'Default credentials issue on older IP cameras.', url: '#', model: 'Camera' },
];

const ScoringEngine = {
    mapCvssToScore: (maxCvss, totalCves, criticalCves) => {
        // Base score from max CVSS
        let baseScore = 100;
        if (maxCvss >= 9.0) baseScore = 0;
        else if (maxCvss >= 7.0) baseScore = 20;
        else if (maxCvss >= 4.0) baseScore = 50;
        else if (maxCvss > 0) baseScore = 75;
        
        // Penalize for multiple vulnerabilities
        if (totalCves > 0) {
            const cvePenalty = Math.min(totalCves * 3, 30); // Max 30 point penalty
            baseScore = Math.max(0, baseScore - cvePenalty);
        }
        
        // Additional penalty for critical vulnerabilities
        if (criticalCves > 0) {
            const criticalPenalty = criticalCves * 10; // 10 points per critical CVE
            baseScore = Math.max(0, baseScore - criticalPenalty);
        }
        
        return Math.round(baseScore);
    },
    calculatePhysicalScore: (checks) => {
        const checkItems = Object.values(checks).filter(status => status !== 'na');

        if (checkItems.length === 0) return 100;

        const totalChecks = checkItems.length;
        const passedCount = checkItems.filter(status => status === 'pass').length;
        const failedCount = checkItems.filter(status => status === 'fail').length;

        // Calculate score based on pass percentage
        // Formula: (passed / total) * 100
        // Example: 60 passed, 11 failed out of 71 = (60/71) * 100 = 84.5%
        // This directly reflects the pass rate, which is fair
        
        const passRatio = passedCount / totalChecks;
        let finalScore = passRatio * 100;
        
        // Apply a minimal penalty for failures: 0.2 points per failure (max 5 points)
        // This way: 60 passed, 11 failed = 84.5 - (11 * 0.2) = 84.5 - 2.2 = 82.3 ≈ 82
        // This gives a score close to the pass percentage, which is fair
        const failPenalty = Math.min(failedCount * 0.2, 5);
        finalScore = finalScore - failPenalty;
        
        return Math.round(Math.max(0, Math.min(100, finalScore)));
    },
    getCameraScoreValue: (coverage) => {
        switch (coverage.toLowerCase()) {
            case 'full': return 100;
            case 'partial': return 60;
            case 'blindspot': return 20;
            case 'none': return 0;
            default: return 0;
        }
    },
    processAudit: (devices, checks, coverage) => {
        // ============================================
        // FACTOR 1: CVE IDs COUNT (kitni hai)
        // ============================================
        let maxCvss = 0;
        let totalCves = 0;  // Total number of CVEs found across all devices
        let criticalCves = 0;
        let highCves = 0;
        
        let processedDevices = devices.map(d => {
            // Use real CVE data from device if available, otherwise fallback to MOCK_CVES
            let cves = [];
            if (d.cves && Array.isArray(d.cves) && d.cves.length > 0) {
                // Use real CVE data from API lookup
                cves = d.cves;
            } else {
                // Fallback to mock data if no API data available
                cves = MOCK_CVES.filter(c =>
                    (d.model.toLowerCase().includes(c.model.toLowerCase().split(' ')[0])) ||
                    (d.firmware.toLowerCase().includes(c.model.toLowerCase().split(' ')[0]))
                );
            }

            // Count all CVEs for this device
            cves.forEach(c => {
                maxCvss = Math.max(maxCvss, c.cvss);
                totalCves++;  // Increment total CVE count
                if (c.severity === 'CRITICAL' || c.cvss >= 9.0) criticalCves++;
                else if (c.severity === 'HIGH' || c.cvss >= 7.0) highCves++;
            });

            return { ...d, cves, maxCvss: cves.length > 0 ? Math.max(...cves.map(c => c.cvss)) : 0 };
        });

        // Calculate vulnerability subscore based on CVE count, max CVSS, and critical CVEs
        let vuln_subscore;
        let hasDevices = devices.length > 0;
        
        if (!hasDevices) {
            vuln_subscore = 0; // No devices = don't count this factor
        } else {
            // This uses: maxCvss, totalCves (count), and criticalCves (count)
            vuln_subscore = ScoringEngine.mapCvssToScore(maxCvss, totalCves, criticalCves);
        }
        
        // ============================================
        // FACTOR 2: PHYSICAL SECURITY CONTROLS (Score Breakdown)
        // ============================================
        const physical_subscore = Object.keys(checks).length === 0 ? 100 : ScoringEngine.calculatePhysicalScore(checks);
        
        // ============================================
        // FACTOR 3: CAMERA COVERAGE
        // ============================================
        const camera_subscore = ScoringEngine.getCameraScoreValue(coverage);
        
        // ============================================
        // FINAL SCORE CALCULATION - All 3 Factors Combined
        // ============================================
        // Weighted scoring system
        const FINAL_SCORE_VULN_WEIGHT = 0.40;      // 40% - Device vulnerabilities (CVE count)
        const FINAL_SCORE_PHYSICAL_WEIGHT = 0.40;  // 40% - Physical security checks (Score Breakdown)
        const FINAL_SCORE_CAMERA_WEIGHT = 0.20;    // 20% - Camera coverage

        // Calculate base weighted score - adjust weights if no devices provided
        let final_score;
        if (!hasDevices) {
            // If no devices, redistribute weights: Physical 50%, Camera 50%
            final_score = (0.50 * physical_subscore) + (0.50 * camera_subscore);
        } else {
            // Normal calculation with all 3 factors
            final_score = (FINAL_SCORE_VULN_WEIGHT * vuln_subscore) +      // Factor 1: CVE count
                         (FINAL_SCORE_PHYSICAL_WEIGHT * physical_subscore) + // Factor 2: Physical security
                         (FINAL_SCORE_CAMERA_WEIGHT * camera_subscore);      // Factor 3: Camera coverage
        }

        // Additional penalties
        // Penalty for poor camera coverage
        if (camera_subscore < 50) {
            final_score *= 0.85; // 15% penalty
        } else if (camera_subscore < 60) {
            final_score *= 0.90; // 10% penalty
        }
        
        // Penalty for having many devices with vulnerabilities
        const devicesWithVulns = processedDevices.filter(d => d.cves && d.cves.length > 0).length;
        if (devicesWithVulns > 0 && devices.length > 0) {
            const vulnDeviceRatio = devicesWithVulns / devices.length;
            if (vulnDeviceRatio > 0.5) {
                final_score *= 0.90; // 10% penalty if more than 50% of devices have vulnerabilities
            }
        }

        final_score = Math.round(Math.max(0, Math.min(100, final_score)));

        // Calculate breakdown details
        const totalChecks = Object.keys(checks).length;
        const activeChecks = Object.values(checks).filter(s => s !== 'na').length;
        const passedChecks = Object.values(checks).filter(s => s === 'pass').length;
        const failedChecks = Object.values(checks).filter(s => s === 'fail').length;
        
        const breakdown = [
            { 
                name: "Device Vulnerabilities", 
                weight: 40, 
                score: vuln_subscore, 
                details: totalCves > 0 ? `${totalCves} CVEs found${criticalCves > 0 ? `, ${criticalCves} critical` : ''}${highCves > 0 ? `, ${highCves} high` : ''}` : 'No vulnerabilities detected'
            },
            { 
                name: "Physical Security Controls", 
                weight: 40, 
                score: physical_subscore,
                details: activeChecks > 0 ? `${passedChecks} passed, ${failedChecks} failed out of ${activeChecks} checked` : 'No checks performed'
            },
            { 
                name: "Camera Coverage", 
                weight: 20, 
                score: camera_subscore,
                details: coverage.charAt(0).toUpperCase() + coverage.slice(1) + ' coverage'
            },
        ];

        return { final_score, breakdown, processedDevices };
    }
};

// --- Auto Destruct Timer Logic ---
const startDestructTimer = () => {
    let timeLeft = AUTO_DESTRUCT_TIMEOUT;
    const timerDisplay = document.getElementById('destruct-timer');

    clearInterval(destructTimerInterval);

    const updateTimer = () => {
        const minutes = Math.floor(timeLeft / 60);
        const seconds = timeLeft % 60;
        timerDisplay.textContent = `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;

        if (timeLeft <= 0) {
            clearInterval(destructTimerInterval);
            timerDisplay.textContent = '00:00';
            clearSession(false); 
        }
        timeLeft--;
    };

    updateTimer();
    destructTimerInterval = setInterval(updateTimer, 1000);
};

window.clearSession = (shouldAlert = true) => {
    clearInterval(destructTimerInterval);
    localStorage.removeItem('physisecAuditData');
    localStorage.removeItem('physisecCurrentView');
    console.log("All session data explicitly cleared.");
    if(shouldAlert) {
        alert("Session data has been cleared."); 
    }
    window.location.href = 'main_page.html';
};

// --- Navigation ---
window.navigate = (target) => {
    clearInterval(destructTimerInterval); 
    
    localStorage.setItem('physisecCurrentView', target);

    if (target === 'landing' || target === 'audit-form') {
        window.location.href = 'main_page.html';
    }
};

// --- Renderer Functions ---

window.switchTab = (button) => {
    const tabName = button.dataset.tab;
    
    document.querySelectorAll('#vulnerability-tabs .tab-btn').forEach(btn => {
        btn.classList.remove('active-tab');
    });
    button.classList.add('active-tab');

    document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.add('hidden');
    });
    document.getElementById(`tab-${tabName}`).classList.remove('hidden');
};

const getColorCode = (severity) => {
    switch (severity.toUpperCase()) {
        case 'CRITICAL': return { color: 'red', hex: '#dc2626' };
        case 'HIGH': return { color: 'orange', hex: '#f97316' };
        case 'LOW':
        case 'MEDIUM':
        default: return { color: 'green', hex: '#10b981' };
    }
}

const renderImagePreview = () => {
    const previewContainer = document.getElementById('report-image-preview');
    if (!previewContainer) return;

    previewContainer.innerHTML = auditData.images.map((imgUrl, index) => `
        <div class="image-wrapper">
            <img src="${imgUrl}" alt="Audit evidence ${index + 1}">
            <p>Image ${index + 1}</p>
        </div>
    `).join('');
};


const renderReportPage = () => {
    if (!auditData.metadata.room) {
        // Fallback or redirection if essential data is missing
        console.error("Missing audit data. Redirecting.");
        window.location.href = 'main_page.html';
        return;
    }
    
    const analysisResult = ScoringEngine.processAudit(auditData.devices, auditData.checks, auditData.coverage);
    processedAuditData = analysisResult; 

    const { final_score, breakdown, processedDevices } = analysisResult;
    document.getElementById('report-room').textContent = auditData.metadata.room;
    document.getElementById('final-score').textContent = final_score;
    renderImagePreview(); 

    // 1. Score Display - Simple number with color coding
    const scoreValueElement = document.getElementById('final-score');
    
    // Dynamic color based on score
    let scoreColorHex;
    let scoreLabel;
    if (final_score >= 80) {
        scoreColorHex = '#10b981'; // Green
        scoreLabel = 'Excellent';
    } else if (final_score >= 65) {
        scoreColorHex = '#22c55e'; // Light green
        scoreLabel = 'Good';
    } else if (final_score >= 50) {
        scoreColorHex = '#f97316'; // Orange
        scoreLabel = 'Fair';
    } else if (final_score >= 30) {
        scoreColorHex = '#f59e0b'; // Amber
        scoreLabel = 'Poor';
    } else {
        scoreColorHex = '#ef4444'; // Red
        scoreLabel = 'Critical';
    }

    // Apply color to score
    scoreValueElement.style.color = scoreColorHex;
    
    // Add a subtle pulse animation for low scores
    if (final_score < 50) {
        scoreValueElement.style.animation = 'pulse 2s ease-in-out infinite';
    } else {
        scoreValueElement.style.animation = 'none';
    }

    // 2. Score Breakdown with enhanced details
    document.getElementById('score-breakdown-details').innerHTML = breakdown.map((item, index) => {
        // Determine progress bar color based on score
        let barColor = '#10b981'; // Green
        if (item.score < 50) barColor = '#ef4444'; // Red
        else if (item.score < 70) barColor = '#f97316'; // Orange
        
        // Ensure minimum width of 2% so color is visible even for score of 0
        const barWidth = item.score === 0 ? 2 : item.score;
        
        return `
        <div class="breakdown-item" style="animation: fadeIn 0.6s ease-out ${index * 0.1}s both;">
            <div class="breakdown-header">
                <span>${item.name} <span class="weight">(${item.weight}%)</span></span>
                <span class="breakdown-score">${item.score}/100</span>
            </div>
            ${item.details ? `<p class="breakdown-details-text">${item.details}</p>` : ''}
            <div class="progress-bar-bg">
                <div class="progress-bar-fill" style="width: ${barWidth}%; background-color: ${barColor} !important; transition: width 1s ease-out ${index * 0.2}s, background-color 0.3s ease;"></div>
            </div>
        </div>
    `;
    }).join('');

    // 3. Devices Tab Content
    document.getElementById('device-vulnerability-list').innerHTML = processedDevices.map(device => {
        const hasVulnerabilities = device.cves.length > 0;
        const hasCritical = device.cves.some(c => c.severity === 'CRITICAL');
        const listBorderColor = hasCritical ? '#ef4444' : (hasVulnerabilities ? '#f97316' : '#10b981');
        const tagText = hasVulnerabilities ? `${device.cves.length} CVEs` : `Good`;
        const tagColor = hasVulnerabilities ? (hasCritical ? 'red' : 'orange') : 'green';

        return `
            <div class="device-item-report" style="border-left-color: ${listBorderColor};">
                <div class="device-header">
                    <div class="device-details">
                        <span class="device-icon">&#x1F310;</span>
                        <div>
                            <p class="device-name">${device.name}</p>
                            <p class="device-model-firmware">Model: ${device.model} | Firmware: ${device.firmware}</p>
                        </div>
                    </div>
                    <span class="device-tag bg-${tagColor}">${tagText}</span>
                </div>
                
                ${hasVulnerabilities ? `<div class="cves-detected-list">
                    ${device.cves.map(cve => {
                        const { color } = getColorCode(cve.severity);
                        return `
                        <div class="cve-item-list">
                            <div class="cve-info">
                                <span class="cve-id text-${color}">${cve.id}</span> - ${cve.desc}
                            </div>
                            <span class="cve-score-tag bg-${color}">CVSS ${cve.cvss}</span>
                        </div>
                    `;
                    }).join('')}
                </div>` : ''}
            </div>
        `;
    }).join('');

    // 4. CVEs Tab Content
    let allCves = processedDevices.flatMap(d => d.cves.map(c => ({...c, device: d.name, model: d.model})));
    
    document.getElementById('cve-full-list').innerHTML = allCves.length > 0 ? allCves.map(cve => {
        const { color, hex } = getColorCode(cve.severity);
        return `
            <div class="cve-item-card" style="border-left-color: ${hex};">
                <div class="cve-card-header">
                    <span class="id">${cve.id}</span>
                    <span class="cve-card-severity bg-${color}">${cve.severity} (CVSS ${cve.cvss})</span>
                </div>
                <p class="cve-card-desc">${cve.desc}</p>
                <p class="cve-card-device">Affected Device: ${cve.device} (${cve.model})</p>
            </div>
        `;
    }).join('') : '<p class="no-vulnerabilities">No vulnerabilities found on the analyzed devices.</p>';

    const criticalCves = allCves.filter(c => c.severity === 'CRITICAL');
    document.getElementById('cve-summary-list').innerHTML = criticalCves.length > 0
        ? criticalCves.map(cve => `
            <div class="cve-summary-item">
                <span class="icon">&#x26A0;</span>
                <p>
                    <strong>${cve.id} (CVSS ${cve.cvss})</strong>: ${cve.desc}
                </p>
            </div>
        `).join('')
        : '<p class="no-vulnerabilities text-green">No critical vulnerabilities detected on scanned devices.</p>';


    // 5. Physical Checks Summary
    const checkCounts = { pass: 0, fail: 0, na: 0 };
    Object.values(auditData.checks).forEach(state => checkCounts[state]++);
    const totalChecks = Object.keys(auditData.checks).length;

    document.getElementById('physical-check-summary').innerHTML = `
        <p>Total Checks Performed: <strong>${totalChecks}</strong></p>
        <p class="text-green">Passed: <strong>${checkCounts.pass}</strong></p>
        <p class="text-red">Failed: <strong>${checkCounts.fail}</strong></p>
        <p class="text-gray">Not Applicable/Pending: <strong>${checkCounts.na}</strong></p>
        <p class="recommendation">
            Recommendation: Fix the ${checkCounts.fail} failed physical checks immediately.
        </p>
    `;

    const initialButton = document.querySelector('#vulnerability-tabs button[data-tab="devices"]');
    if (initialButton) {
        switchTab(initialButton);
    }
};

// --- Export Functions ---

window.downloadPdf = () => {
    // Store original tab states
    const tabDevices = document.getElementById('tab-devices');
    const tabCves = document.getElementById('tab-cves');
    const tabEvidence = document.getElementById('tab-evidence');
    const wasDevicesHidden = tabDevices.classList.contains('hidden');
    const wasCvesHidden = tabCves.classList.contains('hidden');
    const wasEvidenceHidden = tabEvidence.classList.contains('hidden');
    
    // Hide auto-destruct bar and export card before PDF generation
    const autoDestructBar = document.querySelector('.auto-destruct-bar');
    const exportCard = document.querySelector('.export-card');
    let wasAutoDestructVisible = true;
    let wasExportCardVisible = true;
    
    if (autoDestructBar) {
        wasAutoDestructVisible = autoDestructBar.style.display !== 'none';
        autoDestructBar.style.display = 'none';
    }
    if (exportCard) {
        wasExportCardVisible = exportCard.style.display !== 'none';
        exportCard.style.display = 'none';
    }
    
    // Show all tabs temporarily for PDF
    tabDevices.classList.remove('hidden');
    tabCves.classList.remove('hidden');
    tabEvidence.classList.remove('hidden');
    
    // Add a temporary title element for the PDF header
    const titleElement = document.createElement('h1');
    titleElement.textContent = `Physisec Audit Report - ${auditData.metadata.room}`;
    titleElement.style.cssText = 'text-align: center; margin-bottom: 20px; font-size: 2em; font-weight: bold; color: #1f2937;';
    
    const reportElement = document.getElementById('report-content');
    reportElement.insertAdjacentElement('beforebegin', titleElement);

    // Wait for content to render
    setTimeout(() => {
        html2pdf().set({
            margin: 10, // Equal margins on all sides
            filename: `Physisec_Audit_${auditData.metadata.room}_${auditData.metadata.auditor}.pdf`,
            image: { type: 'jpeg', quality: 0.98 },
            html2canvas: { 
                scale: 2,
                logging: false,
                dpi: 192,
                letterRendering: true,
                useCORS: true,
                backgroundColor: '#ffffff',
                onclone: function(clonedDoc) {
                    // Completely remove auto-destruct bar from PDF - try multiple selectors
                    const autoDestructBar = clonedDoc.querySelector('.auto-destruct-bar');
                    if (autoDestructBar) {
                        autoDestructBar.remove();
                    }
                    // Also try by ID and other methods
                    const destructTimer = clonedDoc.getElementById('destruct-timer');
                    if (destructTimer && destructTimer.parentElement && destructTimer.parentElement.parentElement) {
                        const bar = destructTimer.parentElement.parentElement;
                        if (bar.classList && bar.classList.contains('auto-destruct-bar')) {
                            bar.remove();
                        }
                    }
                    // Remove any remaining auto-destruct related elements
                    const allDestructElements = clonedDoc.querySelectorAll('[class*="destruct"], [class*="timer"], [id*="destruct"]');
                    allDestructElements.forEach(el => {
                        if (el.closest && el.closest('.auto-destruct-bar')) {
                            el.closest('.auto-destruct-bar').remove();
                        }
                    });
                    
                    // Completely remove export report box from PDF - try multiple selectors
                    const exportCard = clonedDoc.querySelector('.export-card');
                    if (exportCard) {
                        exportCard.remove();
                    }
                    // Also remove export buttons and subtext directly
                    const exportButtons = clonedDoc.querySelector('.export-buttons');
                    if (exportButtons) {
                        exportButtons.remove();
                    }
                    const exportSubtext = clonedDoc.querySelector('.export-subtext');
                    if (exportSubtext) {
                        exportSubtext.remove();
                    }
                    // Remove any card-section that contains export
                    const allCards = clonedDoc.querySelectorAll('.card-section');
                    allCards.forEach(card => {
                        if (card.classList.contains('export-card')) {
                            card.remove();
                        }
                    });
                    
                    // Basic body fixes
                    clonedDoc.body.style.margin = '0';
                    clonedDoc.body.style.padding = '0';
                    
                    // Ensure all tabs are visible in clone with proper spacing
                    const clonedTabDevices = clonedDoc.getElementById('tab-devices');
                    const clonedTabCves = clonedDoc.getElementById('tab-cves');
                    const clonedTabEvidence = clonedDoc.getElementById('tab-evidence');
                    
                    // Add section headers and spacing for each tab
                    if (clonedTabDevices) {
                        clonedTabDevices.classList.remove('hidden');
                        clonedTabDevices.style.display = 'block';
                        clonedTabDevices.style.marginBottom = '40px';
                        clonedTabDevices.style.paddingBottom = '30px';
                        clonedTabDevices.style.borderBottom = '2px solid #e5e7eb';
                        // Add header if not exists
                        if (!clonedTabDevices.querySelector('h3.pdf-section-header')) {
                            const header = clonedDoc.createElement('h3');
                            header.className = 'pdf-section-header';
                            header.textContent = 'Devices';
                            header.style.cssText = 'font-size: 1.5em; font-weight: 700; color: #1f2937; margin-bottom: 20px; padding-top: 20px;';
                            clonedTabDevices.insertBefore(header, clonedTabDevices.firstChild);
                        }
                    }
                    
                    if (clonedTabCves) {
                        clonedTabCves.classList.remove('hidden');
                        clonedTabCves.style.display = 'block';
                        clonedTabCves.style.marginBottom = '40px';
                        clonedTabCves.style.paddingBottom = '30px';
                        clonedTabCves.style.borderBottom = '2px solid #e5e7eb';
                        // Add header if not exists
                        if (!clonedTabCves.querySelector('h3.pdf-section-header')) {
                            const header = clonedDoc.createElement('h3');
                            header.className = 'pdf-section-header';
                            header.textContent = 'CVEs (Common Vulnerabilities and Exposures)';
                            header.style.cssText = 'font-size: 1.5em; font-weight: 700; color: #1f2937; margin-bottom: 20px; padding-top: 20px;';
                            clonedTabCves.insertBefore(header, clonedTabCves.firstChild);
                        }
                    }
                    
                    if (clonedTabEvidence) {
                        clonedTabEvidence.classList.remove('hidden');
                        clonedTabEvidence.style.display = 'block';
                        clonedTabEvidence.style.marginBottom = '20px';
                        clonedTabEvidence.style.paddingBottom = '20px';
                        // Add header if not exists
                        if (!clonedTabEvidence.querySelector('h3.pdf-section-header')) {
                            const header = clonedDoc.createElement('h3');
                            header.className = 'pdf-section-header';
                            header.textContent = 'Evidence Gallery';
                            header.style.cssText = 'font-size: 1.5em; font-weight: 700; color: #1f2937; margin-bottom: 20px; padding-top: 20px;';
                            clonedTabEvidence.insertBefore(header, clonedTabEvidence.firstChild);
                        }
                    }
                    
                    // Hide tab navigation buttons in PDF
                    const tabNavigation = clonedDoc.querySelector('.tab-navigation');
                    if (tabNavigation) {
                        tabNavigation.style.display = 'none';
                    }
                    
                    // Remove all hidden classes
                    const allHidden = clonedDoc.querySelectorAll('.hidden');
                    allHidden.forEach(el => {
                        el.classList.remove('hidden');
                        el.style.display = '';
                        el.style.visibility = 'visible';
                    });
                    
                    // Fix main container
                    const mainContainer = clonedDoc.getElementById('main-container');
                    if (mainContainer) {
                        mainContainer.style.margin = '0 auto';
                        mainContainer.style.padding = '20px';
                        mainContainer.style.maxWidth = '100%';
                        mainContainer.style.width = '100%';
                        mainContainer.style.boxSizing = 'border-box';
                    }
                    
                    // Fix report content
                    const reportContent = clonedDoc.getElementById('report-content');
                    if (reportContent) {
                        reportContent.style.padding = '20px';
                        reportContent.style.margin = '0';
                        reportContent.style.width = '100%';
                        reportContent.style.maxWidth = '100%';
                        reportContent.style.boxSizing = 'border-box';
                    }
                    
                    // Fix grid layout for PDF
                    const gridLayout = clonedDoc.querySelector('.grid-layout');
                    if (gridLayout) {
                        gridLayout.style.display = 'block';
                        gridLayout.style.width = '100%';
                        gridLayout.style.maxWidth = '100%';
                    }
                    
                    // Fix main column and side column for PDF
                    const mainColumn = clonedDoc.querySelector('.main-column');
                    if (mainColumn) {
                        mainColumn.style.width = '100%';
                        mainColumn.style.maxWidth = '100%';
                        mainColumn.style.marginBottom = '30px';
                    }
                    
                    const sideColumn = clonedDoc.querySelector('.side-column');
                    if (sideColumn) {
                        sideColumn.style.width = '100%';
                        sideColumn.style.maxWidth = '100%';
                    }
                    
                    // Ensure card sections have proper spacing
                    const cardSections = clonedDoc.querySelectorAll('.card-section');
                    cardSections.forEach(card => {
                        card.style.marginBottom = '30px';
                        card.style.pageBreakInside = 'avoid';
                        card.style.breakInside = 'avoid';
                    });
                    
                    // Ensure vulnerabilities card has proper structure
                    const vulnerabilitiesCard = clonedDoc.querySelector('.vulnerabilities-card');
                    if (vulnerabilitiesCard) {
                        vulnerabilitiesCard.style.overflow = 'visible';
                    }
                    
                    // Remove animations and ensure breakdown items are visible
                    const allElements = clonedDoc.querySelectorAll('*');
                    allElements.forEach(el => {
                        el.style.animation = 'none';
                        el.style.transition = 'none';
                        
                        // Ensure breakdown items are visible (they start with opacity: 0)
                        if (el.classList && el.classList.contains('breakdown-item')) {
                            el.style.opacity = '1';
                            el.style.visibility = 'visible';
                            el.style.display = 'block';
                        }
                    });
                    
                    // Specifically ensure breakdown details container is visible
                    const breakdownDetails = clonedDoc.getElementById('score-breakdown-details');
                    if (breakdownDetails) {
                        breakdownDetails.style.opacity = '1';
                        breakdownDetails.style.visibility = 'visible';
                        breakdownDetails.style.display = 'block';
                        breakdownDetails.style.height = 'auto';
                        breakdownDetails.style.minHeight = '100px';
                        const breakdownItems = breakdownDetails.querySelectorAll('.breakdown-item');
                        breakdownItems.forEach(item => {
                            item.style.opacity = '1';
                            item.style.visibility = 'visible';
                            item.style.display = 'block';
                            item.style.height = 'auto';
                            item.style.minHeight = '60px';
                        });
                        // Also ensure progress bars are visible
                        const progressBars = breakdownDetails.querySelectorAll('.progress-bar-fill');
                        progressBars.forEach(bar => {
                            bar.style.opacity = '1';
                            bar.style.visibility = 'visible';
                        });
                    }
                    
                    // Ensure the score breakdown card itself is visible
                    const scoreBreakdownCard = clonedDoc.querySelector('.score-breakdown-card');
                    if (scoreBreakdownCard) {
                        scoreBreakdownCard.style.opacity = '1';
                        scoreBreakdownCard.style.visibility = 'visible';
                        scoreBreakdownCard.style.display = 'block';
                    }
                }
            },
            jsPDF: { 
                unit: 'mm', 
                format: 'a4', 
                orientation: 'portrait'
            }
        }).from(reportElement).save().then(() => {
            // Restore original tab visibility
            if (wasDevicesHidden) tabDevices.classList.add('hidden');
            if (wasCvesHidden) tabCves.classList.add('hidden');
            if (wasEvidenceHidden) tabEvidence.classList.add('hidden');
            // Restore auto-destruct bar and export card visibility
            if (autoDestructBar && wasAutoDestructVisible) {
                autoDestructBar.style.display = '';
            }
            if (exportCard && wasExportCardVisible) {
                exportCard.style.display = '';
            }
            titleElement.remove();
            console.log("PDF generation complete.");
        }).catch(err => {
            // Restore original tab visibility on error
            if (wasDevicesHidden) tabDevices.classList.add('hidden');
            if (wasCvesHidden) tabCves.classList.add('hidden');
            if (wasEvidenceHidden) tabEvidence.classList.add('hidden');
            // Restore auto-destruct bar and export card visibility on error
            if (autoDestructBar && wasAutoDestructVisible) {
                autoDestructBar.style.display = '';
            }
            if (exportCard && wasExportCardVisible) {
                exportCard.style.display = '';
            }
            console.error("PDF generation error:", err);
            titleElement.remove();
            alert("Error generating PDF: " + err.message);
        });
    }, 500);
};

window.downloadCsv = () => {
    let csvContent = "data:text/csv;charset=utf-8,";
    const data = processedAuditData; 

    csvContent += `Field,Value\n`;
    csvContent += `Room,${auditData.metadata.room}\n`;
    csvContent += `Auditor,${auditData.metadata.auditor}\n`;
    csvContent += `Final Score,${data.final_score}\n\n`;

    csvContent += `Devices/Vulnerabilities,,,\n`;
    csvContent += `Device Name,Model,Firmware,CVE ID,CVSS,Severity,Description\n`;
    
    data.processedDevices.forEach(d => {
        if (d.cves.length > 0) {
            d.cves.forEach(cve => {
                const desc = cve.desc.replace(/,/g, ' ').replace(/\n/g, ' '); 
                csvContent += `${d.name || 'N/A'},${d.model || 'N/A'},${d.firmware || 'N/A'},${cve.id},${cve.cvss},${cve.severity},"${desc}"\n`;
            });
        } else {
            csvContent += `${d.name || 'N/A'},${d.model || 'N/A'},${d.firmware || 'N/A'},,,"No Issues"\n`;
        }
    });
    csvContent += `\n`;

    csvContent += `Physical Checks,\n`;
    csvContent += `Check Item,Status\n`;
    for (const [id, status] of Object.entries(auditData.checks)) {
        let label = id; 
        if(id.startsWith('custom')) {
            label = `Custom Check ${id.replace('custom-', '')}`;
        }
        
        csvContent += `"${label}",${status}\n`;
    }

    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", `Physisec_Audit_${auditData.metadata.room}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
};

// --- Initialization ---
document.addEventListener('DOMContentLoaded', () => {
    if (Object.keys(auditData.checks).length === 0 && auditData.devices.length === 0) {
        // Only redirect if there is absolutely no data
        console.error("No audit data found. Redirecting to start page.");
        window.location.href = 'main_page.html';
        return;
    }

    renderReportPage();
    startDestructTimer();
    
    const tabsContainer = document.getElementById('vulnerability-tabs');
    if (tabsContainer) {
        tabsContainer.addEventListener('click', (event) => {
            const button = event.target.closest('.tab-btn');
            if (button && button.dataset.tab) {
                switchTab(button);
            }
        });
    }
});