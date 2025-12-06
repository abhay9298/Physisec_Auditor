// Global State & Constants
const VIEWS = {
    LANDING: 'landing-page',
    AUDIT_FORM: 'audit-form',
};

// Data persistence simulation - will be stored in localStorage as a string
let auditData = {
    devices: [],
    checks: {
        // Fire Safety & Emergency Response (7 items)
        'extinguisher': 'na', 'fireAlarm': 'na', 'emergencyExit': 'na',
        'smokeDetector': 'na', 'sprinklerSystem': 'na', 'fireDrill': 'na', 'emergencyLighting': 'na',
        // Access Control & Perimeter Security (9 items)
        'doorLocks': 'na', 'accessPoints': 'na', 'badgeSystem': 'na', 'visitorLog': 'na',
        'windowSecurity': 'na', 'perimeterFence': 'na', 'motionSensors': 'na', 'intrusionAlarm': 'na', 'secureStorage': 'na',
        // Environmental & Infrastructure Security (6 items)
        'climateControl': 'na', 'powerBackup': 'na', 'waterLeak': 'na', 'cableManagement': 'na', 'serverRack': 'na', 'ventilation': 'na',
        // Surveillance & Monitoring (7 items)
        'cameraPlacement': 'na', 'cameraRecording': 'na', 'cameraMaintenance': 'na', 'nightVision': 'na', 'videoStorage': 'na', 'monitoringStation': 'na', 'cameraCoverageCheck': 'na',
        // Personnel & Access Management (7 items)
        'backgroundChecks': 'na', 'accessRevocation': 'na', 'securityTraining': 'na', 'idBadges': 'na', 'escortPolicy': 'na', 'accessLogs': 'na', 'securityPersonnel': 'na',
        // Physical Barriers & Deterrents (7 items)
        'bollards': 'na', 'reinforcedDoors': 'na', 'securityGlass': 'na', 'locksUpgrade': 'na', 'lighting': 'na', 'barrierGates': 'na', 'securitySignage': 'na',
        // Network & Physical Security (7 items)
        'firewallConfig': 'na', 'networkSegmentation': 'na', 'wifiSecurity': 'na', 'dataEncryption': 'na', 'vpnAccess': 'na', 'networkMonitoring': 'na', 'serverPhysical': 'na',
        // Incident Response & Procedures (6 items)
        'incidentPlan': 'na', 'emergencyContacts': 'na', 'responseTeam': 'na', 'communicationPlan': 'na', 'drillConducted': 'na', 'incidentLog': 'na',
        // Compliance & Documentation (6 items)
        'securityPolicy': 'na', 'auditTrail': 'na', 'complianceStandards': 'na', 'riskAssessment': 'na', 'documentation': 'na', 'vendorSecurity': 'na'
    },
    images: [],
    metadata: { room: "Untitled Room", auditor: "Auditor", timestamp: new Date().toISOString() },
    coverage: 'full', // Default for new input
    nextCheckId: 100, // Counter for dynamic checklist items
    apiKeys: {
        chatgpt: '',
        gemini: ''
    }
};

let currentState = VIEWS.LANDING;

// --- Initialization Functions ---

document.addEventListener('DOMContentLoaded', () => {
    // Attempt to load state from localStorage 
    const storedState = localStorage.getItem('physisecAuditData');
    if (storedState) {
        // Deep merge, preserving the current default structure if keys are missing
        const loadedData = JSON.parse(storedState);
        auditData.devices = loadedData.devices || [];
        
        // Merge checks: keep default checks and merge with loaded checks
        // This ensures all default checklist items are preserved
        const defaultChecks = { ...auditData.checks };
        const loadedChecks = loadedData.checks || {};
        auditData.checks = { ...defaultChecks, ...loadedChecks };
        
        auditData.images = loadedData.images || [];
        auditData.metadata = loadedData.metadata || auditData.metadata;
        auditData.coverage = loadedData.coverage || 'full';
        auditData.nextCheckId = loadedData.nextCheckId || 100;
        auditData.apiKeys = loadedData.apiKeys || { chatgpt: '', gemini: '' };

        // Ensure all visual elements are initialized to the loaded state
        updateVisualChecklistState();
    } else {
        // If no stored state, set initial state of visible checklist items
        initializeDefaultChecks();
    }

    // Initialize all event listeners and state
    setupEventListeners();
    updateChecklistCounts();
    renderDeviceList();
    renderImagePreview();
    
    // Set initial form values based on auditData
    document.getElementById('auditor-name').value = auditData.metadata.auditor;
    document.getElementById('room-location').value = auditData.metadata.room;
    document.getElementById('camera-coverage').value = auditData.coverage;
    
    // Load saved API keys
    if (auditData.apiKeys) {
        const chatgptInput = document.getElementById('chatgpt-api-key');
        const geminiInput = document.getElementById('gemini-api-key');
        if (chatgptInput && auditData.apiKeys.chatgpt) {
            chatgptInput.value = auditData.apiKeys.chatgpt;
        }
        if (geminiInput && auditData.apiKeys.gemini) {
            geminiInput.value = auditData.apiKeys.gemini;
        }
    }

    // Check if we need to immediately jump to the form 
    const initialView = localStorage.getItem('physisecCurrentView') || VIEWS.LANDING;
    
    // Ensure landing page is visible by default
    const landingPageEl = document.getElementById(VIEWS.LANDING);
    if (landingPageEl) {
        landingPageEl.classList.remove('hidden');
    }
    
    // Ensure Start Audit button is visible on landing page
    const startBtn = document.getElementById('header-start-audit-btn');
    if (startBtn && initialView === VIEWS.LANDING) {
        startBtn.style.display = 'inline-flex';
    }
    
    if (initialView === 'report-page') {
        // If coming from report, go back to form
        navigate(VIEWS.AUDIT_FORM);
    } else if (initialView === VIEWS.AUDIT_FORM && (auditData.devices.length > 0 || Object.keys(auditData.checks).some(k => auditData.checks[k] !== 'na'))) {
        // Only show audit form if there's existing data
        navigate(VIEWS.AUDIT_FORM);
    } else {
        // Default to landing page - ensure it's visible
        navigate(VIEWS.LANDING);
    }
});

const initializeDefaultChecks = () => {
    // This is crucial for accurately counting N/A items even if they're not explicitly marked
    document.querySelectorAll('.check-group-container').forEach(group => {
        const itemId = group.dataset.itemId;
        if (!auditData.checks.hasOwnProperty(itemId)) {
            auditData.checks[itemId] = 'na';
            group.dataset.state = 'na';
            group.querySelector('.na-btn').classList.add('active-na');
        }
    });
}


const setupEventListeners = () => {
    const modalContinueButton = document.getElementById('modal-continue-button');
    const analyzeButton = document.getElementById('analyze-button');
    const addDeviceButton = document.getElementById('add-device-button');
    const uploadZone = document.getElementById('upload-zone');
    const fileUploadInput = document.getElementById('file-upload');
    const checklistContainer = document.getElementById('checklist-container');
    const addCheckButton = document.getElementById('add-check-button');
    const commitNewCheckButton = document.getElementById('commit-new-check');
    const cancelNewCheckButton = document.getElementById('cancel-new-check');

    if (modalContinueButton) modalContinueButton.addEventListener('click', handleModalContinue);
    if (analyzeButton) analyzeButton.addEventListener('click', handleAnalyze);
    if (addDeviceButton) addDeviceButton.addEventListener('click', handleAddDevice);
    if (uploadZone) uploadZone.addEventListener('click', () => fileUploadInput.click());
    if (fileUploadInput) fileUploadInput.addEventListener('change', handleFileUpload);
    if (checklistContainer) checklistContainer.addEventListener('click', handleChecklistClick);
    
    if (addCheckButton) addCheckButton.addEventListener('click', () => {
        document.getElementById('custom-check-input').classList.remove('hidden');
        addCheckButton.classList.add('hidden');
        document.getElementById('new-check-label').value = ''; // Clear previous input
        document.getElementById('new-check-label').focus();
    });
    if (cancelNewCheckButton) cancelNewCheckButton.addEventListener('click', handleCancelNewCheck);
    if (commitNewCheckButton) commitNewCheckButton.addEventListener('click', handleCommitNewCheck);
    
    // API key save handlers
    const saveChatGPTButton = document.getElementById('save-chatgpt-api');
    const saveGeminiButton = document.getElementById('save-gemini-api');
    if (saveChatGPTButton) saveChatGPTButton.addEventListener('click', handleSaveChatGPTAPI);
    if (saveGeminiButton) saveGeminiButton.addEventListener('click', handleSaveGeminiAPI);
};

// --- Navigation & Persistance ---

const persistState = () => {
    localStorage.setItem('physisecAuditData', JSON.stringify(auditData));
    localStorage.setItem('physisecCurrentView', currentState);
};

window.navigate = (target) => {
    // Hide all view containers
    document.querySelectorAll('.view-container').forEach(el => {
        el.classList.add('hidden');
    });
    
    // Show the target view
    const targetElement = document.getElementById(target);
    if (targetElement) {
        targetElement.classList.remove('hidden');
    } else {
        // If target not found, default to landing page
        const landingPage = document.getElementById(VIEWS.LANDING);
        if (landingPage) {
            landingPage.classList.remove('hidden');
        }
    }
    
    currentState = target;
    const modal = document.getElementById('start-audit-modal');
    if (modal) {
        modal.classList.add('hidden'); 
    }
    
    updateHeaderVisibility(target);
    
    if (target === VIEWS.AUDIT_FORM) {
        document.getElementById('session-room').textContent = auditData.metadata.room;
        document.getElementById('session-auditor').textContent = auditData.metadata.auditor;
        updateVisualChecklistState(); 
        updateChecklistCounts();
    }
    
    persistState();
};

window.showModal = () => {
    const modal = document.getElementById('start-audit-modal');
    if (modal) modal.classList.remove('hidden');
}

const updateHeaderVisibility = (target) => {
    const startBtn = document.getElementById('header-start-audit-btn');
    if (startBtn) {
        if (target === VIEWS.LANDING) {
            startBtn.style.display = 'inline-flex';
        } else {
            startBtn.style.display = 'none';
        }
    }
}

// Handler for Modal Continue Button
const handleModalContinue = () => {
    const roomInput = document.getElementById('room-location');
    const auditorInput = document.getElementById('auditor-name');
    
    auditData.metadata.room = roomInput.value || 'Untitled Room';
    auditData.metadata.auditor = auditorInput.value || 'Auditor';
    navigate(VIEWS.AUDIT_FORM);
};

// Handler for Analyze Button - Redirects to Report Page
const handleAnalyze = () => {
    auditData.coverage = document.getElementById('camera-coverage').value;
    auditData.metadata.timestamp = new Date().toISOString();
    
    persistState();
    
    // Redirects to the separate report page HTML file
    window.location.href = 'report_page.html'; 
};

// --- API Functions for CVE Lookup ---

const searchCVEsForDevice = async (device) => {
    // Check if any API key is available
    if (!auditData.apiKeys || (!auditData.apiKeys.chatgpt && !auditData.apiKeys.gemini)) {
        console.log('No API key configured. Skipping CVE lookup.');
        return;
    }

    // Mark device as searching for CVEs
    const deviceIndex = auditData.devices.findIndex(d => 
        d.name === device.name && d.model === device.model && d.firmware === device.firmware
    );
    if (deviceIndex !== -1) {
        auditData.devices[deviceIndex].searchingCVEs = true;
        renderDeviceList();
    }

    // Try ChatGPT first, then Gemini
    let cves = [];
    let errorMessage = null;
    
    if (auditData.apiKeys.chatgpt) {
        try {
            cves = await searchCVEsWithChatGPT(device);
        } catch (error) {
            console.error('ChatGPT API error:', error);
            errorMessage = error.message;
            // Fallback to Gemini if available
            if (auditData.apiKeys.gemini) {
                try {
                    cves = await searchCVEsWithGemini(device);
                    errorMessage = null; // Clear error if Gemini succeeds
                } catch (geminiError) {
                    console.error('Gemini API error:', geminiError);
                    errorMessage = geminiError.message;
                }
            }
        }
    } else if (auditData.apiKeys.gemini) {
        try {
            cves = await searchCVEsWithGemini(device);
        } catch (error) {
            console.error('Gemini API error:', error);
            errorMessage = error.message;
        }
    }

    // Update device with found CVEs or error
    if (deviceIndex !== -1) {
        auditData.devices[deviceIndex].searchingCVEs = false;
        auditData.devices[deviceIndex].cves = cves;
        if (errorMessage) {
            auditData.devices[deviceIndex].cveError = errorMessage;
        } else {
            // Clear any previous error if search succeeded
            delete auditData.devices[deviceIndex].cveError;
        }
        persistState();
        renderDeviceList(); // Update UI to show CVEs found or error
        
        // Log results for debugging
        if (cves.length === 0 && !errorMessage) {
            console.warn(`No CVEs found for device: ${device.name} (${device.model})`);
        }
    }
};

const searchCVEsWithChatGPT = async (device) => {
    const apiKey = auditData.apiKeys.chatgpt;
    if (!apiKey) return [];

    const prompt = `You are a cybersecurity expert. Search for Common Vulnerabilities and Exposures (CVEs) for this device:

Device Name/Brand: ${device.name}
Model/Series: ${device.model}
Firmware Version: ${device.firmware}

CRITICAL REQUIREMENT: Search the National Vulnerability Database (NVD) at nvd.nist.gov, CVE database at cve.mitre.org, and manufacturer security advisories for vulnerabilities affecting:
- ONLY the EXACT model series: "${device.model}"
- This firmware version: "${device.firmware}" and related firmware versions for THIS SPECIFIC MODEL

DO NOT include CVEs for:
- Other models from the same manufacturer/brand (${device.name})
- Different product lines or series
- Similar but different model numbers

ONLY return CVEs that specifically mention or affect the exact model series "${device.model}". If a CVE affects multiple models but does not specifically list "${device.model}", do NOT include it.

Search for:
- Default credentials vulnerabilities
- Authentication bypass issues
- Remote code execution vulnerabilities
- Buffer overflow vulnerabilities
- SQL injection vulnerabilities
- Cross-site scripting (XSS) vulnerabilities
- Denial of service vulnerabilities
- Any other security flaws

Return a JSON array with ALL found CVEs. If you find vulnerabilities, you MUST return them. Do not return an empty array if vulnerabilities exist.

Format:
[
  {
    "id": "CVE-YYYY-XXXXX",
    "cvss": 7.5,
    "severity": "HIGH",
    "desc": "Detailed description of the vulnerability"
  }
]

Severity: "CRITICAL" (9.0-10.0), "HIGH" (7.0-8.9), "MEDIUM" (4.0-6.9), "LOW" (0.1-3.9)
Return ONLY valid JSON array, no markdown, no code blocks, no explanations. If no CVEs found after thorough search, return [].`;

    try {
        const response = await fetch('https://api.openai.com/v1/chat/completions', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${apiKey}`
            },
            body: JSON.stringify({
                model: 'gpt-4',
                messages: [
                    {
                        role: 'system',
                        content: 'You are a cybersecurity expert specializing in CVE research. Always search thoroughly and return all found vulnerabilities. Return only valid JSON arrays with CVE information.'
                    },
                    {
                        role: 'user',
                        content: prompt
                    }
                ],
                temperature: 0.2,
                max_tokens: 3000
            })
        });

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            console.error('OpenAI API response error:', response.status, errorData);
            throw new Error(`OpenAI API error: ${response.status} - ${errorData.error?.message || 'Unknown error'}`);
        }

        const data = await response.json();
        if (!data.choices || !data.choices[0] || !data.choices[0].message) {
            console.error('Unexpected OpenAI API response structure:', data);
            throw new Error('Invalid response format from OpenAI API');
        }

        const content = data.choices[0].message.content.trim();
        console.log('ChatGPT API raw response:', content);
        
        // Try to extract JSON - handle markdown code blocks
        let jsonMatch = content.match(/```json\s*(\[[\s\S]*?\])\s*```/);
        if (!jsonMatch) {
            jsonMatch = content.match(/```\s*(\[[\s\S]*?\])\s*```/);
        }
        if (!jsonMatch) {
            jsonMatch = content.match(/\[[\s\S]*\]/);
        }
        
        if (jsonMatch) {
            try {
                const jsonStr = jsonMatch[1] || jsonMatch[0];
                const cves = JSON.parse(jsonStr);
                if (Array.isArray(cves) && cves.length > 0) {
                    console.log('Found CVEs:', cves);
                    return cves;
                } else {
                    console.log('API returned empty CVE array');
                }
            } catch (parseError) {
                console.error('JSON parsing error:', parseError, 'Content:', jsonMatch[0]);
                throw new Error(`Failed to parse CVE data: ${parseError.message}`);
            }
        } else {
            console.warn('No JSON array found in response. Full response:', content);
            throw new Error('No valid JSON array found in API response');
        }
        
        return [];
    } catch (error) {
        console.error('Error calling ChatGPT API:', error);
        throw error;
    }
};

const searchCVEsWithGemini = async (device) => {
    const apiKey = auditData.apiKeys.gemini;
    if (!apiKey) return [];

    const prompt = `You are a cybersecurity expert. Search for Common Vulnerabilities and Exposures (CVEs) for this device:

Device Name/Brand: ${device.name}
Model/Series: ${device.model}
Firmware Version: ${device.firmware}

CRITICAL REQUIREMENT: Search the National Vulnerability Database (NVD) at nvd.nist.gov, CVE database at cve.mitre.org, and manufacturer security advisories for vulnerabilities affecting:
- ONLY the EXACT model series: "${device.model}"
- This firmware version: "${device.firmware}" and related firmware versions for THIS SPECIFIC MODEL

DO NOT include CVEs for:
- Other models from the same manufacturer/brand (${device.name})
- Different product lines or series
- Similar but different model numbers

ONLY return CVEs that specifically mention or affect the exact model series "${device.model}". If a CVE affects multiple models but does not specifically list "${device.model}", do NOT include it.

Search for:
- Default credentials vulnerabilities
- Authentication bypass issues
- Remote code execution vulnerabilities
- Buffer overflow vulnerabilities
- SQL injection vulnerabilities
- Cross-site scripting (XSS) vulnerabilities
- Denial of service vulnerabilities
- Any other security flaws

Return a JSON array with ALL found CVEs. If you find vulnerabilities, you MUST return them. Do not return an empty array if vulnerabilities exist.

Format:
[
  {
    "id": "CVE-YYYY-XXXXX",
    "cvss": 7.5,
    "severity": "HIGH",
    "desc": "Detailed description of the vulnerability"
  }
]

Severity: "CRITICAL" (9.0-10.0), "HIGH" (7.0-8.9), "MEDIUM" (4.0-6.9), "LOW" (0.1-3.9)
Return ONLY valid JSON array, no markdown, no code blocks, no explanations. If no CVEs found after thorough search, return [].`;

    try {
        // Try the latest Gemini model first, fallback to older version
        let response;
        try {
            response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${apiKey}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    contents: [{
                        parts: [{
                            text: prompt
                        }]
                    }],
                    generationConfig: {
                        temperature: 0.2,
                        maxOutputTokens: 3000,
                        topP: 0.95,
                        topK: 40
                    }
                })
            });
        } catch (e) {
            // Fallback to gemini-pro if gemini-1.5-pro is not available
            response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key=${apiKey}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    contents: [{
                        parts: [{
                            text: prompt
                        }]
                    }],
                    generationConfig: {
                        temperature: 0.2,
                        maxOutputTokens: 3000
                    }
                })
            });
        }

        if (!response.ok) {
            const errorText = await response.text();
            console.error('Gemini API response error:', response.status, errorText);
            throw new Error(`Gemini API error: ${response.status} - ${errorText}`);
        }

        const data = await response.json();
        
        // Check for API errors in response
        if (data.error) {
            console.error('Gemini API error in response:', data.error);
            throw new Error(`Gemini API error: ${data.error.message || 'Unknown error'}`);
        }

        if (!data.candidates || !data.candidates[0] || !data.candidates[0].content) {
            console.error('Unexpected Gemini API response structure:', data);
            throw new Error('Invalid response format from Gemini API');
        }

        const content = data.candidates[0].content.parts[0].text.trim();
        console.log('Gemini API raw response:', content);
        
        // Try to extract JSON - handle markdown code blocks
        let jsonMatch = content.match(/```json\s*(\[[\s\S]*?\])\s*```/);
        if (!jsonMatch) {
            jsonMatch = content.match(/```\s*(\[[\s\S]*?\])\s*```/);
        }
        if (!jsonMatch) {
            jsonMatch = content.match(/\[[\s\S]*\]/);
        }
        
        if (jsonMatch) {
            try {
                const jsonStr = jsonMatch[1] || jsonMatch[0];
                const cves = JSON.parse(jsonStr);
                if (Array.isArray(cves) && cves.length > 0) {
                    console.log('Found CVEs:', cves);
                    return cves;
                } else {
                    console.log('API returned empty CVE array');
                }
            } catch (parseError) {
                console.error('JSON parsing error:', parseError, 'Content:', jsonMatch[0]);
                throw new Error(`Failed to parse CVE data: ${parseError.message}`);
            }
        } else {
            console.warn('No JSON array found in response. Full response:', content);
            throw new Error('No valid JSON array found in API response');
        }
        
        return [];
    } catch (error) {
        console.error('Error calling Gemini API:', error);
        throw error;
    }
};

// --- Device Management Logic ---

const handleAddDevice = async () => {
    const name = document.getElementById('device-name');
    const model = document.getElementById('device-model');
    const firmware = document.getElementById('firmware-version');

    if (name.value.trim() && model.value.trim() && firmware.value.trim()) {
        const deviceData = { 
            name: name.value.trim(), 
            model: model.value.trim(), 
            firmware: firmware.value.trim(),
            cves: [] // Initialize empty CVE array
        };
        
        auditData.devices.push(deviceData);
        name.value = '';
        model.value = '';
        firmware.value = '';
        renderDeviceList();
        persistState();
        
        // Search for CVEs using API if available
        await searchCVEsForDevice(deviceData);
    } else {
        alert('Please enter Device Name, Model, and Firmware Version.');
    }
};

window.removeDevice = (index) => {
    auditData.devices.splice(index, 1);
    renderDeviceList();
    persistState();
};

const renderDeviceList = () => {
    const listBody = auditData.devices.map((device, index) => {
        let cveStatus = '';
        let retryButton = '';
        
        if (device.searchingCVEs) {
            cveStatus = '<span class="cve-status searching">Searching for CVEs...</span>';
        } else if (device.cveError) {
            const shortError = device.cveError.length > 50 ? device.cveError.substring(0, 50) + '...' : device.cveError;
            cveStatus = `<span class="cve-status error" title="${device.cveError}">CVE search failed: ${shortError}</span>`;
            retryButton = `<button onclick="retryCVESearch(${index})" class="btn blue-btn small" style="margin-left: 10px; padding: 4px 8px; font-size: 0.8em;">Retry</button>`;
        } else if (device.cves && device.cves.length > 0) {
            cveStatus = `<span class="cve-status found">${device.cves.length} CVE${device.cves.length !== 1 ? 's' : ''} found</span>`;
        } else if (auditData.apiKeys && (auditData.apiKeys.chatgpt || auditData.apiKeys.gemini)) {
            cveStatus = '<span class="cve-status no-cves">No CVEs found</span>';
            retryButton = `<button onclick="retryCVESearch(${index})" class="btn blue-btn small" style="margin-left: 10px; padding: 4px 8px; font-size: 0.8em;">Retry Search</button>`;
        }
        
        return `
        <div class="device-item">
            <div style="flex: 1;">
                <p class="name">${device.name}</p>
                <p class="model-firmware">Model: ${device.model} | Firmware: ${device.firmware}</p>
                <div style="display: flex; align-items: center; margin-top: 5px;">
                    ${cveStatus}
                    ${retryButton}
                </div>
            </div>
            <button onclick="removeDevice(${index})" title="Remove Device">
                &times;
            </button>
        </div>
    `;
    }).join('');

    const deviceListHeader = document.querySelector('.device-list-header');
    if (deviceListHeader) deviceListHeader.textContent = `Devices to Analyze (${auditData.devices.length})`;
    document.getElementById('device-list').innerHTML = `
        <h4 class="device-list-header">Devices to Analyze (${auditData.devices.length})</h4>
        ${listBody}
    `;
};

// Retry CVE search for a specific device
window.retryCVESearch = async (deviceIndex) => {
    if (deviceIndex >= 0 && deviceIndex < auditData.devices.length) {
        const device = auditData.devices[deviceIndex];
        // Clear previous error and CVEs
        delete device.cveError;
        device.cves = [];
        persistState();
        renderDeviceList();
        // Trigger new search
        await searchCVEsForDevice(device);
    }
};

// --- Image Management Logic ---

const handleFileUpload = (event) => {
    Array.from(event.target.files).forEach(file => {
        const reader = new FileReader();
        reader.onload = (e) => {
            auditData.images.push(e.target.result);
            renderImagePreview();
            persistState();
        };
        reader.readAsDataURL(file);
    });
};

window.removeImage = (index) => {
    auditData.images.splice(index, 1);
    renderImagePreview();
    persistState();
};

const renderImagePreview = () => {
    const previewContainer = document.getElementById('image-preview');
    if (!previewContainer) return;

    previewContainer.innerHTML = auditData.images.map((imgUrl, index) => `
        <div class="image-wrapper">
            <img src="${imgUrl}" alt="Audit evidence ${index + 1}">
            <button onclick="removeImage(${index})" class="remove-image-btn" title="Remove image">&times;</button>
        </div>
    `).join('');
};

// --- Checklist Logic ---

window.toggleCategory = (id, iconId) => {
    const element = document.getElementById(id);
    const icon = document.getElementById(iconId);
    
    element.classList.toggle('hidden');
    if (icon) {
        // Toggle arrow direction
        icon.innerHTML = element.classList.contains('hidden') ? '&#9660;' : '&#9650;';
    }
};

const handleChecklistClick = (event) => {
    const button = event.target.closest('.check-btn');
    if (!button) return;

    const group = button.closest('.check-group-container');
    const itemId = group.dataset.itemId;
    const newState = button.dataset.state;
    
    // Update data
    auditData.checks[itemId] = newState;

    // Update visual state
    updateVisualChecklistState(group, newState);
    
    // Update counts
    updateChecklistCounts();
    persistState();
};

const updateVisualChecklistState = (targetGroup = null, newState = null) => {
    const groups = targetGroup ? [targetGroup] : document.querySelectorAll('.check-group-container');
    
    groups.forEach(group => {
        const itemId = group.dataset.itemId;
        const state = newState || auditData.checks[itemId] || 'na'; // Use stored state or default
        
        // Remove all active classes first
        group.querySelectorAll('.check-btn').forEach(btn => {
            btn.classList.remove('active-pass', 'active-fail', 'active-na');
        });
        
        // Find the button matching the state and activate it
        const activeButton = group.querySelector(`[data-state="${state}"]`);
        if (activeButton) {
            activeButton.classList.add(`active-${state}`);
        }
    });
};

window.updateChecklistCounts = () => {
    let pass = 0, fail = 0;
    
    // Calculate pass/fail based on actual recorded state
    Object.values(auditData.checks).forEach(state => {
        if (state === 'pass') pass++;
        else if (state === 'fail') fail++;
    });

    const totalItems = Object.keys(auditData.checks).length;
    const na = totalItems - pass - fail;

    document.getElementById('pass-count').textContent = pass;
    document.getElementById('fail-count').textContent = fail;
    document.getElementById('na-count').textContent = na;
};

// Custom Check Logic
window.removeCheckItem = (button) => {
    const itemDiv = button.closest('.check-item');
    const groupContainer = itemDiv.querySelector('.check-group-container');
    const itemId = groupContainer ? groupContainer.dataset.itemId : null;
    
    // Check if this is a custom check item
    const isCustomCheck = itemDiv.classList.contains('dynamic-check-item');
    const parentList = itemDiv.closest('.checklist-items');
    
    if (itemId) {
        delete auditData.checks[itemId];
    }
    itemDiv.remove();
    
    // Update custom checks count if it's in the custom checks category
    if (isCustomCheck && parentList && parentList.id === 'custom-checks-items') {
        const customChecks = parentList.querySelectorAll('.check-item').length;
        const countElement = document.getElementById('custom-checks-count');
        if (countElement) {
            countElement.textContent = `${customChecks} item${customChecks !== 1 ? 's' : ''}`;
        }
    }
    
    updateChecklistCounts();
    persistState();
};

const handleCancelNewCheck = () => {
    document.getElementById('custom-check-input').classList.add('hidden');
    document.getElementById('add-check-button').classList.remove('hidden');
    document.getElementById('new-check-label').value = '';
};

const handleCommitNewCheck = () => {
    const labelInput = document.getElementById('new-check-label');
    const label = labelInput.value.trim();
    if (!label) {
        alert('Please enter a check item description.');
        return;
    }

    const itemId = `custom-${auditData.nextCheckId++}`;
    
    // Create or get custom checks category
    let customChecksList = document.getElementById('custom-checks-items');
    if (!customChecksList) {
        // Create custom checks category if it doesn't exist
        const checklistContainer = document.getElementById('checklist-container');
        const customCategoryHtml = `
            <div class="category-section">
                <button class="category-toggle" onclick="toggleCategory('custom-checks-items', 'custom-checks-icon')">
                    <span>Custom Security Checks</span>
                    <span class="item-count" id="custom-checks-count">0 items</span>
                    <span class="toggle-icon" id="custom-checks-icon">&#9660;</span>
                </button>
                <div id="custom-checks-items" class="checklist-items"></div>
            </div>
        `;
        checklistContainer.insertAdjacentHTML('beforeend', customCategoryHtml);
        customChecksList = document.getElementById('custom-checks-items');
    }
    
    const newItemHtml = `
        <div class="check-item dynamic-check-item">
            <span>${label} <span class="custom-tag">(Custom)</span></span>
            <div class="check-group-container" data-item-id="${itemId}" data-state="na">
                <button class="check-btn pass-btn" data-state="pass" title="Pass">&#x2713;</button>
                <button class="check-btn fail-btn" data-state="fail" title="Fail">&#x2715;</button>
                <button class="check-btn na-btn active-na" data-state="na" title="Not Applicable">-</button>
            </div>
            <button onclick="removeCheckItem(this)" class="remove-check-btn" title="Remove Check">&times;</button>
        </div>
    `;
    
    customChecksList.insertAdjacentHTML('beforeend', newItemHtml);
    
    // Update custom checks count
    const customChecks = customChecksList.querySelectorAll('.check-item').length;
    const countElement = document.getElementById('custom-checks-count');
    if (countElement) {
        countElement.textContent = `${customChecks} item${customChecks !== 1 ? 's' : ''}`;
    }
    
    auditData.checks[itemId] = 'na'; 
    updateVisualChecklistState(); // To correctly set 'active-na' class
    updateChecklistCounts();
    labelInput.value = '';
    handleCancelNewCheck(); // Hide the input field
    persistState();
};

// API Key Management Functions
const handleSaveChatGPTAPI = () => {
    const apiKeyInput = document.getElementById('chatgpt-api-key');
    if (apiKeyInput) {
        auditData.apiKeys.chatgpt = apiKeyInput.value.trim();
        persistState();
        alert('ChatGPT API key saved successfully!');
    }
};

const handleSaveGeminiAPI = () => {
    const apiKeyInput = document.getElementById('gemini-api-key');
    if (apiKeyInput) {
        auditData.apiKeys.gemini = apiKeyInput.value.trim();
        persistState();
        alert('Gemini API key saved successfully!');
    }
};