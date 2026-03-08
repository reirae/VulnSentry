const KALI_SERVER = "http://47.131.83.34:8000/scan";
const CACHE_DURATION = 60 * 60 * 1000; // 1 hour in milliseconds

// Get cached data if valid
async function getCachedData(cacheKey) {
    const result = await chrome.storage.local.get(cacheKey);
    if (!result[cacheKey]) return null;

    const cached = result[cacheKey];
    const now = Date.now();
    
    // Check if cache is still valid
    if (now - cached.timestamp < CACHE_DURATION) {
        return cached;
    }
    
    // Cache expired, remove it
    await chrome.storage.local.remove(cacheKey);
    return null;
}

// Save data to cache
async function saveCacheData(cacheKey, data, log) {
    await chrome.storage.local.set({
        [cacheKey]: {
            timestamp: Date.now(),
            data: data,
            log: log
        }
    });
}

// Display cached or fresh results
function displayResults(data, log, statusDiv, logDiv) {
    statusDiv.innerHTML = "";
    logDiv.textContent = log;

    if (data.length === 0) {
        statusDiv.innerHTML = "<li>No technologies detected.</li>";
        return;
    }

    data.forEach(item => {
        const li = document.createElement('li');
        li.style.cssText = "margin-bottom:15px; border-bottom:1px solid #eee; padding-bottom:10px;";

        // CVE section
        let cveHtml = "";
        if (item.cves && item.cves.length > 0) {
            cveHtml = `<div style="margin-top:8px;">
                <strong style="color:#d32f2f; font-size:12px;">[!] ${item.cves.length} Vulnerabilities:</strong>
                <ul style="padding-left:15px; margin-top:5px; font-size:11px; color:#444;">
                    ${item.cves.map(cve => `
                        <li style="margin-bottom:4px;">
                            <a href="${cve.link}" target="_blank" style="color:#0056b3; font-weight:bold; text-decoration:none;">
                                ${cve.id}
                            </a>
                            <div style="color:#666;">${cve.desc.substring(0, 80)}...</div>
                        </li>
                    `).join('')}
                </ul>
            </div>`;
        } else {
            cveHtml = `<div style="color:green; font-size:12px; margin-top:5px;">[OK] No immediate CVEs found.</div>`;
        }

        // Dorks section
        let dorksHtml = "";
        if (item.dorks && item.dorks.length > 0) {
            dorksHtml = `<div style="margin-top:6px;">
                <strong style="color:#e65100; font-size:12px;">[G] ${item.dorks.length} Google Dork(s):</strong>
                <ul style="padding-left:15px; margin-top:4px; font-size:11px; color:#444;">
                    ${item.dorks.map(d => {
                        const encoded = encodeURIComponent(d.query);
                        const link = `https://www.google.com/search?q=${encoded}`;
                        const tag = d.type === 'ver' ? '[STRICT]' : '[GENERIC]';
                        return `<li style="margin-bottom:4px;">
                            ${tag} <a href="${link}" target="_blank" style="color:#0056b3; text-decoration:none;">${d.desc}</a>
                        </li>`;
                    }).join('')}
                </ul>
            </div>`;
        }

        li.innerHTML = `
            <div style="font-size:14px; display:flex; justify-content:space-between; align-items:center;">
                <strong>${item.technology}</strong>
                <span style="background:#eee; padding:2px 6px; border-radius:4px; font-size:11px; font-family:monospace;">
                    v${item.version}
                </span>
            </div>
            ${cveHtml}
            ${dorksHtml}
        `;
        statusDiv.appendChild(li);
    });
}

// Update cache info display
function updateCacheInfo(timestamp, cacheInfo) {
    const age = Date.now() - timestamp;
    const minutes = Math.floor(age / 60000);
    const timeLeft = 60 - minutes;
    
    if (minutes < 1) {
        cacheInfo.textContent = `Cached: just now (expires in ${timeLeft} min)`;
    } else if (minutes === 1) {
        cacheInfo.textContent = `Cached: 1 minute ago (expires in ${timeLeft} min)`;
    } else {
        cacheInfo.textContent = `Cached: ${minutes} minutes ago (expires in ${timeLeft} min)`;
    }
    cacheInfo.style.display = 'block';
}

document.addEventListener('DOMContentLoaded', async () => {
    const statusDiv = document.getElementById('tech-list');
    const logDiv = document.getElementById('scan-log');
    const toggleBtn = document.getElementById('toggle-log');
    const rescanBtn = document.getElementById('rescan-btn');
    const cacheInfo = document.getElementById('cache-info');
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

    const hostname = new URL(tab.url).hostname;
    const cacheKey = `scan_cache_${hostname}`;
    document.getElementById('site-url').textContent = hostname;

    // Wire up the log toggle button
    toggleBtn.addEventListener('click', () => {
        const isHidden = logDiv.style.display === 'none' || logDiv.style.display === '';
        logDiv.style.display = isHidden ? 'block' : 'none';
        toggleBtn.textContent = isHidden ? '- Hide scan log' : '+ Show scan log';
    });

    // Perform scan function
    async function performScan(forceRescan = false) {
        // Show loading state
        statusDiv.innerHTML = `<li style="text-align:center; padding:10px; color:#888;">Waiting for results...</li>`;
        logDiv.textContent = "Starting scan...\n";
        cacheInfo.style.display = 'none';

        let scanLog = "Starting scan...\n";
        let scanData = [];

        try {
            // SSE requires a GET or a fetch with ReadableStream — we use fetch + ReadableStream
            const response = await fetch(KALI_SERVER, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: tab.url })
            });

            if (!response.ok) throw new Error(`Server error: ${response.status}`);

            const reader = response.body.getReader();
            const decoder = new TextDecoder();
            let buffer = "";

            while (true) {
                const { done, value } = await reader.read();
                if (done) break;

                buffer += decoder.decode(value, { stream: true });

                // SSE messages are separated by "\n\n"
                const parts = buffer.split("\n\n");
                buffer = parts.pop(); // keep incomplete last chunk

                for (const part of parts) {
                    if (!part.startsWith("data: ")) continue;
                    let event;
                    try {
                        event = JSON.parse(part.slice(6)); // strip "data: "
                    } catch { continue; }

                    if (event.type === "log") {
                        // Append log line to the log panel
                        const logMessage = event.message + "\n";
                        scanLog += logMessage;
                        logDiv.textContent += logMessage;
                        logDiv.scrollTop = logDiv.scrollHeight; // auto-scroll

                    } else if (event.type === "done") {
                        scanData = event.data;
                        displayResults(scanData, scanLog, statusDiv, logDiv);
                        
                        // Save to cache
                        await saveCacheData(cacheKey, scanData, scanLog);
                        updateCacheInfo(Date.now(), cacheInfo);
                    }
                }
            }

        } catch (error) {
            console.error(error);
            statusDiv.innerHTML = `
                <li style="color:red; font-size:12px;">
                    <strong>[X] Connection Failed!</strong><br>
                    1. Is server.py running on EC2?<br>
                    2. Is the IP correct? (${KALI_SERVER})<br>
                    3. Error: ${error.message}
                </li>`;
        }
    }

    // Wire up the rescan button
    rescanBtn.addEventListener('click', async () => {
        rescanBtn.disabled = true;
        rescanBtn.textContent = 'Rescanning...';
        await performScan(true);
        rescanBtn.disabled = false;
        rescanBtn.textContent = '🔄 Rescan';
    });

    // Check cache first
    const cachedData = await getCachedData(cacheKey);
    if (cachedData) {
        displayResults(cachedData.data, cachedData.log, statusDiv, logDiv);
        updateCacheInfo(cachedData.timestamp, cacheInfo);
        return;
    }

    // No cache, perform initial scan
    await performScan(false);
});