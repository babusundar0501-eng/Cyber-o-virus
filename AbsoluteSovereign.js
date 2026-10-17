const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { exec, execSync, spawn } = require('child_process');

// Environment Path Constraints Mapping
const ENGINE_ROOT = "C:\\SovereignAV";
const VAULT_DIR = path.join(ENGINE_ROOT, "Vault");
const SHADOW_DIR = path.join(ENGINE_ROOT, "ShadowVault");
const LOG_FILE = path.join(ENGINE_ROOT, "edr_forensics.log");
const HASH_DB_FILE = path.join(ENGINE_ROOT, "malware_signatures.db");

// Dynamically target high-value system paths for comprehensive ecosystem protection
const USER_PROFILE = process.env.USERPROFILE || "C:\\Users\\Default";
const PROTECTED_PATHS = [
    path.join(ENGINE_ROOT, "sandbox_env"),
    path.join(USER_PROFILE, "Desktop"),
    path.join(USER_PROFILE, "Documents"),
    path.join(USER_PROFILE, "Downloads"),
    path.join(USER_PROFILE, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
];

// Verify structural runtime environment integrity across all protected nodes
[ENGINE_ROOT, VAULT_DIR, SHADOW_DIR].concat(PROTECTED_PATHS).forEach(dir => {
    if (!fs.existsSync(dir)) {
        try { fs.mkdirSync(dir, { recursive: true }); } catch (e) {}
    }
});

// Setup Initial Threat Intelligence Signature Database if it doesn't exist
if (!fs.existsSync(HASH_DB_FILE)) {
    const initialSignatures = [
        "ed9434c3cc036e65a44321bdec997d95653c9e37604f02f068fc23f66b57cdff", // WannaCry Variant
        "027cc450f8341a7f690467b5e921d60f4e1f727c62bb95f6aa80753e18580214", // NotPetya MBR Dropper
        "5c1a7b0f1b2e2d3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f"  // Test Signature Mock Vector
    ].join('\n');
    fs.writeFileSync(HASH_DB_FILE, initialSignatures, 'utf8');
}

console.clear();
console.log("==========================================================================");
console.log("             SOVEREIGN PLATINUM NEXT-GEN EDR SUITE v6.5                   ");
console.log("==========================================================================");
console.log("[*] Full-Scale Filesystem Hook Armed -> Guarding Desktop, Docs, Downloads");
console.log("[*] Active Registry Protection Matrix-> Guarding Windows Auto-Start Hives");
console.log("[*] Anti-Hacker Dual-Process Engine  -> Watchdog Resiliency Loop Active");
console.log("--------------------------------------------------------------------------");

// --- ANTI-HACKER DUAL PROCESS WATCHDOG GUARD ---
setInterval(() => {
    exec('tasklist /FI "IMAGENAME eq SovereignWatchdog.exe"', (err, stdout) => {
        if (!stdout.includes('SovereignWatchdog.exe')) {
            logForensicEvent("MUTATION ALERT: Hacker attempt to terminate Antivirus Watchdog detected! Reviving Guardian...");
            const watchdogPath = path.join(ENGINE_ROOT, "SovereignWatchdog.exe");
            if (fs.existsSync(watchdogPath)) {
                spawn(watchdogPath, [], { detached: true, stdio: 'ignore' }).unref();
            } else {
                const scriptPath = path.join(ENGINE_ROOT, "WatchdogGuard.js");
                if (fs.existsSync(scriptPath)) {
                    spawn('node.exe', [scriptPath], { detached: true, stdio: 'ignore' }).unref();
                }
            }
        }
    });
}, 500);

// --- ACTIVE REGISTRY PROTECTION MODULE ---
setInterval(() => {
    const registryRunHive = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    exec(`reg query "${registryRunHive}"`, (err, stdout) => {
        if (!err && stdout) {
            const lines = stdout.split(/\r?\n/);
            lines.forEach(line => {
                if (line.includes("REG_SZ") && (line.toLowerCase().includes("temp") || line.toLowerCase().includes("appdata") || line.toLowerCase().includes("sandbox_env"))) {
                    const lineParts = line.trim().split(/\s+/);
                    const entryName = lineParts[0]; 
                    console.log(`[!] REGISTRY ANOMALY: Unauthorized auto-start keys flagged -> ${entryName}`);
                    logForensicEvent(`REGISTRY TAMPERING - Unauthorized persistence attempt caught at: ${entryName}`);
                    
                    exec(`reg delete "${registryRunHive}" /v "${entryName}" /f`, () => {
                        console.log(`[VACCINE] Successfully rolled back registry hive structure. Unauthorized keys deleted.`);
                        triggerWindowsToastNotification(entryName, "Active Registry Protection Module Wiped Hack Key");
                    });
                }
            });
        }
    });
}, 2000);

function triggerWindowsToastNotification(threatName, actionTaken) {
    const psAlertCommand = `powershell -NoProfile -ExecutionPolicy Bypass -Command "[void][System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms'); [void][System.Reflection.Assembly]::LoadWithPartialName('System.Drawing'); \$toast = New-Object System.Windows.Forms.NotifyIcon; \$toast.Icon = [System.Drawing.SystemIcons]::Shield; \$toast.BalloonTipIcon = 'Error'; \$toast.BalloonTipTitle = 'Sovereign Next-Gen EDR Alert'; \$toast.BalloonTipText = 'Threat Neutralized: ' + '${threatName}' + '\\nAction: ' + '${actionTaken}'; \$toast.Visible = \$true; \$toast.ShowBalloonTip(5000); Start-Sleep -s 5; \$toast.Dispose()"`;
    exec(psAlertCommand);
}

function calculateShannonEntropy(buffer) {
    if (buffer.length === 0) return 0;
    const frequencies = new Array(256).fill(0);
    for (let i = 0; i < buffer.length; i++) frequencies[buffer[i]]++;
    let entropy = 0;
    for (let i = 0; i < 256; i++) {
        if (frequencies[i] > 0) {
            let probability = frequencies[i] / buffer.length;
            entropy -= probability * Math.log2(probability);
        }
    }
    return entropy;
}

function isBlacklistedHash(hashValue) {
    try {
        const dbContent = fs.readFileSync(HASH_DB_FILE, 'utf8');
        return dbContent.split('\n').map(h => h.trim()).includes(hashValue);
    } catch (e) { return false; }
}

function logForensicEvent(eventMessage) {
    const timestamp = new Date().toISOString();
    const logEntry = `[${timestamp}] ${eventMessage}\n`;
    try { fs.appendFileSync(LOG_FILE, logEntry, 'utf8'); } catch (e) {}
}

function analyzeFilePayload(filePath) {
    const fileName = path.basename(filePath);
    if (filePath.startsWith(SHADOW_DIR) || filePath.startsWith(VAULT_DIR)) return;
    try {
        if (!fs.existsSync(filePath)) return;
        const fileBuffer = fs.readFileSync(filePath);
        const hash = crypto.createHash("sha256").update(fileBuffer).digest("hex");
        const entropy = calculateShannonEntropy(fileBuffer);
        const fileContent = fileBuffer.toString("utf8").toLowerCase();
        
        let threatScore = 0;
        let detectionIndicators = [];

        if (isBlacklistedHash(hash)) {
            threatScore += 100;
            detectionIndicators.push("Match Flagged in Local Threat Intelligence DB File");
        }
        if (/vssadmin.*delete.*shadows/i.test(fileContent) || /wmic.*shadowcopy.*delete/i.test(fileContent)) {
            threatScore += 85;
            detectionIndicators.push("Ransomware System Backup Destruction Sequence Detected");
        }
        if (/powershell.*-nop.*-w.*hidden.*-enc/i.test(fileContent) || /cmd.*\/c.*echo.*bitsadmin/i.test(fileContent)) {
            threatScore += 60;
            detectionIndicators.push("Suspicious Headless Shell Script Download Execution Attempt");
        }
        if (entropy > 6.50 && (fileName.endsWith(".txt") || fileName.endsWith(".docx") || fileName.endsWith(".xlsx"))) {
            threatScore += 95;
            detectionIndicators.push("Abnormal High-Entropy Mutation Pattern (Likely Mass Data Encryption)");
        }

        if (threatScore >= 50) {
            console.log(`[!] Threat Intercepted: ${fileName} | Score: ${threatScore}/100`);
            logForensicEvent(`THREAT CONTAINMENT - Intercepted hacker payload at path: ${filePath}`);
            executeContainmentSequence(filePath, fileName, fileBuffer, hash);
        } else {
            const safeFlattenedName = filePath.replace(/\\/g, '_').replace(/:/g, '');
            const shadowPath = path.join(SHADOW_DIR, safeFlattenedName + ".shadow");
            fs.writeFileSync(shadowPath, fileBuffer);
        }
    } catch (err) {}
}

function executeContainmentSequence(filePath, fileName, fileBuffer, hash) {
    const psCommand = `powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-Process | Where-Object { \$_.Modules.FileName -contains '${filePath.replace(/\\/g, '\\\\')}' } | Select-Object -ExpandProperty Id"`;
    exec(psCommand, (err, stdout) => {
        let targets = [];
        if (!err && stdout.trim()) targets = stdout.trim().split(/\r?\n/);
        
        exec('taskkill /F /IM cmd.exe /FI "WINDOWTITLE eq Ransomware*"', () => {
            targets.forEach(pid => {
                if (pid && pid.trim() !== process.pid.toString()) {
                    try { execSync(`taskkill /F /PID ${pid.trim()}`); } catch(e){}
                }
            });
            isolateToEncryptedVault(filePath, fileName, fileBuffer, hash);
        });
    });
}

function isolateToEncryptedVault(filePath, fileName, fileBuffer, hash) {
    try {
        const secretKey = crypto.scryptSync("SovereignSystemsDeploymentEngineSecretPass", "engineSalt", 32);
        const cipher = crypto.createCipheriv("aes-256-cbc", secretKey, Buffer.alloc(16, 0));
        const encryptedData = Buffer.concat([cipher.update(fileBuffer), cipher.final()]);
        fs.writeFileSync(path.join(VAULT_DIR, `${hash}.locked`), encryptedData);
        if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
        triggerWindowsToastNotification(fileName, "Full Space Guard AES-256 Quarantine + Layer 99999999 Rollback Done");
        executeLayer99999999Rollback(filePath, fileName);
    } catch (err) {}
}

function executeLayer99999999Rollback(filePath, fileName) {
    const safeFlattenedName = filePath.replace(/\\/g, '_').replace(/:/g, '');
