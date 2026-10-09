/**
 * MLSecOps Portal Application Controller
 * Handles interactive model scanning, disassembly visualization, SARIF generation, and webhook simulation.
 */

import { SAMPLE_MODELS, base64ToUint8Array } from './sample_models.js';
import { 
  disassemblePickle, 
  validateSafetensors, 
  inspectPyTorchZip, 
  analyzeONNXProtobuf 
} from './disassembler.js';

// Application State
const state = {
  activeModelName: "safe_model.safetensors",
  activeBytes: null,
  activeFormat: "safetensors",
  activeThreshold: "high",
  strictMode: false,
  activeTab: "findings",
  currentScanResult: null,
};

// DOM Element References
const dropzone = document.getElementById("dropzone");
const fileInput = document.getElementById("fileInput");
const samplesContainer = document.getElementById("samplesContainer");
const thresholdSelect = document.getElementById("thresholdSelect");
const strictToggle = document.getElementById("strictToggle");
const btnScan = document.getElementById("btnScan");

// Output Containers
const verdictHero = document.getElementById("verdictHero");
const verdictTitle = document.getElementById("verdictTitle");
const verdictSummary = document.getElementById("verdictSummary");
const scoreDialVal = document.getElementById("scoreDialVal");
const scoreCircleVal = document.getElementById("scoreCircleVal");
const provenanceSha256 = document.getElementById("provenanceSha256");
const findingsList = document.getElementById("findingsList");
const findingsCountBadge = document.getElementById("findingsCountBadge");
const opcodeStream = document.getElementById("opcodeStream");
const hexdumpViewer = document.getElementById("hexdumpViewer");
const webhookRequestCode = document.getElementById("webhookRequestCode");
const webhookResponseCode = document.getElementById("webhookResponseCode");
const btnDownloadSarif = document.getElementById("btnDownloadSarif");
const btnDownloadJson = document.getElementById("btnDownloadJson");
const btnCopyCli = document.getElementById("btnCopyCli");

// Setup Event Listeners
function initApp() {
  renderSampleList();
  setupDragAndDrop();
  setupTabs();

  // Load initial preset model
  loadPresetModel("safe_model.safetensors");

  thresholdSelect.addEventListener("change", (e) => {
    state.activeThreshold = e.target.value;
    runScan();
  });

  strictToggle.addEventListener("change", (e) => {
    state.strictMode = e.target.checked;
    runScan();
  });

  btnScan.addEventListener("click", () => {
    runScan();
  });

  btnDownloadSarif.addEventListener("click", downloadSarif);
  btnDownloadJson.addEventListener("click", downloadJson);
  btnCopyCli.addEventListener("click", copyCliCommand);

  document.getElementById("btnCopyHash")?.addEventListener("click", () => {
    navigator.clipboard.writeText(provenanceSha256.textContent);
    showToast("SHA-256 copied to clipboard!");
  });
}

/**
 * Render Preset Sample List
 */
function renderSampleList() {
  samplesContainer.innerHTML = "";
  Object.values(SAMPLE_MODELS).forEach((model) => {
    const item = document.createElement("div");
    item.className = `sample-item ${model.name === state.activeModelName ? "active" : ""}`;
    item.id = `sample-${model.name.replace(".", "-")}`;
    
    const tagClass = model.classification.toLowerCase();

    item.innerHTML = `
      <div class="sample-info">
        <span class="format-badge ${model.format}">.${model.format}</span>
        <div>
          <div class="sample-name">${model.name}</div>
          <div class="sample-meta">${model.tag}</div>
        </div>
      </div>
      <span class="sample-tag ${tagClass}">${model.classification}</span>
    `;

    item.addEventListener("click", () => {
      document.querySelectorAll(".sample-item").forEach(el => el.classList.remove("active"));
      item.classList.add("active");
      loadPresetModel(model.name);
    });

    samplesContainer.appendChild(item);
  });
}

/**
 * Loads a preset benchmark model
 */
function loadPresetModel(modelName) {
  const model = SAMPLE_MODELS[modelName];
  if (!model) return;

  state.activeModelName = model.name;
  state.activeFormat = model.format;
  state.activeBytes = base64ToUint8Array(model.base64);

  runScan();
}

/**
 * Drag & Drop File Upload Handlers
 */
function setupDragAndDrop() {
  dropzone.addEventListener("click", () => fileInput.click());

  dropzone.addEventListener("dragover", (e) => {
    e.preventDefault();
    dropzone.classList.add("dragover");
  });

  dropzone.addEventListener("dragleave", () => {
    dropzone.classList.remove("dragover");
  });

  dropzone.addEventListener("drop", (e) => {
    e.preventDefault();
    dropzone.classList.remove("dragover");
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleUserFile(e.dataTransfer.files[0]);
    }
  });

  fileInput.addEventListener("change", (e) => {
    if (e.target.files && e.target.files.length > 0) {
      handleUserFile(e.target.files[0]);
    }
  });
}

function handleUserFile(file) {
  const reader = new FileReader();
  const ext = file.name.split(".").pop().toLowerCase();

  reader.onload = (e) => {
    state.activeModelName = file.name;
    state.activeFormat = ext;
    state.activeBytes = new Uint8Array(e.target.result);

    document.querySelectorAll(".sample-item").forEach(el => el.classList.remove("active"));
    runScan();
  };

  reader.readAsArrayBuffer(file);
}

/**
 * Core In-Browser Static Scan Orchestration
 */
async function runScan() {
  if (!state.activeBytes) return;

  // 1. Calculate Real SHA-256
  const hashBuffer = await crypto.subtle.digest("SHA-256", state.activeBytes.buffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const sha256Hex = hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
  provenanceSha256.textContent = sha256Hex;

  // 2. Format Analysis
  let findings = [];
  let opcodes = [];

  const fmt = state.activeFormat;

  if (fmt === "safetensors") {
    const res = validateSafetensors(state.activeBytes, state.activeModelName);
    findings = res.findings;
  } 
  else if (fmt === "pkl" || fmt === "pickle") {
    const res = disassemblePickle(state.activeBytes, state.activeModelName, state.strictMode);
    findings = res.findings;
    opcodes = res.opcodes;
  }
  else if (fmt === "pt" || fmt === "pth" || fmt === "bin") {
    const res = inspectPyTorchZip(state.activeBytes, state.activeModelName);
    findings = res.findings;
    // Disassemble inner data.pkl if found for opcodes tab
    const dataPkl = res.entries.find(e => e.filename.includes("data.pkl"));
    if (dataPkl) {
      const pklRes = disassemblePickle(dataPkl.dataSlice, dataPkl.filename);
      opcodes = pklRes.opcodes;
    }
  }
  else if (fmt === "onnx") {
    const res = analyzeONNXProtobuf(state.activeBytes, state.activeModelName);
    findings = res.findings;
  }
  else {
    // Fallback format sniffing
    const res = disassemblePickle(state.activeBytes, state.activeModelName, state.strictMode);
    findings = res.findings;
    opcodes = res.opcodes;
  }

  // 3. Policy Evaluation
  const severityOrder = { INFO: 1, LOW: 2, MEDIUM: 3, HIGH: 4, CRITICAL: 5 };
  const thresholdVal = severityOrder[state.activeThreshold.toUpperCase()] || 4;

  const violations = findings.filter(f => (severityOrder[f.severity] || 1) >= thresholdVal);
  const passed = violations.length === 0;

  // Calculate Risk Score (0-100)
  let riskScore = 0;
  findings.forEach(f => {
    if (f.severity === "CRITICAL") riskScore += 50;
    else if (f.severity === "HIGH") riskScore += 30;
    else if (f.severity === "MEDIUM") riskScore += 15;
    else riskScore += 5;
  });
  riskScore = Math.min(100, riskScore);

  state.currentScanResult = {
    modelName: state.activeModelName,
    format: state.activeFormat,
    sha256: sha256Hex,
    sizeBytes: state.activeBytes.length,
    findings,
    violations,
    passed,
    riskScore,
    opcodes,
  };

  // 4. Render UI Visualizations
  renderVerdict(passed, violations, findings, riskScore);
  renderFindings(findings);
  renderOpcodes(opcodes);
  renderHexdump(state.activeBytes);
  renderWebhookSimulation(state.currentScanResult);
}

/**
 * Render Admission Verdict Banner & Score Meter
 */
function renderVerdict(passed, violations, findings, riskScore) {
  verdictHero.className = "verdict-hero " + (passed ? (findings.length > 0 ? "warning" : "approved") : "rejected");

  if (!passed) {
    verdictTitle.textContent = "DEPLOYMENT FORBIDDEN (BLOCKED)";
    verdictSummary.textContent = `Security Policy Gate Triggered: ${violations.length} finding(s) met or exceeded threshold '${state.activeThreshold.toUpperCase()}'. Model loading aborted.`;
  } else if (findings.length > 0) {
    verdictTitle.textContent = "ADMISSION APPROVED WITH WARNINGS";
    verdictSummary.textContent = `Model approved for inference runtime. ${findings.length} non-blocking advisory finding(s) recorded for security telemetry.`;
  } else {
    verdictTitle.textContent = "ADMISSION APPROVED (CLEAN)";
    verdictSummary.textContent = `All static bytecode checks verified clean. Zero dangerous deserialization opcodes or memory bounds anomalies detected.`;
  }

  // Animate score dial
  scoreDialVal.textContent = Math.round(riskScore);
  const circumference = 2 * Math.PI * 34; // radius 34 in svg
  const offset = circumference - (riskScore / 100) * circumference;
  scoreCircleVal.style.strokeDashoffset = offset;
  scoreCircleVal.style.stroke = riskScore >= 70 ? "var(--crimson-neon)" : riskScore >= 30 ? "var(--amber-neon)" : "var(--emerald-neon)";
}

/**
 * Render Findings Cards
 */
function renderFindings(findings) {
  findingsCountBadge.textContent = `${findings.length} detected`;
  findingsList.innerHTML = "";

  if (findings.length === 0) {
    findingsList.innerHTML = `
      <div class="clean-findings">
        <svg class="clean-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
          <polyline points="22 4 12 14.01 9 11.01"></polyline>
        </svg>
        <div class="clean-title">Zero Security Anomalies Detected</div>
        <div class="clean-desc">Model artifacts pass zero-executable guarantees and strictly conform to safe serialization baselines.</div>
      </div>
    `;
    return;
  }

  findings.forEach((f) => {
    const card = document.createElement("div");
    card.className = `finding-card ${f.severity}`;

    card.innerHTML = `
      <div class="finding-header">
        <div class="finding-badges">
          <span class="sev-badge ${f.severity}">${f.severity}</span>
          <span class="rule-badge">${f.ruleId}</span>
        </div>
        <span class="finding-loc">${f.location}</span>
      </div>
      <div class="finding-title">${f.title}</div>
      <div class="finding-desc">${f.description}</div>
      ${f.details ? `<div class="finding-details">Context: ${JSON.stringify(f.details)}</div>` : ""}
    `;

    findingsList.appendChild(card);
  });
}

/**
 * Render Opcode Stream
 */
function renderOpcodes(opcodes) {
  opcodeStream.innerHTML = "";
  if (!opcodes || opcodes.length === 0) {
    opcodeStream.innerHTML = `<div style="color: var(--text-muted); padding: 1rem; text-align: center;">Format does not use Python pickle bytecode stream (or container weights are raw tensors).</div>`;
    return;
  }

  opcodes.forEach(op => {
    const row = document.createElement("div");
    row.className = `opcode-row ${op.isDanger ? "danger" : ""}`;
    row.innerHTML = `
      <span class="op-offset">${op.hexOffset}</span>
      <span class="op-name">${op.name}</span>
      <span class="op-arg">${op.arg || ""}</span>
    `;
    opcodeStream.appendChild(row);
  });
}

/**
 * Render Hex Dump View
 */
function renderHexdump(bytes) {
  const maxBytes = Math.min(bytes.length, 512); // preview up to 512 bytes
  let lines = [];

  for (let i = 0; i < maxBytes; i += 16) {
    const chunk = bytes.slice(i, i + 16);
    const offsetHex = "0x" + i.toString(16).padStart(4, "0").toUpperCase();
    
    let hexParts = [];
    let asciiParts = [];

    for (let j = 0; j < 16; j++) {
      if (j < chunk.length) {
        const b = chunk[j];
        hexParts.push(b.toString(16).padStart(2, "0").toUpperCase());
        asciiParts.push(b >= 32 && b <= 126 ? String.fromCharCode(b) : ".");
      } else {
        hexParts.push("  ");
        asciiParts.push(" ");
      }
    }

    lines.push(`${offsetHex}  ${hexParts.slice(0, 8).join(" ")}  ${hexParts.slice(8).join(" ")}  |${asciiParts.join("")}|`);
  }

  if (bytes.length > 512) {
    lines.push(`... [${bytes.length - 512} remaining bytes truncated for display]`);
  }

  hexdumpViewer.textContent = lines.join("\n");
}

/**
 * Render Webhook Simulation Payloads
 */
function renderWebhookSimulation(result) {
  const reqPayload = {
    model_uri: `s3://models-registry/v1/${result.modelName}`,
    fail_on: state.activeThreshold,
    strict: state.strictMode,
    target_cluster: "kserve-inference-pool",
  };

  const resPayload = {
    allowed: result.passed,
    verdict: result.passed ? "PASSED" : "FAILED",
    fail_threshold: state.activeThreshold.toUpperCase(),
    risk_score: result.riskScore,
    violations_count: result.violations.length,
    findings_count: result.findings.length,
    admission_action: result.passed ? "ADMIT_WEIGHTS_TO_GPU_MEMORY" : "REJECT_CONTAINER_STARTUP",
    latency_ms: (Math.random() * 2 + 1.2).toFixed(2),
  };

  webhookRequestCode.textContent = JSON.stringify(reqPayload, null, 2);
  webhookResponseCode.textContent = JSON.stringify(resPayload, null, 2);
}

/**
 * Setup Inspection Tabs
 */
function setupTabs() {
  const tabs = document.querySelectorAll(".tab-btn");
  tabs.forEach(tab => {
    tab.addEventListener("click", () => {
      tabs.forEach(t => t.classList.remove("active"));
      tab.classList.add("active");
      const target = tab.dataset.target;
      
      document.getElementById("findingsTab").style.display = target === "findings" ? "block" : "none";
      document.getElementById("opcodesTab").style.display = target === "opcodes" ? "block" : "none";
      document.getElementById("hexdumpTab").style.display = target === "hexdump" ? "block" : "none";
    });
  });
}

/**
 * SARIF v2.1.0 Export
 */
function downloadSarif() {
  if (!state.currentScanResult) return;
  const res = state.currentScanResult;

  const sarifDoc = {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "MLSecOps-Scanner",
            semanticVersion: "1.0.0",
            informationUri: "https://github.com/ravishkarathnayaka/MLSecOps-AI-Model-Supply-Chain-Malicious-Deserialization-Scanne",
            rules: res.findings.map(f => ({
              id: f.ruleId,
              shortDescription: { text: f.title },
              fullDescription: { text: f.description },
              defaultConfiguration: { level: f.severity === "CRITICAL" || f.severity === "HIGH" ? "error" : "warning" }
            }))
          }
        },
        artifacts: [{ location: { uri: res.modelName } }],
        results: res.findings.map(f => ({
          ruleId: f.ruleId,
          level: f.severity === "CRITICAL" || f.severity === "HIGH" ? "error" : "warning",
          message: { text: f.description },
          locations: [{
            physicalLocation: {
              artifactLocation: { uri: res.modelName },
              region: { startLine: 1, startColumn: 1 }
            }
          }]
        }))
      }
    ]
  };

  downloadFile(`mlsecops-sarif-${res.modelName}.sarif`, JSON.stringify(sarifDoc, null, 2), "application/json");
  showToast("SARIF v2.1.0 report downloaded!");
}

/**
 * JSON Report Export
 */
function downloadJson() {
  if (!state.currentScanResult) return;
  const res = state.currentScanResult;
  const report = {
    scanner: "MLSecOps-AI-Model-Scanner",
    version: "1.0.0",
    scan_timestamp: new Date().toISOString(),
    target: res.modelName,
    sha256: res.sha256,
    verdict: res.passed ? "PASSED" : "FAILED",
    risk_score: res.riskScore,
    findings: res.findings
  };

  downloadFile(`mlsecops-audit-${res.modelName}.json`, JSON.stringify(report, null, 2), "application/json");
  showToast("JSON Audit report downloaded!");
}

function copyCliCommand() {
  const cmd = `mlsec-scan --path ./models/${state.activeModelName} --fail-on ${state.activeThreshold} ${state.strictMode ? "--strict" : ""}`;
  navigator.clipboard.writeText(cmd);
  showToast("CLI Command copied to clipboard!");
}

function downloadFile(filename, content, type) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function showToast(msg) {
  const existing = document.querySelector(".toast-notification");
  if (existing) existing.remove();

  const toast = document.createElement("div");
  toast.className = "toast-notification";
  toast.textContent = msg;
  toast.style.cssText = `
    position: fixed;
    bottom: 2rem;
    right: 2rem;
    background: #00d2ff;
    color: #060911;
    font-weight: 700;
    font-size: 0.85rem;
    padding: 0.75rem 1.25rem;
    border-radius: 8px;
    box-shadow: 0 10px 25px rgba(0, 210, 255, 0.4);
    z-index: 9999;
    animation: fadeIn 0.3s ease;
  `;
  document.body.appendChild(toast);
  setTimeout(() => toast.remove(), 2600);
}

// Initialize on DOM Ready
document.addEventListener("DOMContentLoaded", initApp);
