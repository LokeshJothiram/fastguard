import json
import time
import webbrowser
import socket
import argparse
from http.server import HTTPServer, BaseHTTPRequestHandler
from fastguard import PIIGuard

HTML_CONTENT = """<!DOCTYPE html>
<html lang="en" class="h-full bg-slate-100">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FastGuard — AI PII Guardrail & Vault Sandbox</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = {
            theme: {
                extend: {
                    fontFamily: {
                        sans: ['Inter', 'system-ui', 'sans-serif'],
                        mono: ['JetBrains Mono', 'monospace'],
                    },
                    colors: {
                        brand: {
                            50: '#eef2ff',
                            100: '#e0e7ff',
                            500: '#6366f1',
                            600: '#4f46e5',
                            700: '#4338ca',
                        }
                    }
                }
            }
        }
    </script>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
    <style>
        body { font-family: 'Inter', sans-serif; }
        code, pre, textarea, .font-mono { font-family: 'JetBrains Mono', monospace; }
        ::-webkit-scrollbar { width: 4px; height: 4px; }
        ::-webkit-scrollbar-track { background: #f1f5f9; }
        ::-webkit-scrollbar-thumb { background: #cbd5e1; border-radius: 4px; }
        ::-webkit-scrollbar-thumb:hover { background: #94a3b8; }
    </style>
</head>
<body class="h-screen max-h-screen w-full flex flex-col justify-between overflow-hidden text-slate-800 p-3 gap-2.5 bg-slate-100">

    <!-- Top Header Bar -->
    <header class="w-full bg-white border border-slate-200/80 rounded-xl px-4 py-2 flex items-center justify-between shadow-xs shrink-0">
        <div class="flex items-center gap-2.5">
            <div class="w-7 h-7 rounded-lg bg-brand-600 flex items-center justify-center text-white font-bold text-sm shadow-sm">
                🛡️
            </div>
            <div>
                <h1 class="text-sm font-extrabold text-slate-900 tracking-tight flex items-center gap-2">
                    FastGuard
                    <span class="text-xs font-normal text-slate-500 hidden md:inline">| Sub-millisecond Streaming PII Guardrail & Reversible Vault</span>
                </h1>
            </div>
        </div>
        <div class="flex items-center gap-1.5 flex-wrap">
            <span class="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-indigo-50 text-indigo-700 border border-indigo-200">
                ⚡ &lt;100 µs Latency
            </span>
            <span class="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
                🔄 Zero-Loss Reversible
            </span>
            <span class="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-blue-50 text-blue-700 border border-blue-200">
                🔒 Thread-Safe
            </span>
            <span class="hidden sm:inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-purple-50 text-purple-700 border border-purple-200">
                🌍 Global Regional IDs
            </span>
        </div>
    </header>

    <!-- Main Workspace (2 Balanced Full-Width Columns) -->
    <main class="w-full grid grid-cols-1 lg:grid-cols-2 gap-3 flex-1 min-h-0">

        <!-- LEFT PANEL: Prompt Input & Configuration -->
        <section class="bg-white border border-slate-200/80 rounded-xl p-3 flex flex-col justify-between shadow-xs min-h-0 overflow-hidden gap-2">
            
            <!-- Compact User Prompt (Small Height) -->
            <div class="flex flex-col gap-1 shrink-0">
                <div class="flex items-center justify-between">
                    <label class="text-xs font-bold text-slate-800 flex items-center gap-1.5">
                        <span>📥 1. User Prompt</span>
                        <span class="text-[11px] font-normal text-slate-500">(Input with PII)</span>
                    </label>
                    <span class="text-[11px] text-slate-400 font-mono" id="char-count">0 chars</span>
                </div>

                <textarea id="prompt-input" 
                    rows="2"
                    class="w-full h-14 text-xs sm:text-[13px] bg-slate-50 border border-slate-200 rounded-lg p-2 text-slate-800 focus:bg-white focus:border-brand-600 focus:ring-2 focus:ring-brand-100 outline-none transition font-mono resize-none leading-relaxed"
                    placeholder="Type a prompt or click the entity buttons below to build one..."></textarea>
            </div>

            <!-- Separate Individual PII Entity Selector (Bigger, Clickable Boxes) -->
            <div class="flex flex-col gap-1.5 bg-slate-50 border border-slate-200/80 rounded-lg p-2.5 flex-1 min-h-0 overflow-hidden">
                <div class="flex items-center justify-between shrink-0">
                    <span class="text-[11px] font-bold text-slate-700 flex items-center gap-1">
                        <span>🧩 Add Individual PII Entities (Click to append & combine):</span>
                    </span>
                    <button onclick="clearPrompt()" class="text-[10px] text-slate-400 hover:text-brand-600 font-medium cursor-pointer">↺ Reset Prompt</button>
                </div>

                <!-- Entity Chips Grid with Editable Inputs -->
                <div class="grid grid-cols-2 sm:grid-cols-3 gap-1.5 flex-1 overflow-y-auto pr-0.5">
                    <!-- Email -->
                    <div class="flex flex-col gap-1 p-1.5 bg-white border border-slate-200 rounded-md shadow-2xs">
                        <div class="flex items-center justify-between">
                            <span class="text-[11px] font-bold text-slate-800 flex items-center gap-1">📧 Email</span>
                            <button onclick="appendEntity('email')" class="text-[9px] font-semibold text-brand-600 bg-brand-50 hover:bg-brand-600 hover:text-white px-1.5 py-0.5 rounded transition cursor-pointer">+ Add</button>
                        </div>
                        <input type="text" id="val-email" value="alice@company.com" class="w-full text-[10px] bg-slate-50 border border-slate-200 rounded px-1.5 py-0.5 font-mono text-slate-700 outline-none focus:border-brand-600 focus:bg-white">
                    </div>

                    <!-- Phone -->
                    <div class="flex flex-col gap-1 p-1.5 bg-white border border-slate-200 rounded-md shadow-2xs">
                        <div class="flex items-center justify-between">
                            <span class="text-[11px] font-bold text-slate-800 flex items-center gap-1">📱 Phone</span>
                            <button onclick="appendEntity('phone')" class="text-[9px] font-semibold text-brand-600 bg-brand-50 hover:bg-brand-600 hover:text-white px-1.5 py-0.5 rounded transition cursor-pointer">+ Add</button>
                        </div>
                        <input type="text" id="val-phone" value="+1 650 253 0000" class="w-full text-[10px] bg-slate-50 border border-slate-200 rounded px-1.5 py-0.5 font-mono text-slate-700 outline-none focus:border-brand-600 focus:bg-white">
                    </div>

                    <!-- Credit Card -->
                    <div class="flex flex-col gap-1 p-1.5 bg-white border border-slate-200 rounded-md shadow-2xs">
                        <div class="flex items-center justify-between">
                            <span class="text-[11px] font-bold text-slate-800 flex items-center gap-1">💳 Card (Luhn)</span>
                            <button onclick="appendEntity('card')" class="text-[9px] font-semibold text-brand-600 bg-brand-50 hover:bg-brand-600 hover:text-white px-1.5 py-0.5 rounded transition cursor-pointer">+ Add</button>
                        </div>
                        <input type="text" id="val-card" value="4532 0123 4567 8910" class="w-full text-[10px] bg-slate-50 border border-slate-200 rounded px-1.5 py-0.5 font-mono text-slate-700 outline-none focus:border-brand-600 focus:bg-white">
                    </div>

                    <!-- IBAN -->
                    <div class="flex flex-col gap-1 p-1.5 bg-white border border-slate-200 rounded-md shadow-2xs">
                        <div class="flex items-center justify-between">
                            <span class="text-[11px] font-bold text-slate-800 flex items-center gap-1">🏦 IBAN</span>
                            <button onclick="appendEntity('iban')" class="text-[9px] font-semibold text-brand-600 bg-brand-50 hover:bg-brand-600 hover:text-white px-1.5 py-0.5 rounded transition cursor-pointer">+ Add</button>
                        </div>
                        <input type="text" id="val-iban" value="GB33BUKB20201555555555" class="w-full text-[10px] bg-slate-50 border border-slate-200 rounded px-1.5 py-0.5 font-mono text-slate-700 outline-none focus:border-brand-600 focus:bg-white">
                    </div>

                    <!-- UPI ID -->
                    <div class="flex flex-col gap-1 p-1.5 bg-white border border-slate-200 rounded-md shadow-2xs">
                        <div class="flex items-center justify-between">
                            <span class="text-[11px] font-bold text-slate-800 flex items-center gap-1">💸 UPI ID</span>
                            <button onclick="appendEntity('upi')" class="text-[9px] font-semibold text-brand-600 bg-brand-50 hover:bg-brand-600 hover:text-white px-1.5 py-0.5 rounded transition cursor-pointer">+ Add</button>
                        </div>
                        <input type="text" id="val-upi" value="user@okaxis" class="w-full text-[10px] bg-slate-50 border border-slate-200 rounded px-1.5 py-0.5 font-mono text-slate-700 outline-none focus:border-brand-600 focus:bg-white">
                    </div>

                    <!-- Aadhaar -->
                    <div class="flex flex-col gap-1 p-1.5 bg-white border border-slate-200 rounded-md shadow-2xs">
                        <div class="flex items-center justify-between">
                            <span class="text-[11px] font-bold text-slate-800 flex items-center gap-1">🪪 Aadhaar</span>
                            <button onclick="appendEntity('aadhaar')" class="text-[9px] font-semibold text-brand-600 bg-brand-50 hover:bg-brand-600 hover:text-white px-1.5 py-0.5 rounded transition cursor-pointer">+ Add</button>
                        </div>
                        <input type="text" id="val-aadhaar" value="3675 9834 6012" class="w-full text-[10px] bg-slate-50 border border-slate-200 rounded px-1.5 py-0.5 font-mono text-slate-700 outline-none focus:border-brand-600 focus:bg-white">
                    </div>

                    <!-- US SSN -->
                    <div class="flex flex-col gap-1 p-1.5 bg-white border border-slate-200 rounded-md shadow-2xs">
                        <div class="flex items-center justify-between">
                            <span class="text-[11px] font-bold text-slate-800 flex items-center gap-1">🆔 US SSN</span>
                            <button onclick="appendEntity('ssn')" class="text-[9px] font-semibold text-brand-600 bg-brand-50 hover:bg-brand-600 hover:text-white px-1.5 py-0.5 rounded transition cursor-pointer">+ Add</button>
                        </div>
                        <input type="text" id="val-ssn" value="123-45-6789" class="w-full text-[10px] bg-slate-50 border border-slate-200 rounded px-1.5 py-0.5 font-mono text-slate-700 outline-none focus:border-brand-600 focus:bg-white">
                    </div>

                    <!-- UK NINO -->
                    <div class="flex flex-col gap-1 p-1.5 bg-white border border-slate-200 rounded-md shadow-2xs">
                        <div class="flex items-center justify-between">
                            <span class="text-[11px] font-bold text-slate-800 flex items-center gap-1">🇬🇧 UK NINO</span>
                            <button onclick="appendEntity('nino')" class="text-[9px] font-semibold text-brand-600 bg-brand-50 hover:bg-brand-600 hover:text-white px-1.5 py-0.5 rounded transition cursor-pointer">+ Add</button>
                        </div>
                        <input type="text" id="val-nino" value="QQ123456A" class="w-full text-[10px] bg-slate-50 border border-slate-200 rounded px-1.5 py-0.5 font-mono text-slate-700 outline-none focus:border-brand-600 focus:bg-white">
                    </div>

                    <!-- IP Address -->
                    <div class="flex flex-col gap-1 p-1.5 bg-white border border-slate-200 rounded-md shadow-2xs">
                        <div class="flex items-center justify-between">
                            <span class="text-[11px] font-bold text-slate-800 flex items-center gap-1">🌐 IP Address</span>
                            <button onclick="appendEntity('ip')" class="text-[9px] font-semibold text-brand-600 bg-brand-50 hover:bg-brand-600 hover:text-white px-1.5 py-0.5 rounded transition cursor-pointer">+ Add</button>
                        </div>
                        <input type="text" id="val-ip" value="192.168.1.50" class="w-full text-[10px] bg-slate-50 border border-slate-200 rounded px-1.5 py-0.5 font-mono text-slate-700 outline-none focus:border-brand-600 focus:bg-white">
                    </div>
                </div>
            </div>

            <!-- Configuration Options & Stage Toggles -->
            <div class="grid grid-cols-1 sm:grid-cols-2 gap-2 bg-slate-50 border border-slate-200/60 rounded-lg p-2 text-xs shrink-0">
                <!-- Stage Toggles -->
                <div class="flex flex-col gap-1">
                    <label class="font-bold text-slate-700 block text-[11px]">Guardrail Stage Toggles</label>
                    <div class="flex items-center gap-3 flex-wrap">
                        <label class="inline-flex items-center gap-1.5 cursor-pointer select-none">
                            <input type="checkbox" id="toggle-redact-input" checked class="w-3.5 h-3.5 text-brand-600 rounded border-slate-300 focus:ring-brand-500">
                            <span class="text-[11px] font-semibold text-slate-700">🛡️ Mask Prompt</span>
                        </label>
                        <label class="inline-flex items-center gap-1.5 cursor-pointer select-none">
                            <input type="checkbox" id="toggle-unmask-output" checked class="w-3.5 h-3.5 text-brand-600 rounded border-slate-300 focus:ring-brand-500">
                            <span class="text-[11px] font-semibold text-slate-700">🔄 Unmask Stream</span>
                        </label>
                    </div>
                </div>

                <!-- Speed & Whitelist -->
                <div class="flex flex-col gap-1">
                    <div class="flex items-center justify-between">
                        <label class="font-semibold text-slate-700 text-[11px]">Stream Speed</label>
                        <div class="flex items-center gap-2">
                            <label class="inline-flex items-center gap-1 cursor-pointer">
                                <input type="radio" name="speed" value="fast" checked class="text-brand-600 focus:ring-0">
                                <span class="text-slate-700 text-[11px]">Fast</span>
                            </label>
                            <label class="inline-flex items-center gap-1 cursor-pointer">
                                <input type="radio" name="speed" value="realistic" class="text-brand-600 focus:ring-0">
                                <span class="text-slate-700 text-[11px]">Realistic</span>
                            </label>
                            <label class="inline-flex items-center gap-1 cursor-pointer">
                                <input type="radio" name="speed" value="instant" class="text-brand-600 focus:ring-0">
                                <span class="text-slate-700 text-[11px]">Instant</span>
                            </label>
                        </div>
                    </div>
                    <input type="text" id="whitelist-input" value="localhost, 127.0.0.1" placeholder="Whitelist safe terms..."
                        class="w-full text-[11px] bg-white border border-slate-200 rounded px-2 py-0.5 outline-none focus:border-brand-600 font-mono">
                </div>
            </div>

            <!-- Action Buttons -->
            <div class="flex items-center gap-2 shrink-0">
                <button id="run-btn" class="flex-1 bg-brand-600 hover:bg-brand-700 active:scale-[0.99] text-white font-semibold text-xs sm:text-sm py-2 px-4 rounded-lg shadow-sm transition flex items-center justify-center gap-2 cursor-pointer">
                    <span>⚡ Execute FastGuard Guardrail</span>
                </button>
                <button id="clear-btn" class="bg-slate-100 hover:bg-slate-200 text-slate-700 font-medium text-xs py-2 px-3.5 rounded-lg transition cursor-pointer">
                    🗑️ Clear
                </button>
            </div>
        </section>

        <!-- RIGHT PANEL: Pipeline Outputs & Live Telemetry -->
        <section class="bg-white border border-slate-200/80 rounded-xl p-3 flex flex-col justify-start gap-2.5 shadow-xs min-h-0 overflow-hidden">
            
            <!-- Live Telemetry Badges -->
            <div class="grid grid-cols-3 gap-2 shrink-0">
                <div class="bg-indigo-50/60 border border-indigo-100 rounded-lg py-1.5 px-2 text-center">
                    <div id="stat-latency" class="text-base sm:text-lg font-extrabold text-brand-600 font-mono">-- µs</div>
                    <div class="text-[9px] sm:text-[10px] uppercase font-bold text-slate-500 tracking-wider">Redaction Latency</div>
                </div>
                <div class="bg-slate-50 border border-slate-200/80 rounded-lg py-1.5 px-2 text-center">
                    <div id="stat-entities" class="text-base sm:text-lg font-extrabold text-slate-800 font-mono">--</div>
                    <div class="text-[9px] sm:text-[10px] uppercase font-bold text-slate-500 tracking-wider">PII Detected</div>
                </div>
                <div class="bg-emerald-50/60 border border-emerald-100 rounded-lg py-1.5 px-2 text-center">
                    <div id="stat-time" class="text-base sm:text-lg font-extrabold text-emerald-600 font-mono">-- ms</div>
                    <div class="text-[9px] sm:text-[10px] uppercase font-bold text-slate-500 tracking-wider">Stream Duration</div>
                </div>
            </div>

            <!-- Pipeline Outputs (3 Even Sections) -->
            <div class="flex flex-col gap-2 flex-1 min-h-0">
                
                <!-- 2. Sanitized Prompt -->
                <div class="flex flex-col gap-1 flex-1 min-h-0">
                    <div class="flex items-center justify-between">
                        <label class="text-xs font-bold text-slate-800 flex items-center gap-1.5">
                            <span>🛡️ 2. Redacted Prompt</span>
                            <span class="text-[11px] font-normal text-slate-500">(Sent to LLM / Model)</span>
                        </label>
                        <button onclick="copyText('sanitized-output')" class="text-[11px] text-slate-400 hover:text-slate-700 cursor-pointer">📋 Copy</button>
                    </div>
                    <div id="sanitized-output" class="flex-1 min-h-[50px] overflow-y-auto text-xs bg-slate-50 border border-slate-200 rounded-lg p-2 text-slate-700 font-mono leading-relaxed select-all">
                        Click Execute to run FastGuard...
                    </div>
                </div>

                <!-- 3. Restored Stream -->
                <div class="flex flex-col gap-1 flex-1 min-h-0">
                    <div class="flex items-center justify-between">
                        <label class="text-xs font-bold text-slate-800 flex items-center gap-1.5">
                            <span>🔄 3. Restored Stream</span>
                            <span class="text-[11px] font-normal text-slate-500">(Client-side unmasked in real-time)</span>
                        </label>
                        <div class="flex items-center gap-2">
                            <span id="streaming-indicator" class="hidden inline-flex items-center gap-1 text-[10px] text-emerald-600 font-semibold">
                                <span class="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span> Streaming
                            </span>
                            <button onclick="copyText('stream-output')" class="text-[11px] text-slate-400 hover:text-slate-700 cursor-pointer">📋 Copy</button>
                        </div>
                    </div>
                    <div id="stream-output" class="flex-1 min-h-[50px] overflow-y-auto text-xs bg-slate-50 border border-slate-200 rounded-lg p-2 text-slate-800 font-mono leading-relaxed select-all">
                        --
                    </div>
                </div>

                <!-- 4. Reversible Vault Inspector (Clean Light Mode) -->
                <div class="flex flex-col gap-1 flex-1 min-h-0">
                    <label class="text-xs font-bold text-slate-800 flex items-center gap-1.5">
                        <span>🔑 Reversible Client Vault Inspector</span>
                        <span class="text-[11px] font-normal text-slate-400">(In-Memory Reverse Mapping)</span>
                    </label>
                    <div id="vault-chips" class="flex-1 min-h-[50px] overflow-y-auto bg-slate-50 border border-slate-200 rounded-lg p-2 font-mono text-[11px] flex flex-wrap content-start items-center gap-1.5">
                        <span class="text-slate-400 italic text-[11px]">// No active vault entries. Click execute to populate.</span>
                    </div>
                </div>
            </div>
        </section>
    </main>

    <!-- Footer Status -->
    <footer class="text-center text-[11px] text-slate-400 shrink-0">
        FastGuard v1.0.0 • Client-side In-Memory PII Engine • Created by Lokesh Jothiram
    </footer>

    <!-- Interactive Client JavaScript -->
    <script>
        const ENTITY_SNIPPETS = {
            email: "email alice@company.com",
            phone: "phone +1 650 253 0000",
            card: "card 4532 0123 4567 8910",
            iban: "IBAN GB33BUKB20201555555555",
            upi: "UPI user@okaxis",
            aadhaar: "Aadhaar 2345 6789 0123",
            ssn: "SSN 123-45-6789",
            nino: "NINO QQ123456A",
            ip: "IP 192.168.1.50"
        };

        const promptInput = document.getElementById('prompt-input');
        const whitelistInput = document.getElementById('whitelist-input');
        const runBtn = document.getElementById('run-btn');
        const clearBtn = document.getElementById('clear-btn');
        const charCount = document.getElementById('char-count');

        const sanitizedOutput = document.getElementById('sanitized-output');
        const streamOutput = document.getElementById('stream-output');
        const vaultChips = document.getElementById('vault-chips');
        const statLatency = document.getElementById('stat-latency');
        const statEntities = document.getElementById('stat-entities');
        const statTime = document.getElementById('stat-time');
        const streamIndicator = document.getElementById('streaming-indicator');

        function updateCharCount() {
            charCount.textContent = `${promptInput.value.length} chars`;
        }
        promptInput.addEventListener('input', updateCharCount);
        updateCharCount();

        function appendEntity(type) {
            const inputEl = document.getElementById(`val-${type}`);
            const val = inputEl ? inputEl.value.trim() : "";
            if (!val) return;

            let snippet = "";
            if (type === 'email') snippet = `email ${val}`;
            else if (type === 'phone') snippet = `phone ${val}`;
            else if (type === 'card') snippet = `card ${val}`;
            else if (type === 'iban') snippet = `IBAN ${val}`;
            else if (type === 'upi') snippet = `UPI ${val}`;
            else if (type === 'aadhaar') snippet = `Aadhaar ${val}`;
            else if (type === 'ssn') snippet = `SSN ${val}`;
            else if (type === 'nino') snippet = `NINO ${val}`;
            else if (type === 'ip') snippet = `IP ${val}`;
            else snippet = val;

            let current = promptInput.value.trim();
            if (!current) {
                promptInput.value = `Contact with ${snippet}.`;
            } else {
                if (current.endsWith('.')) {
                    promptInput.value = `${current.slice(0, -1)} and ${snippet}.`;
                } else {
                    promptInput.value = `${current} and ${snippet}.`;
                }
            }
            updateCharCount();
            resetOutputStatus();
        }

        function clearPrompt() {
            promptInput.value = "";
            updateCharCount();
            resetOutputStatus();
        }

        function resetOutputStatus() {
            sanitizedOutput.textContent = 'Click Execute to run FastGuard...';
            streamOutput.textContent = '--';
            vaultChips.innerHTML = '<span class="text-slate-400 italic text-[11px]">// Ready. Click execute to run guardrail.</span>';
            statLatency.textContent = '-- µs';
            statEntities.textContent = '--';
            statTime.textContent = '-- ms';
        }

        function copyText(id) {
            const el = document.getElementById(id);
            navigator.clipboard.writeText(el.innerText || el.textContent);
        }

        async function runGuardrail() {
            const prompt = promptInput.value.trim();
            if (!prompt) return;

            const whitelist = whitelistInput.value.split(',').map(s => s.trim()).filter(Boolean);
            const speed = document.querySelector('input[name="speed"]:checked').value;
            const redactInput = document.getElementById('toggle-redact-input').checked;
            const unmaskOutput = document.getElementById('toggle-unmask-output').checked;

            runBtn.disabled = true;
            runBtn.classList.add('opacity-75');

            try {
                const response = await fetch('/api/process', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ 
                        prompt, 
                        whitelist,
                        redact_input: redactInput,
                        unmask_output: unmaskOutput
                    })
                });

                const data = await response.json();

                // 1. Update stats
                statLatency.textContent = `${data.latency_us.toFixed(1)} µs`;
                statEntities.textContent = `${data.entities_count} Found`;

                // 2. Render vault map chips in clean light mode
                if (Object.keys(data.vault_map).length === 0) {
                    vaultChips.innerHTML = '<span class="text-slate-400 italic text-[11px]">// No PII detected. Vault empty.</span>';
                } else {
                    vaultChips.innerHTML = Object.entries(data.vault_map).map(([k, v]) => `
                        <div class="inline-flex items-center gap-1.5 bg-white border border-slate-200 shadow-2xs px-2.5 py-1 rounded-md text-[11px]">
                            <span class="font-bold text-indigo-700 bg-indigo-50 border border-indigo-200 px-1.5 py-0.5 rounded">${k}</span>
                            <span class="text-slate-400">→</span>
                            <span class="text-emerald-700 font-semibold">${v}</span>
                        </div>
                    `).join('');
                }

                // 3. Set sanitized output
                sanitizedOutput.textContent = data.sanitized;

                // 4. Animate streaming tokens
                streamOutput.textContent = '';
                streamIndicator.classList.remove('hidden');

                const delay = speed === 'fast' ? 15 : speed === 'realistic' ? 40 : 0;
                const startTime = performance.now();

                for (let i = 0; i < data.tokens.length; i++) {
                    streamOutput.textContent += data.tokens[i];
                    if (delay > 0) {
                        await new Promise(r => setTimeout(r, delay));
                    }
                }

                const elapsed = (performance.now() - startTime).toFixed(1);
                statTime.textContent = `${elapsed} ms`;
                streamIndicator.classList.add('hidden');

            } catch (err) {
                console.error(err);
                streamOutput.textContent = 'Error processing request.';
            } finally {
                runBtn.disabled = false;
                runBtn.classList.remove('opacity-75');
            }
        }

        runBtn.addEventListener('click', runGuardrail);
        promptInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) {
                runGuardrail();
            }
        });

        clearBtn.addEventListener('click', () => {
            promptInput.value = '';
            sanitizedOutput.textContent = '--';
            streamOutput.textContent = '--';
            vaultChips.innerHTML = '<span class="text-slate-400 italic text-[11px]">// Vault cleared.</span>';
            statLatency.textContent = '-- µs';
            statEntities.textContent = '--';
            statTime.textContent = '-- ms';
            updateCharCount();
        });
    </script>
</body>
</html>
"""

class GuardrailHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(HTML_CONTENT.encode("utf-8"))

    def do_POST(self):
        if self.path == "/api/process":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)
            data = json.loads(body.decode("utf-8"))

            prompt = data.get("prompt", "")
            whitelist = set(data.get("whitelist", ["localhost", "127.0.0.1", "0.0.0.0"]))
            redact_input = data.get("redact_input", True)
            unmask_output = data.get("unmask_output", True)

            # Create fresh guardrail per request with user-specified stage settings
            guard = PIIGuard(
                whitelist=whitelist,
                redact_input=redact_input,
                unmask_output=unmask_output
            )

            # Benchmark sanitization latency in nanoseconds
            t0 = time.perf_counter_ns()
            sanitized = guard.sanitize_prompt(prompt)
            t1 = time.perf_counter_ns()
            latency_us = (t1 - t0) / 1000.0

            # Simulate token chunks
            chunks = [t + " " for t in sanitized.split()]
            tokens = list(guard.wrap_stream(chunks))

            response_data = {
                "sanitized": sanitized,
                "tokens": tokens,
                "restored": "".join(tokens).strip(),
                "vault_map": guard.vault.reverse_map,
                "latency_us": latency_us,
                "entities_count": len(guard.vault.forward_map)
            }

            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(response_data).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass


def find_available_port(preferred_port=7860, max_attempts=15):
    for offset in range(max_attempts):
        port = preferred_port + offset
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(('localhost', port)) != 0:
                return port
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        return s.getsockname()[1]


def run(default_port=7860):
    parser = argparse.ArgumentParser(description="FastGuard Web Sandbox Server")
    parser.add_argument("--port", type=int, default=default_port, help="Port to run server on")
    args, _ = parser.parse_known_args()

    port = find_available_port(args.port)
    server_address = ("", port)
    httpd = HTTPServer(server_address, GuardrailHandler)
    url = f"http://localhost:{port}"

    print(f"\\n" + "="*60)
    print(f"🛡️  FastGuard Web Sandbox running live at: {url}")
    print(f"="*60 + "\\n")

    try:
        webbrowser.open(url)
    except Exception:
        pass

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\\n🛑 Server stopped.")


if __name__ == "__main__":
    run(default_port=7860)
