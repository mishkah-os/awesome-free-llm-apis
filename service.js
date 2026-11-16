#!/usr/bin/env node
'use strict';

/**
 * Local OpenAI-compatible gateway + periodic dynamic model discovery service
 * for awesome-free-llm-apis (zero external dependencies, Node >= 20).
 *
 * Binds strictly to 127.0.0.1:9078 (configurable via AFL_HOST / AFL_PORT).
 */

const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');

const ROOT_DIR = __dirname;
const DATA_PATH = path.join(ROOT_DIR, 'data.json');
const ENV_VERIFY_PATH = path.join(ROOT_DIR, '.env.verify');
const CACHE_PATH = path.join(ROOT_DIR, '.verify', 'dynamic-catalog.json');

const HOST = process.env.AFL_HOST || '127.0.0.1';
const PORT = Math.max(1, parseInt(process.env.AFL_PORT || '9078', 10) || 9078);
const REFRESH_INTERVAL_MS = Math.max(60_000, parseInt(process.env.AFL_REFRESH_INTERVAL_MS || String(30 * 60 * 1000), 10) || 1_800_000);
const PROBE_TIMEOUT_MS = Math.max(3_000, parseInt(process.env.AFL_PROBE_TIMEOUT_MS || '18000', 10) || 18_000);
const CHAT_TIMEOUT_MS = Math.max(5_000, parseInt(process.env.AFL_CHAT_TIMEOUT_MS || '120000', 10) || 120_000);
const UPSTREAM_DATA_SYNC = (process.env.AFL_UPSTREAM_DATA_SYNC || '1') !== '0';
const UPSTREAM_DATA_URL = 'https://raw.githubusercontent.com/mnfst/awesome-free-llm-apis/main/data.json';

// Intelligence + capability baselines grounded in observed benchmarks and specs.
const MODEL_HINTS = {
  'kilo/nvidia/nemotron-3-ultra-550b-a55b:free': { tier: 100, tools: true, reasoning: true, modality: 'text', note: '550B MoE flagship, 1M ctx' },
  'ovh/Qwen3.5-397B-A17B': { tier: 96, tools: true, reasoning: true, modality: 'text+vision', note: '397B MoE flagship, 262K ctx, Vision' },
  'kilo/stealth/glyph-cluster': { tier: 94, tools: true, reasoning: true, modality: 'text(code)', note: 'Strong code + reasoning, 256K ctx' },
  'kilo/reflection/beam-free': { tier: 93, tools: true, reasoning: true, modality: 'text', note: 'Fast reasoning + Arabic + logic, 1M ctx' },
  'ovh/gpt-oss-120b': { tier: 91, tools: true, reasoning: true, modality: 'text', note: '120B general + logic + Arabic, 131K ctx' },
  'kilo/nvidia/nemotron-3.5-super-vl:free': { tier: 90, tools: true, reasoning: true, modality: 'multimodal', note: 'Multimodal 1M ctx + reasoning' },
  'kilo/cohere/north-mini-code:free': { tier: 88, tools: true, reasoning: true, modality: 'text(code)', note: 'Code + Arabic + logic, 256K ctx' },
  'kilo/baidu/ernie-5.5-flash-preview:free': { tier: 87, tools: true, reasoning: true, modality: 'text', note: 'Fast 1M ctx + Arabic + logic' },
  'kilo/particle-ai/particle-1:free': { tier: 85, tools: true, reasoning: true, modality: 'text', note: '1M ctx + Arabic + logic' },
  'ovh/Qwen3.8-27B': { tier: 84, tools: true, reasoning: true, modality: 'text+vision', note: 'Qwen 3.8 27B Vision, 262K ctx' },
  'ovh/Qwen2.5-VL-72B-Instruct': { tier: 82, tools: false, reasoning: false, modality: 'text+vision', note: '72B Vision (no tool calling), 32K ctx' },
  'kilo/nvidia/nemotron-3-nano-omni-30b-a3b-reasoning:free': { tier: 81, tools: true, reasoning: true, modality: 'multimodal', note: '30B Omni Multimodal + reasoning' },
  'ovh/Qwen3.6-27B': { tier: 78, tools: true, reasoning: true, modality: 'text+vision', note: 'Heavy reasoning, slow/verbose thinking' },
  'kilo/dots-studio/dots-3-note-preview:free': { tier: 77, tools: true, reasoning: true, modality: 'text+vision', note: '512K ctx, 460K max output, Vision' },
  'kilo/nvidia/nemotron-3.5-lightning:free': { tier: 75, tools: true, reasoning: true, modality: 'text', note: 'Ultra-fast reasoning, needs higher max_tokens' },
  'ovh/Mistral-Small-3.2-24B-Instruct-2506': { tier: 74, tools: true, reasoning: false, modality: 'text+vision', note: 'Very fast 24B non-reasoning Vision, 128K' },
  'ovh/gpt-oss-20b': { tier: 72, tools: true, reasoning: true, modality: 'text', note: '20B reasoning, 131K ctx' },
  'ovh/Meta-Llama-3_3-70B-Instruct': { tier: 71, tools: true, reasoning: false, modality: 'text', note: 'Llama 3.3 70B (can be slow under load)' },
  'ovh/Qwen3.5-9B': { tier: 68, tools: true, reasoning: true, modality: 'text+vision', note: 'Lightweight 9B Vision + reasoning, 262K' },
  'kilo/kilo-auto/free': { tier: 65, tools: true, reasoning: true, modality: 'text', note: 'Kilo meta auto-router' },
  'kilo/openrouter/free': { tier: 64, tools: true, reasoning: true, modality: 'text', note: 'OpenRouter free meta auto-router' },
  'llm7/glm-5.3-flash': { tier: 60, tools: false, reasoning: false, modality: 'text', note: 'Keyless anonymous (strict 1 RPS limit)' },
  'llm7/codestral-latest': { tier: 58, tools: false, reasoning: false, modality: 'text(code)', note: 'Code model (strict 1 RPS limit)' },
  'llm7/gpt-oss:20b': { tier: 56, tools: false, reasoning: false, modality: 'text', note: '20B keyless anonymous (strict 1 RPS)' },
  'llm7/mistral-Nemo-Instruct-2407': { tier: 40, tools: false, reasoning: false, modality: 'text', note: 'Legacy 12B (weak arithmetic/logic)' },
};

const OVH_EXCLUDE_RE = /whisper|tts|stable-diffusion|embedding|bge-|guard/i;
const KILLED_OR_AUTH_GATED = new Set();

function loadEnvVerify() {
  const vars = { ...process.env };
  if (fs.existsSync(ENV_VERIFY_PATH)) {
    for (const raw of fs.readFileSync(ENV_VERIFY_PATH, 'utf8').split('\n')) {
      const m = raw.match(/^([A-Z0-9_]+)=(.*)$/);
      if (m && !vars[m[1]]) {
        vars[m[1]] = m[2].trim().replace(/^["']|["']$/g, '');
      }
    }
  }
  return vars;
}

function heuristicRank(id, backend, ctx = 0) {
  const fullId = `${backend}/${id}`;
  if (MODEL_HINTS[fullId]) return MODEL_HINTS[fullId].tier;
  const lower = id.toLowerCase();
  let score = 55;
  if (/550b|405b|397b|3[0-9]{2}b/.test(lower)) score += 35;
  else if (/120b|110b|72b|70b/.test(lower)) score += 25;
  else if (/32b|30b|27b|24b/.test(lower)) score += 16;
  else if (/ultra|pro|super|beam|cluster|particle|ernie-5/.test(lower)) score += 22;
  else if (/flash|mini|small|lite|nano|9b|8b|3b|1\.7b/.test(lower)) score += 8;
  if ((ctx || 0) >= 500_000) score += 4;
  if (backend === 'kilo') score += 3;
  if (backend === 'llm7') score -= 10;
  return score;
}

function parseContextTokens(text) {
  const s = String(text || '').trim().toUpperCase();
  const m = s.match(/^(\d+(?:\.\d+)?)\s*([KM])?$/);
  if (!m) return null;
  const n = parseFloat(m[1]);
  if (m[2] === 'M') return Math.round(n * 1_000_000);
  if (m[2] === 'K') return Math.round(n * 1_000);
  return Math.round(n);
}

async function fetchJson(url, headers = {}, timeoutMs = 15_000) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, { headers, signal: ctrl.signal });
    const text = await res.text();
    let json = null;
    try { json = JSON.parse(text); } catch {}
    return { status: res.status, json, text };
  } catch (err) {
    return { status: 0, json: null, text: String(err?.message || err) };
  } finally {
    clearTimeout(timer);
  }
}

async function probeModel(entry) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), PROBE_TIMEOUT_MS);
  const started = Date.now();
  const headers = { 'Content-Type': 'application/json', ...(entry.upstreamHeaders || {}) };
  try {
    const res = await fetch(`${entry.baseUrl.replace(/\/$/, '')}/chat/completions`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        model: entry.upstreamModel,
        messages: [{ role: 'user', content: 'Reply OK' }],
        max_tokens: 16,
      }),
      signal: ctrl.signal,
    });
    const text = await res.text();
    const latency = Date.now() - started;
    let parsed = null;
    try { parsed = JSON.parse(text); } catch {}
    if (res.status === 200 && parsed?.choices?.length > 0) {
      return { working: true, httpStatus: 200, latencyMs: latency, reason: 'ok' };
    }
    if (res.status === 401 || res.status === 403 || text.includes('PAID_MODEL_AUTH_REQUIRED') || text.includes('Missing API key')) {
      KILLED_OR_AUTH_GATED.add(entry.id);
      return { working: false, httpStatus: res.status, latencyMs: latency, reason: 'auth_required' };
    }
    if (res.status === 429) {
      // 429 proves the endpoint/model is live on the anonymous tier, just temporarily busy.
      return { working: true, httpStatus: 429, latencyMs: latency, reason: 'rate_limited_live' };
    }
    return { working: false, httpStatus: res.status, latencyMs: latency, reason: `http_${res.status}` };
  } catch (err) {
    return { working: false, httpStatus: 0, latencyMs: Date.now() - started, reason: String(err?.message || err).slice(0, 80) };
  } finally {
    clearTimeout(timer);
  }
}

async function syncUpstreamDataJsonIfSafe() {
  if (!UPSTREAM_DATA_SYNC) return null;
  const r = await fetchJson(UPSTREAM_DATA_URL, { 'User-Agent': 'ant-swarm-free-llm-apis/1.0' }, 10_000);
  if (r.status === 200 && r.json && Array.isArray(r.json.providers) && r.json.providers.length >= 10) {
    return r.json;
  }
  return null;
}

function readLocalDataJson() {
  try {
    return JSON.parse(fs.readFileSync(DATA_PATH, 'utf8'));
  } catch {
    return { lastUpdated: null, providers: [] };
  }
}

async function discoverCandidates(envVars) {
  const localData = readLocalDataJson();
  const upstreamData = await syncUpstreamDataJsonIfSafe();
  const catalogData = upstreamData || localData;
  const candidates = [];
  const seen = new Set();

  const pushCandidate = (entry) => {
    if (!entry.id || seen.has(entry.id)) return;
    seen.add(entry.id);
    const hint = MODEL_HINTS[entry.id] || {};
    candidates.push({
      ...entry,
      supportsTools: hint.tools ?? (entry.backend !== 'llm7'),
      supportsReasoning: hint.reasoning ?? /reason|think|nemotron|qwen3\.|gpt-oss|ernie|glyph|beam|particle|dots/i.test(entry.upstreamModel),
      modality: entry.modality || hint.modality || 'text',
      note: hint.note || '',
      rank: heuristicRank(entry.upstreamModel, entry.backend, entry.contextLength),
    });
  };

  // 1) Dynamic public catalogs that require NO registration (keyless/anonymous)
  // 1a. Kilo Code ($0 free pool)
  const kiloKey = envVars.KILO_API_KEY || 'anonymous';
  const kiloRes = await fetchJson('https://api.kilo.ai/api/gateway/models', {}, 15_000);
  if (kiloRes.status === 200 && Array.isArray(kiloRes.json?.data)) {
    for (const m of kiloRes.json.data) {
      const p = m?.pricing || {};
      if (String(p.prompt) === '0' && String(p.completion) === '0' && m.id) {
        const modality = Array.isArray(m.architecture?.input_modalities)
          ? m.architecture.input_modalities.join('+')
          : 'text';
        pushCandidate({
          id: `kilo/${m.id}`,
          upstreamModel: m.id,
          backend: 'kilo',
          providerName: 'Kilo Code',
          baseUrl: 'https://api.kilo.ai/api/gateway',
          upstreamHeaders: { Authorization: `Bearer ${kiloKey}` },
          requiresSignup: Boolean(envVars.KILO_API_KEY) ? false : false,
          authMode: envVars.KILO_API_KEY ? 'api-key' : 'anonymous-bearer',
          contextLength: Number(m.context_length) || null,
          modality,
          rateLimit: '200 req/hr',
        });
      }
    }
  }

  // 1b. OVHcloud AI Endpoints (anonymous: MUST NOT send Authorization header)
  const ovhKey = envVars.OVH_API_KEY || '';
  const ovhRes = await fetchJson('https://oai.endpoints.kepler.ai.cloud.ovh.net/v1/models', {}, 15_000);
  const ovhCatalog = new Map();
  const ovhProvider = (catalogData.providers || []).find(p => /ovh/i.test(p.name));
  for (const pm of ovhProvider?.models || []) {
    if (pm.id) ovhCatalog.set(pm.id, pm);
  }
  if (ovhRes.status === 200 && Array.isArray(ovhRes.json?.data)) {
    for (const m of ovhRes.json.data) {
      if (!m.id || OVH_EXCLUDE_RE.test(m.id)) continue;
      const meta = ovhCatalog.get(m.id);
      pushCandidate({
        id: `ovh/${m.id}`,
        upstreamModel: m.id,
        backend: 'ovh',
        providerName: 'OVHcloud AI Endpoints',
        baseUrl: 'https://oai.endpoints.kepler.ai.cloud.ovh.net/v1',
        upstreamHeaders: ovhKey ? { Authorization: `Bearer ${ovhKey}` } : {},
        requiresSignup: false,
        authMode: ovhKey ? 'api-key' : 'no-auth-header',
        contextLength: parseContextTokens(meta?.context),
        modality: meta?.modality || 'text',
        rateLimit: ovhKey ? '400 RPM' : '2 RPM/IP/model (anonymous)',
      });
    }
  }

  // 1c. LLM7.io (keyless turbo pool listed in data.json + any live keyless models)
  const llm7Key = envVars.LLM7_API_KEY || '';
  const llm7Provider = (catalogData.providers || []).find(p => /llm7/i.test(p.name));
  const llm7SeedIds = new Set((llm7Provider?.models || []).map(m => m.id).filter(Boolean));
  llm7SeedIds.add('glm-5.3-flash');
  for (const mid of llm7SeedIds) {
    const meta = (llm7Provider?.models || []).find(m => m.id === mid);
    pushCandidate({
      id: `llm7/${mid}`,
      upstreamModel: mid,
      backend: 'llm7',
      providerName: 'LLM7.io',
      baseUrl: 'https://api.llm7.io/v1',
      upstreamHeaders: llm7Key ? { Authorization: `Bearer ${llm7Key}` } : {},
      requiresSignup: false,
      authMode: llm7Key ? 'api-key' : 'keyless',
      contextLength: parseContextTokens(meta?.context),
      modality: meta?.modality || 'text',
      rateLimit: llm7Key ? '60 RPM, 250 req/hr' : 'Anonymous 1 RPS (shared)',
    });
  }

  // 2) Optional free-tier providers if user configured keys in .env.verify / environment
  const keyedSpecs = [
    { key: 'GROQ_API_KEY', match: /groq/i, backend: 'groq', baseUrl: 'https://api.groq.com/openai/v1' },
    { key: 'GEMINI_API_KEY', match: /gemini/i, backend: 'gemini', baseUrl: 'https://generativelanguage.googleapis.com/v1beta/openai' },
    { key: 'OPENROUTER_API_KEY', match: /openrouter/i, backend: 'openrouter', baseUrl: 'https://openrouter.ai/api/v1' },
    { key: 'NVIDIA_API_KEY', match: /nvidia/i, backend: 'nvidia', baseUrl: 'https://integrate.api.nvidia.com/v1' },
    { key: 'MISTRAL_API_KEY', match: /mistral/i, backend: 'mistral', baseUrl: 'https://api.mistral.ai/v1' },
    { key: 'ZAI_API_KEY', match: /z ai/i, backend: 'zai', baseUrl: 'https://open.bigmodel.cn/api/paas/v4' },
  ];
  for (const spec of keyedSpecs) {
    const apiKey = envVars[spec.key];
    if (!apiKey) continue;
    const p = (catalogData.providers || []).find(item => spec.match.test(item.name));
    if (!p) continue;
    for (const m of p.models || []) {
      if (!m.id || m.id.startsWith('+')) continue;
      pushCandidate({
        id: `${spec.backend}/${m.id}`,
        upstreamModel: m.id,
        backend: spec.backend,
        providerName: p.name,
        baseUrl: spec.baseUrl,
        upstreamHeaders: { Authorization: `Bearer ${apiKey}` },
        requiresSignup: true,
        authMode: `env:${spec.key}`,
        contextLength: parseContextTokens(m.context),
        modality: m.modality || 'text',
        rateLimit: m.rateLimit || '',
      });
    }
  }

  return {
    candidates,
    upstreamDataUpdatedAt: catalogData.lastUpdated || null,
    upstreamDataSynced: Boolean(upstreamData),
  };
}

class DynamicRegistry {
  constructor() {
    this.models = [];
    this.lastRefreshAt = null;
    this.upstreamLastUpdated = null;
    this.upstreamDataSynced = false;
    this.refreshing = false;
    this.cooldownUntil = new Map();
    this._loadCache();
  }

  _loadCache() {
    try {
      if (!fs.existsSync(CACHE_PATH)) return;
      const saved = JSON.parse(fs.readFileSync(CACHE_PATH, 'utf8'));
      if (Array.isArray(saved.models) && saved.models.length > 0) {
        // Restore non-secret headers dynamically from env on read
        const envVars = loadEnvVerify();
        this.models = saved.models.map(m => this._attachHeaders(m, envVars));
        this.lastRefreshAt = saved.lastRefreshAt || null;
        this.upstreamLastUpdated = saved.upstreamLastUpdated || null;
        this.upstreamDataSynced = Boolean(saved.upstreamDataSynced);
      }
    } catch {}
  }

  _attachHeaders(entry, envVars) {
    const kiloKey = envVars.KILO_API_KEY || 'anonymous';
    if (entry.backend === 'kilo') entry.upstreamHeaders = { Authorization: `Bearer ${kiloKey}` };
    else if (entry.backend === 'ovh') entry.upstreamHeaders = envVars.OVH_API_KEY ? { Authorization: `Bearer ${envVars.OVH_API_KEY}` } : {};
    else if (entry.backend === 'llm7') entry.upstreamHeaders = envVars.LLM7_API_KEY ? { Authorization: `Bearer ${envVars.LLM7_API_KEY}` } : {};
    return entry;
  }

  _saveCache() {
    try {
      fs.mkdirSync(path.dirname(CACHE_PATH), { recursive: true });
      // Never persist bearer credentials to dynamic-catalog.json
      const sanitized = this.models.map(({ upstreamHeaders, ...rest }) => rest);
      fs.writeFileSync(CACHE_PATH, JSON.stringify({
        lastRefreshAt: this.lastRefreshAt,
        upstreamLastUpdated: this.upstreamLastUpdated,
        upstreamDataSynced: this.upstreamDataSynced,
        models: sanitized,
      }, null, 2));
    } catch {}
  }

  isCooledDown(id) {
    return (this.cooldownUntil.get(id) || 0) > Date.now();
  }

  markCooldown(id, ms, status) {
    this.cooldownUntil.set(id, Date.now() + ms);
    if (status === 401 || status === 403) {
      const m = this.models.find(item => item.id === id);
      if (m) m.working = false;
    }
  }

  async refresh() {
    if (this.refreshing) return this.summary();
    this.refreshing = true;
    try {
      const envVars = loadEnvVerify();
      const { candidates, upstreamDataUpdatedAt, upstreamDataSynced } = await discoverCandidates(envVars);
      const probed = [];
      // Pace probing gently (LLM7 spaced >=1100ms, OVH once per model, Kilo batched 3 at a time)
      const kiloList = candidates.filter(c => c.backend === 'kilo');
      const otherList = candidates.filter(c => c.backend !== 'kilo');

      for (let i = 0; i < kiloList.length; i += 3) {
        const batch = kiloList.slice(i, i + 3);
        const resBatch = await Promise.all(batch.map(async (c) => ({ ...c, ...(await probeModel(c)) })));
        probed.push(...resBatch);
      }
      for (const c of otherList) {
        probed.push({ ...c, ...(await probeModel(c)) });
        if (c.backend === 'llm7') await new Promise(r => setTimeout(r, 1150));
      }

      probed.sort((a, b) => {
        if (Boolean(a.working) !== Boolean(b.working)) return a.working ? -1 : 1;
        if (b.rank !== a.rank) return b.rank - a.rank;
        return (a.latencyMs || 99999) - (b.latencyMs || 99999);
      });

      this.models = probed;
      this.lastRefreshAt = new Date().toISOString();
      this.upstreamLastUpdated = upstreamDataUpdatedAt;
      this.upstreamDataSynced = upstreamDataSynced;
      this._saveCache();
      return this.summary();
    } finally {
      this.refreshing = false;
    }
  }

  workingModels({ includeUnhealthy = false } = {}) {
    return this.models.filter(m => includeUnhealthy || m.working);
  }

  resolveTargets(requestedModel, needsTools = false) {
    const clean = String(requestedModel || '').trim();
    const healthy = this.models.filter(m => m.working && !this.isCooledDown(m.id));
    const pool = healthy.length ? healthy : this.models.filter(m => m.working);

    if (!clean || clean === 'free-auto' || clean === 'auto') {
      const filtered = needsTools ? pool.filter(m => m.supportsTools) : pool;
      return (filtered.length ? filtered : pool).slice(0, 5);
    }

    const exact = this.models.find(m => m.id === clean);
    if (exact) return [exact];

    const byUpstream = this.models.filter(m => m.upstreamModel === clean);
    if (byUpstream.length) {
      byUpstream.sort((a, b) => (b.working ? 1 : 0) - (a.working ? 1 : 0) || b.rank - a.rank);
      return byUpstream;
    }
    return [];
  }

  summary() {
    const working = this.models.filter(m => m.working);
    return {
      ok: true,
      last_refresh_at: this.lastRefreshAt,
      upstream_data_updated_at: this.upstreamLastUpdated,
      upstream_data_synced: this.upstreamDataSynced,
      refresh_in_progress: this.refreshing,
      total_discovered: this.models.length,
      working_count: working.length,
    };
  }
}

const registry = new DynamicRegistry();

function readRequestBody(req, maxBytes = 8 * 1024 * 1024) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', chunk => {
      size += chunk.length;
      if (size > maxBytes) {
        reject(new Error('request_too_large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function sendJson(res, status, obj) {
  const payload = JSON.stringify(obj);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
  });
  res.end(payload);
}

async function handleChatCompletions(req, res) {
  let body;
  try {
    body = JSON.parse(await readRequestBody(req) || '{}');
  } catch (err) {
    return sendJson(res, 400, { error: { message: `Invalid JSON: ${err.message}`, type: 'invalid_request_error' } });
  }

  const wantsTools = Array.isArray(body.tools) && body.tools.length > 0;
  const targets = registry.resolveTargets(body.model, wantsTools);
  if (!targets.length) {
    return sendJson(res, 404, {
      error: { message: `Unknown or unavailable free model '${body.model || ''}'`, type: 'invalid_request_error' },
    });
  }

  const wantStream = Boolean(body.stream);
  let lastStatus = 502;
  let lastErrorText = 'No healthy upstream responded';

  for (const target of targets.slice(0, 4)) {
    const upstreamPayload = { ...body, model: target.upstreamModel };
    const headers = { 'Content-Type': 'application/json', ...(target.upstreamHeaders || {}) };
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), CHAT_TIMEOUT_MS);

    try {
      const upstreamRes = await fetch(`${target.baseUrl.replace(/\/$/, '')}/chat/completions`, {
        method: 'POST',
        headers,
        body: JSON.stringify(upstreamPayload),
        signal: ctrl.signal,
      });

      if (upstreamRes.status !== 200) {
        lastStatus = upstreamRes.status || 502;
        lastErrorText = await upstreamRes.text();
        if (lastStatus === 429) registry.markCooldown(target.id, 65_000, 429);
        else if (lastStatus === 401 || lastStatus === 403) registry.markCooldown(target.id, 6 * 3600_000, lastStatus);
        else if (lastStatus >= 500) registry.markCooldown(target.id, 120_000, lastStatus);
        continue;
      }

      if (wantStream && upstreamRes.body) {
        res.writeHead(200, {
          'Content-Type': 'text/event-stream; charset=utf-8',
          'Cache-Control': 'no-cache',
          Connection: 'keep-alive',
          'X-AFL-Backend': target.backend,
          'X-AFL-Model': target.id,
        });
        const reader = upstreamRes.body.getReader();
        while (true) {
          const { value, done } = await reader.read();
          if (done) break;
          if (value) res.write(Buffer.from(value));
        }
        res.end();
        return;
      }

      const text = await upstreamRes.text();
      res.writeHead(200, {
        'Content-Type': upstreamRes.headers.get('content-type') || 'application/json; charset=utf-8',
        'X-AFL-Backend': target.backend,
        'X-AFL-Model': target.id,
      });
      res.end(text);
      return;
    } catch (err) {
      lastStatus = 504;
      lastErrorText = String(err?.message || err);
      registry.markCooldown(target.id, 90_000, 504);
    } finally {
      clearTimeout(timer);
    }
  }

  let parsedErr = null;
  try { parsedErr = JSON.parse(lastErrorText); } catch {}
  return sendJson(res, lastStatus, parsedErr || { error: { message: lastErrorText.slice(0, 500), type: 'upstream_error' } });
}

function formatOpenAIModels(includeUnhealthy) {
  const list = registry.workingModels({ includeUnhealthy });
  const data = [
    {
      id: 'free-auto',
      object: 'model',
      created: 0,
      owned_by: 'free-llm-apis',
      rank: 999,
      description: 'Auto-router across smartest live keyless free models',
    },
    ...list.map(m => ({
      id: m.id,
      object: 'model',
      created: 0,
      owned_by: m.backend,
      rank: m.rank,
      context_length: m.contextLength,
      modality: m.modality,
      supports_tools: m.supportsTools,
      supports_reasoning: m.supportsReasoning,
      requires_signup: m.requiresSignup,
      latency_ms: m.latencyMs,
      rate_limit: m.rateLimit,
    })),
  ];
  return { object: 'list', data };
}

const server = http.createServer(async (req, res) => {
  const u = new URL(req.url || '/', `http://${HOST}:${PORT}`);
  if (req.method === 'GET' && u.pathname === '/health') {
    return sendJson(res, 200, registry.summary());
  }
  if (req.method === 'GET' && u.pathname === '/v1/models') {
    const includeAll = u.searchParams.get('all') === '1';
    return sendJson(res, 200, formatOpenAIModels(includeAll));
  }
  if (req.method === 'GET' && u.pathname === '/catalog') {
    const stripSecrets = registry.models.map(({ upstreamHeaders, ...rest }) => rest);
    return sendJson(res, 200, { ...registry.summary(), models: stripSecrets });
  }
  if (req.method === 'POST' && u.pathname === '/refresh') {
    const sync = u.searchParams.get('wait') === '1';
    if (sync) {
      return sendJson(res, 200, await registry.refresh());
    }
    registry.refresh().catch(() => {});
    return sendJson(res, 202, { started: true, ...registry.summary() });
  }
  if (req.method === 'POST' && u.pathname === '/v1/chat/completions') {
    return handleChatCompletions(req, res);
  }
  return sendJson(res, 404, { error: { message: `Not found: ${req.method} ${u.pathname}` } });
});

server.listen(PORT, HOST, () => {
  console.log(`awesome-free-llm-apis gateway listening on http://${HOST}:${PORT} (refresh every ${Math.round(REFRESH_INTERVAL_MS / 1000)}s)`);
  const ageMs = registry.lastRefreshAt ? (Date.now() - Date.parse(registry.lastRefreshAt)) : Infinity;
  if (!registry.models.length || ageMs > REFRESH_INTERVAL_MS) {
    registry.refresh().catch(err => console.error('Initial refresh error:', err));
  }
  const timer = setInterval(() => {
    registry.refresh().catch(err => console.error('Periodic refresh error:', err));
  }, REFRESH_INTERVAL_MS);
  timer.unref();
});
