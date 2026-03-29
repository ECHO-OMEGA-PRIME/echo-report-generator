/**
 * ECHO Report Generator — GOLD Doctrine → Professional PDF Reports
 * v1.0.0 | Cloudflare Worker
 *
 * Transforms Engine Runtime GOLD doctrine query results into
 * professional, branded, downloadable PDF reports.
 *
 * Pipeline: Sentinel UI → Engine Runtime /query/expert → This Worker → Branded HTML → PDF (client-side html2pdf.js)
 *
 * Endpoints:
 *   POST /report/generate   — Generate a report from query + doctrine results
 *   GET  /report/:token      — View a generated report (public, token-based)
 *   GET  /report/:token/raw  — Get raw JSON of report data
 *   POST /report/from-query  — Full pipeline: accepts query, calls Engine Runtime, generates report
 *   GET  /reports            — List reports (auth required)
 *   DELETE /report/:id       — Delete a report (auth required)
 *   GET  /health             — Health check
 */

import { Hono } from 'hono';
import { cors } from 'hono/cors';

const ALLOWED_ORIGINS = ['https://echo-ept.com','https://www.echo-ept.com','https://echo-op.com','https://profinishusa.com','https://bgat.echo-op.com'];

// ═══════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════

interface Env {
  DB: D1Database;
  R2: R2Bucket;
  ENGINE_RUNTIME: Fetcher;
  SHARED_BRAIN: Fetcher;
  ECHO_API_KEY?: string;
  ENVIRONMENT?: string;
}

interface DoctrineMatch {
  topic: string;
  conclusion: string;
  reasoning?: string;
  confidence: number | string;
  score: number;
  domain: string;
  engine_id: string;
  zone?: string;
  burden_holder?: string;
  adversary_position?: string;
  counter_arguments?: string[];
  resolution_strategy?: string;
  authorities?: Array<{ authority?: string; reference?: string; relevance?: string; citation?: string; type?: string; weight?: string }>;
  key_factors?: string[];
  controlling_precedent?: string;
  related_doctrines?: string[];
  entity_scope?: string[];
  cross_domain_routes?: string[];
}

interface DomainRanking {
  domain: string;
  label?: string;
  matches: number;
  top_score: number;
}

interface EngineExpertAnswer {
  conclusion: string;
  confidence: string;
  domain_analysis?: Array<{ domain: string; finding: string; key_doctrines: string[]; authorities: string[] }>;
  reasoning_chain: Array<{ step: number; domain?: string; analysis: string; doctrine_source: string; authority: string }>;
  cross_domain_synthesis?: string;
  authorities_cited: Array<{ citation: string; type: string; domain?: string; weight: string; from_doctrine: string }>;
  adversary_position: string;
  counter_arguments?: string[];
  appeals_strategy: string;
  risk_assessment?: string;
  action_items?: string[];
  further_analysis_needed?: string[];
  burden_of_proof?: { holder: string; standard: string; key_evidence_needed: string };
  limitations?: string;
  doctrines_consulted: Array<string | { topic: string; domain: string; engine: string }>;
}

interface EngineQueryResult {
  ok: boolean;
  mode: string;
  query: string;
  answer?: EngineExpertAnswer;
  results?: DoctrineMatch[];
  domain_ranking?: DomainRanking[];
  total_matches?: number;
  total_doctrines_searched?: number;
  response_ms?: number;
  determinism_hash?: string;
  audit_trail?: Record<string, unknown>;
}

interface ReportRequest {
  query: string;
  mode?: 'FAST' | 'DEFENSE' | 'MEMO';
  domain?: string;
  domains?: string[];
  engine_result?: EngineQueryResult;
  client_name?: string;
  client_email?: string;
  matter_reference?: string;
  preparer_name?: string;
  firm_name?: string;
  firm_logo_url?: string;
  custom_branding?: {
    primary_color?: string;
    accent_color?: string;
    logo_url?: string;
    company_name?: string;
    tagline?: string;
  };
}

// ═══════════════════════════════════════════════
// APP SETUP
// ═══════════════════════════════════════════════

const app = new Hono<{ Bindings: Env }>();
app.use('*', cors({ origin: (o) => ALLOWED_ORIGINS.includes(o) ? o : ALLOWED_ORIGINS[0], allowMethods: ['GET', 'POST', 'DELETE', 'OPTIONS'], allowHeaders: ['Content-Type', 'X-Echo-API-Key', 'Authorization'] }));
// Security headers middleware
app.use('*', async (c, next) => {
  await next();
  c.res.headers.set('X-Content-Type-Options', 'nosniff');
  c.res.headers.set('X-Frame-Options', 'DENY');
  c.res.headers.set('X-XSS-Protection', '1; mode=block');
  c.res.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  c.res.headers.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
});


function uid(): string { return crypto.randomUUID().replace(/-/g, '').slice(0, 20); }
function esc(s: string): string { return (s || '').replace(/[<>&"']/g, c => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;', "'": '&#39;' }[c] || c)); }

function requireAuth(c: any): Response | null {
  const key = c.req.header('X-Echo-API-Key') || c.req.header('Authorization')?.replace('Bearer ', '');
  if (!key || (c.env.ECHO_API_KEY && key !== c.env.ECHO_API_KEY)) {
    return c.json({ error: 'Unauthorized' }, 401);
  }
  return null;
}

// ═══════════════════════════════════════════════
// SCHEMA INIT
// ═══════════════════════════════════════════════

let schemaReady = false;
async function ensureSchema(db: D1Database) {
  if (schemaReady) return;
  try {
    await db.exec(`CREATE TABLE IF NOT EXISTS reports (id TEXT PRIMARY KEY, view_token TEXT NOT NULL, query TEXT NOT NULL, mode TEXT NOT NULL DEFAULT 'DEFENSE', domain TEXT, domains_analyzed TEXT, client_name TEXT, client_email TEXT, matter_reference TEXT, preparer_name TEXT, firm_name TEXT, r2_key TEXT NOT NULL, total_doctrines INTEGER DEFAULT 0, total_authorities INTEGER DEFAULT 0, confidence TEXT, response_ms INTEGER, metadata TEXT, created_at TEXT DEFAULT (datetime('now')), expires_at TEXT, view_count INTEGER DEFAULT 0, download_count INTEGER DEFAULT 0)`);
    await db.exec(`CREATE TABLE IF NOT EXISTS report_events (id TEXT PRIMARY KEY, report_id TEXT NOT NULL, event_type TEXT NOT NULL, ip_hash TEXT, user_agent TEXT, created_at TEXT DEFAULT (datetime('now')))`);
    await db.exec(`CREATE INDEX IF NOT EXISTS idx_reports_token ON reports(view_token)`);
    await db.exec(`CREATE INDEX IF NOT EXISTS idx_reports_created ON reports(created_at)`);
    await db.exec(`CREATE INDEX IF NOT EXISTS idx_events_report ON report_events(report_id)`);
    schemaReady = true;
  } catch {}
}

// ═══════════════════════════════════════════════
// HEALTH
// ═══════════════════════════════════════════════

app.get("/", (c) => c.json({ service: 'echo-report-generator', status: 'operational' }));

app.get('/health', async (c) => {
  let dbOk = false;
  try { await c.env.DB.prepare('SELECT 1').first(); dbOk = true; } catch {}
  return c.json({
    status: dbOk ? 'healthy' : 'degraded',
    service: 'echo-report-generator',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    db: dbOk,
  });
});

// ═══════════════════════════════════════════════
// CHAT INTEGRATION: Domain Detection + Auto-Report
// Any chat widget (Echo Chat, Sentinel, embeds) calls this
// to determine if a query should trigger engine doctrine lookup
// ═══════════════════════════════════════════════

const DOMAIN_PATTERNS: [RegExp, string, string][] = [
  // [regex, domain_code, human_label]
  [/\b(tax|irs|irc|1031|1040|deduct|deprec|macrs|gilti|subpart\s?f|cfc|pfic|fdii|beat|tcja|amt|estate\s*tax|gift\s*tax|partnership|s.?corp|llc\s*tax|k-?1|schedule\s*[a-z]|section\s*\d{2,4}|capital\s*gain|passive\s*(loss|income|activit)|like.?kind|opportunity\s*zone|qbi|199a|bonus\s*deprec|cost\s*segreg|r&d\s*credit|erc|salt|withhold|w-?[249]|1099|estimated\s*tax|audit|examiner|revenue\s*rul|treasury\s*reg)\b/i, 'TAX', 'Tax & IRS'],
  [/\b(title\s*chain|mineral\s*right|royalt|lease\s*(hold|termina|analy)|deed|survey|abstract|chain\s*of\s*title|conveyance|easement|right.?of.?way|psl|pooling|spacing|unit\s*agree|surface\s*use|curative|run\s*sheet|title\s*opinion|landman|division\s*order)\b/i, 'LM', 'Landman & Title'],
  [/\b(contract|litigation|lawsuit|tort|negligence|breach|fiduciary|statute\s*of\s*limit|injunction|deposition|discovery|summary\s*judgment|class\s*action|arbitrat|mediat|intellect\s*property|trademark|patent|copyright|regulat\s*compli|hipaa|gdpr|aml|kyc|securities|antitrust|employment\s*law|wrongful\s*terminat|bankruptcy|foreclosure)\b/i, 'LG', 'Legal'],
  [/\b(cyber|malware|ransomware|phishing|pentest|penetration\s*test|vulnerability|cve|exploit|firewall|ids|ips|siem|soc|incident\s*response|threat\s*(hunt|intel)|nist|iso\s*27|pci.?dss|zero.?day|buffer\s*overflow|sql\s*inject|xss|csrf|ddos|encryption)\b/i, 'CYBER', 'Cybersecurity'],
  [/\b(medical|clinical|diagnosis|symptom|treatment|pharma|drug\s*interact|dosage|pathology|radiology|oncology|cardiology|neurology|surgery|anesthesia|icd-?\d|cpt\s*code|patient|prescri|lab\s*result|blood\s*test|mri|ct\s*scan|prognosis)\b/i, 'MED', 'Medical'],
  [/\b(drill|completion|fracking|frac|wellbore|casing|cement|mud\s*weight|bop|psi|production|artificial\s*lift|esp|rod\s*pump|gas\s*lift|rrc|railroad\s*commission|p&a|workover|perfora|tubing|annul|spud|deviation|horizontal\s*well)\b/i, 'DRL', 'Drilling & Oil/Gas'],
  [/\b(mechanical\s*engineer|structural|stress\s*analy|finite\s*element|fea|cfd|thermodynamic|fluid\s*mechanic|heat\s*transfer|vibrat\s*analy|fatigue|tolerance|gd&t|materials?\s*science|metallurg|weld|cnc|machin|manufactur)\b/i, 'MECH', 'Engineering'],
  [/\b(portfolio|stock|bond|option|derivative|hedge|valuation|dcf|wacc|capm|balance\s*sheet|income\s*statement|cash\s*flow|ebitda|p\/e\s*ratio|market\s*cap|ipo|merger|acquisit|private\s*equity|venture\s*capital|mutual\s*fund|etf|interest\s*rate)\b/i, 'FIN', 'Finance'],
  [/\b(real\s*estate|property\s*law|zoning|eminent\s*domain|property\s*tax|mortgage|title\s*insurance|closing|escrow|appraisal|comps|cap\s*rate|noi|reit|tenant|landlord|commercial\s*property|residential|1031\s*exchange)\b/i, 'RE', 'Real Estate'],
  [/\b(software\s*architect|microservice|kubernetes|docker|ci\/cd|devops|cloud\s*native|serverless|api\s*design|database\s*design|system\s*design|scalab|load\s*balanc|caching|message\s*queue|event\s*driven)\b/i, 'DEVOPS', 'Software & DevOps'],
  [/\b(nuclear|renewable|solar\s*panel|wind\s*turbine|energy\s*grid|power\s*plant|transmission|distribution|battery\s*storage|ev\s*charg|smart\s*grid|ferc|nerc|utility|kilowatt|megawatt)\b/i, 'ENRG', 'Energy'],
  [/\b(bitcoin|ethereum|blockchain|defi|smart\s*contract|solidity|nft|token|staking|liquidity\s*pool|dex|cex|wallet|web3|dao|consensus|proof\s*of\s*(work|stake))\b/i, 'CRYPTO', 'Crypto & Blockchain'],
  [/\b(accounting|gaap|ifrs|audit|cpa|financial\s*statement|journal\s*entry|ledger|accrual|revenue\s*recogn|asc\s*\d{3}|sox|internal\s*control|materiality|going\s*concern)\b/i, 'ACCT', 'Accounting'],
  [/\b(aviation|faa|airworthiness|turbine|aircraft|aerodynamic|flight\s*plan|pilot|atc|ntsb|airspace|runway|avionics)\b/i, 'AERO', 'Aviation & Aerospace'],
  [/\b(automotive|vehicle|engine\s*repair|transmission|brake|suspension|obd|emission|ase\s*cert|recall|nhtsa|fuel\s*system|hybrid|electric\s*vehicle)\b/i, 'AUTO', 'Automotive'],
  [/\b(chemical|reaction|compound|polymer|catalyst|distillation|corrosion|hazmat|msds|sds|osha\s*chemical|nfpa|process\s*safety)\b/i, 'CHEM', 'Chemical'],
  [/\b(marine|vessel|maritime|admiralty|cargo|shipping|port|anchor|navigation|imo|solas|marpol|offshore\s*platform)\b/i, 'MARINE', 'Marine & Maritime'],
  [/\b(construction|building\s*code|ibc|concrete|steel\s*struct|plumbing|hvac|electrical\s*code|nec|permit|general\s*contract|subcontract|lien|bond\s*claim)\b/i, 'CONST', 'Construction'],
  [/\b(insurance|claim|underwrite|premium|coverage|exclusion|liability|indemnit|subrogat|deductible|policy\s*limit|bad\s*faith|adjuster)\b/i, 'INS', 'Insurance'],
  [/\b(pipeline|midstream|transmission\s*line|compressor|pig|corrosion\s*protect|phmsa|dot\s*regul|scada|metering|custody\s*transfer)\b/i, 'PIPE', 'Pipeline & Midstream'],
];

// Intent patterns that signal "I need an expert answer" vs casual chat
const EXPERT_INTENT_PATTERNS = [
  /\b(how\s+(do|does|should|would|can|to)|what\s+(is|are|does|happens|if)|when\s+(should|do|does|can)|why\s+(is|are|does|do)|explain|analyze|calculate|determine|evaluate|assess|compare|advise|recommend|strategy|risk|penalty|comply|complian|regulat|statute|standard|code\s*section|procedure|protocol|best\s*practice|requirement|obligation)\b/i,
  /\b(what\s+are\s+the\s+(tax|legal|regulat|compli)|how\s+to\s+(handle|treat|report|file|claim|defend|mitigat|avoid)|can\s+(i|we|they)\s+(deduct|claim|offset|appeal|challenge))\b/i,
  /\b(irs|court|judge|examiner|inspector|auditor|regulator|opponent|plaintiff|defendant|prosecutor)\b/i,
  /\?\s*$/,  // ends with question mark
];

app.post('/chat/should-query-engine', async (c) => {
  const body = await c.req.json() as { message: string; context?: string };
  if (!body.message) return c.json({ error: 'message required' }, 400);

  const msg = body.message;
  const q = msg.toLowerCase();

  // Step 1: Detect domain(s)
  const detectedDomains: { code: string; label: string }[] = [];
  for (const [regex, code, label] of DOMAIN_PATTERNS) {
    if (regex.test(q)) {
      detectedDomains.push({ code, label });
    }
  }

  // Step 2: Check expert intent
  let expertIntent = false;
  for (const pattern of EXPERT_INTENT_PATTERNS) {
    if (pattern.test(msg)) {
      expertIntent = true;
      break;
    }
  }

  // Step 3: Determine if engine query is warranted
  const shouldQuery = detectedDomains.length > 0 && (expertIntent || msg.length > 40);
  const suggestReport = shouldQuery && (msg.length > 60 || detectedDomains.length >= 2 || /\b(report|analysis|memo|defense|strategy|comprehensive|detailed|full)\b/i.test(q));

  // Step 4: Recommend mode
  let recommendedMode: 'FAST' | 'DEFENSE' | 'MEMO' = 'FAST';
  if (/\b(defend|defense|audit|appeal|litigation|dispute|challenge|opposition|adversar|counter.?arg|rebuttal)\b/i.test(q)) {
    recommendedMode = 'DEFENSE';
  } else if (/\b(memo|memorandum|report|comprehensive|detailed|full\s*analysis|document|brief|opinion\s*letter)\b/i.test(q)) {
    recommendedMode = 'MEMO';
  } else if (suggestReport) {
    recommendedMode = 'DEFENSE';
  }

  return c.json({
    should_query_engine: shouldQuery,
    suggest_report: suggestReport,
    detected_domains: detectedDomains,
    primary_domain: detectedDomains[0]?.code || null,
    recommended_mode: recommendedMode,
    expert_intent: expertIntent,
    confidence: shouldQuery ? (detectedDomains.length >= 2 ? 'high' : expertIntent ? 'high' : 'moderate') : 'low',
    // Pre-built engine query body for the caller to use
    engine_query: shouldQuery ? {
      query: msg,
      domains: detectedDomains.map(d => d.code),
      mode: recommendedMode,
      limit: 20,
    } : null,
    // Pre-built report request for the caller to use
    report_request: suggestReport ? {
      query: msg,
      mode: recommendedMode,
      domains: detectedDomains.map(d => d.code),
    } : null,
  });
});

// Batch classify multiple messages (for chat history analysis)
app.post('/chat/classify-batch', async (c) => {
  const body = await c.req.json() as { messages: string[] };
  if (!body.messages?.length) return c.json({ error: 'messages[] required' }, 400);

  const results = body.messages.slice(0, 50).map(msg => {
    const q = msg.toLowerCase();
    const domains: string[] = [];
    for (const [regex, code] of DOMAIN_PATTERNS) {
      if (regex.test(q)) domains.push(code);
    }
    return { message: msg.slice(0, 100), domains, has_expert_intent: EXPERT_INTENT_PATTERNS.some(p => p.test(msg)) };
  });

  return c.json({ ok: true, results, total: results.length });
});

// ═══════════════════════════════════════════════
// FULL PIPELINE: Query → Engine Runtime → Report
// ═══════════════════════════════════════════════

app.post('/report/from-query', async (c) => {
  await ensureSchema(c.env.DB);
  const body: ReportRequest = await c.req.json();
  if (!body.query) return c.json({ error: 'query required' }, 400);

  const mode = body.mode || 'DEFENSE';
  const startTime = Date.now();

  // Step 1: Query Engine Runtime (service binding → fallback to public URL)
  let engineResult: EngineQueryResult | null = null;
  const engineBody: Record<string, unknown> = {
    query: body.query,
    limit: 20,
    mode: mode,
  };
  if (body.domains?.length) engineBody.domains = body.domains;
  if (body.domain) engineBody.domain = body.domain;

  // Use /query for pure doctrine matching (fast, deterministic, no LLM needed)
  // The doctrine IS the answer — Commander's rule.
  const endpoint = mode === 'MEMO' ? '/query/expert' : '/query';

  try {
    // Service binding for internal Worker-to-Worker call
    const resp = await c.env.ENGINE_RUNTIME.fetch(new Request(`https://engine${endpoint}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(engineBody),
    }));
    if (resp.ok) {
      engineResult = await resp.json() as EngineQueryResult;
    } else {
      const errText = await resp.text();
      return c.json({ error: 'Engine Runtime query failed', status: resp.status, details: errText }, 502);
    }
  } catch (err: any) {
    return c.json({ error: 'Engine Runtime unreachable', details: err.message }, 502);
  }

  // Step 2: Generate report
  try {
    return await generateReport(c, body, engineResult!, mode, startTime);
  } catch (err: any) {
    return c.json({ error: 'Report generation failed', details: err.message, stack: err.stack?.split('\n').slice(0, 5) }, 500);
  }
});

// ═══════════════════════════════════════════════
// GENERATE FROM PRE-FETCHED ENGINE RESULT
// ═══════════════════════════════════════════════

app.post('/report/generate', async (c) => {
  await ensureSchema(c.env.DB);
  const body: ReportRequest = await c.req.json();
  if (!body.query || !body.engine_result) return c.json({ error: 'query and engine_result required' }, 400);

  const mode = body.mode || 'DEFENSE';
  try {
    return await generateReport(c, body, body.engine_result, mode, Date.now());
  } catch (err: any) {
    return c.json({ error: 'Report generation failed', details: err.message }, 500);
  }
});

// ═══════════════════════════════════════════════
// VIEW REPORT (PUBLIC — TOKEN-BASED)
// ═══════════════════════════════════════════════

app.get('/report/:token', async (c) => {
  await ensureSchema(c.env.DB);
  const token = c.req.param('token');
  const report = await c.env.DB.prepare('SELECT * FROM reports WHERE view_token = ?').bind(token).first() as any;
  if (!report) return c.html('<html><body style="font-family:sans-serif;text-align:center;padding:80px"><h1 style="color:#666">Report Not Found</h1><p>This report may have expired or been removed.</p></body></html>', 404);

  // Track view
  const evtId = uid();
  const ip = c.req.header('CF-Connecting-IP') || 'unknown';
  const ipHash = await hashStr(ip);
  await c.env.DB.prepare("INSERT INTO report_events (id, report_id, event_type, ip_hash, user_agent, created_at) VALUES (?,?,?,?,?,datetime('now'))").bind(evtId, report.id, 'view', ipHash, (c.req.header('User-Agent') || '').slice(0, 200)).run();
  await c.env.DB.prepare('UPDATE reports SET view_count = view_count + 1 WHERE id = ?').bind(report.id).run();

  // Load HTML from R2
  const obj = await c.env.R2.get(report.r2_key);
  if (!obj) return c.html('<html><body style="font-family:sans-serif;text-align:center;padding:80px"><h1 style="color:#666">Report Expired</h1></body></html>', 404);
  const html = await obj.text();

  return c.html(html);
});

// ═══════════════════════════════════════════════
// RAW JSON
// ═══════════════════════════════════════════════

app.get('/report/:token/raw', async (c) => {
  await ensureSchema(c.env.DB);
  const token = c.req.param('token');
  const report = await c.env.DB.prepare('SELECT * FROM reports WHERE view_token = ?').bind(token).first() as any;
  if (!report) return c.json({ error: 'Not found' }, 404);
  let metadata = {};
  try { metadata = JSON.parse(report.metadata || '{}'); } catch {}
  return c.json({ ...report, metadata });
});

// ═══════════════════════════════════════════════
// LIST REPORTS (AUTH)
// ═══════════════════════════════════════════════

app.get('/reports', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  await ensureSchema(c.env.DB);

  const limit = Math.min(parseInt(c.req.query('limit') || '50'), 100);
  const offset = parseInt(c.req.query('offset') || '0');
  const rows = await c.env.DB.prepare('SELECT id, view_token, query, mode, domain, domains_analyzed, client_name, matter_reference, confidence, total_doctrines, total_authorities, response_ms, created_at, view_count, download_count FROM reports ORDER BY created_at DESC LIMIT ? OFFSET ?').bind(limit, offset).all();
  const count = await c.env.DB.prepare('SELECT COUNT(*) as c FROM reports').first() as any;
  return c.json({ ok: true, reports: rows.results, total: count?.c || 0, limit, offset });
});

// ═══════════════════════════════════════════════
// DELETE REPORT (AUTH)
// ═══════════════════════════════════════════════

app.delete('/report/:id', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  await ensureSchema(c.env.DB);

  const id = c.req.param('id');
  const report = await c.env.DB.prepare('SELECT r2_key FROM reports WHERE id = ?').bind(id).first() as any;
  if (!report) return c.json({ error: 'Not found' }, 404);

  await c.env.R2.delete(report.r2_key);
  await c.env.DB.prepare('DELETE FROM report_events WHERE report_id = ?').bind(id).run();
  await c.env.DB.prepare('DELETE FROM reports WHERE id = ?').bind(id).run();
  return c.json({ ok: true, deleted: id });
});

// ═══════════════════════════════════════════════
// CORE: GENERATE REPORT
// ═══════════════════════════════════════════════

async function generateReport(c: any, req: ReportRequest, engineResult: EngineQueryResult, mode: string, startTime: number) {
  const reportId = uid();
  const viewToken = crypto.randomUUID();
  const now = new Date();
  const dateStr = now.toISOString().split('T')[0];
  const timeStr = now.toISOString().split('T')[1].split('.')[0];

  // Extract data from engine result — /query returns results[] or analysis.matches[], /query/expert returns answer{}
  const answer = engineResult.answer;
  // Engine Runtime /query with domain returns results under 'analysis' or 'results'
  const rawResults = engineResult.results
    || (engineResult as any).analysis?.matches
    || (engineResult as any).matches
    || [];
  const doctrines: DoctrineMatch[] = rawResults.map((r: any) => ({
    topic: r.topic || r.doctrine_key || 'Unknown',
    conclusion: r.conclusion || r.conclusion_template || '',
    reasoning: r.reasoning || r.reasoning_framework || '',
    confidence: r.confidence || 0,
    score: r.score || r.relevance_score || 0,
    domain: r.domain || (engineResult as any).domain || '',
    engine_id: r.engine_id || r.source_engine || '',
    zone: r.zone || '',
    burden_holder: r.burden_holder || '',
    adversary_position: r.adversary_position || r.irs_typical_position || '',
    counter_arguments: r.counter_arguments || [],
    resolution_strategy: r.resolution_strategy || r.appeals_strategy || '',
    authorities: r.authorities || r.primary_authority || [],
    key_factors: r.key_factors || [],
    controlling_precedent: r.controlling_precedent || '',
    related_doctrines: r.related_doctrines || [],
    entity_scope: r.entity_scope || [],
    cross_domain_routes: r.cross_domain_routes || [],
  }));
  const domainRanking = engineResult.domain_ranking || [];
  // For single-domain responses, construct domain from the response
  const singleDomain = (engineResult as any).domain_label || (engineResult as any).domain || '';
  const domainsAnalyzed = domainRanking.length > 0
    ? domainRanking.map(d => d.label || d.domain).join(', ')
    : singleDomain;

  // Build a synthetic answer from doctrine results when /query was used (no LLM answer)
  const topDoctrine = doctrines[0];
  const synthesizedConclusion = answer?.conclusion
    || (topDoctrine ? topDoctrine.conclusion : 'No matching doctrines found for this query.');
  const synthesizedAdversary = answer?.adversary_position
    || doctrines.map(d => d.adversary_position).filter(Boolean)[0] || '';
  const synthesizedAppeals = answer?.appeals_strategy
    || doctrines.map(d => d.resolution_strategy).filter(Boolean)[0] || '';
  const synthesizedCounterArgs = answer?.counter_arguments
    || doctrines.flatMap(d => d.counter_arguments || []).slice(0, 6);
  const synthesizedBurden = answer?.burden_of_proof
    || (topDoctrine?.burden_holder ? { holder: topDoctrine.burden_holder, standard: 'preponderance', key_evidence_needed: 'Documentation and substantiation of position' } : undefined);

  // Collect ALL authorities from ALL matched doctrines
  const allAuthorities = [
    ...(answer?.authorities_cited || []),
    ...doctrines.flatMap(d => (d.authorities || []).map(a => ({
      citation: a.reference || a.citation || '',
      type: a.authority || a.type || 'STANDARD',
      weight: a.weight || 'SUPPORTING',
      domain: d.domain,
      from_doctrine: d.topic,
    }))),
  ];
  const uniqueAuthorities = [...new Set(allAuthorities.map(a => a.citation).filter(Boolean))];

  // Deduplicate authorities by citation
  const seenCitations = new Set<string>();
  const dedupedAuthorities = allAuthorities.filter(a => {
    if (!a.citation || seenCitations.has(a.citation)) return false;
    seenCitations.add(a.citation);
    return true;
  });

  // Branding
  const brand = req.custom_branding || {};
  const primaryColor = brand.primary_color || '#1E3A5F';
  const accentColor = brand.accent_color || '#C49A6C';
  const companyName = brand.company_name || req.firm_name || 'ECHO PRIME';
  const tagline = brand.tagline || 'Intelligence Engine';
  const logoUrl = brand.logo_url || '';

  // Confidence mapping
  const rawConfidence = answer?.confidence || topDoctrine?.confidence || 'DEFENSIBLE';
  const confidenceLabel = typeof rawConfidence === 'object'
    ? ((rawConfidence as any).label || (rawConfidence as any).level || 'DEFENSIBLE')
    : String(rawConfidence);
  const confidenceColor = confidenceLabel === 'DEFENSIBLE' ? '#059669' : confidenceLabel === 'AGGRESSIVE_SUPPORTABLE' ? '#D97706' : confidenceLabel === 'DISCLOSURE_RECOMMENDED' ? '#DC2626' : '#7C3AED';

  // Build the HTML report
  const html = buildReportHTML({
    reportId,
    dateStr,
    timeStr,
    query: req.query,
    mode,
    clientName: req.client_name,
    clientEmail: req.client_email,
    matterRef: req.matter_reference,
    preparerName: req.preparer_name,
    companyName,
    tagline,
    logoUrl,
    primaryColor,
    accentColor,
    confidenceLabel,
    confidenceColor,
    domainsAnalyzed,
    conclusion: synthesizedConclusion,
    domainAnalysis: answer?.domain_analysis || [],
    reasoningChain: answer?.reasoning_chain || [],
    crossDomainSynthesis: answer?.cross_domain_synthesis || '',
    authorities: uniqueAuthorities,
    authoritiesFull: dedupedAuthorities,
    adversaryPosition: synthesizedAdversary,
    counterArguments: synthesizedCounterArgs,
    appealsStrategy: synthesizedAppeals,
    burdenOfProof: synthesizedBurden,
    riskAssessment: answer?.risk_assessment || '',
    actionItems: answer?.action_items || [],
    furtherAnalysis: answer?.further_analysis_needed || [],
    limitations: answer?.limitations || '',
    doctrines,
    domainRanking,
    totalMatches: engineResult.total_matches || doctrines.length,
    totalSearched: engineResult.total_doctrines_searched || 0,
    engineResponseMs: engineResult.response_ms || 0,
    determinismHash: engineResult.determinism_hash || '',
    auditTrail: engineResult.audit_trail,
  });

  // Store to R2
  const r2Key = `reports/${now.getFullYear()}/${String(now.getMonth() + 1).padStart(2, '0')}/${reportId}.html`;
  await c.env.R2.put(r2Key, html, { httpMetadata: { contentType: 'text/html' } });

  // Store to D1
  const responseMs = Date.now() - startTime;
  await c.env.DB.prepare(
    `INSERT INTO reports (id, view_token, query, mode, domain, domains_analyzed, client_name, client_email, matter_reference, preparer_name, firm_name, r2_key, total_doctrines, total_authorities, confidence, response_ms, metadata, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,datetime('now'))`
  ).bind(
    reportId, viewToken, req.query, mode,
    req.domain || domainRanking[0]?.domain || '',
    domainsAnalyzed,
    req.client_name || '', req.client_email || '',
    req.matter_reference || '', req.preparer_name || '',
    req.firm_name || companyName,
    r2Key,
    doctrines.length,
    uniqueAuthorities.length,
    confidenceLabel,
    responseMs,
    JSON.stringify({ engine_mode: engineResult.mode, determinism_hash: engineResult.determinism_hash }),
  ).run();

  // Brain ingest
  try {
    await c.env.SHARED_BRAIN.fetch('https://brain/ingest', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        instance_id: 'echo-report-generator',
        role: 'assistant',
        content: `REPORT GENERATED: "${req.query}" → ${mode} mode, ${doctrines.length} doctrines, ${uniqueAuthorities.length} authorities, confidence: ${confidenceLabel}, ${responseMs}ms`,
        importance: 5,
        tags: ['report', 'sentinel', mode.toLowerCase()],
      }),
    });
  } catch {}

  const viewUrl = `${new URL(c.req.url).origin}/report/${viewToken}`;

  return c.json({
    ok: true,
    report_id: reportId,
    view_token: viewToken,
    view_url: viewUrl,
    mode,
    confidence: confidenceLabel,
    total_doctrines: doctrines.length,
    total_authorities: uniqueAuthorities.length,
    domains_analyzed: domainsAnalyzed,
    response_ms: responseMs,
  });
}

// ═══════════════════════════════════════════════
// HTML REPORT BUILDER — THE HEART OF THE SYSTEM
// ═══════════════════════════════════════════════

function buildReportHTML(opts: {
  reportId: string;
  dateStr: string;
  timeStr: string;
  query: string;
  mode: string;
  clientName?: string;
  clientEmail?: string;
  matterRef?: string;
  preparerName?: string;
  companyName: string;
  tagline: string;
  logoUrl: string;
  primaryColor: string;
  accentColor: string;
  confidenceLabel: string;
  confidenceColor: string;
  domainsAnalyzed: string;
  conclusion: string;
  domainAnalysis: Array<{ domain: string; finding: string; key_doctrines: string[]; authorities: string[] }>;
  reasoningChain: Array<{ step: number; domain?: string; analysis: string; doctrine_source: string; authority: string }>;
  crossDomainSynthesis: string;
  authorities: string[];
  authoritiesFull: Array<{ citation: string; type: string; domain?: string; weight: string; from_doctrine: string }>;
  adversaryPosition: string;
  counterArguments: string[];
  appealsStrategy: string;
  burdenOfProof?: { holder: string; standard: string; key_evidence_needed: string };
  riskAssessment: string;
  actionItems: string[];
  furtherAnalysis: string[];
  limitations: string;
  doctrines: DoctrineMatch[];
  domainRanking: DomainRanking[];
  totalMatches: number;
  totalSearched: number;
  engineResponseMs: number;
  determinismHash: string;
  auditTrail?: Record<string, unknown>;
}): string {
  const o = opts;
  const modeLabel = o.mode === 'MEMO' ? 'Professional Memorandum' : o.mode === 'DEFENSE' ? 'Defense Analysis Report' : 'Quick Analysis Summary';
  const modeDesc = o.mode === 'MEMO'
    ? 'This memorandum provides a comprehensive, firm-ready analysis with full citation table, burden analysis, and appeals strategy.'
    : o.mode === 'DEFENSE'
    ? 'This defense report includes adversary position analysis, counter-arguments, and recommended defense strategy.'
    : 'This summary provides key findings and top authorities for quick reference.';

  // ── Authority table rows
  const authorityRows = o.authoritiesFull.map((a, i) => `
    <tr>
      <td style="padding:8px 12px;border-bottom:1px solid #E5E7EB;font-size:12px;font-weight:600">${i + 1}</td>
      <td style="padding:8px 12px;border-bottom:1px solid #E5E7EB;font-size:12px">${esc(a.citation)}</td>
      <td style="padding:8px 12px;border-bottom:1px solid #E5E7EB;font-size:11px;text-transform:uppercase;color:#6B7280">${esc(a.type)}</td>
      <td style="padding:8px 12px;border-bottom:1px solid #E5E7EB;font-size:11px">
        <span style="padding:2px 8px;border-radius:4px;font-size:10px;font-weight:600;background:${a.weight === 'PRIMARY' ? '#DCFCE7' : a.weight === 'SUPPORTING' ? '#FEF3C7' : '#E0E7FF'};color:${a.weight === 'PRIMARY' ? '#166534' : a.weight === 'SUPPORTING' ? '#92400E' : '#3730A3'}">${esc(a.weight)}</span>
      </td>
      <td style="padding:8px 12px;border-bottom:1px solid #E5E7EB;font-size:11px;color:#6B7280">${esc(a.domain || '')}</td>
      <td style="padding:8px 12px;border-bottom:1px solid #E5E7EB;font-size:11px;color:#6B7280">${esc(a.from_doctrine)}</td>
    </tr>`).join('');

  // ── Reasoning chain rows
  const reasoningRows = o.reasoningChain.map(r => `
    <div style="display:flex;gap:12px;padding:12px 0;border-bottom:1px solid #F3F4F6">
      <div style="flex-shrink:0;width:28px;height:28px;border-radius:50%;background:${o.primaryColor};color:#fff;display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:700">${r.step}</div>
      <div style="flex:1">
        ${r.domain ? `<span style="font-size:10px;background:${o.primaryColor}15;color:${o.primaryColor};padding:2px 6px;border-radius:3px;font-weight:600;text-transform:uppercase;margin-bottom:4px;display:inline-block">${esc(r.domain)}</span>` : ''}
        <p style="font-size:13px;color:#374151;margin:4px 0;line-height:1.6">${esc(r.analysis)}</p>
        <div style="font-size:11px;color:#6B7280;margin-top:4px">
          <span style="font-weight:600">Source:</span> ${esc(r.doctrine_source)} &nbsp;|&nbsp; <span style="font-weight:600">Authority:</span> ${esc(r.authority)}
        </div>
      </div>
    </div>`).join('');

  // ── Domain analysis sections
  const domainSections = o.domainAnalysis.map(da => `
    <div style="margin-bottom:16px;padding:16px;background:#F9FAFB;border-radius:8px;border-left:4px solid ${o.primaryColor}">
      <h4 style="margin:0 0 8px;font-size:14px;color:${o.primaryColor};font-weight:700">${esc(da.domain)}</h4>
      <p style="font-size:13px;color:#374151;line-height:1.6;margin:0 0 8px">${esc(da.finding)}</p>
      ${da.key_doctrines?.length ? `<div style="font-size:11px;color:#6B7280"><strong>Key Doctrines:</strong> ${da.key_doctrines.map(d => esc(d)).join(', ')}</div>` : ''}
      ${da.authorities?.length ? `<div style="font-size:11px;color:#6B7280;margin-top:4px"><strong>Authorities:</strong> ${da.authorities.map(a => esc(a)).join('; ')}</div>` : ''}
    </div>`).join('');

  // ── Counter-arguments list
  const counterArgsList = o.counterArguments.map((ca, i) => `
    <div style="display:flex;gap:8px;padding:8px 0;border-bottom:1px solid #F3F4F6">
      <span style="flex-shrink:0;width:20px;height:20px;border-radius:50%;background:#DCFCE7;color:#166534;display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:700">${i + 1}</span>
      <p style="font-size:13px;color:#374151;margin:0;line-height:1.5">${esc(ca)}</p>
    </div>`).join('');

  // ── Action items
  const actionItemsList = o.actionItems.map(ai => `
    <div style="display:flex;gap:8px;padding:6px 0">
      <span style="color:${o.accentColor};font-size:14px">&#9654;</span>
      <p style="font-size:13px;color:#374151;margin:0">${esc(ai)}</p>
    </div>`).join('');

  // ── Doctrine detail cards
  const doctrineCards = o.doctrines.slice(0, 10).map((d, i) => {
    const confScore = typeof d.confidence === 'number' ? d.confidence : (d.confidence === 'high' ? 0.9 : d.confidence === 'moderate' ? 0.7 : 0.5);
    const confPct = Math.round((typeof d.score === 'number' ? d.score : confScore) * 100);
    return `
    <div style="margin-bottom:12px;padding:14px;border:1px solid #E5E7EB;border-radius:8px;page-break-inside:avoid">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
        <div>
          <span style="font-size:11px;background:${o.primaryColor}15;color:${o.primaryColor};padding:2px 8px;border-radius:4px;font-weight:600">#${i + 1}</span>
          <span style="font-size:13px;font-weight:700;color:#1F2937;margin-left:8px">${esc(d.topic)}</span>
        </div>
        <div style="display:flex;gap:8px;align-items:center">
          <span style="font-size:10px;color:#6B7280">${esc(d.engine_id)} · ${esc(d.domain)}</span>
          <span style="padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700;background:${confPct >= 80 ? '#DCFCE7' : confPct >= 60 ? '#FEF3C7' : '#FEE2E2'};color:${confPct >= 80 ? '#166534' : confPct >= 60 ? '#92400E' : '#991B1B'}">${confPct}%</span>
        </div>
      </div>
      <p style="font-size:12px;color:#374151;line-height:1.6;margin:0">${esc(d.conclusion)}</p>
      ${d.authorities?.length ? `<div style="margin-top:8px;font-size:11px;color:#6B7280"><strong>Authorities:</strong> ${d.authorities.map(a => esc(a.reference || a.citation || '')).filter(Boolean).join('; ')}</div>` : ''}
      ${d.burden_holder ? `<div style="font-size:11px;color:#6B7280;margin-top:4px"><strong>Burden:</strong> ${esc(d.burden_holder)}</div>` : ''}
    </div>`;
  }).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${esc(modeLabel)} | ${esc(o.companyName)}</title>
<link href="https://fonts.googleapis.com/css2?family=Merriweather:wght@400;700&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:"Inter",sans-serif;color:#1F2937;background:#fff;max-width:900px;margin:0 auto;line-height:1.6}
h1,h2,h3,h4{font-family:"Merriweather",serif}
@media print{
  body{-webkit-print-color-adjust:exact!important;print-color-adjust:exact!important;max-width:100%}
  .no-print{display:none!important}
  .page-break{page-break-before:always}
  @page{margin:0.5in 0.6in}
}
.toolbar{background:#F8FAFC;padding:12px 24px;display:flex;gap:10px;flex-wrap:wrap;align-items:center;border-bottom:1px solid #E2E8F0;position:sticky;top:0;z-index:100}
.toolbar button{padding:8px 16px;border:none;border-radius:6px;font-size:12px;font-weight:600;cursor:pointer;display:inline-flex;align-items:center;gap:6px;transition:all .15s}
.btn-print{background:${o.primaryColor};color:#fff}
.btn-pdf{background:#059669;color:#fff}
.btn-copy{background:#6366F1;color:#fff}
.section{padding:24px 40px}
.section-title{font-size:16px;font-weight:700;color:${o.primaryColor};text-transform:uppercase;letter-spacing:1px;padding-bottom:8px;border-bottom:2px solid ${o.primaryColor};margin-bottom:16px}
.confidence-badge{display:inline-block;padding:4px 12px;border-radius:6px;font-size:12px;font-weight:700;letter-spacing:0.5px}
</style>
<script src="https://cdnjs.cloudflare.com/ajax/libs/html2pdf.js/0.10.2/html2pdf.bundle.min.js"><\/script>
</head>
<body>

<!-- ═══ TOOLBAR (no-print) ═══ -->
<div class="toolbar no-print">
  <button class="btn-print" onclick="window.print()">&#128424; Print</button>
  <button class="btn-pdf" onclick="downloadPDF()">&#128196; Save PDF</button>
  <button class="btn-copy" onclick="copyText()">&#128203; Copy Text</button>
  <span style="margin-left:auto;font-size:11px;color:#6B7280">${esc(o.mode)} Report · ${esc(o.reportId)}</span>
</div>

<div id="reportContent">

<!-- ═══ COVER PAGE ═══ -->
<div style="padding:60px 40px;text-align:center;background:linear-gradient(135deg,${o.primaryColor} 0%,${o.primaryColor}DD 100%);color:#fff;min-height:280px;display:flex;flex-direction:column;justify-content:center">
  ${o.logoUrl ? `<img src="${esc(o.logoUrl)}" alt="Logo" style="max-height:60px;margin:0 auto 16px">` : ''}
  <h1 style="font-size:28px;margin-bottom:8px;letter-spacing:1px">${esc(o.companyName)}</h1>
  <p style="font-size:14px;opacity:0.8;letter-spacing:2px;text-transform:uppercase">${esc(o.tagline)}</p>
  <div style="width:60px;height:2px;background:${o.accentColor};margin:20px auto"></div>
  <h2 style="font-size:20px;margin-bottom:6px">${esc(modeLabel)}</h2>
  <p style="font-size:13px;opacity:0.7">${esc(o.dateStr)} · ${esc(o.timeStr)} UTC</p>
</div>

<!-- ═══ REPORT METADATA ═══ -->
<div style="padding:20px 40px;background:#F9FAFB;border-bottom:1px solid #E5E7EB;display:flex;flex-wrap:wrap;gap:20px;font-size:12px">
  ${o.clientName ? `<div><span style="color:#6B7280;font-weight:600">Client:</span> ${esc(o.clientName)}</div>` : ''}
  ${o.matterRef ? `<div><span style="color:#6B7280;font-weight:600">Matter:</span> ${esc(o.matterRef)}</div>` : ''}
  ${o.preparerName ? `<div><span style="color:#6B7280;font-weight:600">Prepared by:</span> ${esc(o.preparerName)}</div>` : ''}
  <div><span style="color:#6B7280;font-weight:600">Domains:</span> ${esc(o.domainsAnalyzed || 'Auto-detected')}</div>
  <div><span style="color:#6B7280;font-weight:600">Doctrines:</span> ${o.totalMatches} matched / ${o.totalSearched.toLocaleString()} searched</div>
  <div>
    <span style="color:#6B7280;font-weight:600">Confidence:</span>
    <span class="confidence-badge" style="background:${o.confidenceColor}15;color:${o.confidenceColor}">${esc(o.confidenceLabel)}</span>
  </div>
</div>

<!-- ═══ QUERY ═══ -->
<div class="section">
  <div class="section-title">Query</div>
  <div style="background:#F1F5F9;padding:16px;border-radius:8px;border-left:4px solid ${o.accentColor};font-size:14px;color:#1E293B;font-style:italic">"${esc(o.query)}"</div>
  <p style="font-size:12px;color:#6B7280;margin-top:8px">${esc(modeDesc)}</p>
</div>

<!-- ═══ EXECUTIVE SUMMARY ═══ -->
<div class="section" style="background:#FFFBEB;border-top:1px solid #FDE68A;border-bottom:1px solid #FDE68A">
  <div class="section-title" style="color:#92400E;border-color:#92400E">Executive Summary</div>
  <p style="font-size:14px;color:#1E293B;line-height:1.8">${esc(o.conclusion)}</p>
</div>

${o.mode !== 'FAST' && o.domainAnalysis.length > 0 ? `
<!-- ═══ DOMAIN ANALYSIS ═══ -->
<div class="section">
  <div class="section-title">Domain Analysis</div>
  ${domainSections}
</div>` : ''}

${o.mode !== 'FAST' && o.reasoningChain.length > 0 ? `
<!-- ═══ REASONING CHAIN ═══ -->
<div class="section page-break">
  <div class="section-title">Analytical Framework</div>
  <p style="font-size:12px;color:#6B7280;margin-bottom:12px">Step-by-step analysis with doctrine sources and controlling authorities.</p>
  ${reasoningRows}
</div>` : ''}

${o.crossDomainSynthesis ? `
<!-- ═══ CROSS-DOMAIN SYNTHESIS ═══ -->
<div class="section">
  <div class="section-title">Cross-Domain Synthesis</div>
  <p style="font-size:13px;color:#374151;line-height:1.7">${esc(o.crossDomainSynthesis)}</p>
</div>` : ''}

<!-- ═══ AUTHORITY TABLE ═══ -->
<div class="section page-break">
  <div class="section-title">Authorities Cited (${o.authorities.length})</div>
  ${o.authoritiesFull.length > 0 ? `
  <table style="width:100%;border-collapse:collapse;font-size:12px">
    <thead>
      <tr style="background:${o.primaryColor};color:#fff">
        <th style="padding:8px 12px;text-align:left;font-size:11px">#</th>
        <th style="padding:8px 12px;text-align:left;font-size:11px">Citation</th>
        <th style="padding:8px 12px;text-align:left;font-size:11px">Type</th>
        <th style="padding:8px 12px;text-align:left;font-size:11px">Weight</th>
        <th style="padding:8px 12px;text-align:left;font-size:11px">Domain</th>
        <th style="padding:8px 12px;text-align:left;font-size:11px">Source Doctrine</th>
      </tr>
    </thead>
    <tbody>${authorityRows}</tbody>
  </table>` : `
  <div style="text-align:center;padding:20px;color:#6B7280;font-size:13px">
    <p><strong>${o.authorities.length} authorities referenced:</strong></p>
    <p style="margin-top:8px">${o.authorities.map(a => esc(a)).join('<br>')}</p>
  </div>`}
</div>

${(o.mode === 'DEFENSE' || o.mode === 'MEMO') && o.adversaryPosition ? `
<!-- ═══ ADVERSARY POSITION ═══ -->
<div class="section" style="background:#FEF2F2;border-top:1px solid #FECACA;border-bottom:1px solid #FECACA">
  <div class="section-title" style="color:#991B1B;border-color:#991B1B">Adversary / Opposing Position</div>
  <p style="font-size:13px;color:#374151;line-height:1.7">${esc(o.adversaryPosition)}</p>

  ${o.counterArguments.length > 0 ? `
  <div style="margin-top:20px">
    <h4 style="font-size:14px;color:#166534;margin-bottom:8px">Counter-Arguments & Rebuttals</h4>
    ${counterArgsList}
  </div>` : ''}
</div>` : ''}

${(o.mode === 'DEFENSE' || o.mode === 'MEMO') && o.appealsStrategy ? `
<!-- ═══ DEFENSE / APPEALS STRATEGY ═══ -->
<div class="section">
  <div class="section-title" style="color:#059669;border-color:#059669">Defense & Appeals Strategy</div>
  <p style="font-size:13px;color:#374151;line-height:1.7">${esc(o.appealsStrategy)}</p>

  ${o.burdenOfProof ? `
  <div style="margin-top:16px;padding:12px;background:#F0FDF4;border-radius:8px;border:1px solid #BBF7D0">
    <h4 style="font-size:13px;color:#166534;margin-bottom:6px">Burden of Proof</h4>
    <div style="font-size:12px;color:#374151">
      <strong>Holder:</strong> ${esc(o.burdenOfProof.holder)} &nbsp;|&nbsp;
      <strong>Standard:</strong> ${esc(o.burdenOfProof.standard)}
    </div>
    <p style="font-size:12px;color:#6B7280;margin-top:4px"><strong>Key Evidence Needed:</strong> ${esc(o.burdenOfProof.key_evidence_needed)}</p>
  </div>` : ''}
</div>` : ''}

${o.riskAssessment ? `
<!-- ═══ RISK ASSESSMENT ═══ -->
<div class="section">
  <div class="section-title" style="color:#DC2626;border-color:#DC2626">Risk Assessment</div>
  <p style="font-size:13px;color:#374151;line-height:1.7">${esc(o.riskAssessment)}</p>
</div>` : ''}

${o.actionItems.length > 0 ? `
<!-- ═══ ACTION ITEMS ═══ -->
<div class="section" style="background:#F0F9FF;border-top:1px solid #BAE6FD;border-bottom:1px solid #BAE6FD">
  <div class="section-title" style="color:#0369A1;border-color:#0369A1">Recommended Action Items</div>
  ${actionItemsList}
</div>` : ''}

${o.doctrines.length > 0 ? `
<!-- ═══ SUPPORTING DOCTRINES ═══ -->
<div class="section page-break">
  <div class="section-title">Supporting Doctrine Analysis (${o.doctrines.length})</div>
  <p style="font-size:12px;color:#6B7280;margin-bottom:12px">Individual doctrine matches ranked by relevance score.</p>
  ${doctrineCards}
</div>` : ''}

${o.mode === 'MEMO' ? `
<!-- ═══ METHODOLOGY & AUDIT ═══ -->
<div class="section page-break" style="background:#F9FAFB">
  <div class="section-title">Methodology & Audit Trail</div>
  <div style="font-size:12px;color:#6B7280;line-height:1.8">
    <p><strong>Engine Mode:</strong> ${esc(o.mode)} (deterministic doctrine matching + LLM synthesis)</p>
    <p><strong>Doctrines Searched:</strong> ${o.totalSearched.toLocaleString()}</p>
    <p><strong>Doctrines Matched:</strong> ${o.totalMatches}</p>
    <p><strong>Domains Analyzed:</strong> ${esc(o.domainsAnalyzed)}</p>
    <p><strong>Engine Response:</strong> ${o.engineResponseMs}ms</p>
    ${o.determinismHash ? `<p><strong>Determinism Hash:</strong> <code style="background:#E5E7EB;padding:2px 6px;border-radius:3px;font-size:11px">${esc(o.determinismHash)}</code></p>` : ''}
    <p><strong>Report Generated:</strong> ${esc(o.dateStr)} ${esc(o.timeStr)} UTC</p>
  </div>

  ${o.limitations ? `
  <div style="margin-top:16px;padding:12px;background:#FFFBEB;border-radius:8px;border:1px solid #FDE68A">
    <h4 style="font-size:13px;color:#92400E;margin-bottom:4px">Limitations</h4>
    <p style="font-size:12px;color:#92400E;line-height:1.6">${esc(o.limitations)}</p>
  </div>` : ''}

  ${o.furtherAnalysis.length > 0 ? `
  <div style="margin-top:16px">
    <h4 style="font-size:13px;color:#374151;margin-bottom:8px">Areas Requiring Further Analysis</h4>
    <ul style="font-size:12px;color:#6B7280;padding-left:20px;line-height:1.8">
      ${o.furtherAnalysis.map(f => `<li>${esc(f)}</li>`).join('')}
    </ul>
  </div>` : ''}
</div>` : ''}

<!-- ═══ FOOTER ═══ -->
<div style="padding:20px 40px;text-align:center;border-top:2px solid ${o.primaryColor};font-size:11px;color:#6B7280">
  <p style="font-weight:600;color:${o.primaryColor}">${esc(o.companyName)} · ${esc(o.tagline)}</p>
  <p style="margin-top:4px">This report was generated by the ECHO Intelligence Engine using deterministic doctrine matching.</p>
  <p style="margin-top:2px">All cited authorities should be independently verified before reliance in legal or regulatory proceedings.</p>
  <p style="margin-top:4px;font-size:10px;color:#9CA3AF">Report ID: ${esc(o.reportId)} · Generated: ${esc(o.dateStr)} ${esc(o.timeStr)} UTC</p>
</div>

</div><!-- /reportContent -->

<script>
function downloadPDF() {
  const el = document.getElementById('reportContent');
  const filename = '${esc(o.mode)}_Report_${esc(o.reportId)}.pdf';
  html2pdf().set({
    margin: [0.4, 0.5, 0.4, 0.5],
    filename: filename,
    image: { type: 'jpeg', quality: 0.98 },
    html2canvas: { scale: 2, useCORS: true, logging: false },
    jsPDF: { unit: 'in', format: 'letter', orientation: 'portrait' },
    pagebreak: { mode: ['avoid-all', 'css', 'legacy'] }
  }).from(el).save();
}

function copyText() {
  const el = document.getElementById('reportContent');
  const text = el.innerText || el.textContent || '';
  navigator.clipboard.writeText(text).then(() => {
    const btn = document.querySelector('.btn-copy');
    if (btn) { const orig = btn.innerHTML; btn.innerHTML = '&#10003; Copied!'; setTimeout(() => btn.innerHTML = orig, 2000); }
  });
}
<\/script>
</body>
</html>`;
}

// ═══════════════════════════════════════════════
// UTILITY
// ═══════════════════════════════════════════════

async function hashStr(s: string): Promise<string> {
  const data = new TextEncoder().encode(s);
  const buf = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('').slice(0, 16);
}

// ═══════════════════════════════════════════════
// EXPORT
// ═══════════════════════════════════════════════


app.onError((err, c) => {
  if (err.message?.includes('JSON')) {
    return c.json({ error: 'Invalid JSON body' }, 400);
  }
  console.error(`[echo-report-generator] ${err.message}`);
  return c.json({ error: 'Internal server error' }, 500);
});

app.notFound((c) => {
  return c.json({ error: 'Not found' }, 404);
});

export default app;
