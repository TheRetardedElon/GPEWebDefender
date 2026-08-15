const $ = (s, r = document) => r.querySelector(s);

let severity = "all";
let plane = "";
try { plane = localStorage.getItem("gpesiem.plane") || ""; } catch (_) {}
let query = "";
let seen = new Set();

let currentUser = null;

function goLogin() {
  location.href = "/login";
}

async function j(url, opts) {
  const r = await fetch(url, Object.assign({ credentials: "same-origin" }, opts || {}));
  if (r.status === 401) {
    goLogin();
    throw new Error("unauthorized");
  }
  if (!r.ok) throw new Error((await r.text()).trim() || r.statusText);
  if (r.status === 204) return null;
  const ct = r.headers.get("content-type") || "";
  if (!ct.includes("application/json")) return null;
  return r.json();
}

function ago(iso) {
  const t = new Date(iso).getTime();
  const s = Math.max(0, (Date.now() - t) / 1000);
  if (s < 60) return Math.floor(s) + "s";
  if (s < 3600) return Math.floor(s / 60) + "m";
  if (s < 86400) return Math.floor(s / 3600) + "h";
  return Math.floor(s / 86400) + "d";
}

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[c]));
}

/* ---------- live map ---------- */
// Simplified continent rings [lon, lat] — enough landmass for a threat map.
const LAND = [
  // North America
  [[-168,71],[-141,70],[-128,71],[-105,73],[-88,74],[-80,73],[-70,68],[-64,60],[-55,52],[-60,47],[-67,45],[-70,42],[-74,40],[-76,35],[-81,25],[-80,25],[-97,16],[-106,22],[-110,24],[-117,32],[-124,39],[-125,48],[-130,55],[-153,58],[-166,64],[-168,71]],
  // Greenland
  [[-73,78],[-47,83],[-20,81],[-22,70],[-44,60],[-52,69],[-68,76],[-73,78]],
  // South America
  [[-81,12],[-60,8],[-50,0],[-35,-7],[-35,-23],[-40,-32],[-62,-55],[-75,-52],[-71,-18],[-81,-5],[-81,12]],
  // Europe + west Russia
  [[-10,36],[-9,42],[-8,52],[-5,58],[0,61],[5,62],[10,63],[16,69],[25,71],[31,70],[30,60],[28,50],[24,45],[18,40],[12,36],[3,36],[-5,36],[-10,36]],
  // Scandinavia extra
  [[5,58],[8,63],[12,66],[18,69],[24,71],[28,71],[21,64],[12,59],[5,58]],
  // UK / IE
  [[-10,51],[-6,55],[-1,58],[1,52],[-5,50],[-10,51]],
  // Africa
  [[-17,15],[-17,21],[-13,27],[-6,36],[10,37],[25,32],[32,31],[43,12],[51,12],[40,0],[42,-16],[32,-30],[20,-35],[18,-34],[12,-18],[8,4],[-5,5],[-17,15]],
  // Madagascar
  [[43,-12],[50,-13],[47,-26],[43,-25],[43,-12]],
  // Middle East + India
  [[27,37],[36,37],[44,40],[48,30],[56,27],[66,25],[73,28],[77,32],[80,22],[80,8],[76,8],[72,20],[68,24],[60,25],[54,17],[43,13],[34,28],[27,31],[27,37]],
  // Asia
  [[40,48],[50,55],[70,56],[80,52],[90,48],[100,52],[110,48],[120,53],[135,48],[142,47],[145,44],[142,35],[130,33],[128,38],[120,40],[110,30],[108,21],[102,22],[97,17],[94,28],[88,28],[80,30],[75,40],[67,45],[60,45],[50,42],[40,48]],
  // Siberia
  [[60,60],[80,72],[100,76],[130,71],[160,68],[180,66],[180,60],[140,58],[110,56],[80,56],[60,60]],
  // SE Asia / islands
  [[95,6],[104,1],[109,2],[117,5],[119,-4],[115,-8],[105,-8],[102,-1],[95,6]],
  [[120,5],[127,2],[131,-3],[125,-8],[115,-8],[116,0],[120,5]],
  // Australia
  [[113,-22],[129,-12],[142,-11],[153,-25],[150,-38],[145,-39],[136,-35],[115,-35],[113,-22]],
  // NZ
  [[166,-41],[176,-38],[178,-46],[168,-47],[166,-41]],
  // Japan
  [[130,32],[141,35],[146,43],[141,45],[130,34],[130,32]],
];

const CAT_COLOR = {
  sqli: "#e24a3b",
  xss: "#e07a2f",
  rce: "#d14d7a",
  cmdi: "#c43b6e",
  ssrf: "#9b59b6",
  ssti: "#8e44ad",
  traversal: "#d4a054",
  injection: "#e05a4a",
  recon: "#5b9fd4",
  scanner: "#6b9e7a",
  brute: "#e08a3a",
  dos: "#7a8fa3",
  snoop: "#e8c36a",
  canary: "#f31260",
  hostauth: "#5b9fd4",
  applogin: "#c47ad4",
  tenant: "#ffb020",
  authz: "#e05a4a",
  secprobe: "#33cfff",
  tamper: "#33cfff",
  bypass: "#7c6cff",
  web: "#8a8274",
};
const CAT_LABEL = {
  sqli: "SQLi", xss: "XSS", rce: "RCE", cmdi: "CMDi", ssrf: "SSRF", ssti: "SSTI",
  traversal: "Traversal", injection: "Injection", recon: "Recon", scanner: "Scanner",
  brute: "Brute", dos: "Flood", snoop: "Snoop", canary: "Canary",
  hostauth: "Linux auth", applogin: "App login", tenant: "Tenant login",
  authz: "Authz deny", secprobe: "App probe",
  tamper: "Tamper", bypass: "Bypass", web: "Other",
};

const map = {
  canvas: null,
  ctx: null,
  home: { lat: 37.09, lon: -95.71, name: "Home" },
  homes: [],
  arcs: [],
  fly: [],
  countries: [],
  geoip: false,
  filter: new Set(), // empty = all types
};

const HOME_PALETTE = ["#d4a054", "#5b9fd4", "#6b9e7a", "#c47ad4", "#e07a2f", "#33cfff"];

let lastAlerts = [];
let selectedSource = "";
try { selectedSource = localStorage.getItem("gpesiem.source") || ""; } catch (_) {}
let sourceList = [];

/* Calibrated to ui/map-basemap.jpg (equirectangular land, HUD padding). */
const MAP_PROJ = { padX: 0.052, padTop: 0.086, padBot: 0.108, latMax: 83, latMin: -55 };
const MAP_ASPECT = 895 / 1600;

function project(lat, lon, w, h) {
  const p = MAP_PROJ;
  const x = p.padX + (lon + 180) / 360 * (1 - 2 * p.padX);
  const y = p.padTop + (p.latMax - lat) / (p.latMax - p.latMin) * (1 - p.padTop - p.padBot);
  return [x * w, y * h];
}

const mapArt = new Image();
mapArt.decoding = "async";
mapArt.src = "/map-basemap.jpg";

function drawLand(ctx, w, h) {
  ctx.fillStyle = "#050807";
  ctx.fillRect(0, 0, w, h);
  if (mapArt.complete && mapArt.naturalWidth) {
    ctx.drawImage(mapArt, 0, 0, w, h);
    return;
  }
  ctx.strokeStyle = "#1c1914";
  ctx.lineWidth = 1;
  for (let lat = -60; lat <= 80; lat += 20) {
    const [, y] = project(lat, 0, w, h);
    ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke();
  }
  ctx.fillStyle = "#1a1713";
  ctx.strokeStyle = "#2a261f";
  for (const ring of LAND) {
    ctx.beginPath();
    ring.forEach(([lon, lat], i) => {
      const [x, y] = project(lat, lon, w, h);
      if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
    });
    ctx.closePath();
    ctx.fill();
    ctx.stroke();
  }
}

function catColor(cat) {
  return CAT_COLOR[cat] || "#8a8274";
}

function catShown(cat) {
  return map.filter.size === 0 || map.filter.has(cat || "web");
}

function quadCtrl(x1, y1, x2, y2) {
  const mx = (x1 + x2) / 2;
  const my = (y1 + y2) / 2;
  const dx = x2 - x1, dy = y2 - y1;
  const dist = Math.hypot(dx, dy) || 1;
  const lift = Math.min(90, 18 + dist * 0.22);
  return [mx, my - lift];
}

function drawMap() {
  const c = map.canvas;
  if (!c) return;
  const ctx = map.ctx;
  const dpr = window.devicePixelRatio || 1;
  const w = c.clientWidth || 1600;
  const h = Math.max(320, Math.round(w * MAP_ASPECT));
  if (c.width !== Math.round(w * dpr) || c.height !== Math.round(h * dpr)) {
    c.width = Math.round(w * dpr);
    c.height = Math.round(h * dpr);
  }
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  drawLand(ctx, w, h);

  const homes = laidOutHomes();
  const now = performance.now();

  for (const a of map.fly) {
    if (!catShown(a.category)) continue;
    if (!sourceShown(a.source)) continue;
    const dest = destHome(a, homes);
    const [hx, hy] = project(dest.lat, dest.lon, w, h);
    const age = now - a.born;
    if (age > a.life) continue;
    const col = catColor(a.category);
    const [x1, y1] = project(a.lat, a.lon, w, h);
    const [cx, cy] = quadCtrl(x1, y1, hx, hy);
    const t = Math.min(1, age / 1400);
    const fade = age > a.life - 800 ? (a.life - age) / 800 : 1;
    ctx.beginPath();
    ctx.moveTo(x1, y1);
    ctx.quadraticCurveTo(cx, cy, hx, hy);
    ctx.strokeStyle = hexA(col, 0.18 + 0.45 * fade);
    ctx.lineWidth = a.severity === "critical" ? 2 : 1.4;
    ctx.stroke();

    const mt = easeOut(t);
    const px = (1 - mt) * (1 - mt) * x1 + 2 * (1 - mt) * mt * cx + mt * mt * hx;
    const py = (1 - mt) * (1 - mt) * y1 + 2 * (1 - mt) * mt * cy + mt * mt * hy;
    ctx.beginPath();
    ctx.arc(px, py, 2.4, 0, Math.PI * 2);
    ctx.fillStyle = hexA(col, fade);
    ctx.fill();

    ctx.beginPath();
    ctx.arc(x1, y1, 3 + (1 - fade) * 6, 0, Math.PI * 2);
    ctx.fillStyle = hexA(col, 0.18 * fade);
    ctx.fill();
    ctx.beginPath();
    ctx.arc(x1, y1, 2.6, 0, Math.PI * 2);
    ctx.fillStyle = hexA(col, 0.9 * fade);
    ctx.fill();
  }
  map.fly = map.fly.filter(a => now - a.born < a.life);

  // lingering dots — one per IP + type so filters stay honest
  const seen = new Set();
  for (const a of map.arcs) {
    if (!a.country || !catShown(a.category) || !sourceShown(a.source)) continue;
    const k = a.src_ip + "|" + (a.category || "");
    if (seen.has(k)) continue;
    seen.add(k);
    const [x, y] = project(a.lat, a.lon, w, h);
    ctx.beginPath();
    ctx.arc(x, y, 2.6, 0, Math.PI * 2);
    ctx.fillStyle = hexA(catColor(a.category), 0.7);
    ctx.fill();
  }

  homes.forEach((h, i) => {
    const [hx, hy] = project(h.lat, h.lon, w, h);
    const col = HOME_PALETTE[i % HOME_PALETTE.length];
    const pulse = 0.5 + 0.5 * Math.sin(now / 400 + i);
    ctx.beginPath();
    ctx.arc(hx, hy, 10 + pulse * 6, 0, Math.PI * 2);
    ctx.fillStyle = hexA(col, 0.10);
    ctx.fill();
    ctx.beginPath();
    ctx.arc(hx, hy, 4.5, 0, Math.PI * 2);
    ctx.fillStyle = col;
    ctx.fill();
    ctx.fillStyle = "#e8e2d6";
    ctx.font = "11px Segoe UI, system-ui, sans-serif";
    ctx.fillText(h.name || "home", hx + 8, hy - 6);
  });

  requestAnimationFrame(drawMap);
}

function sourceShown(src) {
  return !selectedSource || !src || src === selectedSource;
}

function shownHomes() {
  if (selectedSource) {
    const named = (map.homes || []).find(h => h.source === selectedSource || h.name === selectedSource);
    return [named || map.home];
  }
  if (map.homes && map.homes.length) return map.homes.slice();
  return [map.home];
}

function spreadHomes(homes) {
  const groups = new Map();
  homes.forEach((h, i) => {
    const k = Math.round(h.lat) + "," + Math.round(h.lon);
    if (!groups.has(k)) groups.set(k, []);
    groups.get(k).push({ ...h, _i: i });
  });
  const out = new Array(homes.length);
  for (const arr of groups.values()) {
    if (arr.length === 1) {
      out[arr[0]._i] = arr[0];
      continue;
    }
    arr.forEach((h, i) => {
      const ang = (i / arr.length) * Math.PI * 2;
      out[h._i] = { ...h, lat: h.lat + Math.sin(ang) * 0.55, lon: h.lon + Math.cos(ang) * 0.75 };
    });
  }
  return out;
}

function laidOutHomes() {
  return spreadHomes(shownHomes());
}

function destHome(a, homes) {
  const list = homes || laidOutHomes();
  if (a && a.source) {
    const hit = list.find(h => h.source === a.source || h.name === a.source);
    if (hit) return hit;
  }
  return list[0] || map.home;
}

function easeOut(t) { return 1 - (1 - t) * (1 - t); }

function hexA(hex, a) {
  const n = parseInt(hex.slice(1), 16);
  const r = (n >> 16) & 255, g = (n >> 8) & 255, b = n & 255;
  return `rgba(${r},${g},${b},${a})`;
}

function pushFly(a) {
  if (!a || a.lat == null || (a.lat === 0 && a.lon === 0 && !a.country)) return;
  map.fly.push({
    ...a,
    born: performance.now(),
    life: 4200 + Math.random() * 1200,
  });
  if (map.fly.length > 80) map.fly.shift();
}

function visibleArcs() {
  return map.arcs.filter(a => catShown(a.category) && sourceShown(a.source));
}

function renderMapMeta() {
  const vis = visibleArcs();
  const filt = [...map.filter];
  const hostBit = selectedSource ? selectedSource : (shownHomes().length > 1 ? shownHomes().length + " hosts" : "all hosts");
  $("#map-meta").textContent = map.geoip
    ? (hostBit + " · " + (filt.length ? filt.map(c => CAT_LABEL[c] || c).join(", ") + " · " : "") + vis.length + " origins")
    : "no GeoIP file yet — feed still works, map needs a .mmdb for real countries";

  const counts = {};
  for (const a of map.arcs) {
    const c = a.category || "web";
    counts[c] = (counts[c] || 0) + 1;
  }
  const cats = Object.keys(counts).sort((a, b) => counts[b] - counts[a]);
  const key = $("#map-key");
  if (key) {
    const allOn = map.filter.size === 0;
    key.innerHTML = `<button type="button" class="key ${allOn ? "on" : "dim"}" data-cat="">All types</button>` +
      cats.map(c => {
        const on = allOn || map.filter.has(c);
        return `<button type="button" class="key ${on ? "on" : "dim"}" data-cat="${esc(c)}" style="--sw:${catColor(c)}">
          <span class="swatch"></span>${esc(CAT_LABEL[c] || c)} ${counts[c]}
        </button>`;
      }).join("");
  }

  const originCounts = {};
  for (const a of vis) {
    const name = a.name || a.country;
    if (!name) continue;
    originCounts[name] = (originCounts[name] || 0) + 1;
  }
  const origins = Object.entries(originCounts).sort((a, b) => b[1] - a[1]).slice(0, 6);
  $("#map-legend").innerHTML = origins.length
    ? origins.map(([n, c]) => `<span><b>${esc(n)}</b> ${c}</span>`).join("")
    : (map.geoip
      ? `<span>nothing to plot in this filter</span>`
      : `<span>drop a GeoLite2 / DB-IP <code>.mmdb</code> on the box and real IPs will arc. until then, the list below is the truth.</span>`);
}

function toggleCat(cat) {
  if (!cat) {
    map.filter.clear();
  } else if (map.filter.has(cat)) {
    map.filter.delete(cat);
  } else {
    map.filter.add(cat);
  }
  renderMapMeta();
  renderAlerts();
}

function renderStats(st) {
  const cards = [
    ["Events / 1h", st.events_1h ?? 0],
    ["Alerts / 1h", st.alerts_1h ?? 0],
    ["Critical / 1h", st.critical_1h ?? 0, "crit"],
    ["Attacker IPs / 1h", st.unique_ips_1h ?? 0],
    ["Origin countries", map.countries.length],
    ["Rules loaded", st.rules_loaded ?? 0],
  ];
  $("#stats").innerHTML = cards.map(([k, v, c]) =>
    `<div class="card ${c || ""}"><div class="k">${k}</div><div class="v">${v}</div></div>`
  ).join("");

  const cats = st.by_category || {};
  const max = Math.max(1, ...Object.values(cats));
  const keys = Object.keys(cats).sort((a, b) => cats[b] - cats[a]);
  $("#cats").innerHTML = keys.length
    ? keys.map(k => `<div class="bar"><span>${esc(k)}</span><div class="track"><div class="fill" style="width:${(cats[k] / max) * 100}%"></div></div><span class="n">${cats[k]}</span></div>`).join("")
    : `<div class="empty">No alerts yet</div>`;

  const stMix = st.by_status || {};
  const order = ["200", "301", "302", "401", "403", "404", "429", "500", "502", "503"];
  const keysS = Object.keys(stMix).sort((a, b) => {
    const ia = order.indexOf(a), ib = order.indexOf(b);
    if (ia >= 0 || ib >= 0) return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib);
    return Number(a) - Number(b);
  });
  const maxS = Math.max(1, ...Object.values(stMix));
  const box = $("#status");
  if (box) {
    box.innerHTML = keysS.length
      ? keysS.map(k => `<div class="bar"><span>${esc(k)}</span><div class="track"><div class="fill" style="width:${(stMix[k] / maxS) * 100}%"></div></div><span class="n">${stMix[k]}</span></div>`).join("")
      : `<div class="empty">No requests yet</div>`;
  }
}

let alertBuf = [];
let alertHasMore = false;
let alertLoading = false;

function mergeAlerts(incoming, mode) {
  const byId = new Map(alertBuf.map(a => [a.id, a]));
  for (const a of incoming) byId.set(a.id, a);
  alertBuf = [...byId.values()].sort((a, b) => (b.num || 0) - (a.num || 0));
  if (mode === "reset") {
    // keep only this page plus we already replaced via byId from incoming-only
    const ids = new Set(incoming.map(a => a.id));
    if (incoming.length) alertBuf = alertBuf.filter(a => ids.has(a.id));
    else alertBuf = [];
  }
}

function renderAlerts() {
  const box = $("#alerts");
  const list = alertBuf;
  const shown = list.filter(a => catShown(a.category));
  if (!shown.length) {
    box.innerHTML = `<div class="empty">${list.length ? "Nothing in this map filter…" : "Quiet. Waiting on web traffic…"}</div>`;
    $("#feed-meta").textContent = "0 shown";
    return;
  }
  const more = alertHasMore ? `<div class="empty" id="alert-more">Scroll for older…</div>` : "";
  box.innerHTML = shown.map(a => `
    <div class="row" data-id="${esc(a.id)}">
      <div class="anum">${a.num ? "#" + a.num : ""}</div>
      <div class="sev ${esc(a.severity)}">${esc(a.severity)}</div>
      <div>
        <div class="title"><span class="swatch" style="--sw:${catColor(a.category)}"></span>${esc(a.title)}${(a.tags || []).map(t => `<span class="chip">${esc(t)}</span>`).join("")}</div>
        <div class="meta">${esc(a.src_ip)}${a.country ? " · " + esc(a.country_name || a.country) : ""}${a.source ? " · " + esc(a.source) : ""} · ${esc(a.method)} ${esc(a.url)}</div>
      </div>
      <div class="when">${ago(a.time)}</div>
    </div>`).join("") + more;
  box.querySelectorAll(".row").forEach(el => {
    el.addEventListener("click", () => {
      const a = shown.find(x => x.id === el.dataset.id);
      if (a) openDetail(a);
    });
  });
  $("#feed-meta").textContent = shown.length + (alertHasMore ? "+" : "") + " shown";
}

async function fetchAlertPage(extra) {
  const params = new URLSearchParams({ limit: "40" });
  if (severity !== "all") params.set("severity", severity);
  if (plane) params.set("plane", plane);
  if (query) params.set("q", query);
  Object.entries(extra || {}).forEach(([k, v]) => { if (v != null && v !== "") params.set(k, v); });
  return j("/api/alerts" + hostQS(params));
}

async function loadAlerts(mode) {
  if (alertLoading) return;
  alertLoading = true;
  try {
    const extra = {};
    if (mode === "older") {
      const oldest = alertBuf.length ? Math.min(...alertBuf.map(a => a.num || 0).filter(Boolean)) : 0;
      if (!oldest) { alertLoading = false; return; }
      extra.before = String(oldest);
    } else if (mode === "newer") {
      const newest = alertBuf.length ? Math.max(...alertBuf.map(a => a.num || 0)) : 0;
      if (newest) extra.after = String(newest);
    }
    const page = await fetchAlertPage(extra);
    const incoming = page.alerts || (Array.isArray(page) ? page : []);
    if (mode === "reset") {
      alertBuf = incoming.slice();
      alertHasMore = !!page.has_more;
    } else if (mode === "older") {
      mergeAlerts(incoming, "older");
      alertHasMore = !!page.has_more;
    } else {
      mergeAlerts(incoming, "newer");
    }
    lastAlerts = alertBuf;
    renderAlerts();
  } finally {
    alertLoading = false;
  }
}

function renderAttackers(list) {
  const box = $("#attackers");
  if (!list.length) {
    box.innerHTML = `<div class="empty">No attackers yet</div>`;
    return;
  }
  box.innerHTML = list.map(a => `
    <div class="att" data-ip="${esc(a.src_ip)}">
      <div>
        <div class="ip">${esc(a.src_ip)}</div>
        <div class="muted">${a.country ? esc(a.country) + " · " : ""}${esc(a.last_title || "")}</div>
      </div>
      <div class="when">${a.alerts}</div>
    </div>`).join("");
  box.querySelectorAll(".att").forEach(el => {
    el.addEventListener("click", () => {
      query = el.dataset.ip;
      $("#q").value = query;
      refresh();
    });
  });
}

function openDetail(a) {
  const d = $("#detail");
  d.querySelector("article").innerHTML = `
    <h3>${esc(a.title)}</h3>
    <dl>
      <dt>Number</dt><dd>${a.num ? "#" + a.num : "—"}</dd>
      <dt>Severity</dt><dd>${esc(a.severity)} · ${esc(a.category)}</dd>
      <dt>Tags</dt><dd>${esc((a.tags || []).join(", ") || "—")}</dd>
      <dt>When</dt><dd>${esc(a.time)}</dd>
      <dt>Source IP</dt><dd>${esc(a.src_ip)}</dd>
      <dt>Country</dt><dd>${esc(a.country_name || a.country || "—")}</dd>
      <dt>Request</dt><dd>${esc(a.method)} ${esc(a.url)}</dd>
      <dt>Status</dt><dd>${esc(a.status)}</dd>
      <dt>Rule</dt><dd>${esc(a.rule_id)}</dd>
      <dt>Evidence</dt><dd>${esc(a.evidence)}</dd>
      <dt>User-Agent</dt><dd>${esc(a.ua)}</dd>
      <dt>MITRE</dt><dd>${esc((a.mitre || []).join(", ") || "—")}</dd>
      <dt>Host / src</dt><dd>${esc(a.source || "—")}</dd>
    </dl>`;
  d.showModal();
}

function hostQS(extra) {
  const params = extra instanceof URLSearchParams ? extra : new URLSearchParams(extra || {});
  if (selectedSource) params.set("source", selectedSource);
  const s = params.toString();
  return s ? "?" + s : "";
}

function fillHostSelect() {
  const sel = $("#host");
  if (!sel) return;
  const prev = selectedSource;
  const opts = [`<option value="">All hosts</option>`].concat(
    sourceList.map(s => {
      const n = s.events_1h || s.alerts_1h
        ? ` (${s.alerts_1h || 0} alerts / 1h)`
        : "";
      return `<option value="${esc(s.name)}">${esc(s.name)}${esc(n)}</option>`;
    })
  );
  sel.innerHTML = opts.join("");
  if (prev && !sourceList.some(s => s.name === prev)) {
    sel.insertAdjacentHTML("beforeend", `<option value="${esc(prev)}">${esc(prev)}</option>`);
  }
  sel.value = prev;
}

async function refresh() {
  const [st, attackers, feed, srcs] = await Promise.all([
    j("/api/stats" + hostQS()),
    j("/api/attackers" + hostQS({ since: "24h" })),
    j("/api/map" + hostQS({ since: "24h", limit: "160" })),
    j("/api/sources"),
  ]);
  if (feed.home && feed.home.lat != null) {
    map.home = { lat: feed.home.lat, lon: feed.home.lon, name: feed.home.name || feed.home.country || "home" };
  }
  map.homes = feed.homes || [];
  map.geoip = !!feed.geoip;
  map.arcs = feed.arcs || [];
  map.countries = feed.countries || [];
  sourceList = (srcs && srcs.sources) || [];
  fillHostSelect();
  renderStats(st);
  renderAttackers(attackers);
  renderMapMeta();
  await loadAlerts(alertBuf.length ? "newer" : "reset");
  if (currentView === "reports") refreshReports().catch(() => {});
  if (currentView === "settings") loadSettings().catch(() => {});
}

function connect() {
  const es = new EventSource("/api/stream");
  const dot = $("#live-dot");
  const lab = $("#live-label");
  es.addEventListener("open", () => {
    dot.className = "dot on";
    lab.textContent = "live";
  });
  es.addEventListener("error", () => {
    dot.className = "dot bad";
    lab.textContent = "reconnecting";
  });
  es.addEventListener("alert", (ev) => {
    try {
      const a = JSON.parse(ev.data);
      if (seen.has(a.id)) return;
      seen.add(a.id);
      if ((a.has_geo || a.country) && sourceShown(a.source)) pushFly(a);
      if (a.id) {
        mergeAlerts([a], "newer");
        lastAlerts = alertBuf;
        renderAlerts();
      }
      refresh().catch(() => {});
    } catch (_) {}
  });
}

$("#filters").addEventListener("click", (e) => {
  const b = e.target.closest("button");
  if (!b) return;
  severity = b.dataset.sev;
  $("#filters").querySelectorAll("button").forEach(x => x.classList.toggle("on", x === b));
  alertBuf = [];
  loadAlerts("reset").catch(console.error);
  refresh().catch(console.error);
});
const planeFilters = $("#plane-filters");
if (planeFilters) {
  planeFilters.querySelectorAll("button").forEach(b => {
    b.classList.toggle("on", (b.dataset.plane || "") === plane);
  });
  planeFilters.addEventListener("click", (e) => {
    const b = e.target.closest("button");
    if (!b) return;
    plane = b.dataset.plane || "";
    try { localStorage.setItem("gpesiem.plane", plane); } catch (_) {}
    planeFilters.querySelectorAll("button").forEach(x => x.classList.toggle("on", x === b));
    alertBuf = [];
    loadAlerts("reset").catch(console.error);
    refresh().catch(console.error);
  });
}

let t;
$("#q").addEventListener("input", (e) => {
  clearTimeout(t);
  t = setTimeout(() => {
    query = e.target.value.trim();
    alertBuf = [];
    loadAlerts("reset").catch(console.error);
  }, 200);
});

const hostSel = $("#host");
if (hostSel) {
  hostSel.addEventListener("change", () => {
    selectedSource = hostSel.value;
    try { localStorage.setItem("gpesiem.source", selectedSource); } catch (_) {}
    alertBuf = [];
    refresh().catch(console.error);
  });
}

map.canvas = $("#map");
map.ctx = map.canvas.getContext("2d");
mapArt.addEventListener("load", () => requestAnimationFrame(drawMap));
requestAnimationFrame(drawMap);

const mapTip = $("#map-tip");
if (map.canvas && mapTip) {
  map.canvas.addEventListener("mousemove", (ev) => {
    const r = map.canvas.getBoundingClientRect();
    const x = ev.clientX - r.left;
    const y = ev.clientY - r.top;
    const w = map.canvas.clientWidth || 1;
    const h = map.canvas.clientHeight || 1;
    let best = null, bestD = 22;
    for (const a of map.arcs) {
      if (!a.lat && !a.lon) continue;
      if (!catShown(a.category) || !sourceShown(a.source)) continue;
      const [px, py] = project(a.lat, a.lon, w, h);
      const d = Math.hypot(px - x, py - y);
      if (d < bestD) {
        bestD = d;
        best = a;
      }
    }
    for (const home of laidOutHomes()) {
      const [px, py] = project(home.lat, home.lon, w, h);
      const d = Math.hypot(px - x, py - y);
      if (d < bestD) {
        bestD = d;
        best = { home: true, name: home.name, lat: home.lat, lon: home.lon };
      }
    }
    if (!best) {
      mapTip.hidden = true;
      return;
    }
    mapTip.hidden = false;
    mapTip.style.left = x + "px";
    mapTip.style.top = y + "px";
    if (best.home) {
      mapTip.textContent = (best.name || "home") + " · " + best.lat.toFixed(2) + "," + best.lon.toFixed(2);
    } else {
      const where = best.country_name || best.country || best.src_ip || "";
      mapTip.textContent = (best.src_ip || "") + (where ? " · " + where : "") +
        (best.category ? " · " + (CAT_LABEL[best.category] || best.category) : "");
    }
  });
  map.canvas.addEventListener("mouseleave", () => { mapTip.hidden = true; });
}

document.addEventListener("click", (e) => {
  const b = e.target.closest("#map-key .key");
  if (!b) return;
  toggleCat(b.dataset.cat || "");
});

let currentView = "live";
let reportKind = "vectors";
let reportRange = "24h";
try {
  currentView = localStorage.getItem("gpesiem.view") || "live";
  reportKind = localStorage.getItem("gpesiem.report") || "vectors";
  reportRange = localStorage.getItem("gpesiem.range") || "24h";
} catch (_) {}

function setView(v) {
  currentView = (v === "reports" || v === "settings" || v === "search") ? v : "live";
  try { localStorage.setItem("gpesiem.view", currentView); } catch (_) {}
  const live = $("#view-live");
  const reps = $("#view-reports");
  const sets = $("#view-settings");
  const sea = $("#view-search");
  if (live) live.hidden = currentView !== "live";
  if (reps) reps.hidden = currentView !== "reports";
  if (sets) sets.hidden = currentView !== "settings";
  if (sea) sea.hidden = currentView !== "search";
  document.querySelectorAll("#view-tabs [data-view]").forEach(b => {
    b.classList.toggle("on", b.dataset.view === currentView);
  });
  if (currentView === "reports") refreshReports().catch(console.error);
  if (currentView === "settings") {
    loadSettings().catch(console.error);
    loadUsers().catch(() => {});
  }
}

function parseHomesStr(s) {
  return String(s || "").split(/[;\n]/).map(part => {
    part = part.trim();
    if (!part) return null;
    const i = part.indexOf("=");
    if (i < 0) return { name: part, loc: "" };
    return { name: part.slice(0, i).trim(), loc: part.slice(i + 1).trim() };
  }).filter(Boolean);
}

function isAdmin() {
  return !!(currentUser && currentUser.role === "admin");
}

function addHomeRow(name, loc) {
  const box = $("#home-rows");
  if (!box) return;
  const row = document.createElement("div");
  row.className = "home-row";
  const canEdit = isAdmin() || !currentUser;
  row.innerHTML = `<input class="hn" placeholder="web-1" value="${esc(name || "")}" ${canEdit ? "" : "disabled"} />
    <input class="hl" placeholder="40.7,-74.0" value="${esc(loc || "")}" ${canEdit ? "" : "disabled"} />
    ${canEdit ? `<button type="button" class="btn-x" aria-label="Remove">×</button>` : `<span></span>`}`;
  const x = row.querySelector(".btn-x");
  if (x) x.addEventListener("click", () => row.remove());
  box.appendChild(row);
}

function applyRoleChrome() {
  const form = $("#settings-form");
  const saveBtn = form && form.querySelector("button[type=submit]");
  const add = $("#home-add");
  const users = $("#users-block");
  const admin = isAdmin();
  const viewer = !!(currentUser && !admin);
  if (form) {
    form.querySelectorAll("input, select, textarea, button").forEach(el => {
      if (el.closest("#pw-form")) return;
      if (el.type === "submit" || el.id === "home-add" || el.classList.contains("btn-x")) {
        el.hidden = viewer && (el.type === "submit" || el.id === "home-add");
      }
      if (el.tagName === "INPUT" || el.tagName === "SELECT" || el.tagName === "TEXTAREA") {
        el.disabled = viewer;
      }
    });
    form.classList.toggle("readonly", viewer);
  }
  if (saveBtn) {
    saveBtn.disabled = viewer;
    saveBtn.hidden = viewer;
    saveBtn.title = viewer ? "Admins only" : "";
  }
  if (add) add.hidden = viewer;
  if (users) users.hidden = viewer;
  const intro = form && form.querySelector(".settings-intro p");
  if (intro && viewer) {
    intro.textContent = "View only. An admin can change pins, retention, and operators.";
  }
}

function collectHomes() {
  return [...document.querySelectorAll("#home-rows .home-row")].map(row => {
    const name = row.querySelector(".hn").value.trim();
    const loc = row.querySelector(".hl").value.trim();
    if (!name || !loc) return "";
    return name + "=" + loc;
  }).filter(Boolean).join(";");
}

function retainChoice(raw) {
  const d = String(raw || "168h");
  const map = { "24h": "24h", "24h0m0s": "24h", "72h": "72h", "72h0m0s": "72h",
    "168h": "168h", "168h0m0s": "168h", "336h": "336h", "336h0m0s": "336h",
    "720h": "720h", "720h0m0s": "720h" };
  return map[d] || "168h";
}

async function loadSettings() {
  const data = await j("/api/settings");
  const st = data.settings || {};
  const name = $("#set-name");
  if (name) name.value = st.site_name || "";
  const home = $("#set-home");
  if (home) home.value = st.home || "";
  const box = $("#home-rows");
  if (box) {
    box.innerHTML = "";
    const rows = parseHomesStr(st.homes);
    if (rows.length) rows.forEach(r => addHomeRow(r.name, r.loc));
    else addHomeRow("", "");
  }
  const retain = $("#set-retain");
  if (retain) retain.value = retainChoice(st.retain);
  const tz = $("#set-tz");
  if (tz) tz.value = st.timezone === "local" ? "local" : "UTC";
  const meta = $("#settings-meta");
  if (meta) {
    meta.textContent = (data.rules || 0) + " detection rules · map GeoIP " +
      (data.geoip ? "is on" : "is off") + " · ingest token " + (data.token_set ? "is set" : "is not set");
  }
  if (st.site_name) {
    const brand = document.querySelector(".brand .name");
    if (brand) brand.textContent = st.site_name;
    document.title = st.site_name + " — Web Attack Monitor";
  }
  applyRoleChrome();
}

async function saveSettings(ev) {
  ev.preventDefault();
  const status = $("#settings-status");
  if (currentUser && !isAdmin()) {
    if (status) status.textContent = "admins only";
    return;
  }
  const body = {
    site_name: $("#set-name").value.trim(),
    home: $("#set-home").value.trim(),
    homes: collectHomes(),
    retain: $("#set-retain").value.trim(),
    timezone: $("#set-tz").value,
  };
  try {
    const r = await fetch("/api/settings", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!r.ok) throw new Error(await r.text());
    if (status) status.textContent = "saved";
    if (body.site_name) {
      const brand = document.querySelector(".brand .name");
      if (brand) brand.textContent = body.site_name;
    }
    refresh().catch(() => {});
  } catch (err) {
    if (status) status.textContent = err.message || "save failed";
  }
}

function markReportChrome() {
  document.querySelectorAll("#report-views [data-report]").forEach(b => {
    b.classList.toggle("on", b.dataset.report === reportKind);
  });
  document.querySelectorAll("#report-range [data-range]").forEach(b => {
    b.classList.toggle("on", b.dataset.range === reportRange);
  });
}

function panel(title, inner, span) {
  return `<section class="panel ${span || ""}"><header><h2>${esc(title)}</h2></header>${inner}</section>`;
}

function nameTable(rows, nameH, extra) {
  if (!rows || !rows.length) return `<div class="empty">Nothing in this window</div>`;
  return `<table class="rpt"><thead><tr><th>${esc(nameH)}</th><th>Count</th>${extra ? "<th>" + extra + "</th>" : ""}</tr></thead><tbody>` +
    rows.map(r => `<tr><td class="mono">${esc(r.name || r.id || r.src_ip)}</td><td>${r.count ?? r.alerts ?? 0}</td>${extra ? "<td>" + esc(r.ips || r.severity || r.country || "") + "</td>" : ""}</tr>`).join("") +
    `</tbody></table>`;
}

function hourBars(hours) {
  if (!hours || !hours.length) return `<div class="empty">No hourly buckets yet</div>`;
  const max = Math.max(1, ...hours.map(h => h.count));
  return `<div class="hours" title="alerts per hour">` +
    hours.map(h => `<i style="height:${Math.max(4, (h.count / max) * 100)}%" title="${esc(h.time)} · ${h.count}"></i>`).join("") +
    `</div>`;
}

function cards(list) {
  return list.map(([k, v, c]) =>
    `<div class="card ${c || ""}"><div class="k">${k}</div><div class="v">${v}</div></div>`
  ).join("");
}

function authEmpty(kind) {
  if (kind === "linux") {
    return `<div class="hint-box">No Linux auth events yet. Point an agent at <code>/var/log/auth.log</code> (or <code>/var/log/secure</code>) with the same token. Only sshd / sudo / login / PAM failures are kept — this is not a general syslog SIEM.</div>`;
  }
  if (kind === "tenant") {
    return `<div class="hint-box">No tenant / site-owner login events yet. The app should POST <code>kind=tenantlogin</code> (or <code>kind=applogin</code> with <code>role=tenant</code>). Never send passwords.</div>`;
  }
  if (kind === "probes") {
    return `<div class="hint-box">No application probe events yet. Your app POSTs <code>kind=secprobe</code> with a <code>reason</code> (<code>canary_hit</code>, <code>path_probe</code>, <code>sensitive_deny</code>, <code>webhook_reject</code>, <code>auth_rate_limit</code>, <code>enum_burst</code>, <code>app_deny</code>). Plant generic canaries at <code>/.well-known/siem-canary</code> or <code>/__canary__/siem</code>. Never send secrets.</div>`;
  }
  if (kind === "app") {
    return `<div class="hint-box">No application login events yet. Your app should POST JSON to <code>/api/ingest</code> (Bearer token, <code>X-SIEM-Source</code> set). Do not send passwords.<pre style="margin:10px 0 0;white-space:pre-wrap">{
  "kind": "applogin",
  "src_ip": "203.0.113.9",
  "user": "alice",
  "path": "/api/login",
  "status": 401,
  "outcome": "fail",
  "method": "LOGIN"
}</pre></div>`;
  }
  return `<div class="hint-box">No 401/403 or login-path hits in this window. Web auth is derived from access logs (status + paths like <code>/login</code>, <code>/auth</code>).</div>`;
}

function renderVectorReport(rep) {
  $("#report-stats").innerHTML = cards([
    ["Alerts", rep.alerts ?? 0],
    ["Attacker IPs", rep.unique_ips ?? 0],
    ["Critical", rep.critical ?? 0, "crit"],
    ["Categories", (rep.by_category || []).length],
    ["Rules fired", (rep.by_rule || []).length],
    ["Countries", (rep.by_country || []).length],
  ]);
  const rules = (rep.by_rule || []).map(r => ({
    name: r.title || r.id, count: r.count, severity: r.severity, id: r.id,
  }));
  $("#report-body").innerHTML =
    panel("By category", nameTable(rep.by_category, "Category", "IPs")) +
    panel("Top rules", nameTable(rules, "Rule", "Sev")) +
    panel("Paths being hit", nameTable(rep.by_path, "Path", "IPs")) +
    panel("Origin countries", nameTable(rep.by_country, "Country")) +
    panel("Volume by hour", hourBars(rep.by_hour), "span2") +
    panel("Top attacker IPs", nameTable((rep.top_ips || []).map(a => ({
      name: a.src_ip, count: a.alerts, country: a.country || a.last_title || "",
    })), "IP", "Note"), "span2");
}

function renderAuthReport(rep, kind) {
  $("#report-stats").innerHTML = cards([
    ["Failures", rep.fails ?? 0, "crit"],
    ["Fails / 1h", rep.fails_1h ?? 0],
    ["Successes", rep.success ?? 0],
    ["Unique IPs", rep.unique_ips ?? 0],
    ["Unique users", rep.unique_users ?? 0],
    ["Sources", (rep.by_source || []).length],
  ]);
  if (!(rep.fails || 0) && !(rep.recent || []).length) {
    $("#report-body").innerHTML = panel("Nothing here yet", authEmpty(kind), "span2");
    return;
  }
  const recent = (rep.recent || []).map(e => `
    <tr>
      <td>${ago(e.time)}</td>
      <td class="mono">${esc(e.src_ip || "—")}</td>
      <td class="mono">${esc(e.user || "—")}</td>
      <td class="mono">${esc(e.path || e.url || "")}</td>
      <td>${esc(e.status || e.outcome || "")}</td>
      <td>${esc(e.source || "")}</td>
    </tr>`).join("");
  $("#report-body").innerHTML =
    panel("Top IPs", nameTable((rep.top_ips || []).map(a => ({
      name: a.src_ip, count: a.count, country: a.country || a.last_user || "",
    })), "IP", "Geo / user")) +
    panel("Users", nameTable(rep.by_user, "User")) +
    panel("Paths / services", nameTable(rep.by_path, "Path")) +
    panel("By host", nameTable(rep.by_source, "Source")) +
    panel("Recent failures", recent
      ? `<table class="rpt"><thead><tr><th>When</th><th>IP</th><th>User</th><th>Where</th><th>Result</th><th>Src</th></tr></thead><tbody>${recent}</tbody></table>`
      : `<div class="empty">None</div>`, "span2");
}

async function refreshReports() {
  markReportChrome();
  const params = new URLSearchParams({ since: reportRange });
  if (selectedSource) params.set("source", selectedSource);
  const box = $("#report-body");
  const stats = $("#report-stats");
  if (!box || !stats) return;
  try {
    if (reportKind === "vectors") {
      renderVectorReport(await j("/api/reports/vectors?" + params.toString()));
      return;
    }
    params.set("channel", reportKind);
    renderAuthReport(await j("/api/reports/auth?" + params.toString()), reportKind);
  } catch (err) {
    stats.innerHTML = "";
    box.innerHTML = `<div class="empty">${esc(err.message)}</div>`;
  }
}

const viewTabs = $("#view-tabs");
if (viewTabs) {
  viewTabs.addEventListener("click", (e) => {
    const b = e.target.closest("button[data-view]");
    if (b) setView(b.dataset.view);
  });
}
const reportViews = $("#report-views");
if (reportViews) {
  reportViews.addEventListener("click", (e) => {
    const b = e.target.closest("button[data-report]");
    if (!b) return;
    reportKind = b.dataset.report;
    try { localStorage.setItem("gpesiem.report", reportKind); } catch (_) {}
    refreshReports().catch(console.error);
  });
}
const reportRangeEl = $("#report-range");
if (reportRangeEl) {
  reportRangeEl.addEventListener("click", (e) => {
    const b = e.target.closest("button[data-range]");
    if (!b) return;
    reportRange = b.dataset.range;
    try { localStorage.setItem("gpesiem.range", reportRange); } catch (_) {}
    refreshReports().catch(console.error);
  });
}

let searchOldest = false;
try { searchOldest = localStorage.getItem("gpesiem.searchSort") === "oldest"; } catch (_) {}

function paintSearchSort() {
  const dir = $("#search-when-dir");
  const btn = $("#search-when");
  if (dir) dir.textContent = searchOldest ? "▴" : "▾";
  if (btn) btn.title = searchOldest ? "Oldest first — click for newest" : "Newest first — click for oldest";
}

async function runSearch(ev) {
  if (ev) ev.preventDefault();
  const params = new URLSearchParams();
  const q = ($("#sq") && $("#sq").value.trim()) || "";
  const ip = ($("#sip") && $("#sip").value.trim()) || "";
  const host = ($("#shost") && $("#shost").value.trim()) || "";
  const kind = ($("#skind") && $("#skind").value) || "";
  if (q) params.set("q", q);
  if (ip) params.set("ip", ip);
  if (host) params.set("host", host);
  if (kind) params.set("kind", kind);
  params.set("sort", searchOldest ? "oldest" : "newest");
  params.set("limit", "50");
  paintSearchSort();
  const meta = $("#search-meta");
  const body = $("#search-body");
  if (!q && !ip && !host && !kind) {
    if (body) body.innerHTML = `<tr><td colspan="6" class="empty">Type a keyword, IP, or host.</td></tr>`;
    if (meta) meta.textContent = "";
    return;
  }
  try {
    const page = await j("/api/search?" + params.toString());
    const hits = page.hits || [];
    if (meta) meta.textContent = hits.length + " hits · " + (page.took_ms ?? 0) + " ms";
    if (!hits.length) {
      body.innerHTML = `<tr><td colspan="6" class="empty">Nothing matched.</td></tr>`;
      return;
    }
    body.innerHTML = hits.map(h => `<tr>
      <td>${h.num ? "#" + h.num : h.bucket}</td>
      <td title="${esc(h.time || "")}">${h.time ? ago(h.time) : ""}</td>
      <td>${esc(h.title || h.kind || h.category || "")}</td>
      <td class="mono">${esc(h.src_ip || "")}${h.user ? " · " + esc(h.user) : ""}</td>
      <td class="mono">${esc(h.path || h.url || "")}</td>
      <td>${esc(h.source || h.host || "")}</td>
    </tr>`).join("");
  } catch (err) {
    if (body) body.innerHTML = `<tr><td colspan="6" class="empty">${esc(err.message)}</td></tr>`;
  }
}

const searchForm = $("#search-form");
if (searchForm) searchForm.addEventListener("submit", runSearch);
const searchWhen = $("#search-when");
if (searchWhen) {
  paintSearchSort();
  searchWhen.addEventListener("click", () => {
    searchOldest = !searchOldest;
    try { localStorage.setItem("gpesiem.searchSort", searchOldest ? "oldest" : "newest"); } catch (_) {}
    paintSearchSort();
    runSearch().catch(console.error);
  });
}

function paintWho() {
  const who = $("#whoami");
  const out = $("#logout");
  const acct = $("#acct-block");
  if (!currentUser) {
    if (who) who.hidden = true;
    if (out) out.hidden = true;
    if (acct) acct.hidden = true;
    applyRoleChrome();
    return;
  }
  if (who) {
    who.hidden = false;
    who.textContent = currentUser.username + " · " + currentUser.role;
  }
  if (out) out.hidden = false;
  if (acct) acct.hidden = false;
  applyRoleChrome();
}

async function bootAuth() {
  let st;
  try {
    st = await authStatus();
  } catch (_) {
    return;
  }
  if (!st || !st.users) return;
  try {
    currentUser = await j("/api/me");
    paintWho();
  } catch (_) {}
}

async function authStatus() {
  const r = await fetch("/api/auth-status", { credentials: "same-origin" });
  if (!r.ok) throw new Error("auth-status");
  return r.json();
}

async function loadUsers() {
  const block = $("#users-block");
  const setupBox = $("#users-setup");
  const adminBox = $("#users-admin");
  if (!block) return;
  let st = { users: 0, setup: true };
  try {
    st = await authStatus();
  } catch (_) {}
  if (st.setup || !st.users) {
    block.hidden = false;
    if (setupBox) setupBox.hidden = false;
    if (adminBox) adminBox.hidden = true;
    return;
  }
  if (setupBox) setupBox.hidden = true;
  if (!isAdmin()) {
    if (block) block.hidden = true;
    if (adminBox) adminBox.hidden = true;
    return;
  }
  block.hidden = false;
  if (adminBox) adminBox.hidden = false;
  const body = $("#users-body");
  if (!body) return;
  try {
    const list = await j("/api/users");
    if (!list || !list.length) {
      body.innerHTML = `<tr><td colspan="4" class="empty">No users.</td></tr>`;
      return;
    }
    body.innerHTML = list.map(u => {
      const last = u.last_login ? ago(u.last_login) : "never";
      const dis = u.disabled ? " · disabled" : "";
      return `<tr data-id="${u.id}">
        <td>${esc(u.username)}${dis}</td>
        <td>${esc(u.role)}</td>
        <td>${esc(last)}</td>
        <td class="user-actions">
          <button type="button" class="btn-quiet" data-act="reset">Reset password</button>
          <button type="button" class="btn-quiet" data-act="toggle">${u.disabled ? "Enable" : "Disable"}</button>
          <button type="button" class="btn-quiet" data-act="del">Delete</button>
        </td>
      </tr>`;
    }).join("");
  } catch (err) {
    body.innerHTML = `<tr><td colspan="4" class="empty">${esc(err.message)}</td></tr>`;
  }
}

async function createFirstAdmin(ev) {
  ev.preventDefault();
  const status = $("#setup-status");
  const username = ($("#su-name") && $("#su-name").value.trim()) || "";
  const password = ($("#su-pass") && $("#su-pass").value) || "";
  const password2 = ($("#su-pass2") && $("#su-pass2").value) || "";
  if (password !== password2) {
    if (status) status.textContent = "passwords do not match";
    return;
  }
  try {
    await j("/api/setup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
    if (status) status.textContent = "created — reloading";
    location.reload();
  } catch (err) {
    if (status) status.textContent = err.message || "failed";
  }
}

async function changeOwnPassword(ev) {
  ev.preventDefault();
  const status = $("#pw-status");
  const cur = $("#pw-cur").value;
  const next = $("#pw-new").value;
  const next2 = $("#pw-new2").value;
  if (next !== next2) {
    status.textContent = "passwords do not match";
    return;
  }
  try {
    await j("/api/me/password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ current: cur, next }),
    });
    $("#pw-form").reset();
    status.textContent = "password changed";
  } catch (err) {
    status.textContent = err.message || "failed";
  }
}

async function createOperator(ev) {
  ev.preventDefault();
  const status = $("#user-status");
  try {
    await j("/api/users", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: $("#nu-name").value.trim(),
        password: $("#nu-pass").value,
        role: $("#nu-role").value,
      }),
    });
    $("#user-form").reset();
    status.textContent = "created";
    await loadUsers();
  } catch (err) {
    status.textContent = err.message || "failed";
  }
}

async function userRowAction(ev) {
  const btn = ev.target.closest("button[data-act]");
  if (!btn) return;
  const tr = btn.closest("tr");
  const id = tr && tr.dataset.id;
  if (!id) return;
  const act = btn.dataset.act;
  const status = $("#user-status");
  try {
    if (act === "del") {
      if (!confirm("Delete this operator?")) return;
      await j("/api/users/" + id, { method: "DELETE" });
    } else if (act === "toggle") {
      const disabled = !/Enable/.test(btn.textContent);
      await j("/api/users/" + id + "/disable", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ disabled }),
      });
    } else if (act === "reset") {
      const next = prompt("New password (min 12 characters)");
      if (!next) return;
      await j("/api/users/" + id + "/password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ next }),
      });
    }
    status.textContent = "updated";
    await loadUsers();
  } catch (err) {
    status.textContent = err.message || "failed";
  }
}

async function doLogout() {
  try {
    await fetch("/api/logout", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: "{}",
    });
  } catch (_) {}
  goLogin();
}

const settingsForm = $("#settings-form");
if (settingsForm) settingsForm.addEventListener("submit", saveSettings);
const homeAdd = $("#home-add");
if (homeAdd) homeAdd.addEventListener("click", () => addHomeRow("", ""));
const pwForm = $("#pw-form");
if (pwForm) pwForm.addEventListener("submit", changeOwnPassword);
const userForm = $("#user-form");
if (userForm) userForm.addEventListener("submit", createOperator);
const setupForm = $("#setup-form");
if (setupForm) setupForm.addEventListener("submit", createFirstAdmin);
const usersBody = $("#users-body");
if (usersBody) usersBody.addEventListener("click", userRowAction);
const logoutBtn = $("#logout");
if (logoutBtn) logoutBtn.addEventListener("click", doLogout);

const alertList = $("#alerts");
if (alertList) {
  alertList.addEventListener("scroll", () => {
    if (!alertHasMore || alertLoading) return;
    if (alertList.scrollTop + alertList.clientHeight > alertList.scrollHeight - 80) {
      loadAlerts("older").catch(() => {});
    }
  });
}

bootAuth().then(() => {
  connect();
  setView(currentView);
  loadSettings().catch(() => {});
  loadUsers().catch(() => {});
  refresh().catch(err => {
    const box = $("#alerts");
    if (box) box.innerHTML = `<div class="empty">${esc(err.message)}</div>`;
  });
  setInterval(() => refresh().catch(() => {}), 8000);
});
