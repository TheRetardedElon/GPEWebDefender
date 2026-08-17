const $ = (s, r = document) => r.querySelector(s);

let severity = "all";
let plane = "";
try { plane = localStorage.getItem("gwd.plane") || ""; } catch (_) {}
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
const REASON_LABEL = {
  canary_hit: "canary hit",
  path_probe: "path probe",
  sensitive_deny: "privileged path denied",
  webhook_reject: "webhook rejected",
  auth_rate_limit: "login rate-limited",
  rate_limit: "public route rate-limited",
  enum_burst: "identifier enum burst",
  app_deny: "feature denied (no credentials)",
  score_abuse: "score / leaderboard abuse",
  signup_abuse: "signup abuse",
  idor: "cross-record access (IDOR)",
  priv_esc: "privilege escalation",
  key_replay: "stolen or replayed key",
  ssrf_out: "outbound fetch blocked",
  upload_abuse: "upload abuse",
  ws_abuse: "live-channel abuse",
  logic_deny: "business-logic abuse",
  stepup_bypass: "2FA / step-up bypass",
};
function reasonLabel(r) {
  r = String(r || "").trim();
  return REASON_LABEL[r] || r.replace(/_/g, " ");
}

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
try { selectedSource = localStorage.getItem("gwd.source") || ""; } catch (_) {}
let sourceList = [];

/* Calibrated to ui/map-basemap.jpg. NA is drawn a bit south of true
   equirectangular on this plate, so mid-US latitudes get a small bias. */
const MAP_PROJ = { padX: 0.045, padTop: 0.10, padBot: 0.07, latMax: 84, latMin: -56 };
const MAP_ASPECT = 895 / 1600;
const MAP_VIEW_H = 520;

const mapCam = { z: 1, x: 0, y: 0 };
const MAP_ZMIN = 1, MAP_ZMAX = 8;

function projectLat(lat, lon) {
  if (lon > -170 && lon < -50 && lat > 14 && lat < 72) return lat - 6.2;
  return lat;
}

function project(lat, lon, w, h) {
  const p = MAP_PROJ;
  lat = projectLat(lat, lon);
  const x = p.padX + (lon + 180) / 360 * (1 - 2 * p.padX);
  const y = p.padTop + (p.latMax - lat) / (p.latMax - p.latMin) * (1 - p.padTop - p.padBot);
  return [x * w, y * h];
}

function applyCam(ctx, w, h) {
  ctx.translate(w / 2 + mapCam.x, h / 2 + mapCam.y);
  ctx.scale(mapCam.z, mapCam.z);
  ctx.translate(-w / 2, -h / 2);
}

function screenToWorld(sx, sy, w, h) {
  return {
    x: (sx - w / 2 - mapCam.x) / mapCam.z + w / 2,
    y: (sy - h / 2 - mapCam.y) / mapCam.z + h / 2,
  };
}

function clampCam(w, h) {
  mapCam.z = Math.min(MAP_ZMAX, Math.max(MAP_ZMIN, mapCam.z));
  const limX = (w * (mapCam.z - 1)) / 2 + 40;
  const limY = (h * (mapCam.z - 1)) / 2 + 40;
  mapCam.x = Math.max(-limX, Math.min(limX, mapCam.x));
  mapCam.y = Math.max(-limY, Math.min(limY, mapCam.y));
}

function zoomAt(sx, sy, factor, w, h) {
  const world = screenToWorld(sx, sy, w, h);
  mapCam.z *= factor;
  clampCam(w, h);
  mapCam.x = sx - (world.x - w / 2) * mapCam.z - w / 2;
  mapCam.y = sy - (world.y - h / 2) * mapCam.z - h / 2;
  clampCam(w, h);
}

function fitHomes() {
  const c = map.canvas;
  if (!c) return;
  const w = c.clientWidth || 1600;
  const h = Math.min(MAP_VIEW_H, Math.max(280, Math.round(w * MAP_ASPECT)));
  const homes = selectedSource ? spreadHomes(shownHomes()) : laidOutHomes();
  if (!homes.length) {
    mapCam.z = 1; mapCam.x = 0; mapCam.y = 0;
    return;
  }
  const pts = homes.map(hm => project(hm.lat, hm.lon, w, h));
  let minX = pts[0][0], maxX = pts[0][0], minY = pts[0][1], maxY = pts[0][1];
  for (const [x, y] of pts) {
    if (x < minX) minX = x; if (x > maxX) maxX = x;
    if (y < minY) minY = y; if (y > maxY) maxY = y;
  }
  const pad = 80;
  const bw = Math.max(40, maxX - minX + pad * 2);
  const bh = Math.max(40, maxY - minY + pad * 2);
  mapCam.z = Math.min(MAP_ZMAX, Math.max(1.4, Math.min(w / bw, h / bh)));
  const cx = (minX + maxX) / 2, cy = (minY + maxY) / 2;
  mapCam.x = (w / 2 - cx) * mapCam.z;
  mapCam.y = (h / 2 - cy) * mapCam.z;
  clampCam(w, h);
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

const TYPE_ICON = {
  recon: "types/recon.svg",
  scanner: "types/scanner.svg",
  snoop: "types/recon.svg",
  brute: "types/brute.svg",
  dos: "types/dos.svg",
  canary: "types/canary.svg",
  traversal: "types/traversal.svg",
  hostauth: "types/hostauth.svg",
};
const COUNTRY_ICON = {
  ad: "countries/ad.svg", cn: "countries/cn.svg", do: "countries/do.svg",
  de: "countries/de.svg", id: "countries/id.svg", ie: "countries/ie.svg",
  jp: "countries/jp.svg", lr: "countries/lr.svg", my: "countries/my.svg",
  nl: "countries/nl.svg", ru: "countries/ru.svg", ch: "countries/ch.svg",
  us: "countries/us.svg", ca: "countries/ca.svg",
  eg: "countries/eg.svg", sg: "countries/sg.svg",
  gb: "countries/gb.svg", mx: "countries/mx.svg",
  im: "countries/im.svg", hk: "countries/hk.svg",
  ve: "countries/ve.svg", in: "countries/in.svg",
};
const COUNTRY_ALIAS = {
  "united states": "us", usa: "us", america: "us",
  "the netherlands": "nl", netherlands: "nl", holland: "nl",
  switzerland: "ch", japan: "jp", china: "cn", germany: "de",
  indonesia: "id", ireland: "ie", malaysia: "my", russia: "ru",
  andorra: "ad", liberia: "lr", "dominican republic": "do",
  canada: "ca", egypt: "eg", singapore: "sg",
  "united kingdom": "gb", uk: "gb", britain: "gb", "great britain": "gb",
  mexico: "mx", "isle of man": "im", "hong kong": "hk",
  venezuela: "ve", india: "in",
};

const ICONS = {};
[
  "node-ok.svg", "node-err.svg", "node-warn.svg", "canary.svg", "shield.svg", "flare.svg",
  "hosts/rack.svg", "hosts/datastore.svg", "hosts/edge.svg", "hosts/terminal.svg", "hosts/cloud.svg",
  "types/recon.svg", "types/scanner.svg", "types/brute.svg", "types/dos.svg", "types/canary.svg", "types/traversal.svg",
].forEach(name => {
  const im = new Image();
  im.src = "/icons/" + name;
  ICONS[name] = im;
});

function countryKey(code, name) {
  const iso = String(code || "").trim().toLowerCase();
  if (COUNTRY_ICON[iso]) return iso;
  const alias = COUNTRY_ALIAS[String(name || "").trim().toLowerCase()];
  if (alias) return alias;
  return iso;
}

function countryArt(code, name) {
  const k = countryKey(code, name);
  return COUNTRY_ICON[k] || "";
}

function typeArt(cat) {
  return TYPE_ICON[cat] || "";
}

function hostArt(name) {
  const s = String(name || "").toLowerCase();
  if (/proxy|edge|waf|gw/.test(s)) return "hosts/edge.svg";
  if (/dnode|db|data|sql|store/.test(s)) return "hosts/datastore.svg";
  if (/dev|work|term/.test(s)) return "hosts/terminal.svg";
  if (/cloud|k8s|kube/.test(s)) return "hosts/cloud.svg";
  return "hosts/rack.svg";
}

function hostRegionArt(name) {
  const s = String(name || "").toLowerCase();
  if (/web-1|chic|illinois/.test(s)) return "countries/us-il.svg";
  if (/proxy|dnode|devbox|atlanta|ga/.test(s)) return "countries/us-ga.svg";
  return "";
}

function artImg(src, cls, alt) {
  if (!src) return "";
  return `<img class="${esc(cls || "art-inline")}" src="/icons/${esc(src)}" alt="${esc(alt || "")}" />`;
}

function drawIcon(ctx, name, x, y, size) {
  const im = ICONS[name];
  if (!im || !im.complete || !im.naturalWidth) return false;
  ctx.drawImage(im, x - size / 2, y - size / 2, size, size);
  return true;
}

function drawShieldMark(ctx, x, y, size) {
  const r = size / 2;
  ctx.save();
  ctx.translate(x, y);
  ctx.beginPath();
  const pts = [
    [0, -r],
    [r * 0.86, -r * 0.48],
    [r * 0.72, r * 0.32],
    [0, r],
    [-r * 0.72, r * 0.32],
    [-r * 0.86, -r * 0.48],
  ];
  pts.forEach(([px, py], i) => (i === 0 ? ctx.moveTo(px, py) : ctx.lineTo(px, py)));
  ctx.closePath();
  ctx.fillStyle = hexA("#00f0ff", 0.28);
  ctx.strokeStyle = "#7ee8ff";
  ctx.lineWidth = 2.2;
  ctx.shadowColor = "#00f0ff";
  ctx.shadowBlur = 16;
  ctx.fill();
  ctx.stroke();
  ctx.beginPath();
  ctx.arc(0, 0, r * 0.22, 0, Math.PI * 2);
  ctx.fillStyle = "#e8ffff";
  ctx.fill();
  ctx.restore();
}

function drawHomePin(ctx, home, x, y, now, idx) {
  const tag = home.source || home.name;
  const mine = !selectedSource || selectedSource === tag;
  const pulse = mine ? 0.5 + 0.5 * Math.sin(now / 380 + idx) : 0.15;
  ctx.save();
  ctx.globalAlpha = mine ? 1 : 0.42;
  ctx.beginPath();
  ctx.arc(x, y, 11 + pulse * 4, 0, Math.PI * 2);
  ctx.fillStyle = hexA("#041410", 0.82);
  ctx.fill();
  ctx.strokeStyle = hexA("#00f0ff", mine ? 0.55 : 0.22);
  ctx.lineWidth = 1.1;
  ctx.stroke();
  const art = hostArt(home.name || home.source);
  if (!drawIcon(ctx, art, x, y, 22)) {
    drawShieldMark(ctx, x, y, 14);
  }
  const label = home.name || "home";
  ctx.font = "600 11px Segoe UI, system-ui, sans-serif";
  const tw = ctx.measureText(label).width;
  ctx.fillStyle = "#050807ee";
  ctx.fillRect(x + 12, y - 14, tw + 8, 15);
  ctx.strokeStyle = hexA("#00f0ff", 0.35);
  ctx.lineWidth = 1;
  ctx.strokeRect(x + 12, y - 14, tw + 8, 15);
  ctx.fillStyle = "#7ee8ff";
  ctx.fillText(label, x + 16, y - 3);
  ctx.restore();
}

function iconForCat(cat) {
  return typeArt(cat) || (cat === "canary" ? "canary.svg" : "node-err.svg");
}

function strokeGlowPartial(ctx, x1, y1, cx, cy, x2, y2, col, width, alpha, t) {
  const tt = Math.max(0, Math.min(1, t));
  if (tt <= 0 || alpha <= 0) return;
  ctx.save();
  ctx.beginPath();
  ctx.moveTo(x1, y1);
  if (tt >= 1) {
    ctx.quadraticCurveTo(cx, cy, x2, y2);
  } else {
    const ax = x1 + (cx - x1) * tt;
    const ay = y1 + (cy - y1) * tt;
    const bx = cx + (x2 - cx) * tt;
    const by = cy + (y2 - cy) * tt;
    ctx.quadraticCurveTo(ax, ay, ax + (bx - ax) * tt, ay + (by - ay) * tt);
  }
  ctx.strokeStyle = hexA(col, alpha);
  ctx.lineWidth = width;
  ctx.lineCap = "round";
  ctx.stroke();
  ctx.restore();
}

function quadCtrl(x1, y1, x2, y2) {
  const mx = (x1 + x2) / 2;
  const my = (y1 + y2) / 2;
  const dx = x2 - x1, dy = y2 - y1;
  const dist = Math.hypot(dx, dy) || 1;
  const lift = Math.min(90, 18 + dist * 0.22);
  return [mx, my - lift];
}

let mapRaf = 0;
let mapIdle = 0;

function kickMap() {
  if (document.hidden) return;
  if (mapRaf) return;
  if (mapIdle) { clearTimeout(mapIdle); mapIdle = 0; }
  mapRaf = requestAnimationFrame(drawMap);
}

function drawMap() {
  mapRaf = 0;
  const c = map.canvas;
  if (!c) return;
  const ctx = map.ctx;
  const dpr = Math.min(1.25, window.devicePixelRatio || 1);
  const w = c.clientWidth || 1600;
  const h = Math.min(MAP_VIEW_H, Math.max(280, Math.round(w * MAP_ASPECT)));
  if (c.width !== Math.round(w * dpr) || c.height !== Math.round(h * dpr)) {
    c.width = Math.round(w * dpr);
    c.height = Math.round(h * dpr);
  }
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.fillStyle = "#050807";
  ctx.fillRect(0, 0, w, h);
  ctx.save();
  applyCam(ctx, w, h);
  drawLand(ctx, w, h);

  const homes = laidOutHomes();
  const now = performance.now();

  for (const a of map.fly) {
    if (!catShown(a.category)) continue;
    const dest = destHome(a, homes);
    const [hx, hy] = project(dest.lat, dest.lon, w, h);
    const age = now - a.born;
    if (age > a.life) continue;
    const col = catColor(a.category);
    const [x1, y1] = project(a.lat, a.lon, w, h);
    const [cx, cy] = quadCtrl(x1, y1, hx, hy);
    const travel = 1400;
    const t = Math.min(1, age / travel);
    const fade = age > a.life - 380 ? Math.max(0, (a.life - age) / 380) : 1;
    strokeGlowPartial(ctx, x1, y1, cx, cy, hx, hy, col, a.severity === "critical" ? 4.2 : 3.2, 0.92 * fade, t);

    const qpt = (tt) => {
      const u = easeOut(Math.max(0, Math.min(1, tt)));
      return [
        (1 - u) * (1 - u) * x1 + 2 * (1 - u) * u * cx + u * u * hx,
        (1 - u) * (1 - u) * y1 + 2 * (1 - u) * u * cy + u * u * hy,
      ];
    };
    if (t < 1) {
      const [tx, ty] = qpt(t - 0.05);
      ctx.beginPath();
      ctx.arc(tx, ty, 4, 0, Math.PI * 2);
      ctx.fillStyle = hexA(col, 0.35 * fade);
      ctx.fill();
      const [px, py] = qpt(t);
      ctx.beginPath();
      ctx.arc(px, py, 7, 0, Math.PI * 2);
      ctx.fillStyle = hexA(col, 0.7 * fade);
      ctx.fill();
      ctx.beginPath();
      ctx.arc(px, py, 3, 0, Math.PI * 2);
      ctx.fillStyle = hexA("#ffffff", fade);
      ctx.fill();
    }

    ctx.beginPath();
    ctx.arc(x1, y1, 4, 0, Math.PI * 2);
    ctx.fillStyle = hexA(col, 0.95 * fade);
    ctx.fill();
  }
  map.fly = map.fly.filter(a => now - a.born < a.life);

  homes.forEach((home, i) => {
    if (home.lat == null || home.lon == null) return;
    const [hx, hy] = project(home.lat, home.lon, w, h);
    if (!Number.isFinite(hx) || !Number.isFinite(hy)) return;
    drawHomePin(ctx, home, hx, hy, now, i);
  });

  ctx.restore();
  if (map.fly.length || shotQ.length) kickMap();
  else mapIdle = setTimeout(() => { mapIdle = 0; kickMap(); }, 500);
}

function sourceShown(src) {
  return !selectedSource || !src || src === selectedSource;
}

function allConfiguredHomes() {
  if (map.homes && map.homes.length) return map.homes.slice();
  return [map.home];
}

function shownHomes() {
  if (selectedSource) {
    const named = allConfiguredHomes().find(h => h.source === selectedSource || h.name === selectedSource);
    return [named || map.home];
  }
  return allConfiguredHomes();
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

let homesCache = null, homesCacheKey = "";
function laidOutHomes() {
  const list = allConfiguredHomes();
  const key = list.map(h => (h.name || "") + "," + h.lat + "," + h.lon).join("|");
  if (homesCache && homesCacheKey === key) return homesCache;
  homesCacheKey = key;
  homesCache = spreadHomes(list);
  return homesCache;
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
  if (a.id && map.fly.some(f => f.id === a.id)) return;
  map.fly.push({
    ...a,
    born: performance.now(),
    life: 1850 + Math.random() * 200,
  });
  if (map.fly.length > 24) map.fly.shift();
}

const shotQ = [];
let shotKick = 0;
const SHOT_MAX = 6;
const SHOT_GAP = 100;

function enqueueShot(a) {
  const k = (a.src_ip || "") + ">" + (a.source || "") + "|" + (a.category || "");
  const now = performance.now();
  for (let i = shotQ.length - 1; i >= 0; i--) {
    if (shotQ[i]._k === k && now - shotQ[i]._qat < 450) {
      shotQ[i]._n = (shotQ[i]._n || 1) + 1;
      return;
    }
  }
  shotQ.push({ ...a, _k: k, _qat: now, _n: 1 });
  if (shotQ.length > 36) shotQ.shift();
  pumpShots();
  kickMap();
}

function pumpShots() {
  if (shotKick) return;
  const tick = () => {
    shotKick = 0;
    const now = performance.now();
    const live = map.fly.filter(f => now - f.born < f.life).length;
    if (live < SHOT_MAX && shotQ.length) pushFly(shotQ.shift());
    if (shotQ.length) shotKick = setTimeout(tick, SHOT_GAP);
  };
  tick();
}

function fireShot(a) {
  if (!a) return;
  if (a.id) {
    if (seen.has(a.id)) return;
    seen.add(a.id);
  }
  if (a.has_geo || a.country || (a.lat != null && (a.lat !== 0 || a.lon !== 0))) {
    enqueueShot(a);
  }
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
          ${artImg(typeArt(c), "art-inline", c)}<span class="swatch"></span>${esc(CAT_LABEL[c] || c)} ${counts[c]}
        </button>`;
      }).join("");
  }

  const originCounts = {};
  for (const a of vis) {
    const name = a.name || a.country;
    if (!name) continue;
    if (!originCounts[name]) originCounts[name] = { n: 0, iso: a.country || "" };
    originCounts[name].n++;
    if (a.country) originCounts[name].iso = a.country;
  }
  const origins = Object.entries(originCounts).sort((a, b) => b[1].n - a[1].n).slice(0, 6);
  $("#map-legend").innerHTML = origins.length
    ? origins.map(([n, rec]) => `<span>${artImg(countryArt(rec.iso, n), "art-flag", n)}<b>${esc(n)}</b> ${rec.n}</span>`).join("")
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
  if (alertBuf.length > 50) alertBuf.length = 50;
  if (mode === "reset") {
    // keep only this page plus we already replaced via byId from incoming-only
    const ids = new Set(incoming.map(a => a.id));
    if (incoming.length) alertBuf = alertBuf.filter(a => ids.has(a.id));
    else alertBuf = [];
  }
}

let alertPaint = 0;
function renderAlertsSoon() {
  if (alertPaint) return;
  alertPaint = requestAnimationFrame(() => {
    alertPaint = 0;
    renderAlerts();
  });
}

function renderAlerts() {
  const box = $("#alerts");
  const list = alertBuf;
  const shown = list.filter(a => catShown(a.category)).slice(0, 40);
  if (!shown.length) {
    box.innerHTML = `<div class="empty">${list.length ? "Nothing in this map filter…" : "Quiet. Waiting on web traffic…"}</div>`;
    $("#feed-meta").textContent = "0 shown";
    return;
  }
  const more = alertHasMore
    ? `<button type="button" class="btn-quiet load-older" id="alert-more">Load older</button>`
    : "";
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
  $("#feed-meta").textContent = shown.length + (alertHasMore || list.length > 40 ? "+" : "") + " shown";
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
      for (const a of incoming) if (a.id) seen.add(a.id);
    } else if (mode === "older") {
      mergeAlerts(incoming, "older");
      alertHasMore = !!page.has_more;
      for (const a of incoming) if (a.id) seen.add(a.id);
    } else {
      mergeAlerts(incoming, "newer");
      for (const a of incoming) fireShot(a);
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
    el.addEventListener("click", () => openIntel(el.dataset.ip));
  });
}

async function openIntel(ip) {
  if (!ip) return;
  const d = $("#detail");
  if (!d) return;
  d.querySelector("article").innerHTML = `<h3 class="mono">${esc(ip)}</h3><section class="intel-box" id="detail-intel"></section>`;
  d.showModal();
  await loadIntel(ip, d.querySelector("#detail-intel"));
}

const IP_LOOKUPS = [
  { name: "AbuseIPDB", href: ip => "https://www.abuseipdb.com/check/" + ip, primary: true },
  { name: "GreyNoise", href: ip => "https://viz.greynoise.io/ip/" + ip, primary: true },
  { name: "VirusTotal", href: ip => "https://www.virustotal.com/gui/ip-address/" + ip, primary: true },
  { name: "Talos", href: ip => "https://www.talosintelligence.com/reputation_center/lookup?search=" + ip, primary: true },
  { name: "IPOK", href: ip => "https://ipok.io/en?ip=" + ip },
  { name: "IPQS", href: ip => "https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/" + ip },
  { name: "OTX", href: ip => "https://otx.alienvault.com/indicator/ip/" + ip },
  { name: "X-Force", href: ip => "https://exchange.xforce.ibmcloud.com/ip/" + ip },
  { name: "Shodan", href: ip => "https://www.shodan.io/host/" + ip },
  { name: "MXToolbox", href: ip => "https://mxtoolbox.com/SuperTool.aspx?action=blacklist%3a" + ip },
  { name: "Spamhaus", href: ip => "https://check.spamhaus.org/listed/?searchterm=" + ip },
  { name: "Honey Pot", href: ip => "https://www.projecthoneypot.org/ip_" + ip },
  { name: "IPinfo", href: ip => "https://ipinfo.io/" + ip },
  { name: "Pulsedive", href: ip => "https://pulsedive.com/indicator/?ioc=" + ip },
];

function lookupLinks(ip, all) {
  const list = all ? IP_LOOKUPS : IP_LOOKUPS.filter(x => x.primary);
  return list.map(x => `<a class="intel-link" href="${esc(x.href(ip))}" target="_blank" rel="noopener noreferrer">${esc(x.name)}</a>`).join("");
}

function openLookups(ip) {
  IP_LOOKUPS.filter(x => x.primary).forEach((x, i) => {
    setTimeout(() => window.open(x.href(ip), "_blank", "noopener"), i * 180);
  });
}

function researchLine(intel) {
  const r = intel.research || "local";
  if (r === "off") return "Research trickle is off (no ABUSEIPDB_KEY). Our logs + these tabs only.";
  if (r === "queued") return "In the slow queue — one check ~every 90s, cached. We do not hammer free APIs.";
  if (r === "cached" && intel.ext_source) {
    return intel.ext_source + " cached" + (intel.ext_score != null ? " · confidence " + intel.ext_score : "") +
      (intel.ext_note ? " · " + intel.ext_note : "");
  }
  if (r === "stale") return "Cached lookup expired — queued for a polite recheck.";
  return "Our logs only so far. Open the tabs for third-party context.";
}

function paintIntelBox(el, intel) {
  if (!el) return;
  const v = intel.verdict || "unknown";
  const why = (intel.why || []).map(w => `<li>${esc(w)}</li>`).join("");
  const hosts = (intel.hosts || []).join(", ") || "—";
  const cats = (intel.categories || []).map(c => CAT_LABEL[c] || c).join(", ") || "—";
  const users = (intel.users || []).map(u => esc(u.name) + " ×" + u.count).join(", ");
  el.innerHTML = `
    <div class="intel-head">
      <span class="intel-score ${esc(v)}">${intel.weight ?? 0}</span>
      <div>
        <div class="intel-verdict">${esc(v)} · ${esc(intel.intent || "")}</div>
        <div class="muted">${esc(researchLine(intel))}</div>
      </div>
    </div>
    <ul class="intel-why">${why || "<li>no extra notes</li>"}</ul>
    <div class="muted">Hosts: ${esc(hosts)} · Types: ${esc(cats)}${users ? " · Users tried: " + users : ""}</div>
    <div class="intel-links">${intel.private ? "<span class='muted'>private IP — no public lookups</span>" : lookupLinks(intel.src_ip, true)}</div>
    ${intel.private ? "" : `<button type="button" class="intel-open" data-open-lookups="${esc(intel.src_ip)}">Open top 4 lookups</button>`}
  `;
}

async function loadIntel(ip, box) {
  if (!box || !ip) return;
  box.innerHTML = `<div class="muted">weighing ${esc(ip)} from our logs…</div>`;
  try {
    const intel = await j("/api/intel?ip=" + encodeURIComponent(ip) + "&since=168h");
    paintIntelBox(box, intel);
  } catch (err) {
    box.innerHTML = `<div class="muted">${esc(err.message || "intel failed")}</div>`;
  }
}

function alertKind(a) {
  if (a.kind) return a.kind;
  if (a.category === "hostauth" || /^(SSH|SUDO)$/i.test(a.method || "")) return "hostauth";
  if (a.category === "applogin") return "applogin";
  if (a.category === "tenant") return "tenantlogin";
  if (["canary", "authz", "secprobe", "tamper"].includes(a.category)) return "secprobe";
  if (/^LOGIN$/i.test(a.method || "")) return "applogin";
  return "web";
}

function alertUser(a) {
  if (a.user) return a.user;
  const ev = String(a.evidence || "").trim();
  if (ev && ev.length < 40 && !/[\s\/?=]/.test(ev)) return ev;
  const m = String(a.url || "").match(/\bfor (\S+) from\b/i);
  return m ? m[1] : "";
}

function alertOutcome(a) {
  const o = String(a.outcome || "").toLowerCase();
  if (o === "ok") return "accepted";
  if (o === "fail") return "failed";
  const u = String(a.url || "");
  if (/accepted/i.test(u)) return "accepted";
  if (/failed password|invalid user|authentication failure|max auth/i.test(u)) return "failed";
  if (a.status === 401 || a.status === 403) return "failed";
  if (a.status === 200 || a.status === 201 || a.status === 204) return "accepted";
  return "";
}

function alertWhat(a) {
  const kind = alertKind(a);
  const url = String(a.url || "").replace(/^(SSH|SUDO|LOGIN)\s+/i, "").trim();
  if (kind === "hostauth") {
    if (/invalid user/i.test(url)) return "invalid user";
    if (/failed password/i.test(url)) return "failed password";
    if (/accepted/i.test(url)) return "accepted login";
    if (/max auth/i.test(url)) return "max auth failures";
    if (/sudo/i.test(url) || /^SUDO$/i.test(a.method || "")) return "sudo failure";
    return url || a.title || "";
  }
  if (kind === "applogin" || kind === "tenantlogin") {
    return (a.path || url || "/login").trim();
  }
  if (kind === "secprobe") {
    return a.reason ? reasonLabel(a.reason) : (a.path || url || a.title || "");
  }
  if (a.method && (a.path || url)) return a.method + " " + (a.path || url);
  return url || a.title || "";
}

function detailRows(a) {
  const kind = alertKind(a);
  const user = alertUser(a);
  const outcome = alertOutcome(a);
  const what = alertWhat(a);
  const rows = [];
  const add = (k, v) => {
    if (v == null) return;
    const s = String(v).trim();
    if (!s || s === "—" || s === "0") return;
    rows.push([k, s]);
  };
  add("User tried", user);
  if (kind === "hostauth" || kind === "applogin" || kind === "tenantlogin") {
    add("Result", outcome);
    add("What", what && what !== a.title ? what : "");
  } else if (kind === "secprobe") {
    add("Reason", a.reason ? reasonLabel(a.reason) : "");
    add("Path", a.path || a.url || "");
    if (a.status) add("HTTP status", String(a.status));
  } else {
    add("Request", what);
    if (a.status) add("HTTP status", String(a.status));
    add("User-Agent", a.ua);
  }
  add("From", a.src_ip);
  add("Against", a.source);
  if (kind === "web" && a.host && a.host !== a.source) add("Host header", a.host);
  add("Rule", a.rule_id);
  add("MITRE", (a.mitre || []).join(", "));
  if (a.count > 1) add("Count", String(a.count));
  add("Tags", (a.tags || []).join(", "));
  return rows;
}

async function openDetail(a) {
  lastDetail = a;
  if (isAdmin()) {
    try { await loadPairing(); } catch (_) {}
  }
  const d = $("#detail");
  const originName = a.country_name || a.country || "";
  const originSrc = countryArt(a.country, a.country_name);
  const catSrc = typeArt(a.category);
  const hostSrc = a.source ? hostArt(a.source) : "";
  const regionSrc = a.source ? hostRegionArt(a.source) : "";
  const iso = (a.country || "").toString().trim().toUpperCase();
  const tile = (src, cap, extra) => {
    if (!src && !cap) return "";
    const mark = src
      ? artImg(src, "detail-svg", cap)
      : `<span class="detail-fallback">${esc(iso && cap === originName ? iso : String(cap || "?").slice(0, 3))}</span>`;
    return `<div class="detail-art">
      ${mark}
      ${extra ? artImg(extra, "detail-svg sub", cap) : ""}
      <span class="cap">${esc(cap || "—")}</span>
    </div>`;
  };
  const rows = detailRows(a).map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join("");
  const kicker = [
    a.num ? "#" + a.num : "",
    a.severity || "",
    CAT_LABEL[a.category] || a.category || "",
  ].filter(Boolean).join(" · ");
  d.querySelector("article").innerHTML = `
    <div class="detail-hero">
      ${tile(originSrc, originName || (a.src_ip || "origin"))}
      ${tile(catSrc, CAT_LABEL[a.category] || a.category || "event")}
      ${tile(hostSrc, a.source || "host", regionSrc)}
    </div>
    <div class="detail-kicker">${esc(kicker)}</div>
    <h3>${esc(a.title)}</h3>
    <p class="detail-when">${esc(fmtWhen(a.time))}${a.time ? " · " + ago(a.time) + " ago" : ""}</p>
    ${rows ? `<dl>${rows}</dl>` : ""}
    ${blockPanel(a)}
    <section class="intel-box" id="detail-intel"></section>`;
  d.showModal();
  if (a.src_ip) loadIntel(a.src_ip, d.querySelector("#detail-intel"));
}

let agentCache = [];

function pairedAgent(source) {
  return (agentCache || []).find(x => x.name === source && x.status === "active");
}

function durBtns(ip, agentId, all) {
  return ["15m", "1h", "24h", "7d"].map(d => {
    if (all) return `<button type="button" class="btn-quiet" data-ban-all="${esc(ip)}" data-ban-dur="${d}">${d}</button>`;
    return `<button type="button" class="btn-quiet" data-ban-host="${esc(agentId)}" data-ban-ip="${esc(ip)}" data-ban-dur="${d}">${d}</button>`;
  }).join("");
}

function blockPanel(a) {
  if (!isAdmin() || !a.src_ip) return "";
  const host = pairedAgent(a.source);
  const pairedN = (agentCache || []).filter(x => x.status === "active").length;
  const thisRow = host
    ? `<div class="ban-row">
        <div><b>This host</b><div class="muted">${esc(a.source)}</div></div>
        <div class="row-btns">${durBtns(a.src_ip, host.id, false)}</div>
      </div>`
    : `<div class="ban-row">
        <div><b>This host</b><div class="muted">${esc(a.source || "—")} is not paired</div></div>
        <a class="btn-quiet" href="#pair-block" id="ban-goto-pair">Pair in Settings</a>
      </div>`;
  const allRow = pairedN
    ? `<div class="ban-row">
        <div><b>All paired</b><div class="muted">${pairedN} host${pairedN === 1 ? "" : "s"}</div></div>
        <div class="row-btns">${durBtns(a.src_ip, "", true)}</div>
      </div>`
    : "";
  return `<section class="detail-block">
    <div class="intel-verdict">Contain</div>
    <div class="muted">Block <span class="mono">${esc(a.src_ip)}</span> — public IPs only. The sensor applies it on the next poll. <a href="#" data-goto-blocks>Blocklist</a></div>
    ${thisRow}
    ${allRow}
    <div class="muted" id="ban-status"></div>
  </section>`;
}

let lastDetail = null;

async function doBan(ip, agentId, duration, all) {
  const status = $("#ban-status");
  const dur = duration || "1h";
  const msg = all
    ? `Block ${ip} on every paired host for ${dur}?`
    : `Block ${ip} on this host for ${dur}?`;
  if (!confirm(msg)) return;
  try {
    const url = all ? "/api/agents/ban-all" : "/api/agents/" + encodeURIComponent(agentId) + "/ban";
    const r = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ip, duration: dur,
        title: lastDetail && lastDetail.title || "",
        category: lastDetail && lastDetail.category || "",
        num: lastDetail && lastDetail.num || 0,
        scope: all ? "all" : "this",
      }),
    });
    const t = await r.text();
    if (!r.ok) throw new Error(t.trim() || r.statusText);
    if (status) status.textContent = "queued — the sensor applies it on its next poll";
  } catch (err) {
    if (status) status.textContent = err.message || "ban failed";
  }
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
  if (currentView === "settings") loadSettings().catch(() => {});
}

let refreshSoon = 0;
function scheduleRefresh() {
  if (refreshSoon) return;
  refreshSoon = setTimeout(() => {
    refreshSoon = 0;
    refresh().catch(() => {});
  }, 900);
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
      fireShot(a);
      if (a.id) {
        mergeAlerts([a], "newer");
        lastAlerts = alertBuf;
        renderAlertsSoon();
      }
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
    try { localStorage.setItem("gwd.plane", plane); } catch (_) {}
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
    try { localStorage.setItem("gwd.source", selectedSource); } catch (_) {}
    alertBuf = [];
    if (selectedSource) fitHomes();
    else { mapCam.z = 1; mapCam.x = 0; mapCam.y = 0; }
    refresh().catch(console.error);
    if (currentView === "reports") refreshReports().catch(console.error);
  });
}

map.canvas = $("#map");
map.ctx = map.canvas.getContext("2d", { alpha: false });
mapArt.addEventListener("load", () => kickMap());
Object.values(ICONS).forEach(im => im.addEventListener("load", () => kickMap()));
kickMap();
document.addEventListener("visibilitychange", () => { if (!document.hidden) kickMap(); });
const alertBox = $("#alerts");
if (alertBox && !alertBox.dataset.bound) {
  alertBox.dataset.bound = "1";
  alertBox.addEventListener("click", (e) => {
    if (e.target.closest("#alert-more")) {
      loadAlerts("older").catch(console.error);
      return;
    }
    const row = e.target.closest(".row");
    if (!row) return;
    const a = alertBuf.find(x => x.id === row.dataset.id);
    if (a) openDetail(a);
  });
}

const mapTip = $("#map-tip");
if (map.canvas) {
  const cnv = map.canvas;
  let dragging = false, lastX = 0, lastY = 0;
  cnv.addEventListener("wheel", (ev) => {
    ev.preventDefault();
    const r = cnv.getBoundingClientRect();
    const w = cnv.clientWidth || 1, h = cnv.clientHeight || 1;
    zoomAt(ev.clientX - r.left, ev.clientY - r.top, ev.deltaY > 0 ? 0.88 : 1.14, w, h);
    kickMap();
  }, { passive: false });
  cnv.addEventListener("mousedown", (ev) => {
    if (ev.button !== 0) return;
    dragging = true;
    lastX = ev.clientX; lastY = ev.clientY;
    cnv.classList.add("drag");
  });
  window.addEventListener("mouseup", () => { dragging = false; cnv.classList.remove("drag"); });
  window.addEventListener("mousemove", (ev) => {
    if (!dragging) return;
    mapCam.x += ev.clientX - lastX;
    mapCam.y += ev.clientY - lastY;
    lastX = ev.clientX; lastY = ev.clientY;
    const w = cnv.clientWidth || 1, h = cnv.clientHeight || 1;
    clampCam(w, h);
    kickMap();
  });
  if (mapTip) {
    cnv.addEventListener("mousemove", (ev) => {
      if (dragging) { mapTip.hidden = true; return; }
      const r = cnv.getBoundingClientRect();
      const sx = ev.clientX - r.left, sy = ev.clientY - r.top;
      const w = cnv.clientWidth || 1, h = cnv.clientHeight || 1;
      const wrld = screenToWorld(sx, sy, w, h);
      let best = null, bestD = 18 / mapCam.z;
      for (const a of map.fly) {
        if (!a.lat && !a.lon) continue;
        if (!catShown(a.category) || !sourceShown(a.source)) continue;
        const [px, py] = project(a.lat, a.lon, w, h);
        const d = Math.hypot(px - wrld.x, py - wrld.y);
        if (d < bestD) { bestD = d; best = a; }
      }
      for (const home of laidOutHomes()) {
        const [px, py] = project(home.lat, home.lon, w, h);
        const d = Math.hypot(px - wrld.x, py - wrld.y);
        if (d < bestD) {
          bestD = d;
          best = { home: true, name: home.name, lat: home.lat, lon: home.lon };
        }
      }
      if (!best) { mapTip.hidden = true; return; }
      mapTip.hidden = false;
      mapTip.style.left = sx + "px";
      mapTip.style.top = sy + "px";
      if (best.home) {
        mapTip.textContent = (best.name || "home") + " · " + best.lat.toFixed(2) + "," + best.lon.toFixed(2);
      } else {
        const where = best.country_name || best.country || "";
        mapTip.textContent = (best.src_ip || "") + (where ? " · " + where : "") +
          (best.category ? " · " + (CAT_LABEL[best.category] || best.category) : "");
      }
    });
    cnv.addEventListener("mouseleave", () => { mapTip.hidden = true; });
  }
}
const mapZin = $("#map-zin");
const mapZout = $("#map-zout");
if (mapZin) mapZin.addEventListener("click", () => {
  const c = map.canvas; if (!c) return;
  zoomAt(c.clientWidth / 2, c.clientHeight / 2, 1.25, c.clientWidth, c.clientHeight);
});
if (mapZout) mapZout.addEventListener("click", () => {
  const c = map.canvas; if (!c) return;
  zoomAt(c.clientWidth / 2, c.clientHeight / 2, 0.8, c.clientWidth, c.clientHeight);
});
const mapFit = $("#map-fit");
if (mapFit) mapFit.addEventListener("click", () => fitHomes());
const mapReset = $("#map-reset");
if (mapReset) mapReset.addEventListener("click", () => { mapCam.z = 1; mapCam.x = 0; mapCam.y = 0; });

document.addEventListener("click", (e) => {
  const b = e.target.closest("#map-key .key");
  if (b) { toggleCat(b.dataset.cat || ""); return; }
  const open = e.target.closest("[data-open-lookups]");
  if (open) { openLookups(open.dataset.openLookups); return; }
  const weigh = e.target.closest("[data-intel-ip]");
  if (weigh) { openIntel(weigh.dataset.intelIp); return; }
  const banHost = e.target.closest("[data-ban-host]");
  if (banHost) {
    doBan(banHost.dataset.banIp, banHost.dataset.banHost, banHost.dataset.banDur || "1h", false);
    return;
  }
  const banAll = e.target.closest("[data-ban-all]");
  if (banAll) {
    doBan(banAll.dataset.banAll, "", banAll.dataset.banDur || "1h", true);
    return;
  }
  const goPair = e.target.closest("#ban-goto-pair");
  if (goPair) {
    e.preventDefault();
    const dlg = $("#detail");
    if (dlg) dlg.close();
    setView("settings");
    const el = $("#pair-block");
    if (el) el.scrollIntoView({ behavior: "smooth", block: "start" });
    return;
  }
  const goBlocks = e.target.closest("[data-goto-blocks]");
  if (goBlocks) {
    e.preventDefault();
    const dlg = $("#detail");
    if (dlg) dlg.close();
    reportKind = "blocks";
    try { localStorage.setItem("gwd.report", reportKind); } catch (_) {}
    setView("reports");
    refreshReports().catch(console.error);
  }
});

let currentView = "live";
let reportKind = "vectors";
let reportRange = "24h";
let displayTZ = "UTC";
let lastReport = null;

function useLocalTime() { return displayTZ === "local"; }

function fmtWhen(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return String(iso);
  if (useLocalTime()) return d.toLocaleString();
  return d.toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

function fmtTick(iso) {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  if (useLocalTime()) {
    if (reportRange === "1h") return d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
    if (reportRange === "168h") return d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit" });
    return d.toLocaleTimeString(undefined, { hour: "2-digit" });
  }
  if (reportRange === "1h") return d.toISOString().slice(11, 16);
  if (reportRange === "168h") return d.toISOString().slice(5, 13).replace("T", " ");
  return d.toISOString().slice(11, 13) + "z";
}

function rangeLabel() {
  return { "1h": "last 1 hour", "24h": "last 24 hours", "168h": "last 7 days" }[reportRange] || reportRange;
}

function paintReportWindow(rep) {
  const el = $("#report-window");
  if (!el) return;
  const from = fmtWhen(rep && rep.since);
  const to = fmtWhen((rep && rep.until) || new Date().toISOString());
  const host = selectedSource || "all hosts";
  const bucket = (rep && rep.bucket) === "5m" ? "5-minute buckets" : (rep && rep.bucket) === "4h" ? "4-hour buckets" : (reportKind === "vectors" ? "hourly buckets" : "event time");
  let msg = host + " · " + rangeLabel() + " · " + from + " → " + to;
  if (reportKind === "vectors") msg += " · " + bucket;
  if (rep && reportKind === "vectors" && !(rep.alerts)) msg += " · no alerts in this exact window";
  el.textContent = msg;
}
try {
  currentView = localStorage.getItem("gwd.view") || "live";
  reportKind = localStorage.getItem("gwd.report") || "vectors";
  reportRange = localStorage.getItem("gwd.range") || "24h";
} catch (_) {}

function setView(v) {
  currentView = (v === "reports" || v === "settings" || v === "search" || v === "status") ? v : "live";
  try { localStorage.setItem("gwd.view", currentView); } catch (_) {}
  const live = $("#view-live");
  const reps = $("#view-reports");
  const sets = $("#view-settings");
  const sea = $("#view-search");
  const sta = $("#view-status");
  if (live) live.hidden = currentView !== "live";
  if (reps) reps.hidden = currentView !== "reports";
  if (sets) sets.hidden = currentView !== "settings";
  if (sea) sea.hidden = currentView !== "search";
  if (sta) sta.hidden = currentView !== "status";
  document.querySelectorAll("#view-tabs [data-view]").forEach(b => {
    b.classList.toggle("on", b.dataset.view === currentView);
  });
  if (currentView === "reports") refreshReports().catch(console.error);
  if (currentView === "settings") {
    loadSettings().catch(console.error);
    loadUsers().catch(() => {});
  }
  if (currentView === "status") loadStatus().catch(console.error);
}

function bytesHuman(n) {
  n = Number(n) || 0;
  if (!n) return "—";
  if (n >= 1e12) return (n / 1e12).toFixed(1) + " TB";
  if (n >= 1e9) return (n / 1e9).toFixed(1) + " GB";
  if (n >= 1e6) return (n / 1e6).toFixed(0) + " MB";
  return n + " B";
}

function pctBar(n) {
  const v = Math.max(0, Math.min(100, Number(n) || 0));
  const cls = v >= 90 ? "hot" : v >= 75 ? "warn" : "";
  return `<div class="status-bar ${cls}"><i style="width:${v}%"></i></div>`;
}

function sparkSeries(hist, key, maxHint) {
  if (!hist || hist.length < 2) return "";
  const vals = hist.map(p => Number(p[key]) || 0);
  const max = maxHint || Math.max(1, ...vals);
  return `<div class="status-spark">${vals.map(v => {
    const h = Math.max(4, Math.round((v / Math.max(max, 1)) * 100));
    return `<i style="height:${h}%" title="${v}"></i>`;
  }).join("")}</div>`;
}

function uptimeHuman(s) {
  s = Number(s) || 0;
  if (!s) return "—";
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600);
  return d ? d + "d " + h + "h" : h + "h " + Math.floor((s % 3600) / 60) + "m";
}

async function loadStatus() {
  const grid = $("#status-grid");
  if (!grid) return;
  const allBtn = $("#status-check-all");
  if (allBtn) allBtn.hidden = !isAdmin();
  const data = await j("/api/status");
  const hosts = data.hosts || [];
  if (!hosts.length) {
    grid.innerHTML = `<div class="empty">No hosts yet. Pair a sensor in Settings, or Check the manager.</div>`;
    return;
  }
  grid.innerHTML = hosts.map(h => {
    const snap = h.snapshot;
    const check = h.checked ? ago(h.checked) + " ago" : "never checked";
    const btn = isAdmin() ? `<button type="button" class="btn-quiet" data-check="${esc(h.id)}">Check now</button>` : "";
    if (!h.paired && h.id !== "local") {
      return `<article class="status-card"><h3>${esc(h.name)}</h3><div class="muted">not paired — pair in Settings to collect specs</div></article>`;
    }
    if (!snap) {
      return `<article class="status-card"><h3>${esc(h.name)}</h3><div class="muted">${esc(h.status || "")} · ${esc(check)}</div><div class="muted">no snapshot yet — click Check now</div>${btn}</article>`;
    }
    const hist = h.history || [];
    const loadMax = Math.max(1, snap.cpu_count || 1, ...hist.map(p => Number(p.load1) || 0));
    const charts = hist.length > 1 ? `<div class="status-charts">
      <div><span class="muted">Memory</span>${sparkSeries(hist, "mem_pct", 100)}</div>
      <div><span class="muted">Disk</span>${sparkSeries(hist, "disk_pct", 100)}</div>
      <div><span class="muted">Load</span>${sparkSeries(hist, "load1", loadMax)}</div>
    </div>` : `<div class="muted">Check again later to build a usage chart from your snapshots.</div>`;
    const disks = (snap.disks || []).map(d =>
      `<div class="muted">${esc(d.path)} · ${d.pct}% used · ${bytesHuman(d.free)} free of ${bytesHuman(d.total)}</div>${pctBar(d.pct)}`
    ).join("");
    const swap = snap.swap_total
      ? `<div class="muted">Swap ${snap.swap_pct || 0}% · ${bytesHuman(snap.swap_used)} of ${bytesHuman(snap.swap_total)}</div>${pctBar(snap.swap_pct)}`
      : "";
    const load = (snap.load1 || snap.load5 || snap.load15)
      ? `<div class="muted">Load ${Number(snap.load1 || 0).toFixed(2)} / ${Number(snap.load5 || 0).toFixed(2)} / ${Number(snap.load15 || 0).toFixed(2)}</div>`
      : "";
    const ver = snap.version ? ` · ${esc(snap.version)}` : "";
    return `<article class="status-card">
      <h3>${esc(h.name)}</h3>
      <div class="muted">${esc(snap.hostname || "")} · ${esc(snap.os)}/${esc(snap.arch)} · ${snap.cpu_count || "?"} CPU · up ${uptimeHuman(snap.uptime_sec)}${ver}</div>
      <div class="muted">last check ${esc(check)}</div>
      <div>Memory ${snap.mem_pct || 0}% · ${bytesHuman(snap.mem_avail)} available of ${bytesHuman(snap.mem_total)}</div>
      ${pctBar(snap.mem_pct)}
      ${swap}${load}${disks}${charts}${btn}
    </article>`;
  }).join("");
}

async function requestCheck(id) {
  const note = $("#status-note");
  try {
    if (id === "all") await j("/api/agents/check-all", { method: "POST" });
    else await j("/api/agents/" + encodeURIComponent(id) + "/check", { method: "POST" });
    if (note) note.textContent = "check sent — results land in a few seconds";
    setTimeout(() => loadStatus().catch(() => {}), 4000);
    setTimeout(() => loadStatus().catch(() => {}), 10000);
  } catch (err) {
    if (note) note.textContent = err.message || "check failed";
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
  const pair = $("#pair-block");
  if (pair) {
    const controls = pair.querySelectorAll("#pair-phrase-form, #pair-mint, #pair-phrase-wrap");
    controls.forEach(el => { el.hidden = viewer; });
  }
  const intro = form && form.querySelector(".settings-intro p");
  if (intro && viewer) {
    intro.textContent = "View only. An admin can change pins, retention, and operators.";
  }
  const checkAll = $("#status-check-all");
  if (checkAll) checkAll.hidden = viewer;
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
  displayTZ = st.timezone === "local" ? "local" : "UTC";
  if (tz) tz.value = displayTZ === "local" ? "local" : "UTC";
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
  loadPairing().catch(() => {});
}

async function loadPairing() {
  const body = $("#agents-body");
  const stEl = $("#pair-phrase-status");
  try {
    const st = await j("/api/pair-status");
    if (stEl && st.phrase_set) stEl.textContent = "phrase is set";
    agentCache = await j("/api/agents") || [];
  } catch (_) {
    agentCache = [];
    return;
  }
  if (!body) return;
  if (!agentCache.length) {
    body.innerHTML = `<tr><td colspan="5" class="empty">No paired hosts yet.</td></tr>`;
    return;
  }
  const admin = isAdmin();
  body.innerHTML = agentCache.map(a => {
    const seen = a.last_seen ? ago(a.last_seen) + " ago" : (a.seen_ip || "—");
    const acts = [];
    if (admin && a.status === "pending") {
      acts.push(`<button type="button" class="btn-quiet" data-agent-act="approve" data-id="${esc(a.id)}">Approve</button>`);
      acts.push(`<button type="button" class="btn-quiet" data-agent-act="reject" data-id="${esc(a.id)}">Reject</button>`);
    }
    if (admin && a.status === "active") {
      acts.push(`<button type="button" class="btn-quiet" data-agent-act="revoke" data-id="${esc(a.id)}">Revoke</button>`);
    }
    return `<tr>
      <td class="mono">${esc(a.name)}<div class="muted">${esc(a.fingerprint || "")}${a.hostname ? " · " + esc(a.hostname) : ""}</div></td>
      <td class="st-${esc(a.status)}">${esc(a.status)}</td>
      <td class="muted">${esc(a.seen_ip || "")} ${esc(seen)}</td>
      <td class="muted">${esc(a.block || "—")}</td>
      <td class="user-actions">${acts.join("")}</td>
    </tr>`;
  }).join("");
}

async function savePairPhrase(ev) {
  ev.preventDefault();
  const status = $("#pair-phrase-status");
  const phrase = ($("#pair-phrase") || {}).value || "";
  try {
    const r = await fetch("/api/pair-phrase", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ phrase }),
    });
    const t = await r.text();
    if (!r.ok) throw new Error(t.trim() || r.statusText);
    if (status) status.textContent = "phrase saved — it is never shown again";
    const inp = $("#pair-phrase");
    if (inp) inp.value = "";
  } catch (err) {
    if (status) status.textContent = err.message || "failed";
  }
}

async function mintPairCode() {
  const box = $("#pair-code-box");
  const status = $("#pair-mint-status");
  try {
    const r = await fetch("/api/pair-codes", { method: "POST" });
    const t = await r.text();
    if (!r.ok) throw new Error(t.trim() || r.statusText);
    const data = JSON.parse(t);
    if (box) {
      box.hidden = false;
      box.innerHTML = `On the host, as root:<br><code>gpewebdefender pair --url https://YOUR-MONITOR --name HOST --code ${esc(data.code)} --block fail2ban</code>
        <div class="pair-code">${esc(data.code)}</div>
        One-time. Expires in 15 minutes. The host will also ask for the enrollment phrase. Then Approve the fingerprint below.`;
    }
    if (status) status.textContent = "code minted";
  } catch (err) {
    if (status) status.textContent = err.message || "failed";
  }
}

async function agentAct(id, act) {
  if (act === "revoke" && !confirm("Revoke this host? It will stop taking block orders.")) return;
  const r = await fetch("/api/agents/" + encodeURIComponent(id) + "/" + act, { method: "POST" });
  if (!r.ok) throw new Error((await r.text()).trim() || r.statusText);
  await loadPairing();
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

function nameTable(rows, nameH, extra, opts) {
  if (!rows || !rows.length) return `<div class="empty">Nothing in this window</div>`;
  const iconOf = opts && opts.icon;
  return `<table class="rpt"><thead><tr><th>${esc(nameH)}</th><th>Count</th>${extra ? "<th>" + extra + "</th>" : ""}</tr></thead><tbody>` +
    rows.map(r => {
      const mark = iconOf ? iconOf(r) : "";
      const raw = r.name || r.id || r.src_ip || "";
      const label = esc(raw);
      const drill = (opts && opts.drill) ? opts.drill(r) : (/^\d{1,3}(\.\d{1,3}){3}$/.test(raw) ? `data-drill="ip" data-ip="${esc(raw)}"` : `data-drill="q" data-q="${esc(raw)}"`);
      return `<tr ${drill} style="cursor:pointer"><td class="mono">${mark}${label}</td><td>${r.count ?? r.alerts ?? 0}</td>${extra ? "<td>" + esc(r.ips || r.severity || r.country || "") + "</td>" : ""}</tr>`;
    }).join("") +
    `</tbody></table>`;
}

function hourBars(hours) {
  if (!hours || !hours.length) return `<div class="empty">No hourly buckets yet</div>`;
  const max = Math.max(1, ...hours.map(h => h.count));
  return `<div class="hours" title="alerts per hour">` +
    hours.map(h => `<i style="height:${Math.max(4, (h.count / max) * 100)}%" title="${esc(h.time)} · ${h.count}"></i>`).join("") +
    `</div>`;
}

const MITRE_NAME = {
  T1190: "Exploit public app",
  T1189: "Drive-by",
  T1110: "Brute force",
  "T1110.001": "Password guessing",
  T1595: "Active scanning",
  "T1595.002": "Wordlist scan",
  "T1595.003": "Wordlist scan",
  T1498: "Network flood",
  T1499: "Endpoint flood",
  "T1548.003": "Sudo abuse",
  T1565: "Data tamper",
  T1068: "Privilege escape",
  T1550: "Stolen token",
  T1105: "Tool transfer",
  T1556: "Auth modify",
  "T1552.001": "Loose credentials",
  T1589: "Identity gather",
  T1082: "System discovery",
};
const MITRE_TACTIC = {
  T1190: "Initial access", T1189: "Initial access",
  T1110: "Credential access", "T1110.001": "Credential access",
  T1595: "Recon", "T1595.002": "Recon", "T1595.003": "Recon",
  T1498: "Impact", T1499: "Impact",
  "T1548.003": "Privilege", T1068: "Privilege",
  T1565: "Impact", T1550: "Lateral", T1105: "Command",
  T1556: "Persistence", "T1552.001": "Credential access",
  T1589: "Recon", T1082: "Discovery",
};

function sevColor(s) {
  return { critical: "#e24a3b", high: "#e07a2f", medium: "#d4a054", low: "#6b9e7a" }[s] || "#8a8274";
}

function mixBars(rows, opts) {
  if (!rows || !rows.length) return `<div class="empty">Nothing in this window</div>`;
  const max = Math.max(1, ...rows.map(r => r.count || 0));
  return `<div class="mix">` + rows.map(r => {
    const label = (opts && opts.label) ? opts.label(r) : (r.name || r.id);
    const col = (opts && opts.color) ? opts.color(r) : catColor(r.name);
    const icon = (opts && opts.icon) ? opts.icon(r) : "";
    const tip = (opts && opts.tip) ? opts.tip(r) : "Click to search";
    const drill = (opts && opts.drill) ? opts.drill(r) : "";
    return `<div class="mix-row" ${drill} title="${esc(tip)}">
      <div class="mix-lab">${icon}<span>${esc(label)}</span></div>
      <div class="mix-track"><div class="mix-fill" style="width:${(r.count / max) * 100}%;background:${col}"></div></div>
      <div class="mix-n">${r.count ?? 0}</div>
    </div>`;
  }).join("") + `</div>`;
}

function stackHours(mix) {
  if (!mix || !mix.length) return "";
  const byT = new Map();
  const cats = [];
  const seen = new Set();
  for (const row of mix) {
    const k = row.time;
    if (!byT.has(k)) byT.set(k, { time: k, total: 0, parts: {} });
    const b = byT.get(k);
    b.parts[row.category] = (b.parts[row.category] || 0) + row.count;
    b.total += row.count;
    if (!seen.has(row.category)) { seen.add(row.category); cats.push(row.category); }
  }
  const cols = [...byT.values()];
  const max = Math.max(1, ...cols.map(c => c.total));
  const every = Math.max(1, Math.ceil(cols.length / 8));
  return `<div class="stack-wrap"><div class="stack-hours">` +
    cols.map(c => {
      const bits = cats.filter(cat => c.parts[cat]).map(cat => {
        const h = Math.max(3, (c.parts[cat] / max) * 100);
        return `<i style="height:${h}%;background:${catColor(cat)}" title="${esc(fmtWhen(c.time))} · ${esc(CAT_LABEL[cat] || cat)} · ${c.parts[cat]}"></i>`;
      }).join("");
      return `<div class="stack-col" title="${esc(fmtWhen(c.time))} · ${c.total}">${bits}</div>`;
    }).join("") +
    `</div><div class="stack-axis">` +
    cols.map((c, i) => `<span>${(i % every === 0 || i === cols.length - 1) ? esc(fmtTick(c.time)) : ""}</span>`).join("") +
    `</div></div>
    <div class="stack-key">${cats.map(c => `<span><i style="background:${catColor(c)}"></i>${esc(CAT_LABEL[c] || c)}</span>`).join("")}</div>`;
}

function hostStrip(rows) {
  if (!rows || !rows.length) return `<div class="empty">No host split in this window</div>`;
  const max = Math.max(1, ...rows.map(r => r.count || 0));
  return `<div class="host-strip">` + rows.map(r => `
    <button type="button" class="host-card" data-host="${esc(r.name)}">
      ${artImg(hostArt(r.name), "host-svg", r.name)}
      <div class="host-name">${esc(r.name)}</div>
      <div class="host-n">${r.count}</div>
      <div class="muted">${r.ips ? r.ips + " IPs" : ""}</div>
      <div class="mix-track"><div class="mix-fill" style="width:${(r.count / max) * 100}%;background:#33cfff"></div></div>
    </button>`).join("") + `</div>`;
}

function countryStrip(rows) {
  if (!rows || !rows.length) return `<div class="empty">No geo in this window</div>`;
  const max = Math.max(1, ...rows.map(r => r.count || 0));
  return `<div class="country-strip">` + rows.map(r => `
    <div class="country-chip" data-drill="q" data-q="${esc(r.name)}" title="${esc(r.name)} · ${r.count} — click to search">
      ${artImg(countryArt(r.key, r.name), "art-flag", r.name)}
      <div>
        <b>${esc(r.name)}</b>
        <div class="mix-track"><div class="mix-fill" style="width:${(r.count / max) * 100}%;background:#6b9e7a"></div></div>
      </div>
      <span class="mix-n">${r.count}</span>
    </div>`).join("") + `</div>`;
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
    return `<div class="hint-box">No application probe events yet. Your app POSTs <code>kind=secprobe</code> with a <code>reason</code> (<code>canary_hit</code>, <code>idor</code>, <code>key_replay</code>, <code>score_abuse</code>, <code>rate_limit</code>, <code>enum_burst</code>, …). Plant generic canaries at <code>/.well-known/siem-canary</code>. Never send secrets. See Docs 19.</div>`;
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
  lastReport = rep;
  paintReportWindow(rep);
  const high = (rep.by_severity || []).find(s => s.name === "high");
  $("#report-stats").innerHTML = cards([
    ["Alerts", rep.alerts ?? 0],
    ["Attacker IPs", rep.unique_ips ?? 0],
    ["Critical", rep.critical ?? 0, "crit"],
    ["High", high ? high.count : 0],
    ["Hosts hit", (rep.by_source || []).length],
    ["Countries", (rep.by_country || []).length],
  ]);
  const rules = (rep.by_rule || []).map(r => ({
    name: r.title || r.id, count: r.count, severity: r.severity, id: r.id, category: r.category,
  }));
  const stack = (rep.hour_mix && rep.hour_mix.length) ? stackHours(rep.hour_mix) : hourBars(rep.by_hour);
  $("#report-body").innerHTML =
    panel("Volume by hour", stack || `<div class="empty">No hourly buckets yet</div>`, "span2") +
    panel("What they are doing", mixBars(rep.by_category, {
      label: r => CAT_LABEL[r.name] || r.name,
      color: r => catColor(r.name),
      icon: r => artImg(typeArt(r.name), "art-inline", r.name),
      drill: r => `data-drill="q" data-q="${esc(r.name)}"`,
    })) +
    panel("Severity", mixBars(rep.by_severity, {
      color: r => sevColor(r.name),
      label: r => r.name,
      drill: r => `data-drill="q" data-q="${esc(r.name)}"`,
    })) +
    panel("MITRE techniques", mixBars(rep.by_mitre, {
      label: r => r.name + (MITRE_NAME[r.name] ? " · " + MITRE_NAME[r.name] : ""),
      color: () => "#7c6cff",
      tip: r => ((MITRE_TACTIC[r.name] || "") + (MITRE_NAME[r.name] ? " — " + MITRE_NAME[r.name] : "") + " — click to search"),
      drill: r => `data-drill="q" data-q="${esc(r.name)}"`,
    })) +
    panel("By host", hostStrip(rep.by_source), "span2") +
    panel("Origin countries", countryStrip(rep.by_country), "span2") +
    panel("Top rules", mixBars(rules, {
      label: r => r.name,
      color: r => catColor(r.category),
      drill: r => `data-drill="q" data-q="${esc(r.name)}"`,
    })) +
    panel("Paths being hit", nameTable(rep.by_path, "Path", "IPs", {
      drill: r => `data-drill="q" data-q="${esc(r.name)}"`,
    })) +
    panel("Top attacker IPs", nameTable((rep.top_ips || []).map(a => ({
      name: a.src_ip, count: a.alerts, country: a.country || a.last_title || "",
    })), "IP", "Note", {
      icon: r => artImg(countryArt(r.country, r.country), "art-flag", r.country),
      drill: r => `data-drill="ip" data-ip="${esc(r.name)}"`,
    }), "span2");
}

function renderAuthReport(rep, kind) {
  lastReport = rep;
  paintReportWindow(rep);
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
    })), "IP", "Geo / user", {
      icon: r => artImg(countryArt(r.country, r.country), "art-flag", r.country),
    })) +
    panel("Users", nameTable(rep.by_user, "User")) +
    panel("Paths / services", nameTable(rep.by_path, "Path")) +
    panel("By host", nameTable(rep.by_source, "Source")) +
    panel("Recent failures", recent
      ? `<table class="rpt"><thead><tr><th>When</th><th>IP</th><th>User</th><th>Where</th><th>Result</th><th>Src</th></tr></thead><tbody>${recent}</tbody></table>`
      : `<div class="empty">None</div>`, "span2");
}

function leftLabel(until, active) {
  if (!active) return "ended";
  if (!until) return "until you unban";
  const ms = new Date(until).getTime() - Date.now();
  if (Number.isNaN(ms) || ms <= 0) return "ending";
  const m = Math.max(1, Math.round(ms / 60000));
  if (m < 90) return m + "m left";
  const h = Math.round(m / 60);
  if (h < 48) return h + "h left";
  return Math.round(h / 24) + "d left";
}

function appliedLabel(s) {
  return { applied: "on the host", failed: "sensor failed", queued: "waiting on sensor" }[s] || (s || "waiting");
}

function renderBlockReport(rep) {
  const stats = $("#report-stats");
  const box = $("#report-body");
  const n = (rep && rep.active) || 0;
  const ips = (rep && rep.ips) || 0;
  stats.innerHTML = `
    <div class="card"><div class="k">Active bans</div><div class="v">${n}</div></div>
    <div class="card"><div class="k">IPs</div><div class="v">${ips}</div></div>
    <div class="card"><div class="k">Applied</div><div class="v">${(rep && rep.applied) || 0}</div></div>
    <div class="card"><div class="k">Waiting</div><div class="v">${(rep && rep.queued) || 0}</div></div>
    <div class="card"><div class="k">Failed</div><div class="v">${(rep && rep.failed) || 0}</div></div>
    <div class="card"><div class="k">Rows</div><div class="v">${((rep && rep.rows) || []).length}</div></div>`;
  const el = $("#report-window");
  if (el) el.textContent = "current blocklist · one row per host · hits after ban should stay 0 if it is working";
  const all = (rep && rep.rows) || [];
  const rows = all.filter(r => r.active);
  const old = all.filter(r => !r.active).slice(0, 20);
  const line = r => {
    const why = r.title || "—";
    const num = r.alert_num ? "#" + r.alert_num : "";
    const scope = r.scope === "all" ? "all paired hosts" : "this host";
    const hits = r.active ? (r.hits_after ? r.hits_after + " hits after ban" : "no hits since") : "";
    const unban = r.active && isAdmin()
      ? `<button type="button" class="btn-quiet" data-unban-host="${esc(r.agent_id)}" data-unban-ip="${esc(r.ip)}">Unban</button>`
      : "";
    return `<tr>
      <td class="mono" data-drill="ip" data-ip="${esc(r.ip)}" style="cursor:pointer">${esc(r.ip)}</td>
      <td>${esc(r.host || "—")}<div class="muted">${esc(scope)}</div></td>
      <td>${esc(why)} ${num ? `<span class="muted">${esc(num)}</span>` : ""}<div class="muted">${esc(CAT_LABEL[r.category] || r.category || "")}</div></td>
      <td>${esc(appliedLabel(r.applied))}<div class="muted">${esc(hits)}</div></td>
      <td>${esc(leftLabel(r.until, r.active))}<div class="muted">${esc(r.duration || "")} · ${esc(r.created_by || "")}</div></td>
      <td>${unban}</td>
    </tr>`;
  };
  const table = list => !list.length
    ? `<div class="empty">None</div>`
    : `<table class="rpt"><thead><tr><th>IP</th><th>Host</th><th>Blocked for</th><th>On the box?</th><th>Time left</th><th></th></tr></thead><tbody>${list.map(line).join("")}</tbody></table>`;
  const emptyHelp = `<div class="hint-box">Nothing is banned right now. Open an alert on <strong>Live</strong>, then <strong>Block on this host</strong> (15m / 1h / 24h / 7d) or all paired hosts. This page lists the IP, which host, the alert that caused it, whether the sensor applied it, time left, and hits after the ban (should stay 0).</div>`;
  box.innerHTML = (rows.length || old.length
    ? panel("Currently blocked", table(rows), "span2") + panel("Recently ended", table(old), "span2")
    : panel("Currently blocked", emptyHelp, "span2"));
}

let reportSeq = 0;

function reportTabLabel(kind) {
  return ({
    vectors: "Insight", web: "Auth · Web", linux: "Auth · Linux",
    app: "Auth · App", tenant: "Auth · Tenants", probes: "Probes", blocks: "Blocklist",
  })[kind] || kind;
}

async function refreshReports() {
  const seq = ++reportSeq;
  const kind = reportKind;
  markReportChrome();
  const box = $("#report-body");
  const stats = $("#report-stats");
  if (!box || !stats) return;
  stats.innerHTML = "";
  box.innerHTML = `<div class="empty">Loading ${esc(reportTabLabel(kind))}…</div>`;
  try {
    const st = await j("/api/settings");
    if (seq !== reportSeq) return;
    const cur = (st && st.settings) || st || {};
    if (cur.timezone) displayTZ = cur.timezone === "local" ? "local" : "UTC";
  } catch (_) {}
  if (seq !== reportSeq) return;
  const params = new URLSearchParams({ since: reportRange });
  if (selectedSource) params.set("source", selectedSource);
  try {
    if (kind === "vectors") {
      const data = await j("/api/reports/vectors?" + params.toString());
      if (seq !== reportSeq) return;
      renderVectorReport(data);
      return;
    }
    if (kind === "blocks") {
      const data = await j("/api/reports/blocks");
      if (seq !== reportSeq) return;
      renderBlockReport(data);
      return;
    }
    params.set("channel", kind);
    const data = await j("/api/reports/auth?" + params.toString());
    if (seq !== reportSeq) return;
    renderAuthReport(data, kind);
  } catch (err) {
    if (seq !== reportSeq) return;
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
    try { localStorage.setItem("gwd.report", reportKind); } catch (_) {}
    refreshReports().catch(console.error);
  });
}
const reportBody = $("#report-body");
if (reportBody && !reportBody.dataset.bound) {
  reportBody.dataset.bound = "1";
  reportBody.addEventListener("click", async (e) => {
    const host = e.target.closest("[data-host]");
    if (host) {
      const name = host.dataset.host;
      if (!name || name === "(none)") return;
      selectedSource = name;
      try { localStorage.setItem("gwd.source", selectedSource); } catch (_) {}
      fillHostSelect();
      refresh().catch(console.error);
      return;
    }
    const unban = e.target.closest("[data-unban-host]");
    if (unban) {
      if (!confirm("Unban " + unban.dataset.unbanIp + " on this host?")) return;
      try {
        const r = await fetch("/api/agents/" + encodeURIComponent(unban.dataset.unbanHost) + "/unban", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ ip: unban.dataset.unbanIp }),
        });
        if (!r.ok) throw new Error((await r.text()).trim() || r.statusText);
        refreshReports().catch(console.error);
      } catch (err) {
        alert(err.message || "unban failed");
      }
      return;
    }
    const hit = e.target.closest("[data-drill]");
    if (!hit) return;
    const kind = hit.dataset.drill;
    const ip = hit.dataset.ip || "";
    const q = hit.dataset.q || "";
    setView("search");
    if ($("#sip")) $("#sip").value = kind === "ip" ? ip : "";
    if ($("#sq")) $("#sq").value = kind === "ip" ? "" : q;
    if ($("#shost")) $("#shost").value = selectedSource || "";
    runSearch().catch(console.error);
  });
}
async function downloadExport(format) {
  if (reportKind === "blocks") {
    const data = await j("/api/reports/blocks");
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "gwd-blocklist.json";
    document.body.appendChild(a);
    a.click();
    a.remove();
    return;
  }
  const params = new URLSearchParams({ since: reportRange, format });
  if (selectedSource) params.set("source", selectedSource);
  const path = reportKind === "vectors" ? "/api/export/alerts" : "/api/export/events";
  if (reportKind !== "vectors") params.set("channel", reportKind);
  const r = await fetch(path + "?" + params.toString(), { credentials: "same-origin" });
  if (r.status === 401) { goLogin(); throw new Error("unauthorized"); }
  if (!r.ok) throw new Error((await r.text()).trim() || r.statusText);
  const blob = await r.blob();
  const cd = r.headers.get("Content-Disposition") || "";
  const m = /filename="([^"]+)"/.exec(cd);
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = (m && m[1]) || ("gwd-export." + format);
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 2000);
}

function copyReportSummary() {
  if (!lastReport || !navigator.clipboard) return;
  const body = {
    window: { since: lastReport.since, until: lastReport.until, range: reportRange, source: selectedSource || "all" },
    alerts: lastReport.alerts,
    unique_ips: lastReport.unique_ips,
    critical: lastReport.critical,
    by_category: lastReport.by_category,
    by_severity: lastReport.by_severity,
    by_mitre: lastReport.by_mitre,
    by_source: lastReport.by_source,
    by_country: lastReport.by_country,
    top_ips: lastReport.top_ips,
    fails: lastReport.fails,
    channel: lastReport.channel,
  };
  navigator.clipboard.writeText(JSON.stringify(body, null, 2)).catch(() => {});
}

const expCsv = $("#exp-csv");
if (expCsv) expCsv.addEventListener("click", () => downloadExport("csv").catch(console.error));
const expJson = $("#exp-json");
if (expJson) expJson.addEventListener("click", () => downloadExport("json").catch(console.error));
const expCopy = $("#exp-copy");
if (expCopy) expCopy.addEventListener("click", () => copyReportSummary());

const reportRangeEl = $("#report-range");
if (reportRangeEl) {
  reportRangeEl.addEventListener("click", (e) => {
    const b = e.target.closest("button[data-range]");
    if (!b) return;
    reportRange = b.dataset.range;
    try { localStorage.setItem("gwd.range", reportRange); } catch (_) {}
    refreshReports().catch(console.error);
  });
}

let searchOldest = false;
try { searchOldest = localStorage.getItem("gwd.searchSort") === "oldest"; } catch (_) {}

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
    try { localStorage.setItem("gwd.searchSort", searchOldest ? "oldest" : "newest"); } catch (_) {}
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
const pairPhraseForm = $("#pair-phrase-form");
if (pairPhraseForm) pairPhraseForm.addEventListener("submit", savePairPhrase);
const pairMint = $("#pair-mint");
if (pairMint) pairMint.addEventListener("click", mintPairCode);
const agentsBody = $("#agents-body");
if (agentsBody) {
  agentsBody.addEventListener("click", (ev) => {
    const b = ev.target.closest("[data-agent-act]");
    if (!b) return;
    agentAct(b.dataset.id, b.dataset.agentAct).catch(err => {
      const s = $("#pair-mint-status");
      if (s) s.textContent = err.message || "failed";
    });
  });
}
const statusCheckAll = $("#status-check-all");
if (statusCheckAll) statusCheckAll.addEventListener("click", () => requestCheck("all"));
const statusGrid = $("#status-grid");
if (statusGrid) {
  statusGrid.addEventListener("click", (e) => {
    const b = e.target.closest("[data-check]");
    if (b) requestCheck(b.dataset.check);
  });
}
const logoutBtn = $("#logout");
if (logoutBtn) logoutBtn.addEventListener("click", doLogout);

const alertList = $("#alerts");


bootAuth().then(() => {
  connect();
  setView(currentView);
  loadSettings().catch(() => {});
  loadUsers().catch(() => {});
  refresh().catch(err => {
    const box = $("#alerts");
    if (box) box.innerHTML = `<div class="empty">${esc(err.message)}</div>`;
  });
  setInterval(() => {
    if (document.hidden) return;
    if (currentView !== "live" && currentView !== "reports") return;
    refresh().catch(() => {});
  }, 12000);
});
