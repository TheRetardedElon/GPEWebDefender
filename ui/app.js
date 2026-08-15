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
};
const COUNTRY_ALIAS = {
  "united states": "us", usa: "us", america: "us",
  "the netherlands": "nl", netherlands: "nl", holland: "nl",
  switzerland: "ch", japan: "jp", china: "cn", germany: "de",
  indonesia: "id", ireland: "ie", malaysia: "my", russia: "ru",
  andorra: "ad", liberia: "lr", "dominican republic": "do",
  canada: "ca", egypt: "eg", singapore: "sg",
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
    el.addEventListener("click", () => {
      query = el.dataset.ip;
      $("#q").value = query;
      refresh();
    });
  });
}

function openDetail(a) {
  const d = $("#detail");
  const originName = a.country_name || a.country || "";
  const originSrc = countryArt(a.country, a.country_name);
  const catSrc = typeArt(a.category);
  const hostSrc = a.source ? hostArt(a.source) : "";
  const regionSrc = a.source ? hostRegionArt(a.source) : "";
  const tile = (src, cap, extra) => {
    if (!src && !cap) return "";
    return `<div class="detail-art">
      ${artImg(src, "detail-svg", cap)}
      ${extra ? artImg(extra, "detail-svg sub", cap) : ""}
      <span class="cap">${esc(cap || "—")}</span>
    </div>`;
  };
  d.querySelector("article").innerHTML = `
    <div class="detail-hero">
      ${tile(originSrc, originName || (a.src_ip || "origin"))}
      ${tile(catSrc, CAT_LABEL[a.category] || a.category || "event")}
      ${tile(hostSrc, a.source || "host", regionSrc)}
    </div>
    <h3>${esc(a.title)}</h3>
    <dl>
      <dt>Number</dt><dd>${a.num ? "#" + a.num : "—"}</dd>
      <dt>Severity</dt><dd>${esc(a.severity)} · ${esc(a.category)}</dd>
      <dt>Tags</dt><dd>${esc((a.tags || []).join(", ") || "—")}</dd>
      <dt>When</dt><dd>${esc(a.time)}</dd>
      <dt>Source IP</dt><dd>${esc(a.src_ip)}</dd>
      <dt>Country</dt><dd>${esc(originName || "—")}</dd>
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
    if (selectedSource) fitHomes();
    else { mapCam.z = 1; mapCam.x = 0; mapCam.y = 0; }
    refresh().catch(console.error);
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
  if (!b) return;
  toggleCat(b.dataset.cat || "");
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

async function refreshReports() {
  markReportChrome();
  try {
    const st = await j("/api/settings");
    const cur = (st && st.settings) || st || {};
    if (cur.timezone) displayTZ = cur.timezone === "local" ? "local" : "UTC";
  } catch (_) {}
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
const reportBody = $("#report-body");
if (reportBody && !reportBody.dataset.bound) {
  reportBody.dataset.bound = "1";
  reportBody.addEventListener("click", (e) => {
    const host = e.target.closest("[data-host]");
    if (host) {
      const name = host.dataset.host;
      if (!name || name === "(none)") return;
      selectedSource = name;
      try { localStorage.setItem("gpesiem.source", selectedSource); } catch (_) {}
      fillHostSelect();
      refresh().catch(console.error);
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
  a.download = (m && m[1]) || ("gpesiem-export." + format);
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
  setInterval(() => {
    if (document.hidden) return;
    if (currentView !== "live" && currentView !== "reports") return;
    refresh().catch(() => {});
  }, 12000);
});
