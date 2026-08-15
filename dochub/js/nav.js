/** Shared sidebar for the SIEM DocHub.
 * Chapter order is strictly numerical 00 → 17.
 */
(function () {
  const base = document.body.dataset.base || ".";
  const html = `
  <div class="brand">
    <a href="${base}/index.html">
      <div class="brand-mark"><span class="dot"></span> GPEWebDefender</div>
      <div class="brand-sub">Web-attack monitor · truth map</div>
    </a>
  </div>
  <h3>Start here</h3>
  <a href="${base}/index.html">Hub home</a>
  <a href="${base}/pages/00-what-this-is.html">00 · What this is</a>
  <a href="${base}/pages/01-what-it-is-not.html">01 · What it is not</a>
  <a href="${base}/pages/02-architecture.html">02 · Architecture</a>
  <h3>Run it</h3>
  <a href="${base}/pages/03-install-and-run.html">03 · Install &amp; run</a>
  <a href="${base}/pages/04-demo-vs-live.html">04 · Demo vs live</a>
  <a href="${base}/pages/05-log-formats.html">05 · Log formats</a>
  <h3>Detection</h3>
  <a href="${base}/pages/06-detection-engine.html">06 · Detection engine</a>
  <a href="${base}/pages/07-rule-catalog.html">07 · Rule catalog</a>
  <h3>Operate</h3>
  <a href="${base}/pages/08-ui-and-api.html">08 · UI &amp; API</a>
  <a href="${base}/pages/09-agent-and-hosts.html">09 · Agent &amp; hosts</a>
  <a href="${base}/pages/10-deploy.html">10 · Deploy</a>
  <h3>Honesty</h3>
  <a href="${base}/pages/11-limits-and-honesty.html">11 · Limits &amp; honesty</a>
  <a href="${base}/pages/12-roadmap.html">12 · Roadmap</a>
  <a href="${base}/pages/13-attack-map.html">13 · Attack map</a>
  <a href="${base}/pages/14-snoop-and-canaries.html">14 · Snoop &amp; canaries</a>
  <a href="${base}/pages/15-production-edge.html">15 · Production edge</a>
  <a href="${base}/pages/16-reports-and-auth.html">16 · Reports &amp; auth</a>
  <a href="${base}/pages/17-configure.html">17 · Configure it</a>
  `;
  const el = document.getElementById("dochub-nav");
  if (el) el.innerHTML = html;
})();
