/* DocHub shared behavior */
(function () {
  // Active nav link
  const path = location.pathname.replace(/\/+$/, "") || "/";
  const file = path.split("/").pop() || "index.html";
  document.querySelectorAll(".side a[href]").forEach((a) => {
    const href = a.getAttribute("href") || "";
    const name = href.split("/").pop();
    if (name === file || (file === "" && name === "index.html")) {
      a.classList.add("active");
    }
    if (path.endsWith(href.replace(/^\.\.\//, "").replace(/^\.\//, ""))) {
      a.classList.add("active");
    }
  });

  // Mobile nav
  const toggle = document.querySelector(".nav-toggle");
  const side = document.querySelector(".side");
  if (toggle && side) {
    toggle.addEventListener("click", () => side.classList.toggle("open"));
    document.addEventListener("click", (e) => {
      if (!side.contains(e.target) && !toggle.contains(e.target)) {
        side.classList.remove("open");
      }
    });
  }

  // Mermaid
  if (window.mermaid) {
    mermaid.initialize({
      startOnLoad: true,
      theme: "dark",
      securityLevel: "loose",
      flowchart: { curve: "basis", htmlLabels: true, useMaxWidth: true },
      themeVariables: {
        primaryColor: "#172235",
        primaryTextColor: "#e8eef7",
        primaryBorderColor: "#5eb1ff",
        lineColor: "#5eb1ff",
        secondaryColor: "#121b2b",
        tertiaryColor: "#0d1420",
        background: "#070b12",
        mainBkg: "#121b2b",
        nodeBorder: "#3a4f6b",
        clusterBkg: "#0d1420",
        clusterBorder: "#243044",
        titleColor: "#e8eef7",
        edgeLabelBackground: "#0d1420",
      },
    });
  }

  // Stamp generated time if placeholder present
  const stamp = document.querySelector("[data-generated]");
  if (stamp && !stamp.textContent.trim()) {
    stamp.textContent = new Date().toISOString().slice(0, 10);
  }
})();
