/* CSP-friendly: no inline scripts. Chart data comes from <script type="application/json" id="chart-data">. */
(function () {
  "use strict";
  var COLORS = { PASS: "#1f7a4d", WARN: "#b7791f", BLOCK: "#b42318", ERROR: "#5b2a86" };
  var SEV = { Critical: "#7a1b1b", High: "#c4402f", Medium: "#d98a1c", Low: "#4f7cac", Info: "#7b8794" };

  var node = document.getElementById("chart-data");
  if (node && window.Chart) {
    var d = JSON.parse(node.textContent);
    var trend = document.getElementById("chart-trend");
    if (trend && d.trend.length) {
      new Chart(trend, {
        type: "bar",
        data: {
          labels: d.trend.map(function (t) { return t.label; }),
          datasets: [{
            label: "Findings per run",
            data: d.trend.map(function (t) { return t.total; }),
            backgroundColor: d.trend.map(function (t) { return COLORS[t.decision] || "#98a2b3"; })
          }]
        },
        options: { maintainAspectRatio: false, plugins: { legend: { display: false },
          tooltip: { callbacks: { afterLabel: function (c) { return "Decision: " + d.trend[c.dataIndex].decision; } } } },
          scales: { y: { beginAtZero: true, ticks: { precision: 0 } } } }
      });
    }
    var sev = document.getElementById("chart-severity");
    if (sev) {
      var labels = Object.keys(d.severity);
      new Chart(sev, {
        type: "doughnut",
        data: { labels: labels, datasets: [{ data: labels.map(function (k) { return d.severity[k]; }),
          backgroundColor: labels.map(function (k) { return SEV[k]; }) }] },
        options: { maintainAspectRatio: false, plugins: { legend: { position: "right" } } }
      });
    }
  }

  document.addEventListener("click", function (e) {
    var t = e.target.closest("[data-copy]");
    if (t) { navigator.clipboard && navigator.clipboard.writeText(t.getAttribute("data-copy")); t.textContent = "Copied"; }
    var c = e.target.closest("[data-confirm]");
    if (c && !window.confirm(c.getAttribute("data-confirm"))) { e.preventDefault(); }
  });

  var sel = document.getElementById("status-select");
  var box = document.getElementById("accept-fields");
  if (sel && box) {
    var sync = function () { box.classList.toggle("d-none", sel.value !== "Accepted"); };
    sel.addEventListener("change", sync); sync();
  }
})();
