"use strict";

(() => {
  const $ = (id) => document.getElementById(id);
  const state = { notices: [], status: null, loading: false, visible: 6, expanded: new Set(), lastUpdated: null, feedError: false };
  const names = { "cisa-kev": "CISA KEV", nvd: "NVD", x: "X / Twitter", "ubuntu-usn": "Ubuntu notices", ubuntu: "Ubuntu notices" };
  const MAX_BODY_BYTES = 3 * 1024 * 1024;

  function node(tag, className, text) {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (text !== undefined) element.textContent = text;
    return element;
  }

  function boundedString(value, limit = 500) {
    return typeof value === "string" ? value.slice(0, limit) : "";
  }

  function validSequence(value) {
    return Number.isSafeInteger(value) && value >= 0;
  }

  function sourceName(value) {
    return (Object.hasOwn(names, value) ? names[value] : "") || value.replaceAll("-", " ").replaceAll("_", " ");
  }

  function safeURL(value) {
    try {
      const url = new URL(value);
      if (!["https:", "http:"].includes(url.protocol) || url.username || url.password) return null;
      return url.href;
    } catch {
      return null;
    }
  }

  function dateValue(value) {
    if (typeof value !== "string" || !value.trim()) return null;
    const date = new Date(value);
    return Number.isFinite(date.getTime()) && date.getTime() >= 0 ? date : null;
  }

  function age(value) {
    const date = dateValue(value);
    if (!date) return "Date unknown";
    const minutes = Math.floor((Date.now() - date.getTime()) / 60000);
    const calendarDate = () => date.toLocaleDateString(undefined, { month: "short", day: "numeric", ...(date.getFullYear() !== new Date().getFullYear() ? { year: "numeric" } : {}) });
    if (minutes < -1) return calendarDate();
    if (minutes < 1) return "Just now";
    if (minutes < 60) return `${minutes}m ago`;
    if (minutes < 1440) return `${Math.floor(minutes / 60)}h ago`;
    if (minutes < 10080) return `${Math.floor(minutes / 1440)}d ago`;
    return calendarDate();
  }

  async function getJSON(path) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);
    try {
      const response = await fetch(path, { signal: controller.signal, cache: "no-store", credentials: "omit", redirect: "error", headers: { Accept: "application/json" } });
      if (!response.ok) throw new Error("Feed request failed");
      const size = Number(response.headers.get("content-length"));
      if (size > MAX_BODY_BYTES) throw new Error("Feed response exceeds limit");
      const reader = response.body.getReader();
      const chunks = [];
      let received = 0;
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        received += value.byteLength;
        if (received > MAX_BODY_BYTES) {
          await reader.cancel();
          throw new Error("Feed response exceeds limit");
        }
        chunks.push(value);
      }
      const bytes = new Uint8Array(received);
      let offset = 0;
      for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
      return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    } finally {
      clearTimeout(timeout);
    }
  }

  function recentNotices(result) {
    // This endpoint is an unsigned display view sorted by publication date.
    // Host agents use the separate signed cursor feed with a pinned key.
    if (!result || result.version !== 1 || result.kind !== "recent_notices" || !Array.isArray(result.notices) || result.notices.length > 500) throw new Error("Unsupported recent notice response");
    return result.notices.map(normalizeNotice).filter(Boolean).sort((a, b) => {
      const publishedA = dateValue(a.published)?.getTime() ?? -1;
      const publishedB = dateValue(b.published)?.getTime() ?? -1;
      return publishedB - publishedA || b.seq - a.seq;
    }).slice(0, 60);
  }

  function normalizeNotice(notice) {
    if (!notice || !validSequence(notice.seq) || typeof notice.title !== "string" || typeof notice.source !== "string" || notice.untrusted !== true) return null;
    return {
      seq: notice.seq,
      source: boundedString(notice.source, 100),
      id: boundedString(notice.id, 300),
      title: boundedString(notice.title, 600) || "Untitled advisory",
      summary: boundedString(notice.summary, 10000),
      url: safeURL(boundedString(notice.url, 4000)),
      cves: Array.isArray(notice.cves) ? notice.cves.filter((value) => typeof value === "string" && /^CVE-\d{4}-\d{4,}$/.test(value)).slice(0, 30) : [],
      published: boundedString(notice.published_at, 80),
      observed: boundedString(notice.observed_at, 80),
    };
  }

  function filteredNotices() {
    const query = $("notice-search").value.trim().toLocaleLowerCase();
    const source = $("source-filter").value;
    return state.notices.filter((notice) => (!source || notice.source === source) && (!query || `${notice.title} ${notice.summary} ${notice.cves.join(" ")} ${notice.source}`.toLocaleLowerCase().includes(query)));
  }

  function placeholder(title, detail) {
    const box = node("div", "feed-placeholder empty");
    box.append(node("span", "loading-mark", "⌁"), node("p", "", title), node("span", "", detail));
    $("notice-list").replaceChildren(box);
  }

  function renderNotices() {
    const selected = filteredNotices();
    const list = $("notice-list");
    if (!selected.length) {
      if (state.notices.length) placeholder("No matching notices", "Try a different source, CVE identifier, or package name.");
      else if (state.feedError) placeholder("The notice feed is unavailable", "The board will retry automatically. An unavailable feed does not mean there are no vulnerabilities.");
      else placeholder("No notices published yet", "New disclosures appear here after the hub receives them. Source coverage is shown below.");
    } else {
      const fragment = document.createDocumentFragment();
      for (const notice of selected.slice(0, state.visible)) {
        const row = node("article", "notice-row");
        const source = node("div", "notice-source");
        source.append(node("span", "source-label", sourceName(notice.source)));
        const main = node("div", "notice-main");
        const button = node("button", "notice-title", notice.title);
        button.type = "button";
        const detailID = `notice-detail-${notice.seq}`;
        button.setAttribute("aria-controls", detailID);
        button.setAttribute("aria-expanded", state.expanded.has(notice.seq) ? "true" : "false");
        main.append(button);
        if (notice.cves.length) main.append(node("span", "notice-cves", notice.cves.join(" · ")));
        const hasPublished = Boolean(dateValue(notice.published));
        const timestamp = hasPublished ? notice.published : notice.observed;
        const displayAge = age(timestamp);
        const time = node("time", "", !hasPublished && dateValue(timestamp) ? `Seen ${displayAge === "Just now" ? "now" : displayAge}` : displayAge);
        const date = dateValue(timestamp);
        if (date) { time.dateTime = date.toISOString(); time.title = `${hasPublished ? "Published" : "Observed by hub; publication date unknown"}: ${date.toLocaleString()} (${date.toISOString()})`; }
        const link = notice.url ? node("a", "notice-source-link", "↗") : node("span", "notice-source-link", "—");
        if (notice.url) {
          link.href = notice.url;
          link.target = "_blank";
          link.rel = "noopener noreferrer";
          link.setAttribute("aria-label", `Read original source: ${notice.title}`);
        }
        const detail = node("div", "notice-detail");
        detail.id = detailID;
        detail.hidden = !state.expanded.has(notice.seq);
        detail.append(node("p", "", notice.summary || "No summary was provided. Open the original source for details."));
        detail.append(node("p", "", "Untrusted notice data. Applicability and evidence of compromise require local investigation."));
        button.addEventListener("click", () => {
          const expanded = !state.expanded.has(notice.seq);
          if (expanded) state.expanded.add(notice.seq); else state.expanded.delete(notice.seq);
          button.setAttribute("aria-expanded", String(expanded));
          detail.hidden = !expanded;
        });
        row.append(source, main, time, link, detail);
        fragment.append(row);
      }
      list.replaceChildren(fragment);
    }
    $("show-more").hidden = selected.length <= state.visible;
    const count = selected.length;
    const shown = Math.min(count, state.visible);
    const updated = state.lastUpdated ? ` · Updated ${state.lastUpdated.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" })}` : "";
    $("feed-result").textContent = state.feedError ? `Feed unavailable${count ? " · Showing previously loaded notices" : ""}` : `${shown} of ${count} recent ${count === 1 ? "notice" : "notices"}${updated}`;
  }

  function updateSourceOptions() {
    const select = $("source-filter");
    const previous = select.value;
    const sources = new Set(state.notices.map((notice) => notice.source));
    for (const source of state.status?.sources || []) if (source && typeof source.name === "string") sources.add(source.name.slice(0, 100));
    const options = [node("option", "", "All sources")];
    options[0].value = "";
    for (const source of [...sources].sort()) { const option = node("option", "", sourceName(source)); option.value = source; options.push(option); }
    select.replaceChildren(...options);
    if (sources.has(previous)) select.value = previous;
  }

  function renderSources() {
    const container = $("source-status-list");
    if (!state.status) {
      container.replaceChildren(node("p", "muted", "Source status is unavailable."));
      return;
    }
    const sources = Array.isArray(state.status.sources) ? state.status.sources.filter((source) => source && typeof source.name === "string").slice(0, 30) : [];
    if (!sources.length) container.replaceChildren(node("p", "muted", "No intake sources are configured."));
    else {
      const rows = sources.map((source) => {
        const status = source.state === "healthy" ? "healthy" : source.state === "degraded" ? "degraded" : "pending";
        const row = node("div", "source-status-row");
        const dot = node("span", `status-dot ${status}`);
        dot.setAttribute("aria-hidden", "true");
        const label = node("span", "source-status-name", sourceName(boundedString(source.name, 100)) || "Unnamed source");
        let description = status === "healthy" ? "Polling normally" : status === "degraded" ? "Upstream unavailable" : "Waiting for first poll";
        if (source.error_code === "not_configured") description = "Credential not configured";
        const text = node("span", status === "healthy" ? "visually-hidden" : `source-status-state ${status}`, status === "healthy" ? `: ${description}` : description);
        if (source.last_success && dateValue(source.last_success)) row.title = `Last successful intake: ${new Date(source.last_success).toLocaleString()}`;
        row.append(dot, label, text);
        return row;
      });
      container.replaceChildren(...rows);
    }
  }

  function renderFeedState() {
    const status = $("feed-state");
    let label = "Feed available";
    let kind = "healthy";
    if (state.feedError) { label = "Feed unavailable"; kind = "degraded"; }
    else if (!state.status) { label = "Source status unknown"; kind = "pending"; }
    else if (state.status.degraded) { label = "Partial source coverage"; kind = "degraded"; }
    const dot = node("span", `status-dot ${kind}`); dot.setAttribute("aria-hidden", "true");
    status.replaceChildren(dot, document.createTextNode(label));
  }

  async function refresh() {
    if (state.loading) return;
    state.loading = true;
    $("refresh-notices").disabled = true;
    try {
      let status = null;
      try {
        const result = await getJSON("/api/v1/status");
        if (!result || result.version !== 1 || result.service !== "firefighter-hub" || !validSequence(result.latest_sequence) || !Array.isArray(result.sources)) throw new Error("Unsupported status response");
        status = result;
      } catch { /* Notices may still be usable when the status endpoint is unavailable. */ }
      state.status = status;
      state.notices = recentNotices(await getJSON("/api/v1/recent?limit=60"));
      const currentIDs = new Set(state.notices.map((notice) => notice.seq));
      for (const id of state.expanded) if (!currentIDs.has(id)) state.expanded.delete(id);
      state.lastUpdated = new Date();
      state.feedError = false;
    } catch {
      state.feedError = true;
    } finally {
      state.loading = false;
      $("refresh-notices").disabled = false;
      updateSourceOptions(); renderNotices(); renderSources(); renderFeedState();
    }
  }

  $("notice-search").addEventListener("input", () => { state.visible = 6; renderNotices(); });
  $("source-filter").addEventListener("change", () => { state.visible = 6; renderNotices(); });
  $("refresh-notices").addEventListener("click", refresh);
  $("show-more").addEventListener("click", () => { state.visible += 6; renderNotices(); });

  for (const button of document.querySelectorAll("[data-copy]")) {
    button.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText($(button.dataset.copy).textContent);
        button.textContent = "Copied";
        $("copy-status").textContent = "Setup command copied.";
        setTimeout(() => { button.textContent = "Copy"; }, 1800);
      } catch {
        const range = document.createRange(); range.selectNodeContents($(button.dataset.copy));
        const selection = window.getSelection(); selection.removeAllRanges(); selection.addRange(range);
        $("copy-status").textContent = "Clipboard unavailable. The command is selected for manual copying.";
      }
    });
  }
  refresh();
  setInterval(() => { if (!document.hidden) refresh(); }, 30000);
  document.addEventListener("visibilitychange", () => { if (!document.hidden) refresh(); });
})();
