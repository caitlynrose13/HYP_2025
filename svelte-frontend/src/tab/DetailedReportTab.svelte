<script lang="ts">
  import { theme } from "../stores/themeStore";
  import { onMount } from "svelte";
  import { get } from "svelte/store";

  export let handleGoBack: () => void;
  export let tlsReportData: any;

  $: cert = tlsReportData || {};

  // Spinner and error states for external scans
  let mozillaLoading = false;
  let mozillaError: string | null = null;
  let ssllabsLoading = false;
  let ssllabsError: string | null = null;

  async function fetchMozillaObservatory(domain: string) {
    mozillaLoading = true;
    mozillaError = null;
    try {
      const resp = await fetch(
        `http://127.0.0.1:8080/api/observatory?domain=${encodeURIComponent(domain)}&scan_type=observatory`
      );
      if (!resp.ok) throw new Error(await resp.text());
      const mozillaResult = await resp.json();
      cert.mozilla_observatory_grade = mozillaResult.grade;
      cert.mozilla_observatory_scan_time = mozillaResult.scan_duration;
      cert = { ...cert };
    } catch (e: any) {
      mozillaError =
        e.message || "Failed to fetch Mozilla Observatory results.";
      cert.mozilla_observatory_grade = undefined;
      cert.mozilla_observatory_scan_time = undefined;
      cert = { ...cert };
    } finally {
      mozillaLoading = false;
    }
  }

  async function fetchSsllabs(domain: string) {
    ssllabsLoading = true;
    ssllabsError = null;
    try {
      const resp = await fetch(
        `http://127.0.0.1:8080/api/observatory?domain=${encodeURIComponent(domain)}&scan_type=ssllabs`
      );
      if (!resp.ok) throw new Error(await resp.text());
      const ssllabsResult = await resp.json();
      cert.ssllabs_grade = ssllabsResult.grade;
      cert.ssllabs_scan_time = ssllabsResult.scan_duration;
      cert = { ...cert };
    } catch (e: any) {
      ssllabsError = e.message || "Failed to fetch SSL Labs results.";
      cert.ssllabs_grade = undefined;
      cert.ssllabs_scan_time = undefined;
      cert = { ...cert };
    } finally {
      ssllabsLoading = false;
    }
  }

  // Theme and scan initialization
  onMount(() => {
    const savedTheme =
      localStorage.getItem("darkMode") === "true" ? "dark" : "light";
    theme.set(savedTheme);

    const setTheme = (value: string) => {
      document.body.setAttribute("data-theme", value);
      document.documentElement.setAttribute("data-theme", value);
      const tabContainer = document.querySelector(".tab-container");
      if (tabContainer) tabContainer.setAttribute("data-theme", value);
    };

    setTheme(savedTheme);
    theme.subscribe(setTheme);

    if (cert.domain) {
      fetchMozillaObservatory(cert.domain);
      fetchSsllabs(cert.domain);
    }
  });

  // Helper to format date string to 'DD Mon YYYY'
  function formatDate(dateStr: string): string {
    if (!dateStr) return "";
    const d = new Date(dateStr);
    if (isNaN(d.getTime())) return dateStr.split(" ")[0];
    return d.toLocaleDateString("en-GB", {
      day: "2-digit",
      month: "short",
      year: "numeric",
    });
  }
</script>

<main class="tab-container">
  <header class="tab-header">
    <div class="tab-header-left">
      <!-- Header logo -->
      <img src="/logo.png" alt="App Logo" class="tab-logo" />
      <span class="tab-title">TLS Security Report</span>
    </div>
    <button class="tab-close" on:click={handleGoBack} aria-label="Close Tab"
      >✕</button
    >
  </header>

  <!-- Summary Section -->
  <section class="summary-section">
    <div class="summary-header">
      <h1 class="domain-title">{cert.domain || "Security Analysis"}</h1>
      <div class="scan-metadata">
        <span class="summary-label">Scan Date:</span>
        <span class="summary-value">
          {cert.tls_scan_date
            ? formatDate(cert.tls_scan_date)
            : new Date().toLocaleDateString("en-GB", {
                day: "2-digit",
                month: "short",
                year: "numeric",
              })}
        </span>
      </div>
    </div>

    <!-- Grade Comparison Cards -->
    <div class="summary-comparison">
      <div class="comparison-card our-analysis">
        <!-- Summary card logo (Our Analysis) -->
        <img src="/logo.png" alt="Our Analysis" class="comparison-logo" />
        <div class="comparison-label">TLS Analyser</div>
        <div class="comparison-grade">
          Grade: <span
            class="grade-badge grade-{cert.grade
              ? cert.grade.toLowerCase().replace(/plus/g, '+')
              : 'placeholder'}"
          >
            {cert.grade ? cert.grade.replace(/plus/gi, "+") : "-"}
          </span>
        </div>
        <div class="comparison-time">
          Scan Time:
          {#if cert.tls_scan_duration}
            <span>{cert.tls_scan_duration}</span>
          {:else}
            <span class="status-text">Not Available</span>
          {/if}
        </div>
      </div>
      <div class="comparison-card">
        <img
          src="/mozzilalogo.png"
          alt="Mozilla Observatory"
          class="comparison-logo"
        />
        <div class="comparison-label">Mozilla Observatory</div>
        <div class="comparison-grade">
          {#if mozillaLoading}
            <span class="spinner"></span>
            <span class="grade-badge grade-placeholder">Loading...</span>
          {:else if mozillaError}
            <span class="grade-badge grade-placeholder">Error</span>
          {:else}
            Grade: <span
              class="grade-badge grade-{cert.mozilla_observatory_grade
                ? cert.mozilla_observatory_grade
                    .toLowerCase()
                    .replace(/\+/g, 'plus')
                : 'placeholder'}"
            >
              {cert.mozilla_observatory_grade
                ? cert.mozilla_observatory_grade
                : "-"}
            </span>
          {/if}
        </div>
        <div class="comparison-time">
          Scan Time: <span class="status-text">
            {#if mozillaLoading}
              Loading...
            {:else if mozillaError}
              {mozillaError}
            {:else}
              {cert.mozilla_observatory_scan_time
                ? cert.mozilla_observatory_scan_time
                : "Not Available"}
            {/if}
          </span>
        </div>
      </div>
      <div class="comparison-card">
        <img src="/sslabs.jpg" alt="SSL Labs" class="comparison-logo" />
        <div class="comparison-label">SSL Labs</div>
        <div class="comparison-grade">
          {#if ssllabsLoading}
            <span class="spinner"></span>
            <span class="grade-badge grade-placeholder">Loading...</span>
          {:else if ssllabsError}
            <span class="grade-badge grade-placeholder">Error</span>
          {:else}
            Grade: <span
              class="grade-badge grade-{cert.ssllabs_grade
                ? cert.ssllabs_grade.toLowerCase()
                : 'placeholder'}"
            >
              {cert.ssllabs_grade ? cert.ssllabs_grade : "-"}
            </span>
          {/if}
        </div>
        <div class="comparison-time">
          Scan Time: <span class="status-text">
            {#if ssllabsLoading}
              Loading...
            {:else if ssllabsError}
              {ssllabsError}
            {:else}
              {cert.ssllabs_scan_time
                ? (cert.ssllabs_scan_time / 1000).toFixed(2) + "s"
                : "Not Available"}
            {/if}
          </span>
        </div>
      </div>
    </div>
  </section>

  <!-- Grid Section: Certificate, Protocols, Cipher Suites, Key Exchange, Vulnerabilities -->
  <div class="grid-section">
    <div class="grid-card">
      <h2>Certificate</h2>
      <table>
        <tbody>
          <tr>
            <td>Common Name:</td>
            <td>{cert.certificate?.common_name || "N/A"}</td>
          </tr>
          <tr>
            <td>Valid From and To:</td>
            <td
              >{formatDate(cert.certificate?.valid_from)} - {formatDate(
                cert.certificate?.valid_to
              )}</td
            >
          </tr>
          <tr>
            <td>Days Until Expiry:</td>
            <td>{cert.certificate?.days_until_expiry || "Unknown"}</td>
          </tr>
          <tr>
            <td>Chain Trust:</td>
            <td>{cert.certificate?.chain_trust || "Unknown"}</td>
          </tr>
          {#if cert.certificate?.subject_alt_names && cert.certificate.subject_alt_names.length > 0}
            <tr>
              <td>Subject Alt Names:</td>
              <td>{cert.certificate.subject_alt_names.join(", ")}</td>
            </tr>
          {/if}
        </tbody>
      </table>
    </div>
    <div class="grid-card">
      <h2>Protocol Support</h2>
      <table>
        <tbody>
          <tr>
            <td>TLS 1.0:</td>
            <td
              class="protocol-status {cert.protocols?.tls_1_0 === 'Supported'
                ? 'not-supported'
                : 'supported'}"
            >
              {cert.protocols?.tls_1_0 || "Unknown"}
            </td>
          </tr>
          <tr>
            <td>TLS 1.1:</td>
            <td
              class="protocol-status {cert.protocols?.tls_1_1 === 'Supported'
                ? 'not-supported'
                : 'supported'}"
            >
              {cert.protocols?.tls_1_1 || "Unknown"}
            </td>
          </tr>
          <tr>
            <td>TLS 1.2:</td>
            <td
              class="protocol-status {cert.protocols?.tls_1_2 === 'Supported'
                ? 'supported'
                : 'not-supported'}"
            >
              {cert.protocols?.tls_1_2 || "Unknown"}
            </td>
          </tr>
          <tr>
            <td>TLS 1.3:</td>
            <td
              class="protocol-status {cert.protocols?.tls_1_3 === 'Supported'
                ? 'supported'
                : 'not-supported'}"
            >
              {cert.protocols?.tls_1_3 || "Unknown"}
            </td>
          </tr>
        </tbody>
      </table>
    </div>
    <div class="grid-card">
      <h2>Cipher Suites</h2>
      <table>
        <tbody>
          {#if cert.cipher_suites?.preferred_suite}
            <tr>
              <td>Preferred:</td>
              <td>{cert.cipher_suites.preferred_suite}</td>
            </tr>
          {/if}
          {#if cert.cipher_suites?.tls_1_2_suites && cert.cipher_suites.tls_1_2_suites.length > 0}
            <tr>
              <td>TLS 1.2:</td>
              <td>{cert.cipher_suites.tls_1_2_suites.join(", ")}</td>
            </tr>
          {/if}
          {#if cert.cipher_suites?.tls_1_3_suites && cert.cipher_suites.tls_1_3_suites.length > 0}
            <tr>
              <td>TLS 1.3:</td>
              <td>{cert.cipher_suites.tls_1_3_suites.join(", ")}</td>
            </tr>
          {/if}
        </tbody>
      </table>
    </div>
    <div class="grid-card">
      <h2>Key Exchange</h2>
      <table>
        <tbody>
          <tr>
            <td>Forward Secrecy:</td>
            <td
              class="fs-status {cert.key_exchange?.supports_forward_secrecy
                ? 'supported'
                : 'not-supported'}"
            >
              {cert.key_exchange?.supports_forward_secrecy ? "Yes" : "No"}
            </td>
          </tr>
          {#if cert.key_exchange?.key_exchange_algorithm}
            <tr>
              <td>Algorithm:</td>
              <td>{cert.key_exchange.key_exchange_algorithm}</td>
            </tr>
          {/if}
          {#if cert.key_exchange?.curve_name}
            <tr>
              <td>Curve:</td>
              <td>{cert.key_exchange.curve_name}</td>
            </tr>
          {/if}
        </tbody>
      </table>
    </div>
    <div class="grid-card">
      <h2>Vulnerabilities</h2>
      <table>
        <tbody>
          <tr>
            <td>POODLE:</td>
            <td class="vuln-status"
              >{cert.vulnerabilities?.poodle || "Unknown"}</td
            >
          </tr>
          <tr>
            <td>BEAST:</td>
            <td class="vuln-status"
              >{cert.vulnerabilities?.beast || "Unknown"}</td
            >
          </tr>
          <tr>
            <td>Heartbleed:</td>
            <td class="vuln-status"
              >{cert.vulnerabilities?.heartbleed || "Unknown"}</td
            >
          </tr>
          <tr>
            <td>FREAK:</td>
            <td class="vuln-status"
              >{cert.vulnerabilities?.freak || "Unknown"}</td
            >
          </tr>
          <tr>
            <td>Logjam:</td>
            <td class="vuln-status"
              >{cert.vulnerabilities?.logjam || "Unknown"}</td
            >
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</main>

<style>
  /* Modern tab layout styles */
  .tab-container {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
      "Helvetica Neue", Arial, sans-serif;
    color: var(--text-color);
    background: var(--background-color);
    min-height: 100vh;
    height: 100vh;
    box-sizing: border-box;
    padding: 0;
    width: 100vw;
    max-width: 100vw;
    overflow-x: hidden;
    overflow-y: auto;
    line-height: 1.6;
    display: flex;
    flex-direction: column;
  }

  .tab-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    background-color: var(--header-bg-color);
    padding: 20px 32px;
    border-bottom: 1px solid var(--border-color);
    box-shadow: 0 2px 12px rgba(0, 0, 0, 0.06);
    backdrop-filter: blur(10px);
  }

  .tab-header-left {
    display: flex;
    align-items: center;
  }

  .tab-logo {
    width: 36px;
    height: 36px;
    margin-right: 16px;
    border-radius: 8px;
  }

  .tab-title {
    font-size: 1.4em;
    font-weight: 600;
    color: var(--text-color);
    letter-spacing: -0.02em;
  }

  .tab-close {
    background: var(--card-background-color);
    border: 1px solid var(--border-color);
    color: var(--text-color);
    font-size: 1.2em;
    cursor: pointer;
    padding: 8px 12px;
    border-radius: 8px;
    transition: all 0.2s ease;
    display: flex;
    align-items: center;
    justify-content: center;
    width: 40px;
    height: 40px;
  }

  .tab-close:hover {
    background: var(--button-bg-color);
    color: #fff;
    transform: translateY(-1px);
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
  }

  .summary-section {
    background: var(--card-background-color);
    border-bottom: 1px solid var(--border-color);
    padding: 32px 48px;
    margin-bottom: 32px;
  }

  .summary-header {
    margin-bottom: 32px;
    text-align: center;
  }

  .domain-title {
    font-size: 2.2em;
    font-weight: 700;
    color: var(--text-color);
    margin: 0 0 12px 0;
    letter-spacing: -0.03em;
    word-break: break-all;
  }

  .scan-metadata {
    font-size: 1.1em;
    color: var(--text-color);
    opacity: 0.8;
  }

  .summary-label {
    font-weight: 600;
    margin-right: 8px;
  }

  .summary-value {
    font-weight: 400;
  }
  .summary-group {
    display: flex;
    flex-wrap: wrap;
    align-items: flex-start;
    justify-content: space-between;
    background: var(--card-background-color);
    padding: 32px 48px 20px 48px;
    border-bottom: 1px solid var(--border-color);
    gap: 32px;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.04);
    border-radius: 0 0 16px 16px;
    margin-bottom: 8px;
    width: 100%;
    max-width: 1400px;
    margin-left: auto;
    margin-right: auto;
  }
  .summary-main {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    min-width: 260px;
    max-width: 340px;
    gap: 18px;
    padding-right: 16px;
  }
  .summary-domain {
    font-size: 1.25em;
    font-weight: 700;
    color: var(--text-color);
    margin-bottom: 4px;
    word-break: break-all;
  }
  .summary-grade-large {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 2px;
  }
  .grade-label {
    font-weight: 600;
    font-size: 1.08em;
    margin-right: 2px;
    color: #555;
  }
  .grade-badge-large {
    display: inline-block;
    min-width: 56px;
    padding: 8px 20px;
    border-radius: 24px;
    font-weight: bold;
    font-size: 1.5em;
    background: #e0e0e0;
    color: #333;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08);
    letter-spacing: 1px;
    text-align: center;
  }
  .grade-badge {
    display: inline-block;
    min-width: 32px;
    padding: 4px 12px;
    border-radius: 16px;
    font-weight: bold;
    font-size: 1.1em;
    background: #e0e0e0;
    color: #333;
    text-align: center;
  }
  .summary-time {
    font-size: 1.05em;
    color: #444;
    margin-bottom: 2px;
  }
  .summary-label {
    font-weight: 500;
    margin-right: 6px;
  }
  .summary-comparison {
    display: flex;
    gap: 32px;
    align-items: flex-start;
    justify-content: space-around;
    margin-top: 24px;
    flex-wrap: wrap;
    width: 100%;
    max-width: 1200px;
    margin-left: auto;
    margin-right: auto;
  }

  .comparison-logo {
    width: 56px;
    height: 56px;
    margin-bottom: 12px;
    border-radius: 12px;
    object-fit: cover;
    object-position: center;
    box-shadow: 0 4px 16px rgba(0, 0, 0, 0.08);
    background: var(--card-background-color);
    border: 2px solid var(--border-color);
    padding: 0;
    display: block;
  }

  /* Mobile */
  @media (max-width: 768px) {
    .comparison-logo {
      width: 48px;
      height: 48px;
    }
  }

  .comparison-card {
    background: var(--background-color);
    border-radius: 16px;
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.06);
    padding: 24px;
    flex: 1;
    min-width: 250px;
    max-width: 300px;
    display: flex;
    flex-direction: column;
    align-items: center;
    border: 2px solid var(--border-color);
    transition: all 0.3s ease;
    margin: 16px;
  }

  .comparison-card.our-analysis {
    border-color: var(--button-bg-color);
    background: linear-gradient(
      135deg,
      var(--card-background-color),
      var(--background-color)
    );
    box-shadow: 0 6px 24px rgba(0, 0, 0, 0.1);
  }

  .comparison-card:hover {
    transform: translateY(-4px);
    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.12);
    border-color: var(--button-bg-color);
  }

  .comparison-card:hover .comparison-logo {
    transform: scale(1.05);
    box-shadow: 0 6px 24px rgba(0, 0, 0, 0.15);
  }

  .comparison-label {
    font-size: 1.1em;
    font-weight: 600;
    margin-bottom: 8px;
    color: var(--text-color);
    text-align: center;
  }

  .comparison-grade {
    font-size: 1em;
    margin-bottom: 6px;
    color: var(--text-color);
    text-align: center;
  }

  .comparison-time {
    font-size: 0.9em;
    color: var(--text-color);
    text-align: center;
    opacity: 0.7;
  }

  .grade-placeholder {
    background: var(--border-color);
    color: var(--text-color);
    opacity: 0.6;
  }

  .status-text {
    font-style: italic;
    opacity: 0.7;
  }

  /* Grade color styling */
  .grade-a\+,
  .grade-aplus,
  .grade-a {
    background: #2e7d32;
    color: #fff;
  }

  .grade-a-,
  .grade-aminus {
    background: #388e3c;
    color: #fff;
  }

  .grade-b\+,
  .grade-bplus,
  .grade-b {
    background: #1976d2;
    color: #fff;
  }

  .grade-b-,
  .grade-bminus {
    background: #1976d2;
    color: #fff;
  }

  .grade-c\+,
  .grade-cplus,
  .grade-c {
    background: #f57c00;
    color: #fff;
  }

  .grade-c-,
  .grade-cminus {
    background: #f57c00;
    color: #fff;
  }

  .grade-d,
  .grade-f {
    background: #d32f2f;
    color: #fff;
  }
  .grid-section {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 24px;
    padding: 0 48px 80px 48px;
    width: 100%;
    max-width: 1400px;
    margin-left: auto;
    margin-right: auto;
    flex: 1;
    overflow-y: visible;
    align-items: start;
    grid-auto-rows: auto;
  }

  .grid-card {
    background: var(--card-background-color);
    border-radius: 16px;
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.06);
    padding: 28px 32px;
    border: 2px solid var(--border-color);
    color: var(--text-color);
    min-width: 0;
    width: 100%;
    transition: all 0.3s ease;
    position: static;
    height: fit-content;
    box-sizing: border-box;
  }

  .grid-card:hover {
    transform: translateY(-2px);
    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
    border-color: var(--button-bg-color);
  }

  .grid-card h2 {
    margin: 0 0 20px 0;
    font-size: 1.3em;
    font-weight: 600;
    color: var(--text-color);
    text-align: left;
    letter-spacing: -0.02em;
    border-bottom: 2px solid var(--border-color);
    padding-bottom: 12px;
  }

  .grid-card table {
    width: 100%;
    border-collapse: collapse;
    font-size: 1em;
    table-layout: fixed;
  }

  .grid-card td {
    padding: 12px 0;
    vertical-align: top;
    color: var(--text-color);
    border-bottom: 1px solid var(--border-color);
  }

  .grid-card td:first-child {
    width: 40%;
    font-weight: 600;
    color: var(--text-color);
    padding-right: 16px;
    word-wrap: break-word;
    overflow-wrap: break-word;
    opacity: 0.8;
  }

  .grid-card td:nth-child(2) {
    width: 60%;
    word-wrap: break-word;
    overflow-wrap: break-word;
    white-space: normal;
    font-weight: 500;
  }

  .grid-card tr:last-child td {
    border-bottom: none;
  }
  .protocol-status.supported {
    color: #2e7d32;
    font-weight: 600;
    background: rgba(46, 125, 50, 0.1);
    padding: 4px 8px;
    border-radius: 6px;
    font-size: 0.9em;
  }

  .protocol-status.not-supported {
    color: #d32f2f;
    font-weight: 600;
    background: rgba(211, 47, 47, 0.1);
    padding: 4px 8px;
    border-radius: 6px;
    font-size: 0.9em;
  }

  .fs-status.supported {
    color: #2e7d32;
    font-weight: 600;
    background: rgba(46, 125, 50, 0.1);
    padding: 4px 8px;
    border-radius: 6px;
    font-size: 0.9em;
  }

  .fs-status.not-supported {
    color: #f57c00;
    font-weight: 600;
    background: rgba(245, 124, 0, 0.1);
    padding: 4px 8px;
    border-radius: 6px;
    font-size: 0.9em;
  }

  .vuln-status {
    font-size: 0.95em;
    font-weight: 500;
    padding: 4px 8px;
    border-radius: 6px;
    background: rgba(128, 128, 128, 0.1);
  }

  /* Dark mode adjustments */
  [data-theme="dark"] .protocol-status.supported,
  [data-theme="dark"] .fs-status.supported {
    color: #66bb6a;
    background: rgba(102, 187, 106, 0.15);
  }

  [data-theme="dark"] .protocol-status.not-supported {
    color: #ef5350;
    background: rgba(239, 83, 80, 0.15);
  }

  [data-theme="dark"] .fs-status.not-supported {
    color: #ffb74d;
    background: rgba(255, 183, 77, 0.15);
  }

  /* Mobile responsiveness */
  @media (max-width: 768px) {
    .tab-header {
      padding: 16px 20px;
    }

    .summary-section {
      padding: 24px 20px;
    }

    .domain-title {
      font-size: 1.8em;
    }

    .grid-section {
      padding: 0 20px 60px 20px;
      grid-template-columns: 1fr;
      gap: 24px;
    }

    .summary-comparison {
      flex-direction: column;
      gap: 20px;
      align-items: center;
      padding: 0 8px;
    }

    .comparison-card {
      min-width: 280px;
      max-width: 320px;
      padding: 20px 24px;
      margin: 6px 0;
    }

    .comparison-logo {
      width: 48px;
      height: 48px;
    }
  }

  .spinner {
    display: inline-block;
    width: 24px;
    height: 24px;
    border: 3px solid #ccc;
    border-top: 3px solid #1976d2;
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
    vertical-align: middle;
    margin-right: 8px;
  }
  @keyframes spin {
    to {
      transform: rotate(360deg);
    }
  }
</style>
