<!--Main Settings Page -->
<script lang="ts">
  import { theme } from "../stores/themeStore";
  import { onMount } from "svelte";
  import { getActiveTabUrl } from "../lib/getDomain";
  import { currentView } from "../stores/navigationStore";
  import SettingsPage from "./SettingsPage.svelte";
  import GradeCard from "./components/GradeCard.svelte";

  // Persistent settings
  let autoScan = false;
  let scanOnlyHttps = true;
  let darkMode = false;

  function loadSettings() {
    autoScan = localStorage.getItem("autoScan") === "true";
    scanOnlyHttps = localStorage.getItem("scanOnlyHttps") !== "false";
    darkMode = localStorage.getItem("darkMode") === "true";
    theme.set(darkMode ? "dark" : "light");
  }

  // Domain and analysis state
  let domain: string = "";
  let result: string = "";
  let error: string = "";
  let loading: boolean = false;
  let analysisInitiated: boolean = false;
  let tlsReportData: any = null;

  // Calculate days until certificate expiry
  $: certExpiryDays = (() => {
    if (
      tlsReportData &&
      tlsReportData.certificate &&
      tlsReportData.certificate.valid_to
    ) {
      const expiry = new Date(tlsReportData.certificate.valid_to);
      const now = new Date();
      const diffMs = expiry.getTime() - now.getTime();
      const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));
      return diffDays;
    }
    if (
      tlsReportData &&
      tlsReportData.certificate &&
      tlsReportData.certificate.days_until_expiry
    ) {
      return tlsReportData.certificate.days_until_expiry;
    }
    return null;
  })();

  interface TlsReportData {
    domain: string;
    message: string;
    grade: string;
    certificate: {
      common_name: string;
      issuer: string;
      valid_from: string;
      valid_to: string;
      key_size?: string;
      signature_algorithm?: string;
      chain_trust: string;
      days_until_expiry?: number;
      subject_alt_names: string[];
      serial_number?: string;
    };
    protocols: {
      tls_1_0: string;
      tls_1_1: string;
      tls_1_2: string;
      tls_1_3: string;
    };
    cipher_suites: {
      tls_1_2_suites: string[];
      tls_1_3_suites: string[];
      preferred_suite?: string;
    };
    vulnerabilities: {
      poodle: string;
      beast: string;
      heartbleed: string;
      freak: string;
      logjam: string;
    };
    key_exchange: {
      supports_forward_secrecy: boolean;
      key_exchange_algorithm?: string;
      curve_name?: string;
    };
  }

  // Assess domain and fetch report from backend
  async function assess(domainToAssess: string) {
    if (!domainToAssess || loading) return;

    let urlToAssess = domainToAssess;
    if (
      !urlToAssess.startsWith("http://") &&
      !urlToAssess.startsWith("https://")
    ) {
      urlToAssess = `https://${urlToAssess}`;
    }

    if (scanOnlyHttps && urlToAssess.startsWith("http://")) {
      error =
        "This domain uses HTTP. Only secure (HTTPS) domains can be scanned.";
      tlsReportData = {
        domain: urlToAssess,
        message: "HTTP domain. Scan not performed as per settings.",
        grade: "F",
        certificate: {},
        protocols: {},
        cipher_suites: {},
        vulnerabilities: {},
        key_exchange: {},
      };
      result = "Analysis not performed.";
      analysisInitiated = true;
      loading = false;
      return;
    }

    let backendDomain = urlToAssess;
    try {
      backendDomain = new URL(urlToAssess).hostname;
    } catch (e) {
      // fallback: send as-is
    }

    loading = true;
    result = "";
    error = "";
    tlsReportData = null;

    try {
      const controller = new AbortController();
      setTimeout(() => {
        controller.abort();
      }, 60000);

      const res = await fetch("http://127.0.0.1:8080/assess", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain: backendDomain }),
        signal: controller.signal,
      });
      if (!res.ok) {
        const errorText = await res.text();
        throw new Error(`HTTP error! Status: ${res.status} - ${errorText}`);
      }

      const json = await res.json();
      tlsReportData = json;
      result = "Analysis complete.";
    } catch (err: any) {
      if (err.name === "AbortError") {
        error = `Request timed out after 60 seconds. The TLS assessment may take longer for some domains.`;
      } else {
        error = `Failed to connect to backend or invalid response: ${err.message || err}`;
      }
    } finally {
      loading = false;
    }
  }

  // Auto-fill domain and scan on mount if enabled
  onMount(async () => {
    loadSettings();
    const activeUrl = await getActiveTabUrl();
    if (activeUrl) {
      domain = activeUrl;
      if (autoScan) {
        analysisInitiated = true;
        assess(domain);
      }
    } else {
      error = "Failed to get active tab URL.";
    }
  });

  function goToSettings() {
    currentView.set("settings");
  }

  function goToHome() {
    currentView.set("home");
  }

  function goToReport() {
    if (!tlsReportData) return;
    localStorage.setItem("tlsReportData", JSON.stringify(tlsReportData));
    window.open(
      window.location.origin + window.location.pathname + "#/tab",
      "_blank"
    );
  }
  $: {
    document.body.setAttribute("data-theme", $theme);
    document.documentElement.setAttribute("data-theme", $theme);
  }
</script>

<main>
  {#if $currentView === "home"}
    <header class="header">
      <h1>SSL/TLS Analyser</h1>
      <button class="menu-button" on:click={goToSettings}>⚙️</button>
    </header>

    <div class="input-section">
      <input
        type="text"
        placeholder="Auto-filled or enter manually"
        bind:value={domain}
        disabled={loading}
      />
      {#if !autoScan}
        <button
          class="analyse-button"
          on:click={() => {
            analysisInitiated = true;
            assess(domain);
          }}
          disabled={loading || !domain}
        >
          {#if loading}
            Checking...
          {:else}
            Analyse
          {/if}
        </button>
      {/if}
    </div>

    {#if analysisInitiated}
      <div class="results-area">
        {#if loading && !result && !error}
          <p>Loading analysis for {domain}...</p>
        {:else if tlsReportData}
          <GradeCard
            grade={tlsReportData.grade ?? "?"}
            summary={tlsReportData.message}
            tlsProtocol={tlsReportData.protocols?.tls_1_3 === "Supported"
              ? "TLS 1.3"
              : tlsReportData.protocols?.tls_1_2 === "Supported"
                ? "TLS 1.2"
                : "Unknown"}
            certValid={tlsReportData.certificate?.chain_trust === "Trusted"}
            certIssuer={tlsReportData.certificate?.issuer ?? "Unknown"}
            certExpiryDays={certExpiryDays ?? 0}
            onViewDetailedReport={goToReport}
          />
        {:else if error}
          <p class="error">{error}</p>
        {/if}
      </div>
    {/if}
  {:else if $currentView === "settings"}
    <SettingsPage onGoBack={goToHome} />
  {/if}
</main>

<style>
  .header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    background-color: var(--header-bg-color);
    padding: 8px 10px;
    border-bottom: 1px solid var(--border-color);
  }
  .header h1 {
    margin: 0;
    font-size: 1.35em;
    color: var(--text-color);
    font-weight: 700;
    text-align: center;
    flex-grow: 1;
  }
  .main-content {
    padding: 24px 10px 32px 10px;
    min-height: 70vh;
    display: flex;
    flex-direction: column;
    justify-content: flex-start;
  }
  .security-overview-heading {
    font-size: 1.18em;
    font-weight: 700;
    margin: 0 0 1em 0;
    color: var(--text-color);
    text-align: left;
    letter-spacing: 0.5px;
  }
  .menu-button {
    background: none;
    border: none;
    color: var(--text-color);
    font-size: 1.3em;
    cursor: pointer;
    padding: 0;
    width: 40px;
    height: 40px;
    display: flex;
    align-items: center;
    justify-content: center;
    outline: none;
    transition: color 0.2s;
  }
  .menu-button:hover,
  .menu-button:focus {
    opacity: 0.7;
    color: var(--button-bg-color);
    outline: none;
  }
  .input-section {
    display: flex;
    padding: 10px;
    gap: 8px;
    border-bottom: 1px solid var(--border-color);
    background-color: var(--card-background-color);
  }
  .results-area {
    flex-grow: 1;
    padding: 10px;
    background-color: var(--card-background-color);
    overflow-y: visible;
  }
</style>
