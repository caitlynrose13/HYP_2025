<!--Main Settings Page -->
<script lang="ts">
  import { theme } from "../stores/themeStore";
  import { onMount } from "svelte";
  import { getActiveTabDomain } from "../lib/getDomain";
  import { currentView } from "../stores/navigationStore";
  import SettingsPage from "./SettingsPage.svelte";
  import GradeCard from "./components/GradeCard.svelte";
  import DetailedReport from "./DetailedReport.svelte";

  $: {
    document.body.setAttribute("data-theme", $theme);
  }

  let domain: string = "";
  let result: string = "";
  let error: string = "";
  let loading: boolean = false;
  let analysisInitiated: boolean = false;

  let tlsReportData: any = null;

  // Calculate days until certificate expiry
  $: certExpiryDays = (() => {
    if (tlsReportData && tlsReportData.cert_valid_to) {
      const expiry = new Date(tlsReportData.cert_valid_to);
      const now = new Date();
      const diffMs = expiry.getTime() - now.getTime();
      const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));
      return diffDays;
    }
    return null;
  })();

  interface TlsReportData {
    domain: string;
    certificate: {
      issuer: string;
      validFrom: string;
      validTo: string;
      keySize: string;
      commonName: string;
    };
    protocols: Record<string, string>;
    vulnerabilities: Record<string, string>;
  }

  //Function to assess domain, takes in a domain string to parse to backend.
  async function assess(domainToAssess: string) {
    if (!domainToAssess || loading) return;

    loading = true;
    result = "";
    error = "";
    tlsReportData = null;

    try {
      console.log("About to start fetch...");
      const controller = new AbortController();
      setTimeout(() => controller.abort(), 5000); // 5 seconds
      const res = await fetch("http://127.0.0.1:8080/assess", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain: domainToAssess }),
        signal: controller.signal,
      });
      console.log("Fetch returned, status:", res.status);
      if (!res.ok) {
        const errorText = await res.text();
        throw new Error(`HTTP error! Status: ${res.status} - ${errorText}`);
      }

      const json = await res.json();
      console.log("[assess] JSON response:", json);
      tlsReportData = json; // Store the full response
      result = "Analysis complete.";
    } catch (err: any) {
      console.error("[assess] Fetch error:", err);
      error = `Failed to connect to backend or invalid response: ${err.message || err}`;
    } finally {
      loading = false;
    }
  }

  // Automatically get the active tab's domain on mount
  onMount(async () => {
    const activeDomain = await getActiveTabDomain();
    if (activeDomain) {
      console.log("[ Auto-filled domain:", activeDomain);
      domain = activeDomain;
    } else {
      error = "Failed to get active tab domain.";
      console.warn("Couldn't retrieve active tab domain.");
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
    currentView.set("detailedReport");
  }
</script>

<!--Main UI-->
<main>
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
    </div>

    <!--If analysis selected SHOW GRADE AND DETAILS LATER-->
    {#if analysisInitiated}
      <div class="results-area">
        {#if loading && !result && !error}
          <p>Loading analysis for {domain}...</p>
        {:else if tlsReportData}
          <GradeCard
            grade={tlsReportData.grade ?? "?"}
            summary={tlsReportData.message}
            tlsProtocol={tlsReportData.tls_version}
            certValid={tlsReportData.cert_chain_trust === "Trusted"}
            certIssuer={tlsReportData.cert_issuer}
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
  {:else if $currentView === "detailedReport"}
    {#if tlsReportData}
      <DetailedReport handleGoBack={goToHome} {tlsReportData} />
    {/if}
  {/if}
</main>
