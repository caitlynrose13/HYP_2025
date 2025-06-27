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

  let fullDetailedReport: TlsReportData | null = null; // Initialize as null

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

    try {
      console.log(" Sending domain to backend:", domainToAssess);

      const res = await fetch("http://127.0.0.1:8080/assess", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain: domainToAssess }),
      });

      if (!res.ok) {
        const errorText = await res.text();
        throw new Error(`HTTP error! Status: ${res.status} - ${errorText}`);
      }

      const json = await res.json();
      if (json && json.domain && json.message) {
        result = `${json.domain}: ${json.message}`;
      } else {
        result = "Analysis complete, but response format was unexpected.";
        console.warn("[assess] Unexpected response format:", json);
      }
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
    fullDetailedReport = {
      domain,
      certificate: {
        issuer: "Let's Encrypt",
        validFrom: "2024-01-01",
        validTo: "2025-03-30",
        keySize: "2048-bit",
        commonName: domain,
      },
      protocols: {
        "TLS 1.3": "✅ Supported",
        "TLS 1.2": "✅ Supported",
        "TLS 1.0": "❌ Deprecated",
      },
      vulnerabilities: {
        Heartbleed: "Not vulnerable",
        POODLE: "Not vulnerable",
      },
    };

    currentView.set("detailedReport");
  }
</script>

<!--Main UI-->
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
        {:else if result}
          <!--HARDCODED FOR NOW-->
          <GradeCard
            grade="A+"
            summary="Secure Connection"
            tlsProtocol="TLS 1.3"
            certValid={true}
            certIssuer="Let's Encrypt"
            certExpiryDays={90}
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
    {#if fullDetailedReport}
      <DetailedReport
        handleGoBack={goToHome}
        domain={fullDetailedReport.domain}
        certificate={fullDetailedReport.certificate}
        protocols={fullDetailedReport.protocols}
        vulnerabilities={fullDetailedReport.vulnerabilities}
      />
    {/if}
  {/if}
</main>
