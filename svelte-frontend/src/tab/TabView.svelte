<script lang="ts">
  import DetailedReportTab from "../tab/DetailedReportTab.svelte";
  import { theme } from "../stores/themeStore";
  import { onMount } from "svelte";

  let tlsReportData: any = null;

  // Initialize theme and load report data from localStorage
  onMount(() => {
    const savedTheme =
      localStorage.getItem("darkMode") === "true" ? "dark" : "light";
    theme.set(savedTheme);
    document.body.setAttribute("data-theme", savedTheme);
    document.documentElement.setAttribute("data-theme", savedTheme);

    const stored = localStorage.getItem("tlsReportData");
    if (stored) {
      try {
        tlsReportData = JSON.parse(stored);
      } catch {
        tlsReportData = null;
      }
    }
  });

  function handleGoBack() {
    window.close();
  }
</script>

{#if tlsReportData}
  <DetailedReportTab {tlsReportData} {handleGoBack} />
{:else}
  <main class="no-data-container">
    <div class="no-data-content">
      <h2>No Report Data Available</h2>
      <p>Please run a security analysis from the browser extension first.</p>
      <button class="retry-button" on:click={handleGoBack}>Close Tab</button>
    </div>
  </main>
{/if}

<style>
  .no-data-container {
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    background: var(--background-color);
    color: var(--text-color);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
      sans-serif;
  }

  .no-data-content {
    text-align: center;
    padding: 48px 32px;
    background: var(--card-background-color);
    border-radius: 16px;
    border: 2px solid var(--border-color);
    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.08);
    max-width: 500px;
  }

  .no-data-content h2 {
    font-size: 1.8em;
    font-weight: 600;
    margin-bottom: 16px;
    color: var(--text-color);
  }

  .no-data-content p {
    font-size: 1.1em;
    margin-bottom: 32px;
    color: var(--text-color);
    opacity: 0.8;
    line-height: 1.6;
  }

  .retry-button {
    background: var(--button-bg-color);
    color: var(--button-text-color);
    border: none;
    padding: 12px 24px;
    border-radius: 8px;
    font-size: 1em;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.2s ease;
  }

  .retry-button:hover {
    background: var(--button-hover-bg-color);
    transform: translateY(-1px);
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
  }
</style>
