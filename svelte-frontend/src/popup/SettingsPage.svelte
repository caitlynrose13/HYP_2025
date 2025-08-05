<!--Main Settings Page -->
<script lang="ts">
  import "../app.css";
  import "./settings.css";
  import { theme } from "../stores/themeStore";
  import { onMount } from "svelte";

  let isDarkMode = false;
  export let onGoBack: () => void;
  let autoScanOnPageLoad = false;
  let scanOnlyHttps = true;

  // Load settings from localStorage
  function loadSettings() {
    isDarkMode = localStorage.getItem("darkMode") === "true";
    autoScanOnPageLoad = localStorage.getItem("autoScan") === "true";
    scanOnlyHttps = localStorage.getItem("scanOnlyHttps") !== "false";
    theme.set(isDarkMode ? "dark" : "light");
  }

  // Save settings to localStorage

  //when user toggles dark mode, save the preference, updates theme store, and applies the theme
  function saveDarkMode() {
    localStorage.setItem("darkMode", isDarkMode.toString());
    theme.set(isDarkMode ? "dark" : "light");
  }
  function saveAutoScan() {
    localStorage.setItem("autoScan", autoScanOnPageLoad.toString());
  }
  function saveScanOnlyHttps() {
    localStorage.setItem("scanOnlyHttps", scanOnlyHttps.toString());
  }
  function clearData() {
    localStorage.clear();
    loadSettings();
  }

  function handleGoBack() {
    onGoBack();
  }

  onMount(() => {
    loadSettings();
  });

  // Ensure global theme styling is applied
  $: {
    document.body.setAttribute("data-theme", $theme);
    document.documentElement.setAttribute("data-theme", $theme);
  }
</script>

<!--Options to toggle NEED TO IMPLEMENT-->
<main class="settings-page" aria-label="Settings Page">
  <header class="settings-header">
    <button class="back-button" on:click={handleGoBack} aria-label="Go back">
      <svg width="20" height="20" viewBox="0 0 20 20" fill="none">
        <path
          d="M12.5 15L8 10L12.5 5"
          stroke="currentColor"
          stroke-width="2"
          stroke-linecap="round"
          stroke-linejoin="round"
        />
      </svg>
    </button>
    <h1>Settings</h1>
  </header>

  <!-- Preferences Section -->
  <section class="setting-group" aria-labelledby="preferences-header">
    <h2 id="preferences-header">Preferences</h2>
    <div class="setting-item">
      <span class="label-text">Toggle Dark Mode</span>
      <label class="switch">
        <input
          type="checkbox"
          id="theme-toggle"
          bind:checked={isDarkMode}
          on:change={saveDarkMode}
        />
        <span class="slider"></span>
      </label>
    </div>

    <div class="setting-item">
      <span class="label-text">Automatically scan on page load</span>
      <label class="switch">
        <input
          type="checkbox"
          id="auto-scan"
          bind:checked={autoScanOnPageLoad}
          on:change={saveAutoScan}
        />
        <span class="slider"></span>
      </label>
    </div>

    <div class="setting-item">
      <span class="label-text">Scan only HTTPS</span>
      <label class="switch">
        <input
          type="checkbox"
          id="scan-https"
          bind:checked={scanOnlyHttps}
          on:change={saveScanOnlyHttps}
        />
        <span class="slider"></span>
      </label>
    </div>
  </section>

  <section class="setting-group compact-group" aria-labelledby="about-header">
    <h2 id="about-header">About</h2>
    <div class="setting-item static-item">
      <span>Version</span>
      <span>1.0.0</span>
    </div>
    <div class="setting-item static-item">
      <span>Developed by</span>
      <span>Caitlyn Ross | University of Johannesburg</span>
    </div>
  </section>
</main>

<style>
  main.settings-page {
    min-height: 0;
    height: auto;
    max-width: 400px;
    margin: 0 auto;
    padding-bottom: 0;
  }
  .settings-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    background-color: var(--header-bg-color);
    padding: 0 6px 0 6px;
    border-bottom: 1px solid var(--border-color);
    margin-top: 0;
    min-height: 48px;
    position: relative;
  }
  .header-left,
  .header-right {
    width: 40px;
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
  }
  .header-center {
    flex: 1;
    display: flex;
    justify-content: center;
    align-items: center;
    min-width: 0;
  }
  .settings-header h1 {
    margin: 0;
    font-size: 1.35em;
    color: var(--text-color);
    text-align: center;
    font-weight: 700;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .back-button {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 32px;
    height: 32px;
    border-radius: 50%;
    background: var(--card-background-color);
    border: 1px solid var(--border-color);
    color: var(--text-color);
    cursor: pointer;
    transition:
      background 0.2s,
      box-shadow 0.2s;
    box-shadow: 0 1px 2px rgba(0, 0, 0, 0.04);
    z-index: 1;
    flex-shrink: 0;
  }
  .back-button:hover {
    background: var(--border-color);
    box-shadow: 0 2px 6px rgba(0, 0, 0, 0.1);
  }
  .setting-group {
    background-color: var(--card-background-color);
    border-radius: 8px;
    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
    margin: 14px 10px 10px 10px;
    padding: 12px 12px 10px 12px;
    border: 1px solid var(--border-color);
  }
  .setting-group h2 {
    color: var(--text-color);
    font-size: 0.98em;
    margin-top: 0;
    margin-bottom: 10px;
    padding-bottom: 6px;
    border-bottom: 1px solid var(--border-color);
    font-weight: 600;
  }
  .setting-item {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 8px 0;
    border-bottom: 1px solid var(--border-color);
    font-size: 0.95em;
  }
  .setting-item:last-child {
    border-bottom: none;
  }
  .about-dev-row {
    align-items: center;
  }
  .about-dev-value {
    text-align: right;
    white-space: normal;
    overflow-wrap: anywhere;
    font-size: 0.93em;
    max-width: 180px;
    display: inline-block;
  }
  .bottom-button-container,
  .compact-button {
    padding: 8px 10px 0 10px;
    margin-top: 0;
    margin-bottom: 0;
  }
  .compact-group {
    margin-top: 8px;
    margin-bottom: 6px;
    padding: 8px 8px 6px 8px;
  }
</style>
