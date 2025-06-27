<!--Main Settings Page -->
<script lang="ts">
  import "./settings.css";
  import { theme } from "../stores/themeStore";

  let isLightMode = false;
  $: theme.set(isLightMode ? "light" : "dark");
  $: isLightMode = $theme === "light";

  export let onGoBack: () => void;

  let autoScanOnPageLoad: boolean = false;
  let scanOnlyHttps: boolean = true;

  function clearData() {
    console.log("Clear Stored Data button clicked!");
    alert("Data would be cleared here!");
  }

  function handleGoBack() {
    onGoBack();
  }
</script>

<!--Options to toggle NEED TO IMPLEMENT-->
<main class="settings-page" aria-label="Settings Page">
  <header class="settings-header">
    <button class="back-button" on:click={handleGoBack} aria-label="Go back">
      <!--go back to homepage-->
      &#8592;
    </button>
    <h1>Settings</h1>
  </header>

  <section class="setting-group" aria-labelledby="preferences-header">
    <h2 id="preferences-header">Preferences</h2>

    <div class="setting-item">
      <label for="label-text">Dark/Light Mode</label>
      <label class="switch">
        <input type="checkbox" id="theme-toggle" bind:checked={isLightMode} />
        <span class="slider round"></span>
      </label>
    </div>

    <div class="setting-item">
      <label for="auto-scan">Automatically scan on page load</label>
      <label class="switch">
        <input
          type="checkbox"
          id="auto-scan"
          bind:checked={autoScanOnPageLoad}
        />
        <span class="slider round"></span>
      </label>
    </div>

    <div class="setting-item">
      <label for="scan-https">Scan only HTTPS</label>
      <label class="switch">
        <input type="checkbox" id="scan-https" bind:checked={scanOnlyHttps} />
        <span class="slider round"></span>
      </label>
    </div>
  </section>

  <section class="setting-group" aria-labelledby="about-header">
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

  <div class="bottom-button-container">
    <button class="clear-data-button" on:click={clearData}>
      Clear Stored Data
    </button>
  </div>
</main>
