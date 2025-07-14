<!--Page to display the detailed view of tls report-->
<script lang="ts">
  export let handleGoBack: () => void;
  export let tlsReportData: any; // Accept the full backend response

  // Extract fields for display
  $: cert = tlsReportData || {};

  // Helper function to determine icon and display text for protocol status
  function getProtocolStatusDisplay(status: string): {
    icon: string;
    text: string;
  } {
    if (status.includes("Supported")) {
      return { icon: "", text: "Supported" };
    } else if (status.includes("Recommended")) {
      return { icon: "", text: status };
    } else if (status.includes("Deprecated") || status.includes("Insecure")) {
      return { icon: "", text: "Deprecated" };
    }
    return { icon: "", text: status };
  }
</script>

<main class="report-container">
  <header class="report-header">
    <button class="back-button" on:click={handleGoBack} aria-label="Go back">
      <!--go back to homepage-->
      &#8592;
    </button>
    <h1>Detailed Report</h1>
    <div class="right-placeholder"></div>
  </header>

  <p class="intro">Report for <span class="domain-text">{cert.domain}</span></p>

  <section class="report-block">
    <h2>1. Certificate</h2>
    <table>
      <tbody>
        <tr><td>Common Name:</td><td>{cert.cert_common_name}</td></tr>
        <tr><td>Issuer:</td><td>{cert.cert_issuer}</td></tr>
        <tr
          ><td>Valid From and To:</td><td
            >{cert.cert_valid_from} - {cert.cert_valid_to}</td
          ></tr
        >
        <tr><td>Chain Trust:</td><td>{cert.cert_chain_trust}</td></tr>
      </tbody>
    </table>
  </section>

  <section class="report-block">
    <h2>2. Protocol Support</h2>
    <table>
      <tbody>
        <tr
          ><td>TLS 1.2:</td><td
            >{cert.tls_version === "TLS1_2" ? "Yes" : "No"}</td
          ></tr
        >
      </tbody>
    </table>
  </section>

  <section class="report-block">
    <h2>3. Cipher Suites</h2>
    <table>
      <tbody>
        <tr><td>TLS 1.2:</td><td>{cert.cipher_suite}</td></tr>
        <!-- will need more later for 1.3 -->
      </tbody>
    </table>
  </section>
</main>

<style>
  .report-container {
    padding: 0;
    max-width: 600px;
    margin: auto;
    font-family: inherit;
    color: var(--text-color);
    background: var(--background-color);
    min-height: 100vh;
    box-sizing: border-box;
    overflow-y: auto;
  }
  .report-header {
    display: flex;
    align-items: center;
    background-color: var(--header-bg-color);
    padding: 10px 15px;
    border-bottom: 1px solid var(--border-color);
    position: sticky;
  }
  .report-header h1 {
    margin: 0;
    font-size: 1.2em;
    color: var(--text-color);
    flex-grow: 1;
    text-align: center;
  }
  .back-button {
    background: none;
    border: none;
    color: var(--text-color);
    font-size: 1.5rem;
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
  .back-button:hover,
  .back-button:focus {
    opacity: 0.7;
    color: var(--button-bg-color);
    outline: none;
  }
  .intro {
    font-size: 0.95rem;
    color: var(--text-color);
    margin: 20px 20px 20px 20px;
  }
  .intro .domain-text {
    font-weight: bold;
  }
  .report-block {
    background: var(--card-background-color);
    padding: 15px 20px;
    margin: 0 20px 20px 20px;
    border-radius: 5px;
    border: 1px solid var(--border-color);
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05);
    color: var(--text-color);
  }
  .report-block h2 {
    color: var(--text-color);
    margin-top: 0;
    margin-bottom: 10px;
    border-bottom: 1px solid var(--border-color);
    padding-bottom: 8px;
    font-size: 1.05rem;
    font-weight: bold;
  }
  .report-block table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.9rem;
    table-layout: fixed;
  }
  .report-block td {
    padding: 8px 0;
    vertical-align: top;
    color: var(--text-color);
  }
  .report-block td:first-child {
    width: 35%;
    font-weight: normal;
    color: var(--text-color);
    padding-right: 10px;
    word-wrap: break-word;
    overflow-wrap: break-word;
  }
  .report-block td:nth-child(2) {
    width: 65%;
    word-wrap: break-word;
    overflow-wrap: break-word;
    white-space: normal;
  }
</style>
