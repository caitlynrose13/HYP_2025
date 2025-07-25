<!--Page to display the detailed view of tls report-->
<script lang="ts">
  export let handleGoBack: () => void;
  export let tlsReportData: any; // Accept the full backend response

  // Extract fields for display
  $: cert = tlsReportData || {};

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
        <tr
          ><td>Common Name:</td><td>{cert.certificate?.common_name || "N/A"}</td
          ></tr
        >
        <tr><td>Issuer:</td><td>{cert.certificate?.issuer || "N/A"}</td></tr>
        <tr>
          <td>Valid From and To:</td>
          <td
            >{formatDate(cert.certificate?.valid_from)} - {formatDate(
              cert.certificate?.valid_to
            )}</td
          >
        </tr>
        <tr
          ><td>Chain Trust:</td><td
            >{cert.certificate?.chain_trust || "Unknown"}</td
          ></tr
        >
        <tr
          ><td>Days Until Expiry:</td><td
            >{cert.certificate?.days_until_expiry || "Unknown"}</td
          ></tr
        >
        {#if cert.certificate?.subject_alt_names && cert.certificate.subject_alt_names.length > 0}
          <tr
            ><td>Subject Alt Names:</td><td
              >{cert.certificate.subject_alt_names.join(", ")}</td
            ></tr
          >
        {/if}
      </tbody>
    </table>
  </section>

  <section class="report-block">
    <h2>2. Protocol Support</h2>
    <table>
      <tbody>
        <tr
          ><td>TLS 1.0:</td><td
            class="protocol-status {cert.protocols?.tls_1_0 === 'Supported'
              ? 'supported'
              : 'not-supported'}">{cert.protocols?.tls_1_0 || "Unknown"}</td
          ></tr
        >
        <tr
          ><td>TLS 1.1:</td><td
            class="protocol-status {cert.protocols?.tls_1_1 === 'Supported'
              ? 'supported'
              : 'not-supported'}">{cert.protocols?.tls_1_1 || "Unknown"}</td
          ></tr
        >
        <tr
          ><td>TLS 1.2:</td><td
            class="protocol-status {cert.protocols?.tls_1_2 === 'Supported'
              ? 'supported'
              : 'not-supported'}">{cert.protocols?.tls_1_2 || "Unknown"}</td
          ></tr
        >
        <tr
          ><td>TLS 1.3:</td><td
            class="protocol-status {cert.protocols?.tls_1_3 === 'Supported'
              ? 'supported'
              : 'not-supported'}">{cert.protocols?.tls_1_3 || "Unknown"}</td
          ></tr
        >
      </tbody>
    </table>
  </section>

  <section class="report-block">
    <h2>3. Cipher Suites</h2>
    <table>
      <tbody>
        {#if cert.cipher_suites?.preferred_suite}
          <tr
            ><td>Preferred:</td><td>{cert.cipher_suites.preferred_suite}</td
            ></tr
          >
        {/if}
        {#if cert.cipher_suites?.tls_1_2_suites && cert.cipher_suites.tls_1_2_suites.length > 0}
          <tr
            ><td>TLS 1.2:</td><td
              >{cert.cipher_suites.tls_1_2_suites.join(", ")}</td
            ></tr
          >
        {/if}
        {#if cert.cipher_suites?.tls_1_3_suites && cert.cipher_suites.tls_1_3_suites.length > 0}
          <tr
            ><td>TLS 1.3:</td><td
              >{cert.cipher_suites.tls_1_3_suites.join(", ")}</td
            ></tr
          >
        {/if}
      </tbody>
    </table>
  </section>

  <section class="report-block">
    <h2>4. Key Exchange</h2>
    <table>
      <tbody>
        <tr
          ><td>Forward Secrecy:</td><td
            class="fs-status {cert.key_exchange?.supports_forward_secrecy
              ? 'supported'
              : 'not-supported'}"
            >{cert.key_exchange?.supports_forward_secrecy ? "Yes" : "No"}</td
          ></tr
        >
        {#if cert.key_exchange?.key_exchange_algorithm}
          <tr
            ><td>Algorithm:</td><td
              >{cert.key_exchange.key_exchange_algorithm}</td
            ></tr
          >
        {/if}
        {#if cert.key_exchange?.curve_name}
          <tr><td>Curve:</td><td>{cert.key_exchange.curve_name}</td></tr>
        {/if}
      </tbody>
    </table>
  </section>

  <section class="report-block">
    <h2>5. Vulnerabilities</h2>
    <table>
      <tbody>
        <tr
          ><td>POODLE:</td><td class="vuln-status"
            >{cert.vulnerabilities?.poodle || "Unknown"}</td
          ></tr
        >
        <tr
          ><td>BEAST:</td><td class="vuln-status"
            >{cert.vulnerabilities?.beast || "Unknown"}</td
          ></tr
        >
        <tr
          ><td>Heartbleed:</td><td class="vuln-status"
            >{cert.vulnerabilities?.heartbleed || "Unknown"}</td
          ></tr
        >
        <tr
          ><td>FREAK:</td><td class="vuln-status"
            >{cert.vulnerabilities?.freak || "Unknown"}</td
          ></tr
        >
        <tr
          ><td>Logjam:</td><td class="vuln-status"
            >{cert.vulnerabilities?.logjam || "Unknown"}</td
          ></tr
        >
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
    font-size: 1.35em;
    color: var(--text-color);
    flex-grow: 1;
    text-align: center;
    font-weight: 700;
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

  .protocol-status.supported {
    color: #4caf50;
    font-weight: bold;
  }

  .protocol-status.not-supported {
    color: #f44336;
  }

  .fs-status.supported {
    color: #4caf50;
    font-weight: bold;
  }

  .fs-status.not-supported {
    color: #ff9800;
  }

  .vuln-status {
    font-size: 0.9em;
  }
</style>
