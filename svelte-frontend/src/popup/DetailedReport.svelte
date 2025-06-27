<!--Page to display the detailed view of tls report-->
<script lang="ts">
  import "./detailedReport.css";
  export let handleGoBack: () => void;
  export let domain: string;
  export let certificate: {
    issuer: string;
    validFrom: string;
    validTo: string;
    keySize: string;
    commonName: string;
  };
  export let protocols: Record<string, string>;
  export let vulnerabilities: Record<string, string>;

  // Helper function to determine icon and display text for protocol status
  function getProtocolStatusDisplay(status: string): {
    icon: string;
    text: string;
  } {
    if (status.includes("Supported")) {
      return { icon: "✅", text: "Supported" };
    } else if (status.includes("Recommended")) {
      return { icon: "⚠️", text: status };
    } else if (status.includes("Deprecated") || status.includes("Insecure")) {
      return { icon: "❌", text: "Deprecated" };
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

  <p class="intro">Report for <span class="domain-text">{domain}</span></p>

  <section class="report-block">
    <h2>1. Certificate</h2>
    <table>
      <tbody>
        <tr>
          <td>Common Name:</td>
          <td>{certificate.commonName}</td>
        </tr>
        <tr>
          <td>Issuer:</td>
          <td>{certificate.issuer}</td>
        </tr>
        <tr>
          <td>Valid From and To:</td>
          <td>{certificate.validFrom} - {certificate.validTo}</td>
        </tr>
        <tr>
          <td>Key Size:</td>
          <td>{certificate.keySize}</td>
        </tr>
        <tr>
          <td>Signature Algorithm:</td>
          <td>SHA256 with RSA</td>
        </tr>
        <tr>
          <td>Chain Trust:</td>
          <td>Trusted</td>
        </tr>
      </tbody>
    </table>
  </section>

  <section class="report-block">
    <h2>2. Protocol Support</h2>
    <table>
      <tbody>
        {#each Object.entries(protocols) as [proto, value]}
          {@const { icon, text } = getProtocolStatusDisplay(value)}
          <tr>
            <td>{proto}:</td>
            <td>
              <span class="protocol-status-icon">{icon}</span>
              {text}
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  </section>

  <section class="report-block">
    <h2>3. Cipher Suites</h2>
    <table>
      <tbody>
        <tr>
          <td>TLS 1.3:</td>
          <td>TLS_AES_256_GCM_SHA384 (Forward Secrecy)</td>
        </tr>
        <tr>
          <td>TLS 1.2:</td>
          <td>TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (PFS)</td>
        </tr>
        <tr>
          <td>Weak Cipher:</td>
          <td>None</td>
        </tr>
        <tr>
          <td>Forward Secrecy:</td>
          <td>Yes</td>
        </tr>
      </tbody>
    </table>
  </section>

  <section class="report-block">
    <h2>4. Vulnerability Checks</h2>
    <table>
      <tbody>
        {#each Object.entries(vulnerabilities) as [name, status]}
          <tr>
            <td>{name}:</td>
            <td>{status}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  </section>
</main>
