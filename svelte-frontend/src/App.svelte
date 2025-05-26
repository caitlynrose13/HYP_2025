<script lang="ts">
  let domain = "example.com"; //set default for now - will be accessed dynamically
  let result = "";
  let error = "";
  let loading = false;

  //Assess Function - Take in the domain and connect to backend
  async function assess() {
    loading = true;
    result = "";
    error = "";
    try {
      const res = await fetch("http://127.0.0.1:8080/assess", {
        //connect to backend
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain }),
      });
      const json = await res.json();
      result = `${json.domain}: ${json.message}`;
    } catch (err) {
      error = "Failed to connect to backend.";
    } finally {
      loading = false;
    }
  }
</script>

<main>
  <h1>TLS Analyser</h1>
  <input bind:value={domain} placeholder="Enter domain" />
  <!--default domain -->
  <button on:click={assess} disabled={loading}>
    <!--on click call the assess function in main.ts -->
    {loading ? "Checking..." : "Assess"}
  </button>

  <!--diplay result -->
  {#if result}
    <p style="color: green">{result}</p>
  {/if}

  {#if error}
    <p style="color: red">{error}</p>
  {/if}
</main>
