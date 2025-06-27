<!--Component that displays the grade and TLS basci information-->
<script lang="ts">
  export let grade: string;
  export let summary: string;
  export let tlsProtocol: string;
  export let certValid: boolean;
  export let certIssuer: string;
  export let certExpiryDays: number;
  export let onViewDetailedReport: () => void;

  //get colour from grade
  const gradeColour = {
    A: "green",
    B: "yellow",
    C: "orange",
    D: "red",
    F: "darkred",
  }[grade];
</script>

<div class="grade-card">
  <h2>Security Overview</h2>
  <div class="grade-section">
    <div class="label">Overall Rating</div>
    <div class="icon-grade">
      <span class="lock-icon" style="color: {gradeColour}">🔒</span>
      <span class="grade" style="color: {gradeColour}">{grade}</span>
    </div>
    <div class="summary">{summary}</div>
  </div>

  <div class="details">
    <div><strong>Protocol:</strong> {tlsProtocol}</div>
    <div><strong>Certificate Valid:</strong> {certValid ? "Yes" : "No"}</div>
    <div><strong>Issuer:</strong> {certIssuer}</div>
    <div><strong>Expires In:</strong> {certExpiryDays}</div>
  </div>

  <button class="details-button" on:click={onViewDetailedReport}>
    View Detailed Report
  </button>
</div>

<style>
  .grade-card {
    margin-top: 1rem;
    padding: 1rem;
    border: 1px solid #ddd;
    border-radius: 6px;
    background-color: #fff;
    font-size: 0.95rem;
    color: #333;
  }

  .grade-card h2 {
    color: #222;
    margin-top: 0;
    margin-bottom: 1rem;
    text-align: center;
  }

  .grade-section {
    text-align: center;
    margin-bottom: 1rem;
  }

  .label {
    font-weight: bold;
    margin-bottom: 0.4rem;
  }

  .icon-grade {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 0.5rem;
    font-size: 2rem;
  }

  .summary {
    margin-top: 0.5rem;
    color: #444;
  }

  .details {
    background: #f8f8f8;
    padding: 0.75rem;
    border-radius: 4px;
    margin: 1rem 0;
  }

  .details div {
    margin: 0.4rem 0;
  }

  .details-button {
    width: 100%;
    padding: 0.6rem;
    font-size: 1rem;
    background-color: #1976d2;
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
  }

  .details-button:hover {
    background-color: #125ea8;
  }
</style>
