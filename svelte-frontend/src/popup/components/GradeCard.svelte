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
  const gradeColour =
    {
      APlus: "green",
      A: "green",
      AMinus: "yellowgreen",
      B: "yellow",
      C: "orange",
      F: "darkred",
    }[grade] || "gray";

  const gradeDisplay =
    {
      APlus: "A+",
      A: "A",
      AMinus: "A-",
      B: "B",
      C: "C",
      F: "F",
    }[grade] || grade;
</script>

<div class="grade-card">
  <h2>Security Overview</h2>
  <div class="grade-section">
    <div class="label">Overall Rating</div>
    <div class="icon-grade">
      <span class="lock-icon" style="color: {gradeColour}">🔒</span>
      <span class="grade" style="color: {gradeColour}">{gradeDisplay}</span>
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
    margin-top: 1.5rem;
    padding: 1.5rem 1rem 1.5rem 1rem;
    border: 1.5px solid var(--border-color);
    border-radius: 12px;
    background-color: var(--card-background-color);
    box-shadow: 0 4px 16px rgba(0, 0, 0, 0.1);
    color: var(--text-color);
    transition:
      background-color 0.3s,
      color 0.3s,
      border-color 0.3s,
      box-shadow 0.2s;
    max-width: 420px;
    margin-left: auto;
    margin-right: auto;
    display: flex;
    flex-direction: column;
    align-items: center;
  }
  .grade-card:hover {
    box-shadow: 0 8px 24px rgba(0, 0, 0, 0.16);
    border-color: var(--button-bg-color);
  }
  .grade-card h2 {
    color: var(--text-color);
    margin-top: 0;
    margin-bottom: 1.2rem;
    text-align: center;
    font-size: 1.3rem;
    font-weight: 700;
    letter-spacing: 0.01em;
  }
  .grade-section {
    text-align: center;
    margin-bottom: 1.5rem;
  }
  .label {
    font-weight: 600;
    margin-bottom: 0.5rem;
    font-size: 1.05rem;
    color: var(--text-color);
  }
  .icon-grade {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 0.7rem;
    font-size: 2.8rem;
    margin-bottom: 0.3rem;
  }
  .icon-grade .lock-icon {
    border-radius: 50%;
    border: 2.5px solid var(--button-bg-color);
    background: var(--background-color);
    padding: 0.25em 0.35em;
    font-size: 2.2rem;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08);
    margin-right: 0.3em;
  }
  .icon-grade .grade {
    font-size: 2.2rem;
    font-weight: 800;
    letter-spacing: 0.03em;
    color: var(--accent-color-green);
    text-shadow: 0 2px 8px rgba(0, 0, 0, 0.08);
  }
  .summary {
    margin-top: 0.5rem;
    color: var(--text-color);
    font-size: 1.08rem;
    font-weight: 500;
  }
  .details {
    background: color-mix(
      in srgb,
      var(--card-background-color) 90%,
      var(--background-color) 10%
    );
    /* fallback for browsers without color-mix: */
    background: rgba(0, 0, 0, 0.03);
    border-radius: 8px;
    padding: 1.1rem 1rem 1.1rem 1rem;
    margin: 1.2rem 0 1.2rem 0;
    width: 100%;
    box-sizing: border-box;
    border: 1px solid var(--border-color);
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }
  .details div {
    margin: 0.2rem 0;
    font-size: 1.01rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }
  .details strong {
    font-weight: 600;
    color: var(--text-color);
    min-width: 110px;
    display: inline-block;
  }
  .details-button {
    width: 100%;
    padding: 0.9rem 0;
    font-size: 1.08rem;
    font-weight: 700;
    background-color: var(--button-bg-color);
    color: var(--button-text-color);
    border: none;
    border-radius: 6px;
    cursor: pointer;
    margin-top: 0.7rem;
    transition:
      background-color 0.2s,
      box-shadow 0.2s;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08);
    letter-spacing: 0.01em;
  }
  .details-button:hover {
    background-color: var(--button-hover-bg-color);
    box-shadow: 0 4px 16px rgba(0, 0, 0, 0.12);
  }
  @media (max-width: 480px) {
    .grade-card {
      padding: 1rem 0.3rem 1rem 0.3rem;
    }
    .details {
      padding: 0.8rem 0.3rem 0.8rem 0.3rem;
    }
  }
</style>
