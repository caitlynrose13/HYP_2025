<!--Component that displays the grade and TLS basci information-->
<script lang="ts">
  export let grade: string;
  export let summary: string;
  export let tlsProtocol: string;
  export let certValid: boolean;
  export let certIssuer: string;
  export let certExpiryDays: number;
  export let onViewDetailedReport: () => void;

  //  render the correct SVG icon for each grade
  function getGradeIcon(grade: string) {
    switch (grade) {
      case "APlus":
        // Green lock with A+
        return `<svg width='70' height='70'><rect x='10' y='30' width='50' height='30' rx='8' fill='#19d44b'/><rect x='25' y='15' width='20' height='20' rx='10' fill='none' stroke='#19d44b' stroke-width='6'/><text x='35' y='55' text-anchor='middle' font-size='22' fill='white' font-weight='bold'>A+</text></svg>`;
      case "A":
        // Green padlock with A
        return `<svg width='70' height='70'><rect x='10' y='30' width='50' height='30' rx='8' fill='#19d44b'/><rect x='25' y='15' width='20' height='20' rx='10' fill='none' stroke='#19d44b' stroke-width='6'/><text x='35' y='55' text-anchor='middle' font-size='28' fill='white' font-weight='bold'>A</text></svg>`;
      case "AMinus":
        // Yellow-green circle with A-
        return `<svg width='70' height='70'><circle cx='35' cy='35' r='28' fill='#b6e26d' stroke='#7bb13c' stroke-width='6'/><text x='35' y='45' text-anchor='middle' font-size='28' fill='#4a6c1c' font-weight='bold'>A-</text></svg>`;
      case "B":
        // Gold/yellow circle with B
        return `<svg width='70' height='70'><circle cx='35' cy='35' r='28' fill='#ffe066' stroke='#e6b800' stroke-width='6'/><text x='35' y='45' text-anchor='middle' font-size='28' fill='#bfa600' font-weight='bold'>B</text></svg>`;
      case "C":
        // Grey circle with darker grey outline and C
        return `<svg width='70' height='70'><circle cx='35' cy='35' r='28' fill='#e0e0e0' stroke='#888' stroke-width='6'/><text x='35' y='45' text-anchor='middle' font-size='28' fill='#555' font-weight='bold'>C</text></svg>`;
      case "F":
        // Red triangle with F
        return `<svg width='70' height='70'><polygon points='35,10 60,60 10,60' fill='#d32f2f'/><text x='35' y='45' text-anchor='middle' font-size='22' fill='white' font-weight='bold'>F</text></svg>`;
      default:
        // Default: gray outlined circle
        return `<svg width='70' height='70'><circle cx='35' cy='35' r='28' fill='none' stroke='#888' stroke-width='2'/></svg>`;
    }
  }
</script>

<h3 class="security-overview-heading">Security Overview</h3>
<div class="grade-card">
  <div class="grade-section">
    <div class="label overall-rating-label">Overall Rating</div>
    <div
      class="icon-grade"
      style="display: flex; align-items: center; justify-content: center;"
    >
      {@html getGradeIcon(grade)}
    </div>
    <div class="summary handshake-status">{summary}</div>
  </div>
  <div class="details details-table">
    <div class="detail-row">
      <span class="detail-label">Protocol:</span>
      <span class="detail-value">{tlsProtocol}</span>
    </div>
    <div class="detail-row">
      <span class="detail-label">Certificate Valid:</span>
      <span class="detail-value">{certValid ? "Yes" : "No"}</span>
    </div>
    <div class="detail-row">
      <span class="detail-label">Issuer:</span>
      <span class="detail-value">{certIssuer}</span>
    </div>
    <div class="detail-row">
      <span class="detail-label">Expires In:</span>
      <span class="detail-value">{certExpiryDays} days</span>
    </div>
  </div>

  <button class="details-button" on:click={onViewDetailedReport}>
    View Detailed Report
  </button>
</div>

<style>
  .security-overview-heading {
    font-size: 1.18em;
    font-weight: 700;
    margin: 0 0 1em 0;
    color: var(--text-color);
    text-align: left;
    letter-spacing: 0.5px;
  }
  .grade-card {
    margin-bottom: 1rem;
    padding: 2.2rem 1.2rem 2.2rem 1.2rem;
    border-radius: 10px;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.07);
    color: var(--text-color);
    background: var(--card-background-color);
    border: 1px solid var(--border-color);
    font-size: 1em;
    max-width: 96%;
    margin-left: auto;
    margin-right: auto;
    display: flex;
    flex-direction: column;
    align-items: center;
  }
  .grade-section {
    display: flex;
    flex-direction: column;
    align-items: center;
    margin-bottom: 1.2em;
  }
  .label.overall-rating-label {
    font-size: 1.25em;
    font-weight: 700;
    margin-bottom: 0.5em;
  }
  .icon-grade {
    margin-bottom: 0.5em;
  }
  .summary.handshake-status {
    font-size: 1.1em;
    font-weight: 600;
    margin-bottom: 0.5em;
    color: var(--text-color);
    text-align: center;
  }
  .details.details-table {
    font-size: 1.05em;
    margin-top: 0.6em;
    width: 100%;
    display: flex;
    flex-direction: column;
    gap: 0.3em;
  }
  .detail-row {
    display: flex;
    justify-content: flex-start;
    align-items: center;
    gap: 2.5em;
  }
  .detail-label {
    min-width: 140px;
    font-weight: 600;
    color: var(--text-color);
    text-align: right;
    flex-shrink: 0;
    padding-right: 12px;
  }
  .detail-value {
    font-weight: 400;
    color: var(--text-color);
    text-align: left;
    word-break: break-all;
    padding-left: 16px;
  }
  .details {
    font-size: 0.9em;
    margin-top: 0.3em;
    width: 100%;
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    gap: 0.2em;
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
