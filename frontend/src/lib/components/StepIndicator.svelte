<script lang="ts">
  interface Props {
    steps: string[];
    currentStep: number; // 0-indexed, -1 if not on any step
    completedSteps?: number[];
    /** Hide the per-step text labels under the circles. Useful in flows
     * where the step name is already in the page heading and the labels
     * would just wrap unevenly. Default: true (labels visible). */
    showLabels?: boolean;
  }

  let { steps, currentStep, completedSteps = [], showLabels = true }: Props = $props();

  // A connector should be green if the step BEFORE it is completed
  // Connector after step 0 connects steps 0-1, should be green if step 0 is completed
  // Connector after step 1 connects steps 1-2, should be green if step 1 is completed
  function isConnectorCompleted(index: number): boolean {
    // The connector after step index connects step index to step index+1
    // It should be green if step index is completed
    return completedSteps.includes(index);
  }
</script>

<div class="step-indicator" role="progressbar" aria-valuenow={currentStep + 1} aria-valuemin={1} aria-valuemax={steps.length}>
  {#each steps as step, i}
    <div class="step-item" class:active={i === currentStep} class:completed={completedSteps.includes(i)}>
      <div class="step-circle">
        {#if completedSteps.includes(i)}
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3">
            <polyline points="20 6 9 17 4 12"></polyline>
          </svg>
        {:else if i === currentStep}
          <span class="step-number">{i + 1}</span>
        {:else}
          <span class="step-number">{i + 1}</span>
        {/if}
      </div>
      {#if showLabels}
        <span class="step-label">{step}</span>
      {/if}
      {#if i < steps.length - 1}
        <div class="step-connector" class:completed={isConnectorCompleted(i)}></div>
      {/if}
    </div>
  {/each}
</div>

<style>
  .step-indicator {
    display: flex;
    justify-content: center;
    /* Anchor every step-item by its TOP edge so circles and connectors stay
       on the same horizontal line even when some labels wrap to two lines
       (e.g. "Creating Vault"). With `align-items: center` the taller items
       push the shorter ones downward, breaking the connector line. */
    align-items: flex-start;
    gap: 0;
    margin-bottom: var(--sp-lg);
    width: 100%;
  }

  .step-item {
    display: flex;
    flex-direction: column;
    align-items: center;
    position: relative;
    flex: 1;
  }

  .step-circle {
    width: 32px;
    height: 32px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    background: var(--bg-surface-raised);
    color: var(--text-secondary);
    font-size: var(--t-body-sm-size);
    font-weight: 600;
    transition: all 0.3s ease;
    position: relative;
    z-index: 2;
  }

  .step-number {
    line-height: 1;
  }

  .step-item.active .step-circle {
    background: var(--accent);
    color: var(--text-inverse);
    box-shadow: 0 0 0 4px var(--accent-muted);
  }

  .step-item.completed .step-circle {
    background: var(--accent);
    color: var(--text-inverse);
  }

  .step-label {
    font-size: var(--t-label-size);
    color: var(--text-secondary);
    margin-top: var(--sp-sm);
    text-align: center;
    max-width: 80px;
    transition: color 0.3s ease;
  }

  .step-item.active .step-label {
    color: var(--accent-text);
    font-weight: 600;
  }

  .step-item.completed .step-label {
    color: var(--accent-text);
  }

  .step-connector {
    position: absolute;
    top: 16px;
    left: calc(50% + 20px);
    width: calc(100% - 40px);
    height: 2px;
    background: var(--bg-surface-raised);
    transition: background 0.3s ease;
  }

  .step-connector.completed {
    background: var(--accent);
  }

  /* Mobile adjustments */
  @media (max-width: 480px) {
    .step-circle {
      width: 28px;
      height: 28px;
      font-size: var(--t-label-size);
    }

    .step-label {
      font-size: 0.625rem;
      max-width: 60px;
    }

    .step-connector {
      top: 14px;
      left: calc(50% + 18px);
      width: calc(100% - 36px);
    }
  }
</style>
