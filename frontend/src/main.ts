// Inter font — self-hosted via @fontsource to avoid CSP/CORS issues with Google Fonts
import '@fontsource/inter/400.css';
import '@fontsource/inter/500.css';
import '@fontsource/inter/600.css';
import '@fontsource/inter/700.css';

// Design system CSS — imported here since App.svelte (managed) is not part of the BYO bundle
import './lib/styles/design-system.css';
import './lib/styles/component-classes.css';

import ByoApp from './lib/components/byo/ByoApp.svelte';

function showError(element: HTMLElement, message: string): void {
  const errorDiv = document.createElement('div');
  errorDiv.style.cssText = 'padding: 20px; color: red;';
  const heading = document.createElement('h1');
  heading.textContent = 'Error';
  errorDiv.appendChild(heading);
  const pre = document.createElement('pre');
  pre.textContent = message || 'Unknown error';
  errorDiv.appendChild(pre);
  element.appendChild(errorDiv);
}

const appElement = document.getElementById('app');
if (!appElement) {
  console.error('CRITICAL: #app element not found in DOM');
  const errorDiv = document.createElement('div');
  errorDiv.style.cssText = 'padding: 20px; color: red;';
  errorDiv.textContent = 'Error: App container not found';
  document.body.appendChild(errorDiv);
} else {
  try {
    new ByoApp({ target: appElement });
  } catch (e) {
    console.error('Failed to mount BYO app:', e);
    showError(appElement, e instanceof Error ? e.message : String(e));
  }
}
