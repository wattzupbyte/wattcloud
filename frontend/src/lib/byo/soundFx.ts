/**
 * soundFx — opt-in vault audio identity (§29.6).
 *
 * Off by default. User must enable via Settings → Advanced → "Vault sounds".
 * Preference is persisted in localStorage under BYO_SOUND_KEY.
 *
 * Sounds are synthesised via Web Audio API — no asset files to ship or
 * gate behind trust. Each cue is <150ms so the reviewer's latency
 * budget stays intact.
 *
 *   playLockClick() — soft metallic click for unlock / authentication.
 *   playSealThunk() — low thunk for upload encryption seal.
 *
 * AudioContext is lazy: constructed on first successful play so the
 * autoplay-policy prompt is never triggered for users who never enable
 * the feature.
 */
import { writable, get } from 'svelte/store';

const BYO_SOUND_KEY = 'sc-byo-sounds-enabled';

function readInitial(): boolean {
  if (typeof localStorage === 'undefined') return false;
  return localStorage.getItem(BYO_SOUND_KEY) === '1';
}

export const byoSoundEnabled = writable<boolean>(readInitial());

export function setByoSoundEnabled(enabled: boolean): void {
  byoSoundEnabled.set(enabled);
  if (typeof localStorage === 'undefined') return;
  if (enabled) localStorage.setItem(BYO_SOUND_KEY, '1');
  else localStorage.removeItem(BYO_SOUND_KEY);
}

let ctx: AudioContext | null = null;
let primedOnce = false;

/**
 * Bind a one-shot primer to the document so the next user gesture
 * creates + resumes the AudioContext. Without this, the first
 * non-gesture play (e.g. upload completion after a page load with
 * sounds already enabled) creates a suspended context that Safari
 * refuses to resume on a later non-gesture tick.
 */
function armPrimer(): void {
  if (primedOnce || typeof window === 'undefined') return;
  primedOnce = true;
  const prime = () => {
    const AC = window.AudioContext || (window as any).webkitAudioContext;
    if (!AC) return;
    try {
      if (!ctx) ctx = new AC();
      if (ctx.state === 'suspended') ctx.resume().catch(() => {});
    } catch {
      /* ignore */
    }
  };
  window.addEventListener('pointerdown', prime, { once: true, passive: true });
  window.addEventListener('keydown', prime, { once: true, passive: true });
  window.addEventListener('touchstart', prime, { once: true, passive: true });
}

function getCtx(): AudioContext | null {
  if (typeof window === 'undefined') return null;
  const AC = window.AudioContext || (window as any).webkitAudioContext;
  if (!AC) return null;
  if (!ctx) {
    try { ctx = new AC(); } catch { return null; }
  }
  // Safari may suspend the context when the tab is backgrounded —
  // resume() is idempotent and must follow a user gesture on first call.
  if (ctx.state === 'suspended') ctx.resume().catch(() => {});
  return ctx;
}

// Arm the primer as soon as the module loads so the AudioContext is
// ready by the time the first sound actually needs to play.
if (typeof window !== 'undefined') armPrimer();

function isEnabled(): boolean {
  return get(byoSoundEnabled);
}

/** Soft metallic click — short filtered noise burst. */
export function playLockClick(): void {
  if (!isEnabled()) return;
  const c = getCtx();
  if (!c) return;
  const now = c.currentTime;

  // Short noise buffer (~60ms).
  const duration = 0.06;
  const buf = c.createBuffer(1, Math.floor(c.sampleRate * duration), c.sampleRate);
  const data = buf.getChannelData(0);
  for (let i = 0; i < data.length; i++) {
    // Decaying white noise — metallic feel comes from the bandpass below.
    const t = i / data.length;
    data[i] = (Math.random() * 2 - 1) * (1 - t);
  }

  const src = c.createBufferSource();
  src.buffer = buf;

  const bp = c.createBiquadFilter();
  bp.type = 'bandpass';
  bp.frequency.value = 3200;
  bp.Q.value = 3;

  const gain = c.createGain();
  gain.gain.setValueAtTime(0.22, now);
  gain.gain.exponentialRampToValueAtTime(0.001, now + duration);

  src.connect(bp);
  bp.connect(gain);
  gain.connect(c.destination);
  src.start(now);
  src.stop(now + duration);
}

/** Low, quiet "thunk" for upload-seal completion. */
export function playSealThunk(): void {
  if (!isEnabled()) return;
  const c = getCtx();
  if (!c) return;
  const now = c.currentTime;

  const osc = c.createOscillator();
  osc.type = 'sine';
  // Pitch drops from 220 → 110Hz over 90ms for a subtle "seal" feel.
  osc.frequency.setValueAtTime(220, now);
  osc.frequency.exponentialRampToValueAtTime(110, now + 0.09);

  const gain = c.createGain();
  gain.gain.setValueAtTime(0.0001, now);
  gain.gain.exponentialRampToValueAtTime(0.18, now + 0.012);
  gain.gain.exponentialRampToValueAtTime(0.001, now + 0.12);

  osc.connect(gain);
  gain.connect(c.destination);
  osc.start(now);
  osc.stop(now + 0.13);
}
