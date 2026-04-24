/**
 * Minimal placeBounds store for wattcloud's BYO mode.
 *
 * Wattcloud is server-stateless (the relay never sees user data) so we
 * can't fetch a curated dataset from the backend the way secure-cloud
 * does. Instead, we ship the static `PLACE_BOUNDS` table bundled with
 * the SPA and expose it through the same store API so the shared
 * `PlaceSearch.svelte` component can consume it.
 */

import { writable } from 'svelte/store';
import { PLACE_BOUNDS, type PlaceBounds } from '../data/placeBounds';

export const placesStore = writable<PlaceBounds[]>(PLACE_BOUNDS);

/** No-op loader kept for API compatibility with the shared PlaceSearch. */
export async function loadPlaces(): Promise<void> { /* static dataset */ }
