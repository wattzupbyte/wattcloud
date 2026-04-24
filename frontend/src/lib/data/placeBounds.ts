// Static place bounding-box lookup table.
// Sources: Natural Earth (public domain), SimpleMaps World Cities Basic (CC).
// To regenerate, run: npx tsx scripts/updatePlaceBounds.ts
// Last updated: 2026-04-07

export type PlaceType = 'country' | 'region' | 'city';

export interface PlaceBounds {
  name: string;       // search key (lowercase-friendly)
  display: string;    // shown in UI
  flag?: string;      // emoji flag for countries
  type: PlaceType;
  parent?: string;    // country name for regions/cities
  latMin: number;
  latMax: number;
  lonMin: number;
  lonMax: number;
}

export const PLACE_BOUNDS: PlaceBounds[] = [
  // ── Countries ─────────────────────────────────────────────────────────────
  { name: 'afghanistan', display: 'Afghanistan', flag: '🇦🇫', type: 'country', latMin: 29.38, latMax: 38.49, lonMin: 60.52, lonMax: 74.89 },
  { name: 'albania', display: 'Albania', flag: '🇦🇱', type: 'country', latMin: 39.62, latMax: 42.66, lonMin: 19.27, lonMax: 21.06 },
  { name: 'algeria', display: 'Algeria', flag: '🇩🇿', type: 'country', latMin: 18.97, latMax: 37.09, lonMin: -8.67, lonMax: 11.99 },
  { name: 'andorra', display: 'Andorra', flag: '🇦🇩', type: 'country', latMin: 42.43, latMax: 42.66, lonMin: 1.41, lonMax: 1.79 },
  { name: 'angola', display: 'Angola', flag: '🇦🇴', type: 'country', latMin: -18.04, latMax: -4.39, lonMin: 11.64, lonMax: 24.08 },
  { name: 'argentina', display: 'Argentina', flag: '🇦🇷', type: 'country', latMin: -55.06, latMax: -21.78, lonMin: -73.56, lonMax: -53.59 },
  { name: 'armenia', display: 'Armenia', flag: '🇦🇲', type: 'country', latMin: 38.84, latMax: 41.30, lonMin: 43.44, lonMax: 46.64 },
  { name: 'australia', display: 'Australia', flag: '🇦🇺', type: 'country', latMin: -43.63, latMax: -10.67, lonMin: 113.15, lonMax: 153.64 },
  { name: 'austria', display: 'Austria', flag: '🇦🇹', type: 'country', latMin: 46.37, latMax: 49.02, lonMin: 9.53, lonMax: 17.16 },
  { name: 'azerbaijan', display: 'Azerbaijan', flag: '🇦🇿', type: 'country', latMin: 38.27, latMax: 41.86, lonMin: 44.79, lonMax: 50.39 },
  { name: 'bahrain', display: 'Bahrain', flag: '🇧🇭', type: 'country', latMin: 25.79, latMax: 26.33, lonMin: 50.45, lonMax: 50.64 },
  { name: 'bangladesh', display: 'Bangladesh', flag: '🇧🇩', type: 'country', latMin: 20.74, latMax: 26.63, lonMin: 88.01, lonMax: 92.67 },
  { name: 'belarus', display: 'Belarus', flag: '🇧🇾', type: 'country', latMin: 51.26, latMax: 56.17, lonMin: 23.18, lonMax: 32.76 },
  { name: 'belgium', display: 'Belgium', flag: '🇧🇪', type: 'country', latMin: 49.50, latMax: 51.51, lonMin: 2.55, lonMax: 6.41 },
  { name: 'belize', display: 'Belize', flag: '🇧🇿', type: 'country', latMin: 15.89, latMax: 18.50, lonMin: -89.23, lonMax: -87.78 },
  { name: 'benin', display: 'Benin', flag: '🇧🇯', type: 'country', latMin: 6.22, latMax: 12.41, lonMin: 0.77, lonMax: 3.84 },
  { name: 'bhutan', display: 'Bhutan', flag: '🇧🇹', type: 'country', latMin: 26.72, latMax: 28.32, lonMin: 88.75, lonMax: 92.13 },
  { name: 'bolivia', display: 'Bolivia', flag: '🇧🇴', type: 'country', latMin: -22.90, latMax: -9.67, lonMin: -69.64, lonMax: -57.46 },
  { name: 'bosnia and herzegovina', display: 'Bosnia and Herzegovina', flag: '🇧🇦', type: 'country', latMin: 42.56, latMax: 45.28, lonMin: 15.72, lonMax: 19.62 },
  { name: 'botswana', display: 'Botswana', flag: '🇧🇼', type: 'country', latMin: -26.91, latMax: -17.78, lonMin: 19.99, lonMax: 29.38 },
  { name: 'brazil', display: 'Brazil', flag: '🇧🇷', type: 'country', latMin: -33.75, latMax: 5.27, lonMin: -73.98, lonMax: -28.85 },
  { name: 'brunei', display: 'Brunei', flag: '🇧🇳', type: 'country', latMin: 4.00, latMax: 5.05, lonMin: 114.07, lonMax: 115.36 },
  { name: 'bulgaria', display: 'Bulgaria', flag: '🇧🇬', type: 'country', latMin: 41.24, latMax: 44.23, lonMin: 22.36, lonMax: 28.61 },
  { name: 'burkina faso', display: 'Burkina Faso', flag: '🇧🇫', type: 'country', latMin: 9.40, latMax: 15.08, lonMin: -5.52, lonMax: 2.41 },
  { name: 'burundi', display: 'Burundi', flag: '🇧🇮', type: 'country', latMin: -4.47, latMax: -2.31, lonMin: 29.00, lonMax: 30.85 },
  { name: 'cambodia', display: 'Cambodia', flag: '🇰🇭', type: 'country', latMin: 9.22, latMax: 14.69, lonMin: 102.33, lonMax: 107.63 },
  { name: 'cameroon', display: 'Cameroon', flag: '🇨🇲', type: 'country', latMin: 1.65, latMax: 12.86, lonMin: 8.49, lonMax: 16.01 },
  { name: 'canada', display: 'Canada', flag: '🇨🇦', type: 'country', latMin: 41.68, latMax: 83.11, lonMin: -141.00, lonMax: -52.64 },
  { name: 'chile', display: 'Chile', flag: '🇨🇱', type: 'country', latMin: -55.98, latMax: -17.51, lonMin: -75.64, lonMax: -66.42 },
  { name: 'china', display: 'China', flag: '🇨🇳', type: 'country', latMin: 18.17, latMax: 53.56, lonMin: 73.50, lonMax: 134.77 },
  { name: 'colombia', display: 'Colombia', flag: '🇨🇴', type: 'country', latMin: -4.23, latMax: 13.39, lonMin: -79.01, lonMax: -66.87 },
  { name: 'congo', display: 'Congo', flag: '🇨🇬', type: 'country', latMin: -5.03, latMax: 3.71, lonMin: 11.15, lonMax: 18.64 },
  { name: 'democratic republic of congo', display: 'DR Congo', flag: '🇨🇩', type: 'country', latMin: -13.46, latMax: 5.38, lonMin: 12.20, lonMax: 31.31 },
  { name: 'costa rica', display: 'Costa Rica', flag: '🇨🇷', type: 'country', latMin: 5.50, latMax: 11.22, lonMin: -85.95, lonMax: -82.56 },
  { name: 'croatia', display: 'Croatia', flag: '🇭🇷', type: 'country', latMin: 42.39, latMax: 46.56, lonMin: 13.49, lonMax: 19.43 },
  { name: 'cuba', display: 'Cuba', flag: '🇨🇺', type: 'country', latMin: 19.83, latMax: 23.19, lonMin: -84.96, lonMax: -74.15 },
  { name: 'cyprus', display: 'Cyprus', flag: '🇨🇾', type: 'country', latMin: 34.57, latMax: 35.71, lonMin: 32.27, lonMax: 34.00 },
  { name: 'czech republic', display: 'Czech Republic', flag: '🇨🇿', type: 'country', latMin: 48.55, latMax: 51.06, lonMin: 12.09, lonMax: 18.86 },
  { name: 'czechia', display: 'Czechia', flag: '🇨🇿', type: 'country', latMin: 48.55, latMax: 51.06, lonMin: 12.09, lonMax: 18.86 },
  { name: 'denmark', display: 'Denmark', flag: '🇩🇰', type: 'country', latMin: 54.56, latMax: 57.75, lonMin: 8.07, lonMax: 15.20 },
  { name: 'djibouti', display: 'Djibouti', flag: '🇩🇯', type: 'country', latMin: 10.94, latMax: 12.71, lonMin: 41.77, lonMax: 43.42 },
  { name: 'dominican republic', display: 'Dominican Republic', flag: '🇩🇴', type: 'country', latMin: 17.47, latMax: 19.93, lonMin: -72.01, lonMax: -68.32 },
  { name: 'ecuador', display: 'Ecuador', flag: '🇪🇨', type: 'country', latMin: -5.01, latMax: 1.68, lonMin: -80.97, lonMax: -75.19 },
  { name: 'egypt', display: 'Egypt', flag: '🇪🇬', type: 'country', latMin: 22.00, latMax: 31.67, lonMin: 24.70, lonMax: 37.06 },
  { name: 'el salvador', display: 'El Salvador', flag: '🇸🇻', type: 'country', latMin: 13.15, latMax: 14.45, lonMin: -90.10, lonMax: -87.69 },
  { name: 'eritrea', display: 'Eritrea', flag: '🇪🇷', type: 'country', latMin: 12.36, latMax: 18.00, lonMin: 36.44, lonMax: 43.14 },
  { name: 'estonia', display: 'Estonia', flag: '🇪🇪', type: 'country', latMin: 57.51, latMax: 59.68, lonMin: 21.76, lonMax: 28.21 },
  { name: 'ethiopia', display: 'Ethiopia', flag: '🇪🇹', type: 'country', latMin: 3.40, latMax: 15.00, lonMin: 33.00, lonMax: 47.99 },
  { name: 'finland', display: 'Finland', flag: '🇫🇮', type: 'country', latMin: 59.81, latMax: 70.09, lonMin: 19.08, lonMax: 31.59 },
  { name: 'france', display: 'France', flag: '🇫🇷', type: 'country', latMin: 41.33, latMax: 51.12, lonMin: -5.14, lonMax: 9.56 },
  { name: 'gabon', display: 'Gabon', flag: '🇬🇦', type: 'country', latMin: -3.98, latMax: 2.32, lonMin: 8.70, lonMax: 14.50 },
  { name: 'georgia', display: 'Georgia', flag: '🇬🇪', type: 'country', latMin: 41.06, latMax: 43.59, lonMin: 39.98, lonMax: 46.72 },
  { name: 'germany', display: 'Germany', flag: '🇩🇪', type: 'country', latMin: 47.27, latMax: 55.07, lonMin: 5.87, lonMax: 15.04 },
  { name: 'ghana', display: 'Ghana', flag: '🇬🇭', type: 'country', latMin: 4.74, latMax: 11.17, lonMin: -3.26, lonMax: 1.20 },
  { name: 'greece', display: 'Greece', flag: '🇬🇷', type: 'country', latMin: 34.80, latMax: 41.75, lonMin: 19.37, lonMax: 29.65 },
  { name: 'guatemala', display: 'Guatemala', flag: '🇬🇹', type: 'country', latMin: 13.74, latMax: 17.82, lonMin: -92.23, lonMax: -88.22 },
  { name: 'guinea', display: 'Guinea', flag: '🇬🇳', type: 'country', latMin: 7.19, latMax: 12.68, lonMin: -15.08, lonMax: -7.65 },
  { name: 'haiti', display: 'Haiti', flag: '🇭🇹', type: 'country', latMin: 18.02, latMax: 20.09, lonMin: -74.48, lonMax: -71.62 },
  { name: 'honduras', display: 'Honduras', flag: '🇭🇳', type: 'country', latMin: 12.98, latMax: 16.01, lonMin: -89.35, lonMax: -83.15 },
  { name: 'hungary', display: 'Hungary', flag: '🇭🇺', type: 'country', latMin: 45.74, latMax: 48.58, lonMin: 16.11, lonMax: 22.90 },
  { name: 'iceland', display: 'Iceland', flag: '🇮🇸', type: 'country', latMin: 63.39, latMax: 66.57, lonMin: -24.54, lonMax: -13.50 },
  { name: 'india', display: 'India', flag: '🇮🇳', type: 'country', latMin: 6.75, latMax: 35.67, lonMin: 68.18, lonMax: 97.40 },
  { name: 'indonesia', display: 'Indonesia', flag: '🇮🇩', type: 'country', latMin: -10.36, latMax: 5.48, lonMin: 95.01, lonMax: 141.02 },
  { name: 'iran', display: 'Iran', flag: '🇮🇷', type: 'country', latMin: 25.06, latMax: 39.77, lonMin: 44.03, lonMax: 63.33 },
  { name: 'iraq', display: 'Iraq', flag: '🇮🇶', type: 'country', latMin: 29.06, latMax: 37.39, lonMin: 38.79, lonMax: 48.57 },
  { name: 'ireland', display: 'Ireland', flag: '🇮🇪', type: 'country', latMin: 51.43, latMax: 55.39, lonMin: -10.48, lonMax: -6.00 },
  { name: 'israel', display: 'Israel', flag: '🇮🇱', type: 'country', latMin: 29.49, latMax: 33.33, lonMin: 34.27, lonMax: 35.90 },
  { name: 'italy', display: 'Italy', flag: '🇮🇹', type: 'country', latMin: 35.49, latMax: 47.09, lonMin: 6.63, lonMax: 18.52 },
  { name: 'jamaica', display: 'Jamaica', flag: '🇯🇲', type: 'country', latMin: 17.70, latMax: 18.52, lonMin: -78.37, lonMax: -76.19 },
  { name: 'japan', display: 'Japan', flag: '🇯🇵', type: 'country', latMin: 24.25, latMax: 45.52, lonMin: 122.94, lonMax: 153.99 },
  { name: 'jordan', display: 'Jordan', flag: '🇯🇴', type: 'country', latMin: 29.19, latMax: 33.38, lonMin: 34.96, lonMax: 39.30 },
  { name: 'kazakhstan', display: 'Kazakhstan', flag: '🇰🇿', type: 'country', latMin: 40.57, latMax: 55.45, lonMin: 50.27, lonMax: 87.36 },
  { name: 'kenya', display: 'Kenya', flag: '🇰🇪', type: 'country', latMin: -4.68, latMax: 4.62, lonMin: 33.91, lonMax: 41.90 },
  { name: 'north korea', display: 'North Korea', flag: '🇰🇵', type: 'country', latMin: 37.67, latMax: 42.99, lonMin: 124.27, lonMax: 130.67 },
  { name: 'south korea', display: 'South Korea', flag: '🇰🇷', type: 'country', latMin: 33.19, latMax: 38.61, lonMin: 125.08, lonMax: 129.58 },
  { name: 'kuwait', display: 'Kuwait', flag: '🇰🇼', type: 'country', latMin: 28.52, latMax: 30.10, lonMin: 46.57, lonMax: 48.43 },
  { name: 'kyrgyzstan', display: 'Kyrgyzstan', flag: '🇰🇬', type: 'country', latMin: 39.17, latMax: 43.26, lonMin: 69.26, lonMax: 80.30 },
  { name: 'laos', display: 'Laos', flag: '🇱🇦', type: 'country', latMin: 13.92, latMax: 22.50, lonMin: 100.10, lonMax: 107.64 },
  { name: 'latvia', display: 'Latvia', flag: '🇱🇻', type: 'country', latMin: 55.67, latMax: 57.97, lonMin: 20.97, lonMax: 28.24 },
  { name: 'lebanon', display: 'Lebanon', flag: '🇱🇧', type: 'country', latMin: 33.05, latMax: 34.69, lonMin: 35.10, lonMax: 36.62 },
  { name: 'libya', display: 'Libya', flag: '🇱🇾', type: 'country', latMin: 19.50, latMax: 33.17, lonMin: 9.31, lonMax: 25.16 },
  { name: 'liechtenstein', display: 'Liechtenstein', flag: '🇱🇮', type: 'country', latMin: 47.05, latMax: 47.27, lonMin: 9.48, lonMax: 9.64 },
  { name: 'lithuania', display: 'Lithuania', flag: '🇱🇹', type: 'country', latMin: 53.89, latMax: 56.45, lonMin: 20.94, lonMax: 26.84 },
  { name: 'luxembourg', display: 'Luxembourg', flag: '🇱🇺', type: 'country', latMin: 49.44, latMax: 50.18, lonMin: 5.73, lonMax: 6.53 },
  { name: 'madagascar', display: 'Madagascar', flag: '🇲🇬', type: 'country', latMin: -25.61, latMax: -11.95, lonMin: 43.22, lonMax: 50.48 },
  { name: 'malawi', display: 'Malawi', flag: '🇲🇼', type: 'country', latMin: -17.13, latMax: -9.36, lonMin: 32.68, lonMax: 35.92 },
  { name: 'malaysia', display: 'Malaysia', flag: '🇲🇾', type: 'country', latMin: 0.85, latMax: 7.36, lonMin: 99.64, lonMax: 119.27 },
  { name: 'mali', display: 'Mali', flag: '🇲🇱', type: 'country', latMin: 10.14, latMax: 25.00, lonMin: -4.24, lonMax: 4.27 },
  { name: 'mauritania', display: 'Mauritania', flag: '🇲🇷', type: 'country', latMin: 14.72, latMax: 27.30, lonMin: -17.07, lonMax: -4.83 },
  { name: 'mexico', display: 'Mexico', flag: '🇲🇽', type: 'country', latMin: 14.53, latMax: 32.72, lonMin: -117.13, lonMax: -86.74 },
  { name: 'moldova', display: 'Moldova', flag: '🇲🇩', type: 'country', latMin: 45.47, latMax: 48.49, lonMin: 26.62, lonMax: 30.13 },
  { name: 'mongolia', display: 'Mongolia', flag: '🇲🇳', type: 'country', latMin: 41.57, latMax: 52.15, lonMin: 87.75, lonMax: 119.93 },
  { name: 'montenegro', display: 'Montenegro', flag: '🇲🇪', type: 'country', latMin: 41.86, latMax: 43.56, lonMin: 18.43, lonMax: 20.36 },
  { name: 'morocco', display: 'Morocco', flag: '🇲🇦', type: 'country', latMin: 27.67, latMax: 35.92, lonMin: -13.17, lonMax: -0.99 },
  { name: 'mozambique', display: 'Mozambique', flag: '🇲🇿', type: 'country', latMin: -26.87, latMax: -10.47, lonMin: 30.22, lonMax: 40.84 },
  { name: 'myanmar', display: 'Myanmar', flag: '🇲🇲', type: 'country', latMin: 9.79, latMax: 28.55, lonMin: 92.19, lonMax: 101.17 },
  { name: 'namibia', display: 'Namibia', flag: '🇳🇦', type: 'country', latMin: -29.05, latMax: -16.96, lonMin: 11.72, lonMax: 25.26 },
  { name: 'nepal', display: 'Nepal', flag: '🇳🇵', type: 'country', latMin: 26.35, latMax: 30.42, lonMin: 80.06, lonMax: 88.20 },
  { name: 'netherlands', display: 'Netherlands', flag: '🇳🇱', type: 'country', latMin: 50.75, latMax: 53.55, lonMin: 3.37, lonMax: 7.23 },
  { name: 'new zealand', display: 'New Zealand', flag: '🇳🇿', type: 'country', latMin: -46.64, latMax: -34.39, lonMin: 166.43, lonMax: 178.56 },
  { name: 'nicaragua', display: 'Nicaragua', flag: '🇳🇮', type: 'country', latMin: 10.71, latMax: 15.03, lonMin: -87.67, lonMax: -83.15 },
  { name: 'niger', display: 'Niger', flag: '🇳🇪', type: 'country', latMin: 11.69, latMax: 23.52, lonMin: 0.16, lonMax: 15.90 },
  { name: 'nigeria', display: 'Nigeria', flag: '🇳🇬', type: 'country', latMin: 4.24, latMax: 13.89, lonMin: 2.69, lonMax: 14.68 },
  { name: 'north macedonia', display: 'North Macedonia', flag: '🇲🇰', type: 'country', latMin: 40.86, latMax: 42.37, lonMin: 20.45, lonMax: 23.04 },
  { name: 'norway', display: 'Norway', flag: '🇳🇴', type: 'country', latMin: 57.98, latMax: 71.18, lonMin: 4.77, lonMax: 31.29 },
  { name: 'oman', display: 'Oman', flag: '🇴🇲', type: 'country', latMin: 16.64, latMax: 26.39, lonMin: 51.99, lonMax: 59.84 },
  { name: 'pakistan', display: 'Pakistan', flag: '🇵🇰', type: 'country', latMin: 23.69, latMax: 37.10, lonMin: 60.87, lonMax: 77.84 },
  { name: 'panama', display: 'Panama', flag: '🇵🇦', type: 'country', latMin: 7.20, latMax: 9.64, lonMin: -83.05, lonMax: -77.17 },
  { name: 'papua new guinea', display: 'Papua New Guinea', flag: '🇵🇬', type: 'country', latMin: -10.65, latMax: -1.34, lonMin: 140.84, lonMax: 155.96 },
  { name: 'paraguay', display: 'Paraguay', flag: '🇵🇾', type: 'country', latMin: -27.59, latMax: -19.29, lonMin: -62.64, lonMax: -54.29 },
  { name: 'peru', display: 'Peru', flag: '🇵🇪', type: 'country', latMin: -18.35, latMax: -0.02, lonMin: -81.41, lonMax: -68.67 },
  { name: 'philippines', display: 'Philippines', flag: '🇵🇭', type: 'country', latMin: 4.59, latMax: 21.12, lonMin: 116.93, lonMax: 126.60 },
  { name: 'poland', display: 'Poland', flag: '🇵🇱', type: 'country', latMin: 49.00, latMax: 54.84, lonMin: 14.12, lonMax: 24.15 },
  { name: 'portugal', display: 'Portugal', flag: '🇵🇹', type: 'country', latMin: 36.96, latMax: 42.15, lonMin: -9.52, lonMax: -6.19 },
  { name: 'qatar', display: 'Qatar', flag: '🇶🇦', type: 'country', latMin: 24.56, latMax: 26.18, lonMin: 50.75, lonMax: 51.61 },
  { name: 'romania', display: 'Romania', flag: '🇷🇴', type: 'country', latMin: 43.63, latMax: 48.26, lonMin: 20.26, lonMax: 29.74 },
  { name: 'russia', display: 'Russia', flag: '🇷🇺', type: 'country', latMin: 41.19, latMax: 81.86, lonMin: 19.64, lonMax: 180.00 },
  { name: 'rwanda', display: 'Rwanda', flag: '🇷🇼', type: 'country', latMin: -2.84, latMax: -1.05, lonMin: 28.86, lonMax: 30.90 },
  { name: 'saudi arabia', display: 'Saudi Arabia', flag: '🇸🇦', type: 'country', latMin: 16.37, latMax: 32.16, lonMin: 36.47, lonMax: 55.67 },
  { name: 'senegal', display: 'Senegal', flag: '🇸🇳', type: 'country', latMin: 12.31, latMax: 16.69, lonMin: -17.54, lonMax: -11.37 },
  { name: 'serbia', display: 'Serbia', flag: '🇷🇸', type: 'country', latMin: 42.23, latMax: 46.19, lonMin: 18.82, lonMax: 23.01 },
  { name: 'sierra leone', display: 'Sierra Leone', flag: '🇸🇱', type: 'country', latMin: 6.93, latMax: 10.00, lonMin: -13.30, lonMax: -10.28 },
  { name: 'singapore', display: 'Singapore', flag: '🇸🇬', type: 'country', latMin: 1.16, latMax: 1.47, lonMin: 103.60, lonMax: 104.09 },
  { name: 'slovakia', display: 'Slovakia', flag: '🇸🇰', type: 'country', latMin: 47.73, latMax: 49.61, lonMin: 16.83, lonMax: 22.57 },
  { name: 'slovenia', display: 'Slovenia', flag: '🇸🇮', type: 'country', latMin: 45.42, latMax: 46.88, lonMin: 13.38, lonMax: 16.60 },
  { name: 'somalia', display: 'Somalia', flag: '🇸🇴', type: 'country', latMin: -1.68, latMax: 12.02, lonMin: 40.99, lonMax: 51.41 },
  { name: 'south africa', display: 'South Africa', flag: '🇿🇦', type: 'country', latMin: -34.82, latMax: -22.13, lonMin: 16.46, lonMax: 32.89 },
  { name: 'south sudan', display: 'South Sudan', flag: '🇸🇸', type: 'country', latMin: 3.49, latMax: 12.24, lonMin: 23.89, lonMax: 35.30 },
  { name: 'spain', display: 'Spain', flag: '🇪🇸', type: 'country', latMin: 35.95, latMax: 43.79, lonMin: -9.39, lonMax: 4.33 },
  { name: 'sri lanka', display: 'Sri Lanka', flag: '🇱🇰', type: 'country', latMin: 5.92, latMax: 9.84, lonMin: 79.64, lonMax: 81.89 },
  { name: 'sudan', display: 'Sudan', flag: '🇸🇩', type: 'country', latMin: 8.68, latMax: 23.15, lonMin: 21.83, lonMax: 38.61 },
  { name: 'sweden', display: 'Sweden', flag: '🇸🇪', type: 'country', latMin: 55.34, latMax: 69.06, lonMin: 10.96, lonMax: 24.16 },
  { name: 'switzerland', display: 'Switzerland', flag: '🇨🇭', type: 'country', latMin: 45.82, latMax: 47.81, lonMin: 5.96, lonMax: 10.49 },
  { name: 'syria', display: 'Syria', flag: '🇸🇾', type: 'country', latMin: 32.31, latMax: 37.33, lonMin: 35.73, lonMax: 42.38 },
  { name: 'taiwan', display: 'Taiwan', flag: '🇹🇼', type: 'country', latMin: 21.89, latMax: 25.30, lonMin: 120.11, lonMax: 121.95 },
  { name: 'tajikistan', display: 'Tajikistan', flag: '🇹🇯', type: 'country', latMin: 36.67, latMax: 41.04, lonMin: 67.34, lonMax: 75.16 },
  { name: 'tanzania', display: 'Tanzania', flag: '🇹🇿', type: 'country', latMin: -11.74, latMax: -0.99, lonMin: 29.34, lonMax: 40.44 },
  { name: 'thailand', display: 'Thailand', flag: '🇹🇭', type: 'country', latMin: 5.61, latMax: 20.46, lonMin: 97.35, lonMax: 105.64 },
  { name: 'togo', display: 'Togo', flag: '🇹🇬', type: 'country', latMin: 6.10, latMax: 11.13, lonMin: -0.15, lonMax: 1.81 },
  { name: 'tunisia', display: 'Tunisia', flag: '🇹🇳', type: 'country', latMin: 30.24, latMax: 37.55, lonMin: 7.52, lonMax: 11.59 },
  { name: 'turkey', display: 'Turkey', flag: '🇹🇷', type: 'country', latMin: 35.82, latMax: 42.11, lonMin: 25.67, lonMax: 44.82 },
  { name: 'turkmenistan', display: 'Turkmenistan', flag: '🇹🇲', type: 'country', latMin: 35.14, latMax: 42.79, lonMin: 52.44, lonMax: 66.69 },
  { name: 'uganda', display: 'Uganda', flag: '🇺🇬', type: 'country', latMin: -1.48, latMax: 4.23, lonMin: 29.57, lonMax: 35.04 },
  { name: 'ukraine', display: 'Ukraine', flag: '🇺🇦', type: 'country', latMin: 44.39, latMax: 52.38, lonMin: 22.14, lonMax: 40.23 },
  { name: 'united arab emirates', display: 'United Arab Emirates', flag: '🇦🇪', type: 'country', latMin: 22.63, latMax: 26.09, lonMin: 51.58, lonMax: 56.40 },
  { name: 'uae', display: 'United Arab Emirates', flag: '🇦🇪', type: 'country', latMin: 22.63, latMax: 26.09, lonMin: 51.58, lonMax: 56.40 },
  { name: 'united kingdom', display: 'United Kingdom', flag: '🇬🇧', type: 'country', latMin: 49.67, latMax: 60.86, lonMin: -8.65, lonMax: 1.76 },
  { name: 'uk', display: 'United Kingdom', flag: '🇬🇧', type: 'country', latMin: 49.67, latMax: 60.86, lonMin: -8.65, lonMax: 1.76 },
  { name: 'united states', display: 'United States', flag: '🇺🇸', type: 'country', latMin: 24.52, latMax: 49.38, lonMin: -124.77, lonMax: -66.95 },
  { name: 'usa', display: 'United States', flag: '🇺🇸', type: 'country', latMin: 24.52, latMax: 49.38, lonMin: -124.77, lonMax: -66.95 },
  { name: 'uruguay', display: 'Uruguay', flag: '🇺🇾', type: 'country', latMin: -34.95, latMax: -30.11, lonMin: -58.44, lonMax: -53.11 },
  { name: 'uzbekistan', display: 'Uzbekistan', flag: '🇺🇿', type: 'country', latMin: 37.19, latMax: 45.59, lonMin: 55.99, lonMax: 73.14 },
  { name: 'venezuela', display: 'Venezuela', flag: '🇻🇪', type: 'country', latMin: 0.65, latMax: 12.20, lonMin: -73.35, lonMax: -59.81 },
  { name: 'vietnam', display: 'Vietnam', flag: '🇻🇳', type: 'country', latMin: 8.56, latMax: 23.39, lonMin: 102.14, lonMax: 109.46 },
  { name: 'yemen', display: 'Yemen', flag: '🇾🇪', type: 'country', latMin: 12.11, latMax: 19.00, lonMin: 42.55, lonMax: 53.11 },
  { name: 'zambia', display: 'Zambia', flag: '🇿🇲', type: 'country', latMin: -18.08, latMax: -8.22, lonMin: 21.97, lonMax: 33.71 },
  { name: 'zimbabwe', display: 'Zimbabwe', flag: '🇿🇼', type: 'country', latMin: -22.42, latMax: -15.61, lonMin: 25.24, lonMax: 33.07 },

  // ── US States ──────────────────────────────────────────────────────────────
  { name: 'alabama', display: 'Alabama', type: 'region', parent: 'United States', latMin: 30.14, latMax: 35.01, lonMin: -88.47, lonMax: -84.89 },
  { name: 'alaska', display: 'Alaska', type: 'region', parent: 'United States', latMin: 51.21, latMax: 71.35, lonMin: -179.15, lonMax: -129.97 },
  { name: 'arizona', display: 'Arizona', type: 'region', parent: 'United States', latMin: 31.33, latMax: 37.00, lonMin: -114.82, lonMax: -109.04 },
  { name: 'arkansas', display: 'Arkansas', type: 'region', parent: 'United States', latMin: 33.00, latMax: 36.50, lonMin: -94.62, lonMax: -89.64 },
  { name: 'california', display: 'California', type: 'region', parent: 'United States', latMin: 32.53, latMax: 42.01, lonMin: -124.41, lonMax: -114.13 },
  { name: 'colorado', display: 'Colorado', type: 'region', parent: 'United States', latMin: 36.99, latMax: 41.00, lonMin: -109.05, lonMax: -102.04 },
  { name: 'connecticut', display: 'Connecticut', type: 'region', parent: 'United States', latMin: 40.98, latMax: 42.05, lonMin: -73.73, lonMax: -71.79 },
  { name: 'florida', display: 'Florida', type: 'region', parent: 'United States', latMin: 24.54, latMax: 31.00, lonMin: -87.63, lonMax: -80.03 },
  { name: 'georgia usa', display: 'Georgia (US)', type: 'region', parent: 'United States', latMin: 30.36, latMax: 35.00, lonMin: -85.61, lonMax: -80.84 },
  { name: 'hawaii', display: 'Hawaii', type: 'region', parent: 'United States', latMin: 18.91, latMax: 22.24, lonMin: -160.25, lonMax: -154.81 },
  { name: 'idaho', display: 'Idaho', type: 'region', parent: 'United States', latMin: 41.99, latMax: 49.00, lonMin: -117.24, lonMax: -111.04 },
  { name: 'illinois', display: 'Illinois', type: 'region', parent: 'United States', latMin: 36.97, latMax: 42.51, lonMin: -91.51, lonMax: -87.02 },
  { name: 'indiana', display: 'Indiana', type: 'region', parent: 'United States', latMin: 37.77, latMax: 41.76, lonMin: -88.10, lonMax: -84.79 },
  { name: 'iowa', display: 'Iowa', type: 'region', parent: 'United States', latMin: 40.38, latMax: 43.50, lonMin: -96.64, lonMax: -90.14 },
  { name: 'kansas', display: 'Kansas', type: 'region', parent: 'United States', latMin: 36.99, latMax: 40.00, lonMin: -102.05, lonMax: -94.59 },
  { name: 'kentucky', display: 'Kentucky', type: 'region', parent: 'United States', latMin: 36.50, latMax: 39.15, lonMin: -89.57, lonMax: -81.96 },
  { name: 'louisiana', display: 'Louisiana', type: 'region', parent: 'United States', latMin: 28.93, latMax: 33.02, lonMin: -94.04, lonMax: -88.82 },
  { name: 'maine', display: 'Maine', type: 'region', parent: 'United States', latMin: 43.06, latMax: 47.46, lonMin: -71.08, lonMax: -66.95 },
  { name: 'maryland', display: 'Maryland', type: 'region', parent: 'United States', latMin: 37.91, latMax: 39.72, lonMin: -79.49, lonMax: -75.05 },
  { name: 'massachusetts', display: 'Massachusetts', type: 'region', parent: 'United States', latMin: 41.24, latMax: 42.89, lonMin: -73.51, lonMax: -69.93 },
  { name: 'michigan', display: 'Michigan', type: 'region', parent: 'United States', latMin: 41.70, latMax: 48.31, lonMin: -90.42, lonMax: -82.41 },
  { name: 'minnesota', display: 'Minnesota', type: 'region', parent: 'United States', latMin: 43.50, latMax: 49.38, lonMin: -97.24, lonMax: -89.49 },
  { name: 'mississippi', display: 'Mississippi', type: 'region', parent: 'United States', latMin: 30.17, latMax: 35.01, lonMin: -91.65, lonMax: -88.10 },
  { name: 'missouri', display: 'Missouri', type: 'region', parent: 'United States', latMin: 35.99, latMax: 40.61, lonMin: -95.77, lonMax: -89.10 },
  { name: 'montana', display: 'Montana', type: 'region', parent: 'United States', latMin: 44.36, latMax: 49.00, lonMin: -116.05, lonMax: -104.04 },
  { name: 'nebraska', display: 'Nebraska', type: 'region', parent: 'United States', latMin: 40.00, latMax: 43.00, lonMin: -104.05, lonMax: -95.31 },
  { name: 'nevada', display: 'Nevada', type: 'region', parent: 'United States', latMin: 35.00, latMax: 42.00, lonMin: -120.00, lonMax: -114.03 },
  { name: 'new hampshire', display: 'New Hampshire', type: 'region', parent: 'United States', latMin: 42.70, latMax: 45.31, lonMin: -72.56, lonMax: -70.61 },
  { name: 'new jersey', display: 'New Jersey', type: 'region', parent: 'United States', latMin: 38.93, latMax: 41.36, lonMin: -75.56, lonMax: -73.89 },
  { name: 'new mexico', display: 'New Mexico', type: 'region', parent: 'United States', latMin: 31.33, latMax: 37.00, lonMin: -109.05, lonMax: -103.00 },
  { name: 'new york', display: 'New York', type: 'region', parent: 'United States', latMin: 40.50, latMax: 45.01, lonMin: -79.76, lonMax: -71.86 },
  { name: 'north carolina', display: 'North Carolina', type: 'region', parent: 'United States', latMin: 33.84, latMax: 36.59, lonMin: -84.32, lonMax: -75.46 },
  { name: 'north dakota', display: 'North Dakota', type: 'region', parent: 'United States', latMin: 45.94, latMax: 49.00, lonMin: -104.05, lonMax: -96.56 },
  { name: 'ohio', display: 'Ohio', type: 'region', parent: 'United States', latMin: 38.40, latMax: 42.32, lonMin: -84.82, lonMax: -80.52 },
  { name: 'oklahoma', display: 'Oklahoma', type: 'region', parent: 'United States', latMin: 33.62, latMax: 37.00, lonMin: -103.00, lonMax: -94.43 },
  { name: 'oregon', display: 'Oregon', type: 'region', parent: 'United States', latMin: 41.99, latMax: 46.26, lonMin: -124.57, lonMax: -116.46 },
  { name: 'pennsylvania', display: 'Pennsylvania', type: 'region', parent: 'United States', latMin: 39.72, latMax: 42.51, lonMin: -80.52, lonMax: -74.69 },
  { name: 'rhode island', display: 'Rhode Island', type: 'region', parent: 'United States', latMin: 41.15, latMax: 42.02, lonMin: -71.86, lonMax: -71.12 },
  { name: 'south carolina', display: 'South Carolina', type: 'region', parent: 'United States', latMin: 32.04, latMax: 35.22, lonMin: -83.36, lonMax: -78.54 },
  { name: 'south dakota', display: 'South Dakota', type: 'region', parent: 'United States', latMin: 42.48, latMax: 45.94, lonMin: -104.06, lonMax: -96.44 },
  { name: 'tennessee', display: 'Tennessee', type: 'region', parent: 'United States', latMin: 34.98, latMax: 36.68, lonMin: -90.31, lonMax: -81.65 },
  { name: 'texas', display: 'Texas', type: 'region', parent: 'United States', latMin: 25.84, latMax: 36.50, lonMin: -106.65, lonMax: -93.51 },
  { name: 'utah', display: 'Utah', type: 'region', parent: 'United States', latMin: 36.99, latMax: 42.00, lonMin: -114.05, lonMax: -109.04 },
  { name: 'vermont', display: 'Vermont', type: 'region', parent: 'United States', latMin: 42.73, latMax: 45.02, lonMin: -73.43, lonMax: -71.47 },
  { name: 'virginia', display: 'Virginia', type: 'region', parent: 'United States', latMin: 36.54, latMax: 39.47, lonMin: -83.68, lonMax: -75.24 },
  { name: 'washington', display: 'Washington', type: 'region', parent: 'United States', latMin: 45.54, latMax: 49.00, lonMin: -124.73, lonMax: -116.92 },
  { name: 'west virginia', display: 'West Virginia', type: 'region', parent: 'United States', latMin: 37.20, latMax: 40.64, lonMin: -82.64, lonMax: -77.72 },
  { name: 'wisconsin', display: 'Wisconsin', type: 'region', parent: 'United States', latMin: 42.49, latMax: 47.08, lonMin: -92.89, lonMax: -86.25 },
  { name: 'wyoming', display: 'Wyoming', type: 'region', parent: 'United States', latMin: 40.99, latMax: 45.01, lonMin: -111.06, lonMax: -104.05 },

  // ── German Länder ──────────────────────────────────────────────────────────
  { name: 'bavaria', display: 'Bavaria', type: 'region', parent: 'Germany', latMin: 47.27, latMax: 50.56, lonMin: 9.73, lonMax: 13.84 },
  { name: 'baden-württemberg', display: 'Baden-Württemberg', type: 'region', parent: 'Germany', latMin: 47.53, latMax: 49.79, lonMin: 7.51, lonMax: 10.50 },
  { name: 'berlin', display: 'Berlin', type: 'region', parent: 'Germany', latMin: 52.34, latMax: 52.68, lonMin: 13.09, lonMax: 13.76 },
  { name: 'brandenburg', display: 'Brandenburg', type: 'region', parent: 'Germany', latMin: 51.36, latMax: 53.56, lonMin: 11.27, lonMax: 14.77 },
  { name: 'bremen', display: 'Bremen', type: 'region', parent: 'Germany', latMin: 53.01, latMax: 53.23, lonMin: 8.48, lonMax: 8.99 },
  { name: 'hamburg', display: 'Hamburg', type: 'region', parent: 'Germany', latMin: 53.39, latMax: 53.96, lonMin: 8.42, lonMax: 10.33 },
  { name: 'hesse', display: 'Hesse', type: 'region', parent: 'Germany', latMin: 49.40, latMax: 51.66, lonMin: 7.77, lonMax: 10.24 },
  { name: 'lower saxony', display: 'Lower Saxony', type: 'region', parent: 'Germany', latMin: 51.30, latMax: 53.89, lonMin: 6.65, lonMax: 11.60 },
  { name: 'mecklenburg-vorpommern', display: 'Mecklenburg-Vorpommern', type: 'region', parent: 'Germany', latMin: 53.11, latMax: 54.68, lonMin: 10.59, lonMax: 14.41 },
  { name: 'north rhine-westphalia', display: 'North Rhine-Westphalia', type: 'region', parent: 'Germany', latMin: 50.32, latMax: 52.53, lonMin: 5.87, lonMax: 9.46 },
  { name: 'rhineland-palatinate', display: 'Rhineland-Palatinate', type: 'region', parent: 'Germany', latMin: 48.97, latMax: 50.94, lonMin: 6.11, lonMax: 8.51 },
  { name: 'saarland', display: 'Saarland', type: 'region', parent: 'Germany', latMin: 49.11, latMax: 49.64, lonMin: 6.36, lonMax: 7.40 },
  { name: 'saxony', display: 'Saxony', type: 'region', parent: 'Germany', latMin: 50.17, latMax: 51.68, lonMin: 11.88, lonMax: 15.04 },
  { name: 'saxony-anhalt', display: 'Saxony-Anhalt', type: 'region', parent: 'Germany', latMin: 50.94, latMax: 53.06, lonMin: 10.56, lonMax: 13.19 },
  { name: 'schleswig-holstein', display: 'Schleswig-Holstein', type: 'region', parent: 'Germany', latMin: 53.36, latMax: 55.07, lonMin: 8.00, lonMax: 11.31 },
  { name: 'thuringia', display: 'Thuringia', type: 'region', parent: 'Germany', latMin: 50.20, latMax: 51.65, lonMin: 9.87, lonMax: 12.65 },

  // ── French Régions ─────────────────────────────────────────────────────────
  { name: 'auvergne-rhône-alpes', display: 'Auvergne-Rhône-Alpes', type: 'region', parent: 'France', latMin: 44.12, latMax: 46.81, lonMin: 2.07, lonMax: 7.18 },
  { name: 'bourgogne-franche-comté', display: 'Bourgogne-Franche-Comté', type: 'region', parent: 'France', latMin: 46.16, latMax: 48.40, lonMin: 2.84, lonMax: 7.08 },
  { name: 'brittany', display: 'Brittany', type: 'region', parent: 'France', latMin: 47.28, latMax: 48.90, lonMin: -5.15, lonMax: -1.02 },
  { name: 'centre-val de loire', display: 'Centre-Val de Loire', type: 'region', parent: 'France', latMin: 46.35, latMax: 48.94, lonMin: 0.05, lonMax: 3.13 },
  { name: 'corsica', display: 'Corsica', type: 'region', parent: 'France', latMin: 41.33, latMax: 43.03, lonMin: 8.54, lonMax: 9.57 },
  { name: 'grand est', display: 'Grand Est', type: 'region', parent: 'France', latMin: 47.41, latMax: 49.84, lonMin: 4.05, lonMax: 8.24 },
  { name: 'hauts-de-france', display: 'Hauts-de-France', type: 'region', parent: 'France', latMin: 49.97, latMax: 51.09, lonMin: 1.45, lonMax: 4.24 },
  { name: 'île-de-france', display: 'Île-de-France', type: 'region', parent: 'France', latMin: 48.12, latMax: 49.24, lonMin: 1.45, lonMax: 3.56 },
  { name: 'normandy', display: 'Normandy', type: 'region', parent: 'France', latMin: 48.12, latMax: 50.06, lonMin: -1.93, lonMax: 2.21 },
  { name: 'nouvelle-aquitaine', display: 'Nouvelle-Aquitaine', type: 'region', parent: 'France', latMin: 42.77, latMax: 47.96, lonMin: -4.79, lonMax: 2.88 },
  { name: 'occitanie', display: 'Occitanie', type: 'region', parent: 'France', latMin: 42.33, latMax: 45.05, lonMin: -0.33, lonMax: 4.84 },
  { name: 'pays de la loire', display: 'Pays de la Loire', type: 'region', parent: 'France', latMin: 46.27, latMax: 48.55, lonMin: -2.55, lonMax: 0.91 },
  { name: "provence-alpes-côte d'azur", display: "Provence-Alpes-Côte d'Azur", type: 'region', parent: 'France', latMin: 43.16, latMax: 45.14, lonMin: 4.23, lonMax: 7.72 },

  // ── Spanish Communities ────────────────────────────────────────────────────
  { name: 'andalusia', display: 'Andalusia', type: 'region', parent: 'Spain', latMin: 36.00, latMax: 38.74, lonMin: -7.52, lonMax: -1.63 },
  { name: 'catalonia', display: 'Catalonia', type: 'region', parent: 'Spain', latMin: 40.52, latMax: 42.87, lonMin: 0.16, lonMax: 3.33 },
  { name: 'madrid', display: 'Madrid (region)', type: 'region', parent: 'Spain', latMin: 39.88, latMax: 41.17, lonMin: -4.58, lonMax: -3.05 },
  { name: 'basque country', display: 'Basque Country', type: 'region', parent: 'Spain', latMin: 42.46, latMax: 43.45, lonMin: -3.45, lonMax: -1.72 },
  { name: 'valencia', display: 'Valencia', type: 'region', parent: 'Spain', latMin: 37.84, latMax: 40.79, lonMin: -1.53, lonMax: 0.53 },

  // ── Italian Regions ────────────────────────────────────────────────────────
  { name: 'lombardy', display: 'Lombardy', type: 'region', parent: 'Italy', latMin: 44.68, latMax: 46.64, lonMin: 8.50, lonMax: 11.36 },
  { name: 'tuscany', display: 'Tuscany', type: 'region', parent: 'Italy', latMin: 42.37, latMax: 44.47, lonMin: 9.69, lonMax: 12.37 },
  { name: 'sicily', display: 'Sicily', type: 'region', parent: 'Italy', latMin: 36.65, latMax: 38.33, lonMin: 12.43, lonMax: 15.65 },
  { name: 'lazio', display: 'Lazio', type: 'region', parent: 'Italy', latMin: 41.17, latMax: 42.84, lonMin: 11.45, lonMax: 14.03 },
  { name: 'veneto', display: 'Veneto', type: 'region', parent: 'Italy', latMin: 44.80, latMax: 46.68, lonMin: 10.62, lonMax: 13.08 },
  { name: 'sardinia', display: 'Sardinia', type: 'region', parent: 'Italy', latMin: 38.86, latMax: 41.26, lonMin: 8.13, lonMax: 9.83 },

  // ── UK Countries ───────────────────────────────────────────────────────────
  { name: 'england', display: 'England', type: 'region', parent: 'United Kingdom', latMin: 49.89, latMax: 55.81, lonMin: -5.73, lonMax: 1.77 },
  { name: 'scotland', display: 'Scotland', type: 'region', parent: 'United Kingdom', latMin: 54.63, latMax: 60.86, lonMin: -7.58, lonMax: -0.73 },
  { name: 'wales', display: 'Wales', type: 'region', parent: 'United Kingdom', latMin: 51.34, latMax: 53.43, lonMin: -5.35, lonMax: -2.65 },
  { name: 'northern ireland', display: 'Northern Ireland', type: 'region', parent: 'United Kingdom', latMin: 54.01, latMax: 55.31, lonMin: -8.18, lonMax: -5.43 },

  // ── Australian States ──────────────────────────────────────────────────────
  { name: 'new south wales', display: 'New South Wales', type: 'region', parent: 'Australia', latMin: -37.51, latMax: -28.16, lonMin: 140.99, lonMax: 153.64 },
  { name: 'victoria australia', display: 'Victoria (AU)', type: 'region', parent: 'Australia', latMin: -39.16, latMax: -33.98, lonMin: 140.96, lonMax: 149.98 },
  { name: 'queensland', display: 'Queensland', type: 'region', parent: 'Australia', latMin: -29.18, latMax: -10.67, lonMin: 138.00, lonMax: 153.55 },
  { name: 'western australia', display: 'Western Australia', type: 'region', parent: 'Australia', latMin: -35.13, latMax: -13.69, lonMin: 112.92, lonMax: 129.00 },
  { name: 'south australia', display: 'South Australia', type: 'region', parent: 'Australia', latMin: -38.06, latMax: -25.98, lonMin: 129.00, lonMax: 141.00 },

  // ── Canadian Provinces ─────────────────────────────────────────────────────
  { name: 'ontario', display: 'Ontario', type: 'region', parent: 'Canada', latMin: 41.68, latMax: 56.85, lonMin: -95.16, lonMax: -74.35 },
  { name: 'quebec', display: 'Québec', type: 'region', parent: 'Canada', latMin: 44.99, latMax: 62.58, lonMin: -79.76, lonMax: -57.11 },
  { name: 'british columbia', display: 'British Columbia', type: 'region', parent: 'Canada', latMin: 48.30, latMax: 60.00, lonMin: -139.07, lonMax: -114.03 },
  { name: 'alberta', display: 'Alberta', type: 'region', parent: 'Canada', latMin: 49.00, latMax: 60.00, lonMin: -120.00, lonMax: -110.01 },

  // ── Cities ─────────────────────────────────────────────────────────────────
  { name: 'new york city', display: 'New York City', type: 'city', parent: 'United States', latMin: 40.48, latMax: 40.92, lonMin: -74.26, lonMax: -73.70 },
  { name: 'los angeles', display: 'Los Angeles', type: 'city', parent: 'United States', latMin: 33.70, latMax: 34.34, lonMin: -118.67, lonMax: -117.91 },
  { name: 'chicago', display: 'Chicago', type: 'city', parent: 'United States', latMin: 41.64, latMax: 42.02, lonMin: -87.94, lonMax: -87.52 },
  { name: 'houston', display: 'Houston', type: 'city', parent: 'United States', latMin: 29.52, latMax: 30.11, lonMin: -95.79, lonMax: -95.01 },
  { name: 'miami', display: 'Miami', type: 'city', parent: 'United States', latMin: 25.59, latMax: 25.86, lonMin: -80.45, lonMax: -80.14 },
  { name: 'san francisco', display: 'San Francisco', type: 'city', parent: 'United States', latMin: 37.63, latMax: 37.93, lonMin: -122.54, lonMax: -122.33 },
  { name: 'seattle', display: 'Seattle', type: 'city', parent: 'United States', latMin: 47.49, latMax: 47.73, lonMin: -122.44, lonMax: -122.24 },
  { name: 'las vegas', display: 'Las Vegas', type: 'city', parent: 'United States', latMin: 35.94, latMax: 36.29, lonMin: -115.38, lonMax: -114.95 },
  { name: 'boston', display: 'Boston', type: 'city', parent: 'United States', latMin: 42.23, latMax: 42.40, lonMin: -71.19, lonMax: -70.99 },
  { name: 'washington dc', display: 'Washington D.C.', type: 'city', parent: 'United States', latMin: 38.79, latMax: 38.99, lonMin: -77.12, lonMax: -76.91 },
  { name: 'denver', display: 'Denver', type: 'city', parent: 'United States', latMin: 39.61, latMax: 39.91, lonMin: -105.11, lonMax: -104.60 },
  { name: 'phoenix', display: 'Phoenix', type: 'city', parent: 'United States', latMin: 33.28, latMax: 33.82, lonMin: -112.32, lonMax: -111.93 },
  { name: 'london', display: 'London', type: 'city', parent: 'United Kingdom', latMin: 51.28, latMax: 51.69, lonMin: -0.51, lonMax: 0.33 },
  { name: 'manchester', display: 'Manchester', type: 'city', parent: 'United Kingdom', latMin: 53.35, latMax: 53.55, lonMin: -2.34, lonMax: -2.14 },
  { name: 'edinburgh', display: 'Edinburgh', type: 'city', parent: 'United Kingdom', latMin: 55.87, latMax: 55.99, lonMin: -3.35, lonMax: -3.10 },
  { name: 'paris', display: 'Paris', type: 'city', parent: 'France', latMin: 48.82, latMax: 48.90, lonMin: 2.25, lonMax: 2.42 },
  { name: 'lyon', display: 'Lyon', type: 'city', parent: 'France', latMin: 45.71, latMax: 45.81, lonMin: 4.77, lonMax: 4.90 },
  { name: 'marseille', display: 'Marseille', type: 'city', parent: 'France', latMin: 43.17, latMax: 43.39, lonMin: 5.22, lonMax: 5.53 },
  { name: 'nice', display: 'Nice', type: 'city', parent: 'France', latMin: 43.65, latMax: 43.74, lonMin: 7.19, lonMax: 7.30 },
  { name: 'berlin', display: 'Berlin', type: 'city', parent: 'Germany', latMin: 52.34, latMax: 52.68, lonMin: 13.09, lonMax: 13.76 },
  { name: 'munich', display: 'Munich', type: 'city', parent: 'Germany', latMin: 47.97, latMax: 48.24, lonMin: 11.36, lonMax: 11.72 },
  { name: 'hamburg city', display: 'Hamburg', type: 'city', parent: 'Germany', latMin: 53.39, latMax: 53.74, lonMin: 9.73, lonMax: 10.33 },
  { name: 'frankfurt', display: 'Frankfurt', type: 'city', parent: 'Germany', latMin: 50.02, latMax: 50.23, lonMin: 8.47, lonMax: 8.80 },
  { name: 'cologne', display: 'Cologne', type: 'city', parent: 'Germany', latMin: 50.83, latMax: 51.08, lonMin: 6.77, lonMax: 7.16 },
  { name: 'düsseldorf', display: 'Düsseldorf', type: 'city', parent: 'Germany', latMin: 51.12, latMax: 51.37, lonMin: 6.69, lonMax: 6.94 },
  { name: 'stuttgart', display: 'Stuttgart', type: 'city', parent: 'Germany', latMin: 48.69, latMax: 48.87, lonMin: 9.04, lonMax: 9.31 },
  { name: 'rome', display: 'Rome', type: 'city', parent: 'Italy', latMin: 41.79, latMax: 42.01, lonMin: 12.35, lonMax: 12.64 },
  { name: 'milan', display: 'Milan', type: 'city', parent: 'Italy', latMin: 45.40, latMax: 45.54, lonMin: 9.07, lonMax: 9.28 },
  { name: 'naples', display: 'Naples', type: 'city', parent: 'Italy', latMin: 40.79, latMax: 40.92, lonMin: 14.17, lonMax: 14.35 },
  { name: 'venice', display: 'Venice', type: 'city', parent: 'Italy', latMin: 45.39, latMax: 45.51, lonMin: 12.19, lonMax: 12.43 },
  { name: 'florence', display: 'Florence', type: 'city', parent: 'Italy', latMin: 43.72, latMax: 43.84, lonMin: 11.19, lonMax: 11.33 },
  { name: 'madrid city', display: 'Madrid', type: 'city', parent: 'Spain', latMin: 40.31, latMax: 40.56, lonMin: -3.84, lonMax: -3.52 },
  { name: 'barcelona', display: 'Barcelona', type: 'city', parent: 'Spain', latMin: 41.32, latMax: 41.47, lonMin: 2.07, lonMax: 2.23 },
  { name: 'seville', display: 'Seville', type: 'city', parent: 'Spain', latMin: 37.30, latMax: 37.44, lonMin: -6.04, lonMax: -5.89 },
  { name: 'amsterdam', display: 'Amsterdam', type: 'city', parent: 'Netherlands', latMin: 52.28, latMax: 52.43, lonMin: 4.73, lonMax: 5.08 },
  { name: 'rotterdam', display: 'Rotterdam', type: 'city', parent: 'Netherlands', latMin: 51.87, latMax: 51.97, lonMin: 4.40, lonMax: 4.60 },
  { name: 'brussels', display: 'Brussels', type: 'city', parent: 'Belgium', latMin: 50.78, latMax: 50.92, lonMin: 4.29, lonMax: 4.45 },
  { name: 'zurich', display: 'Zurich', type: 'city', parent: 'Switzerland', latMin: 47.32, latMax: 47.43, lonMin: 8.46, lonMax: 8.62 },
  { name: 'geneva', display: 'Geneva', type: 'city', parent: 'Switzerland', latMin: 46.17, latMax: 46.26, lonMin: 6.07, lonMax: 6.21 },
  { name: 'vienna', display: 'Vienna', type: 'city', parent: 'Austria', latMin: 48.12, latMax: 48.32, lonMin: 16.18, lonMax: 16.58 },
  { name: 'prague', display: 'Prague', type: 'city', parent: 'Czechia', latMin: 49.94, latMax: 50.18, lonMin: 14.22, lonMax: 14.71 },
  { name: 'warsaw', display: 'Warsaw', type: 'city', parent: 'Poland', latMin: 52.10, latMax: 52.37, lonMin: 20.85, lonMax: 21.27 },
  { name: 'budapest', display: 'Budapest', type: 'city', parent: 'Hungary', latMin: 47.35, latMax: 47.61, lonMin: 18.91, lonMax: 19.33 },
  { name: 'stockholm', display: 'Stockholm', type: 'city', parent: 'Sweden', latMin: 59.26, latMax: 59.44, lonMin: 17.75, lonMax: 18.30 },
  { name: 'oslo', display: 'Oslo', type: 'city', parent: 'Norway', latMin: 59.81, latMax: 60.01, lonMin: 10.49, lonMax: 10.94 },
  { name: 'copenhagen', display: 'Copenhagen', type: 'city', parent: 'Denmark', latMin: 55.58, latMax: 55.76, lonMin: 12.45, lonMax: 12.69 },
  { name: 'helsinki', display: 'Helsinki', type: 'city', parent: 'Finland', latMin: 60.12, latMax: 60.30, lonMin: 24.78, lonMax: 25.25 },
  { name: 'athens', display: 'Athens', type: 'city', parent: 'Greece', latMin: 37.89, latMax: 38.08, lonMin: 23.63, lonMax: 23.84 },
  { name: 'lisbon', display: 'Lisbon', type: 'city', parent: 'Portugal', latMin: 38.66, latMax: 38.80, lonMin: -9.23, lonMax: -9.09 },
  { name: 'moscow', display: 'Moscow', type: 'city', parent: 'Russia', latMin: 55.49, latMax: 56.01, lonMin: 37.18, lonMax: 37.97 },
  { name: 'saint petersburg', display: 'Saint Petersburg', type: 'city', parent: 'Russia', latMin: 59.77, latMax: 60.09, lonMin: 30.10, lonMax: 30.57 },
  { name: 'istanbul', display: 'Istanbul', type: 'city', parent: 'Turkey', latMin: 40.80, latMax: 41.32, lonMin: 28.60, lonMax: 29.45 },
  { name: 'ankara', display: 'Ankara', type: 'city', parent: 'Turkey', latMin: 39.76, latMax: 40.00, lonMin: 32.63, lonMax: 32.98 },
  { name: 'dubai', display: 'Dubai', type: 'city', parent: 'United Arab Emirates', latMin: 24.79, latMax: 25.36, lonMin: 54.89, lonMax: 55.57 },
  { name: 'abu dhabi', display: 'Abu Dhabi', type: 'city', parent: 'United Arab Emirates', latMin: 24.36, latMax: 24.56, lonMin: 54.33, lonMax: 54.56 },
  { name: 'tokyo', display: 'Tokyo', type: 'city', parent: 'Japan', latMin: 35.53, latMax: 35.82, lonMin: 139.53, lonMax: 139.92 },
  { name: 'osaka', display: 'Osaka', type: 'city', parent: 'Japan', latMin: 34.57, latMax: 34.74, lonMin: 135.44, lonMax: 135.62 },
  { name: 'kyoto', display: 'Kyoto', type: 'city', parent: 'Japan', latMin: 34.91, latMax: 35.14, lonMin: 135.65, lonMax: 135.84 },
  { name: 'beijing', display: 'Beijing', type: 'city', parent: 'China', latMin: 39.44, latMax: 41.06, lonMin: 115.42, lonMax: 117.51 },
  { name: 'shanghai', display: 'Shanghai', type: 'city', parent: 'China', latMin: 30.70, latMax: 31.53, lonMin: 120.85, lonMax: 121.98 },
  { name: 'hong kong', display: 'Hong Kong', type: 'city', parent: 'China', latMin: 22.15, latMax: 22.56, lonMin: 113.84, lonMax: 114.44 },
  { name: 'seoul', display: 'Seoul', type: 'city', parent: 'South Korea', latMin: 37.43, latMax: 37.70, lonMin: 126.76, lonMax: 127.18 },
  { name: 'singapore city', display: 'Singapore', type: 'city', parent: 'Singapore', latMin: 1.16, latMax: 1.47, lonMin: 103.60, lonMax: 104.09 },
  { name: 'bangkok', display: 'Bangkok', type: 'city', parent: 'Thailand', latMin: 13.49, latMax: 13.95, lonMin: 100.33, lonMax: 100.95 },
  { name: 'jakarta', display: 'Jakarta', type: 'city', parent: 'Indonesia', latMin: -6.37, latMax: -6.07, lonMin: 106.69, lonMax: 107.01 },
  { name: 'kuala lumpur', display: 'Kuala Lumpur', type: 'city', parent: 'Malaysia', latMin: 2.97, latMax: 3.28, lonMin: 101.59, lonMax: 101.84 },
  { name: 'mumbai', display: 'Mumbai', type: 'city', parent: 'India', latMin: 18.89, latMax: 19.27, lonMin: 72.77, lonMax: 72.99 },
  { name: 'delhi', display: 'Delhi', type: 'city', parent: 'India', latMin: 28.40, latMax: 28.88, lonMin: 76.84, lonMax: 77.35 },
  { name: 'bangalore', display: 'Bangalore', type: 'city', parent: 'India', latMin: 12.83, latMax: 13.14, lonMin: 77.46, lonMax: 77.75 },
  { name: 'cairo', display: 'Cairo', type: 'city', parent: 'Egypt', latMin: 29.85, latMax: 30.25, lonMin: 31.13, lonMax: 31.50 },
  { name: 'cape town', display: 'Cape Town', type: 'city', parent: 'South Africa', latMin: -34.36, latMax: -33.73, lonMin: 18.33, lonMax: 18.74 },
  { name: 'johannesburg', display: 'Johannesburg', type: 'city', parent: 'South Africa', latMin: -26.36, latMax: -26.07, lonMin: 27.83, lonMax: 28.16 },
  { name: 'nairobi', display: 'Nairobi', type: 'city', parent: 'Kenya', latMin: -1.40, latMax: -1.15, lonMin: 36.70, lonMax: 37.10 },
  { name: 'lagos', display: 'Lagos', type: 'city', parent: 'Nigeria', latMin: 6.39, latMax: 6.70, lonMin: 3.13, lonMax: 3.55 },
  { name: 'casablanca', display: 'Casablanca', type: 'city', parent: 'Morocco', latMin: 33.49, latMax: 33.64, lonMin: -7.68, lonMax: -7.54 },
  { name: 'sydney', display: 'Sydney', type: 'city', parent: 'Australia', latMin: -34.17, latMax: -33.58, lonMin: 150.52, lonMax: 151.34 },
  { name: 'melbourne', display: 'Melbourne', type: 'city', parent: 'Australia', latMin: -38.17, latMax: -37.64, lonMin: 144.59, lonMax: 145.35 },
  { name: 'toronto', display: 'Toronto', type: 'city', parent: 'Canada', latMin: 43.58, latMax: 43.86, lonMin: -79.64, lonMax: -79.12 },
  { name: 'vancouver', display: 'Vancouver', type: 'city', parent: 'Canada', latMin: 49.20, latMax: 49.32, lonMin: -123.22, lonMax: -123.02 },
  { name: 'montreal', display: 'Montréal', type: 'city', parent: 'Canada', latMin: 45.41, latMax: 45.70, lonMin: -73.98, lonMax: -73.48 },
  { name: 'sao paulo', display: 'São Paulo', type: 'city', parent: 'Brazil', latMin: -23.77, latMax: -23.36, lonMin: -46.83, lonMax: -46.37 },
  { name: 'rio de janeiro', display: 'Rio de Janeiro', type: 'city', parent: 'Brazil', latMin: -23.08, latMax: -22.74, lonMin: -43.79, lonMax: -43.10 },
  { name: 'buenos aires', display: 'Buenos Aires', type: 'city', parent: 'Argentina', latMin: -34.71, latMax: -34.52, lonMin: -58.53, lonMax: -58.34 },
  { name: 'bogota', display: 'Bogotá', type: 'city', parent: 'Colombia', latMin: 4.45, latMax: 4.83, lonMin: -74.24, lonMax: -73.99 },
  { name: 'lima', display: 'Lima', type: 'city', parent: 'Peru', latMin: -12.22, latMax: -11.95, lonMin: -77.18, lonMax: -76.92 },
  { name: 'mexico city', display: 'Mexico City', type: 'city', parent: 'Mexico', latMin: 19.05, latMax: 19.59, lonMin: -99.37, lonMax: -98.94 },
  { name: 'tehran', display: 'Tehran', type: 'city', parent: 'Iran', latMin: 35.57, latMax: 35.82, lonMin: 51.12, lonMax: 51.61 },
  { name: 'tel aviv', display: 'Tel Aviv', type: 'city', parent: 'Israel', latMin: 31.99, latMax: 32.16, lonMin: 34.73, lonMax: 34.91 },
  { name: 'jerusalem', display: 'Jerusalem', type: 'city', parent: 'Israel', latMin: 31.73, latMax: 31.83, lonMin: 35.15, lonMax: 35.26 },
  { name: 'riyadh', display: 'Riyadh', type: 'city', parent: 'Saudi Arabia', latMin: 24.53, latMax: 24.84, lonMin: 46.57, lonMax: 46.90 },
  { name: 'doha', display: 'Doha', type: 'city', parent: 'Qatar', latMin: 25.23, latMax: 25.38, lonMin: 51.46, lonMax: 51.60 },
  { name: 'karachi', display: 'Karachi', type: 'city', parent: 'Pakistan', latMin: 24.78, latMax: 25.07, lonMin: 66.97, lonMax: 67.25 },
  { name: 'dhaka', display: 'Dhaka', type: 'city', parent: 'Bangladesh', latMin: 23.67, latMax: 23.87, lonMin: 90.32, lonMax: 90.53 },
  { name: 'kathmandu', display: 'Kathmandu', type: 'city', parent: 'Nepal', latMin: 27.63, latMax: 27.79, lonMin: 85.25, lonMax: 85.42 },
  { name: 'colombo', display: 'Colombo', type: 'city', parent: 'Sri Lanka', latMin: 6.83, latMax: 6.98, lonMin: 79.82, lonMax: 80.00 },
  { name: 'yangon', display: 'Yangon', type: 'city', parent: 'Myanmar', latMin: 16.72, latMax: 16.98, lonMin: 96.03, lonMax: 96.26 },
  { name: 'hanoi', display: 'Hanoi', type: 'city', parent: 'Vietnam', latMin: 20.93, latMax: 21.10, lonMin: 105.73, lonMax: 105.95 },
  { name: 'ho chi minh city', display: 'Ho Chi Minh City', type: 'city', parent: 'Vietnam', latMin: 10.62, latMax: 10.89, lonMin: 106.59, lonMax: 106.82 },
  { name: 'manila', display: 'Manila', type: 'city', parent: 'Philippines', latMin: 14.48, latMax: 14.68, lonMin: 120.96, lonMax: 121.10 },
  { name: 'taipei', display: 'Taipei', type: 'city', parent: 'Taiwan', latMin: 24.97, latMax: 25.13, lonMin: 121.46, lonMax: 121.60 },
  { name: 'ulaanbaatar', display: 'Ulaanbaatar', type: 'city', parent: 'Mongolia', latMin: 47.83, latMax: 47.99, lonMin: 106.66, lonMax: 107.05 },
  { name: 'phnom penh', display: 'Phnom Penh', type: 'city', parent: 'Cambodia', latMin: 11.50, latMax: 11.63, lonMin: 104.84, lonMax: 105.02 },
  { name: 'reykjavik', display: 'Reykjavik', type: 'city', parent: 'Iceland', latMin: 63.99, latMax: 64.19, lonMin: -22.06, lonMax: -21.79 },
  { name: 'riga', display: 'Riga', type: 'city', parent: 'Latvia', latMin: 56.88, latMax: 57.03, lonMin: 23.97, lonMax: 24.27 },
  { name: 'tallinn', display: 'Tallinn', type: 'city', parent: 'Estonia', latMin: 59.35, latMax: 59.50, lonMin: 24.56, lonMax: 24.87 },
  { name: 'vilnius', display: 'Vilnius', type: 'city', parent: 'Lithuania', latMin: 54.62, latMax: 54.76, lonMin: 25.12, lonMax: 25.35 },
  { name: 'kyiv', display: 'Kyiv', type: 'city', parent: 'Ukraine', latMin: 50.21, latMax: 50.59, lonMin: 30.24, lonMax: 30.82 },
  { name: 'minsk', display: 'Minsk', type: 'city', parent: 'Belarus', latMin: 53.81, latMax: 53.97, lonMin: 27.39, lonMax: 27.67 },
  { name: 'bucharest', display: 'Bucharest', type: 'city', parent: 'Romania', latMin: 44.36, latMax: 44.55, lonMin: 25.95, lonMax: 26.26 },
  { name: 'sofia', display: 'Sofia', type: 'city', parent: 'Bulgaria', latMin: 42.61, latMax: 42.77, lonMin: 23.22, lonMax: 23.44 },
  { name: 'belgrade', display: 'Belgrade', type: 'city', parent: 'Serbia', latMin: 44.69, latMax: 44.90, lonMin: 20.39, lonMax: 20.57 },
  { name: 'zagreb', display: 'Zagreb', type: 'city', parent: 'Croatia', latMin: 45.71, latMax: 45.86, lonMin: 15.86, lonMax: 16.09 },
  { name: 'ljubljana', display: 'Ljubljana', type: 'city', parent: 'Slovenia', latMin: 46.01, latMax: 46.10, lonMin: 14.44, lonMax: 14.58 },
  { name: 'bratislava', display: 'Bratislava', type: 'city', parent: 'Slovakia', latMin: 48.07, latMax: 48.20, lonMin: 16.99, lonMax: 17.21 },
  { name: 'tbilisi', display: 'Tbilisi', type: 'city', parent: 'Georgia', latMin: 41.61, latMax: 41.76, lonMin: 44.72, lonMax: 44.90 },
  { name: 'yerevan', display: 'Yerevan', type: 'city', parent: 'Armenia', latMin: 40.11, latMax: 40.22, lonMin: 44.44, lonMax: 44.60 },
  { name: 'baku', display: 'Baku', type: 'city', parent: 'Azerbaijan', latMin: 40.32, latMax: 40.44, lonMin: 49.77, lonMax: 49.96 },
  { name: 'tashkent', display: 'Tashkent', type: 'city', parent: 'Uzbekistan', latMin: 41.22, latMax: 41.39, lonMin: 69.15, lonMax: 69.40 },
  { name: 'almaty', display: 'Almaty', type: 'city', parent: 'Kazakhstan', latMin: 43.12, latMax: 43.35, lonMin: 76.76, lonMax: 77.08 },
  { name: 'accra', display: 'Accra', type: 'city', parent: 'Ghana', latMin: 5.52, latMax: 5.66, lonMin: -0.28, lonMax: -0.12 },
  { name: 'addis ababa', display: 'Addis Ababa', type: 'city', parent: 'Ethiopia', latMin: 8.91, latMax: 9.07, lonMin: 38.70, lonMax: 38.84 },
  { name: 'dar es salaam', display: 'Dar es Salaam', type: 'city', parent: 'Tanzania', latMin: -6.95, latMax: -6.74, lonMin: 39.17, lonMax: 39.35 },
  { name: 'tunis', display: 'Tunis', type: 'city', parent: 'Tunisia', latMin: 36.73, latMax: 36.87, lonMin: 10.11, lonMax: 10.26 },
  { name: 'algiers', display: 'Algiers', type: 'city', parent: 'Algeria', latMin: 36.67, latMax: 36.82, lonMin: 2.97, lonMax: 3.12 },
  { name: 'auckland', display: 'Auckland', type: 'city', parent: 'New Zealand', latMin: -37.06, latMax: -36.70, lonMin: 174.62, lonMax: 175.00 },
];

/** Search places by name (case-insensitive substring match). Returns top results. */
export function searchIn(dataset: PlaceBounds[], query: string, limit = 8): PlaceBounds[] {
  if (!query.trim()) return [];
  const q = query.toLowerCase().trim();
  const scored = dataset
    .filter(p => p.name.includes(q) || p.display.toLowerCase().includes(q))
    .map(p => {
      let score = 0;
      if (p.name === q || p.display.toLowerCase() === q) score += 100;
      else if (p.name.startsWith(q) || p.display.toLowerCase().startsWith(q)) score += 50;
      if (p.type === 'country') score += 10;
      else if (p.type === 'region') score += 5;
      return { place: p, score };
    })
    .sort((a, b) => b.score - a.score)
    .map(s => s.place);

  const seen = new Set<string>();
  const unique: PlaceBounds[] = [];
  for (const p of scored) {
    const key = p.display + p.type;
    if (!seen.has(key)) {
      seen.add(key);
      unique.push(p);
    }
  }
  return unique.slice(0, limit);
}

export function searchPlaces(query: string, limit = 8): PlaceBounds[] {
  if (!query.trim()) return [];
  const q = query.toLowerCase().trim();
  const scored = PLACE_BOUNDS
    .filter(p => p.name.includes(q) || p.display.toLowerCase().includes(q))
    .map(p => {
      let score = 0;
      if (p.name === q || p.display.toLowerCase() === q) score += 100;
      else if (p.name.startsWith(q) || p.display.toLowerCase().startsWith(q)) score += 50;
      // Countries rank higher than regions, regions higher than cities for same score
      if (p.type === 'country') score += 10;
      else if (p.type === 'region') score += 5;
      return { place: p, score };
    })
    .sort((a, b) => b.score - a.score)
    .map(s => s.place);

  // Deduplicate by display name (e.g. uk/united kingdom both point to same bounds)
  const seen = new Set<string>();
  const unique: PlaceBounds[] = [];
  for (const p of scored) {
    const key = p.display + p.type;
    if (!seen.has(key)) {
      seen.add(key);
      unique.push(p);
    }
  }
  return unique.slice(0, limit);
}
