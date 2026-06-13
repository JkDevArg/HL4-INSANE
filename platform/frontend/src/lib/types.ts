// Tipos que reflejan EXACTAMENTE el contrato de la platform-api.
// Ver docs/ARCHITECTURE.md y backend/app/schemas.py.

export type Category = 'web' | 'api' | 'crypto';

export interface TokenResponse {
  access_token: string;
  token_type: 'bearer';
  team_id: string;
  display_name: string;
}

export interface MeResponse {
  team_id: string;
  display_name: string;
}

export interface Challenge {
  id: string; // p.ej. web-supply-01
  category: Category;
  name: string;
  difficulty: string; // siempre "insane" en este evento
  points: number;
  description: string;
  connection_info: string; // host:puerto de la instancia del equipo
  solved: boolean;
}

export interface SubmitResponse {
  correct: boolean;
  already_solved: boolean;
  points_awarded: number;
  message: string;
}

export interface ScoreboardEntry {
  rank: number;
  team_id: string;
  display_name: string;
  points: number;
  solves: number;
  last_solve: string | null; // ISO datetime
}

export interface ScoreboardResponse {
  entries: ScoreboardEntry[];
}
