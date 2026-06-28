export type Category = 'web' | 'crypto' | 'pwn' | 'rev' | 'gobl1n' | 'jaka';
export type InstanceStatus = 'stopped' | 'starting' | 'running' | 'error';

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
  id: string;
  category: Category;
  name: string;
  difficulty: string;
  points: number;
  description: string;
  connection_info: string;
  solved: boolean;
  instance_status: InstanceStatus;
}

export interface InstanceOut {
  challenge_id: string;
  status: InstanceStatus;
  message?: string;
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
  last_solve: string | null;
}

export interface ScoreboardResponse {
  entries: ScoreboardEntry[];
}
