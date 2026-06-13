// Manejo de la sesion en el cliente.
// Para el MVP guardamos el JWT en localStorage (aceptable segun el contrato).
// Si en el futuro se migra a cookie httpOnly, solo cambia este modulo.

const TOKEN_KEY = 'ctf.token';
const TEAM_KEY = 'ctf.team_id';
const NAME_KEY = 'ctf.display_name';

export interface Session {
  token: string;
  teamId: string;
  displayName: string;
}

export function saveSession(s: Session): void {
  if (typeof window === 'undefined') return;
  localStorage.setItem(TOKEN_KEY, s.token);
  localStorage.setItem(TEAM_KEY, s.teamId);
  localStorage.setItem(NAME_KEY, s.displayName);
}

export function getToken(): string | null {
  if (typeof window === 'undefined') return null;
  return localStorage.getItem(TOKEN_KEY);
}

export function getSession(): Session | null {
  if (typeof window === 'undefined') return null;
  const token = localStorage.getItem(TOKEN_KEY);
  const teamId = localStorage.getItem(TEAM_KEY);
  const displayName = localStorage.getItem(NAME_KEY);
  if (!token || !teamId) return null;
  return { token, teamId, displayName: displayName ?? teamId };
}

export function clearSession(): void {
  if (typeof window === 'undefined') return;
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(TEAM_KEY);
  localStorage.removeItem(NAME_KEY);
}
