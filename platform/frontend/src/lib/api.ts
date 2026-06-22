import { clearSession, getToken } from './storage';
import type {
  Challenge,
  InstanceOut,
  MeResponse,
  ScoreboardResponse,
  SubmitResponse,
  TokenResponse,
} from './types';

export const API_BASE = process.env.NEXT_PUBLIC_API_BASE || '/api';

export class ApiError extends Error {
  status: number;
  payload: unknown;
  constructor(status: number, message: string, payload?: unknown) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.payload = payload;
  }
}

interface RequestOptions {
  method?: 'GET' | 'POST';
  body?: unknown;
  auth?: boolean;
  redirectOn401?: boolean;
  redirectOn403?: boolean;
}

function redirect(path: string) {
  if (typeof window !== 'undefined' && window.location.pathname !== path) {
    window.location.href = path;
  }
}

async function parseError(res: Response): Promise<{ message: string; payload: unknown }> {
  let payload: unknown = null;
  let message = '';
  try {
    payload = await res.json();
    const detail = (payload as { detail?: unknown })?.detail;
    if (typeof detail === 'string') message = detail;
    else if (Array.isArray(detail) && detail.length && typeof detail[0]?.msg === 'string')
      message = detail[0].msg;
  } catch { /* non-JSON */ }
  return { message, payload };
}

async function request<T>(path: string, opts: RequestOptions = {}): Promise<T> {
  const { method = 'GET', body, auth = true, redirectOn401 = true, redirectOn403 = true } = opts;

  const headers: Record<string, string> = {};
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (auth) {
    const token = getToken();
    if (token) headers['Authorization'] = `Bearer ${token}`;
  }

  let res: Response;
  try {
    res = await fetch(`${API_BASE}${path}`, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
      cache: 'no-store',
    });
  } catch {
    throw new ApiError(0, 'No se pudo contactar la plataforma. Verifica tu VPN.');
  }

  if (res.status === 204) return undefined as T;

  if (!res.ok) {
    const { message, payload } = await parseError(res);
    if (res.status === 401 && redirectOn401) { clearSession(); redirect('/login'); }
    else if (res.status === 403 && redirectOn403) { redirect('/blocked'); }
    throw new ApiError(res.status, message || defaultMessage(res.status), payload);
  }

  return (await res.json()) as T;
}

function defaultMessage(status: number): string {
  switch (status) {
    case 400: return 'Solicitud inválida.';
    case 401: return 'Credenciales inválidas o sesión expirada.';
    case 403: return 'Acceso denegado.';
    case 404: return 'Recurso no encontrado.';
    case 429: return 'Demasiadas solicitudes. Espera un momento.';
    default: return `Error del servidor (${status}).`;
  }
}

export const api = {
  login(username: string, password: string): Promise<TokenResponse> {
    return request<TokenResponse>('/auth/login', {
      method: 'POST', body: { username, password },
      auth: false, redirectOn401: false, redirectOn403: false,
    });
  },

  me(): Promise<MeResponse> {
    return request<MeResponse>('/auth/me');
  },

  logout(): Promise<void> {
    return request<void>('/auth/logout', { method: 'POST' });
  },

  challenges(): Promise<Challenge[]> {
    return request<Challenge[]>('/challenges');
  },

  submit(id: string, flag: string): Promise<SubmitResponse> {
    return request<SubmitResponse>(`/challenges/${encodeURIComponent(id)}/submit`, {
      method: 'POST', body: { flag }, redirectOn403: false,
    });
  },

  scoreboard(): Promise<ScoreboardResponse> {
    return request<ScoreboardResponse>('/scoreboard');
  },

  instanceStart(challengeId: string): Promise<InstanceOut> {
    return request<InstanceOut>(`/instances/${encodeURIComponent(challengeId)}/start`, {
      method: 'POST',
    });
  },

  instanceStop(challengeId: string): Promise<InstanceOut> {
    return request<InstanceOut>(`/instances/${encodeURIComponent(challengeId)}/stop`, {
      method: 'POST',
    });
  },

  instanceStatus(challengeId: string): Promise<InstanceOut> {
    return request<InstanceOut>(`/instances/${encodeURIComponent(challengeId)}/status`);
  },
};
