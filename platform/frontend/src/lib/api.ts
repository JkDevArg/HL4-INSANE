// Cliente API central del CTF.
// - Adjunta el Bearer en cada request autenticado.
// - Normaliza errores HTTP en una clase ApiError con el status.
// - Maneja 401 (sesion invalida -> redirige a /login) y
//   403 de ban/VPN (redirige a la pantalla de bloqueo).
//
// Base configurable por NEXT_PUBLIC_API_BASE (default "/api"); un nginx
// hace proxy de /api -> platform-api:8000.

import { clearSession, getToken } from './storage';
import type {
  Challenge,
  MeResponse,
  ScoreboardResponse,
  SubmitResponse,
  TokenResponse,
} from './types';

export const API_BASE = process.env.NEXT_PUBLIC_API_BASE || '/api';

/** Error de API con el codigo HTTP y un mensaje ya legible para el usuario. */
export class ApiError extends Error {
  status: number;
  /** payload crudo del backend (por si se necesita el detail). */
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
  /** Si true, adjunta el Bearer guardado. */
  auth?: boolean;
  /** Si false, NO redirige ante 401 (lo maneja la pagina, p.ej. /login). */
  redirectOn401?: boolean;
  /** Si false, NO redirige ante 403 (p.ej. submit: 403 = flag de otro equipo, no ban). */
  redirectOn403?: boolean;
}

function redirect(path: string) {
  if (typeof window !== 'undefined' && window.location.pathname !== path) {
    window.location.href = path;
  }
}

/**
 * Extrae un mensaje legible del cuerpo de error.
 * FastAPI devuelve {detail: "..."} o {detail: [{msg}]}.
 */
async function parseError(res: Response): Promise<{ message: string; payload: unknown }> {
  let payload: unknown = null;
  let message = '';
  try {
    payload = await res.json();
    const detail = (payload as { detail?: unknown })?.detail;
    if (typeof detail === 'string') message = detail;
    else if (Array.isArray(detail) && detail.length && typeof detail[0]?.msg === 'string')
      message = detail[0].msg;
  } catch {
    // cuerpo no-JSON; se usara el mensaje por defecto del status mas abajo.
  }
  return { message, payload };
}

async function request<T>(path: string, opts: RequestOptions = {}): Promise<T> {
  const {
    method = 'GET',
    body,
    auth = true,
    redirectOn401 = true,
    redirectOn403 = true,
  } = opts;

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
    // Fallo de red: tipico cuando NO estas conectado a la VPN del CTF.
    throw new ApiError(
      0,
      'No se pudo contactar la plataforma. Verifica tu conexion a la VPN del CTF.',
    );
  }

  // 204 No Content (p.ej. logout).
  if (res.status === 204) return undefined as T;

  if (!res.ok) {
    const { message, payload } = await parseError(res);

    // Manejo centralizado de errores de sesion.
    if (res.status === 401 && redirectOn401) {
      clearSession();
      redirect('/login');
    } else if (res.status === 403 && redirectOn403) {
      // Equipo baneado o fuera de VPN: pantalla de bloqueo.
      redirect('/blocked');
    }

    throw new ApiError(res.status, message || defaultMessage(res.status), payload);
  }

  return (await res.json()) as T;
}

/** Mensajes por defecto en español si el backend no aporta detail. */
function defaultMessage(status: number): string {
  switch (status) {
    case 400:
      return 'Solicitud invalida.';
    case 401:
      return 'Credenciales invalidas o sesion expirada.';
    case 403:
      return 'Acceso denegado: fuera de la VPN o equipo baneado.';
    case 404:
      return 'Recurso no encontrado.';
    case 429:
      return 'Demasiadas solicitudes. Espera un momento e intenta de nuevo.';
    default:
      return `Error del servidor (${status}).`;
  }
}

// ---------------------------------------------------------------------------
// Endpoints del contrato
// ---------------------------------------------------------------------------

export const api = {
  /** POST /auth/login — NO redirige en error: la pagina /login muestra el mensaje. */
  login(username: string, password: string): Promise<TokenResponse> {
    return request<TokenResponse>('/auth/login', {
      method: 'POST',
      body: { username, password },
      auth: false,
      redirectOn401: false,
      redirectOn403: false,
    });
  },

  /** GET /auth/me */
  me(): Promise<MeResponse> {
    return request<MeResponse>('/auth/me');
  },

  /** POST /auth/logout -> 204 */
  logout(): Promise<void> {
    return request<void>('/auth/logout', { method: 'POST' });
  },

  /** GET /challenges */
  challenges(): Promise<Challenge[]> {
    return request<Challenge[]>('/challenges');
  },

  /** POST /challenges/{id}/submit */
  submit(id: string, flag: string): Promise<SubmitResponse> {
    return request<SubmitResponse>(`/challenges/${encodeURIComponent(id)}/submit`, {
      method: 'POST',
      body: { flag },
      // El 403 aqui NO es ban: es "flag de otro equipo" (incidente). Lo maneja la card.
      // Un 401 si redirige (sesion expirada).
      redirectOn403: false,
    });
  },

  /** GET /scoreboard */
  scoreboard(): Promise<ScoreboardResponse> {
    return request<ScoreboardResponse>('/scoreboard');
  },
};
