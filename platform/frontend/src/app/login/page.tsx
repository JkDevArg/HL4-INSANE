'use client';

// Login del CTF. Maneja explicitamente los codigos del contrato:
//  401 -> credenciales invalidas
//  403 -> fuera de VPN o equipo baneado
//  429 -> mas de 4 sesiones activas
import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { api, ApiError } from '@/lib/api';
import { getSession, saveSession } from '@/lib/storage';

export default function LoginPage() {
  const router = useRouter();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Si ya hay sesion local, salta directo a los retos.
  useEffect(() => {
    if (getSession()) router.replace('/');
  }, [router]);

  // Traduce el codigo HTTP a un mensaje claro en español.
  function messageFor(err: ApiError): string {
    switch (err.status) {
      case 401:
        return 'Usuario o contraseña incorrectos.';
      case 403:
        return (
          err.message ||
          'Acceso denegado: debes estar conectado a la VPN del CTF y tu equipo no debe estar baneado.'
        );
      case 429:
        return 'Límite de sesiones alcanzado (máx. 4 por equipo). Cierra alguna sesión activa e intenta de nuevo.';
      case 0:
        return err.message; // fallo de red / sin VPN
      default:
        return err.message || 'No se pudo iniciar sesión. Intenta nuevamente.';
    }
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (submitting) return;
    setError(null);
    setSubmitting(true);
    try {
      const res = await api.login(username.trim(), password);
      saveSession({
        token: res.access_token,
        teamId: res.team_id,
        displayName: res.display_name,
      });
      router.replace('/');
    } catch (err) {
      setError(err instanceof ApiError ? messageFor(err) : 'Error inesperado. Intenta de nuevo.');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <main className="flex min-h-screen items-center justify-center px-4 py-10">
      <div className="w-full max-w-md">
        <div className="mb-6 text-center">
          <div className="font-mono text-3xl font-bold tracking-tight text-neon">
            <span className="text-neon-cyan">&gt;_</span> CTF HACKL4BS
          </div>
          <p className="mt-2 font-mono text-sm text-muted">Plataforma de retos — HackL4bs</p>
        </div>

        {/* Banner VPN obligatorio */}
        <div className="mb-4 rounded-md border border-neon-cyan/40 bg-neon-cyan/5 px-4 py-3 text-center font-mono text-xs text-neon-cyan">
          Acceso exclusivo vía VPN del CTF. Sin VPN, la plataforma no es alcanzable.
        </div>

        <form onSubmit={handleSubmit} className="card flex flex-col gap-4">
          <div className="flex flex-col gap-1.5">
            <label htmlFor="username" className="font-mono text-xs uppercase tracking-widest text-muted">
              Usuario del equipo
            </label>
            <input
              id="username"
              name="username"
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="input-term"
              placeholder="team_03"
              autoComplete="username"
              autoCapitalize="none"
              spellCheck={false}
              required
            />
          </div>

          <div className="flex flex-col gap-1.5">
            <label htmlFor="password" className="font-mono text-xs uppercase tracking-widest text-muted">
              Contraseña
            </label>
            <input
              id="password"
              name="password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="input-term"
              placeholder="••••••••"
              autoComplete="current-password"
              required
            />
          </div>

          {error && (
            <p
              role="alert"
              className="rounded-md border border-danger/50 bg-danger/10 px-3 py-2 font-mono text-xs text-danger"
            >
              {error}
            </p>
          )}

          <button type="submit" className="btn-neon w-full" disabled={submitting}>
            {submitting ? 'Verificando…' : 'Iniciar sesión'}
          </button>
        </form>

        <p className="mt-6 text-center font-mono text-[11px] text-muted">
          Una credencial por equipo. Compartir flags se detecta y se reporta.
        </p>
      </div>
    </main>
  );
}
