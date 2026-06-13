'use client';

// Provee la sesion verificada contra /auth/me a las paginas protegidas.
// Si no hay token o /auth/me falla con 401 -> redirige a /login.
// Si 403 (ban/VPN) -> el cliente api ya redirige a /blocked.

import { createContext, useContext, useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { api, ApiError } from '@/lib/api';
import { clearSession, getSession, type Session } from '@/lib/storage';
import { Spinner } from './Spinner';

interface SessionState extends Session {
  logout: () => Promise<void>;
}

const SessionContext = createContext<SessionState | null>(null);

export function useSession(): SessionState {
  const ctx = useContext(SessionContext);
  if (!ctx) throw new Error('useSession debe usarse dentro de <SessionProvider>');
  return ctx;
}

export function SessionProvider({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const [session, setSession] = useState<Session | null>(null);
  const [checking, setChecking] = useState(true);

  useEffect(() => {
    const local = getSession();
    if (!local) {
      router.replace('/login');
      return;
    }

    // Verifica la sesion realmente con el backend.
    let alive = true;
    api
      .me()
      .then((me) => {
        if (!alive) return;
        setSession({ token: local.token, teamId: me.team_id, displayName: me.display_name });
        setChecking(false);
      })
      .catch((err) => {
        // 401/403 ya disparan redireccion en el cliente api.
        // Cualquier otro error: limpiamos y vamos a login por seguridad.
        if (!(err instanceof ApiError) || (err.status !== 401 && err.status !== 403)) {
          clearSession();
          router.replace('/login');
        }
      });

    return () => {
      alive = false;
    };
  }, [router]);

  async function logout() {
    try {
      await api.logout();
    } catch {
      // Aunque falle el backend, cerramos sesion localmente.
    } finally {
      clearSession();
      router.replace('/login');
    }
  }

  if (checking || !session) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <Spinner label="Verificando sesión…" />
      </div>
    );
  }

  return (
    <SessionContext.Provider value={{ ...session, logout }}>{children}</SessionContext.Provider>
  );
}
