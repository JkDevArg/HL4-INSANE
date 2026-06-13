'use client';

// Pantalla de bloqueo: se llega aqui ante un 403 del backend.
// Significa que el equipo esta baneado o que la conexion no proviene de la VPN.
import Link from 'next/link';
import { clearSession } from '@/lib/storage';
import { useEffect } from 'react';

export default function BlockedPage() {
  // Al caer aqui la sesion deja de ser confiable; la limpiamos.
  useEffect(() => {
    clearSession();
  }, []);

  return (
    <main className="flex min-h-screen items-center justify-center px-4 py-10">
      <div className="w-full max-w-lg text-center">
        <div className="mb-4 font-mono text-6xl text-danger">⛔</div>
        <h1 className="font-mono text-2xl font-bold text-danger">Acceso bloqueado</h1>
        <div className="card mt-6 text-left">
          <p className="text-sm leading-relaxed text-[#c2d4cc]">
            El servidor rechazó la petición (HTTP 403). Esto ocurre por una de estas razones:
          </p>
          <ul className="mt-3 list-inside list-disc space-y-1.5 font-mono text-sm text-muted">
            <li>
              <span className="text-neon-cyan">Fuera de la VPN:</span> tu conexión no proviene del
              túnel del CTF.
            </li>
            <li>
              <span className="text-danger">Equipo baneado:</span> tu equipo fue suspendido (p. ej.
              por desconexiones repetidas o anti-cheat).
            </li>
          </ul>
          <p className="mt-4 text-sm leading-relaxed text-[#c2d4cc]">
            Verifica que la VPN del CTF esté activa. Si crees que es un error, contacta al jurado.
          </p>
        </div>
        <Link href="/login" className="btn-ghost mt-6 inline-flex">
          Volver al inicio de sesión
        </Link>
      </div>
    </main>
  );
}
