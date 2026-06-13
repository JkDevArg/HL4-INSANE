'use client';

// Scoreboard: ranking de equipos. Resalta la fila del equipo propio.
import { useCallback, useEffect, useState } from 'react';
import { api, ApiError } from '@/lib/api';
import type { ScoreboardEntry } from '@/lib/types';
import { useSession } from '@/components/SessionProvider';
import { Spinner } from '@/components/Spinner';

// Formatea el datetime ISO a hora local de Peru (es-PE).
function formatLastSolve(iso: string | null): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toLocaleString('es-PE', {
    day: '2-digit',
    month: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  });
}

// Medalla para el top 3.
function rankBadge(rank: number): string {
  if (rank === 1) return '🥇';
  if (rank === 2) return '🥈';
  if (rank === 3) return '🥉';
  return `#${rank}`;
}

export default function ScoreboardPage() {
  const { teamId } = useSession();
  const [entries, setEntries] = useState<ScoreboardEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const data = await api.scoreboard();
      setEntries(data.entries);
      setError(null);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'No se pudo cargar el scoreboard.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
    // Refresco periodico ligero para ver movimientos en vivo.
    const t = setInterval(load, 30_000);
    return () => clearInterval(t);
  }, [load]);

  if (loading) {
    return (
      <div className="flex justify-center py-16">
        <Spinner label="Cargando scoreboard…" />
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="font-mono text-2xl font-bold text-neon">Scoreboard</h1>
        <p className="mt-1 text-sm text-muted">
          Empates se desempatan por el último solve más temprano. Se actualiza cada 30s.
        </p>
      </div>

      {error && (
        <p className="rounded-md border border-danger/50 bg-danger/10 px-4 py-3 font-mono text-sm text-danger">
          {error}
        </p>
      )}

      <div className="overflow-x-auto rounded-lg border border-line bg-bg-panel">
        <table className="w-full border-collapse text-left">
          <thead>
            <tr className="border-b border-line font-mono text-[11px] uppercase tracking-widest text-muted">
              <th className="px-4 py-3">Rank</th>
              <th className="px-4 py-3">Equipo</th>
              <th className="px-4 py-3 text-right">Puntos</th>
              <th className="px-4 py-3 text-right">Solves</th>
              <th className="px-4 py-3 text-right">Último solve</th>
            </tr>
          </thead>
          <tbody>
            {entries.map((e) => {
              const isMine = e.team_id === teamId;
              return (
                <tr
                  key={e.team_id}
                  aria-current={isMine ? 'true' : undefined}
                  className={`border-b border-line/60 font-mono text-sm transition ${
                    isMine
                      ? 'bg-neon/10 text-neon shadow-[inset_3px_0_0_0_#39ff14]'
                      : 'text-[#c2d4cc] hover:bg-bg-elevated'
                  }`}
                >
                  <td className="px-4 py-3 font-bold">{rankBadge(e.rank)}</td>
                  <td className="px-4 py-3">
                    <span className="font-semibold">{e.display_name}</span>
                    {isMine && (
                      <span className="ml-2 rounded border border-neon/50 px-1.5 py-0.5 text-[10px] uppercase tracking-widest text-neon">
                        tú
                      </span>
                    )}
                    <span className="ml-2 text-[11px] text-muted">{e.team_id}</span>
                  </td>
                  <td className="px-4 py-3 text-right font-bold text-neon-cyan">{e.points}</td>
                  <td className="px-4 py-3 text-right">{e.solves}</td>
                  <td className="px-4 py-3 text-right text-muted">{formatLastSolve(e.last_solve)}</td>
                </tr>
              );
            })}
            {entries.length === 0 && !error && (
              <tr>
                <td colSpan={5} className="px-4 py-8 text-center font-mono text-sm text-muted">
                  Aún no hay puntajes registrados.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
