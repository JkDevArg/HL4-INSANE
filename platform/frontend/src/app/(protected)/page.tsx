'use client';

// Pagina principal: retos agrupados por categoria (web / api / crypto).
// Muestra puntaje total del equipo (suma de retos resueltos) y refresca al resolver.

import { useCallback, useEffect, useMemo, useState } from 'react';
import { api, ApiError } from '@/lib/api';
import type { Category, Challenge } from '@/lib/types';
import { ChallengeCard } from '@/components/ChallengeCard';
import { Spinner } from '@/components/Spinner';

// Orden de presentacion de las categorias.
const CATEGORY_ORDER: Category[] = ['web', 'api', 'crypto'];
const CATEGORY_LABEL: Record<Category, string> = {
  web: 'Web',
  api: 'API',
  crypto: 'Crypto',
};

export default function ChallengesPage() {
  const [challenges, setChallenges] = useState<Challenge[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const data = await api.challenges();
      setChallenges(data);
      setError(null);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'No se pudieron cargar los retos.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  // Al resolver: marcamos localmente como solved y recargamos desde el backend
  // para tener el estado autoritativo (puntos, etc.).
  const handleSolved = useCallback(
    (id: string) => {
      setChallenges((prev) => prev.map((c) => (c.id === id ? { ...c, solved: true } : c)));
      load();
    },
    [load],
  );

  // Puntaje total = suma de puntos de retos resueltos.
  const { totalPoints, solvedCount } = useMemo(() => {
    const solved = challenges.filter((c) => c.solved);
    return {
      totalPoints: solved.reduce((acc, c) => acc + c.points, 0),
      solvedCount: solved.length,
    };
  }, [challenges]);

  // Agrupa por categoria respetando el orden definido.
  const grouped = useMemo(() => {
    const map = new Map<Category, Challenge[]>();
    for (const c of challenges) {
      const list = map.get(c.category) ?? [];
      list.push(c);
      map.set(c.category, list);
    }
    return map;
  }, [challenges]);

  if (loading) {
    return (
      <div className="flex justify-center py-16">
        <Spinner label="Cargando retos…" />
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-8">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="font-mono text-2xl font-bold text-neon">Retos</h1>
          <p className="mt-1 text-sm text-muted">
            Cada reto es una instancia exclusiva de tu equipo. Las flags son únicas.
          </p>
        </div>
        <div className="rounded-lg border border-neon/40 bg-neon/5 px-4 py-2 text-right shadow-neon">
          <div className="font-mono text-[10px] uppercase tracking-widest text-muted">
            puntaje del equipo
          </div>
          <div className="font-mono text-2xl font-bold text-neon">{totalPoints}</div>
          <div className="font-mono text-[11px] text-muted">
            {solvedCount}/{challenges.length} resueltos
          </div>
        </div>
      </div>

      {error && (
        <p className="rounded-md border border-danger/50 bg-danger/10 px-4 py-3 font-mono text-sm text-danger">
          {error}
        </p>
      )}

      {!error && challenges.length === 0 && (
        <p className="font-mono text-sm text-muted">No hay retos disponibles por ahora.</p>
      )}

      {CATEGORY_ORDER.filter((cat) => grouped.has(cat)).map((cat) => {
        const items = grouped.get(cat)!;
        const solved = items.filter((c) => c.solved).length;
        return (
          <section key={cat} aria-labelledby={`cat-${cat}`}>
            <div className="mb-3 flex items-center gap-3 border-b border-line pb-2">
              <h2 id={`cat-${cat}`} className="font-mono text-lg font-semibold text-neon-cyan">
                {CATEGORY_LABEL[cat]}
              </h2>
              <span className="font-mono text-xs text-muted">
                {solved}/{items.length}
              </span>
            </div>
            <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
              {items.map((c) => (
                <ChallengeCard key={c.id} challenge={c} onSolved={handleSolved} />
              ))}
            </div>
          </section>
        );
      })}
    </div>
  );
}
