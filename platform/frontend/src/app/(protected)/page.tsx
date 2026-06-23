'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { api, ApiError } from '@/lib/api';
import type { Category, Challenge, InstanceStatus } from '@/lib/types';
import { ChallengeCard } from '@/components/ChallengeCard';
import { Spinner } from '@/components/Spinner';

const CATEGORY_ORDER: Category[] = ['web', 'crypto', 'pwn', 'rev'];
const CATEGORY_LABEL: Record<Category, string> = {
  web: 'Web',
  crypto: 'Crypto',
  pwn: 'Pwn',
  rev: 'Reversing',
};

const POLL_INTERVAL_MS = 6000;

export default function ChallengesPage() {
  const [challenges, setChallenges] = useState<Challenge[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  // Local override map: challengeId → status (merges on top of backend data)
  const [instanceOverrides, setInstanceOverrides] = useState<Record<string, InstanceStatus>>({});
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

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

  // Merge backend instance_status with local overrides
  const challengesWithStatus = useMemo(
    () =>
      challenges.map((c) => ({
        ...c,
        instance_status: instanceOverrides[c.id] ?? c.instance_status,
      })),
    [challenges, instanceOverrides],
  );

  // IDs of challenges currently "starting" — poll until they transition
  const startingIds = useMemo(
    () => challengesWithStatus.filter((c) => c.instance_status === 'starting').map((c) => c.id),
    [challengesWithStatus],
  );

  useEffect(() => {
    if (startingIds.length === 0) {
      if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
      return;
    }
    if (pollRef.current) return;

    pollRef.current = setInterval(async () => {
      const updates: Record<string, InstanceStatus> = {};
      await Promise.allSettled(
        startingIds.map(async (id) => {
          try {
            const res = await api.instanceStatus(id);
            updates[id] = res.status;
          } catch { /* keep current */ }
        }),
      );
      if (Object.keys(updates).length > 0) {
        setInstanceOverrides((prev) => ({ ...prev, ...updates }));
      }
    }, POLL_INTERVAL_MS);

    return () => {
      if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
    };
  }, [startingIds]);

  const handleSolved = useCallback(
    (id: string) => {
      setChallenges((prev) => prev.map((c) => (c.id === id ? { ...c, solved: true } : c)));
      load();
    },
    [load],
  );

  const handleInstanceChange = useCallback((id: string, status: InstanceStatus) => {
    setInstanceOverrides((prev) => ({ ...prev, [id]: status }));
  }, []);

  const { totalPoints, solvedCount } = useMemo(() => {
    const solved = challengesWithStatus.filter((c) => c.solved);
    return {
      totalPoints: solved.reduce((acc, c) => acc + c.points, 0),
      solvedCount: solved.length,
    };
  }, [challengesWithStatus]);

  const grouped = useMemo(() => {
    const map = new Map<Category, Challenge[]>();
    for (const c of challengesWithStatus) {
      const list = map.get(c.category) ?? [];
      list.push(c);
      map.set(c.category, list);
    }
    return map;
  }, [challengesWithStatus]);

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
            {solvedCount}/{challengesWithStatus.length} resueltos
          </div>
        </div>
      </div>

      {error && (
        <p className="rounded-md border border-danger/50 bg-danger/10 px-4 py-3 font-mono text-sm text-danger">
          {error}
        </p>
      )}

      {!error && challengesWithStatus.length === 0 && (
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
                <ChallengeCard
                  key={c.id}
                  challenge={c}
                  onSolved={handleSolved}
                  onInstanceChange={handleInstanceChange}
                />
              ))}
            </div>
          </section>
        );
      })}
    </div>
  );
}
