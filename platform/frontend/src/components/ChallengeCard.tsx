'use client';

// Card de un reto: metadatos, connection_info y formulario inline para enviar flag.
// Maneja todos los desenlaces del POST /challenges/{id}/submit:
//  - correct          -> exito, refresca estado
//  - already_solved   -> aviso neutro
//  - incorrect        -> error
//  - 403              -> "Incidente registrado" (flag de otro equipo)
//  - 404 / 429 / otros -> mensaje claro

import { useState } from 'react';
import { api, ApiError } from '@/lib/api';
import type { Challenge } from '@/lib/types';
import { CategoryBadge, DifficultyBadge } from './Badge';

type Feedback =
  | { kind: 'ok'; text: string }
  | { kind: 'info'; text: string }
  | { kind: 'error'; text: string }
  | { kind: 'incident'; text: string }
  | null;

const FEEDBACK_STYLE: Record<NonNullable<Feedback>['kind'], string> = {
  ok: 'border-neon/50 bg-neon/10 text-neon',
  info: 'border-neon-cyan/50 bg-neon-cyan/10 text-neon-cyan',
  error: 'border-danger/50 bg-danger/10 text-danger',
  incident: 'border-danger bg-danger/15 text-danger',
};

export function ChallengeCard({
  challenge,
  onSolved,
}: {
  challenge: Challenge;
  onSolved: (id: string) => void;
}) {
  const [flag, setFlag] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [feedback, setFeedback] = useState<Feedback>(null);
  const solved = challenge.solved;

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    const value = flag.trim();
    if (!value || submitting) return;

    setSubmitting(true);
    setFeedback(null);

    try {
      const res = await api.submit(challenge.id, value);
      if (res.correct) {
        setFeedback({
          kind: 'ok',
          text: res.message || `¡Correcto! +${res.points_awarded} pts`,
        });
        setFlag('');
        onSolved(challenge.id);
      } else if (res.already_solved) {
        setFeedback({ kind: 'info', text: res.message || 'Este reto ya estaba resuelto.' });
      } else {
        setFeedback({ kind: 'error', text: res.message || 'Flag incorrecta.' });
      }
    } catch (err) {
      if (err instanceof ApiError) {
        if (err.status === 403) {
          // Flag perteneciente a OTRO equipo: posible intento de trampa.
          setFeedback({
            kind: 'incident',
            text:
              '⚠ Incidente registrado: esa flag pertenece a otro equipo. ' +
              'Compartir flags se detecta y se reporta al jurado.',
          });
        } else if (err.status === 429) {
          setFeedback({
            kind: 'error',
            text: err.message || 'Demasiados intentos. Espera unos segundos.',
          });
        } else if (err.status === 404) {
          setFeedback({ kind: 'error', text: 'El reto ya no está disponible.' });
        } else {
          setFeedback({ kind: 'error', text: err.message });
        }
      } else {
        setFeedback({ kind: 'error', text: 'Error inesperado al enviar la flag.' });
      }
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <article
      className={`card flex flex-col gap-3 ${
        solved ? 'border-neon/40 shadow-neon' : 'hover:border-neon/30'
      }`}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <CategoryBadge category={challenge.category} />
          <DifficultyBadge difficulty={challenge.difficulty} />
        </div>
        <div className="flex items-center gap-2">
          <span className="font-mono text-sm font-bold text-neon-cyan">{challenge.points} pts</span>
          {solved && (
            <span
              className="flex items-center gap-1 font-mono text-xs font-bold text-neon"
              title="Resuelto"
            >
              <span aria-hidden>✓</span> resuelto
            </span>
          )}
        </div>
      </div>

      <div>
        <h3 className="font-mono text-base font-semibold text-neon">{challenge.name}</h3>
        <p className="mt-0.5 font-mono text-[11px] text-muted">{challenge.id}</p>
      </div>

      <p className="text-sm leading-relaxed text-[#c2d4cc]">{challenge.description}</p>

      {challenge.connection_info && (
        <div className="rounded-md border border-line bg-black/40 px-3 py-2">
          <span className="font-mono text-[10px] uppercase tracking-widest text-muted">
            conexión
          </span>
          <code className="mt-0.5 block select-all break-all font-mono text-sm text-neon-cyan">
            {challenge.connection_info}
          </code>
        </div>
      )}

      <form onSubmit={handleSubmit} className="mt-auto flex flex-col gap-2">
        <div className="flex gap-2">
          <input
            type="text"
            value={flag}
            onChange={(e) => setFlag(e.target.value)}
            placeholder={solved ? 'Reto resuelto' : 'flag{…}'}
            className="input-term"
            aria-label={`Flag para ${challenge.name}`}
            autoComplete="off"
            spellCheck={false}
            disabled={solved}
          />
          <button type="submit" className="btn-neon" disabled={solved || submitting || !flag.trim()}>
            {submitting ? '…' : 'Enviar'}
          </button>
        </div>

        {feedback && (
          <p
            role="status"
            className={`rounded-md border px-3 py-2 font-mono text-xs ${FEEDBACK_STYLE[feedback.kind]}`}
          >
            {feedback.text}
          </p>
        )}
      </form>
    </article>
  );
}
