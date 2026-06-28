'use client';

import { useState } from 'react';
import { api, ApiError } from '@/lib/api';
import type { Challenge, InstanceStatus } from '@/lib/types';
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

const STATUS_DOT: Record<InstanceStatus, string> = {
  stopped: 'bg-gray-500',
  starting: 'bg-yellow-400 animate-pulse',
  running: 'bg-green-400 animate-pulse',
  error: 'bg-red-500',
};

const STATUS_LABEL: Record<InstanceStatus, string> = {
  stopped: 'Detenida',
  starting: 'Iniciando…',
  running: 'Activa',
  error: 'Error',
};

export function ChallengeCard({
  challenge,
  onSolved,
  onInstanceChange,
}: {
  challenge: Challenge;
  onSolved: (id: string) => void;
  onInstanceChange: (id: string, status: InstanceStatus) => void;
}) {
  const [flag, setFlag] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [feedback, setFeedback] = useState<Feedback>(null);
  const [instanceAction, setInstanceAction] = useState(false);
  const solved = challenge.solved;
  const instStatus = challenge.instance_status;
  const isRunning = instStatus === 'running';

  async function handleStart() {
    if (instanceAction) return;
    setInstanceAction(true);
    onInstanceChange(challenge.id, 'starting');
    try {
      const res = await api.instanceStart(challenge.id);
      onInstanceChange(challenge.id, res.status);
    } catch (err) {
      onInstanceChange(challenge.id, 'error');
      setFeedback({
        kind: 'error',
        text: err instanceof ApiError ? err.message : 'Error al iniciar la instancia.',
      });
    } finally {
      setInstanceAction(false);
    }
  }

  async function handleStop() {
    if (instanceAction) return;
    setInstanceAction(true);
    try {
      const res = await api.instanceStop(challenge.id);
      onInstanceChange(challenge.id, res.status);
    } catch (err) {
      setFeedback({
        kind: 'error',
        text: err instanceof ApiError ? err.message : 'Error al detener la instancia.',
      });
    } finally {
      setInstanceAction(false);
    }
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    const value = flag.trim();
    if (!value || submitting) return;
    setSubmitting(true);
    setFeedback(null);
    try {
      const res = await api.submit(challenge.id, value);
      if (res.correct) {
        setFeedback({ kind: 'ok', text: res.message || `¡Correcto! +${res.points_awarded} pts` });
        setFlag('');
        onSolved(challenge.id);
      } else if (res.already_solved) {
        setFeedback({ kind: 'info', text: res.message });
      } else {
        setFeedback({ kind: 'error', text: res.message || 'Flag incorrecta.' });
      }
    } catch (err) {
      if (err instanceof ApiError) {
        if (err.status === 403) {
          setFeedback({
            kind: 'incident',
            text: '⚠ Incidente registrado: esa flag pertenece a otro equipo.',
          });
        } else if (err.status === 429) {
          setFeedback({ kind: 'error', text: 'Demasiados intentos. Espera unos segundos.' });
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
          <span className={`font-mono text-sm font-bold ${challenge.category === 'gobl1n' || challenge.category === 'jaka' ? 'text-amber-400' : 'text-neon-cyan'}`}>{challenge.points} pts</span>
          {solved && (
            <span className="flex items-center gap-1 font-mono text-xs font-bold text-neon">
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

      {/* Control de instancia */}
      <div className="rounded-md border border-line bg-black/30 p-3 flex flex-col gap-2">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className={`inline-block h-2 w-2 rounded-full ${STATUS_DOT[instStatus]}`} />
            <span className="font-mono text-xs text-muted">
              Instancia:{' '}
              <span className="text-neon-cyan">{STATUS_LABEL[instStatus]}</span>
            </span>
          </div>
          <div className="flex gap-2">
            {!isRunning && (
              <button
                onClick={handleStart}
                disabled={instanceAction || instStatus === 'starting'}
                className="btn-neon py-1 px-3 text-xs disabled:opacity-40"
              >
                {instStatus === 'starting' ? 'Iniciando…' : '▶ Iniciar'}
              </button>
            )}
            {isRunning && (
              <button
                onClick={handleStop}
                disabled={instanceAction}
                className="rounded border border-danger/50 bg-danger/10 px-3 py-1 font-mono text-xs text-danger hover:bg-danger/20 disabled:opacity-40"
              >
                ■ Detener
              </button>
            )}
          </div>
        </div>

        {isRunning && challenge.connection_info && (
          <div>
            <span className="font-mono text-[10px] uppercase tracking-widest text-muted">
              conexión
            </span>
            <code className="mt-0.5 block select-all break-all font-mono text-sm text-neon-cyan">
              {challenge.connection_info}
            </code>
          </div>
        )}
        {!isRunning && (
          <p className="font-mono text-[11px] text-muted italic">
            Inicia la instancia para ver el endpoint de conexión.
          </p>
        )}
      </div>

      {isRunning || solved ? (
        <form onSubmit={handleSubmit} className="mt-auto flex flex-col gap-2">
          <div className="flex gap-2">
            <input
              type="text"
              value={flag}
              onChange={(e) => setFlag(e.target.value)}
              placeholder={solved ? 'Reto resuelto' : 'HL4{…}'}
              className="input-term"
              autoComplete="off"
              spellCheck={false}
              disabled={solved}
            />
            <button
              type="submit"
              className="btn-neon"
              disabled={solved || submitting || !flag.trim()}
            >
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
      ) : (
        <p className="mt-auto border-t border-line pt-3 font-mono text-[11px] italic text-muted text-center">
          Inicia la instancia para desbloquear el envío de flag.
        </p>
      )}
    </article>
  );
}
