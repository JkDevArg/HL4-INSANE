import type { Category } from '@/lib/types';

// Badge de categoria con color por tipo de reto.
const CAT_STYLES: Record<Category, string> = {
  web: 'border-neon/50 text-neon',
  crypto: 'border-warn/50 text-warn',
  pwn: 'border-red-500/50 text-red-400',
  rev: 'border-neon-cyan/50 text-neon-cyan',
  gobl1n: 'border-purple-500/50 text-purple-400',
};

export function CategoryBadge({ category }: { category: Category }) {
  const cls = CAT_STYLES[category] ?? 'border-line text-muted';
  return (
    <span
      className={`rounded border px-2 py-0.5 font-mono text-[10px] uppercase tracking-widest ${cls}`}
    >
      {category}
    </span>
  );
}

// Badge de dificultad. En este evento todo es INSANE: rojo neon, peligro.
export function DifficultyBadge({ difficulty }: { difficulty: string }) {
  return (
    <span className="rounded border border-danger/60 bg-danger/10 px-2 py-0.5 font-mono text-[10px] font-bold uppercase tracking-widest text-danger">
      {difficulty || 'insane'}
    </span>
  );
}
