import type { Category } from '@/lib/types';

// Badge de categoria con color por tipo de reto.
const CAT_STYLES: Record<Category, string> = {
  web: 'border-neon/50 text-neon',
  api: 'border-neon-cyan/50 text-neon-cyan',
  crypto: 'border-warn/50 text-warn',
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
