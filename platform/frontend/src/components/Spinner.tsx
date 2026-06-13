// Indicador de carga minimalista.
export function Spinner({ label = 'Cargando…' }: { label?: string }) {
  return (
    <div className="flex items-center gap-3 font-mono text-sm text-muted" role="status">
      <span
        aria-hidden
        className="inline-block h-4 w-4 animate-spin rounded-full border-2 border-line border-t-neon"
      />
      <span>{label}</span>
    </div>
  );
}
