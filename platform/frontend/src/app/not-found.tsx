import Link from 'next/link';

export default function NotFound() {
  return (
    <main className="flex min-h-screen items-center justify-center px-4 text-center">
      <div>
        <div className="font-mono text-5xl font-bold text-neon">404</div>
        <p className="mt-2 font-mono text-sm text-muted">Ruta no encontrada.</p>
        <Link href="/" className="btn-ghost mt-6 inline-flex">
          Volver a los retos
        </Link>
      </div>
    </main>
  );
}
