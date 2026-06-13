'use client';

// Cabecera de las paginas protegidas: marca, navegacion, identidad del equipo y logout.
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useSession } from './SessionProvider';

const NAV = [
  { href: '/', label: 'Retos' },
  { href: '/scoreboard', label: 'Scoreboard' },
];

export function Header() {
  const { teamId, displayName, logout } = useSession();
  const pathname = usePathname();

  return (
    <header className="sticky top-0 z-20 border-b border-line bg-bg/90 backdrop-blur">
      <div className="mx-auto flex max-w-6xl flex-wrap items-center gap-x-6 gap-y-3 px-4 py-3">
        <Link href="/" className="flex items-center gap-2 font-mono text-neon">
          <span className="text-neon-cyan">&gt;_</span>
          <span className="font-bold tracking-tight">CTFHL4</span>
          <span className="rounded border border-danger/60 px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-widest text-danger">
            insane
          </span>
        </Link>

        <nav className="flex items-center gap-1" aria-label="Principal">
          {NAV.map((item) => {
            const active = pathname === item.href;
            return (
              <Link
                key={item.href}
                href={item.href}
                aria-current={active ? 'page' : undefined}
                className={`rounded-md px-3 py-1.5 font-mono text-sm transition ${
                  active
                    ? 'bg-neon/10 text-neon'
                    : 'text-muted hover:text-neon'
                }`}
              >
                {item.label}
              </Link>
            );
          })}
        </nav>

        <div className="ml-auto flex items-center gap-3">
          <div className="text-right">
            <div className="font-mono text-sm text-neon">{displayName}</div>
            <div className="font-mono text-[11px] text-muted">{teamId}</div>
          </div>
          <button onClick={logout} className="btn-ghost" type="button">
            Cerrar sesión
          </button>
        </div>
      </div>
    </header>
  );
}
