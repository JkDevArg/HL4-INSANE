// Layout de las rutas protegidas: envuelve con SessionProvider (verifica /auth/me)
// y muestra la cabecera comun. Las rutas hijas asumen sesion valida.
import { SessionProvider } from '@/components/SessionProvider';
import { Header } from '@/components/Header';

export default function ProtectedLayout({ children }: { children: React.ReactNode }) {
  return (
    <SessionProvider>
      <Header />
      <main className="mx-auto max-w-6xl px-4 py-8">{children}</main>
    </SessionProvider>
  );
}
