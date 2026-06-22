package com.equicore;

import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.FilterHolder;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;

import javax.servlet.DispatcherType;
import java.util.EnumSet;

/**
 * Equicore - portal interno del buro de credito "Equicore".
 *
 * Arranca un Jetty embebido en el puerto 8080 (interno; sin publicar al host;
 * la red del equipo lo expone en 172.30.N.41:8080).
 *
 * Rutas:
 *   GET  /                      landing / ayuda del portal.
 *   GET  /api/report            consulta de reporte de credito (requiere sesion).
 *   POST /api/session/restore   restaura una sesion guardada (VULNERABLE).
 *   GET  /healthz               liveness.
 *
 * El ReqLogFilter (CTFREQ) envuelve TODAS las rutas.
 */
public class Main {

    public static void main(String[] args) throws Exception {
        int port = 8080;
        String p = System.getenv("PORT");
        if (p != null && !p.isEmpty()) {
            try { port = Integer.parseInt(p); } catch (NumberFormatException ignore) { }
        }

        Server server = new Server(port);

        ServletContextHandler ctx = new ServletContextHandler(ServletContextHandler.SESSIONS);
        ctx.setContextPath("/");

        // Logging CTFREQ sobre TODAS las peticiones.
        ctx.addFilter(new FilterHolder(new ReqLogFilter()), "/*",
                EnumSet.of(DispatcherType.REQUEST));

        ctx.addServlet(new ServletHolder(new IndexServlet()), "/");
        ctx.addServlet(new ServletHolder(new HealthServlet()), "/healthz");
        ctx.addServlet(new ServletHolder(new ReportServlet()), "/api/report");
        ctx.addServlet(new ServletHolder(new SessionRestoreServlet()), "/api/session/restore");

        server.setHandler(ctx);

        System.out.println("Equicore credit bureau listening on :" + port);
        System.out.flush();
        server.start();
        server.join();
    }
}
