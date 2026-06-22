package com.equicore;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

/**
 * IndexServlet - landing del portal Equicore. Da contexto al jugador: el portal
 * "recuerda" tu sesion mediante un blob que puedes guardar y restaurar.
 */
public class IndexServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        // Solo respondemos en la raiz exacta.
        if (req.getRequestURI() != null && !"/".equals(req.getRequestURI())) {
            resp.setStatus(404);
            resp.setContentType("application/json; charset=utf-8");
            resp.getWriter().println("{\"error\":\"not found\"}");
            return;
        }
        resp.setStatus(200);
        resp.setContentType("text/html; charset=utf-8");
        PrintWriter w = resp.getWriter();
        w.println("<!doctype html>");
        w.println("<html lang=\"es\"><head><meta charset=\"utf-8\">");
        w.println("<title>Equicore | Buro de Credito</title></head><body>");
        w.println("<h1>Equicore</h1>");
        w.println("<p>Portal interno de analistas del buro de credito Equicore.</p>");
        w.println("<h2>Servicios</h2>");
        w.println("<ul>");
        w.println("  <li><code>GET  /api/report?dni=NNNNNNNN</code> &mdash; consulta de reporte (requiere sesion de analista).</li>");
        w.println("  <li><code>GET  /api/session/restore</code> &mdash; devuelve una sesion invitado de ejemplo (base64).</li>");
        w.println("  <li><code>POST /api/session/restore</code> &mdash; restaura tu sesion guardada (cookie <code>EQUICORE_SESSION</code> o campo <code>state</code>).</li>");
        w.println("</ul>");
        w.println("<p><em>Sugerencia:</em> el portal serializa la sesion del analista para que no tengas que volver a iniciar. Guarda tu blob y restauralo cuando vuelvas.</p>");
        w.println("</body></html>");
    }
}
