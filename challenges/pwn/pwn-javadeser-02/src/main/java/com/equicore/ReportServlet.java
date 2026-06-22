package com.equicore;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * ReportServlet - consulta de reporte de credito. Funcionalidad "normal" del
 * portal y senuelo: requiere un rol de analista. La via real no es subir de
 * privilegios aqui sino la deserializacion en /api/session/restore.
 */
public class ReportServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String dni = req.getParameter("dni");
        resp.setContentType("application/json; charset=utf-8");
        if (dni == null || dni.isEmpty()) {
            resp.setStatus(400);
            resp.getWriter().println("{\"error\":\"missing dni\"}");
            return;
        }
        // Requiere sesion de analista (cookie). El portal restaura la sesion via
        // /api/session/restore. Sin analista valido, 401.
        resp.setStatus(401);
        resp.getWriter().println("{\"error\":\"no active analyst session; restore one at /api/session/restore\"}");
    }
}
