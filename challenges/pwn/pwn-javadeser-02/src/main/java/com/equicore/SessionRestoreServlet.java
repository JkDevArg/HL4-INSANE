package com.equicore;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.util.Base64;

/**
 * SessionRestoreServlet - "restaura" la sesion del analista a partir de un blob
 * serializado de Java entregado por el cliente.
 *
 * ===================== VULNERABILIDAD (INSANE) =========================
 * Deserializacion insegura de Java (CWE-502). El blob viene del cliente:
 *   - cookie EQUICORE_SESSION (base64), o
 *   - parametro/cuerpo "state" (base64).
 * El servidor hace ObjectInputStream.readObject() SIN ningun filtro de clases
 * (sin ObjectInputFilter / setObjectInputFilter, sin allow-list, sin
 * resolveClass sobreescrito). El classpath incluye Apache Commons Collections
 * 3.1 (vulnerable, CVE-2015-7501). Un atacante envia una gadget chain estilo
 * ysoserial (CommonsCollections1/5/6): durante readObject() la cadena
 * InvokerTransformer/LazyMap/AnnotationInvocationHandler ejecuta Runtime.exec()
 * => RCE => leer la FLAG (env / archivo) y exfiltrarla.
 *
 * Esta es la misma clase de bug que hundio a Equifax en 2017 (~$1.4 mil
 * millones en perdidas). Equifax fue Struts2 (CVE-2017-5638), pero la familia
 * "el servidor procesa datos serializados sin validar" es la misma; aqui la
 * variante clasica de objeto Java serializado.
 *
 * GET sin parametros: emite una sesion "invitado" recien serializada (semilla
 * que el jugador inspecciona para entender el formato).
 * ======================================================================
 */
public class SessionRestoreServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String b64 = extractState(req);
        if (b64 == null || b64.isEmpty()) {
            // Semilla: entrega una sesion invitado serializada en base64.
            EquicoreSession guest = new EquicoreSession("guest", "viewer");
            String seed = Base64.getEncoder().encodeToString(serialize(guest));
            resp.setStatus(200);
            resp.setContentType("application/json; charset=utf-8");
            PrintWriter w = resp.getWriter();
            w.println("{");
            w.println("  \"info\": \"Equicore session service. POST your saved session blob to restore it.\",");
            w.println("  \"hint\": \"Send the base64 session as cookie EQUICORE_SESSION or as form/body field 'state'.\",");
            w.println("  \"guest_session_b64\": \"" + seed + "\"");
            w.println("}");
            return;
        }
        restore(b64, resp);
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String b64 = extractState(req);
        if (b64 == null || b64.isEmpty()) {
            resp.setStatus(400);
            resp.getWriter().println("{\"error\":\"missing session blob (cookie EQUICORE_SESSION or field 'state')\"}");
            return;
        }
        restore(b64, resp);
    }

    /**
     * Restaura la sesion. AQUI esta el bug: readObject() sobre bytes del cliente
     * sin ningun filtrado de clases.
     */
    private void restore(String b64, HttpServletResponse resp) throws IOException {
        byte[] raw;
        try {
            raw = Base64.getDecoder().decode(b64.trim());
        } catch (IllegalArgumentException e) {
            resp.setStatus(400);
            resp.getWriter().println("{\"error\":\"session blob is not valid base64\"}");
            return;
        }

        Object obj;
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(raw))) {
            // VULNERABLE: deserializacion de datos no confiables sin allow-list.
            obj = ois.readObject();
        } catch (Exception e) {
            // La gadget chain ya ejecuto su payload ANTES de llegar aqui (durante
            // readObject), aunque el cast posterior falle. Devolvemos error
            // generico para no delatar el flujo.
            resp.setStatus(500);
            resp.setContentType("application/json; charset=utf-8");
            resp.getWriter().println("{\"error\":\"could not restore session\"}");
            return;
        }

        resp.setContentType("application/json; charset=utf-8");
        if (obj instanceof EquicoreSession) {
            EquicoreSession s = (EquicoreSession) obj;
            resp.setStatus(200);
            resp.getWriter().println("{\"restored\":true,\"analyst\":\"" + jsafe(s.getAnalyst())
                    + "\",\"role\":\"" + jsafe(s.getRole()) + "\"}");
        } else {
            resp.setStatus(200);
            resp.getWriter().println("{\"restored\":false,\"type\":\"" + jsafe(obj.getClass().getName()) + "\"}");
        }
    }

    /** Extrae el blob base64 de la cookie EQUICORE_SESSION o del campo 'state'. */
    private String extractState(HttpServletRequest req) throws IOException {
        Cookie[] cookies = req.getCookies();
        if (cookies != null) {
            for (Cookie c : cookies) {
                if ("EQUICORE_SESSION".equals(c.getName())) {
                    return c.getValue();
                }
            }
        }
        String p = req.getParameter("state");
        if (p != null && !p.isEmpty()) {
            return p;
        }
        // Si el body no es form-urlencoded, lo tomamos crudo como base64.
        String body = readBody(req);
        if (body != null && !body.isEmpty()) {
            if (body.startsWith("state=")) {
                return body.substring("state=".length());
            }
            return body;
        }
        return null;
    }

    private static byte[] serialize(Object o) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(bos)) {
            oos.writeObject(o);
        }
        return bos.toByteArray();
    }

    private static String readBody(HttpServletRequest req) throws IOException {
        InputStream in = req.getInputStream();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int n;
        while ((n = in.read(buf)) != -1) out.write(buf, 0, n);
        return new String(out.toByteArray(), "UTF-8").trim();
    }

    private static String jsafe(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
