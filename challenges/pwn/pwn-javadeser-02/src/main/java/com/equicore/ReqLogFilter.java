package com.equicore;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TimeZone;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ReadListener;
import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

/**
 * ReqLogFilter - equivalente Java del reqlog.py de los retos Python.
 *
 * OBJETIVO: que el comentarista del stream vea CUALQUIER cosa que un jugador
 * envie a este reto. Cada peticion se imprime a STDOUT como UNA linea con el
 * prefijo "CTFREQ " seguido de JSON compacto. Promtail recoge esas lineas
 * (filtro "CTFREQ ") y el caster-overlay las narra anonimizadas por equipo.
 *
 * Formato EXACTO de la linea (HTTP):
 *   CTFREQ {"ts":"&lt;iso8601&gt;","challenge_id":"&lt;id&gt;","src_ip":"&lt;ip cliente&gt;",
 *           "proto":"http","method":"POST","path":"/api/score",
 *           "query":"...","headers":{...},"body":"&lt;texto, &lt;=8192 chars&gt;"}
 *
 * REGLAS (identicas al reqlog.py):
 *   - challenge_id sale del env CHALLENGE_ID.
 *   - src_ip es la IP REAL del cliente: X-Forwarded-For (primer salto) si existe,
 *     si no remoteAddr.
 *   - body se trunca a MAX_BODY (8192) chars.
 *   - NUNCA se loguea la FLAG propia del reto (env FLAG): se redacta si aparece
 *     incrustada en headers/body/query.
 */
public class ReqLogFilter implements Filter {

    private static final int MAX_BODY = 8192;
    private static final String CHALLENGE_ID = envOr("CHALLENGE_ID", "unknown");
    private static final String FLAG = System.getenv("FLAG");
    private static final String FLAG_REDACTION = "[FLAG-REDACTADA]";

    @Override
    public void init(FilterConfig filterConfig) { }

    @Override
    public void destroy() { }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {

        if (!(req instanceof HttpServletRequest)) {
            chain.doFilter(req, res);
            return;
        }
        HttpServletRequest http = (HttpServletRequest) req;

        // El body se consume una sola vez: lo leemos completo y lo re-servimos
        // mediante un wrapper para que el servlet destino lo siga viendo.
        byte[] body = readAll(http.getInputStream());
        CachedBodyRequest wrapped = new CachedBodyRequest(http, body);

        try {
            emit(http, body);
        } catch (Throwable ignore) {
            // El logging jamas debe tumbar el reto.
        }

        chain.doFilter(wrapped, res);
    }

    private void emit(HttpServletRequest http, byte[] body) {
        String srcIp = clientIp(http);
        String method = nz(http.getMethod());
        String path = nz(http.getRequestURI());
        String query = http.getQueryString() == null ? "" : http.getQueryString();

        Map<String, String> headers = new LinkedHashMap<String, String>();
        Enumeration<String> names = http.getHeaderNames();
        if (names != null) {
            while (names.hasMoreElements()) {
                String k = names.nextElement();
                headers.put(k, redactFlag(nz(http.getHeader(k))));
            }
        }

        String bodyText = coerceText(body);

        StringBuilder sb = new StringBuilder();
        sb.append("CTFREQ {");
        sb.append("\"ts\":").append(jsonStr(nowIso())).append(',');
        sb.append("\"challenge_id\":").append(jsonStr(CHALLENGE_ID)).append(',');
        sb.append("\"src_ip\":").append(jsonStr(srcIp.isEmpty() ? "?" : srcIp)).append(',');
        sb.append("\"proto\":\"http\",");
        sb.append("\"method\":").append(jsonStr(method.isEmpty() ? "?" : method)).append(',');
        sb.append("\"path\":").append(jsonStr(path.isEmpty() ? "/" : path)).append(',');
        sb.append("\"query\":").append(jsonStr(redactFlag(query))).append(',');
        sb.append("\"headers\":{");
        boolean first = true;
        for (Map.Entry<String, String> e : headers.entrySet()) {
            if (!first) sb.append(',');
            first = false;
            sb.append(jsonStr(e.getKey())).append(':').append(jsonStr(e.getValue()));
        }
        sb.append("},");
        sb.append("\"body\":").append(jsonStr(truncate(redactFlag(bodyText))));
        sb.append('}');

        System.out.println(sb.toString());
        System.out.flush();
    }

    /** IP real del cliente: X-Forwarded-For (primer valor) o remoteAddr. */
    private static String clientIp(HttpServletRequest http) {
        String xff = http.getHeader("X-Forwarded-For");
        if (xff != null && !xff.trim().isEmpty()) {
            int comma = xff.indexOf(',');
            return (comma >= 0 ? xff.substring(0, comma) : xff).trim();
        }
        return nz(http.getRemoteAddr());
    }

    /** ISO-8601 UTC con sufijo Z (segundos), igual que _now_iso() de Python. */
    private static String nowIso() {
        SimpleDateFormat f = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
        f.setTimeZone(TimeZone.getTimeZone("UTC"));
        return f.format(new Date());
    }

    private static String coerceText(byte[] data) {
        if (data == null || data.length == 0) return "";
        // Si los bytes son texto imprimible (el body llega en base64), se loguea
        // tal cual. Si son binarios crudos, se loguea como 'hex:...' igual que
        // el reqlog.py de Python.
        if (isMostlyPrintable(data)) {
            try {
                return new String(data, "UTF-8");
            } catch (Exception e) {
                return "hex:" + toHex(data);
            }
        }
        return "hex:" + toHex(data);
    }

    private static boolean isMostlyPrintable(byte[] data) {
        for (byte b : data) {
            int c = b & 0xFF;
            if (c == '\t' || c == '\n' || c == '\r') continue;
            if (c < 0x20 || c == 0x7F) return false;
        }
        return true;
    }

    private static String toHex(byte[] data) {
        StringBuilder sb = new StringBuilder(data.length * 2);
        for (byte b : data) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }

    private static String truncate(String text) {
        if (text == null) return "";
        if (text.length() > MAX_BODY) {
            return text.substring(0, MAX_BODY) + "...[+" + (text.length() - MAX_BODY) + " chars]";
        }
        return text;
    }

    private static String redactFlag(String text) {
        if (text == null || text.isEmpty() || FLAG == null || FLAG.isEmpty()) {
            return text == null ? "" : text;
        }
        return text.contains(FLAG) ? text.replace(FLAG, FLAG_REDACTION) : text;
    }

    /** Escapado JSON minimo de una cadena (comillas + control chars). */
    private static String jsonStr(String s) {
        if (s == null) s = "";
        StringBuilder sb = new StringBuilder(s.length() + 2);
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':  sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        sb.append('"');
        return sb.toString();
    }

    private static byte[] readAll(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int n;
        while ((n = in.read(buf)) != -1) {
            out.write(buf, 0, n);
            if (out.size() > 16 * 1024 * 1024) break; // tope defensivo
        }
        return out.toByteArray();
    }

    private static String nz(String s) { return s == null ? "" : s; }

    private static String envOr(String k, String def) {
        String v = System.getenv(k);
        return (v == null || v.isEmpty()) ? def : v;
    }

    /** Wrapper que re-sirve el body ya leido al servlet destino. */
    static final class CachedBodyRequest extends HttpServletRequestWrapper {
        private final byte[] body;
        CachedBodyRequest(HttpServletRequest req, byte[] body) {
            super(req);
            this.body = body;
        }
        @Override
        public ServletInputStream getInputStream() {
            final ByteArrayInputStream bais = new ByteArrayInputStream(body);
            return new ServletInputStream() {
                @Override public int read() { return bais.read(); }
                @Override public boolean isFinished() { return bais.available() == 0; }
                @Override public boolean isReady() { return true; }
                @Override public void setReadListener(ReadListener l) { }
            };
        }
    }
}
