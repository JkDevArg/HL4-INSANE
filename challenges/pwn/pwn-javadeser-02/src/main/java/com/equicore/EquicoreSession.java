package com.equicore;

import java.io.Serializable;

/**
 * EquicoreSession - estado de sesion del analista del buro, serializable.
 *
 * El portal "guarda" la sesion del analista serializandola con Java
 * ObjectOutputStream y entregandola al cliente codificada en base64 (cookie
 * EQUICORE_SESSION / campo "state"). Cuando el cliente vuelve, el servidor la
 * "restaura" con ObjectInputStream.readObject().
 *
 * Este es el patron clasico que abre la puerta a la deserializacion insegura:
 * el servidor confia en un objeto serializado controlado por el cliente.
 */
public class EquicoreSession implements Serializable {
    private static final long serialVersionUID = 1L;

    private String analyst;
    private String role;
    private long lastSeenEpoch;

    public EquicoreSession() { }

    public EquicoreSession(String analyst, String role) {
        this.analyst = analyst;
        this.role = role;
        this.lastSeenEpoch = System.currentTimeMillis() / 1000L;
    }

    public String getAnalyst() { return analyst; }
    public String getRole() { return role; }
    public long getLastSeenEpoch() { return lastSeenEpoch; }

    @Override
    public String toString() {
        return "EquicoreSession{analyst=" + analyst + ", role=" + role
                + ", lastSeen=" + lastSeenEpoch + "}";
    }
}
