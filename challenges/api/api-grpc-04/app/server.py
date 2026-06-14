"""SilentChannel gRPC — api-grpc-04 (API INSANE).

Reto: "Silent Channel". Un servidor gRPC ("SilentChannel") con reflexión
habilitada PERO con un servicio administrativo OCULTO.

Cadena de vulnerabilidades (INSANE):

  1) REFLEXIÓN PARCIAL: grpc.reflection está activa, pero el servicio admin
     (vault.AdminService) NO se anuncia en la lista de servicios reflejados.
     Solo aparece channel.SilentChannel. El jugador que hace
     `grpcurl list` cree que eso es todo lo que hay.

  2) FUGA DE INFORMACIÓN: el servicio público filtra el .proto del admin y
     la clave de acceso:
       - GetServerInfo() devuelve un `notice` que menciona un "canal
         silencioso" reservado y deja caer el nombre del paquete/servicio.
       - Echo() con un mensaje que contenga "debug"/"trace"/"admin"/"vault"
         dispara DIAGNÓSTICOS verbosos que vuelcan:
            * el nombre completo del método admin
              (vault.AdminService/GetVault) y la firma de VaultRequest,
            * la metadata exigida: header `x-channel-key`,
            * el valor del `x-channel-key` (huella derivada del servidor).
       - Cualquier error de un RPC inexistente devuelve un detalle verboso
         que reafirma el nombre del servicio oculto.

  3) MÉTODO ADMIN OCULTO: reconstruyendo el .proto (o con descriptores), el
     jugador invoca vault.AdminService/GetVault con la metadata
     `x-channel-key: <valor filtrado>` y `confirm=true`. La respuesta es la
     FLAG.

La FLAG se inyecta por equipo vía env FLAG. NO hardcodeada.
"""
import hashlib
import os
import time
from concurrent import futures

import grpc
from grpc_reflection.v1alpha import reflection

import channel_pb2
import channel_pb2_grpc
import vault_pb2
import vault_pb2_grpc

from siem import emit
from reqlog import reqlog_grpc

FLAG = os.environ.get("FLAG", "flag{EJEMPLO_LOCAL}")
SERVER_NAME = "SilentChannel"
SERVER_VERSION = "1.4.2"

# --- Clave del canal silencioso ---
# El x-channel-key es una huella DETERMINISTA derivada del nombre+versión del
# servidor. NO depende de la FLAG (así el reqlog jamás la redacta y el jugador
# la puede recolectar de los diagnósticos). Es la misma en todas las
# instancias del reto -> el conocimiento se comparte pero la FLAG no (la FLAG
# sigue siendo per-team). La gracia INSANE es DESCUBRIR que existe y de dónde
# sale, no fuerza bruta.
CHANNEL_KEY = "sk_" + hashlib.sha256(f"{SERVER_NAME}:{SERVER_VERSION}:silent".encode()).hexdigest()[:32]

# Nombre del método admin oculto (se filtra en diagnósticos).
ADMIN_FULL_METHOD = "vault.AdminService/GetVault"


def _peer_ip(context) -> str:
    """Extrae la IP del cliente del peer del contexto gRPC.

    grpc devuelve cosas como 'ipv4:172.30.3.99:54321' o
    'ipv6:[::1]:54321'. Nos quedamos con la parte de IP.
    """
    try:
        peer = context.peer() or ""
    except Exception:
        return "?"
    if peer.startswith("ipv4:"):
        host = peer[len("ipv4:"):]
        return host.rsplit(":", 1)[0] if ":" in host else host
    if peer.startswith("ipv6:"):
        host = peer[len("ipv6:"):]
        # formato [::1]:port
        if host.startswith("[") and "]" in host:
            return host[1:host.index("]")]
        return host.rsplit(":", 1)[0] if ":" in host else host
    if peer.startswith("unix:"):
        return "unix"
    return peer or "?"


# ---------------- Interceptor de logging gRPC ----------------
class ReqLogInterceptor(grpc.ServerInterceptor):
    """Loguea CADA RPC entrante con el formato `CTFREQ {json}` del SIEM.

    Como gRPC va sobre HTTP/2, el middleware HTTP de los otros retos no aplica.
    Este interceptor de servidor envuelve el handler para capturar, por cada
    llamada: peer (src_ip), full_method, metadata y el mensaje request.

    El mensaje request se serializa a su representación textual de protobuf
    (text_format) para que el comentarista del stream vea el contenido.
    """

    def intercept_service(self, continuation, handler_call_details):
        full_method = handler_call_details.method or "?"
        # La metadata viene como tupla de pares (clave, valor).
        metadata = handler_call_details.invocation_metadata or ()

        handler = continuation(handler_call_details)
        if handler is None:
            # RPC desconocido: logueamos igualmente el intento (sin body).
            try:
                reqlog_grpc(src_ip="?", full_method=full_method,
                            metadata=metadata, body="")
            except Exception:
                pass
            return handler

        # Solo manejamos unary-unary en este reto (todos los RPC lo son).
        if not (handler.request_streaming or handler.response_streaming):
            inner = handler.unary_unary

            def new_unary_unary(request, context):
                try:
                    body = _msg_to_text(request)
                    reqlog_grpc(
                        src_ip=_peer_ip(context),
                        full_method=full_method,
                        metadata=context.invocation_metadata(),
                        body=body,
                    )
                except Exception:
                    # El logging jamás debe tumbar el reto.
                    pass
                return inner(request, context)

            return grpc.unary_unary_rpc_method_handler(
                new_unary_unary,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )
        return handler


def _msg_to_text(msg) -> str:
    """Representa un mensaje protobuf como una sola línea legible."""
    try:
        from google.protobuf import text_format
        return text_format.MessageToString(msg, as_one_line=True)
    except Exception:
        try:
            return str(msg).replace("\n", " ").strip()
        except Exception:
            return ""


# ---------------- Servicio PÚBLICO ----------------
_DIAG_TRIGGERS = ("debug", "trace", "admin", "vault", "silent", "channel")


class SilentChannelServicer(channel_pb2_grpc.SilentChannelServicer):
    """Servicio visible. Filtra pistas sobre el servicio admin oculto."""

    def Ping(self, request, context):
        return channel_pb2.PingReply(pong="pong")

    def GetServerInfo(self, request, context):
        return channel_pb2.ServerInfoReply(
            server=SERVER_NAME,
            version=SERVER_VERSION,
            channels=["channel.SilentChannel"],
            notice=(
                "Public channels are advertised via gRPC server reflection. "
                "There is also a SILENT operator channel that is NOT reflected "
                "for security reasons. Send Echo with a diagnostics keyword "
                "(e.g. 'debug') to dump the operator runbook."
            ),
        )

    def Echo(self, request, context):
        msg = request.message or ""
        diagnostics = []
        low = msg.lower()
        if any(t in low for t in _DIAG_TRIGGERS):
            # FUGA: vuelca el "runbook" del operador con el proto del admin y
            # la clave del canal silencioso.
            emit("scan_detected", "warn", src_ip=_peer_ip(context),
                 detail={"vuln": "grpc-verbose-diagnostics", "trigger": msg[:64]})
            diagnostics = [
                "== SilentChannel operator runbook (internal) ==",
                "hidden service: vault.AdminService  (NOT exposed via reflection)",
                "hidden method : vault.AdminService/GetVault",
                "request proto : message VaultRequest { string vault_id = 1; bool confirm = 2; }",
                "reply   proto : message VaultReply   { string flag = 1; string message = 2; }",
                "auth          : call requires gRPC metadata header 'x-channel-key'",
                "vault_id      : use 'primary'  (confirm must be true)",
                f"x-channel-key : {CHANNEL_KEY}",
                "note          : key is the server channel fingerprint; rotate per release.",
            ]
        return channel_pb2.EchoReply(message=msg, diagnostics=diagnostics)


# ---------------- Servicio ADMIN OCULTO ----------------
class AdminServiceServicer(vault_pb2_grpc.AdminServiceServicer):
    """Servicio administrativo. Registrado y atendiendo, pero NO reflejado.

    Entrega la FLAG si la llamada trae la metadata 'x-channel-key' correcta y
    confirm=true.
    """

    def GetVault(self, request, context):
        md = dict(context.invocation_metadata() or ())
        key = md.get("x-channel-key", "")

        if key != CHANNEL_KEY:
            emit("scan_detected", "alert", src_ip=_peer_ip(context),
                 detail={"event": "grpc-admin-bad-key", "method": ADMIN_FULL_METHOD})
            context.abort(
                grpc.StatusCode.PERMISSION_DENIED,
                "vault.AdminService/GetVault: invalid or missing x-channel-key metadata",
            )

        if not request.confirm:
            context.abort(
                grpc.StatusCode.FAILED_PRECONDITION,
                "GetVault: 'confirm' must be true to open the vault",
            )

        vault_id = request.vault_id or ""
        if vault_id != "primary":
            context.abort(
                grpc.StatusCode.NOT_FOUND,
                f"vault '{vault_id}' not found; the operator vault is 'primary'",
            )

        emit("scan_detected", "alert", src_ip=_peer_ip(context),
             detail={"event": "grpc-vault-opened", "method": ADMIN_FULL_METHOD})
        return vault_pb2.VaultReply(
            flag=FLAG,
            message="vault opened on the silent channel",
        )


def serve():
    server = grpc.server(
        futures.ThreadPoolExecutor(max_workers=10),
        interceptors=[ReqLogInterceptor()],
    )

    # Ambos servicios quedan ATENDIENDO en el servidor.
    channel_pb2_grpc.add_SilentChannelServicer_to_server(
        SilentChannelServicer(), server)
    vault_pb2_grpc.add_AdminServiceServicer_to_server(
        AdminServiceServicer(), server)

    # REFLEXIÓN PARCIAL: solo se anuncia el servicio público + la propia API
    # de reflexión. vault.AdminService se OMITE a propósito -> oculto a
    # `grpcurl list` / descriptores por reflexión.
    SERVICE_NAMES = (
        channel_pb2.DESCRIPTOR.services_by_name["SilentChannel"].full_name,
        reflection.SERVICE_NAME,
    )
    reflection.enable_server_reflection(SERVICE_NAMES, server)

    server.add_insecure_port("0.0.0.0:8080")
    server.start()
    print(f"[SilentChannel] gRPC escuchando en 0.0.0.0:8080 "
          f"(reflexión: {list(SERVICE_NAMES)})", flush=True)
    print(f"[SilentChannel] servicio oculto registrado: {ADMIN_FULL_METHOD}", flush=True)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        server.stop(0)


if __name__ == "__main__":
    serve()
