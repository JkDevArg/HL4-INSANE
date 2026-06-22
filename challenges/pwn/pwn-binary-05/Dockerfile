# pwn-binary-05 — ColdVault Firmware (PWN INSANE, binario C clásico, TCP).
#
# Stage 1: compila el firmware C con flags FIJAS para que el exploit sea
#          REPRODUCIBLE (mismos offsets en todas las instancias):
#            - PIE/ASLR activos   (-fPIE -pie)
#            - canario de stack   (-fstack-protector-all)
#            - NX / no-exec stack  (-Wl,-z,noexecstack)  + Full RELRO
#            - -O0 -fno-omit-frame-pointer -> layout de stack predecible.
# Stage 2: runtime Python que expone el binario por TCP 9999 (bridge.py) y
#          loguea cada conexión (CTFREQ). La flag llega por env FLAG en runtime.
# ============================================================================

FROM gcc:13 AS build
WORKDIR /src
COPY vuln.c .
RUN gcc -O0 -fno-omit-frame-pointer \
        -fstack-protector-all \
        -fPIE -pie \
        -Wl,-z,relro,-z,now \
        -Wl,-z,noexecstack \
        -o coldvault vuln.c \
 && chmod +x coldvault
# Verificación de mitigaciones en build-time (deja traza en el log de build).
RUN echo "== checksec-lite ==" \
 && readelf -d coldvault | grep -E 'BIND_NOW|FLAGS' || true \
 && readelf -h coldvault | grep -E 'Type:' || true \
 && (readelf -l coldvault | grep -i 'GNU_STACK') || true

FROM python:3.12-slim
WORKDIR /app

# El binario y el front Python. ASLR depende del kernel del host (suele estar
# activo); no se desactiva. Sin dependencias externas en Python (solo stdlib).
COPY --from=build /src/coldvault /app/coldvault
COPY app/ /app/

EXPOSE 9999
# La FLAG se inyecta por env FLAG en runtime (no en la imagen).
CMD ["python", "-u", "bridge.py"]
