# Solución — web-CAMBIAME-NN (TEMPLATE)

> Reemplaza este writeup con la solución real del reto.

## Vulnerabilidad central

CAMBIAME (ej: SSTI, SQLi, deserialización, supply chain...).

## Pasos de explotación

1. ...
2. ...
3. Obtener la flag: `HL4{EJEMPLO}`.

## Nota anti-cheat

Este reto resiste el compartir porque la flag es **dinámica y única por
equipo** (HMAC del flag-service, `ARCHITECTURE §4`). Si un equipo envía la
flag de otro, la plataforma detecta el dueño vía `POST /whose-flag` y dispara
`cheat_flag_share`. Compartir el *método* no entrega puntos: cada equipo debe
explotar su propia instancia para obtener SU flag.
