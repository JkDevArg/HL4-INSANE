# CTFHL4-INSANE — atajos de operación (ejecutar en el servidor Ubuntu).
COMPOSE = docker compose
SURICATA = docker compose -f docker-compose.suricata.yml

.PHONY: help up down build seed logs ps siem-up restart launch-team stop-team

help:
	@echo "Targets:"
	@echo "  make up           - levanta plataforma + SIEM (build incluido)"
	@echo "  make seed         - crea 10 equipos + retos, imprime credenciales"
	@echo "  make siem-up      - levanta Suricata (necesita tun0 activo)"
	@echo "  make down         - apaga todo"
	@echo "  make logs         - sigue logs de todos los servicios"
	@echo "  make ps           - estado de contenedores"
	@echo "  make launch-team TEAM=team_03 - lanza los retos del equipo (aislados)"
	@echo "  make stop-team   TEAM=team_03 - detiene los retos del equipo"

up:
	$(COMPOSE) up -d --build

build:
	$(COMPOSE) build

seed:
	# exec (no run): siembra dentro del contenedor ya corriendo. 'run' crearia
	# un contenedor nuevo que choca con la IP fija 10.10.100.12 de platform-api.
	$(COMPOSE) exec platform-api python seed.py

down:
	$(COMPOSE) down

restart:
	$(COMPOSE) restart

logs:
	$(COMPOSE) logs -f --tail=100

ps:
	$(COMPOSE) ps

siem-up:
	$(SURICATA) up -d

launch-team:
	./launch-team-challenges.sh $(TEAM)

stop-team:
	./launch-team-challenges.sh $(TEAM) down
