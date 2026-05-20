# Monitorized — commandes utiles (make help)
SHELL := /bin/bash
COMPOSE := docker compose
PROJECT ?= monitorized
SERVICE := monitorized
BIN := bin/monitorized
API_URL ?= http://127.0.0.1:8080
LOG_LINES ?= 150
WATCH_INTERVAL ?= 2
LOG_DIR := logs
PORTAINER_WEBHOOK_URL ?=

.DEFAULT_GOAL := help

.PHONY: help build run test tidy clean \
	docker up up-build pull down restart ps \
	status status-live status-once health env-check config-check \
	logs logs-tail logs-live logs-app logs-save logs-clear \
	secrets env-init env-prod git-status save push sync deploy-portainer \
	dev install

help: ## Affiche toutes les commandes
	@echo ""

secrets: ## Génère des secrets forts à coller dans .env
	@command -v openssl >/dev/null || (echo "openssl requis" && exit 1)
	@echo ""
	@echo "Copie ces valeurs dans .env (ne les commit jamais) :"
	@echo ""
	@printf "MONITORIZED_ADMIN_PASSWORD="
	@openssl rand -base64 36 | tr -d '\n'
	@echo ""
	@printf "MONITORIZED_JWT_SECRET="
	@openssl rand -base64 64 | tr -d '\n'
	@echo ""
	@echo ""

env-init: ## Crée .env depuis .env.example si absent
	@test -f .env || cp .env.example .env
	@echo "→ .env prêt. Lance 'make secrets' puis remplace les placeholders."

env-prod: ## Crée .env depuis .env.production.example si absent
	@test -f .env || cp .env.production.example .env
	@echo "→ .env prod prêt. Lance 'make secrets' puis adapte domaines/volumes."
	@echo "  Monitorized — make <cible>"
	@echo ""
	@grep -E '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'
	@echo ""

# --- Build & local ---

build: ## Compile le binaire (bin/monitorized)
	@mkdir -p bin
	go build -ldflags="-s -w" -o $(BIN) ./cmd/monitorized

run: build ## Lance en local (nécessite .env)
	@test -f .env || (echo "→ cp .env.example .env puis édite les secrets" && exit 1)
	set -a && source ./.env && set +a && ./$(BIN)

dev: ## Lance en local avec logs verbeux sur stdout
	@test -f .env || cp -n .env.example .env 2>/dev/null || true
	set -a && source ./.env 2>/dev/null; set +a; \
	./$(BIN) 2>&1 | tee -a $(LOG_DIR)/monitorized-dev.log

install: build env-check ## Build + rappel config .env
	@echo "→ Dashboard: $(API_URL)"
	@echo "→ Docker:    make up"

test: ## Tests Go
	go test ./...

tidy: ## go mod tidy
	go mod tidy

clean: ## Supprime bin/ (pas data/ ni .env)
	rm -rf bin/

# --- Docker ---

docker: ## Build image Docker
	COMPOSE_PROJECT_NAME=$(PROJECT) $(COMPOSE) build

up: env-check ## Démarre en arrière-plan
	@mkdir -p $(LOG_DIR)
	COMPOSE_PROJECT_NAME=$(PROJECT) $(COMPOSE) up -d
	@echo "→ $(API_URL) (health: make health)"

up-build: env-check ## Rebuild + démarre
	@mkdir -p $(LOG_DIR)
	COMPOSE_PROJECT_NAME=$(PROJECT) $(COMPOSE) up -d --build

pull: ## Pull/rebuild selon la stack compose
	COMPOSE_PROJECT_NAME=$(PROJECT) $(COMPOSE) pull || true
	COMPOSE_PROJECT_NAME=$(PROJECT) $(COMPOSE) build --pull

down: ## Arrête les conteneurs
	COMPOSE_PROJECT_NAME=$(PROJECT) $(COMPOSE) down

restart: ## Redémarre monitorized
	COMPOSE_PROJECT_NAME=$(PROJECT) $(COMPOSE) restart $(SERVICE)

ps: ## Liste les conteneurs du projet
	COMPOSE_PROJECT_NAME=$(PROJECT) $(COMPOSE) ps -a

# --- Status ---

status: ## État du projet (docker, API, fichiers, ressources)
	@echo ""
	@echo "═══ Monitorized — status ═══"
	@echo ""
	@echo "── Fichiers"
	@test -f .env && echo "  .env          ✓" || echo "  .env          ✗  (cp .env.example .env)"
	@test -f $(BIN) && echo "  binaire       ✓  ($(BIN))" || echo "  binaire       ✗  (make build)"
	@test -d data && echo "  data/         ✓" || echo "  data/         —  (créé au 1er run)"
	@test -d $(LOG_DIR) && echo "  $(LOG_DIR)/        ✓" || echo "  $(LOG_DIR)/        —"
	@echo ""
	@echo "── Git"
	@git rev-parse --short HEAD 2>/dev/null | xargs -I{} echo "  commit        {}" || echo "  git           —"
	@git status -sb 2>/dev/null | head -1 | sed 's/^/  /' || true
	@echo ""
	@echo "── Docker Compose (project: $(PROJECT))"
	@if COMPOSE_PROJECT_NAME=$(PROJECT) $(COMPOSE) ps -a 2>/dev/null | grep -q $(SERVICE); then \
		COMPOSE_PROJECT_NAME=$(PROJECT) $(COMPOSE) ps -a; \
	else \
		echo "  conteneur     non démarré (make up)"; \
	fi
	@echo ""
	@echo "── API $(API_URL)"
	@if curl -sf "$(API_URL)/health" 2>/dev/null; then \
		echo ""; \
	else \
		echo "  ✗ inaccessible"; \
	fi
	@echo ""
	@echo "── Ressources conteneur (si actif)"
	@docker stats --no-stream --format "  {{.Name}}  CPU {{.CPUPerc}}  RAM {{.MemUsage}}" $(SERVICE) 2>/dev/null || true
	@echo ""
	@echo "── Ports / volumes"
	@docker port $(SERVICE) 2>/dev/null | sed 's/^/  /' || true
	@docker inspect $(SERVICE) --format '  restart={{.HostConfig.RestartPolicy.Name}} readonly={{.HostConfig.ReadonlyRootfs}} image={{.Config.Image}}' 2>/dev/null || true
	@echo ""

status-live: ## Status rafraîchi en continu (Ctrl+C pour quitter)
	@command -v watch >/dev/null || (echo "Installez 'watch' (procps)" && exit 1)
	@watch -n $(WATCH_INTERVAL) -c '$(MAKE) --no-print-directory status'

status-once: status ## Alias explicite pour snapshot status

health: ## Ping /health
	@curl -sf "$(API_URL)/health" | jq . 2>/dev/null || curl -sf "$(API_URL)/health" || (echo "API down" && exit 1)

env-check: ## Vérifie que .env existe
	@test -f .env || (echo "→ cp .env.example .env" && exit 1)

config-check: env-check ## Valide la configuration docker compose
	COMPOSE_PROJECT_NAME=$(PROJECT) $(COMPOSE) config >/dev/null
	@echo "→ compose OK"

# --- Logs ---

logs: logs-app ## Logs live du conteneur monitorized uniquement

logs-live: ## Logs temps réel de tous les conteneurs du projet
	@echo "→ Ctrl+C pour quitter"
	COMPOSE_PROJECT_NAME=$(PROJECT) $(COMPOSE) logs -f --tail=$(LOG_LINES)

logs-app: ## Logs temps réel du service monitorized uniquement
	@echo "→ Ctrl+C pour quitter"
	COMPOSE_PROJECT_NAME=$(PROJECT) $(COMPOSE) logs -f --tail=$(LOG_LINES) $(SERVICE)

logs-tail: ## Dernières lignes des logs du projet
	COMPOSE_PROJECT_NAME=$(PROJECT) $(COMPOSE) logs --tail=$(LOG_LINES)

logs-save: ## Enregistre les logs dans logs/ (horodaté)
	@mkdir -p $(LOG_DIR)
	@OUT="$(LOG_DIR)/monitorized-$$(date +%Y%m%d-%H%M%S).log"; \
	COMPOSE_PROJECT_NAME=$(PROJECT) $(COMPOSE) logs --no-color --tail=5000 > "$$OUT" 2>&1; \
	echo "→ enregistré: $$OUT"

logs-clear: ## Vide les logs Docker du service (redémarrage léger)
	@echo "→ truncate logs docker (nécessite conteneur arrêté ou recreate)"
	COMPOSE_PROJECT_NAME=$(PROJECT) $(COMPOSE) down
	@COMPOSE_PROJECT_NAME=$(PROJECT) $(COMPOSE) rm -f $(SERVICE) 2>/dev/null || true
	@echo "→ redémarrez avec: make up"

# --- Git / production ---

push: ## Commit si demandé séparément, puis push la branche courante
	git push origin $$(git branch --show-current)

sync: push ## Alias : synchronise GitHub

git-status: ## État Git court avant commit/push
	@git status -sb
	@git remote -v

save: ## Git add + commit + push (MSG="message")
	@test -n "$(MSG)" || (echo 'MSG requis, ex: make save MSG="docs: update production setup"' && exit 1)
	@git status --short
	@git add -A
	@if ! git diff --cached --quiet; then \
		if git diff --cached --name-only | grep -E '(^|/)\.env$$|\.pem$$|\.key$$|credentials\.json$$' >/dev/null; then \
			echo "Refus: secret potentiel staged"; \
			exit 1; \
		fi; \
	else \
		echo "Rien à committer"; \
		exit 0; \
	fi
	git commit -m "$(MSG)"
	git push origin $$(git branch --show-current)

deploy-portainer: ## Déclenche un webhook Portainer après push
	@test -n "$(PORTAINER_WEBHOOK_URL)" || (echo "PORTAINER_WEBHOOK_URL requis" && exit 1)
	git push origin $$(git branch --show-current)
	curl -fsS -X POST "$(PORTAINER_WEBHOOK_URL)"
	@echo ""
	@echo "→ Webhook Portainer déclenché"
