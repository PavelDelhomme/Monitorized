# Déploiement production (Portainer)

## Objectif

Déployer Monitorized sur ton VPS de façon :

- légère (128 Mo RAM max)
- sécurisée (non-root, read-only, socket Docker en `ro`)
- simple à mettre à jour depuis GitHub

## 1. Préparer les secrets

Sur ta machine locale ou directement sur le VPS :

```bash
cp .env.production.example .env
make secrets
```

Colle dans `.env` :

- `MONITORIZED_ADMIN_PASSWORD`
- `MONITORIZED_JWT_SECRET`

Adapte aussi :

- `MONITORIZED_ALLOWED_ORIGINS=https://monitorized.tondomaine.ovh`
- `NPM_LOG_GLOB=/data/logs/proxy-host-*_access.log`

## 2. Explication des variables `.env`

| Variable | À quoi ça sert |
|----------|----------------|
| `MONITORIZED_ADDR` | Port d'écoute interne du conteneur (`:8080`) |
| `MONITORIZED_DATA_DIR` | Dossier SQLite (`/data` en prod) |
| `MONITORIZED_ADMIN_USER` | Login dashboard |
| `MONITORIZED_ADMIN_PASSWORD` | Mot de passe admin (bcrypt côté app) |
| `MONITORIZED_JWT_SECRET` | Secret de signature des tokens (32+ chars) |
| `MONITORIZED_ALLOWED_ORIGINS` | Domaines autorisés CORS (ton URL HTTPS publique) |
| `DOCKER_HOST` | Socket Docker local |
| `NPM_LOG_GLOB` | Pattern des access logs NPM |
| `COLLECT_*_INTERVAL` | Fréquence de collecte |
| `RETENTION_DAYS` | Durée de rétention SQLite |
| `ALERT_WEBHOOK_URL` | Webhook alertes (optionnel) |
| `COMPROMISE_*` | Veille compromission gratuite |

## 3. Déployer dans Portainer

### Option A — Stack Git (recommandé)

1. Portainer → **Stacks** → **Add stack**
2. **Repository** :
   - URL : `https://github.com/PavelDelhomme/Monitorized`
   - Compose path : `docker-compose.portainer.yml`
   - Branch : `main`
3. **Environment variables** : colle le contenu de ton `.env` + `NPM_LOGS_HOST_PATH`
4. Deploy

### Option B — Webhook auto après push

1. Dans Portainer, active le webhook de la stack
2. Copie l'URL webhook
3. Sur ta machine :

```bash
export PORTAINER_WEBHOOK_URL="https://portainer.../webhooks/xxxx"
make deploy-portainer
```

## 4. Nginx Proxy Manager (obligatoire en prod)

Ne publie pas `8080` sur Internet.

Dans NPM :

- Proxy Host → `monitorized.tondomaine.ovh`
- Forward : IP du VPS, port `8080` (local) ou réseau Docker interne
- SSL Let's Encrypt activé
- Access List / auth recommandé en plus du login Monitorized

## 5. Commandes utiles

```bash
make status-live      # état live du projet
make logs-live        # logs live de la stack projet
make logs-app         # logs live du conteneur monitorized
make up-build         # rebuild local
make secrets          # génère mots de passe/JWT forts
make save MSG="..."   # commit + push sécurisé
```

## 6. Mise à jour rapide

```bash
git pull
make up-build
# ou webhook Portainer :
make deploy-portainer
```

## 7. Checklist sécurité

- [ ] `.env` jamais commité
- [ ] secrets générés via `make secrets`
- [ ] HTTPS via NPM
- [ ] port 8080 non exposé publiquement
- [ ] socket Docker en lecture seule
- [ ] mot de passe admin changé
- [ ] domaine dans `MONITORIZED_ALLOWED_ORIGINS`
