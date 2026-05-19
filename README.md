# Monitorized

**Monitoring VPS ultra-léger** — serveur, conteneurs Docker, trafic Nginx Proxy Manager, alertes et sécurité de base (WAF, blocage IP).

Un seul binaire Go (~15–30 Mo RAM en fonctionnement), interface web embarquée, stockage SQLite local.

## Fonctionnalités (v0.1)

| Module | Statut |
|--------|--------|
| Métriques hôte (CPU, RAM, disque, load, réseau) | ✅ |
| Snapshots conteneurs Docker | ✅ |
| Ingestion logs NPM (access) | ✅ |
| Dashboard web + JWT | ✅ |
| Alertes basiques (CPU, WAF) | ✅ |
| WAF léger + blocage IP | ✅ |
| Veille compromission (fuites, threat intel) | ✅ |
| Logs conteneurs en streaming | 🔜 |
| Analyse requêtes avancée / GeoIP | 🔜 |
| Notifications (webhook, email) | 🔜 |
| Gestion ports / pare-feu | 🔜 |

## Démarrage rapide

```bash
cp .env.example .env
# Éditer : mot de passe admin + JWT secret (32+ caractères)
make tidy && make build
make run
```

Ouvrir [http://127.0.0.1:8080](http://127.0.0.1:8080)

## Docker (VPS)

1. Copier `.env` et configurer les secrets.
2. Adapter `docker-compose.yml` : volume NPM (`npm_data`) et chemin des logs.
3. `docker compose up -d`
4. Placer **Nginx Proxy Manager** devant avec HTTPS + authentification supplémentaire recommandée.

```bash
# Générer un secret JWT
openssl rand -base64 48
```

### Monter les logs NPM

Sur la plupart des installs NPM, les access logs sont dans le volume Docker de l’app. Exemple :

```yaml
volumes:
  - /chemin/vers/npm/data/logs:/data/logs:ro
```

Variable `NPM_LOG_GLOB=/data/logs/proxy-host-*_access.log`

## API

| Endpoint | Auth | Description |
|----------|------|-------------|
| `GET /health` | Non | Santé |
| `POST /api/v1/auth/login` | Non | Token JWT |
| `GET /api/v1/overview` | Oui | Vue d’ensemble |
| `GET /api/v1/host/history` | Oui | Historique CPU |
| `GET /api/v1/containers` | Oui | Conteneurs |
| `GET /api/v1/npm/stats` | Oui | Stats NPM 24h |
| `GET /api/v1/alerts` | Oui | Alertes |
| `POST /api/v1/security/block` | Oui | Bloquer une IP |
| `DELETE /api/v1/security/block/{ip}` | Oui | Débloquer |
| `GET /api/v1/compromise/summary` | Oui | Synthèse compromission |
| `GET /api/v1/compromise/findings` | Oui | Détails des findings |
| `POST /api/v1/compromise/targets` | Oui | Ajouter une cible |
| `POST /api/v1/compromise/scan` | Oui | Lancer un scan immédiat |

## Veille compromission (100 % gratuit, interface graphique)

**Aucune clé API payante** (HIBP retiré). Tout se configure dans l’onglet **Compromission** du dashboard :

- Ajout unitaire ou **import en masse** (une cible par ligne, autant que tu veux)
- Filtres Emails / Domaines / IP + recherche
- Suppression par clic

| Source gratuite | Vérifie |
|-----------------|---------|
| **XposedOrNot** | Fuites d’emails |
| **EmailRep** | Réputation & fuites email |
| **ThreatFox** (abuse.ch) | Malware / C2 |
| **URLhaus** | Domaines malware |
| **PhishTank** | Phishing |
| **DNSBL** | IP sur blocklists |
| **Shodan InternetDB** | Ports & CVE exposés |

Auto : IP publique du VPS, domaines NPM (option `.env`). **Pas de scraping dark web.**

## Sécurité

- JWT HS256, mot de passe hashé (bcrypt)
- Rate limiting (20 req/s burst 40)
- WAF règles basiques (SQLi, XSS, path traversal)
- Conteneur non-root, `read_only`, capabilities droppées
- **Ne pas exposer** le port 8080 sur Internet sans reverse proxy TLS
- Changer les identifiants par défaut immédiatement

## GitHub

```bash
git init
git add .
git commit -m "feat: initial Monitorized v0.1 — monitoring VPS léger"
gh repo create monitorized --public --source=. --push
```

## Roadmap

1. **v0.2** — streaming logs Docker + système (tail)
2. **v0.3** — analyse NPM détaillée (top hosts, paths, latence p95)
3. **v0.4** — webhooks alertes, règles configurables
4. **v0.5** — agent multi-nœuds, export Prometheus optionnel

## Licence

MIT — voir [LICENSE](LICENSE)
