# Architecture Monitorized

## Principes

- **Un binaire** : agent + API + UI embarquée (pas de Node/React en prod)
- **SQLite WAL** : stockage local, faible empreinte, pas de cluster requis
- **Collecte par intervalles** : pas de polling agressif (10–30 s par défaut)
- **Séparation des privilèges** : socket Docker en `ro`, utilisateur non-root

## Schéma

```
┌─────────────────────────────────────────────────────────┐
│                    Monitorized (Go)                      │
│  ┌──────────┐  ┌────────────┐  ┌─────────┐  ┌────────┐ │
│  │ Engine   │→ │ Collectors │→ │ SQLite  │← │ API    │ │
│  │ (ticks)  │  │ host/docker│  │ store   │  │ + WAF  │ │
│  │          │  │ npm logs   │  └─────────┘  │ + UI   │ │
│  └──────────┘  └────────────┘              └────────┘ │
└───────────▲──────────────▲──────────────────▲──────────┘
            │              │                  │
     /proc, gopsutil   docker.sock      NPM access logs
```

## Extensions prévues

- `internal/collector/logs` — tails journald + docker logs API
- `internal/analyzer/npm` — agrégations, détection anomalies
- `internal/notify` — webhooks, SMTP
- `internal/network` — introspection ports (ss/netlink) sans modifier iptables directement au début
