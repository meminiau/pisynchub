# PiSyncHub

Unified multi-node dashboard and selective Teleporter sync engine designed for Pi-hole.

> **⚠️ Early Release / Testing Notice:**  
> PiSyncHub is currently in active early development and requires ongoing testing. Features, sync behavior, and endpoints may change as builds progress. Please ensure you maintain backups of your Pi-hole instances before syncing configurations.

---

## Features

- **Multi-Node Overview:** Monitor multiple Pi-hole instances from a single lightweight dashboard.
- **Selective Sync:** Synchronize adlists, domains, client groups, and local DNS records between nodes without manual export/import friction.
- **Automated Vault Backups:** Periodically extract and store local Teleporter archives for quick rollbacks.
- **Docker-Ready:** Engineered to deploy seamlessly on unRAID, Docker Compose, or standalone container runtimes.

---

## Quick Start (Docker)

Run the container directly:

```bash
docker run -d \
  --name pisynchub \
  -p 8085:8085 \
  -v /mnt/user/appdata/pisynchub:/config \
  --restart unless-stopped \
  homerj007/pisynchub:latest
