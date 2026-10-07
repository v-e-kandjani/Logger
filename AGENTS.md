# Logger Platform - Development & Synchronization Guidelines

Whenever code, configuration, templates, or scripts in this project are modified:

## 1. Version Management (MANDATORY)
- Whenever any changes, fixes, or new features are introduced, **bump the semantic version** (e.g. `v1.2.1` -> `v1.2.2`).
- Update:
  - `internal/version/version.go`: Increment `Version`, update `BuildDate` to current date (`YYYY-MM-DD`), and set `CommitSHA`.
  - `web/templates/index.html`: Update `#brand-version`, `#upd-current-version`, `#upd-build-date`, and cache buster query parameters (`?v=...`).
  - `web/static/js/translations.js`: Update `app_version` in both Turkish (`tr`) and English (`en`).
  - `README.md`: Document changes under Release History.

## 2. Synchronize to GitHub
- Ensure tests and builds pass (`go test ./...`).
- Commit and push all changes directly to `origin/main`:
  ```bash
  git push origin main
  ```

## 3. Synchronize to Remote Production VPS
- **Host**: `168.231.106.208`
- **User**: `alex`
- **Password**: `9m1KE=LPW=N*jd`
- **Path**: `/home/alex/projects/logger`
- **Action**:
  - Pull latest repository changes from `origin/main`.
  - Rebuild `syslog-app` and restart containers:
    ```bash
    git pull origin main
    echo '9m1KE=LPW=N*jd' | sudo -S docker compose build syslog-app
    echo '9m1KE=LPW=N*jd' | sudo -S docker compose up -d
    ```

## 4. Synchronize to Local Docker Desktop
- Rebuild and restart the local Docker container:
  ```bash
  docker compose build syslog-app && docker compose up -d
  ```
