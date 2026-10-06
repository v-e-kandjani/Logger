# Logger Platform - Development & Synchronization Guidelines

Whenever code, configuration, templates, or scripts in this project are modified:

## 1. Synchronize to GitHub
- Ensure tests and builds pass (`go test ./...`).
- Commit and push all changes directly to `origin/main`:
  ```bash
  git push origin main
  ```

## 2. Synchronize to Remote Production VPS
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

## 3. Synchronize to Local Docker Desktop
- Rebuild and restart the local Docker container:
  ```bash
  docker compose build syslog-app && docker compose up -d
  ```
