# DependShield — New Machine Setup Guide

A simple, step-by-step guide to cloning and running **DependShield** on any new computer (Windows, macOS, or Linux).

---

## ⚡ Quick Start (TL;DR)

If you already have **Git** and **Docker Desktop** installed and running, run these commands in your terminal:

```bash
# 1. Clone & enter directory
git clone https://github.com/your-username/dependshield.git
cd dependshield

# 2. Copy the Docker environment template
# On Windows (PowerShell):
Copy-Item .env.docker.example .env
# On macOS / Linux:
cp .env.docker.example .env

# 3. Start all services
docker compose up -d --build

# 4. Initialize database tables
docker compose exec backend npx prisma migrate deploy
```

🎉 **Done!** Open your browser and navigate to **[http://localhost](http://localhost)**.

---

## 📋 Table of Contents
1. [Prerequisites](#1-prerequisites)
2. [Step-by-Step Setup Guide](#2-step-by-step-setup-guide)
3. [Using DependShield](#3-using-dependshield)
4. [Day-to-Day Commands](#4-day-to-day-commands)
5. [Troubleshooting & FAQs](#5-troubleshooting--faqs)
6. [Manual Setup (Without Docker)](#6-manual-setup-without-docker)

---

## 1. Prerequisites

Ensure the following tools are installed on the new PC before beginning:

| Software | Required Version | Why It's Needed | Download |
| :--- | :--- | :--- | :--- |
| **Git** | `2.x+` | To download the source code | [Download Git](https://git-scm.com/) |
| **Docker Desktop** | `4.x+` | Runs Database, Backend, and Frontend containers | [Download Docker](https://www.docker.com/products/docker-desktop/) |

> [!IMPORTANT]
> **Docker Desktop must be running** before you run any Docker commands. Look for the whale icon in your system tray/taskbar to ensure it says "running".
> 
> * **Windows users:** Ensure WSL 2 engine is enabled in Docker settings (*Settings → General → Use the WSL 2 based engine*).

---

## 2. Step-by-Step Setup Guide

### Step 1: Clone the Repository
Open PowerShell (Windows) or Terminal (macOS/Linux) and run:

```bash
git clone https://github.com/your-username/dependshield.git
cd dependshield
```

---

### Step 2: Configure Environment (`.env`)
DependShield includes a ready-to-use template (`.env.docker.example`) configured for local container testing.

Copy it to create your `.env` file:

* **Windows (PowerShell):**
  ```powershell
  Copy-Item .env.docker.example .env
  ```
* **macOS / Linux / Git Bash:**
  ```bash
  cp .env.docker.example .env
  ```

> ℹ️ *The template comes pre-configured with:*
> * Web App: `http://localhost` (Port `80`)
> * Backend API: `http://localhost:3000` (Port `3000`)
> * PostgreSQL Database: Port `5432`

---

### Step 3: Build & Start Containers
Run Docker Compose to build the images and launch the stack in the background:

```bash
docker compose up -d --build
```

**What gets started:**
* 🐘 `dependshield-db-1`: PostgreSQL 15 Database
* ⚙️ `dependshield-backend-1`: Node.js Express REST API
* 🌐 `dependshield-frontend-1`: Nginx serving the React SPA

---

### Step 4: Apply Database Migrations
On a new PC, the PostgreSQL volume is newly created and empty. Run this single command to create all tables and indexes:

```bash
docker compose exec backend npx prisma migrate deploy
```

✅ *You should see: `All migrations have been successfully applied.`*

---

### Step 5: Verify the Setup

Check that all 3 services are running and healthy:

```bash
docker compose ps
```

You should see:
```text
NAME                     STATUS              PORTS
dependshield-db-1        running (healthy)   0.0.0.0:5432->5432/tcp
dependshield-backend-1   running (healthy)   0.0.0.0:3000->3000/tcp
dependshield-frontend-1  running             0.0.0.0:80->80/tcp
```

Test the API health endpoint:
```bash
curl http://localhost/api/v1/health
```
*(Should return `{"status":"ok","database":"connected"}`)*

---

## 3. Using DependShield

1. **Open the App:** Navigate to **[http://localhost](http://localhost)** in your browser.
2. **Create Account:** Go to **[http://localhost/register](http://localhost/register)** and sign up.
   * *Password requirements:* 8+ chars, 1 uppercase, 1 lowercase, 1 number.
3. **Log In:** Log in at **[http://localhost/login](http://localhost/login)** to reach your Dashboard.
4. **Create a Project:** Click **+ New Project** and enter a name.
5. **Run a Security Scan:** Inside your project, either:
   * Paste a public GitHub URL (e.g. `https://github.com/expressjs/express`) to scan, or
   * Click **Upload ZIP** to upload a Node.js repository archive with `package.json` and `package-lock.json`.
6. **Review Results:** Inspect extracted dependencies, CycloneDX SBOM, matched vulnerabilities (CVEs), and risk scores.

---

## 4. Day-to-Day Commands

Keep these handy for managing your local instance:

| Task | Command |
| :--- | :--- |
| **Stop all services** | `docker compose down` |
| **Start services again** | `docker compose up -d` |
| **View live logs** | `docker compose logs -f` |
| **View logs for one service** | `docker compose logs -f backend` *(or `frontend`, `db`)* |
| **Rebuild frontend after edits** | `docker compose up -d --build frontend` |
| **Rebuild backend after edits** | `docker compose up -d --build backend` |
| **Reset database (wipe all data)** | `docker compose down -v && docker compose up -d && docker compose exec backend npx prisma migrate deploy` |

---

## 5. Troubleshooting & FAQs

### ❓ Error: "Cannot connect to the Docker daemon"
* **Solution:** Docker Desktop is not running. Launch **Docker Desktop** from your desktop or start menu and wait until the engine is fully started.

### ❓ Port conflict: "Port 80 (or 3000, 5432) already in use"
* **Solution:** If another application on your PC uses port 80 (e.g., IIS, Apache, Skype), open `.env` and change the ports:
  ```env
  FRONTEND_PORT=8080
  BACKEND_PORT=3001
  DB_PORT=5433
  ```
  Then run `docker compose up -d`. You will now access the app at `http://localhost:8080`.

### ❓ Browser shows a blank white page or stale UI
* **Solution:** Perform a hard refresh to clear cached browser files:
  * **Windows / Linux:** `Ctrl + Shift + R` or `Ctrl + F5`
  * **macOS:** `Cmd + Shift + R`

---

## 6. Manual Setup (Without Docker)

If you prefer to run directly on your host machine without Docker:

### Requirements:
* Local **PostgreSQL 15** running on port `5432`.
* **Node.js 20.x** & **npm 10.x**.

### Instructions:

1. **Start Backend (Terminal 1):**
   ```bash
   cd backend
   cp .env.example .env
   # Update DATABASE_URL in .env with your local PostgreSQL password
   npm install
   npx prisma migrate deploy
   npm start
   ```
   *Backend runs on `http://localhost:3000`.*

2. **Start Frontend (Terminal 2):**
   ```bash
   cd frontend
   npm install
   npm run dev
   ```
   *Frontend dev server runs on `http://localhost:5173`.*

3. **Run Backend Test Suite:**
   ```bash
   cd backend
   npm test -- --runInBand --forceExit
   ```
