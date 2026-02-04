# Static Analysis Automation with FastAPI, Celery, and Strelka

This project provides an automated static analysis framework for files using [Strelka](https://github.com/target/strelka). It queues file analysis tasks with Celery, stores results in a PostgreSQL database, and exposes a FastAPI endpoint for uploading files and retrieving results.

### Key Features
* **Deduplication:** Previously analyzed files return results immediately (based on SHA256).
* **Queued Analysis:** Heavy files are processed asynchronously using Celery and RabbitMQ.
* **Scoring Logic:** Assigns a maliciousness score, verdict, and specific reasons based on Strelka analysis.

---

## 1. Prerequisites & Strelka Installation on Ubuntu 
Before setting up the main application, you must install and configure Strelka and its dependencies.

### System Dependencies & Docker
Install necessary system tools and Docker:

```bash
sudo apt install -y wget git docker.io docker-compose-v2 golang jq

# Enable Docker and add current user to the docker group
sudo systemctl enable --now docker
sudo usermod -aG docker $USER
# Note: You may need to log out and log back in for group changes to take effect.
```

### Install Strelka & Build OneShot
Clone the Strelka repository, start the backend containers, and build the `oneshot` client:

```bash
git clone [https://github.com/target/strelka.git](https://github.com/target/strelka.git)
cd strelka

# Start Strelka backend (Headless)
sudo docker compose -f build/docker-compose-no-build.yaml up -d

# Build the Go CLI tool
cd src/go/cmd/strelka-oneshot
go build -o strelka-oneshot

# Move the binary to your project root (adjust path as necessary)
mv strelka-oneshot ../../../../
cd ../../../../
```

### Verification
Verify Strelka is working by running a test scan:

```bash
./strelka-oneshot -f <file path> -l - | jq
```

---

## 2. Project Requirements

* **Python:** 3.12+
* **Database:** PostgreSQL 15+
* **Message Broker:** RabbitMQ
* **Analysis Engine:** Strelka (Headless/Dockerized)

**Python Dependencies** (listed in `requirements.txt`):
* `fastapi`
* `uvicorn`
* `sqlalchemy`
* `psycopg2-binary` (for PostgreSQL connection)
* `celery[redis]`
* `pydantic`
* `python-multipart`
* `requests`

---

## 3. Installation & Setup

### Clone Repository & Environment
```bash
git clone <repo-url>
cd static_analysis

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Database Setup (PostgreSQL)
1. **Install PostgreSQL (Ubuntu):**
    ```bash
    sudo apt update
    sudo apt install postgresql postgresql-contrib -y
    sudo systemctl start postgresql
    sudo systemctl enable postgresql
    ```

2. **Log in as superuser:**
    ```bash
    sudo -u postgres psql
    ```

3. **Create Database and User:**
    ```sql
    CREATE DATABASE analysis_db;

    CREATE USER strelka WITH PASSWORD 'password';

    ALTER ROLE strelka SET client_encoding TO 'utf8';
    ALTER ROLE strelka SET default_transaction_isolation TO 'read committed';
    ALTER ROLE strelka SET timezone TO 'UTC';

    GRANT ALL PRIVILEGES ON DATABASE analysis_db TO strelka;
    ```

3. **Initialize Tables:**
    Run the following Python snippet to create the tables using SQLAlchemy:
    ```python
    from db import engine, Base
    Base.metadata.create_all(bind=engine)
    ```


### Celery & RabbitMQ Setup
1. **Install RabbitMQ:**
    ```bash
    sudo apt update
    sudo apt install rabbitmq-server
    sudo systemctl enable rabbitmq-server
    sudo systemctl start rabbitmq-server
    ```

2. **Start Celery Worker:**
    Ensure your `tasks` module is correctly imported to avoid "unregistered task" errors.
    ```bash
    celery -A celery_app.celery worker --loglevel=info
    ```

---

## 4. Running the Project

Start the FastAPI server:

```bash
uvicorn app:app --reload --port 8000
```

---

## 5. API Endpoints
Go to http http://127.0.0.1:8000/docs and see the two endpoints
### Upload File
Submit a file for analysis.


**Example Response (Queued):**
```json
{
  "message": "File queued for analysis",
  "task_id": "4700f44b-bfa2-4fee-9b82-e8d2d71a54b3",
  "sha256": "205064af53c802ca95a0f902096c0e1f2684081b73c3f6e4005a1af9f778c6aa"
}
```

### Check Result
Retrieve the analysis status and report.

**Example Response (Success):**
```json
{
  "task_id": "4700f44b-bfa2-4fee-9b82-e8d2d71a54b3",
  "state": "SUCCESS",
  "result": {
      "score": 0,
      "verdict": "benign",
      "reasons": ["None"]
  }
}
```

---

## 6. Project Structure

```text
static_analysis/
│
├─ app.py             # FastAPI application entry point
├─ celery_app.py      # Celery configuration
├─ tasks.py           # Celery tasks definitions
├─ db.py              # SQLAlchemy engine and session setup
├─ model.py           # SQLAlchemy database models
├─ utils.py           # Helper functions (SHA256, etc.)
├─ scoring.py         # scoring logic
├─ uploads/           # Directory for temp storage of uploaded files 
├─ requirements.txt   # Project dependencies
└─ README.md          # Documentation
```
