"""
Loads local simulated SOC data from data/alerts/*.jsonl and
data/logs/*.jsonl.

The seed process is incremental:

- Existing alerts are preserved.
- Existing investigations are preserved.
- Alerts already present in the database are skipped.
- Only new alerts are inserted.
- IOC extraction/enrichment runs only for newly inserted alerts.

Run as:
    python -m app.database.seed
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from app.database.session import SessionLocal, init_db
from app.models.alert import Alert
from app.models.ioc import IOC
from app.models.log_event import LogEvent
from app.services.ioc.enrichment.service import enrich_and_persist
from app.services.ioc.extract import extract_iocs


# backend/app/database/seed.py
# database -> app -> backend -> repo root
REPO_ROOT = Path(__file__).resolve().parents[3]
DATA_DIR = REPO_ROOT / "data"


def _parse_ts(value: str) -> datetime:
    """Convert ISO timestamp string into datetime."""

    return datetime.fromisoformat(
        value.replace("Z", "+00:00")
    )


def _read_jsonl(path: Path) -> list[dict]:
    """Read JSONL file and return records."""

    if not path.exists():
        print(f"Seed file not found: {path}")
        return []

    records: list[dict] = []

    with path.open("r", encoding="utf-8") as f:

        for line_number, line in enumerate(f, start=1):

            line = line.strip()

            if not line:
                continue

            try:
                records.append(json.loads(line))

            except json.JSONDecodeError as exc:

                raise ValueError(
                    f"Invalid JSON in {path} "
                    f"at line {line_number}: {exc}"
                ) from exc

    return records


# =========================================================
# LOG SEEDING
# =========================================================

def seed_logs(db) -> int:
    """
    Seed log events.

    Logs are seeded only when the log table is empty.
    This prevents duplicate logs every time seed.py runs.
    """

    existing_logs = db.query(LogEvent).count()

    if existing_logs > 0:

        print(
            f"Database already contains "
            f"{existing_logs} log event(s). "
            "Skipping log seed."
        )

        return 0

    log_dir = DATA_DIR / "logs"

    if not log_dir.exists():

        print(
            f"Logs directory not found: {log_dir}"
        )

        return 0

    count = 0

    for jsonl_file in sorted(
        log_dir.glob("*.jsonl")
    ):

        for record in _read_jsonl(jsonl_file):

            log_event = LogEvent(
                log_type=record["log_type"],
                timestamp=_parse_ts(
                    record["timestamp"]
                ),
                hostname=record.get("hostname"),
                user=record.get("user"),
                source_ip=record.get("source_ip"),
                destination_ip=record.get(
                    "destination_ip"
                ),
                payload=record.get(
                    "payload",
                    {},
                ),
            )

            db.add(log_event)

            count += 1

    return count


# =========================================================
# ALERT SEEDING
# =========================================================

def seed_alerts(db) -> tuple[int, int]:
    """
    Incrementally seed alerts.

    Existing alert IDs are skipped.

    Returns:
        (inserted_count, skipped_count)
    """

    alerts_file = (
        DATA_DIR
        / "alerts"
        / "sample_alerts.jsonl"
    )

    records = _read_jsonl(alerts_file)

    if not records:

        print(
            "No alert records found in "
            f"{alerts_file}"
        )

        return 0, 0

    # -----------------------------------------------------
    # Get alert IDs already stored in PostgreSQL
    # -----------------------------------------------------

    existing_alert_ids = {
        row[0]
        for row in db.query(
            Alert.alert_id
        ).all()
    }

    inserted_count = 0
    skipped_count = 0

    new_iocs: list[IOC] = []

    # Also protect against duplicate IDs inside JSONL itself.
    processed_ids: set[str] = set()

    for record in records:

        alert_id = record["alert_id"]

        # -------------------------------------------------
        # Existing database alert
        # -------------------------------------------------

        if alert_id in existing_alert_ids:

            print(
                f"Skipping existing alert: "
                f"{alert_id}"
            )

            skipped_count += 1
            continue

        # -------------------------------------------------
        # Duplicate alert inside seed file
        # -------------------------------------------------

        if alert_id in processed_ids:

            print(
                f"Skipping duplicate seed alert: "
                f"{alert_id}"
            )

            skipped_count += 1
            continue

        processed_ids.add(alert_id)

        # -------------------------------------------------
        # Create new alert
        # -------------------------------------------------

        alert = Alert(
            alert_id=alert_id,
            alert_name=record["alert_name"],
            severity=record["severity"],
            timestamp=_parse_ts(
                record["timestamp"]
            ),
            source=record["source"],
            user=record.get("user"),
            hostname=record.get("hostname"),
            source_ip=record.get("source_ip"),
            destination_ip=record.get(
                "destination_ip"
            ),
            command_line=record.get(
                "command_line"
            ),
            file_hash=record.get("file_hash"),
            domain=record.get("domain"),
            url=record.get("url"),
            description=record.get(
                "description"
            ),
            raw_event=record.get(
                "raw_event",
                {},
            ),
        )

        db.add(alert)

        # Generate the internal alert.id before
        # creating IOC rows.
        db.flush()

        # -------------------------------------------------
        # IOC extraction
        # -------------------------------------------------

        extracted = extract_iocs(
            source_ip=alert.source_ip,
            destination_ip=alert.destination_ip,
            domain=alert.domain,
            url=alert.url,
            file_hash=alert.file_hash,
            command_line=alert.command_line,
            description=alert.description,
            raw_event=alert.raw_event,
        )

        for extracted_ioc in extracted:

            row = IOC(
                alert_id=alert.id,
                ioc_type=extracted_ioc.ioc_type,
                value=extracted_ioc.value,
            )

            db.add(row)

            new_iocs.append(row)

        inserted_count += 1

        print(
            f"Added new alert: "
            f"{alert_id} - "
            f"{record['alert_name']}"
        )

    # -----------------------------------------------------
    # Generate IOC database IDs
    # -----------------------------------------------------

    db.flush()

    # -----------------------------------------------------
    # Enrich only IOCs belonging to NEW alerts
    # -----------------------------------------------------

    for row in new_iocs:

        try:

            enrich_and_persist(
                db,
                row,
            )

        except Exception as exc:

            # Do not lose the whole seed just because
            # an external IOC enrichment provider fails.
            print(
                f"IOC enrichment failed for "
                f"{row.value}: {exc}"
            )

    return (
        inserted_count,
        skipped_count,
    )


# =========================================================
# MAIN SEED
# =========================================================

def run() -> None:
    """
    Initialize the database and incrementally seed data.

    Existing alerts and investigations are NEVER deleted.

    Only alert IDs not already present in PostgreSQL
    are inserted.
    """

    init_db()

    db = SessionLocal()

    try:

        print(
            "Starting incremental database seed..."
        )

        # -------------------------------------------------
        # Logs
        # -------------------------------------------------

        n_logs = seed_logs(db)

        # -------------------------------------------------
        # Alerts
        # -------------------------------------------------

        inserted_alerts, skipped_alerts = (
            seed_alerts(db)
        )

        # -------------------------------------------------
        # Commit
        # -------------------------------------------------

        db.commit()

        total_alerts = (
            db.query(Alert).count()
        )

        print("")
        print("Seed completed successfully.")
        print(
            f"New log events: {n_logs}"
        )
        print(
            f"New alerts: {inserted_alerts}"
        )
        print(
            f"Existing alerts skipped: "
            f"{skipped_alerts}"
        )
        print(
            f"Total alerts in database: "
            f"{total_alerts}"
        )

    except Exception as exc:

        db.rollback()

        print(
            f"Database seed failed: {exc}"
        )

        raise

    finally:

        db.close()


if __name__ == "__main__":
    run()