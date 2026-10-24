from sqlalchemy import inspect, text

from app.db.session import engine


FINDING_COLUMNS = {
    "is_reviewed": "BOOLEAN NOT NULL DEFAULT FALSE",
    "review_notes": "TEXT",
    "reviewed_at": "TIMESTAMP",
    "reviewed_by_user_id": "INTEGER",
}


def apply_development_migrations() -> None:
    inspector = inspect(engine)
    if "scan_findings" not in inspector.get_table_names():
        return
    existing = {column["name"] for column in inspector.get_columns("scan_findings")}
    with engine.begin() as connection:
        for column, ddl in FINDING_COLUMNS.items():
            if column not in existing:
                connection.execute(text(f"ALTER TABLE scan_findings ADD COLUMN {column} {ddl}"))

