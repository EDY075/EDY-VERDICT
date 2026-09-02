CREATE TABLE schema_migrations (
  version INTEGER PRIMARY KEY,
  checksum TEXT NOT NULL
);
CREATE TABLE infrastructure_runs (
  id INTEGER PRIMARY KEY,
  label TEXT NOT NULL CHECK (length(label) <= 128)
);
CREATE TABLE infrastructure_events (
  id INTEGER PRIMARY KEY,
  run_id INTEGER NOT NULL REFERENCES infrastructure_runs(id),
  kind TEXT NOT NULL CHECK (kind IN ('open', 'close'))
);
