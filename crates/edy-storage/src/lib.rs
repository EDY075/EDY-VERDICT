//! Infrastructure-only SQLite and native secret storage. No findings or secrets in SQL.
pub mod secrets;
use rusqlite::{Connection, OpenFlags};
use sha2::{Digest, Sha256};
use std::{fmt, path::Path, time::Duration};

const MIGRATION: &str = include_str!("../migrations/0001_infrastructure.sql");
const VERSION: u32 = 1;

#[derive(Debug)]
pub enum StorageError {
    Sql(rusqlite::Error),
    UnsafeState(&'static str),
    Io(std::io::Error),
}
impl From<rusqlite::Error> for StorageError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Sql(e)
    }
}
impl From<std::io::Error> for StorageError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sql(_) => write!(f, "SQLite infrastructure operation failed"),
            Self::UnsafeState(s) => f.write_str(s),
            Self::Io(_) => f.write_str("Storage filesystem operation failed"),
        }
    }
}
impl std::error::Error for StorageError {}

pub struct Storage {
    connection: Connection,
}
impl Storage {
    pub fn open(path: &Path) -> Result<Self, StorageError> {
        if !path.is_absolute() {
            return Err(StorageError::UnsafeState("Absolute database path required"));
        }
        // Preflight read-only: refuse corruption/newer/unknown schema without changing WAL or schema.
        let existed = path.exists();
        if existed {
            let check = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
            check.busy_timeout(Duration::from_secs(5))?;
            if check.query_row("PRAGMA quick_check", [], |r| r.get::<_, String>(0))? != "ok" {
                return Err(StorageError::UnsafeState(
                    "Corrupt database preserved; explicit restore required",
                ));
            }
            let version: u32 = check.query_row("PRAGMA user_version", [], |r| r.get(0))?;
            if version > VERSION {
                return Err(StorageError::UnsafeState("Newer schema refused"));
            }
            if version == 0 {
                let tables: u32 = check.query_row("SELECT count(*) FROM sqlite_schema WHERE type='table' AND name NOT GLOB 'sqlite_*'", [], |r| r.get(0))?;
                if tables != 0 {
                    return Err(StorageError::UnsafeState("Unrecognized schema refused"));
                }
            }
            if version == VERSION {
                verify_migration(&check)?;
            }
        }
        let mut connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.execute_batch("PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;")?;
        let version: u32 = connection.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if version == 0 {
            if existed {
                let backup_path = path.with_extension("pre-v1.sqlite3");
                // Never overwrite an existing recovery copy.
                let reserved = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&backup_path)?;
                drop(reserved);
                let mut destination = Connection::open(&backup_path)?;
                rusqlite::backup::Backup::new(&connection, &mut destination)?.run_to_completion(
                    32,
                    Duration::from_millis(5),
                    None,
                )?;
            }
            let transaction = connection.transaction()?;
            transaction.execute_batch(MIGRATION)?;
            transaction.execute(
                "INSERT INTO schema_migrations(version,checksum) VALUES (?1,?2)",
                (VERSION, migration_hash()),
            )?;
            transaction.pragma_update(None, "user_version", VERSION)?;
            transaction.commit()?;
        }
        verify_migration(&connection)?;
        Ok(Self { connection })
    }
    pub fn schema_version(&self) -> Result<u32, StorageError> {
        Ok(self
            .connection
            .query_row("PRAGMA user_version", [], |r| r.get(0))?)
    }
    pub fn backup(&self, path: &Path) -> Result<(), StorageError> {
        if !path.is_absolute() {
            return Err(StorageError::UnsafeState("Absolute backup path required"));
        }
        let reserved = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;
        drop(reserved);
        let mut destination = Connection::open(path)?;
        rusqlite::backup::Backup::new(&self.connection, &mut destination)?.run_to_completion(
            32,
            Duration::from_millis(5),
            None,
        )?;
        if destination.query_row("PRAGMA quick_check", [], |r| r.get::<_, String>(0))? != "ok" {
            return Err(StorageError::UnsafeState("Backup verification failed"));
        }
        Ok(())
    }
}
fn migration_hash() -> String {
    format!("{:x}", Sha256::digest(MIGRATION.as_bytes()))
}
fn verify_migration(connection: &Connection) -> Result<(), StorageError> {
    let (count, checksum): (u32, String) = connection.query_row(
        "SELECT count(*), coalesce(max(checksum),'') FROM schema_migrations WHERE version=1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    if count != 1 || checksum != migration_hash() {
        return Err(StorageError::UnsafeState("Migration checksum mismatch"));
    }
    if connection.query_row("SELECT count(*) FROM schema_migrations", [], |r| {
        r.get::<_, u32>(0)
    })? != 1
    {
        return Err(StorageError::UnsafeState("Unexpected migration history"));
    }
    // Compare the actual structural schema against the embedded migration, not
    // merely a checksum string that could survive dropped tables or altered FKs.
    let expected = Connection::open_in_memory()?;
    expected.execute_batch(MIGRATION)?;
    fn schema(c: &Connection) -> Result<Vec<(String, String, String)>, rusqlite::Error> {
        c.prepare("SELECT type,name,coalesce(sql,'') FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*' ORDER BY type,name")?.query_map([],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?.collect()
    }
    if schema(connection)? != schema(&expected)? {
        return Err(StorageError::UnsafeState("Unexpected database structure"));
    }
    if connection
        .prepare("PRAGMA foreign_key_check")?
        .query([])?
        .next()?
        .is_some()
    {
        return Err(StorageError::UnsafeState("Foreign-key corruption refused"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    #[test]
    fn sqlite_similar_user_objects_are_not_excluded_from_schema_check() {
        let dir = Directory::new();
        let path = dir.0.join("db.sqlite3");
        let store = Storage::open(&path).unwrap();
        store.connection.execute_batch("CREATE TABLE sqliteXevil(id INTEGER); CREATE TRIGGER sqliteXtrigger AFTER INSERT ON infrastructure_runs BEGIN INSERT INTO sqliteXevil VALUES (1); END;").unwrap();
        drop(store);
        assert!(Storage::open(&path).is_err());
    }
    #[test]
    fn missing_table_does_not_become_ready() {
        let dir = Directory::new();
        let path = dir.0.join("db.sqlite3");
        let store = Storage::open(&path).unwrap();
        store
            .connection
            .execute_batch("DROP TABLE infrastructure_events")
            .unwrap();
        drop(store);
        assert!(Storage::open(&path).is_err());
    }
    struct Directory(std::path::PathBuf);
    impl Directory {
        fn new() -> Self {
            let p = std::env::temp_dir().join(format!(
                "edy-storage-{}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn create_migrate_reopen_pragmas_foreign_key_backup() {
        let dir = Directory::new();
        let path = dir.0.join("db.sqlite3");
        let store = Storage::open(&path).unwrap();
        assert_eq!(store.schema_version().unwrap(), 1);
        for (pragma, expected) in [
            ("foreign_keys", 1),
            ("trusted_schema", 0),
            ("synchronous", 2),
            ("busy_timeout", 5000),
        ] {
            assert_eq!(
                store
                    .connection
                    .pragma_query_value(None, pragma, |r| r.get::<_, i64>(0))
                    .unwrap(),
                expected
            );
        }
        assert_eq!(
            store
                .connection
                .pragma_query_value(None, "journal_mode", |r| r.get::<_, String>(0))
                .unwrap(),
            "wal"
        );
        assert!(
            store
                .connection
                .execute(
                    "INSERT INTO infrastructure_events(run_id,kind) VALUES (99,'open')",
                    []
                )
                .is_err()
        );
        store
            .connection
            .execute(
                "INSERT INTO infrastructure_runs(id,label) VALUES (1,'fixture')",
                [],
            )
            .unwrap();
        store
            .connection
            .execute(
                "INSERT INTO infrastructure_events(run_id,kind) VALUES (1,'open')",
                [],
            )
            .unwrap();
        let backup = dir.0.join("backup.sqlite3");
        store.backup(&backup).unwrap();
        assert!(store.backup(&backup).is_err());
        let restored = Storage::open(&backup).unwrap();
        assert_eq!(restored.schema_version().unwrap(), 1);
        assert_eq!(
            restored
                .connection
                .query_row("SELECT count(*) FROM infrastructure_events", [], |r| r
                    .get::<_, u32>(0))
                .unwrap(),
            1
        );
        drop(store);
        assert_eq!(Storage::open(&path).unwrap().schema_version().unwrap(), 1);
    }
    #[test]
    fn existing_empty_database_is_backed_up_before_migration() {
        let dir = Directory::new();
        let path = dir.0.join("db.sqlite3");
        drop(Connection::open(&path).unwrap());
        let store = Storage::open(&path).unwrap();
        assert_eq!(store.schema_version().unwrap(), 1);
        assert!(path.with_extension("pre-v1.sqlite3").exists());
    }
    #[test]
    fn corruption_fails_without_recreation_or_modification() {
        let dir = Directory::new();
        let path = dir.0.join("bad.sqlite3");
        let data = b"harmless simulated corrupt database";
        std::fs::write(&path, data).unwrap();
        assert!(Storage::open(&path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), data);
    }
    #[test]
    fn newer_schema_and_tampered_migration_are_refused() {
        let dir = Directory::new();
        let path = dir.0.join("db.sqlite3");
        let store = Storage::open(&path).unwrap();
        store
            .connection
            .pragma_update(None, "user_version", 99)
            .unwrap();
        drop(store);
        assert!(Storage::open(&path).is_err());
        let connection = Connection::open(&path).unwrap();
        connection.pragma_update(None, "user_version", 1).unwrap();
        connection
            .execute("UPDATE schema_migrations SET checksum='tampered'", [])
            .unwrap();
        drop(connection);
        assert!(Storage::open(&path).is_err());
    }
}
