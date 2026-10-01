package keystore

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/tantosec/badAuthenticator/internal/config"
	"github.com/tantosec/badAuthenticator/pkg/logging"
	_ "modernc.org/sqlite"
)

func OpenAndVerifyDB() (*sql.DB, error) {

	if err := os.MkdirAll(config.KeystoreDir, config.DefaultDirectoryPermissions); err != nil {
		return nil, fmt.Errorf("failed to create keystore directory '%s': %w", config.KeystoreDir, err)
	}

	databasePath := filepath.Join(config.KeystoreDir, "metadata.db")

	// Let SQLite wait for an in-progress write instead of rejecting concurrent requests.
	db, err := sql.Open("sqlite", databasePath+"?_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("error opening database at '%s': %w", databasePath, err)
	}

	var tableName string
	query := "SELECT name FROM sqlite_master WHERE type='table' AND name='credentials';"
	err = db.QueryRow(query).Scan(&tableName)

	if err == sql.ErrNoRows {
		logging.GetLogger().Debug("Database appears to be new or uninitialized. Creating schema...\n")
		if initErr := initializeSchema(db); initErr != nil {
			db.Close()
			return nil, fmt.Errorf("failed to initialize database schema: %w", initErr)
		}
	} else if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to check for credentials table: %w", err)
	} else if migrateErr := MigrateSchema(db); migrateErr != nil {
		db.Close()
		return nil, fmt.Errorf("failed to migrate database schema: %w", migrateErr)
	}

	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS credentials_rpid ON credentials (RPID, CreationDate DESC)`); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create credential RP index: %w", err)
	}

	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS attestation_replays (
		rp TEXT NOT NULL,
		user_id TEXT NOT NULL,
		challenge TEXT NOT NULL,
		response BLOB,
		PRIMARY KEY (rp, user_id, challenge)
	)`); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create attestation replay table: %w", err)
	}

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("error pinging database: %w", err)
	}

	return db, nil
}

func initializeSchema(db *sql.DB) error {
	createTableSQL := `
    CREATE TABLE credentials (
        CredentialID TEXT PRIMARY KEY,
        PrivateKeyFilePath TEXT,
        PublicKeyBytesHex TEXT,
        UserHandle TEXT,
        SignCount INTEGER DEFAULT 0,
        RPIDHash TEXT,
        CreationDate DATETIME NOT NULL,
        RPID TEXT NOT NULL,
		cose_algorithm INTEGER NOT NULL,
		Origin TEXT NOT NULL DEFAULT '',
		AndroidPackageName TEXT NOT NULL DEFAULT '',
		Profile TEXT NOT NULL DEFAULT ''
    );`

	_, err := db.Exec(createTableSQL)
	if err != nil {
		return fmt.Errorf("error creating 'credentials' table: %w", err)
	}
	return nil
}

// addedColumns lists fields to add when opening an older keystore.
var addedColumns = []struct {
	name       string
	definition string
}{
	{name: "Origin", definition: "TEXT NOT NULL DEFAULT ''"},
	{name: "AndroidPackageName", definition: "TEXT NOT NULL DEFAULT ''"},
	{name: "Profile", definition: "TEXT NOT NULL DEFAULT ''"},
}

func MigrateSchema(db *sql.DB) error {
	rows, err := db.Query("PRAGMA table_info(credentials);")
	if err != nil {
		return fmt.Errorf("failed to inspect 'credentials' table: %w", err)
	}
	defer rows.Close()

	existing := make(map[string]bool)
	for rows.Next() {
		var (
			columnIndex  int
			columnName   string
			columnType   sql.NullString
			notNull      sql.NullInt64
			defaultValue sql.NullString
			primaryKey   sql.NullInt64
		)
		if err := rows.Scan(&columnIndex, &columnName, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			return fmt.Errorf("failed to read 'credentials' table info: %w", err)
		}
		existing[strings.ToLower(columnName)] = true
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("failed to iterate 'credentials' table info: %w", err)
	}

	for _, column := range addedColumns {
		if existing[strings.ToLower(column.name)] {
			continue
		}
		alterSQL := fmt.Sprintf("ALTER TABLE credentials ADD COLUMN %s %s;", column.name, column.definition)
		if _, err := db.Exec(alterSQL); err != nil {
			return fmt.Errorf("failed to add column '%s': %w", column.name, err)
		}
		logging.GetLogger().Debug("Added missing keystore column", "column", column.name)
	}

	return nil
}

// Keep this order in sync with scanCredentialEntry. COALESCE handles older rows.
const credentialColumns = `
	CredentialID,
	PrivateKeyFilePath,
	PublicKeyBytesHex,
	UserHandle,
	SignCount,
	RPIDHash,
	CreationDate,
	RPID,
	cose_algorithm,
	COALESCE(Origin, ''),
	COALESCE(AndroidPackageName, ''),
	COALESCE(Profile, '')`

type rowScanner interface {
	Scan(dest ...any) error
}

func scanCredentialEntry(row rowScanner) (CredentialEntry, error) {
	var entry CredentialEntry
	err := row.Scan(
		&entry.CredentialID,
		&entry.PrivateKeyFilePath,
		&entry.PublicKeyBytesHex,
		&entry.UserHandle,
		&entry.SignCount,
		&entry.RPIDHash,
		&entry.CreationDate,
		&entry.RPID,
		&entry.CoseAlgorithm,
		&entry.Origin,
		&entry.AndroidPackageName,
		&entry.Profile,
	)
	return entry, err
}

type MetadataWriter interface {
	Exec(query string, args ...any) (sql.Result, error)
}

func AddCredentialEntryMetadata(db MetadataWriter, metadata CredentialEntry) error {
	const insertSQL = `
	INSERT INTO credentials(
		CredentialID, 
		PrivateKeyFilePath, 
		PublicKeyBytesHex, 
		UserHandle, 
		SignCount, 
		RPIDHash, 
		CreationDate,
		RPID,
		cose_algorithm,
		Origin,
		AndroidPackageName,
		Profile
	) 
	VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := db.Exec(insertSQL,
		metadata.CredentialID,
		metadata.PrivateKeyFilePath,
		metadata.PublicKeyBytesHex,
		metadata.UserHandle,
		metadata.SignCount,
		metadata.RPIDHash,
		metadata.CreationDate,
		metadata.RPID,
		metadata.CoseAlgorithm,
		metadata.Origin,
		metadata.AndroidPackageName,
		metadata.Profile,
	)
	if err != nil {
		return fmt.Errorf("error inserting credential entry: %w", err)
	}

	return nil
}

func GetMetadataCredentialEntry(db *sql.DB, credentialID string, rpidHashHexString string) (*CredentialEntry, error) {
	sqlSELECT := `
	SELECT ` + credentialColumns + `
	FROM credentials 
    WHERE CredentialID = ? AND RPIDHash = ?
    ORDER BY CreationDate DESC 
	LIMIT 1;`

	entry, err := scanCredentialEntry(db.QueryRow(sqlSELECT, credentialID, rpidHashHexString))
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("error scanning credential entry for ID '%s': %w", credentialID, err)
	}

	return &entry, nil
}

func GetCredentialByID(db *sql.DB, credentialID string) (*CredentialEntry, error) {

	sqlSELECT := `SELECT ` + credentialColumns + ` FROM credentials WHERE CredentialID = ? LIMIT 1;`

	entry, err := scanCredentialEntry(db.QueryRow(sqlSELECT, credentialID))
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("error scanning credential entry for ID '%s': %w", credentialID, err)
	}
	return &entry, nil
}

func IncrementMetadataCredentialEntrySignCount(db *sql.DB, credentialID string) (int, error) {
	const sqlUpdateReturning = `
    UPDATE credentials
    SET SignCount = SignCount + 1
    WHERE CredentialID = ?
	RETURNING SignCount;`

	row := db.QueryRow(sqlUpdateReturning, credentialID)
	var newSignCount int
	err := row.Scan(&newSignCount)
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, fmt.Errorf("credential entry with ID '%s' not found for update", credentialID)
		}
		return 0, fmt.Errorf("error updating and returning sign count for ID '%s': %w", credentialID, err)
	}

	return newSignCount, nil
}

func ListCredentialsByRPIDHash(db *sql.DB, rpidHashHexString string) ([]CredentialEntry, error) {
	return listCredentialEntries(db, `SELECT `+credentialColumns+` FROM credentials WHERE RPIDHash = ? ORDER BY CreationDate DESC`, rpidHashHexString)
}

func ListCredentialsByRPID(db *sql.DB, rpid string) ([]CredentialEntry, error) {
	return listCredentialEntries(db, `SELECT `+credentialColumns+` FROM credentials WHERE RPID = ? ORDER BY CreationDate DESC`, rpid)
}

func ListAllCredentialEntries(db *sql.DB) ([]CredentialEntry, error) {
	return listCredentialEntries(db, `SELECT `+credentialColumns+` FROM credentials ORDER BY CreationDate DESC`)
}

func listCredentialEntries(db *sql.DB, query string, args ...any) ([]CredentialEntry, error) {
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query credential entries: %w", err)
	}
	defer rows.Close()
	entries := make([]CredentialEntry, 0)
	for rows.Next() {
		entry, err := scanCredentialEntry(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan credential entry: %w", err)
		}
		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to read credential entries: %w", err)
	}
	return entries, nil
}

func UpdateCredentialByID(db *sql.DB, credentialID string, fieldName string, newValue string) error {
	var valueToUpdate any
	var err error
	fieldNameLower := strings.ToLower(fieldName)
	columnName := ""

	switch fieldNameLower {
	case "privatekeyfilepath":
		columnName = "PrivateKeyFilePath"
		valueToUpdate = newValue
	case "publickeybyteshex":
		columnName = "PublicKeyBytesHex"
		valueToUpdate = newValue
	case "userhandle":
		columnName = "UserHandle"
		valueToUpdate = newValue
	case "rpidhash":
		columnName = "RPIDHash"
		valueToUpdate = newValue
	case "creationdate":
		columnName = "CreationDate"
		valueToUpdate = newValue
	case "rpid":
		columnName = "RPID"
		valueToUpdate = newValue
	case "origin":
		columnName = "Origin"
		valueToUpdate = newValue
	case "androidpackagename":
		columnName = "AndroidPackageName"
		valueToUpdate = newValue
	case "profile":
		columnName = "Profile"
		valueToUpdate = newValue

	case "signcount":
		columnName = "SignCount"
		valueToUpdate, err = strconv.Atoi(newValue)
		if err != nil {
			return fmt.Errorf("invalid value for SignCount: must be an integer")
		}

	case "cosealgorithm", "cose_algorithm":
		columnName = "cose_algorithm"
		valueToUpdate, err = strconv.ParseInt(newValue, 10, 64)
		if err != nil {
			return fmt.Errorf("invalid value for CoseAlgorithm: must be an integer")
		}
	default:
		return fmt.Errorf("invalid field name provided: '%s'", fieldName)
	}

	sqlUPDATE := fmt.Sprintf("UPDATE credentials SET %s = ? WHERE CredentialID = ?;", columnName)
	result, err := db.Exec(sqlUPDATE, valueToUpdate, credentialID)
	if err != nil {
		return fmt.Errorf("database error during update: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("could not verify update: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("no credential found with ID '%s'", credentialID)
	}

	return nil
}
