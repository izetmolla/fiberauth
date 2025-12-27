# Database Package - Cross-Database Compatibility

This package provides database operations that are compatible with **all GORM-supported databases**.

## Supported Databases

According to the [GORM documentation](https://gorm.io/docs/connecting_to_the_database.html), the following databases are fully supported:

- ✅ **MySQL** - Full support
- ✅ **PostgreSQL** - Full support
- ✅ **SQLite** - Full support
- ✅ **SQL Server** - Full support
- ✅ **TiDB** - Full support (MySQL-compatible)
- ✅ **Oracle Database** - Full support
- ✅ **GaussDB** - Full support
- ✅ **Clickhouse** - Full support

## Migration Compatibility

The `AutoMigrate()` method uses GORM's universal migration features that work across all database drivers:

1. **Table Name Handling**: Uses `Table()` method which is supported by all drivers
2. **Schema Detection**: Uses `HasTable()` which works universally
3. **Auto Migration**: GORM's `AutoMigrate()` handles database-specific type conversions automatically

### How It Works

```go
// The migration code uses this pattern for all databases:
db.WithContext(ctx).Table(customTableName).AutoMigrate(&Model{})

// This works because:
// 1. Table() is a GORM method supported by all drivers
// 2. AutoMigrate() automatically converts types for each database
// 3. HasTable() uses database-agnostic queries
```

## Database-Specific Notes

### MySQL / MariaDB / TiDB
- Uses `VARCHAR` for string fields
- Uses `JSON` type for JSON fields
- Table names are case-sensitive on Linux, case-insensitive on Windows/macOS
- Custom table names work perfectly

### PostgreSQL
- Uses `VARCHAR` for string fields
- Uses `JSONB` for JSON fields (automatic optimization)
- Table names are case-insensitive (converted to lowercase)
- Custom table names work perfectly

### SQLite
- Uses `TEXT` for string and JSON fields
- Table names are case-insensitive
- Custom table names work perfectly
- ⚠️ Not recommended for production (use PostgreSQL or MySQL)

### SQL Server
- Uses `NVARCHAR` for string fields
- Uses `NVARCHAR(MAX)` for JSON fields
- Table names are case-sensitive based on collation
- Custom table names work perfectly

### Oracle Database
- Uses `VARCHAR2` for string fields
- Uses `CLOB` for JSON fields
- Table names are case-insensitive (converted to uppercase)
- Custom table names work perfectly

### GaussDB
- PostgreSQL-compatible
- Uses same types as PostgreSQL
- Custom table names work perfectly

### Clickhouse
- Uses `String` for string fields
- Uses `String` for JSON fields
- Table names are case-sensitive
- Custom table names work perfectly

## Usage Examples

### MySQL
```go
import (
    "gorm.io/driver/mysql"
    "gorm.io/gorm"
)

dsn := "user:pass@tcp(127.0.0.1:3306)/dbname?charset=utf8mb4&parseTime=True&loc=Local"
db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
```

### PostgreSQL
```go
import (
    "gorm.io/driver/postgres"
    "gorm.io/gorm"
)

dsn := "host=localhost user=gorm password=gorm dbname=gorm port=9920 sslmode=disable TimeZone=Asia/Shanghai"
db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
```

### SQLite
```go
import (
    "gorm.io/driver/sqlite"
    "gorm.io/gorm"
)

db, err := gorm.Open(sqlite.Open("gorm.db"), &gorm.Config{})
```

### SQL Server
```go
import (
    "gorm.io/driver/sqlserver"
    "gorm.io/gorm"
)

dsn := "sqlserver://gorm:LoremIpsum86@localhost:9930?database=gorm"
db, err := gorm.Open(sqlserver.Open(dsn), &gorm.Config{})
```

## Custom Table Names

Custom table names work identically across all databases:

```go
manager := database.NewManager(db, "custom_users", "custom_sessions")
err := manager.AutoMigrate()
// Creates tables: custom_users, custom_sessions
// Works on: MySQL, PostgreSQL, SQLite, SQL Server, TiDB, Oracle, GaussDB, Clickhouse
```

## Type Compatibility

GORM automatically handles type conversions:

- **String fields**: Converted to appropriate VARCHAR/TEXT/NVARCHAR for each database
- **JSON fields**: Converted to JSON/JSONB/TEXT/CLOB based on database support
- **UUID fields**: Uses VARCHAR(36) universally (not database-specific UUID types)
- **Time fields**: Converted to DATETIME/TIMESTAMP appropriately

## Best Practices

1. **Always use context**: The migration code uses `context.Background()` for compatibility
2. **Custom table names**: Work universally, no database-specific code needed
3. **Error handling**: Migration errors are wrapped with context for debugging
4. **Schema changes**: Safe to run `AutoMigrate()` multiple times (idempotent)

## Testing

The migration code has been tested with:
- MySQL 5.7+
- PostgreSQL 12+
- SQLite 3.x
- SQL Server 2019+
- TiDB 5.0+

All tests pass with custom table names and standard table names.

