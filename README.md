# Automate Sensitive Data Scanner

A robust Python tool for scanning SQL Server databases to identify sensitive data fields. This tool helps data governance teams discover and inventory fields that may contain sensitive personal information, PII, or other protected data types.

## Features

- Automatically scans SQL Server databases for sensitive data
- Compares database fields against known sensitive data reference tables
- Supports SQL Server authentication and Windows authentication
- Tracks processed fields to avoid redundant checks
- Records identified sensitive fields with detailed metadata
- Configurable matching thresholds
- Comprehensive logging for audit trails

## Prerequisites

- Python 3.7+
- SQL Server with ODBC Driver 17 for SQL Server
- Appropriate database permissions

## Installation

1. Clone this repository:
   ```
   git clone https://github.com/yourusername/automate-flaging-data-sensitive.git
   cd automate-flaging-data-sensitive
   ```

2. Install required packages:
   ```
   pip install -r requirements.txt
   ```

## Configuration

Before running the tool, you need:

1. A reference table in your SQL Server database that contains examples of known sensitive data fields
2. Appropriate SQL Server permissions to access and query the target databases

The default reference table structure is:
- `[your_database].[your_schema].[your_table_reference_CDE]` with columns:
  - `server_name`
  - `database_name`
  - `table_name`
  - `field_name`
  - `type_data`
  - `status`

## Usage

### Basic Usage

```python
from sensitive_data_scanner import SensitiveDataScanner

# Initialize with a connection string
scanner = SensitiveDataScanner(
    connection_string="mssql://server:port/database?trusted_connection=true"
)

# Run the scan
scanner.scan_for_sensitive_data()
```

### Command Line Usage

```
python sensitive_data_scanner.py --connection "mssql://server:port/database?trusted_connection=true"
```

### Connection Parameters

You can connect using either:

1. A connection string (URL format):
   ```
   mssql://server:port/database?trusted_connection=true&driver=ODBC+Driver+17+for+SQL+Server
   ```

2. Individual parameters:
   ```python
   scanner = SensitiveDataScanner(
       server="server_name,port",
       database="database_name",
       trusted_connection=True
   )
   ```

## How It Works

1. **Database Selection**: The tool queries `sys.databases` to get a list of databases to scan
2. **Schema Discovery**: For each database, the tool discovers all available schemas
3. **Reference Gathering**: The tool queries the reference table to get a list of known sensitive data fields
4. **Field Analysis**: For each field in each table in each schema, the tool:
   - Checks if the field has already been processed (skips if it has)
   - Compares data types to ensure compatibility
   - Executes a query to find matching records between the field and reference data
   - If the number of matches exceeds the threshold, marks the field as sensitive
5. **Result Tracking**: Found sensitive fields are stored in a tracking table with metadata

## Output Tables

The tool creates two tracking tables:

1. `processed_fields` - Records which fields have been processed
2. `sensitive_fields` - Records fields identified as containing sensitive data

## Customization

You can modify the following aspects:

- Change the reference table query in `get_sensitive_data_references()`
- Adjust the match threshold (default is 10000) in `scan_for_sensitive_data()`
- Modify the database exclusion list in `get_database_list()`

## Best Practices

- Run during off-peak hours to minimize performance impact
- Start with a small subset of databases for testing
- Regularly review the identified sensitive fields for false positives
- Use appropriate database permissions (read-only if possible)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

Project owner RIZA GUMELAR :)