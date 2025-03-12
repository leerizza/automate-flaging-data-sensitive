import pyodbc as db
import urllib.parse
from datetime import datetime
import re
import logging


# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class SensitiveDataScanner:
    def __init__(self, connection_string=None, server=None, database=None, trusted_connection=None):
        """Initialize the scanner with MS SQL Server connection parameters"""
        # Parse connection string if provided
        if connection_string:
            self.parse_connection_string(connection_string)
        else:
            self.server = server
            self.database = database
            self.trusted_connection = trusted_connection
        
        self.conn = None
        self.cursor = None
        
    def parse_connection_string(self, connection_string):
        """Parse a connection string in the format: 'mssql://server:port/database?params'"""
        # Remove the protocol part
        if connection_string.startswith('mssql://'):
            connection_string = connection_string[8:]
        
        # Split the connection string into parts
        server_part, rest = connection_string.split('/', 1)
        
        # Extract server and port
        if ':' in server_part:
            self.server, port = server_part.split(':')
            self.server = f"{self.server},{port}"
        else:
            self.server = server_part
        
        # Extract database and parameters
        if '?' in rest:
            self.database, params_str = rest.split('?', 1)
            # Parse parameters
            params = dict(urllib.parse.parse_qsl(params_str))
            self.trusted_connection = params.get('trusted_connection', 'false').lower() == 'true'
        else:
            self.database = rest
            self.trusted_connection = False
    
    def sanitize_string(self, value):
        """Sanitize a string by removing invalid characters"""
        if value is None:
            return None
        
        # Convert to string if it's not already
        if not isinstance(value, str):
            value = str(value)
            
        # Remove NULL bytes and control characters
        value = re.sub(r'[\x00-\x1F\x7F]', '', value)
        
        # Remove invalid Unicode characters
        value = ''.join(c for c in value if ord(c) < 0xD800 or 0xDFFF < ord(c))
        
        return value
            
    def connect(self):
        """Establish connection to MS SQL Server database"""
        try:
            if self.trusted_connection:
                connection_str = f"DRIVER={{ODBC Driver 17 for SQL Server}};SERVER={self.server};DATABASE={self.database};Trusted_Connection=yes;"
            else:
                # In a real scenario, you would handle username/password here
                connection_str = f"DRIVER={{ODBC Driver 17 for SQL Server}};SERVER={self.server};DATABASE={self.database};"
            
            self.conn = db.connect(connection_str)
            self.cursor = self.conn.cursor()
            logger.info(f"Successfully connected to SQL Server: {self.server}, Database: {self.database}")
            return True
        except Exception as e:
            logger.error(f"Connection error: {str(e)}")
            return False
            
    def close(self):
        """Close the database connection"""
        if self.cursor:
            self.cursor.close()
        if self.conn:
            self.conn.close()
        logger.info("Database connection closed")
        
    def get_sensitive_data_references(self):
        """Get list of sensitive data references from the reference table"""
        try:
            query = """
                SELECT 
                    CAST(server_name AS VARCHAR(255)) AS server_name, 
                    CAST(database_name AS VARCHAR(255)) AS database_name, 
                    CAST(table_name AS VARCHAR(255)) AS table_name, 
                    CAST(field_name AS VARCHAR(255)) AS field_name,
                    CAST(type_data AS VARCHAR(255)) AS type_data,
                    CAST(status AS VARCHAR(50)) AS status
                FROM [your_db].[your_schema].[your_ref_CDE_data_sensitive]
            """
            
            self.cursor.execute(query)
            
            sensitive_data_references = []
            for row in self.cursor.fetchall():
                # Sanitize all string values to remove invalid characters
                sensitive_data_references.append({
                    'server_name': self.sanitize_string(row[0]),
                    'database_name': self.sanitize_string(row[1]),
                    'table_name': self.sanitize_string(row[2]),
                    'field_name': self.sanitize_string(row[3]),
                    'type_data': self.sanitize_string(row[4]),
                    'status': self.sanitize_string(row[5])
                })
            
            return sensitive_data_references
        except Exception as e:
            logger.error(f"Error ketika mengambil nilai sensitive data references: {str(e)}")
            # Log the full traceback for debugging
            import traceback
            logger.error(traceback.format_exc())
            return []
            
    def get_database_list(self):
        """Get list of databases excluding system databases"""
        excluded_databases = [
            ('your_db_want_to_exclude')
        ]
        
        try:
            self.cursor.execute("SELECT name FROM sys.databases WHERE name IN ('your_db')")
            
            databases = []
            for row in self.cursor.fetchall():
                databases.append(self.sanitize_string(row[0]))
            
            return databases
        except Exception as e:
            logger.error(f"Error ketika mengambil nilai database list: {str(e)}")
            return []
    
    def get_schemas_in_database(self, database):
        """Get list of schemas in a database"""
        try:
            # Sanitize the database name to prevent SQL injection
            database = self.sanitize_string(database)
            
            self.cursor.execute(f"USE [{database}]")
            self.cursor.execute("SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA")
            
            schemas = []
            for row in self.cursor.fetchall():
                schema = self.sanitize_string(row[0])
                if schema not in ['sys', 'INFORMATION_SCHEMA']:
                    schemas.append(schema)
            
            return schemas
        except Exception as e:
            logger.error(f"Error ketika mengambil nilai schemas didalam database {database}: {str(e)}")
            return []
            
    def get_comparable_data_types(self, type_data):
        """Get list of comparable data types for a given reference data type"""
        try:
            # Sanitize the type_data to prevent SQL injection
            type_data = self.sanitize_string(type_data)
            
            query = f"""
                SELECT datatypecompare 
                FROM [your_schema].[your_table]
                WHERE datatype_ref = '{type_data}'
            """
            
            self.cursor.execute(query)
            
            return [self.sanitize_string(row[0]) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Error retrieving comparable data types: {str(e)}")
            # Default mappings if table doesn't exist
            if type_data.lower() in ['varchar', 'char', 'nvarchar', 'nchar', 'text', 'ntext']:
                return ['varchar', 'char', 'nvarchar', 'nchar', 'text', 'ntext']
            elif type_data.lower() in ['int', 'integer', 'smallint', 'bigint', 'tinyint']:
                return ['int', 'integer', 'smallint', 'bigint', 'tinyint']
            elif type_data.lower() in ['float', 'real', 'decimal', 'numeric', 'money', 'smallmoney']:
                return ['float', 'real', 'decimal', 'numeric', 'money', 'smallmoney']
            elif type_data.lower() in ['date', 'datetime', 'datetime2', 'smalldatetime']:
                return ['date', 'datetime', 'datetime2', 'smalldatetime']
            else:
                return [type_data]
            
    def get_fields_to_check(self, database, schema, ref_server, ref_db, ref_table, ref_field):
        """Get list of fields to check in a specific schema"""
        try:
            # Sanitize all input parameters
            database = self.sanitize_string(database)
            schema = self.sanitize_string(schema)
            ref_server = self.sanitize_string(ref_server)
            ref_db = self.sanitize_string(ref_db)
            ref_table = self.sanitize_string(ref_table)
            ref_field = self.sanitize_string(ref_field)
            
            # Use the specified database
            self.cursor.execute(f"USE [{database}]")
            
            # Get list of tables in schema
            self.cursor.execute(f"""
                SELECT TABLE_NAME
                FROM INFORMATION_SCHEMA.TABLES
                WHERE TABLE_SCHEMA = '{schema}'
                AND TABLE_TYPE = 'BASE TABLE'
            """)
            tables = [self.sanitize_string(row[0]) for row in self.cursor.fetchall()]
            
            # Check if tracking table exists
            processed_table_exists = False
            try:
                self.cursor.execute(f"SELECT TOP 1 1 FROM processed_fields")
                processed_table_exists = True
            except:
                pass
                
            fields = []
            for table in tables:
                # Get column information for this table
                self.cursor.execute(f"""
                    SELECT COLUMN_NAME, DATA_TYPE
                    FROM INFORMATION_SCHEMA.COLUMNS
                    WHERE TABLE_SCHEMA = '{schema}'
                    AND TABLE_NAME = '{table}'
                """)
                
                for column_info in self.cursor.fetchall():
                    column_name = self.sanitize_string(column_info[0])
                    data_type = self.sanitize_string(column_info[1])
                    
                    # Skip if field has already been processed
                    if processed_table_exists:
                        check_query = f"""
                            SELECT TOP 1 1 FROM processed_fields
                            WHERE database_name = '{database}'
                            AND schema_name = '{schema}'
                            AND table_name = '{table}'
                            AND column_name = '{column_name}'
                            AND ref_server = '{ref_server}'
                            AND ref_db = '{ref_db}'
                            AND ref_table = '{ref_table}'
                            AND ref_field = '{ref_field}'
                        """
                        
                        self.cursor.execute(check_query)
                        if self.cursor.fetchone():
                            continue
                    
                    fields.append({
                        'database': database,
                        'schema': schema,
                        'table': table,
                        'column': column_name,
                        'data_type': data_type
                    })
            
            return fields
        except Exception as e:
            logger.error(f"Error ketika mengambil nilai fields untuk pengecekan didalam {database}.{schema}: {str(e)}")
            return []
            
    def check_matching_records(self, field_info, ref_db, ref_table, ref_field):
        """Check how many matching records exist between two fields"""
        try:
            # Sanitize all input parameters
            database = self.sanitize_string(field_info['database'])
            schema = self.sanitize_string(field_info['schema'])
            table = self.sanitize_string(field_info['table'])
            column = self.sanitize_string(field_info['column'])
            ref_db = self.sanitize_string(ref_db)
            ref_table = self.sanitize_string(ref_table)
            ref_field = self.sanitize_string(ref_field)
            
            # Use 4-part naming for cross-database queries in SQL Server
            query = f"""
            SELECT TOP 100 COUNT(DISTINCT b.[{ref_field}])
            FROM [{database}].[{schema}].[{table}] a
            INNER JOIN [{ref_db}].[dbo].[{ref_table}] b 
            ON a.[{column}] = b.[{ref_field}]
            WHERE b.[{ref_field}] IS NOT NULL
            AND LTRIM(RTRIM(CONVERT(VARCHAR(MAX), b.[{ref_field}]))) != ''
            AND b.[{ref_field}] NOT IN ('N/A', '-')
            """
            
            self.cursor.execute(query)
            count = self.cursor.fetchone()[0]
            return count
        except Exception as e:
            logger.error(f"Error checking matching records: {str(e)}")
            return 0
            
    def ensure_tracking_tables_exist(self):
        """Create tracking tables if they don't exist"""
        try:
            # Create table for tracking processed fields
            processed_table_query = """
            IF NOT EXISTS (SELECT * FROM sys.objects WHERE object_id = OBJECT_ID(N'processed_fields') AND type in (N'U'))
            BEGIN
                CREATE TABLE processed_fields (
                    id BIGINT IDENTITY(1,1) PRIMARY KEY,
                    database_name VARCHAR(255),
                    schema_name VARCHAR(255),
                    table_name VARCHAR(255),
                    column_name VARCHAR(255),
                    ref_server VARCHAR(255),
                    ref_db VARCHAR(255),
                    ref_table VARCHAR(255),
                    ref_field VARCHAR(255),
                    process_date DATETIME
                )
            END
            """
            self.cursor.execute(processed_table_query)
            
                      
    def mark_as_sensitive(self, field_info, server_name, db_name, table_name, field_name):
        """Mark a field as sensitive in the tracking table"""
        try:
            # Sanitize all input parameters
            database = self.sanitize_string(field_info['database'])
            schema = self.sanitize_string(field_info['schema'])
            table = self.sanitize_string(field_info['table'])
            column = self.sanitize_string(field_info['column'])
            data_type = self.sanitize_string(field_info['data_type'])
            server_name = self.sanitize_string(server_name)
            db_name = self.sanitize_string(db_name)
            table_name = self.sanitize_string(table_name)
            field_name = self.sanitize_string(field_name)
            
            params = (
                database, schema, table, column,
                data_type, 'Sensitive', server_name, db_name, table_name, field_name
            )
            
            self.cursor.execute(query, params)
            self.conn.commit()
            logger.info(f"Marked field as sensitive: {database}.{schema}.{table}.{column}")
            return True
        except Exception as e:
            logger.error(f"Error marking field as sensitive: {str(e)}")
            return False
            
    def mark_as_processed(self, field_info, server_name, db_name, table_name, field_name):
        """Mark a field as processed in the tracking table"""
        try:
            # Sanitize all input parameters
            database = self.sanitize_string(field_info['database'])
            schema = self.sanitize_string(field_info['schema'])
            table = self.sanitize_string(field_info['table'])
            column = self.sanitize_string(field_info['column'])
            server_name = self.sanitize_string(server_name)
            db_name = self.sanitize_string(db_name)
            table_name = self.sanitize_string(table_name)
            field_name = self.sanitize_string(field_name)
            
            query = """
                INSERT INTO [DQ_DEV].[dbo].[processed_fields] (
                    database_name, schema_name, table_name, column_name, 
                    ref_server, ref_db, ref_table, ref_field, process_date
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, GETDATE())
            """
            
            params = (
                database, schema, table, column,
                server_name, db_name, table_name, field_name
            )
            
            self.cursor.execute(query, params)
            self.conn.commit()
            logger.info(f"Marked field as processed: {database}.{schema}.{table}.{column}")
            return True
        except Exception as e:
            logger.error(f"Error marking field as processed: {str(e)}")
            return False
    
    def scan_for_sensitive_data(self):
        """Main method to scan for sensitive data across databases"""
        if not self.connect():
            return False
            
        try:
            # Make sure tracking tables exist
            if not self.ensure_tracking_tables_exist():
                return False
            
            # Get sensitive data references
            sensitive_data_refs = self.get_sensitive_data_references()
            logger.info(f"Found {len(sensitive_data_refs)} sensitive data references to check")
            
            # Process each sensitive data reference
            for ref in sensitive_data_refs:
                logger.info(f"Processing reference: {ref['database_name']}.{ref['table_name']}.{ref['field_name']}")
                
                # Get list of databases to check
                databases = self.get_database_list()
                logger.info(f"Found {len(databases)} databases to check")
                
                # Process each database
                for database in databases:
                    logger.info(f"Checking database: {database}")
                    
                    # Get schemas within the database
                    schemas = self.get_schemas_in_database(database)
                    logger.info(f"Found {len(schemas)} schemas in database {database}")
                    
                    # Get comparable data types
                    comparable_types = self.get_comparable_data_types(ref['type_data'])
                    
                    # Process each schema
                    for schema in schemas:
                        logger.info(f"Checking schema: {database}.{schema}")
                        
                        # Get fields to check within the schema
                        fields = self.get_fields_to_check(
                            database,
                            schema,
                            ref['server_name'], 
                            ref['database_name'], 
                            ref['table_name'], 
                            ref['field_name']
                        )
                        logger.info(f"Found {len(fields)} fields to check in schema {database}.{schema}")
                        
                        # Check each field
                        for field in fields:
                            # Extract base data type for comparison
                            base_type = field['data_type'].lower()
                            
                            # Skip if data types cannot be compared
                            if not any(comp_type in base_type for comp_type in comparable_types):
                                self.mark_as_processed(
                                    field,
                                    ref['server_name'],
                                    ref['database_name'],
                                    ref['table_name'],
                                    ref['field_name']
                                )
                                continue
                                
                            # Check how many records match
                            match_count = self.check_matching_records(
                                field,
                                ref['database_name'],
                                ref['table_name'],
                                ref['field_name']
                            )
                            
                            # If match count exceeds threshold, mark as sensitive
                            if match_count >= 10000:
                                self.mark_as_sensitive(
                                    field,
                                    ref['server_name'],
                                    ref['database_name'],
                                    ref['table_name'],
                                    ref['field_name']
                                )
                            
                            # Mark as processed
                            self.mark_as_processed(
                                field,
                                ref['server_name'],
                                ref['database_name'],
                                ref['table_name'],
                                ref['field_name']
                            )
            
            logger.info("Sensitive data scan completed successfully")
            return True
        except Exception as e:
            logger.error(f"Error during sensitive data scan: {str(e)}")
            return False
        finally:
            self.close()


# Example usage
if __name__ == "__main__":
    # Initialize scanner with MS SQL Server connection parameters from URL
    scanner = SensitiveDataScanner(
        connection_string="mssql://dwdb:1433/DQ_DEV?trusted_connection=true&driver=ODBC+Driver+17+for+SQL+Server&charset=utf8"
        
    )
    
    # Run the scan
    scanner.scan_for_sensitive_data()