# -*- coding: utf-8 -*- 

NAME = 'Yet Another Web Fuzz'
VERSION = '1.0'
AUTHOR = 'Yns0ng'

PAYLOAD = '[fuzz]'

VULS_TYPE = [
    'XSS',
    'SQLI',
    'RFI',
    'DT'
]

THREADS_NUM = 10

DBMS_ERRORS = {
    "MySQL": (r"SQL syntax.*MySQL", r"Warning.*mysql_.*", r"valid MySQL result", r"MySqlClient\."),
    "PostgreSQL": (r"PostgreSQL.*ERROR", r"Warning.*\Wpg_.*", r"valid PostgreSQL result", r"Npgsql\."),
    "Microsoft SQL Server": (r"Driver.* SQL[\-\_\ ]*Server", r"OLE DB.* SQL Server", r"(\W|\A)SQL Server.*Driver",
                             r"Warning.*mssql_.*", r"(\W|\A)SQL Server.*[0-9a-fA-F]{8}",
                             r"(?s)Exception.*\WSystem\.Data\.SqlClient\.", r"(?s)Exception.*\WRoadhouse\.Cms\."),
    "Microsoft Access": (r"Microsoft Access Driver", r"JET Database Engine", r"Access Database Engine"),
    "Oracle": (r"\bORA-[0-9][0-9][0-9][0-9]", r"Oracle error", r"Oracle.*Driver", r"Warning.*\Woci_.*", r"Warning.*\Wora_.*"),
    "IBM DB2": (r"CLI Driver.*DB2", r"DB2 SQL error", r"\bdb2_\w+\("),
    "SQLite": (r"SQLite/JDBCDriver", r"SQLite.Exception", r"System.Data.SQLite.SQLiteException", r"Warning.*sqlite_.*",
               r"Warning.*SQLite3::", r"\[SQLITE_ERROR\]"),
    "Sybase": (r"(?i)Warning.*sybase.*", r"Sybase message", r"Sybase.*Server message.*"),
}

HTTP_METHOD = {
    "GET": "GET",
    "POST": "POST"
}

HTTP_HEADER = {
    "COOKIE": "Cookie",
    "PROXY_CONNECTION": "Proxy-Connection",
    "CONNECTION": "Connection"
}
