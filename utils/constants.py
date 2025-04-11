VERSION = 'v3.0.0'

UA = 'Yawf ' + VERSION

MARK_POINT = '[fuzz]'

DBMS_ERRORS = {
    "MySQL": (r"SQL syntax.*MySQL", r"Warning.*mysql_.*", r"valid MySQL result", r"MySqlClient\."),
    "Oracle": (r"\bORA-[0-9][0-9][0-9][0-9]", r"Oracle error", r"Oracle.*Driver", r"Warning.*\Woci_.*", r"Warning.*\Wora_.*"),
    "Microsoft SQL Server": (r"Driver.* SQL[\-\_\ ]*Server", r"OLE DB.* SQL Server", r"(\W|\A)SQL Server.*Driver",
                             r"Warning.*mssql_.*", r"(\W|\A)SQL Server.*[0-9a-fA-F]{8}",
                             r"(?s)Exception.*\WSystem\.Data\.SqlClient\.", r"(?s)Exception.*\WRoadhouse\.Cms\."),
    "PostgreSQL": (r"PostgreSQL.*ERROR", r"Warning.*\Wpg_.*", r"valid PostgreSQL result", r"Npgsql\."),
    "SQLite": (r"SQLite/JDBCDriver", r"SQLite.Exception", r"System.Data.SQLite.SQLiteException", r"Warning.*sqlite_.*",
               r"Warning.*SQLite3::", r"\[SQLITE_ERROR\]"),
    "IBM DB2": (r"CLI Driver.*DB2", r"DB2 SQL error", r"\bdb2_\w+\("),
    "Microsoft Access": (r"Microsoft Access Driver", r"JET Database Engine", r"Access Database Engine"),
    "Sybase": (r"(?i)Warning.*sybase.*", r"Sybase message", r"Sybase.*Server message.*"),
}

DIFF_THRESHOLD = 0.95

REQ_TIMEOUT = 30.0

REQ_SCHEME = 'https'

PROBE = 'xss'

PLATFORM = 'linux'

EFFICIENCY_CONF = {
    # 自动标记忽略的参数
    'ignore_params': {
        '_', 
        'sid', 
        's_id', 
        'session', 
        'session_id', 
        'sessionid', 
        'sessionId', 
        'session_key', 
        'session_token', 
        'session_var', 
        'auth_token', 
        'auth_key', 
        'auth_session_id', 
        'auth_id', 
        'remember_me', 
        'rememberMe', 
        'csrftoken', 
        'csrf_token', 
        'CSRFToken', 
        'access_token', 
        'authentication_token', 
        'timestamp', 
        'JSESSIONID', 
        'PHPSESSID', 
        'ASPSESSIONID'
    },
    # dt 和 ssrf 探针检测参数（包含匹配）
    'dt_and_ssrf_detect_params' : {
        'file', 
        'path', 
        'dir', 
        'src', 
        'dest', 
        'target', 
        'redirect', 
        'folder', 
        'source', 
        'link', 
        'url', 
        'api'
    },
    # 敏感信息关键词
    'sens_info_keywords': {
        'username', 
        'birthday', 
        'employer', 
        'income', 
        'address', 
        'home_address', 
        'phone', 
        'phone_number', 
        'email', 
        'email_address', 
        'id_card', 
        'passport', 
        'passport_number', 
        'uid', 
        'account', 
        'password', 
        'passwd', 
        'account_balance', 
        'transaction_records', 
        'payment_information', 
        'bank_account', 
        'bank_account_number', 
        'credit_card', 
        'credit_card_number', 
        'alipay_account', 
        'wechat_pay_account'
    }
}
