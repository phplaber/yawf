# -*- coding: utf-8 -*-

import importlib
from core.utils.utils import get_conf


class Db:
    def __init__(self):
        self.conn = None
        self.connect()

    def connect(self):

        mysqldb = None
        if get_conf('DB', 'host'):
            try:
                mysqldb = importlib.import_module('MySQLdb')
            except Exception as e:
                pass

        if mysqldb is not None:
            try:
                self.conn = mysqldb.connect(
                    host=get_conf('DB', 'host'),
                    port=int(get_conf('DB', 'port')) if get_conf('DB', 'port') else 3306,
                    user=get_conf('DB', 'user'),
                    passwd=get_conf('DB', 'passwd'),
                    db=get_conf('DB', 'db') if get_conf('DB', 'db') else 'yawf'
                )
            except Exception as e:
                print str(e)

    def create(self):

        sql = """
            CREATE TABLE `vulnerability` (
              `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
              `request` text COMMENT '原始请求',
              `payload` text NOT NULL COMMENT '测试载荷',
              `poc` text NOT NULL COMMENT 'PoC',
              `type` varchar(100) NOT NULL DEFAULT '' COMMENT '漏洞类型',
            PRIMARY KEY (`id`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8;
        """

        try:
            self.connect()

            cur = self.conn.cursor()
            table_not_exists = False
            try:
                cur.execute('SELECT 1 FROM vulnerability LIMIT 1')
            except Exception as e:
                table_not_exists = True

            if table_not_exists:
                cur.execute(sql)
            self.conn.commit()

        except Exception as e:
            self.conn.rollback()

        self.conn.close()

    def save(self, item):

        sql = """
            INSERT INTO vulnerability
            (request, payload, poc, type)
            VALUES (%s,%s,%s,%s)
        """

        try:
            self.connect()

            cur = self.conn.cursor()
            cur.execute(sql, (str(item['request']), str(item['payload']), str(item['poc']), str(item['type'])))
            self.conn.commit()

        except Exception as e:
            self.conn.rollback()

        self.conn.close()



