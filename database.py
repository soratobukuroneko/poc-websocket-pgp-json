import sqlite3

class DataBase():
    def __init__(self, dbfile):
        self._connection = sqlite3.connect(dbfile)
        self._init_database()

    def _init_database(self):
        cursor = self._connection.cursor()
        cursor.execute("PRAGMA foreign_keys = ON")
        cursor.execute("""CREATE TABLE IF NOT EXISTS config
            (key TEXT NOT NULL PRIMARY KEY,
             value TEXT)""")
        cursor.execute("""CREATE TABLE IF NOT EXISTS users
            (fingerprint TEXT NOT NULL PRIMARY KEY,
             access_level INTEGER NOT NULL)""")
        cursor.execute("""CREATE TABLE IF NOT EXISTS data_key_relation
            (data INTEGER NOT NULL,
             user TEXT NOT NULL,
             FOREIGN KEY(data) REFERENCES encrypted_data(id),
             FOREIGN KEY(user) REFERENCES users(fingerprint))""")
        cursor.execute("""CREATE TABLE IF NOT EXISTS encrypted_data
            (id INTEGER PRIMARY KEY AUTOINCREMENT,
             secret TEXT)""")
        self._connection.commit()

    def addUser(self, fingerprint: str, access_level: int):
        cursor = self._connection.cursor()
        cursor.execute("INSERT INTO users VALUES (:fpr, :level)", { "fpr": fingerprint, "level": access_level })
        self._connection.commit()

    def deleteUser(self, fingerprint):
        cursor = self._connection.cursor()
        cursor.execute("DELETE FROM users WHERE fingerprint=:fpr", { "fpr": fingerprint })
        self._connection.commit()

    def getConfig(self, key: str):
        cursor = self._connection.cursor()
        cursor.execute("SELECT value FROM config WHERE key=:key", { "key": key })
        value = cursor.fetchone()
        if value:
            value = value[0]
        return value

    def getUser(self, fingerprint=None):
        cursor = self._connection.cursor()
        if fingerprint == None:
            cursor.execute("SELECT * FROM users")
            query_results = cursor.fetchall()
            if query_results is not None:
                return [{ "fingerprint": row[0], "access_level": row[1] } for row in query_results]
        else:
            cursor.execute("SELECT * FROM users wHERE fingerprint=:fpr", { "fpr": fingerprint })
            query_result = cursor.fetchone()
            if query_result is not None:
                return { "fingerprint": query_result[0], "access_level": query_result[1] }

    def setConfig(self, key: str, value: str):
        cursor = self._connection.cursor()
        cursor.execute("""INSERT INTO config VALUES (:key, :value)
            ON CONFLICT(key) DO UPDATE SET value = :value""", { "key": key, "value": value })
        self._connection.commit()
