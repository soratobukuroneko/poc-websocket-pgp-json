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
        cursor.execute("""CREATE TABLE IF NOT EXISTS forms
            (id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
             name TEXT UNIQUE NOT NULL)""")
        cursor.execute("""CREATE TABLE IF NOT EXISTS users
            (fingerprint TEXT NOT NULL PRIMARY KEY,
             access_level INTEGER NOT NULL)""")
        cursor.execute("""CREATE TABLE IF NOT EXISTS encrypted_data
            (id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
             form INTEGER NOT NULL,
             secret TEXT,
             need_reencryption BOOLEAN NOT NULL,
             CHECK(need_reencryption IN(0, 1))
             FOREIGN KEY(form) REFERENCES forms(id))""")
        cursor.execute("""CREATE TABLE IF NOT EXISTS form_key_relation
            (form INTEGER NOT NULL,
             fingerprint TEXT NOT NULL,
             FOREIGN KEY(form) REFERENCES forms(id),
             FOREIGN KEY(fingerprint) REFERENCES users(fingerprint))""")
        self._connection.commit()

    def add_user(self, fingerprint: str, access_level: int):
        cursor = self._connection.cursor()
        cursor.execute("INSERT INTO users VALUES (:fpr, :level)", { "fpr": fingerprint, "level": access_level })
        self._connection.commit()

    def delete_user(self, fingerprint):
        cursor = self._connection.cursor()
        cursor.execute("DELETE FROM users WHERE fingerprint = :fpr", { "fpr": fingerprint })
        self._connection.commit()

    def get_collected_data(self, form_name: str):
        cursor = self._connection.cursor()
        cursor.execute("""SELECT encrypted_data.id, secret, need_reencryption FROM encrypted_data
            JOIN forms ON forms.id = encrypted_data.form
            WHERE forms.name = :name""", { "name": form_name })
        query_results = cursor.fetchall()

        return {
            "form": form_name,
            "collected_data": [{ "id": row[0], "secret": row[1], "need_reencryption": bool(row[2]) }
                                for row in query_results]
        }

    def get_config(self, key: str):
        cursor = self._connection.cursor()
        cursor.execute("SELECT value FROM config WHERE key = :key", { "key": key })
        value = cursor.fetchone()
        if value:
            value = value[0]
        return value

    def get_form_keys_fingerprints(self, form_name: str):
        cursor = self._connection.cursor()
        cursor.execute("""SELECT fingerprint FROM form_key_relation
            JOIN forms ON forms.id = form_key_relation.form
            WHERE forms.name = :name""", { "name": form_name })
        query_results = cursor.fetchall()
        
        return {
            "form": form_name,
            "fingerprints": [row[0] for row in query_results]
        }

    def get_user(self, fingerprint=None):
        cursor = self._connection.cursor()
        if fingerprint == None:
            cursor.execute("SELECT * FROM users")
            query_results = cursor.fetchall()

            return [{ "fingerprint": row[0], "access_level": row[1] } for row in query_results]
        else:
            cursor.execute("SELECT * FROM users wHERE fingerprint = :fpr", { "fpr": fingerprint.upper() })
            query_result = cursor.fetchone()
            if query_result is not None:
                return { "fingerprint": query_result[0], "access_level": query_result[1] }

    def set_collected_data(self, form_name: str, data):
        cursor = self._connection.cursor()
        for d in data:
            cursor.execute("""UPDATE encrypted_data SET secret = :secret, need_reencryption = 0
                WHERE id = :id""", { "secret": d["secret"], "id": d["id"] })
        self._connection.commit()

    def set_config(self, key: str, value: str):
        cursor = self._connection.cursor()
        cursor.execute("""INSERT INTO config VALUES (:key, :value)
            ON CONFLICT(key) DO UPDATE SET value = :value""", { "key": key, "value": value })
        self._connection.commit()

    def set_form_keys_fingerprints(self, form_name: str, fingerprints: list):
        cursor = self._connection.cursor()
        form_id = cursor.execute("SELECT id FROM forms WHERE name=:name", { "name": form_name }).fetchone()
        if form_id is not None:
            form_id = form_id[0]
            cursor.execute("UPDATE encrypted_data SET need_reencryption=1 WHERE form=:id", { "id": form_id })
            cursor.execute("DELETE FROM form_key_relation WHERE form = :id", { "id": form_id })
        else:
            cursor.execute("INSERT INTO forms VALUES (null, :name)", { "name": form_name })
            form_id = cursor.lastrowid

        for fpr in fingerprints:
            cursor.execute("INSERT INTO form_key_relation VALUES (:form, :fingerprint)",
                { "form": form_id, "fingerprint": fpr })
        self._connection.commit()

    def store_form_data(self, form_name: str, secret: str):
        cursor = self._connection.cursor()
        cursor.execute("SELECT id FROM forms WHERE name = :name", { "name": form_name })
        query_result = cursor.fetchone()
        if query_result is not None:
            form_id = query_result[0]
            cursor.execute("INSERT INTO encrypted_data VALUES (null, :form, :secret, 0)", {
                "form": form_id,
                "secret": secret
            })
            self._connection.commit()
