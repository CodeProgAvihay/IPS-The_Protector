import sqlite3


class SqliteDatabase:
    def __init__(self, db_name: str = "ProtectorDB.db"):
        self.db_name = db_name
        self.conn = sqlite3.connect(self.db_name)
        self.crsr = self.conn.cursor()
        self._create_table()

    def _create_table(self):
        self.crsr.execute('''
        CREATE TABLE IF NOT EXISTS ADDRESSES (
        IP TEXT PRIMARY KEY,
        TYPE TEXT NOT NULL
        );
        ''')
        self.conn.commit()

    def add_address(self, ip: str, attack_type: str):
        self.crsr.execute("INSERT INTO ADDRESSES (IP, TYPE) VALUES (?, ?)",
                          (ip, attack_type))
        self.conn.commit()

    def get_type(self, ip: str):
        self.crsr.execute("SELECT * FROM ADDRESSES WHERE IP = ?", (ip,))
        return self.crsr.fetchone()

    def delete_address(self, ip: str):
        self.crsr.execute("DELETE FROM ADDRESSES WHERE IP = ?", (ip,))
        self.conn.commit()

    def does_address_exist(self, ip: str) -> bool:
        self.crsr.execute("SELECT 1 FROM ADDRESSES WHERE IP = ? LIMIT 1", (ip,))
        result = self.crsr.fetchone()
        return result is not None

    def close(self):
        self.conn.close()

