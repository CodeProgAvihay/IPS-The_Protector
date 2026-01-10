import sqlite3

ATTACK_DESCRIPTIONS = {
    "syn_flood": "SYN Flood attack detected: high rate of SYN packets from the same source IP",
    "port_scanning": "Port Scanning detected: multiple ports probed from the same source IP in a short time window",
    "arp_spoofing": "ARP Spoofing detected: IP address associated with multiple MAC addresses",
    "dns_spoofing": "DNS Spoofing attack detected: forged DNS response does not match expected structure"
}
class SqliteDatabase:
    def __init__(self, db_name: str = "ProtectorDB.db"):
        self.db_name = db_name
        self.conn = sqlite3.connect(self.db_name)
        self.crsr = self.conn.cursor()
        self._create_table()

    def _create_table(self):
        self.crsr.execute('''
        CREATE TABLE IF NOT EXISTS ATTACKS (
        IP TEXT PRIMARY KEY,
        ATTACK_TYPE TEXT NOT NULL,
        TIME TEXT NOT NULL,
        DESCRIPTION TEXT NOT NULL
        );
        ''')
        self.conn.commit()

    def add_attack(self, ip: str, attack_type: str):
        self.crsr.execute("INSERT OR IGNORE INTO ATTACKS (IP, ATTACK_TYPE, TIME, DESCRIPTION) VALUES (?, ?, datetime('now'), ?)",
                          (ip, attack_type, ATTACK_DESCRIPTIONS[attack_type]))
        self.conn.commit()

    def delete_attack(self, ip: str):
        self.crsr.execute("DELETE FROM ATTACKS WHERE IP = ?", (ip,))
        self.conn.commit()

    def does_address_exist(self, ip: str) -> bool:

        self.crsr.execute("SELECT 1 FROM ATTACKS WHERE IP = ? LIMIT 1", (ip,))
        result = self.crsr.fetchone()
        return result is not None


    def get_attacker_with_ip(self, ip: str):
        if self.does_address_exist(ip):
            self.crsr.execute(
            """
            SELECT IP, ATTACK_TYPE, TIME, DESCRIPTION
            FROM attacks
            WHERE IP = ?
            ORDER BY TIME DESC
            """,
            (ip,)
            )
            results = self.crsr.fetchall()
            return results

    def close(self):
        self.conn.close()