import sqlite3
import os
from datetime import datetime
from config import DB_PATH

class AlertLogger:
    def __init__(self):
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        self.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        self.conn.execute('PRAGMA journal_mode=WAL;')
        self.create_table()
        self._last_alert = {}
        print(f'[*] Logger initialized - saving to {DB_PATH}')

    def create_table(self):
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                attack_type TEXT,
                src_ip TEXT,
                severity TEXT,
                detail TEXT
            )
        ''')
        self.conn.commit()

    def log(self, alert):
        key = f"{alert['attack_type']}_{alert['src_ip']}"
        now = datetime.now().timestamp()
        
        # Periodic cleanup of self._last_alert cache to prevent memory leak
        if len(self._last_alert) > 1000:
            self._last_alert = {k: t for k, t in self._last_alert.items() if now - t < 5}

        if key in self._last_alert and now - self._last_alert[key] < 5:
            return
        self._last_alert[key] = now
        self.conn.execute('''
            INSERT INTO alerts (timestamp, attack_type, src_ip, severity, detail)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            alert['timestamp'],
            alert['attack_type'],
            alert['src_ip'],
            alert['severity'],
            alert['detail']
        ))
        self.conn.commit()

    def get_all(self):
        cursor = self.conn.execute('SELECT * FROM alerts ORDER BY id DESC LIMIT 100')
        rows = cursor.fetchall()
        return [
            {
                'id': r[0],
                'timestamp': r[1],
                'attack_type': r[2],
                'src_ip': r[3],
                'severity': r[4],
                'detail': r[5]
            }
            for r in rows
        ]

    def get_stats(self):
        cursor = self.conn.execute('''
            SELECT attack_type, COUNT(*) as count
            FROM alerts
            GROUP BY attack_type
            ORDER BY count DESC
        ''')
        return [{'attack_type': r[0], 'count': r[1]} for r in cursor.fetchall()]

    def get_total_count(self):
        cursor = self.conn.execute('SELECT COUNT(*) FROM alerts')
        row = cursor.fetchone()
        return row[0] if row else 0

    def close(self):
        self.conn.close()
