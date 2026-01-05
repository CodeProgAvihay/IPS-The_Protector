from abc import ABC, abstractmethod
from sqlDataBase import SqliteDatabase

class AttackHandler(ABC):
    def __init__(self, _db: SqliteDatabase):
        self.db = _db

    @abstractmethod
    def detect(self, packet):
        """Analyze the packet and return True if it's suspicious."""
        pass

    @abstractmethod
    def handle(self, packet):
        """What to do when an attack is detected."""
        pass
