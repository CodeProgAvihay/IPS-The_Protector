from abc import ABC, abstractmethod

class AttackHandler(ABC):

    @abstractmethod
    def detect(self, packet):
        """Analyze the packet and return True if it's suspicious."""
        pass

    @abstractmethod
    def handle(self, packet):
        """What to do when an attack is detected."""
        pass
