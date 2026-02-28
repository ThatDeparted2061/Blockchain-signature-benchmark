from __future__ import annotations

from dataclasses import dataclass, asdict
from hashlib import sha256
import json
import time


@dataclass
class Transaction:
    sender: str
    receiver: str
    amount: float
    timestamp: float
    transaction_id: str

    @staticmethod
    def create(sender: str, receiver: str, amount: float) -> "Transaction":
        timestamp = time.time()
        base = {
            "sender": sender,
            "receiver": receiver,
            "amount": amount,
            "timestamp": timestamp,
        }
        serialized = json.dumps(base, sort_keys=True).encode("utf-8")
        tx_id = sha256(serialized).hexdigest()
        return Transaction(sender, receiver, amount, timestamp, tx_id)

    def serialize(self) -> bytes:
        data = asdict(self)
        return json.dumps(data, sort_keys=True).encode("utf-8")

    def hash_id_bytes(self) -> bytes:
        return bytes.fromhex(self.transaction_id)
