"""BloodHound JSON output writer.

Produces one JSON file per AD object type in the exact format BloodHound
CE and legacy expect:
  {"data": [...], "meta": {"count": N, "methods": M, "type": "...",
                           "version": 6, "collectorversion": "..."}}
"""
from __future__ import annotations

import dataclasses
import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

SCHEMA_VERSION    = 6
COLLECTOR_VERSION = "1.0.0"


def _serialise(obj: Any) -> Any:
    """Recursively convert dataclasses / special types to JSON-safe values."""
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {k: _serialise(v) for k, v in dataclasses.asdict(obj).items()}
    if isinstance(obj, list):
        return [_serialise(i) for i in obj]
    if isinstance(obj, bytes):
        return obj.hex()
    return obj


class JsonDataWriter:
    """Serialises a list of BloodHound objects to a JSON file."""

    def __init__(
        self,
        data_type: str,
        collection_methods: int,
        output_dir: str = ".",
        prefix: str = "",
        pretty: bool = False,
    ):
        self.data_type = data_type
        self.collection_methods = collection_methods
        self.output_dir = Path(output_dir)
        self.prefix = prefix
        self.pretty = pretty

    def write(self, objects: list) -> Path:
        timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
        parts = [p for p in [self.prefix, timestamp, self.data_type] if p]
        filename = "_".join(parts) + ".json"
        out_path = self.output_dir / filename

        data_list = [_serialise(o) for o in objects]

        payload = {
            "data": data_list,
            "meta": {
                "methods": self.collection_methods,
                "type": self.data_type,
                "count": len(data_list),
                "version": SCHEMA_VERSION,
                "collectorversion": COLLECTOR_VERSION,
            },
        }

        indent = 2 if self.pretty else None
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=indent, default=str)

        log.info("Wrote %d %s → %s", len(objects), self.data_type, out_path)
        return out_path
