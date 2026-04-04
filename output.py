"""
output.py — OutputFormatter: JSON, NDJSON, CSV export from enriched results.
"""

import json
import csv
import io


class OutputFormatter:
    """Format enriched scan results into various output formats."""

    @staticmethod
    def to_json(results: list[dict], indent: int = 2) -> str:
        return json.dumps(results, indent=indent, ensure_ascii=False)

    @staticmethod
    def to_ndjson(results: list[dict]) -> str:
        return "\n".join(json.dumps(r, ensure_ascii=False) for r in results)

    @staticmethod
    def to_csv(results: list[dict]) -> str:
        if not results:
            return ""
        # Flatten nested dicts for CSV columns
        flat_rows = []
        for r in results:
            flat = {}
            for k, v in r.items():
                if isinstance(v, dict):
                    for sub_k, sub_v in v.items():
                        if isinstance(sub_v, (list, dict)):
                            flat[f"{k}_{sub_k}"] = json.dumps(sub_v)
                        else:
                            flat[f"{k}_{sub_k}"] = sub_v
                elif isinstance(v, list):
                    flat[k] = ", ".join(str(x) for x in v)
                else:
                    flat[k] = v
            flat_rows.append(flat)

        # Collect all keys across all rows for consistent columns
        all_keys = []
        seen = set()
        for row in flat_rows:
            for k in row:
                if k not in seen:
                    all_keys.append(k)
                    seen.add(k)

        out = io.StringIO()
        writer = csv.DictWriter(out, fieldnames=all_keys, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(flat_rows)
        return out.getvalue()

    @staticmethod
    def format(results: list[dict], fmt: str = "json") -> str:
        """Format results in the specified format.

        Args:
            results: list of enriched host dicts.
            fmt: one of "json", "ndjson", "csv".
        """
        if fmt == "json":
            return OutputFormatter.to_json(results)
        elif fmt == "ndjson":
            return OutputFormatter.to_ndjson(results)
        elif fmt == "csv":
            return OutputFormatter.to_csv(results)
        else:
            raise ValueError(f"Unsupported output format: {fmt!r}")
