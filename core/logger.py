"""
core/logger.py — Session logging and export for ReconCLI v3
Every module run is logged. Results can be exported as JSON or TXT.
"""

import os
import json
from datetime import datetime
from core.compat import get_sessions_dir, get_output_dir
from core.utils  import datestamp, success, warn


class SessionLogger:
    """
    Tracks all runs in the current ReconCLI session.
    Persists to sessions/<date>.json automatically.
    """

    def __init__(self):
        self._runs: list[dict] = []
        self._session_id = datestamp()
        self._session_file = os.path.join(
            get_sessions_dir(),
            f"session_{self._session_id}.json"
        )

    # ── Logging ───────────────────────────────────────────────────────────────

    def start_run(self, module: str, target: str) -> dict:
        """Call before a module runs. Returns the run dict to append findings to."""
        run = {
            "id":       len(self._runs) + 1,
            "module":   module,
            "target":   target,
            "started":  datetime.now().isoformat(),
            "finished": None,
            "status":   "running",
            "findings": [],
            "summary":  "",
        }
        self._runs.append(run)
        self._save()
        return run

    def finish_run(self, run: dict, status: str = "ok", summary: str = ""):
        """Call after a module finishes."""
        run["finished"] = datetime.now().isoformat()
        run["status"]   = status
        run["summary"]  = summary
        self._save()

    def add_finding(self, run: dict, severity: str, title: str, detail: str = ""):
        """Add a finding to a run. severity: CRITICAL / HIGH / MEDIUM / LOW / INFO"""
        run["findings"].append({
            "severity": severity,
            "title":    title,
            "detail":   detail,
        })
        self._save()

    # ── Persistence ───────────────────────────────────────────────────────────

    def _save(self):
        try:
            with open(self._session_file, "w", encoding="utf-8") as f:
                json.dump({
                    "session_id": self._session_id,
                    "runs":       self._runs,
                }, f, indent=2)
        except Exception:
            pass  # never crash the tool due to logging

    # ── Display ───────────────────────────────────────────────────────────────

    def show_sessions(self):
        """Print all runs in the current session."""
        from core.utils import color, section, info, warn

        if not self._runs:
            warn("No runs in this session yet.")
            return

        section("Session Runs")
        print(color(f"  {'#':<4} {'MODULE':<28} {'TARGET':<30} {'STATUS'}", "dark"))
        print(color("  " + "─" * 72, "dark"))

        for run in self._runs:
            status  = run["status"]
            c       = "green" if status == "ok" else "red" if status == "error" else "yellow"
            n_finds = len(run["findings"])
            finds_str = f" [{n_finds} finding(s)]" if n_finds else ""
            print(
                color(f"  {run['id']:<4}", "dark") +
                color(f"{run['module']:<28}", "cyan") +
                color(f"{run['target']:<30}", "white") +
                color(status.upper() + finds_str, c)
            )

        print()
        info(f"Session file: {self._session_file}")

    def show_findings(self):
        """Print all findings from this session."""
        from core.utils import color, section, error, warn, info, success

        all_findings = [
            (run["module"], run["target"], f)
            for run in self._runs
            for f in run["findings"]
        ]

        if not all_findings:
            success("No findings recorded this session.")
            return

        SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        SEV_COLOR = {
            "CRITICAL": "red", "HIGH": "yellow",
            "MEDIUM": "cyan", "LOW": "dark", "INFO": "dark"
        }

        section("All Findings This Session")
        for sev in SEV_ORDER:
            hits = [(m, t, f) for m, t, f in all_findings if f["severity"] == sev]
            if not hits:
                continue
            print(color(f"\n  [{sev}]", SEV_COLOR[sev]))
            for module, target, f in hits:
                print(color(f"    {f['title']}", SEV_COLOR[sev]))
                if f["detail"]:
                    print(color(f"    → {f['detail']}", "dark"))
                print(color(f"    Module: {module}  Target: {target}", "dark"))

        print()

    # ── Export ────────────────────────────────────────────────────────────────

    def export_json(self) -> str:
        """Export current session to output/report_<id>.json"""
        out = os.path.join(get_output_dir(), f"report_{self._session_id}.json")
        with open(out, "w", encoding="utf-8") as f:
            json.dump({
                "session_id": self._session_id,
                "runs":       self._runs,
            }, f, indent=2)
        success(f"JSON report → {out}")
        return out

    def export_txt(self) -> str:
        """Export current session to output/report_<id>.txt"""
        out  = os.path.join(get_output_dir(), f"report_{self._session_id}.txt")
        lines = [
            f"ReconCLI v3 — Session Report",
            f"Session ID : {self._session_id}",
            f"Runs       : {len(self._runs)}",
            "=" * 60,
        ]
        for run in self._runs:
            lines += [
                f"\n[{run['id']}] {run['module']} → {run['target']}",
                f"    Status  : {run['status']}",
                f"    Started : {run['started']}",
                f"    Summary : {run['summary']}",
            ]
            for f in run["findings"]:
                lines.append(f"    [{f['severity']}] {f['title']}")
                if f["detail"]:
                    lines.append(f"           → {f['detail']}")

        with open(out, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        success(f"TXT report  → {out}")
        return out


# ── Global session instance ───────────────────────────────────────────────────

_session = SessionLogger()

def get_session() -> SessionLogger:
    return _session
