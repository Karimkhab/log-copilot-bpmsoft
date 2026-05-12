import io
import tempfile
from contextlib import redirect_stdout
from pathlib import Path
import sys
import unittest

from logcopilot.cli import main as cli_main


class CliTests(unittest.TestCase):
    def test_cli_run_command_creates_run_directory(self) -> None:
        content = "2026-03-11 08:20:00 INFO Gateway - GET /api/orders status=200 latency=25ms size=32 ip=10.0.0.1\n"
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            log_file = root / "cli.log"
            out_dir = root / "out"
            log_file.write_text(content, encoding="utf-8")

            original_argv = sys.argv
            stdout = io.StringIO()
            try:
                sys.argv = [
                    "logcopilot.cli",
                    "run",
                    "--input",
                    str(log_file),
                    "--profile",
                    "traffic",
                    "--out",
                    str(out_dir),
                ]
                with redirect_stdout(stdout):
                    cli_main()
            finally:
                sys.argv = original_argv

            output = stdout.getvalue()
            self.assertIn("profile: traffic", output)
            run_dirs = [path for path in (out_dir / "runs").iterdir() if path.is_dir()]
            self.assertEqual(1, len(run_dirs))

    def test_cli_batch_command_creates_batch_summary(self) -> None:
        request_log = (
            "2025-12-01 00:00:23 ::ffff:10.5.31.156 POST /ServiceModel/AuthService.svc/Login -  "
            "Integration ::ffff:10.5.31.159   200 129\n"
        )
        error_log = (
            "2025-12-01 03:04:51,760 [.NET TP Worker] ERROR Integration Foo Bar - Boom\n"
            "   at Foo.Bar()\n"
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            logs_dir = root / "logs"
            logs_dir.mkdir()
            (logs_dir / "Request.log").write_text(request_log, encoding="utf-8")
            (logs_dir / "Error.log").write_text(error_log, encoding="utf-8")
            out_dir = root / "out"

            original_argv = sys.argv
            stdout = io.StringIO()
            try:
                sys.argv = [
                    "logcopilot.cli",
                    "batch",
                    "--input",
                    str(logs_dir),
                    "--profile",
                    "auto",
                    "--semantic",
                    "off",
                    "--out",
                    str(out_dir),
                ]
                with redirect_stdout(stdout):
                    cli_main()
            finally:
                sys.argv = original_argv

            output = stdout.getvalue()
            self.assertIn("batch_id:", output)
            self.assertIn("total_files: 2", output)
            batch_dirs = [path for path in (out_dir / "batches").iterdir() if path.is_dir()]
            self.assertEqual(1, len(batch_dirs))
            self.assertTrue((batch_dirs[0] / "batch_summary.json").exists())


if __name__ == "__main__":
    unittest.main()
