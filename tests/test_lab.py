import json
import os
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
import xml.etree.ElementTree as ET
from unittest.mock import patch

from lab.app import LabHandler
from http.server import ThreadingHTTPServer
from urllib.request import urlopen
from threading import Thread


class TestLab(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), LabHandler)
        cls.thread = Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def test_home_and_health(self):
        with urlopen(self.base + "/") as response:
            self.assertIn(b"Offensive Lab Demo", response.read())
        with urlopen(self.base + "/health") as response:
            self.assertEqual(json.load(response)["status"], "ok")

    def test_debug_marker_and_no_secret(self):
        with urlopen(self.base + "/debug") as response:
            data = json.load(response)
        self.assertTrue(data["LAB_DEBUG_ONLY"])
        self.assertNotIn("token", data)

    def test_external_target_hostname_ip_and_url(self):
        from scripts.normalize_target import normalize
        self.assertEqual(normalize("nmap", "198.51.100.25", "80,443")["host"], "198.51.100.25")
        self.assertEqual(normalize("httpx", "https://lab.example.org:8443/path", "80,443")["url"],
                         "https://lab.example.org:8443/path")
        self.assertEqual(normalize("subfinder", "lab.example.org", "80,443")["domain"], "lab.example.org")
        self.assertTrue(normalize("nmap", "2001:db8::1", "443")["ipv6"])

    def test_external_target_blocks_ranges_and_unsafe_input(self):
        from scripts.normalize_target import normalize
        for tool, target, ports in [
            ("nmap", "192.0.2.0/24", "80"),
            ("nmap", "example.org; echo bad", "80"),
            ("nmap", "example.org", "1-65535"),
            ("nmap", "example.org", ",".join(map(str, range(1, 12)))),
            ("subfinder", "https://example.org", "80"),
            ("nuclei", "http://example.org", "80"),
            ("httpx", "https://example.org/?key=secret", "80"),
        ]:
            with self.subTest(target=target):
                with self.assertRaises(ValueError):
                    normalize(tool, target, ports)

    def test_external_missing_target_exits_before_network(self):
        repo = Path(__file__).resolve().parents[1]
        with TemporaryDirectory() as tmp:
            env = os.environ | {"TOOL": "nmap", "TARGET_MODE": "external",
                                "TARGET_DOMAIN": "", "TARGET_IP": "", "TARGET_URL": "", "RESULT_DIR": tmp}
            proc = subprocess.run(["bash", str(repo / "scripts" / "run_lab.sh")],
                                  cwd=repo, env=env, capture_output=True, text=True)
            self.assertEqual(proc.returncode, 2)
            self.assertIn("requires exactly one", proc.stderr)

    def test_external_rejects_multiple_target_fields(self):
        repo = Path(__file__).resolve().parents[1]
        with TemporaryDirectory() as tmp:
            env = os.environ | {"TOOL": "nmap", "TARGET_MODE": "external",
                                "TARGET_DOMAIN": "example.org", "TARGET_IP": "198.51.100.25",
                                "TARGET_URL": "", "RESULT_DIR": tmp}
            proc = subprocess.run(["bash", str(repo / "scripts" / "run_lab.sh")],
                                  cwd=repo, env=env, capture_output=True, text=True)
            self.assertEqual(proc.returncode, 2)
            self.assertIn("requires exactly one", proc.stderr)

    def test_external_rejects_wrong_target_field_for_tool(self):
        repo = Path(__file__).resolve().parents[1]
        with TemporaryDirectory() as tmp:
            env = os.environ | {"TOOL": "subfinder", "TARGET_MODE": "external",
                                "TARGET_DOMAIN": "", "TARGET_IP": "198.51.100.25",
                                "TARGET_URL": "", "RESULT_DIR": tmp}
            proc = subprocess.run(["bash", str(repo / "scripts" / "run_lab.sh")],
                                  cwd=repo, env=env, capture_output=True, text=True)
            self.assertEqual(proc.returncode, 2)
            self.assertIn("does not accept", proc.stderr)

    def test_subfinder_requires_external_mode(self):
        repo = Path(__file__).resolve().parents[1]
        with TemporaryDirectory() as tmp:
            env = os.environ | {"TOOL": "subfinder", "TARGET_MODE": "local", "RESULT_DIR": tmp}
            proc = subprocess.run(["bash", str(repo / "scripts" / "run_lab.sh")],
                                  cwd=repo, env=env, capture_output=True, text=True)
            self.assertEqual(proc.returncode, 2)
            self.assertIn("Subfinder needs target_mode=external", proc.stderr)

    def test_nmap_summary(self):
        from scripts import build_report
        with TemporaryDirectory() as tmp:
            root = ET.Element("nmaprun")
            host = ET.SubElement(root, "host")
            ports = ET.SubElement(host, "ports")
            port = ET.SubElement(ports, "port", protocol="tcp", portid="8765")
            ET.SubElement(port, "state", state="open")
            ET.ElementTree(root).write(Path(tmp) / "nmap.xml", encoding="utf-8")
            with patch.object(build_report, "OUT", Path(tmp)), patch.object(build_report, "TOOL", "nmap"):
                text = build_report.create_report()
            self.assertIn("8765", text)
            self.assertIn("open", text)

    def test_nuclei_summary(self):
        from scripts import build_report
        with TemporaryDirectory() as tmp:
            (Path(tmp) / "nuclei.jsonl").write_text(json.dumps({
                "template-id": "offensive-lab-debug-exposure",
                "info": {"severity": "info"},
                "matched-at": "http://127.0.0.1:8765/debug"
            }) + "\n")
            with patch.object(build_report, "OUT", Path(tmp)), patch.object(build_report, "TOOL", "nuclei"):
                text = build_report.create_report()
            self.assertIn("offensive-lab-debug-exposure", text)


if __name__ == "__main__":
    unittest.main()

# Additional checks run through a separate class to keep the workshop fixture
# tests independent of scanner installation.
class TestDiagnostics(unittest.TestCase):
    def test_preflight_local_http_server(self):
        from scripts.preflight import inspect
        server = ThreadingHTTPServer(('127.0.0.1', 0), LabHandler)
        worker = Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            data = inspect('127.0.0.1', f'http://127.0.0.1:{server.server_port}', 'httpx')
            self.assertIn('127.0.0.1', data['dns']['addresses'])
            self.assertEqual(data['http_preflight']['status'], 200)
        finally:
            server.shutdown()
            server.server_close()
            worker.join()

    def test_zero_httpx_results_are_labeled_as_empty(self):
        from scripts import build_report
        with TemporaryDirectory() as temp:
            (Path(temp) / 'httpx.jsonl').write_text('')
            (Path(temp) / 'tool-execution.json').write_text('{"exit_code":0,"elapsed_seconds":2}')
            with patch.object(build_report, 'OUT', Path(temp)), patch.object(build_report, 'TOOL', 'httpx'):
                report = build_report.create_report()
            self.assertIn('No HTTP response was recorded', report)
            self.assertIn('Tool process exit code:', report)

    def test_execution_errors_are_distinct_from_empty_findings(self):
        from scripts import build_report
        with TemporaryDirectory() as temp:
            (Path(temp) / 'nuclei.jsonl').write_text('')
            (Path(temp) / 'tool-execution.json').write_text('{"exit_code":125,"elapsed_seconds":1}')
            with patch.object(build_report, 'OUT', Path(temp)), patch.object(build_report, 'TOOL', 'nuclei'):
                report = build_report.create_report()
            self.assertIn('Execution failure:', report)
            self.assertIn('No Nuclei template matched', report)
