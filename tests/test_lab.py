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

    def test_target_allowlist_blocks_arbitrary_external_target(self):
        repo = Path(__file__).resolve().parents[1]
        with TemporaryDirectory() as tmp:
            env = os.environ | {"TOOL": "nmap", "LAB_TARGET": "alvo-arbitrario", "RESULT_DIR": tmp}
            proc = subprocess.run(["bash", str(repo / "scripts" / "run_lab.sh")],
                                  cwd=repo, env=env, capture_output=True, text=True)
            self.assertEqual(proc.returncode, 2)
            self.assertIn("Lab target not allowed", proc.stderr)

    def test_subfinder_requires_matching_authorized_domain(self):
        repo = Path(__file__).resolve().parents[1]
        with TemporaryDirectory() as tmp:
            env = os.environ | {"TOOL": "subfinder", "LAB_TARGET": "miniapp",
                                "LAB_ALLOWED_DOMAIN": "meu-lab.example", "DOMAIN": "outro.example",
                                "RESULT_DIR": tmp}
            proc = subprocess.run(["bash", str(repo / "scripts" / "run_lab.sh")],
                                  cwd=repo, env=env, capture_output=True, text=True)
            self.assertEqual(proc.returncode, 2)
            self.assertIn("Out-of-scope domain", proc.stderr)

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
