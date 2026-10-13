import importlib.util
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
spec = importlib.util.spec_from_file_location("lora_probe", os.path.join(ROOT, "tools", "lora_probe.py"))
lora_probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lora_probe)


class ProbeOutput(unittest.TestCase):
    def test_encrypted_packet_is_counted_and_marked(self):
        p = lora_probe.Probe()
        line = p.handle({"from": 0xA1B2C3D4, "channel": 31, "rxRssi": -97, "rxSnr": 6.5, "hopStart": 3, "hopLimit": 3, "encrypted": "AAAA"}, now=0)
        self.assertIn("!a1b2c3d4", line)
        self.assertIn("ENCRYPTED", line)
        self.assertIn("hops=0", line)
        self.assertIn("encrypted packets DO arrive", p.summary())

    def test_decoded_packet_shows_name_but_never_text_or_position(self):
        p = lora_probe.Probe()
        line = p.handle({"from": 1, "rxRssi": -80, "decoded": {"portnum": "NODEINFO_APP", "user": {"longName": "Hiker"}}}, now=0)
        self.assertIn("Hiker", line)
        text = p.handle({"from": 1, "decoded": {"portnum": "TEXT_MESSAGE_APP", "text": "secret words"}}, now=0)
        pos = p.handle({"from": 1, "decoded": {"portnum": "POSITION_APP", "position": {"latitude": 33.1}}}, now=0)
        self.assertNotIn("secret", text)
        self.assertNotIn("33.1", pos)
        self.assertIn("no encrypted packets arrived", p.summary())

    def test_missing_fields_do_not_crash(self):
        p = lora_probe.Probe()
        line = p.handle({}, now=0)
        self.assertIn("?", line)
        self.assertIn("nothing was heard", lora_probe.Probe().summary())

    def test_relayed_packet_is_not_direct(self):
        p = lora_probe.Probe()
        p.handle({"from": 2, "rxRssi": -60, "hopStart": 3, "hopLimit": 1, "encrypted": "x"}, now=0)
        self.assertFalse(p.senders["!00000002"]["direct"])
        p.handle({"from": 2, "rxRssi": -90, "hopStart": 3, "hopLimit": 3, "encrypted": "x"}, now=0)
        self.assertTrue(p.senders["!00000002"]["direct"])
        self.assertEqual(p.senders["!00000002"]["best"], -60)


if __name__ == "__main__":
    unittest.main()
