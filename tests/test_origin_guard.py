import importlib
import unittest

MODS = ["jwt_inspector_guard.cli", "jwt_inspector_guard.ui_server"]


class TestOriginGuard(unittest.TestCase):
    def test_exact_port_loopback_origins_allowed(self):
        for name in MODS:
            m = importlib.import_module(name)
            for o in (
                None,
                "",
                "http://127.0.0.1:8124",
                "http://localhost:8124",
                "http://[::1]:8124",
                "http://127.0.0.1:3000",
                "http://localhost:3000",
            ):
                self.assertTrue(m._is_local_origin(o, 8124), (name, o))

    def test_spoofed_port_and_foreign_origins_blocked(self):
        for name in MODS:
            m = importlib.import_module(name)
            for o in (
                "https://evil.example",
                "https://evil.example.invalid",
                "http://localhost.evil.example",
                "http://127.0.0.1:81240",
                "http://localhost:9999",
                "https://localhost:8124",
                "null",
                "file://",
                "http://192.168.1.5:8124",
            ):
                self.assertFalse(m._is_local_origin(o, 8124), (name, o))


if __name__ == "__main__":
    unittest.main()
