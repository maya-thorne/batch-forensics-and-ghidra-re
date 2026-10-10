import os
import unittest
from src.entropy_detector import calculate_shannon_entropy, analyze_script_telemetry


class TestEntropyDetector(unittest.TestCase):
    def test_shannon_entropy_calculation(self):
        # Uniform distribution
        data_uniform = bytes(range(256))
        ent = calculate_shannon_entropy(data_uniform)
        self.assertEqual(ent, 8.0)

        # Zero entropy (single byte repeated)
        data_zero = b"A" * 100
        self.assertEqual(calculate_shannon_entropy(data_zero), 0.0)

    def test_benign_script_telemetry(self):
        benign_script = b"@echo off\r\necho Starting backup procedure...\r\nrobocopy C:\\Data D:\\Backup /E\r\necho Finished.\r\n"
        res = analyze_script_telemetry(benign_script)
        self.assertEqual(res.threat_level, "BENIGN")
        self.assertLess(res.composite_threat_score, 25.0)

    def test_obfuscated_samples_detection(self):
        sample_dir = os.path.join(
            os.path.dirname(__file__), "samples", "parser-test-vectors"
        )
        sample_files = [f for f in os.listdir(sample_dir) if f.endswith(".bat")]
        self.assertTrue(len(sample_files) >= 6)

        for s_file in sample_files:
            p = os.path.join(sample_dir, s_file)
            with open(p, "rb") as f:
                raw = f.read()
            res = analyze_script_telemetry(raw)
            self.assertIn(res.threat_level, ["SUSPICIOUS", "HIGH_ANOMALY", "CRITICAL_OBFUSCATION"])
            self.assertGreater(len(res.triggered_anomalies), 0)
            print(f"Scored {s_file}: Score={res.composite_threat_score}, Level={res.threat_level}, Anomalies={len(res.triggered_anomalies)}")


if __name__ == "__main__":
    unittest.main()
