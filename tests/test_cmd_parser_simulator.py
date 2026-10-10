import os
import unittest
from src.cmd_parser_simulator import (
    deobfuscate_batch_script,
    strip_carets_state_machine,
    evaluate_var_expr,
    DEFAULT_WINDOWS_ENV,
)


class TestCmdParserSimulator(unittest.TestCase):
    def setUp(self):
        self.sample_dir = os.path.join(
            os.path.dirname(__file__), "samples", "parser-test-vectors"
        )

    def test_strip_carets_state_machine(self):
        raw = "w^h^o^a^m^i"
        self.assertEqual(strip_carets_state_machine(raw), "whoami")

        # Carets inside double quotes must be preserved as literal characters by cmd.exe
        in_quotes = 'echo "hello ^ world"'
        self.assertEqual(strip_carets_state_machine(in_quotes), 'echo "hello ^ world"')

    def test_var_slicing_and_substitution(self):
        env = dict(DEFAULT_WINDOWS_ENV)
        env["MYVAR"] = "DefensiveSecurity"

        # Positive slicing
        self.assertEqual(evaluate_var_expr("MYVAR:~0,9", env), "Defensive")
        self.assertEqual(evaluate_var_expr("MYVAR:~9,8", env), "Security")

        # Substitution
        self.assertEqual(evaluate_var_expr("MYVAR:Security=Research", env), "DefensiveResearch")

    def test_all_sample_scripts_deobfuscation(self):
        sample_files = [f for f in os.listdir(self.sample_dir) if f.endswith(".bat")]
        self.assertTrue(len(sample_files) >= 6, "Expected at least 6 sample batch vectors")

        for s_file in sample_files:
            p = os.path.join(self.sample_dir, s_file)
            with open(p, "rb") as f:
                raw_bytes = f.read()
            report = deobfuscate_batch_script(raw_bytes)

            self.assertIsNotNone(report.encoding_anomaly)
            self.assertTrue(len(report.normalized_lines) > 0)
            self.assertGreater(report.shannon_entropy, 0.0)
            self.assertTrue(len(report.mitre_techniques) > 0)
            print(f"Verified {s_file}: Entropy={report.shannon_entropy}, MITRE={report.mitre_techniques}")


if __name__ == "__main__":
    unittest.main()
