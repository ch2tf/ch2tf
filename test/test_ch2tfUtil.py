import unittest

from src.util import is_sampling_skip


class CH2TFUtilTest(unittest.TestCase):
    def test_is_sampling_skip_false(self):
        t = [0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 0.99]
        for a in t:
            self.assertEqual(False, is_sampling_skip(1.0, a))
        self.assertEqual(False, is_sampling_skip(0.1, 0.09))

    def test_is_sampling_skip_true(self):
        t = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9]
        for a in t:
            self.assertEqual(True, is_sampling_skip(0.09, a))


if __name__ == "__main__":
    unittest.main()
