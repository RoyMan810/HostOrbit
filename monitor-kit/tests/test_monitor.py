import importlib.util
import pathlib
import unittest

spec = importlib.util.spec_from_file_location('monitor', pathlib.Path(__file__).resolve().parents[1] / 'lib/monitor.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class Transitions(unittest.TestCase):
    def setUp(self):
        self.probe = {'id': 'ru-to-nl', 'name': 'RU to NL', 'stale_after': 720, 'fail_threshold': 2, 'recovery_threshold': 1}
        self.now = 100000
        self.state = None

    def apply(self, status, increment=300):
        self.now += increment
        self.state, event = m.evaluate(self.probe, self.state, (self.now, status), self.now)
        return event

    def test_transitions(self):
        self.assertIsNone(self.apply('OK'))
        self.assertEqual(self.state['state'], 'OK')
        self.assertIsNone(self.apply('FAIL'))
        self.assertEqual(self.apply('FAIL'), 'FAIL')
        self.assertEqual(self.apply('OK'), 'RECOVERED')
        self.now += 721
        self.state, event = m.evaluate(self.probe, self.state, (self.now - 721, 'OK'), self.now)
        self.assertEqual(event, 'UNKNOWN')
        self.assertEqual(self.apply('OK', 1), 'RECOVERED')

    def test_no_duplicate_on_same_timestamp(self):
        self.apply('OK')
        self.apply('FAIL')
        t = self.now
        self.state, event = m.evaluate(self.probe, self.state, (t, 'FAIL'), self.now)
        self.assertIsNone(event)
        self.assertEqual(self.state['fails'], 1)

    def test_initial_absence_no_spam(self):
        state, event = m.evaluate(self.probe, None, None, self.now)
        self.assertIsNone(event)
        self.assertEqual(state['state'], 'INIT')

if __name__ == '__main__':
    unittest.main()
