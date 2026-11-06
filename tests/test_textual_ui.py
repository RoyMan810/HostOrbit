"""Textual headless smoke tests. Optional locally; required in CI's UI venv."""
import importlib.util
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lib'))


@unittest.skipUnless(importlib.util.find_spec('textual'), 'Install Textual in an isolated venv to run UI tests')
class UIAppTests(unittest.IsolatedAsyncioTestCase):
    async def test_dashboard_navigation_and_cancel(self):
        from textual.widgets import ListView, Static
        from textual_ui import KVpnApp, TASKS, decode_prompt, APP_VERSION
        import base64
        app = KVpnApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            self.assertIn('Проверка VPS', str(app.query_one('#title', Static).render()))
            self.assertIn(f'v{APP_VERSION}', str(app.query_one('#brand', Static).render()))
            app.query_one('#nav', ListView).index = next(i for i, t in enumerate(TASKS) if t.key == 'wizard')
            await pilot.pause()
            self.assertEqual(app.selected.key, 'wizard')
            await pilot.click('#run')
            await pilot.pause()
            self.assertEqual(app.screen.__class__.__name__, 'ApprovalScreen')
            await pilot.press('escape')
            await pilot.pause()
            self.assertFalse(app.busy)
            self.assertNotEqual(app.screen.__class__.__name__, 'ApprovalScreen')
        q = base64.b64encode('Что выбрать?'.encode()).decode()
        self.assertEqual(decode_prompt(f'__KVPN_UI_PROMPT__\tinput\t{q}\t'), ('input','Что выбрать?',''))
