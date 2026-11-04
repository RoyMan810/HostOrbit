"""Reproduce long/unterminated process output that breaks readline()."""
import asyncio
import importlib.util
from pathlib import Path
import sys
import unittest

# No Textual dependency needed: extract only the pure async decoder function.
import ast
SOURCE = Path(__file__).resolve().parents[1] / "lib/textual_ui.py"
module_ast = ast.parse(SOURCE.read_text())
reader_ast = next(n for n in module_ast.body if isinstance(n, ast.AsyncFunctionDef) and n.name == 'bounded_output_lines')
reader_module = ast.Module(body=[reader_ast], type_ignores=[])
ns = {}
exec(compile(reader_module, str(SOURCE), 'exec'), ns)


class FakeReader:
    def __init__(self, chunks):
        self.chunks = iter(chunks)

    async def read(self, _):
        return next(self.chunks, b'')


class OutputTests(unittest.IsolatedAsyncioTestCase):
    async def collect(self, chunks, limit=16384):
        return [line async for line in ns['bounded_output_lines'](FakeReader(chunks), maximum=limit)]

    async def test_prompt_frame_split_across_chunks(self):
        data = await self.collect([b'__KVPN_UI_', b'PROMPT__\tinput\tabc\t\nrest', b'\n'])
        self.assertEqual(data, [b'__KVPN_UI_PROMPT__\tinput\tabc\t', b'rest'])

    async def test_huge_line_is_truncated_and_next_prompt_works(self):
        data = await self.collect([b'A'*90000, b'\n__KVPN_UI_PROMPT__\tinput\tx\ty\n'], limit=4096)
        self.assertEqual(len(data), 2)
        self.assertTrue(data[0].startswith(b'A'*4096))
        self.assertIn(b'truncated', data[0])
        self.assertEqual(data[1], b'__KVPN_UI_PROMPT__\tinput\tx\ty')

    async def test_partial_line_at_eof(self):
        self.assertEqual(await self.collect([b'no newline']), [b'no newline'])

    async def test_tui_crash_does_not_launch_fallback(self):
        text = (SOURCE.parents[1] / 'install.sh').read_text()
        self.assertIn('textual_result == 99', text)
        self.assertIn('автоматический переход к другому меню отключён', text)


if __name__ == "__main__":
    unittest.main()
