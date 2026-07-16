"""Configure pytest."""

from sybil import Sybil
from sybil.parsers.codeblock import PythonCodeBlockParser

pytest_collect_file = Sybil(
    parsers=[
        PythonCodeBlockParser(),
    ],
    pattern="*.rst",
).pytest()
