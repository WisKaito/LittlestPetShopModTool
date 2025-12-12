from distutils.core import setup
import py2exe
import sys

sys.argv.append('py2exe')

setup(
    windows=[{
        "script": "lpsmodtool.py",
    }],
    options={
        "py2exe": {
            "bundle_files": 3,
            "compressed": True,
            "includes": ["Tkinter", "tkFileDialog", "tkMessageBox", "os", "struct"],
            "dll_excludes": ["MSVCP90.dll"],
        }
    },
    zipfile=None
)