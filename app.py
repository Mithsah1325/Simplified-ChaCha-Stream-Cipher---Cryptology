#!/usr/bin/env python3
"""
Flask wrapper to display the `chacha.py` demonstration output in a browser.
Run with `python app.py` (defaults to port 8000) or set `PORT` env var.
"""
from flask import Flask, render_template
import io
import sys
import os

import chacha


def get_demo_output():
    """Run the `chacha.main()` demonstration and capture stdout as text."""
    buf = io.StringIO()
    old_stdout = sys.stdout
    try:
        sys.stdout = buf
        # Call the demonstration function from chacha.py
        chacha.main()
    finally:
        sys.stdout = old_stdout
    return buf.getvalue()


app = Flask(__name__)


@app.route('/')
def index():
    output = get_demo_output()
    return render_template('index.html', output=output)


if __name__ == '__main__':
    port = int(os.environ.get('PORT', '8000'))
    app.run(host='0.0.0.0', port=port, debug=True)
