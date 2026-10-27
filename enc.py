from flask import Flask, send_from_directory, abort
import os

app = Flask(__name__, static_folder='.', static_url_path='')
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

@app.route('/')
def serve_html():
    return send_from_directory(BASE_DIR, "index.html")

@app.route('/<path:filename>')
def serve_static(filename):
    try:
        return send_from_directory(BASE_DIR, filename)
    except Exception:
        abort(404)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 6778))
    app.run(host='127.0.0.1', port=port, debug=False)