#!/usr/bin/env python3
"""PS Core Operations — combined dashboard hub.

Serves a small landing page at "/" and mounts each existing dashboard
(built with its own `build_app()` / `load_and_build()`, completely
unmodified in behavior) at its own sub-path, all on ONE port:

    http://<server>:8820/                       -> landing page
    http://<server>:8820/network-degradation/   -> Network Service Degradation
    http://<server>:8820/free-rg-smart-care/    -> Free RGs Smart Care

Each use case keeps its own config, its own data folder, and its own
`tools/daily_update.py` cron job — this file only combines the already-built
Dash apps at the web-server layer (Werkzeug's DispatcherMiddleware), so
adding a new use case later is just: build it the same way (build_app +
load_and_build(args, url_base_pathname)), add one entry to USE_CASES below,
add one tile to the landing page.

Run directly for local testing:
    python3 hub.py
Deploy on the server the same way (see tools/run_hub.sh for the daemon +
cron-refresh-friendly version).
"""
import argparse
import importlib.util
import os
import sys

from flask import Flask
from werkzeug.serving import run_simple

REPO_ROOT = os.path.dirname(os.path.abspath(__file__))


def _load_module(name: str, path: str):
    """Import a dashboard.py file as an isolated module.

    Both use cases have a file literally named `dashboard.py` — importlib's
    normal import machinery would collide the two under the same module
    name, so each is loaded from its exact file path under its own unique
    module name instead.
    """
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    # Run the module with its own directory as the working assumption for
    # relative paths (config/config.yaml, data/, etc.) — chdir around the
    # exec so each dashboard's relative paths resolve exactly like they do
    # when you run it standalone from its own folder.
    prev_cwd = os.getcwd()
    try:
        os.chdir(os.path.dirname(path))
        spec.loader.exec_module(module)
    finally:
        os.chdir(prev_cwd)
    return module


def _build_network_degradation():
    path = os.path.join(REPO_ROOT, "usecases", "network_degradation", "dashboard.py")
    mod = _load_module("uc_network_degradation", path)

    args = argparse.Namespace(
        csv=[os.path.join(os.path.dirname(path), "data", "data_ipv6"),
             os.path.join(os.path.dirname(path), "data", "data_ipv4")],
        ip_csv=None,
        site_csv=None,   # None -> module's own default (data/data_site) applies
        cells_csv=None,  # None -> module's own default (data/data_site_cells) applies
        lookback=7,
        threshold=15.0,
    )
    prev_cwd = os.getcwd()
    try:
        os.chdir(os.path.dirname(path))
        app, _host, _port = mod.load_and_build(
            args, url_base_pathname="/network-degradation/")
    finally:
        os.chdir(prev_cwd)
    return app


def _build_free_rg_smart_care():
    path = os.path.join(REPO_ROOT, "usecases", "free_rg_smart_care", "dashboard.py")
    # Point this dashboard at its Linux-server config (SASL, no JDBC) before
    # the module-level CONFIG_PATH = os.environ.get(...) line runs.
    os.environ.setdefault(
        "FREE_RG_CONFIG",
        os.path.join(os.path.dirname(path), "config", "config.server.yaml"))
    mod = _load_module("uc_free_rg_smart_care", path)

    args = argparse.Namespace(
        csv=os.path.join(os.path.dirname(path), "data"),
        lookback=7,
    )
    prev_cwd = os.getcwd()
    try:
        os.chdir(os.path.dirname(path))
        app, _host, _port = mod.load_and_build(
            args, url_base_pathname="/free-rg-smart-care/")
    finally:
        os.chdir(prev_cwd)
    return app


# Each entry: (url path prefix, display name, one-line description, builder).
# Add a new use case by adding one line here plus a builder function above.
USE_CASES = [
    ("/network-degradation/", "Network Service Degradation",
     "TCP KPI anomaly detection across IPv6/IPv4 subnets and sites.",
     _build_network_degradation),
    ("/free-rg-smart-care/", "Free RGs Smart Care",
     "Free Rating Group traffic, user, and top-user analytics.",
     _build_free_rg_smart_care),
]


def _landing_page_html() -> str:
    tiles = "\n".join(
        f'''<a class="tile" href="{path}">
              <h2>{name}</h2>
              <p>{desc}</p>
            </a>'''
        for path, name, desc, _builder in USE_CASES
    )
    return f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>PS Core Operations Dashboard</title>
  <style>
    body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif;
            background: #0f1419; color: #e6edf3; margin: 0; padding: 48px; }}
    h1 {{ font-weight: 600; margin-bottom: 8px; }}
    .subtitle {{ color: #8b949e; margin-bottom: 40px; }}
    .grid {{ display: flex; flex-wrap: wrap; gap: 20px; }}
    .tile {{ display: block; text-decoration: none; color: inherit;
             background: #161b22; border: 1px solid #30363d;
             border-radius: 10px; padding: 24px; width: 320px;
             transition: border-color .15s ease; }}
    .tile:hover {{ border-color: #58a6ff; }}
    .tile h2 {{ margin: 0 0 8px 0; font-size: 18px; color: #58a6ff; }}
    .tile p {{ margin: 0; color: #8b949e; font-size: 14px; line-height: 1.4; }}
  </style>
</head>
<body>
  <h1>PS Core Operations Dashboard</h1>
  <div class="subtitle">Choose a use case</div>
  <div class="grid">
    {tiles}
  </div>
</body>
</html>"""


class _PrefixDispatcher:
    """Routes by URL prefix WITHOUT stripping it from PATH_INFO.

    werkzeug's DispatcherMiddleware strips the mount prefix before forwarding
    (it expects the sub-app to think it's mounted at "/"). That doesn't work
    here because each Dash app was built with `url_base_pathname` already
    baked into its own route registrations (needed so its assets and
    callback URLs resolve correctly under its sub-path) — stripping the
    prefix a second time just makes every request 404. This dispatcher
    forwards the request unchanged to whichever mounted app's prefix
    matches, falling back to the landing page.
    """

    def __init__(self, landing_wsgi, mounts: dict):
        self.landing_wsgi = landing_wsgi
        self.mounts = mounts  # {"/network-degradation": app.server, ...}

    def __call__(self, environ, start_response):
        path = environ.get("PATH_INFO", "")
        for prefix, wsgi_app in self.mounts.items():
            if path == prefix or path.startswith(prefix + "/"):
                return wsgi_app(environ, start_response)
        return self.landing_wsgi(environ, start_response)


def build_hub_application():
    landing = Flask(__name__)

    @landing.route("/")
    def _index():
        return _landing_page_html()

    mounts = {}
    for path, name, _desc, builder in USE_CASES:
        print(f"Building '{name}' at {path} ...")
        app = builder()
        mounts[path.rstrip("/")] = app.server

    return _PrefixDispatcher(landing, mounts)


def main():
    parser = argparse.ArgumentParser(description="PS Core Operations Dashboard Hub")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8820)
    args = parser.parse_args()

    application = build_hub_application()

    print(f"\nHub running -> open http://localhost:{args.port} in your browser")
    for path, name, _desc, _builder in USE_CASES:
        print(f"  {name:32s} -> http://localhost:{args.port}{path}")
    print("Press Ctrl+C to stop.\n")

    run_simple(args.host, args.port, application,
               use_reloader=False, use_debugger=False, threaded=True)


if __name__ == "__main__":
    main()
