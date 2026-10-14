#!/usr/bin/env python3
"""PS Core Operations — combined dashboard hub.

Serves ONE page at "/" (a sidebar with a tab per dashboard, the selected dashboard
beside it) and mounts each existing dashboard
(built with its own `build_app()` / `load_and_build()`, completely
unmodified in behavior) at its own sub-path, all on ONE port:

    http://<server>:8820/                       -> sidebar shell (a tab per dashboard)
    http://<server>:8820/network-degradation/   -> Network Service Degradation
    http://<server>:8820/free-rg-smart-care/    -> Free RGs Smart Care

Each use case keeps its own config, its own data folder, and its own
`tools/daily_update.py` cron job — this file only combines the already-built
Dash apps at the web-server layer (Werkzeug's DispatcherMiddleware), so
adding a new use case later is just: build it the same way (build_app +
load_and_build(args, url_base_pathname)), add one entry to USE_CASES below,
add it to _ICONS/_SHORT_NAMES if you want a custom icon/label (the sidebar tab is automatic).

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

    # Reads only ClickHouse tables built by usecases/network_degradation/etl.py.
    args = argparse.Namespace(lookback=10, threshold=15.0)
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


_ICONS = {"network-degradation": "&#128225;", "free-rg-smart-care": "&#129534;"}
_SHORT_NAMES = {"network-degradation": "Network Degradation",
                "free-rg-smart-care": "Free RGs Smart Care"}


def _shell_html() -> str:
    """ONE page: a sidebar with a tab per dashboard, and the selected dashboard
    next to it. Each dashboard is loaded once (first click) and then kept alive,
    so switching tabs is instant and keeps its filters/selection. The URL hash
    (#network-degradation) makes a tab bookmarkable and survives a refresh."""
    nav_items = []
    frame_items = []
    for path, name, desc, _builder in USE_CASES:
        slug = path.strip("/")
        short = _SHORT_NAMES.get(slug, name)
        icon = _ICONS.get(slug, "&#128202;")
        nav_items.append(
            f'<a href="#{slug}" data-slug="{slug}" data-src="{path}" '
            f'data-name="{short}" title="{desc}">'
            f'<span class="ico">{icon}</span><span class="lbl">{short}</span></a>')
        frame_items.append(f'<iframe data-slug="{slug}" title="{name}"></iframe>')
    nav = "\n      ".join(nav_items)
    frames = "\n    ".join(frame_items)
    return f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>PS Core Operations</title>
  <style>
    * {{ box-sizing: border-box; }}
    html, body {{ height: 100%; margin: 0; background: #eef0fc; overflow: hidden;
                 font-family: Inter, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; }}
    body {{ display: flex; }}
    .side {{ flex: 0 0 236px; background: #4f52c9; color: #fff; height: 100vh;
             border-radius: 0 30px 30px 0; padding: 26px 16px; display: flex;
             flex-direction: column; gap: 6px; position: relative;
             transition: flex-basis .18s ease, padding .18s ease; overflow: hidden; }}
    body.collapsed .side {{ flex-basis: 76px; padding: 26px 10px; }}
    body.collapsed .side .lbl, body.collapsed .side .brand div:last-child {{ display: none; }}
    body.collapsed .side .nav a {{ justify-content: center; padding: 12px 0; width: 48px; }}
    .toggle {{ position: absolute; top: 24px; right: -14px; width: 28px; height: 28px;
               border-radius: 50%; background: #fff; color: #4f52c9; border: none;
               box-shadow: 0 4px 10px rgba(0,0,0,.2); cursor: pointer; font-size: 13px;
               display: flex; align-items: center; justify-content: center; z-index: 2; }}
    body.collapsed .toggle {{ transform: rotate(180deg); }}
    .brand {{ display: flex; align-items: center; gap: 12px; padding: 0 8px 22px; }}
    .logo {{ width: 44px; height: 44px; border-radius: 50%; background: #fff; color: #4f52c9;
             font-weight: 800; display: flex; align-items: center; justify-content: center; }}
    .brand b {{ font-size: 15px; line-height: 1.2; }}
    .brand small {{ display: block; font-weight: 400; opacity: .75; font-size: 11.5px; }}
    .nav a {{ display: flex; align-items: center; gap: 12px; padding: 12px 14px; margin-bottom: 6px;
              border-radius: 16px; color: rgba(255,255,255,.88); text-decoration: none;
              font-size: 14px; font-weight: 600; transition: background .15s ease; }}
    .nav a:hover {{ background: rgba(255,255,255,.16); }}
    .nav a.active {{ background: #fff; color: #4f52c9; box-shadow: 0 8px 20px rgba(0,0,0,.18); }}
    .ico {{ font-size: 20px; width: 26px; text-align: center; }}
    .main {{ flex: 1; min-width: 0; height: 100vh; position: relative; }}
    iframe {{ position: absolute; top: 0; left: 0; width: 100%; height: 100%; border: 0;
              background: #eef0fc; display: none; }}
    .hint {{ position: absolute; top: 0; left: 0; right: 0; bottom: 0; display: flex;
             align-items: center; justify-content: center; color: #8b8fae; font-size: 14px; }}
    @media (max-width: 900px) {{
      .side {{ flex-basis: 76px; padding: 20px 10px; align-items: center; }}
      .lbl, .brand div:last-child {{ display: none; }}
      .brand {{ padding-bottom: 16px; }}
      .nav a {{ justify-content: center; padding: 12px 0; width: 48px; }}
      .toggle {{ display: none; }}
    }}
  </style>
</head>
<body>
  <aside class="side">
    <button class="toggle" id="sideToggle" title="Collapse sidebar" aria-label="Collapse sidebar">&#10094;</button>
    <div class="brand"><div class="logo">PS</div>
      <div><b>PS Core Ops</b><small>Operations dashboards</small></div></div>
    <nav class="nav">
      {nav}
    </nav>
  </aside>
  <main class="main">
    <div class="hint">Loading dashboard&hellip;</div>
    {frames}
  </main>
<script>
  var links = Array.prototype.slice.call(document.querySelectorAll('.nav a'));
  var frames = Array.prototype.slice.call(document.querySelectorAll('iframe'));
  function show(slug) {{
    var link = links.filter(function (a) {{ return a.dataset.slug === slug; }})[0] || links[0];
    slug = link.dataset.slug;
    links.forEach(function (a) {{ a.classList.toggle('active', a === link); }});
    frames.forEach(function (f) {{
      var on = f.dataset.slug === slug;
      f.style.display = on ? 'block' : 'none';
      if (on && !f.getAttribute('src')) f.setAttribute('src', link.dataset.src);
    }});
    document.title = link.dataset.name + ' - PS Core Operations';
  }}
  window.addEventListener('hashchange', function () {{ show(location.hash.slice(1)); }});
  show(location.hash.slice(1));
  var toggle = document.getElementById('sideToggle');
  var collapsed = localStorage.getItem('nd_sidebar_collapsed') === '1';
  if (collapsed) document.body.classList.add('collapsed');
  toggle.addEventListener('click', function () {{
    document.body.classList.toggle('collapsed');
    localStorage.setItem('nd_sidebar_collapsed', document.body.classList.contains('collapsed') ? '1' : '0');
  }});
</script>
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
    matches, falling back to the sidebar shell page.
    """

    def __init__(self, landing_wsgi, mounts: dict):
        self.landing_wsgi = landing_wsgi
        self.mounts = mounts  # {"/network-degradation": app.server, ...}

    def __call__(self, environ, start_response):
        path = environ.get("PATH_INFO", "")
        for prefix, wsgi_app in self.mounts.items():
            if path == prefix or path.startswith(prefix + "/"):
                # Dashboard URL opened/bookmarked directly (a top-level page load, not
                # the iframe): send it to the shell so the sidebar is always there.
                if (path.rstrip("/") == prefix
                        and environ.get("HTTP_SEC_FETCH_DEST") == "document"):
                    start_response("302 Found", [("Location", "/#" + prefix.strip("/"))])
                    return [b""]
                return wsgi_app(environ, start_response)
        return self.landing_wsgi(environ, start_response)


def build_hub_application():
    landing = Flask(__name__)

    @landing.route("/")
    def _index():
        return _shell_html()

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
