"""WSGI entrypoint for production (Render / Gunicorn).

Import this as: gunicorn backend.wsgi:app
Applies ProxyFix so request.is_secure works behind reverse proxy.
"""
from werkzeug.middleware.proxy_fix import ProxyFix
from .security import app  # reuse existing app definition

# Trust one proxy layer (Render). Adjust if chain differs.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

# Optional: expose variable for type checkers
__all__ = ["app"]
