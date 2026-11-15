import sys
sys.path.insert(0, '.')
from app import app
print("Registered routes:")
for rule in app.url_map.iter_rules():
    print(f"  {rule.rule} -> {rule.endpoint} [{', '.join(rule.methods)}]")
print(f"\nTotal routes: {len(list(app.url_map.iter_rules()))}")
print(f"WSGI application: {hasattr(app, 'application')}")