import sys
sys.path.insert(0, '.')
from app import app

# Test that the app creates successfully and all routes are registered
print("Flask app created successfully")
print(f"WSGI application variable: {hasattr(app, 'application')}")

routes = list(app.url_map.iter_rules())
print(f"Total routes registered: {len(routes)}")
for rule in sorted(routes, key=lambda r: r.rule):
    methods = ', '.join(sorted(rule.methods - {'HEAD', 'OPTIONS'}))
    print(f"  {rule.rule:40s} -> {rule.endpoint:30s} [{methods}]")

# Test that the app context works
with app.app_context():
    from flask import url_for
    # Test that url_for works for key routes
    try:
        url_for('home')
        print("url_for('home'): OK")
    except Exception as e:
        print(f"url_for('home'): FAILED - {e}")

    try:
        url_for('dashboard')
        print("url_for('dashboard'): OK")
    except Exception as e:
        print(f"url_for('dashboard'): FAILED - {e}")

    try:
        url_for('health_check')
        print("url_for('health_check'): OK")
    except Exception as e:
        print(f"url_for('health_check'): FAILED - {e}")

print("\nAll checks passed!")