"""Quick smoke-test for reference extraction + URL resolution."""
import sys, json
sys.path.insert(0, r"c:\Users\ramst\Downloads\google anti gravity\403 bypasser")

from bypasser.verification import _extract_references, _resolve_url
from bypasser.db import init_db

init_db()
print("imports + DB OK")

base = "https://api.example.com/user/100"

# ── HTML attributes ────────────────────────────────────────────
html_body = '<a href="/admin/panel">link</a> <img src="images/avatar.jpg">'
refs = _extract_references(html_body, base)
print(f"\nHTML body: {len(refs)} ref(s)")
for r in refs:
    print(f"  {r}")

# ── JSON body ──────────────────────────────────────────────────
json_body = json.dumps({
    "profile_id": 42567,
    "avatar_url": "/cdn/img/42567.jpg",
    "related_user_id": 99999,
    "name": "Alice",
    "nested": {"image_url": "https://cdn.example.com/pic/1.png"},
})
refs2 = _extract_references(json_body, base)
print(f"\nJSON body: {len(refs2)} ref(s)")
for r in refs2:
    print(f"  {r}")

# ── Inline URLs ────────────────────────────────────────────────
inline_body = "Visit https://cdn.example.com/assets/file.png or https://api.example.com/resource/200"
refs3 = _extract_references(inline_body, base)
print(f"\nInline body: {len(refs3)} ref(s)")
for r in refs3:
    print(f"  {r}")

# ── _resolve_url unit tests ───────────────────────────────────
print("\n_resolve_url tests:")
print("  absolute :", _resolve_url("https://other.com/path", base))
print("  relative :", _resolve_url("/api/v2/info", base))
print("  numericID:", _resolve_url("12345", base))
print("  pathlike :", _resolve_url("static/files/doc.pdf", base))
print("  empty    :", repr(_resolve_url("", base)))
print("  short_id :", repr(_resolve_url("5", base)))  # too short, should be ""

print("\nAll tests passed.")
