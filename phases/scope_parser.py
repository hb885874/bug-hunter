
def parse_scope(target):
    print(f"[Scope] Parsing scope for {target}")
    return {
        "domain": target,
        "allowed_methods": ["GET", "HEAD"],
        "notes": "Manual validation of VDP scope required."
    }
