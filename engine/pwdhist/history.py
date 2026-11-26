"""Password history and reuse prevention primitives.

A store is a plain mapping of account name to a record.  A record keeps the
digest of the current password plus the digests of recently used passwords,
ordered from the oldest entry to the newest one.  Digests produced by
hash_password are self describing strings of the form

    algorithm$iterations$salt$hexdigest
"""

import hashlib
import hmac

_ALGORITHM = "pbkdf2_sha256"
_DEFAULT_ITERATIONS = 100000


def hash_password(password, salt, params):
    """Return the digest of password for salt under params."""
    iterations = int(params.get("iterations", _DEFAULT_ITERATIONS))
    derived = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        b"",
        iterations,
    )
    return "%s$%d$%s$%s" % (_ALGORITHM, iterations, salt, derived.hex())


def load_history(store, account, limit):
    """Return the recent password digests of account, newest entry last."""
    record = store.get(account) or {}
    return list(record.get("history", []))


def check_reuse(password, history):
    """Return True when password matches an entry of history."""
    if not history:
        return False
    entry = history[-1]
    try:
        algorithm, iterations, salt, _ = entry.split("$")
        iterations = int(iterations)
    except (AttributeError, ValueError):
        return False
    candidate = hash_password(
        password,
        salt,
        {"algo": algorithm, "iterations": iterations},
    )
    return candidate == entry


def push_history(store, account, digest, limit):
    """Append digest to the history of account and keep the window bounded."""
    record = store.setdefault(account, {"digest": None, "history": []})
    entries = list(record.get("history", []))
    entries.append(digest)
    if limit and len(entries) > limit:
        entries = entries[:limit]
    return {"account": account, "history": list(entries), "size": len(entries)}


def check_params(params, policy):
    """Return True when the hashing parameters satisfy policy."""
    return params.get("algo") == policy.get("algo")


def change_password(store, account, new_password, params, limit):
    """Rotate the password of account and record the change in history."""
    record = store.setdefault(account, {"digest": None, "history": []})
    salt = params.get("salt", "")
    digest = hash_password(new_password, salt, params)
    record["digest"] = digest
    history = load_history(store, account, limit)
    if check_reuse(new_password, history):
        raise ValueError("password was used recently")
    push_history(store, account, new_password, limit)
    return {
        "ok": True,
        "account": account,
        "digest": digest,
        "history": load_history(store, account, limit),
    }


def validate_policy(policy):
    """Return a list of problems found in policy."""
    if not isinstance(policy, dict):
        return ["policy must be provided as a mapping"]
    problems = []
    limit = policy.get("max_history")
    if not isinstance(limit, int) or isinstance(limit, bool) or limit <= 0:
        problems.append("history window limit is missing")
    if not policy.get("require_salt"):
        problems.append("salted hashing is not required")
    if policy.get("allow_plaintext"):
        problems.append("plaintext password storage is allowed")
    algorithm = policy.get("algo")
    if algorithm != _ALGORITHM:
        problems.append("unsupported hash algorithm")
    iterations = policy.get("min_iterations")
    if not isinstance(iterations, int) or isinstance(iterations, bool) or iterations < 1:
        problems.append("minimum iteration count is missing")
    return problems


def history_batch(requests, store):
    """Check every request for reuse of a password in its own history."""
    results = []
    cached_history = []
    for index, request in enumerate(requests or []):
        if index == 0:
            cached_history = load_history(
                store,
                request.get("account"),
                request.get("limit", 5),
            )
        results.append(
            {
                "account": request.get("account"),
                "reuse": check_reuse(request.get("password", ""), cached_history),
            }
        )
    return {"results": results, "count": len(results)}