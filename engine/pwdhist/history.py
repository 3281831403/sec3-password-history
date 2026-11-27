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
_PBKDF2_PREFIX = "pbkdf2_"


def _resolve_algorithm(algo):
    """Return the hashlib PRF name for a digest algorithm label."""
    if algo is None:
        algo = _ALGORITHM
    if not isinstance(algo, str) or not algo:
        raise ValueError("unsupported hash algorithm: %r" % (algo,))
    if not algo.startswith(_PBKDF2_PREFIX):
        raise ValueError("unsupported hash algorithm: %r" % (algo,))
    prf = algo[len(_PBKDF2_PREFIX):]
    try:
        hashlib.pbkdf2_hmac(prf, b"", b"", 1)
    except (ValueError, TypeError):
        raise ValueError("unsupported hash algorithm: %r" % (algo,))
    return prf


def _normalize_limit(limit):
    """Normalize a history window to a non-negative int or None (no bound)."""
    if limit is None or isinstance(limit, bool):
        return None
    if isinstance(limit, int):
        return max(limit, 0)
    try:
        return max(int(limit), 0)
    except (TypeError, ValueError):
        return None


def _parse_digest(entry):
    """Split a self describing digest into (algorithm, iterations, salt)."""
    if not isinstance(entry, str):
        return None
    parts = entry.split("$")
    if len(parts) != 4:
        return None
    algorithm, iterations, salt, hexdigest = parts
    if not hexdigest:
        return None
    try:
        iterations = int(iterations)
    except (TypeError, ValueError):
        return None
    if iterations < 1:
        return None
    try:
        _resolve_algorithm(algorithm)
    except ValueError:
        return None
    return algorithm, iterations, salt


def _record(store, account):
    """Return the stored record of account without creating one."""
    record = store.get(account)
    if not isinstance(record, dict):
        return None
    return record


def hash_password(password, salt, params):
    """Return the digest of password for salt under params."""
    if not isinstance(password, str):
        raise TypeError("password must be a string")
    if params is None:
        params = {}
    if not isinstance(params, dict):
        raise TypeError("params must be a mapping")

    algorithm = params.get("algo", _ALGORITHM)
    prf = _resolve_algorithm(algorithm)

    iterations = params.get("iterations", _DEFAULT_ITERATIONS)
    if isinstance(iterations, bool):
        raise ValueError("iterations must be a positive integer")
    try:
        iterations = int(iterations)
    except (TypeError, ValueError):
        raise ValueError("iterations must be a positive integer")
    if iterations < 1:
        raise ValueError("iterations must be a positive integer")

    if salt is None:
        salt = ""
    if not isinstance(salt, str):
        salt = str(salt)

    derived = hashlib.pbkdf2_hmac(
        prf,
        password.encode("utf-8"),
        salt.encode("utf-8"),
        iterations,
    )
    return "%s$%d$%s$%s" % (algorithm, iterations, salt, derived.hex())


def load_history(store, account, limit):
    """Return the recent password digests of account, newest entry last."""
    record = _record(store, account)
    if record is None:
        return []
    entries = record.get("history")
    if not isinstance(entries, (list, tuple)):
        return []
    entries = list(entries)
    window = _normalize_limit(limit)
    if window is None:
        return entries
    if window == 0:
        return []
    return entries[-window:]


def check_reuse(password, history):
    """Return True when password matches an entry of history.

    Every entry is hashed with the salt and iteration count embedded in it and
    compared in constant time; malformed entries are ignored.
    """
    if not isinstance(password, str) or not history:
        return False
    try:
        entries = list(history)
    except TypeError:
        return False

    matched = False
    for entry in entries:
        parsed = _parse_digest(entry)
        if parsed is None:
            continue
        algorithm, iterations, salt = parsed
        try:
            candidate = hash_password(
                password,
                salt,
                {"algo": algorithm, "iterations": iterations},
            )
            equal = hmac.compare_digest(
                candidate.encode("utf-8"),
                entry.encode("utf-8"),
            )
        except (ValueError, TypeError, UnicodeError):
            continue
        # Keep checking every entry so the work does not depend on where a
        # match (if any) is located.
        matched = matched | equal
    return bool(matched)


def push_history(store, account, digest, limit):
    """Append digest to the history of account and keep the window bounded."""
    record = _record(store, account)
    if record is None:
        record = {"digest": None, "history": []}
    entries = record.get("history")
    if not isinstance(entries, (list, tuple)):
        entries = []
    entries = list(entries)
    entries.append(digest)

    window = _normalize_limit(limit)
    if window is not None:
        entries = [] if window == 0 else entries[-window:]

    updated = dict(record)
    updated.setdefault("digest", None)
    updated["history"] = list(entries)
    store[account] = updated

    return {"account": account, "history": list(entries), "size": len(entries)}


def check_params(params, policy):
    """Return True when the hashing parameters satisfy policy."""
    if not isinstance(params, dict) or not isinstance(policy, dict):
        return False
    if policy.get("allow_plaintext"):
        return False

    algorithm = policy.get("algo")
    if not isinstance(algorithm, str) or not algorithm:
        return False
    try:
        _resolve_algorithm(algorithm)
    except ValueError:
        return False
    if params.get("algo") != algorithm:
        return False

    minimum = policy.get("min_iterations")
    if isinstance(minimum, bool) or not isinstance(minimum, int) or minimum < 1:
        return False
    iterations = params.get("iterations")
    if isinstance(iterations, bool) or not isinstance(iterations, int):
        return False
    if iterations < minimum:
        return False

    if policy.get("require_salt"):
        salt = params.get("salt")
        if not isinstance(salt, str) or not salt:
            return False

    return True


def change_password(store, account, new_password, params, limit):
    """Rotate the password of account and record the change in history."""
    if params is None:
        params = {}
    if not isinstance(params, dict):
        raise TypeError("params must be a mapping")

    record = _record(store, account)
    if record is None:
        record = {"digest": None, "history": []}

    salt = params.get("salt", "")
    digest = hash_password(new_password, salt, params)

    # Reject a password that appears anywhere in the retained history window,
    # including the current digest (which is the newest entry by contract).
    history = load_history(store, account, limit)
    current = record.get("digest")
    if isinstance(current, str) and current and current not in history:
        history = history + [current]
    if check_reuse(new_password, history):
        # Nothing has been written yet, so the store is left untouched.
        raise ValueError("password was used recently")

    entries = list(history)
    entries.append(digest)
    window = _normalize_limit(limit)
    if window is not None:
        entries = [] if window == 0 else entries[-window:]

    updated = dict(record)
    updated["digest"] = digest
    updated["history"] = list(entries)
    store[account] = updated

    return {
        "ok": True,
        "account": account,
        "digest": digest,
        "history": list(entries),
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
    for request in requests or []:
        if not isinstance(request, dict):
            results.append({"account": None, "reuse": False})
            continue
        account = request.get("account")
        history = load_history(store, account, request.get("limit", 5))
        try:
            reuse = check_reuse(request.get("password", ""), history)
        except (TypeError, ValueError):
            reuse = False
        results.append({"account": account, "reuse": reuse})
    return {"results": results, "count": len(results)}
