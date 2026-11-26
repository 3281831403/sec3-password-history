"""Public test suite for the password history exercise."""

from engine.pwdhist import (
    check_reuse,
    hash_password,
    history_batch,
    load_history,
    push_history,
)

_SALT = "public-salt-01"
_ITERATIONS = 120000


def _digest(password, salt=_SALT):
    return hash_password(
        password,
        salt,
        {"algo": "pbkdf2_sha256", "iterations": _ITERATIONS},
    )


def test_hash_is_salted_and_deterministic():
    first = hash_password(
        "correct-horse", "salt-alpha", {"algo": "pbkdf2_sha256", "iterations": _ITERATIONS}
    )
    repeat = hash_password(
        "correct-horse", "salt-alpha", {"algo": "pbkdf2_sha256", "iterations": _ITERATIONS}
    )
    other = hash_password(
        "correct-horse", "salt-beta", {"algo": "pbkdf2_sha256", "iterations": _ITERATIONS}
    )

    assert first == repeat
    assert first != other
    assert first.split("$")[-1] != other.split("$")[-1]


def test_history_keeps_recent_entries_within_limit():
    store = {
        "acct": {
            "digest": "d5",
            "history": ["d0", "d1", "d2", "d3", "d4", "d5"],
        }
    }

    recent = load_history(store, "acct", 3)

    assert recent == ["d3", "d4", "d5"]


def test_reuse_is_detected_anywhere_in_history():
    history = [_digest("first-pass"), _digest("second-pass"), _digest("third-pass")]

    assert check_reuse("first-pass", history) is True
    assert check_reuse("second-pass", history) is True
    assert check_reuse("fresh-pass", history) is False


def test_push_history_evicts_the_oldest_entry():
    store = {}

    for index in range(4):
        push_history(store, "acct", "digest-%d" % index, 3)

    assert load_history(store, "acct", 3) == ["digest-1", "digest-2", "digest-3"]


def test_batch_checks_each_request_against_its_own_history():
    store = {
        "alice": {"digest": _digest("alice-old"), "history": [_digest("alice-old")]},
        "bob": {"digest": _digest("bob-old"), "history": [_digest("bob-old")]},
    }
    requests = [
        {"account": "alice", "password": "alice-fresh", "limit": 5},
        {"account": "bob", "password": "bob-old", "limit": 5},
    ]

    outcome = history_batch(requests, store)

    assert [item["reuse"] for item in outcome["results"]] == [False, True]