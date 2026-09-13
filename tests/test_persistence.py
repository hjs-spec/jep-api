from concurrent.futures import ThreadPoolExecutor
from state import LocalState


def test_key_and_consumed_nonce_survive_new_instance(tmp_path):
    first = LocalState(tmp_path)
    before = first.signing_key().public_key().public_bytes_raw()
    assert first.consume_nonce("actor", "aud", "n", now=10, expires=100)
    second = LocalState(tmp_path)
    assert second.signing_key().public_key().public_bytes_raw() == before
    assert not second.consume_nonce("actor", "aud", "n", now=11, expires=100)
    assert second.consume_nonce("actor", "different-aud", "n", now=11, expires=100)
    assert second.path.stat().st_mode & 0o077 == 0


def test_multiple_connections_consume_once(tmp_path):
    stores = [LocalState(tmp_path) for _ in range(8)]
    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(lambda i: stores[i].consume_nonce("a", "b", "n", now=10, expires=100), range(8)))
    assert sum(outcomes) == 1
