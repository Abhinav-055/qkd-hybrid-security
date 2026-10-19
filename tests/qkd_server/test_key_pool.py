import threading
import time

import pytest

from qkd_server.key_pool import KeyNotFound, KeyPool, PoolEmpty


@pytest.mark.parametrize("rate_bps", [1000, 10000, 100000])
def test_refill_rate_within_tolerance(rate_bps):
    key_size_bits = 256
    pool = KeyPool(refill_rate_bps=rate_bps, max_keys=1_000_000, key_size_bits=key_size_bits)

    duration_s = 2.0
    tick_s = 0.1
    ticks = int(duration_s / tick_s)
    for _ in range(ticks):
        pool.refill(tick_s)

    expected_keys = (rate_bps * duration_s) / key_size_bits
    actual_keys = pool.occupancy()

    tolerance = 0.05 * expected_keys
    assert abs(actual_keys - expected_keys) <= max(tolerance, 1), (
        f"rate={rate_bps}bps expected~{expected_keys:.1f} got {actual_keys}"
    )


def test_refill_caps_at_max_keys_and_discards_excess():
    pool = KeyPool(refill_rate_bps=1_000_000, max_keys=5, key_size_bits=256)

    added_total = 0
    for _ in range(50):
        added_total += pool.refill(0.1)

    assert pool.occupancy() == 5
    assert added_total == 5  # never grew past the cap even though supply exceeded it


def test_refill_returns_number_of_keys_added():
    pool = KeyPool(refill_rate_bps=2560, max_keys=100, key_size_bits=256)  # 10 keys/sec
    added = pool.refill(1.0)
    assert added == 10
    assert pool.occupancy() == 10


def test_get_key_pops_and_decrements_occupancy():
    pool = KeyPool(refill_rate_bps=100_000, max_keys=100, key_size_bits=256)
    pool.refill(1.0)
    before = pool.occupancy()
    assert before > 0

    key_id, key_bytes = pool.get_key()
    assert isinstance(key_id, str)
    assert len(key_bytes) == 32
    assert pool.occupancy() == before - 1


def test_get_key_on_empty_pool_raises_and_counts_starvation():
    pool = KeyPool(refill_rate_bps=0, max_keys=10, key_size_bits=256)
    assert pool.occupancy() == 0
    assert pool.starvation_events() == 0

    with pytest.raises(PoolEmpty):
        pool.get_key()
    assert pool.starvation_events() == 1

    with pytest.raises(PoolEmpty):
        pool.get_key()
    assert pool.starvation_events() == 2


def test_get_key_does_not_return_zeros_on_empty():
    # There is no "zero key" return path at all -- PoolEmpty is always
    # raised on empty. This test documents/guards that contract explicitly.
    pool = KeyPool(refill_rate_bps=0, max_keys=10, key_size_bits=256)
    try:
        pool.get_key()
        assert False, "expected PoolEmpty"
    except PoolEmpty:
        pass


def test_get_key_by_id_returns_same_bytes_as_get_key():
    pool = KeyPool(refill_rate_bps=100_000, max_keys=100, key_size_bits=256)
    pool.refill(1.0)

    key_id, key_bytes = pool.get_key()
    looked_up = pool.get_key_by_id(key_id)
    assert looked_up == key_bytes


def test_get_key_by_id_unknown_raises_key_not_found():
    pool = KeyPool(refill_rate_bps=0, max_keys=10, key_size_bits=256)
    with pytest.raises(KeyNotFound):
        pool.get_key_by_id("not-a-real-id")


def test_get_keys_atomic_all_or_nothing():
    pool = KeyPool(refill_rate_bps=100_000, max_keys=100, key_size_bits=256)
    pool.refill(1.0)
    occ = pool.occupancy()

    with pytest.raises(PoolEmpty):
        pool.get_keys(occ + 1)
    # nothing should have been popped on the failed bulk request
    assert pool.occupancy() == occ

    popped = pool.get_keys(3)
    assert len(popped) == 3
    assert pool.occupancy() == occ - 3


def test_refill_loop_background_thread_converges_to_rate():
    pool = KeyPool(refill_rate_bps=10000, max_keys=1000, key_size_bits=256)  # ~39 keys/sec
    pool.start_refill_loop(tick_seconds=0.05)
    try:
        time.sleep(1.0)
    finally:
        pool.stop_refill_loop()

    occ = pool.occupancy()
    expected = 39
    assert abs(occ - expected) <= max(0.3 * expected, 5)


def test_concurrent_get_key_never_oversells():
    pool = KeyPool(refill_rate_bps=100_000, max_keys=200, key_size_bits=256)
    pool.refill(1.0)
    total_keys = pool.occupancy()

    results = []
    lock = threading.Lock()

    def worker():
        try:
            key_id, key_bytes = pool.get_key()
            with lock:
                results.append(key_id)
        except PoolEmpty:
            pass

    threads = [threading.Thread(target=worker) for _ in range(total_keys + 20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(results) == total_keys
    assert len(set(results)) == total_keys  # no key handed out twice
    assert pool.occupancy() == 0
