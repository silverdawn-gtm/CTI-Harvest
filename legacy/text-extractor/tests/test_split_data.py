import json

from split_data import load_records, split_records


def test_split_sizes_are_80_10_10():
    train, dev, test = split_records(list(range(100)))
    assert (len(train), len(dev), len(test)) == (80, 10, 10)


def test_split_is_disjoint_and_complete():
    train, dev, test = split_records(list(range(57)))
    assert sorted(train + dev + test) == list(range(57))


def test_split_is_deterministic_for_a_seed():
    assert split_records(list(range(50)), seed=7) == split_records(list(range(50)), seed=7)


def test_split_shuffles():
    train, _, _ = split_records(list(range(100)))
    assert train != list(range(80))


def test_load_records_reads_json_array(tmp_path):
    path = tmp_path / "a.json"
    path.write_text(json.dumps([{"text": "a"}, {"text": "b"}]))
    assert load_records(path) == [{"text": "a"}, {"text": "b"}]


def test_load_records_reads_json_lines(tmp_path):
    path = tmp_path / "a.json"
    path.write_text('{"text": "a"}\n\n{"text": "b"}\n')
    assert load_records(path) == [{"text": "a"}, {"text": "b"}]
