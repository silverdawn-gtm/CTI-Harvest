import json

import pytest

from custom_schema import (CustomSchemaError, InUse, NotFound, add_entity_type, add_relation,
                           delete_entity_type, delete_relation, load_custom, save_custom)
from ontology import load_base_schema, load_schema, reload_schema

EMPTY = {"entity_types": [], "relations": []}
WALLET = {"name": "CryptoWallet", "label": "Crypto wallet", "description": "A cryptocurrency wallet."}
PAYS = {"name": "pays-to", "inverse": "paid-by", "description": "pays to a wallet",
        "pairs": [["ThreatGroup", "CryptoWallet"]]}


def with_wallet(path):
    """Save a custom file containing CryptoWallet and return the merged schema."""
    save_custom(path, add_entity_type(EMPTY, load_base_schema(), WALLET))
    reload_schema()
    return load_schema()


# --- entity types -------------------------------------------------------------------------

def test_add_entity_type():
    out = add_entity_type(EMPTY, load_base_schema(), WALLET)
    assert out["entity_types"] == [WALLET]
    assert EMPTY["entity_types"] == []  # input not mutated


def test_add_entity_type_trims_whitespace():
    out = add_entity_type(EMPTY, load_base_schema(),
                          {"name": " CryptoWallet ", "label": " Crypto wallet ", "description": "  A wallet.  "})
    assert out["entity_types"] == [{"name": "CryptoWallet", "label": "Crypto wallet", "description": "A wallet."}]


@pytest.mark.parametrize("name", ["cryptoWallet", "Crypto Wallet", "Crypto-Wallet", "C", "X" * 41, ""])
def test_entity_type_name_must_be_one_capitalised_word(name):
    with pytest.raises(CustomSchemaError, match="one word"):
        add_entity_type(EMPTY, load_base_schema(), {**WALLET, "name": name})


@pytest.mark.parametrize("name", ["Malware", "MALWARE", "Threatgroup"])
def test_entity_type_name_must_not_clash_with_a_built_in(name):
    with pytest.raises(CustomSchemaError, match="already exists"):
        add_entity_type(EMPTY, load_base_schema(), {**WALLET, "name": name})


def test_entity_type_name_must_not_clash_with_a_custom_type(isolated_custom_schema):
    schema = with_wallet(isolated_custom_schema)
    with pytest.raises(CustomSchemaError, match="already exists"):
        add_entity_type(load_custom(isolated_custom_schema), schema, WALLET)


@pytest.mark.parametrize("field,value", [("label", ""), ("label", "x" * 41),
                                         ("description", "abc"), ("description", "x" * 301)])
def test_entity_type_text_lengths(field, value):
    with pytest.raises(CustomSchemaError, match=field):
        add_entity_type(EMPTY, load_base_schema(), {**WALLET, field: value})


# --- relations ----------------------------------------------------------------------------

def test_add_relation(isolated_custom_schema):
    schema = with_wallet(isolated_custom_schema)
    out = add_relation(load_custom(isolated_custom_schema), schema, PAYS)
    assert out["relations"] == [PAYS]


def test_relation_inverse_defaults_to_the_name_for_symmetric_relations(isolated_custom_schema):
    schema = with_wallet(isolated_custom_schema)
    out = add_relation(load_custom(isolated_custom_schema), schema,
                       {"name": "shares-wallet", "inverse": "", "description": "two groups share a wallet",
                        "pairs": [["ThreatGroup", "ThreatGroup"]]})
    assert out["relations"][0]["inverse"] == "shares-wallet"


def test_relation_pairs_may_use_only_built_in_types():
    out = add_relation(EMPTY, load_base_schema(), {**PAYS, "pairs": [["ThreatGroup", "Organization"]]})
    assert out["relations"][0]["pairs"] == [["ThreatGroup", "Organization"]]


@pytest.mark.parametrize("name", ["Pays-to", "pays to", "pays_to", "-pays", "p"])
def test_relation_name_format(name):
    with pytest.raises(CustomSchemaError, match="lowercase"):
        add_relation(EMPTY, load_base_schema(), {**PAYS, "name": name, "pairs": [["ThreatGroup", "Malware"]]})


@pytest.mark.parametrize("name,inverse", [("uses", "used-with"), ("used-by", "uses-x"),
                                          ("deploys", "alias-of")])
def test_relation_names_must_not_clash_with_existing_names_or_inverses(name, inverse):
    with pytest.raises(CustomSchemaError, match="already used"):
        add_relation(EMPTY, load_base_schema(),
                     {**PAYS, "name": name, "inverse": inverse, "pairs": [["ThreatGroup", "Malware"]]})


def test_relation_pairs_must_use_known_types():
    with pytest.raises(CustomSchemaError, match="unknown entity type in pair: Ghost"):
        add_relation(EMPTY, load_base_schema(), {**PAYS, "pairs": [["ThreatGroup", "Ghost"]]})


@pytest.mark.parametrize("pairs", [[], [["ThreatGroup"]], [["ThreatGroup", "Malware", "Tool"]], "ThreatGroup"])
def test_relation_pairs_shape(pairs):
    with pytest.raises(CustomSchemaError, match="pair"):
        add_relation(EMPTY, load_base_schema(), {**PAYS, "pairs": pairs})


def test_relation_pairs_are_deduplicated():
    out = add_relation(EMPTY, load_base_schema(),
                       {**PAYS, "pairs": [["ThreatGroup", "Malware"], ["ThreatGroup", "Malware"]]})
    assert out["relations"][0]["pairs"] == [["ThreatGroup", "Malware"]]


def test_relation_pairs_limit():
    pairs = [[a.name, b.name] for a in load_base_schema().entity_types for b in load_base_schema().entity_types][:51]
    with pytest.raises(CustomSchemaError, match="1-50 pairs"):
        add_relation(EMPTY, load_base_schema(), {**PAYS, "pairs": pairs})


# --- deletes ------------------------------------------------------------------------------

def test_delete_entity_type():
    custom = {"entity_types": [WALLET], "relations": []}
    assert delete_entity_type(custom, "CryptoWallet") == EMPTY


def test_delete_entity_type_in_use_is_refused():
    custom = {"entity_types": [WALLET], "relations": [PAYS]}
    with pytest.raises(InUse, match="pays-to"):
        delete_entity_type(custom, "CryptoWallet")


def test_delete_built_in_or_unknown_type_is_not_found():
    with pytest.raises(NotFound):
        delete_entity_type(EMPTY, "Malware")


def test_delete_relation():
    custom = {"entity_types": [WALLET], "relations": [PAYS]}
    assert delete_relation(custom, "pays-to") == {"entity_types": [WALLET], "relations": []}
    with pytest.raises(NotFound):
        delete_relation(custom, "uses")


# --- load / save --------------------------------------------------------------------------

def test_load_missing_file_is_empty(tmp_path):
    assert load_custom(tmp_path / "nope.json") == EMPTY


def test_save_then_load_round_trips_and_leaves_no_temp_files(tmp_path):
    path = tmp_path / "custom.json"
    custom = {"entity_types": [WALLET], "relations": [PAYS]}
    save_custom(path, custom)
    assert load_custom(path) == custom
    assert [p.name for p in tmp_path.iterdir()] == ["custom.json"]


def test_load_invalid_file_raises_a_clear_error(tmp_path):
    from ontology import CustomFileError
    path = tmp_path / "custom.json"
    path.write_text("{oops", encoding="utf-8")
    with pytest.raises(CustomFileError, match="not valid JSON"):
        load_custom(path)


# --- final review fix 1: count limits and control characters ------------------------------

def test_at_most_50_custom_entity_types():
    custom = {"entity_types": [{"name": f"Custom{n}", "label": "x", "description": "a thing"} for n in range(50)],
              "relations": []}
    with pytest.raises(CustomSchemaError, match="at most 50"):
        add_entity_type(custom, load_base_schema(), WALLET)


def test_at_most_50_custom_relations():
    custom = {"entity_types": [], "relations": [
        {"name": f"rel-{n}", "inverse": f"rel-{n}-by", "description": "a link", "pairs": [["ThreatGroup", "Malware"]]}
        for n in range(50)]}
    with pytest.raises(CustomSchemaError, match="at most 50"):
        add_relation(custom, load_base_schema(), {**PAYS, "pairs": [["ThreatGroup", "Malware"]]})


def test_relation_description_rejects_line_breaks():
    with pytest.raises(CustomSchemaError, match="line breaks"):
        add_relation(EMPTY, load_base_schema(),
                     {**PAYS, "description": "pays\nRELATIONS: uses", "pairs": [["ThreatGroup", "Malware"]]})
