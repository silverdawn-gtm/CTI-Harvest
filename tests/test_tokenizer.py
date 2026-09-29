from tokenizer import tokenize, split_sentences


def test_separates_comma_from_word():
    assert tokenize("policy, typically") == "policy , typically"


def test_separates_final_period():
    assert tokenize("It targets banks.") == "It targets banks ."


def test_separates_brackets_and_quotes():
    assert tokenize('the "Sofacy" group (APT28)') == 'the " Sofacy " group ( APT28 )'


def test_keeps_internal_punctuation_in_names():
    assert tokenize("admin@338 used 3.5 and C:\\win.exe") == "admin@338 used 3.5 and C:\\win.exe"


def test_collapses_any_whitespace():
    assert tokenize("a \t b\n c") == "a b c"


def test_retokenizing_is_a_no_op():
    once = tokenize('APT28, also "Fancy Bear"; targets (U.S.) govt.')
    assert tokenize(once) == once


def test_split_sentences_on_terminal_punctuation():
    assert split_sentences("It targets banks. It uses PlugX!  Why?") == [
        "It targets banks.",
        "It uses PlugX!",
        "Why?",
    ]


def test_split_sentences_ignores_blank_input():
    assert split_sentences("   \n ") == []


# --- indicators must survive as single tokens (v2 regex types) --------------------------

def test_keeps_defanged_url_whole_and_splits_trailing_comma():
    assert tokenize("from hxxp://evil[.]com/a.php, then") == "from hxxp://evil[.]com/a.php , then"


def test_keeps_defanged_ip_whole_at_sentence_end():
    assert tokenize("contacted 185.12.45[.]6.") == "contacted 185.12.45[.]6 ."


def test_keeps_bracketed_dot_domain_whole():
    assert tokenize("resolves evil[.]com") == "resolves evil[.]com"


def test_keeps_file_name_whole_at_sentence_end():
    assert tokenize("It drops svchost.exe.") == "It drops svchost.exe ."


def test_keeps_hash_whole():
    h = "d41d8cd98f00b204e9800998ecf8427e"
    assert tokenize(f"hash ({h})") == f"hash ( {h} )"


def test_keeps_technique_id_whole():
    assert tokenize("uses T1566.001, then") == "uses T1566.001 , then"


def test_split_sentences_does_not_split_after_abbreviations():
    text = "It targets U.S. agencies, e.g. the DoD. It also uses PlugX."
    assert split_sentences(text) == ["It targets U.S. agencies, e.g. the DoD.", "It also uses PlugX."]


def test_split_sentences_does_not_split_inside_indicators():
    assert split_sentences("It contacts evil[.]com. Then it waits.") == [
        "It contacts evil[.]com.", "Then it waits."]


def test_splits_possessive_s_like_the_dataset():
    assert tokenize("APT28's backdoor and the group’s tools") == "APT28 's backdoor and the group ’s tools"


def test_leaves_other_apostrophes_alone():
    assert tokenize("don't touch O'Brien") == "don't touch O'Brien"


def test_splits_curly_double_quotes():
    assert tokenize("fetched “jquerycodedownload.live/check.aspx” from") == \
        "fetched “ jquerycodedownload.live/check.aspx ” from"
