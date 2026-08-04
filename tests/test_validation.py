import pytest

from bot.validation import InvalidSource, parse_source


def test_public_address_becomes_single_host_cidr():
    assert parse_source("203.0.113.9") == "203.0.113.9/32"


def test_surrounding_whitespace_is_tolerated():
    assert parse_source("  203.0.113.9  ") == "203.0.113.9/32"


def test_any_is_accepted_verbatim():
    assert parse_source("any") == "any"


@pytest.mark.parametrize(
    "hostile",
    [
        "203.0.113.9; rm -rf /",
        "203.0.113.9 && id",
        "$(id)",
        "`id`",
        "203.0.113.9\nid",
        "203.0.113.9|id",
        "203.0.113.9/32",       # we accept bare addresses only
        "203.0.113.9,203.0.113.10",
        "--flag",
        "",
        "ANY",                  # the opt-out token is case-sensitive
        "2001:db8::1",          # IPv6 is out of scope
        "999.1.1.1",
        "203.0.113.09",         # leading zeros are ambiguous, rejected
        "example.com",
    ],
)
def test_hostile_and_malformed_input_is_rejected(hostile):
    with pytest.raises(InvalidSource):
        parse_source(hostile)


@pytest.mark.parametrize(
    "nonroutable",
    ["10.0.0.5", "192.168.1.10", "172.16.4.4", "127.0.0.1",
     "169.254.1.1", "224.0.0.1", "0.0.0.0", "100.101.102.103"],
)
def test_non_routable_addresses_are_rejected(nonroutable):
    """100.64/10 matters specifically: it is the tailnet range."""
    with pytest.raises(InvalidSource):
        parse_source(nonroutable)
