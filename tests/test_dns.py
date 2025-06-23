from datetime import timedelta

import pytest
from dns.rdatatype import RdataType
from dns.resolver import NXDOMAIN, NoAnswer

from certwrangler.dns import resolve_cname, resolve_zone, wait_for_challenges


def test_wait_for_challenges(click_ctx, mocker):
    """
    Test that we can wait for DNS propagation.
    """
    good_answer_mock = mocker.MagicMock()
    good_answer_mock.rdtype = RdataType.TXT
    good_answer_mock.strings[0].decode = mocker.MagicMock(return_value="test123")
    bad_answer_mock = mocker.MagicMock()
    bad_answer_mock.rdtype = RdataType.TXT
    bad_answer_mock.strings[0].decode = mocker.MagicMock(return_value="oops123")
    click_ctx.obj.resolver.resolve = mocker.MagicMock(
        side_effect=[
            NXDOMAIN(),
            [bad_answer_mock],
            [good_answer_mock],
            NoAnswer(),
            [good_answer_mock],
        ]
    )
    wait_timeout = timedelta(seconds=30)
    wait_for_challenges(
        [("test.example.com", "test123"), ("test1.example.com", "test123")],
        wait_timeout,
        sleep=0,
    )
    assert click_ctx.obj.resolver.resolve.call_args_list == [
        mocker.call("test.example.com", rdtype=RdataType.TXT),
        mocker.call("test1.example.com", rdtype=RdataType.TXT),
        mocker.call("test.example.com", rdtype=RdataType.TXT),
        mocker.call("test1.example.com", rdtype=RdataType.TXT),
        mocker.call("test1.example.com", rdtype=RdataType.TXT),
    ]


def test_wait_for_challenges_timeout(click_ctx, mocker):
    """
    Test that we raise a TimeoutError if we exceed our wait_timeout.
    """
    click_ctx.obj.resolver.resolve = mocker.MagicMock(side_effect=NXDOMAIN())
    wait_timeout = timedelta(seconds=1)
    with pytest.raises(
        TimeoutError,
        match="Timeout expired for DNS propagation of following records: test.example.com, test1.example.com.",
    ):
        wait_for_challenges(
            [("test.example.com", "test123"), ("test1.example.com", "test123")],
            wait_timeout,
            sleep=1,
        )


def test_resolve_cname(click_ctx, mocker):
    """
    Test that we can resolve CNAMEs.
    """
    answer_1 = mocker.MagicMock()
    answer_1.target = "answer1.example.com."
    answer_2 = mocker.MagicMock()
    answer_2.target = "answer2.example.com."
    answer_3 = mocker.MagicMock()
    answer_3.target = "answer3.example.com."
    click_ctx.obj.resolver.resolve = mocker.MagicMock(
        side_effect=[
            [answer_1],
            [answer_2],
            [answer_3],
            NoAnswer(),
        ]
    )
    assert resolve_cname("example.com") == "answer3.example.com"


def test_resolve_cname_infinite_loop(click_ctx, mocker):
    """
    Test that we raise a ValueError if the CNAMEs end in an infinite loop.
    """
    answer_1 = mocker.MagicMock()
    answer_1.target = "answer1.example.com"
    answer_2 = mocker.MagicMock()
    answer_2.target = "example.com"
    click_ctx.obj.resolver.resolve = mocker.MagicMock(
        side_effect=[
            [answer_1],
            [answer_2],
        ]
    )
    with pytest.raises(
        ValueError,
        match=(
            "Error, CNAME resolution for example.com ended in an infinite loop!\n"
            "example.com -> answer1.example.com -> example.com"
        ),
    ):
        resolve_cname("example.com")


def test_resolve_zone(click_ctx, mocker):
    """
    Test that we can resolve a zone down to its SOA.
    """
    cname_answer = mocker.MagicMock()
    cname_answer.rdtype = RdataType.CNAME
    soa_answer = mocker.MagicMock()
    soa_answer.rdtype = RdataType.SOA
    soa_answer.name.to_text = mocker.MagicMock(return_value="zone1.example.com.")
    a_answer = mocker.MagicMock()
    a_answer.rdtype = RdataType.A
    response_1 = mocker.MagicMock()
    response_1.response.answer = [a_answer]
    response_2 = mocker.MagicMock()
    response_2.response.answer = [cname_answer]
    response_4 = mocker.MagicMock()
    response_4.response.answer = [a_answer, soa_answer]
    click_ctx.obj.resolver.resolve = mocker.MagicMock(
        side_effect=[
            response_1,
            response_2,
            NoAnswer(),
            response_4,
        ]
    )
    assert resolve_zone("testing.dev.region1.zone1.example.com") == "zone1.example.com"


def test_resolve_zone_no_SOA(click_ctx, mocker):
    """
    Test that we raise a ValueError if no SOA is found.
    """
    cname_answer = mocker.MagicMock()
    cname_answer.rdtype = RdataType.CNAME
    a_answer = mocker.MagicMock()
    a_answer.rdtype = RdataType.A
    response_1 = mocker.MagicMock()
    response_1.response.answer = [a_answer]
    response_2 = mocker.MagicMock()
    response_2.response.answer = [cname_answer]
    click_ctx.obj.resolver.resolve = mocker.MagicMock(
        side_effect=[
            response_1,
            response_2,
            NoAnswer(),
            NXDOMAIN(),
        ]
    )
    with pytest.raises(
        ValueError,
        match="Unable to find SOA in DNS tree for 'region1.zone1.example.com'",
    ):
        resolve_zone("region1.zone1.example.com")
