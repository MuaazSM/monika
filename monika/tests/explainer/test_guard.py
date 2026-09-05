"""Output guard (defence in depth for rule 1)."""

from __future__ import annotations

from app.explainer.guard import guard_output, split_explanation

GOOD = (
    "One session read multiple user records it does not own, the signature of a BOLA sweep. "
    "The sequential ids indicate deliberate enumeration.\n"
    "Next step: review the session's recent object access."
)


def test_clean_prose_passes() -> None:
    assert guard_output(GOOD) == GOOD.strip()


def test_confidence_number_is_rejected() -> None:
    assert guard_output("This looks malicious. confidence: 87\nNext step: review.") is None


def test_score_number_is_rejected() -> None:
    assert guard_output("Risk score 95 detected.\nNext step: review.") is None


def test_block_recommendation_in_next_step_is_rejected() -> None:
    assert guard_output("A sweep occurred.\nNext step: block the session immediately.") is None


def test_factual_mention_of_block_in_explanation_is_allowed() -> None:
    # "was blocked" in the explanation body (not a recommendation) is fine.
    text = "The sweep was blocked by the ladder.\nNext step: review recent access."
    assert guard_output(text) == text


def test_empty_is_none() -> None:
    assert guard_output("") is None
    assert guard_output(None) is None


def test_split_explanation() -> None:
    expl, nxt = split_explanation(GOOD)
    assert expl.startswith("One session")
    assert nxt == "review the session's recent object access."
