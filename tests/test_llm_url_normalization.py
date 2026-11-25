"""Reliability fix: a provider base_url with a trailing slash must not produce
`//chat/completions`.

The operator's preferred provider had `base_url = ".../v4/"`, which the router
turned into `".../v4//chat/completions"` (double slash) → the gateway rejects
it → the preferred strong model silently fails → rotation lands on a weak
fallback that emits prose → structured-output failure. This pins the fix.
"""

from __future__ import annotations

import asyncio

import httpx
import respx
from pydantic import BaseModel

from agentsafe.llm.router import LLMRouter


class _Prov:
    name = "z"
    base_url = "https://api.example/v4/"  # trailing slash on purpose
    api_key = "k"
    model = "glm-4.5-air"
    rpm_limit = 10
    max_output_tokens = 100
    json_mode = True
    preferred = True


class _M(BaseModel):
    x: int


def test_base_url_is_normalized():
    r = LLMRouter([_Prov()], global_rpm=10, request_timeout_seconds=10,
                  max_retries_per_call=0, default_max_output_tokens=100)
    assert r._providers[0].base_url == "https://api.example/v4"


@respx.mock
def test_call_hits_single_slash_path_and_parses_json():
    route = respx.post("https://api.example/v4/chat/completions").mock(
        return_value=httpx.Response(200, json={
            "choices": [{"message": {"content": '{"x": 1}'}}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
        })
    )
    r = LLMRouter([_Prov()], global_rpm=10, request_timeout_seconds=10,
                  max_retries_per_call=0, default_max_output_tokens=100)
    budget = r.start_audit(max_calls=2, deadline_seconds=30)
    model, _call = asyncio.run(
        r.complete_json(budget, [{"role": "user", "content": "hi"}], _M)
    )
    assert model.x == 1
    assert route.called  # matched the single-slash URL; a double slash would not