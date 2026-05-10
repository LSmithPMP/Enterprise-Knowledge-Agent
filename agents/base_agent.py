"""
================================================================================
BASE AGENT
Enterprise Knowledge Research Agent
================================================================================
All 10 agents inherit from BaseAgent. Provides:
- Prompt injection filtering (security control)
- Cost and latency tracking per LLM call
- Structured JSON output enforcement
- Graceful error handling — no agent failure crashes pipeline
- LangSmith tracing integration
================================================================================
"""

import os
import re
import time
import json
from dotenv import load_dotenv
from openai import OpenAI
from agents.contracts import AgentCost

load_dotenv()

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

MODEL_PRICING = {
    "gpt-4o-mini": {"input": 0.15, "output": 0.60},
    "gpt-4o":      {"input": 2.50, "output": 10.00},
}

# Injection patterns blocked before every LLM call
INJECTION_PATTERNS = [
    r"ignore previous instructions",
    r"ignore all previous",
    r"disregard.*instructions",
    r"you are now",
    r"act as",
    r"jailbreak",
    r"reveal.*system prompt",
    r"print.*system prompt",
    r"<[|].*?[|]>",
    r"\[INST\]",
    r"###.*?###",
    r"eval[(]",
    r"exec[(]",
    r"DROP TABLE",
    r"SELECT \* FROM",
    r"__import__",
]


def calculate_cost(model: str, input_tokens: int, output_tokens: int) -> float:
    """Calculate estimated USD cost for a model call."""
    pricing = MODEL_PRICING.get(model, MODEL_PRICING["gpt-4o-mini"])
    return round(
        (input_tokens  / 1_000_000) * pricing["input"] +
        (output_tokens / 1_000_000) * pricing["output"],
        6
    )


class BaseAgent:
    """
    Base class for all 10 research agents.

    Security controls applied at this layer:
    - _sanitize_input(): blocks 16 prompt injection patterns
    - JSON output format enforced on every LLM call
    - Input truncated at 12000 chars to prevent context overflow attacks
    """

    def __init__(self, agent_name: str, model: str = "gpt-4o-mini"):
        self.agent_name = agent_name
        self.model = model
        self.cost_log: list[AgentCost] = []

    def _sanitize_input(self, text: str) -> str:
        """
        SECURITY CONTROL: Filter prompt injection patterns.
        Applied before every LLM call regardless of input source.
        Blocks 16 known injection patterns including jailbreak attempts,
        system prompt extraction, and code execution attempts.
        """
        cleaned = text
        for pattern in INJECTION_PATTERNS:
            cleaned = re.sub(pattern, "[FILTERED]", cleaned,
                             flags=re.IGNORECASE | re.DOTALL)
        # Truncate to prevent context overflow attacks
        if len(cleaned) > 12000:
            cleaned = cleaned[:12000] + "\n...[TRUNCATED FOR SECURITY]"
        return cleaned

    def _sanitize_output(self, text: str) -> str:
        """
        SECURITY CONTROL: Filter sensitive patterns from output.
        Prevents accidental leakage of system internals in responses.
        """
        # Remove any system prompt fragments that may have leaked
        text = re.sub(r"OPENAI_API_KEY.*", "[REDACTED]", text, flags=re.IGNORECASE)
        text = re.sub(r"sk-[a-zA-Z0-9-_]{20,}", "[REDACTED_KEY]", text)
        text = re.sub(r"lsv2_[a-zA-Z0-9-_]{20,}", "[REDACTED_KEY]", text)
        return text

    def call_llm(self, system_prompt: str, user_prompt: str,
                 temperature: float = 0.1) -> tuple[str, AgentCost]:
        """
        Make a tracked, sanitized LLM call.

        Flow:
        1. Sanitize user input (security)
        2. Call LLM with JSON output format enforced
        3. Sanitize output (security)
        4. Log cost and latency
        5. Return response + cost record
        """
        start = time.time()
        success = True
        error_message = None
        response_text = "{}"
        input_tokens = 0
        output_tokens = 0

        # Apply security sanitization
        user_prompt = self._sanitize_input(user_prompt)

        try:
            response = client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user",   "content": user_prompt}
                ],
                temperature=temperature,
                response_format={"type": "json_object"}
            )
            response_text  = self._sanitize_output(
                response.choices[0].message.content
            )
            input_tokens   = response.usage.prompt_tokens
            output_tokens  = response.usage.completion_tokens

        except Exception as e:
            success = False
            error_message = str(e)
            print(f"  [ERROR] {self.agent_name}: {error_message}")

        latency = round(time.time() - start, 2)
        cost = AgentCost(
            agent_name=self.agent_name,
            model_used=self.model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            latency_seconds=latency,
            estimated_usd=calculate_cost(self.model, input_tokens, output_tokens),
            success=success,
            error_message=error_message
        )
        self.cost_log.append(cost)
        return response_text, cost

    def _to_str(self, value) -> str:
        """Convert any LLM output value to string safely."""
        if isinstance(value, str):  return value
        if isinstance(value, dict): return json.dumps(value)
        if isinstance(value, list): return "; ".join(str(v) for v in value)
        return str(value)

    def run(self, *args, **kwargs):
        raise NotImplementedError(f"{self.agent_name} must implement run()")
