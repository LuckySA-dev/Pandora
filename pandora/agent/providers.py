"""LLM backends behind one tiny interface. Each keeps its own native history (append-only).

    p = make(cfg_llm, system, tools)          # tools: [{"name", "description", "input_schema"}]
    text, calls = p.step(user_text)           # first turn; calls = [{"id","name","args"}]
    text, calls = p.step(results=[(id, name, output, is_error)])
"""
import json

import httpx

NO_CREDS = ("No Claude credentials: set ANTHROPIC_API_KEY (or run `ant auth login`), "
            "or set llm.provider = \"ollama\" in pandora.toml")


class Claude:
    def __init__(self, model, system, tools):
        import anthropic
        try:
            self.client = anthropic.Anthropic()  # ANTHROPIC_API_KEY / ANTHROPIC_AUTH_TOKEN / ant auth profile
        except Exception as e:  # newer SDKs fail here when no credential is found
            raise RuntimeError(NO_CREDS) from e
        self.model, self.system, self.tools, self.messages = model, system, tools, []

    def step(self, user_text=None, results=None):
        if user_text is not None:
            self.messages.append({"role": "user", "content": user_text})
        else:  # every tool result goes back in ONE user message
            self.messages.append({"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": i, "content": out, "is_error": err}
                for i, _, out, err in results]})
        try:
            resp = self.client.beta.messages.create(
                model=self.model, max_tokens=16000, system=self.system, tools=self.tools, messages=self.messages,
                betas=["server-side-fallback-2026-07-01"],
                # extra_body so older installed SDKs don't reject newer fields.
                # fallbacks: re-run on a fallback model if the request is declined.
                extra_body={"thinking": {"type": "adaptive"}, "output_config": {"effort": "high"},
                            "fallbacks": "default"},
            )
        except TypeError as e:  # older SDKs only notice the missing credential when sending
            if "authentication" in str(e).lower():
                raise RuntimeError(NO_CREDS) from e
            raise
        # Append the full content (thinking/fallback blocks included): history stays append-only.
        self.messages.append({"role": "assistant", "content": resp.content})
        if resp.stop_reason == "refusal":
            return "The model declined this request.", []
        text = "\n".join(b.text for b in resp.content if b.type == "text")
        calls = [{"id": b.id, "name": b.name, "args": b.input} for b in resp.content if b.type == "tool_use"]
        if resp.stop_reason == "max_tokens" and not calls:
            text += "\n[stopped: max_tokens]"
        return text, calls


class Ollama:
    def __init__(self, model, system, tools, url):
        self.model, self.url = model, url.rstrip("/")
        self.tools = [{"type": "function", "function": {"name": t["name"], "description": t["description"],
                                                        "parameters": t["input_schema"]}} for t in tools]
        self.messages = [{"role": "system", "content": system}]

    def step(self, user_text=None, results=None):
        if user_text is not None:
            self.messages.append({"role": "user", "content": user_text})
        else:
            self.messages += [{"role": "tool", "content": out, "tool_name": name} for _, name, out, _ in results]
        r = httpx.post(f"{self.url}/api/chat", timeout=600, json={
            "model": self.model, "messages": self.messages, "tools": self.tools, "stream": False})
        r.raise_for_status()
        msg = r.json()["message"]
        self.messages.append(msg)
        calls = []
        for n, c in enumerate(msg.get("tool_calls") or []):
            args = c["function"].get("arguments") or {}
            calls.append({"id": f"call{len(self.messages)}_{n}", "name": c["function"]["name"],
                          "args": json.loads(args) if isinstance(args, str) else args})
        return msg.get("content", ""), calls


def make(llm: dict, system: str, tools: list):
    if llm["provider"] == "ollama":
        return Ollama(llm["model"], system, tools, llm["ollama_url"])
    return Claude(llm["model"], system, tools)
