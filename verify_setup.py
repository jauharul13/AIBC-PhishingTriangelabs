"""
verify_setup.py – AIBC 2026 ReAct Phishing Triage Lab
Validates Python version, dependencies, .env configuration, and Groq API connectivity.
"""

import sys
import os

def main():
    ok = True
    print("Checking setup...")

    # ── 1. Python version ≥ 3.11 ──────────────────────────────────────
    if sys.version_info >= (3, 11):
        print("OK: Python version is compatible")
    else:
        print(
            f"FAIL: Python {sys.version_info.major}.{sys.version_info.minor} detected. "
            "Python 3.11 or later is required."
        )
        ok = False

    # ── 2. Package imports ─────────────────────────────────────────────
    try:
        import streamlit  # noqa: F401
        import langchain  # noqa: F401
        import langchain_groq  # noqa: F401
        import requests  # noqa: F401
        import pandas  # noqa: F401
        print("OK: packages imported")
    except ImportError as exc:
        print(f"FAIL: could not import a required package – {exc}")
        ok = False

    # ── 3. .env file exists & loaded ───────────────────────────────────
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")

    if not os.path.isfile(env_path):
        print("FAIL: .env file not found in the project folder")
        print("  → Copy .env.example to .env and add your real API key.")
        ok = False
    else:
        from dotenv import load_dotenv
        load_dotenv(env_path, override=True)
        print("OK: .env loaded")

    # ── 4. GROQ_API_KEY checks ─────────────────────────────────────────
    api_key = os.getenv("GROQ_API_KEY", "")

    if not api_key:
        print("FAIL: GROQ_API_KEY is missing or empty")
        ok = False
    elif api_key == "gsk_your_key_here":
        print("FAIL: GROQ_API_KEY is still the placeholder value")
        print("  → Open .env and replace gsk_your_key_here with your real key.")
        ok = False
    elif not api_key.startswith("gsk_"):
        print("FAIL: GROQ_API_KEY does not start with gsk_")
        ok = False
    else:
        print("OK: Groq API key format looks valid")

    # ── 5. Model env vars ─────────────────────────────────────────────
    groq_model = os.getenv("GROQ_MODEL", "")
    fallback_model = os.getenv("FALLBACK_GROQ_MODEL", "")

    if not groq_model:
        print("FAIL: GROQ_MODEL is empty")
        ok = False
    if not fallback_model:
        print("FAIL: FALLBACK_GROQ_MODEL is empty")
        ok = False

    # ── 6. Test Groq connectivity ──────────────────────────────────────
    if ok:
        model_used = _test_groq(api_key, groq_model, fallback_model)
        if model_used:
            print(f"OK: Groq model active")
        else:
            print("FAIL: could not reach the Groq API with either model")
            ok = False

    # ── Result ─────────────────────────────────────────────────────────
    if ok:
        print("All good. You are ready for the lab.")
        sys.exit(0)
    else:
        print("\nSetup is incomplete. Fix the issues above and run again.")
        sys.exit(1)


def _test_groq(api_key: str, primary: str, fallback: str) -> str | None:
    """Send a minimal request to Groq. Returns the model name on success, None on failure."""
    import requests as _req

    url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    for model in (primary, fallback):
        payload = {
            "model": model,
            "messages": [{"role": "user", "content": "hi"}],
            "max_tokens": 2,
        }
        try:
            resp = _req.post(url, json=payload, headers=headers, timeout=15)
            if resp.status_code == 200:
                return model
            else:
                print(f"  ⚠ {model}: HTTP {resp.status_code}")
        except _req.RequestException as exc:
            print(f"  ⚠ {model}: {exc}")

    return None


if __name__ == "__main__":
    main()
