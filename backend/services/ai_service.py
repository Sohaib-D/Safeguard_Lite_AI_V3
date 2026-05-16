import logging
import httpx
from backend.core.config import settings

logger = logging.getLogger("safeguard.services.ai")

SAFE_MODEL = "llama-3.3-70b-versatile"

class AIService:
    def __init__(self):
        self.api_key = settings.GROQ_API_KEY
        self.base_url = "https://api.groq.com/openai/v1/chat/completions"
        # Always use a known-good model name regardless of what settings says
        self.model = SAFE_MODEL

    async def analyze_threat(self, alert_description: str, metadata: dict) -> str:
        """Consults Groq AI for SOC analyst guidance."""
        if not self.api_key:
            return "AI Analysis unavailable: API Key missing."

        # Truncate context to stay well within token limits
        desc_truncated = str(alert_description)[:1500]
        meta_truncated = str(metadata)[:1500]

        prompt = (
            "Role: Senior SOC Analyst\n"
            "Task: Analyze the following security alert and provide actionable mitigation steps.\n\n"
            f"Alert: {desc_truncated}\n"
            f"Context: {meta_truncated}\n\n"
            "Provide:\n"
            "1. Severity Verification\n"
            "2. Immediate Action Steps\n"
            "3. Long-term Prevention"
        )

        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                response = await client.post(
                    self.base_url,
                    headers={"Authorization": f"Bearer {self.api_key}"},
                    json={
                        "model": self.model,
                        "messages": [
                            {"role": "system", "content": "You are a senior SOC analyst. Be concise and actionable."},
                            {"role": "user", "content": prompt},
                        ],
                        "temperature": 0.3,
                        "max_tokens": 1024,
                    },
                )
                response.raise_for_status()
                data = response.json()
                return data["choices"][0]["message"]["content"]
        except httpx.HTTPStatusError as e:
            logger.error(f"AI Service HTTP error {e.response.status_code}: {e.response.text[:300]}")
            return f"AI Analysis unavailable (HTTP {e.response.status_code}). Check GROQ_API_KEY and model name."
        except Exception as e:
            logger.error(f"AI Service error: {str(e)}")
            return "AI Analysis failed to generate a response."
