"""AI content moderation agent (LangChain).

Usage:
    python make_images.py          # once, creates images/
    python moderator.py            # writes moderation_report.html

Model is set with MODEL env var, e.g. "openai:gpt-4o-mini" (default),
"anthropic:claude-sonnet-5-5", "ollama:llava". It must support vision for image posts.
"""
import base64
import html
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Literal

from langchain.agents import create_agent
from langchain.chat_models import init_chat_model
from langchain_core.messages import HumanMessage
from langchain_core.tools import tool
from pydantic import BaseModel, Field

BASE = Path(__file__).parent
MODEL_NAME = os.getenv("MODEL", "openai:gpt-4o-mini")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
if not OPENAI_API_KEY:
    raise SystemExit("OPENAI_API_KEY is not set. Run: export OPENAI_API_KEY=sk-...")
llm = init_chat_model(MODEL_NAME, temperature=0, api_key=OPENAI_API_KEY)

CATEGORIES = ["hate_speech", "harassment", "violent_threat", "misinformation", "spam",
              "explicit", "graphic_violence", "manipulated_media"]


# ---------- Structured output schemas ----------
class Analysis(BaseModel):
    categories: list[str] = Field(description=f"Detected violations, subset of {CATEGORIES}; empty if none")
    severity: Literal["none", "low", "medium", "high", "critical"]
    extracted_text: str = Field(description="Text found in the image (OCR); empty for text analysis")
    explanation: str


class Decision(BaseModel):
    post_id: str
    content_type: Literal["text-only", "image-only", "text+image"]
    categories: list[str]
    severity: Literal["none", "low", "medium", "high", "critical"]
    verdict: Literal["Approve", "Flag for Review", "Remove"]
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning: str


class CategoryFinding(BaseModel):
    category: str
    analysis: str


class ReportBody(BaseModel):
    executive_summary: str
    category_findings: list[CategoryFinding] = Field(description="one entry per violation category found")
    recommendations: list[str]


# ---------- Tools ----------
@tool
def analyze_text(text: str) -> str:
    """Analyze post text for policy violations (hate speech, harassment, threats,
    misinformation, spam, explicit material). Returns categories and severity as JSON."""
    res = llm.with_structured_output(Analysis).invoke(
        "You are a trust & safety analyst. Classify this social media post text for policy "
        f"violations. Allowed categories: {CATEGORIES}. Consider context (e.g. gaming banter is "
        f"not a real threat).\n\nPOST TEXT:\n{text}")
    return res.model_dump_json()


@tool
def analyze_image(image_path: str) -> str:
    """Analyze an image attached to a post: reads any text inside it (OCR, to catch
    text-in-image evasion) and detects visual violations such as graphic content or
    manipulated/fake media. Returns categories and severity as JSON."""
    data = base64.b64encode((BASE / image_path).read_bytes()).decode()
    msg = HumanMessage(content=[
        {"type": "text", "text":
            "You are a trust & safety analyst. 1) Transcribe all text visible in the image. "
            "2) Check the image AND its embedded text for violations: graphic violence/gore, "
            "explicit content, manipulated media (fake news screenshots, doctored images), "
            f"hate speech, spam. Allowed categories: {CATEGORIES}."},
        {"type": "image_url", "image_url": {"url": f"data:image/png;base64,{data}"}},
    ])
    return llm.with_structured_output(Analysis).invoke([msg]).model_dump_json()


@tool
def generate_report(results_json: str) -> str:
    """Take the combined moderation decisions (JSON list) and produce the HTML
    investigation report. Returns the path of the written file."""
    decisions = [Decision(**d) for d in json.loads(results_json)]
    body = llm.with_structured_output(ReportBody).invoke(
        "You are a head of trust & safety writing an investigation report. Based on these "
        "moderation decisions write: an executive summary, findings per violation category, "
        f"and concrete remediation / policy improvement recommendations.\n\n{results_json}")
    path = BASE / "moderation_report.html"
    path.write_text(render_html(decisions, body))
    return str(path)


# ---------- Agent ----------
SYSTEM = """You are a social media content moderation agent.
Decide your analysis strategy from the content type:
- text only  -> call analyze_text
- image only -> call analyze_image
- text+image -> call BOTH (the caption may look innocent while the image violates policy)
Then combine the results into a final decision:
- Remove: clear, high/critical-severity violation
- Flag for Review: ambiguous, borderline, or medium severity
- Approve: no violation
Give a confidence 0.0-1.0 and clear reasoning citing the tool findings."""

agent = create_agent(llm, tools=[analyze_text, analyze_image], system_prompt=SYSTEM,
                     response_format=Decision)


def moderate(post: dict) -> Decision:
    prompt = (f"Moderate post {post['id']} by {post['user'] or 'unknown'}.\n"
              f"TEXT: {post['text'] or '(none)'}\n"
              f"IMAGE: {post['image'] or '(none)'}")
    return agent.invoke({"messages": [("user", prompt)]})["structured_response"]


# ---------- HTML rendering ----------
def render_html(decisions: list[Decision], body: ReportBody) -> str:
    e = html.escape
    counts = {v: sum(d.verdict == v for d in decisions) for v in ["Approve", "Flag for Review", "Remove"]}
    cat_counts = {}
    for d in decisions:
        for c in d.categories:
            cat_counts[c] = cat_counts.get(c, 0) + 1
    color = {"Approve": "#1a7f37", "Flag for Review": "#b08800", "Remove": "#cf222e"}

    stats = "".join(f"<div class='stat'><b>{n}</b><span>{v}</span></div>" for v, n in counts.items())
    findings = "".join(
        f"<h3>{e(c)} <small>({cat_counts.get(c, 0)} posts: "
        f"{', '.join(d.post_id for d in decisions if c in d.categories)})</small></h3><p>{e(t)}</p>"
        for c, t in ((f.category, f.analysis) for f in body.category_findings))
    rows = "".join(
        f"<tr><td>{d.post_id}</td><td>{d.content_type}</td><td>{e(', '.join(d.categories) or '—')}</td>"
        f"<td>{d.severity}</td><td style='color:{color[d.verdict]};font-weight:bold'>{d.verdict}</td>"
        f"<td>{d.confidence:.2f}</td><td>{e(d.reasoning)}</td></tr>" for d in decisions)
    recs = "".join(f"<li>{e(r)}</li>" for r in body.recommendations)

    return f"""<!doctype html><html><head><meta charset="utf-8"><title>Moderation Report</title>
<style>body{{font-family:system-ui,sans-serif;max-width:1100px;margin:auto;padding:24px;color:#222}}
h1{{border-bottom:3px solid #333}} .stats{{display:flex;gap:16px}}
.stat{{flex:1;background:#f3f4f6;padding:16px;border-radius:8px;text-align:center}}
.stat b{{display:block;font-size:2em}} table{{border-collapse:collapse;width:100%;font-size:14px}}
td,th{{border:1px solid #ddd;padding:6px;vertical-align:top}} th{{background:#333;color:#fff}}
small{{color:#666;font-weight:normal}}</style></head><body>
<h1>Content Moderation Investigation Report</h1>
<h2>Executive Summary</h2><div class="stats"><div class='stat'><b>{len(decisions)}</b><span>Posts processed</span></div>{stats}</div>
<p>{e(body.executive_summary)}</p>
<h2>Findings by Violation Category</h2>{findings}
<h2>Individual Post Assessments</h2>
<table><tr><th>Post</th><th>Type</th><th>Categories</th><th>Severity</th><th>Verdict</th><th>Confidence</th><th>Reasoning</th></tr>{rows}</table>
<h2>Recommendations</h2><ul>{recs}</ul>
<h2>Moderation Metadata</h2><ul><li>Date: {datetime.now():%Y-%m-%d %H:%M}</li>
<li>Model: {e(MODEL_NAME)}</li><li>Posts processed: {len(decisions)}</li>
<li>Framework: LangChain agent (tools: analyze_text, analyze_image, generate_report)</li></ul>
</body></html>"""


if __name__ == "__main__":
    posts = json.loads((BASE / "dataset.json").read_text())
    decisions = []
    for p in posts:
        d = moderate(p)
        print(f"{d.post_id}: {d.verdict:16} conf={d.confidence:.2f} {d.categories}")
        decisions.append(d)
    out = generate_report.invoke({"results_json": json.dumps([d.model_dump() for d in decisions])})
    print("Report written to", out)
