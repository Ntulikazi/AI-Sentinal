import argparse
import json
import os
import sys
from pathlib import Path

from dotenv import load_dotenv
from pydantic import ValidationError

from ai_sentinel.api.app import create_app
from ai_sentinel.config import Settings
from ai_sentinel.evaluations.inception_runner import run_inception_suite
from ai_sentinel.evaluations.service import (
    EvaluationService,
    EvaluationServiceError,
)
from ai_sentinel.evaluations.suites import EVALUATION_SUITES


def _settings_for_live_test() -> Settings:
    load_dotenv(dotenv_path=Path.cwd() / ".env", override=False)
    environment = dict(os.environ)
    environment["AI_SENTINEL_GITHUB_MCP_ENABLED"] = "false"
    environment.pop("AI_SENTINEL_GITHUB_MCP_IMAGE", None)
    environment.pop("GITHUB_PERSONAL_ACCESS_TOKEN", None)
    return Settings.from_environment(environment)


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run a live Inception evaluation using only a built-in synthetic suite."
        )
    )
    parser.add_argument("--assessment-id", required=True)
    parser.add_argument(
        "--suite",
        choices=sorted(EVALUATION_SUITES),
        default="finding-explanation-quality",
    )
    return parser.parse_args()


def main() -> int:
    arguments = _arguments()
    try:
        settings = _settings_for_live_test()
    except ValidationError as exc:
        print(f"Invalid evaluation configuration: {exc}", file=sys.stderr)
        return 2
    if settings.inception_api_key is None or settings.inception_model is None:
        print(
            "Set INCEPTION_API_KEY, INCEPTION_MODEL, and a positive "
            "AI_SENTINEL_MAX_LLM_TOKENS before running live evaluations.",
            file=sys.stderr,
        )
        return 2

    app = create_app(settings)
    preflight = EvaluationService(app.state.repository)
    try:
        preflight.validate_execution(arguments.assessment_id)
    except EvaluationServiceError as exc:
        print(f"Evaluation preflight failed: {exc}", file=sys.stderr)
        return 2

    try:
        result = run_inception_suite(
            app.state.repository,
            arguments.assessment_id,
            settings,
            max_total_tokens=settings.max_llm_tokens,
            suite_id=arguments.suite,
            actor_id="local-inception-evaluation",
        )
    except (EvaluationServiceError, ValueError) as exc:
        print(f"Live evaluation failed: {exc}", file=sys.stderr)
        return 1

    run = result.run
    print(
        json.dumps(
            {
                "evaluation_run_id": run.evaluation_run_id,
                "suite_id": run.suite_id,
                "suite_version": run.suite_version,
                "status": run.status.value,
                "model_provider": run.model_provider,
                "model_version": run.model_version,
                "tokens_used": result.tokens_used,
                "max_tokens": settings.max_llm_tokens,
                "cases": [
                    {
                        "case_id": case.case_id,
                        "status": case.status.value,
                        "metrics": [
                            {
                                "name": metric.name,
                                "score": metric.score,
                                "threshold": metric.threshold,
                            }
                            for metric in case.metrics
                        ],
                    }
                    for case in run.cases
                ],
            },
            indent=2,
        )
    )
    return 0 if run.status.value == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
