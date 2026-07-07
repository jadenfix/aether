#!/usr/bin/env python3
"""Validate the committed public interface manifest against source references."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST_PATH = REPO_ROOT / "docs" / "public-interface-manifest.json"
SERVER_PATH = REPO_ROOT / "crates" / "rpc" / "json-rpc" / "src" / "server.rs"


def read(path: str | Path) -> str:
    return Path(path).read_text(encoding="utf-8")


def load_manifest() -> dict[str, Any]:
    with MANIFEST_PATH.open(encoding="utf-8") as handle:
        return json.load(handle)


def json_rpc_methods(manifest: dict[str, Any]) -> list[str]:
    for transport in manifest["transports"]:
        if transport["name"] == "json-rpc":
            return [method["name"] for method in transport["methods"]]
    raise AssertionError("manifest missing json-rpc transport")


def server_json_rpc_methods() -> list[str]:
    server = read(SERVER_PATH)
    methods = re.findall(r'"(aeth_[A-Za-z0-9]+)"\s*=>', server)
    return sorted(set(methods))


def require_contains(errors: list[str], path: str, needle: str, label: str) -> None:
    if needle not in read(REPO_ROOT / path):
        errors.append(f"{label}: {path} does not contain {needle!r}")


def main() -> int:
    errors: list[str] = []
    manifest = load_manifest()

    if manifest.get("schema_version") != 1:
        errors.append("schema_version must be 1")

    manifest_methods = sorted(json_rpc_methods(manifest))
    source_methods = server_json_rpc_methods()
    if manifest_methods != source_methods:
        errors.append(
            "json-rpc method drift:\n"
            f"  manifest={manifest_methods}\n"
            f"  server={source_methods}"
        )

    required_refs = [
        ("crates/rpc/json-rpc/src/server.rs", 'warp::path("health")', "health route"),
        ("crates/rpc/json-rpc/src/server.rs", 'warp::path("ws")', "websocket route"),
        ("sdks/typescript/src/client.ts", "/health", "typescript health"),
        ("sdks/python/src/aether_sdk/client.py", "/health", "python health"),
        ("sdks/typescript/src/subscriptions.ts", "/ws", "typescript websocket"),
        ("sdks/typescript/src/client.ts", "/v1/jobs", "typescript jobs"),
        ("sdks/python/src/aether_sdk/client.py", "/v1/jobs", "python jobs"),
        ("crates/sdk/rust/src/client.rs", "/v1/jobs", "rust jobs"),
        ("crates/tools/cli/src/jobs.rs", "/v1/jobs", "cli jobs"),
        ("crates/tools/cli/src/main.rs", "aetherctl", "cli binary"),
        ("crates/tools/cli/src/main.rs", "Status", "cli status command"),
        ("crates/tools/cli/src/main.rs", "Transfer", "cli transfer command"),
        ("crates/tools/cli/src/main.rs", "Stake", "cli stake command"),
        ("crates/tools/cli/src/main.rs", "Job", "cli job command"),
    ]
    for path, needle, label in required_refs:
        require_contains(errors, path, needle, label)

    sdk_languages = {sdk["language"] for sdk in manifest.get("sdks", [])}
    if sdk_languages != {"typescript", "python", "rust"}:
        errors.append(f"unexpected SDK language set: {sorted(sdk_languages)}")

    cli_commands = set(manifest.get("cli", {}).get("commands", []))
    required_cli = {
        "status",
        "keys generate",
        "keys show",
        "transfer",
        "stake delegate",
        "stake withdraw",
        "job post",
        "job tutorial",
    }
    if cli_commands != required_cli:
        errors.append(f"cli command drift: {sorted(cli_commands)}")

    if errors:
        print("public interface manifest check failed:")
        for error in errors:
            print(f"  - {error}")
        return 1

    print(
        "public interface manifest check passed: "
        f"{len(manifest_methods)} JSON-RPC method(s), {len(sdk_languages)} SDK(s)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
