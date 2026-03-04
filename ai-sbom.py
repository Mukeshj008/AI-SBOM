import ast
import argparse
import html
import json
import os
import re
import socket
import sqlite3
import subprocess
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path

AI_PACKAGES = [
    "openai",
    "anthropic",
    "google-generativeai",
    "google.generativeai",
    "cohere",
    "mistralai",
    "groq",
    "replicate",
    "langchain",
    "llama_index",
    "llama-index",
    "haystack",
    "guidance",
    "dspy",
    "instructor",
    "litellm",
    "autogen",
    "semantic-kernel",
    "huggingface_hub",
    "transformers",
    "tokenizers",
    "sentence-transformers",
    "accelerate",
    "vllm",
    "ctransformers",
    "onnxruntime",
    "torch",
    "tensorflow",
    "keras",
    "jax",
    "ollama",
    "chromadb",
    "qdrant-client",
    "pinecone",
    "weaviate-client",
    "pymilvus",
    "faiss-cpu",
    "redisvl",
    "pgvector",
    "@openai/openai",
    "@openai/apps-sdk",
    "@openai/apps-sdk-ui",
    "openai",
    "@anthropic-ai/sdk",
    "@google/generative-ai",
    "cohere-ai",
    "@mistralai/mistralai",
    "langchain",
    "@langchain/openai",
    "@langchain/anthropic",
    "@langchain/community",
    "llamaindex",
    "huggingface",
    "@huggingface/inference",
    "@xenova/transformers",
    "onnxruntime-node",
    "ollama",
    "@pinecone-database/pinecone",
    "@qdrant/js-client-rest",
    "weaviate-client",
    "@vercel/ai",
    "openai-go",
    "openai-java",
    "openai4j",
    "langchain4j",
    "spring-ai-openai",
    "azure-ai-openai",
    "azure-ai-inference",
    "openai-dotnet",
    "azure.ai.openai",
    "ruby-openai",
    "openai-ruby",
    "openai-php/client",
    "orhanerday/open-ai",
    "theokanning/openai-java",
    "com.openai",
    "dev.langchain4j",
    "go.openai",
    "ollama-python",
    "ollama-js",
    "github.com/ollama/ollama"
]

VECTOR_DBS = [
    "pinecone",
    "weaviate",
    "milvus",
    "faiss",
    "chromadb",
    "chroma",
    "qdrant",
    "pgvector",
    "redis",
    "elasticsearch",
    "opensearch"
]

AI_ENDPOINTS = [
    "api.openai.com",
    "api.anthropic.com",
    "generativelanguage.googleapis.com",
    "api.cohere.ai",
    "api.groq.com",
    "api.mistral.ai",
    "api.together.xyz",
    "api.perplexity.ai",
    "api.replicate.com",
    "api-inference.huggingface.co",
    "huggingface.co",
    "azure.com/openai"
]

AI_ENV_HINTS = [
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GOOGLE_API_KEY",
    "GEMINI_API_KEY",
    "COHERE_API_KEY",
    "MISTRAL_API_KEY",
    "GROQ_API_KEY",
    "TOGETHER_API_KEY",
    "REPLICATE_API_TOKEN",
    "HUGGINGFACEHUB_API_TOKEN",
    "AZURE_OPENAI_API_KEY",
    "AZURE_OPENAI_ENDPOINT",
    "OLLAMA_HOST",
    "OLLAMA_MODEL"
]

OLLAMA_ENDPOINTS = [
    "localhost:11434",
    "127.0.0.1:11434",
    "0.0.0.0:11434",
    "/api/generate",
    "/api/chat",
    "/api/embeddings",
    "/api/tags",
]

OLLAMA_MODEL_PATTERNS = [
    r"\bollama\s+(?:run|pull|create)\s+([A-Za-z0-9_.:\-]+)",
    r"\bollama\.chat\(\s*model\s*=\s*[\"']([^\"']+)[\"']",
    r"\bollama\.generate\(\s*model\s*=\s*[\"']([^\"']+)[\"']",
    r"\bOllamaEmbeddings\(\s*model\s*=\s*[\"']([^\"']+)[\"']",
    r"\bOllama\(\s*model\s*=\s*[\"']([^\"']+)[\"']",
    r"\bmodel\s*:\s*[\"']([^\"']+)[\"']\s*,?\s*//\s*ollama",
]

MODEL_NAME_PATTERNS = [
    r"\bgpt-[\w.\-]+\b",
    r"\bo\d(?:-[\w.\-]+)?\b",
    r"\bclaude-[\w.\-]+\b",
    r"\bgemini-[\w.\-]+\b",
    r"\bllama(?:-|\s)?[\w.\-]+\b",
    r"\bmistral[\w.\-]*\b",
    r"\bmixtral[\w.\-]*\b",
    r"\bcommand-(?:r|r-plus|light)[\w.\-]*\b",
    r"\btext-embedding-[\w.\-]+\b",
    r"\bembed-[\w.\-]+\b"
]

LOCAL_MODEL_PATTERNS = [
    r"[\w./\-]+\.gguf\b",
    r"[\w./\-]+\.onnx\b",
    r"[\w./\-]+\.pt\b",
    r"[\w./\-]+\.bin\b",
    r"from_pretrained\(\s*[\"']([^\"']+)[\"']",
    r"AutoModel(?:For\w+)?\.from_pretrained\(\s*[\"']([^\"']+)[\"']"
]

RISK_PATTERNS = {
    "pickle_load": r"\bpickle\.load\(",
    "joblib_load": r"\bjoblib\.load\(",
    "unsafe_yaml_load": r"\byaml\.load\(",
    "exec_usage": r"\bexec\(",
    "hardcoded_openai_key": r"sk-[A-Za-z0-9]{20,}",
    "hardcoded_anthropic_key": r"sk-ant-[A-Za-z0-9\-]{20,}",
    "hardcoded_google_key": r"AIza[0-9A-Za-z\-_]{20,}"
}

CATEGORY_ORDER = ["ai_sdks", "llm_models", "local_models", "vector_dbs", "ai_endpoints", "risks"]
CATEGORY_TITLES = {
    "ai_sdks": "AI SDKs",
    "llm_models": "LLM Models",
    "local_models": "Local Models",
    "vector_dbs": "Vector Databases",
    "ai_endpoints": "AI Endpoints",
    "risks": "Risk Findings",
}
CATEGORY_COLORS = {
    "ai_sdks": "#4f46e5",
    "llm_models": "#06b6d4",
    "local_models": "#10b981",
    "vector_dbs": "#f59e0b",
    "ai_endpoints": "#ef4444",
    "risks": "#d946ef",
}
CATEGORY_LIGHT_COLORS = {
    "ai_sdks": "#eef2ff",
    "llm_models": "#ecfeff",
    "local_models": "#ecfdf5",
    "vector_dbs": "#fffbeb",
    "ai_endpoints": "#fef2f2",
    "risks": "#fdf4ff",
}


class AICodeScanner:
    def __init__(
        self,
        project_path,
        enable_ollama=False,
        ollama_model="llama3.2:latest",
        enable_openai=False,
        openai_model="gpt-4o-mini",
        enable_gemini=False,
        gemini_model="gemini-1.5-flash",
    ):
        self.project_path = Path(project_path).resolve()
        self.scanner_file = Path(__file__).resolve()
        self.enable_ollama = enable_ollama
        self.ollama_model = ollama_model
        self.enable_openai = enable_openai
        self.openai_model = openai_model
        self.enable_gemini = enable_gemini
        self.gemini_model = gemini_model
        self.max_text_file_size = 2 * 1024 * 1024
        self.text_extensions = {
            ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
            ".java", ".kt", ".kts", ".go", ".rs", ".cs", ".rb", ".php",
            ".swift", ".scala", ".dart", ".c", ".cc", ".cpp", ".h", ".hpp",
            ".ipynb", ".json", ".yaml", ".yml", ".toml", ".ini",
            ".cfg", ".conf", ".env", ".txt", ".md", ".sh", ".zsh",
            ".Dockerfile", ".tf", ".gradle", ".properties", ".xml",
            ".lock"
        }
        self.results = {
            "ai_sdks": [],
            "llm_models": [],
            "local_models": [],
            "vector_dbs": [],
            "ai_endpoints": [],
            "risks": []
        }

    def _append(self, category, payload):
        self.results[category].append(payload)

    def _normalized_package_variants(self, name):
        raw = str(name).strip().lower()
        variants = {raw}
        variants.add(raw.replace("-", "_"))
        variants.add(raw.replace("_", "-"))
        if "/" in raw:
            tail = raw.split("/")[-1]
            variants.add(tail)
            variants.add(tail.replace("-", "_"))
            variants.add(tail.replace("_", "-"))
        if "." in raw:
            head = raw.split(".")[0]
            variants.add(head)
        return variants

    def _matches_known_package(self, package_name, known_packages):
        normalized = self._normalized_package_variants(package_name)
        for known in known_packages:
            known_variants = self._normalized_package_variants(known)
            if normalized & known_variants:
                return True
        return False

    def _extract_version_from_requirement(self, line):
        match = re.match(r"^\s*([A-Za-z0-9_.\-]+)\s*([<>=!~]{1,2}\s*[^;\s]+)?", line)
        if not match:
            return None, None
        pkg_name = match.group(1)
        version = match.group(2).strip() if match.group(2) else "unknown"
        return pkg_name, version

    def _normalize_version(self, version):
        if version is None:
            return "unknown"
        text = str(version).strip()
        if not text or text.lower() == "unknown":
            return "unknown"
        # Remove common specifier prefixes and whitespace.
        cleaned = text.replace(" ", "").strip("\"'")
        # Keep first range item for specs like >=1.0,<2.0.
        cleaned = cleaned.split(",")[0]
        cleaned = cleaned.lstrip("^~<>=!v")
        # Extract first semantic-like numeric token.
        match = re.search(r"\d+(?:\.\d+){0,4}(?:[-+._a-zA-Z0-9]*)?", cleaned)
        if match:
            return match.group(0)
        return cleaned if cleaned else "unknown"

    def _should_skip_file(self, file_path):
        resolved = file_path.resolve()
        if resolved == self.scanner_file:
            return True
        if file_path.name == "ai_sbom.json":
            return True
        blocked_dirs = {
            ".git", ".hg", ".svn", ".idea", ".vscode",
            "node_modules", "dist", "build", "target", "out",
            "__pycache__", ".mypy_cache", ".pytest_cache", ".next",
            ".nuxt", ".cache", ".venv", "venv", ".tox", "coverage"
        }
        return any(part in blocked_dirs for part in file_path.parts)

    def _is_text_candidate(self, file_path):
        if self._should_skip_file(file_path):
            return False
        if not file_path.is_file():
            return False
        if file_path.stat().st_size > self.max_text_file_size:
            return False
        if file_path.suffix in self.text_extensions:
            return True
        # Handle extensionless important files.
        basename = file_path.name.lower()
        if basename in {"dockerfile", "modelfile", "pipfile", "poetry.lock", "yarn.lock", "pnpm-lock.yaml"}:
            return True
        return False

    def _safe_read(self, file_path):
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as handle:
                return handle.read()
        except Exception:
            return ""

    def _scan_dependency_name(self, dep_name, version, source_file):
        if not self.enable_ollama and "ollama" in str(dep_name).lower():
            return
        normalized_version = self._normalize_version(version)
        if self._matches_known_package(dep_name, AI_PACKAGES):
            self._append("ai_sdks", {
                "name": dep_name,
                "version": normalized_version,
                "source_file": str(source_file)
            })
        if self._matches_known_package(dep_name, VECTOR_DBS):
            self._append("vector_dbs", {
                "name": dep_name,
                "version": normalized_version,
                "source_file": str(source_file)
            })

    # ----------------------------
    # Python source analysis via AST
    # ----------------------------
    def scan_python_files(self):
        for py_file in self.project_path.rglob("*.py"):
            if self._should_skip_file(py_file):
                continue
            try:
                source = self._safe_read(py_file)
                if not source:
                    continue
                tree = ast.parse(source)
            except Exception:
                continue

            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if self._matches_known_package(alias.name, AI_PACKAGES):
                            self._append("ai_sdks", {"name": alias.name, "source_file": str(py_file)})
                        if self._matches_known_package(alias.name, VECTOR_DBS):
                            self._append("vector_dbs", {"name": alias.name, "source_file": str(py_file)})

                if isinstance(node, ast.ImportFrom) and node.module:
                    if self._matches_known_package(node.module, AI_PACKAGES):
                        self._append("ai_sdks", {"name": node.module, "source_file": str(py_file)})
                    if self._matches_known_package(node.module, VECTOR_DBS):
                        self._append("vector_dbs", {"name": node.module, "source_file": str(py_file)})

                if isinstance(node, ast.Call):
                    for keyword in node.keywords:
                        if keyword.arg in {"model", "model_name", "deployment"} and isinstance(keyword.value, ast.Constant):
                            if isinstance(keyword.value.value, str):
                                self._append("llm_models", {
                                    "model": keyword.value.value,
                                    "source_file": str(py_file)
                                })
                    if hasattr(node.func, "attr") and node.func.attr == "from_pretrained":
                        if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                            self._append("local_models", {
                                "name": node.args[0].value,
                                "source_file": str(py_file)
                            })

    # ----------------------------
    # Dependency files (Python)
    # ----------------------------
    def scan_requirements(self):
        req_patterns = ("requirements.txt", "requirements-*.txt", "*requirements*.txt")
        req_files = []
        for pattern in req_patterns:
            req_files.extend(self.project_path.rglob(pattern))

        seen_paths = set()
        for req_file in req_files:
            if str(req_file) in seen_paths:
                continue
            seen_paths.add(str(req_file))
            if self._should_skip_file(req_file):
                continue
            content = self._safe_read(req_file)
            for raw_line in content.splitlines():
                line = raw_line.strip()
                if not line or line.startswith("#") or line.startswith("-r "):
                    continue
                dep_name, version = self._extract_version_from_requirement(line)
                if dep_name:
                    self._scan_dependency_name(dep_name, version, req_file)

    def scan_python_project_files(self):
        # pyproject.toml
        for pyproject in self.project_path.rglob("pyproject.toml"):
            if self._should_skip_file(pyproject):
                continue
            content = self._safe_read(pyproject)
            for dep_name in re.findall(r"[\"']([A-Za-z0-9_.\-]+)[\"']\s*[,}]", content):
                self._scan_dependency_name(dep_name, "unknown", pyproject)

        # poetry.lock
        for poetry_lock in self.project_path.rglob("poetry.lock"):
            if self._should_skip_file(poetry_lock):
                continue
            content = self._safe_read(poetry_lock)
            for match in re.finditer(r'name\s*=\s*"([^"]+)"\s*\nversion\s*=\s*"([^"]+)"', content):
                self._scan_dependency_name(match.group(1), match.group(2), poetry_lock)

        # Pipfile / Pipfile.lock
        for pipfile in self.project_path.rglob("Pipfile"):
            if self._should_skip_file(pipfile):
                continue
            content = self._safe_read(pipfile)
            for dep_name in re.findall(r"^\s*([A-Za-z0-9_.\-]+)\s*=", content, flags=re.MULTILINE):
                self._scan_dependency_name(dep_name, "unknown", pipfile)

        for pipfile_lock in self.project_path.rglob("Pipfile.lock"):
            if self._should_skip_file(pipfile_lock):
                continue
            try:
                data = json.loads(self._safe_read(pipfile_lock))
            except Exception:
                data = {}
            for section in ("default", "develop"):
                for dep_name, spec in data.get(section, {}).items():
                    version = spec.get("version", "unknown") if isinstance(spec, dict) else "unknown"
                    self._scan_dependency_name(dep_name, version, pipfile_lock)

    # ----------------------------
    # Dependency files (polyglot)
    # ----------------------------
    def scan_polyglot_dependency_files(self):
        # Go modules.
        for go_mod in self.project_path.rglob("go.mod"):
            if self._should_skip_file(go_mod):
                continue
            content = self._safe_read(go_mod)
            for match in re.finditer(r"^\s*require\s+([^\s]+)\s+([^\s]+)", content, flags=re.MULTILINE):
                self._scan_dependency_name(match.group(1), match.group(2), go_mod)
            for match in re.finditer(r"^\s*([^\s]+)\s+([^\s]+)\s*(//.*)?$", content, flags=re.MULTILINE):
                module_name = match.group(1)
                version = match.group(2)
                if module_name != "module" and version.startswith("v"):
                    self._scan_dependency_name(module_name, version, go_mod)

        # Rust Cargo.toml.
        for cargo_toml in self.project_path.rglob("Cargo.toml"):
            if self._should_skip_file(cargo_toml):
                continue
            content = self._safe_read(cargo_toml)
            for match in re.finditer(r"^\s*([A-Za-z0-9_\-]+)\s*=\s*[\"']([^\"']+)[\"']", content, flags=re.MULTILINE):
                self._scan_dependency_name(match.group(1), match.group(2), cargo_toml)

        # Ruby Gemfile and gemspec.
        ruby_files = list(self.project_path.rglob("Gemfile")) + list(self.project_path.rglob("*.gemspec"))
        for ruby_file in ruby_files:
            if self._should_skip_file(ruby_file):
                continue
            content = self._safe_read(ruby_file)
            for match in re.finditer(r"^\s*gem\s+[\"']([^\"']+)[\"']\s*(?:,\s*[\"']([^\"']+)[\"'])?", content, flags=re.MULTILINE):
                self._scan_dependency_name(match.group(1), match.group(2) or "unknown", ruby_file)

        # PHP composer.json.
        for composer in self.project_path.rglob("composer.json"):
            if self._should_skip_file(composer):
                continue
            try:
                data = json.loads(self._safe_read(composer))
            except Exception:
                continue
            for section in ("require", "require-dev"):
                for dep_name, version in data.get(section, {}).items():
                    self._scan_dependency_name(dep_name, version, composer)

        # Java Maven pom.xml.
        for pom in self.project_path.rglob("pom.xml"):
            if self._should_skip_file(pom):
                continue
            content = self._safe_read(pom)
            dep_pattern = (
                r"<dependency>.*?<groupId>([^<]+)</groupId>.*?"
                r"<artifactId>([^<]+)</artifactId>.*?"
                r"(?:<version>([^<]+)</version>)?.*?</dependency>"
            )
            for match in re.finditer(dep_pattern, content, flags=re.DOTALL):
                group_id = match.group(1).strip()
                artifact_id = match.group(2).strip()
                version = (match.group(3) or "unknown").strip()
                self._scan_dependency_name(group_id, version, pom)
                self._scan_dependency_name(artifact_id, version, pom)
                self._scan_dependency_name(f"{group_id}:{artifact_id}", version, pom)

        # Java/Kotlin Gradle build files.
        gradle_files = list(self.project_path.rglob("build.gradle")) + list(self.project_path.rglob("build.gradle.kts"))
        for gradle_file in gradle_files:
            if self._should_skip_file(gradle_file):
                continue
            content = self._safe_read(gradle_file)
            for match in re.finditer(r"[\"']([A-Za-z0-9_.\-]+):([A-Za-z0-9_.\-]+):([^\"']+)[\"']", content):
                group_id = match.group(1)
                artifact_id = match.group(2)
                version = match.group(3)
                self._scan_dependency_name(group_id, version, gradle_file)
                self._scan_dependency_name(artifact_id, version, gradle_file)
                self._scan_dependency_name(f"{group_id}:{artifact_id}", version, gradle_file)

        # .NET csproj and packages.config.
        for csproj in self.project_path.rglob("*.csproj"):
            if self._should_skip_file(csproj):
                continue
            content = self._safe_read(csproj)
            for match in re.finditer(r"<PackageReference\s+Include=\"([^\"]+)\"(?:\s+Version=\"([^\"]+)\")?", content):
                self._scan_dependency_name(match.group(1), match.group(2) or "unknown", csproj)

        for packages_config in self.project_path.rglob("packages.config"):
            if self._should_skip_file(packages_config):
                continue
            content = self._safe_read(packages_config)
            for match in re.finditer(r"<package\s+id=\"([^\"]+)\"\s+version=\"([^\"]+)\"", content):
                self._scan_dependency_name(match.group(1), match.group(2), packages_config)

        # Dart pubspec.yaml.
        for pubspec in self.project_path.rglob("pubspec.yaml"):
            if self._should_skip_file(pubspec):
                continue
            content = self._safe_read(pubspec)
            for match in re.finditer(r"^\s*([A-Za-z0-9_\-]+)\s*:\s*([^\n#]+)", content, flags=re.MULTILINE):
                name = match.group(1).strip()
                version = match.group(2).strip()
                if name not in {"name", "version", "environment", "dependencies", "dev_dependencies"}:
                    self._scan_dependency_name(name, version, pubspec)

    # ----------------------------
    # Dependency files (JavaScript/TypeScript)
    # ----------------------------
    def scan_package_json(self):
        for pkg_file in self.project_path.rglob("package.json"):
            if self._should_skip_file(pkg_file):
                continue
            try:
                data = json.loads(self._safe_read(pkg_file))
            except Exception:
                continue

            sections = (
                data.get("dependencies", {}),
                data.get("devDependencies", {}),
                data.get("peerDependencies", {}),
                data.get("optionalDependencies", {})
            )
            for deps in sections:
                for dep_name, version in deps.items():
                    self._scan_dependency_name(dep_name, version, pkg_file)

    def scan_js_lockfiles(self):
        # package-lock.json (npm)
        for lock_file in self.project_path.rglob("package-lock.json"):
            if self._should_skip_file(lock_file):
                continue
            try:
                data = json.loads(self._safe_read(lock_file))
            except Exception:
                continue

            deps = data.get("dependencies", {})
            for dep_name, dep_meta in deps.items():
                version = dep_meta.get("version", "unknown") if isinstance(dep_meta, dict) else "unknown"
                self._scan_dependency_name(dep_name, version, lock_file)

            packages = data.get("packages", {})
            for package_path, dep_meta in packages.items():
                if package_path.startswith("node_modules/"):
                    dep_name = package_path.split("node_modules/")[-1]
                    version = dep_meta.get("version", "unknown") if isinstance(dep_meta, dict) else "unknown"
                    self._scan_dependency_name(dep_name, version, lock_file)

        # yarn.lock / pnpm-lock.yaml / bun.lockb heuristics
        lock_patterns = ("yarn.lock", "pnpm-lock.yaml", "bun.lockb")
        for pattern in lock_patterns:
            for lock_file in self.project_path.rglob(pattern):
                if self._should_skip_file(lock_file):
                    continue
                content = self._safe_read(lock_file)
                for dep_name in AI_PACKAGES + VECTOR_DBS:
                    dep_lower = dep_name.lower()
                    if dep_lower in content.lower():
                        self._scan_dependency_name(dep_name, "unknown", lock_file)

    # ----------------------------
    # Source-level scanning for JS/TS and generic code
    # ----------------------------
    def scan_source_code_patterns(self):
        source_patterns = (
            "*.js", "*.jsx", "*.ts", "*.tsx", "*.mjs", "*.cjs",
            "*.py", "*.java", "*.kt", "*.kts", "*.go", "*.rs",
            "*.cs", "*.rb", "*.php", "*.swift", "*.scala", "*.dart",
            "*.c", "*.cc", "*.cpp", "*.h", "*.hpp", "*.ipynb"
        )
        files = []
        for pattern in source_patterns:
            files.extend(self.project_path.rglob(pattern))

        for file_path in files:
            if self._should_skip_file(file_path):
                continue
            content = self._safe_read(file_path)
            if not content:
                continue
            self._scan_text_content(file_path, content)

    # ----------------------------
    # Generic text scanning (env/config/infra/docs)
    # ----------------------------
    def scan_text_files(self):
        for file_path in self.project_path.rglob("*"):
            if not self._is_text_candidate(file_path):
                continue
            content = self._safe_read(file_path)
            if content:
                self._scan_text_content(file_path, content)

    def scan_ollama_runtime(self):
        # Optional runtime discovery from local Ollama installation.
        if not self.enable_ollama:
            return
        try:
            result = subprocess.run(
                ["ollama", "list"],
                check=False,
                capture_output=True,
                text=True,
                timeout=5
            )
        except Exception:
            return
        if result.returncode != 0:
            return

        lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        if not lines:
            return

        # Expected output has header: NAME ID SIZE MODIFIED
        for line in lines[1:]:
            parts = line.split()
            if not parts:
                continue
            model_name = parts[0]
            self._append("local_models", {
                "name": model_name,
                "source_file": "ollama://local-runtime",
                "detection_method": "ollama_list"
            })
            self._append("llm_models", {
                "model": model_name,
                "source_file": "ollama://local-runtime",
                "detection_method": "ollama_list"
            })

    def _extract_json_array(self, text):
        match = re.search(r"\[\s*\{.*?\}\s*\]", text, flags=re.DOTALL)
        if not match:
            return None
        try:
            parsed = json.loads(match.group(0))
            if isinstance(parsed, list):
                return parsed
        except Exception:
            return None
        return None

    def _collect_candidate_snippets(self, max_snippets=80):
        candidate_pattern = re.compile(
            r"(openai|anthropic|cohere|gemini|llama|ollama|langchain|vector|embedding|"
            r"pinecone|qdrant|weaviate|milvus|faiss|from_pretrained|chat\.completions|"
            r"api\.openai\.com|/api/chat|/api/generate|model\s*=|model:)",
            flags=re.IGNORECASE
        )
        snippets = []
        for file_path in self.project_path.rglob("*"):
            if len(snippets) >= max_snippets:
                break
            if not self._is_text_candidate(file_path):
                continue
            content = self._safe_read(file_path)
            if not content:
                continue
            for idx, line in enumerate(content.splitlines(), start=1):
                if candidate_pattern.search(line):
                    rel_path = str(file_path.resolve().relative_to(self.project_path))
                    snippets.append(f"{rel_path}:{idx}: {line.strip()[:240]}")
                    if len(snippets) >= max_snippets:
                        break
        return snippets

    def _semantic_prompt(self, snippets):
        return (
            "You are an AI SBOM extraction assistant.\n"
            "Given code snippets, return ONLY JSON array. No markdown.\n"
            "Each item schema:\n"
            "{"
            "\"category\": \"ai_sdks|llm_models|local_models|vector_dbs|ai_endpoints|risks\", "
            "\"value\": \"component or model or endpoint or risk name\", "
            "\"source_file\": \"relative/path/from/project\""
            "}\n"
            "Rules:\n"
            "- Be conservative and only include high-confidence AI findings.\n"
            "- Ignore generic words like 'ai' unless clearly an SDK/component usage.\n"
            "- Do not invent files.\n"
            f"Snippets:\n{chr(10).join(snippets)}\n"
        )

    def _apply_semantic_findings(self, findings, detection_method):
        if not findings:
            return
        key_map = {
            "ai_sdks": "name",
            "llm_models": "model",
            "local_models": "name",
            "vector_dbs": "name",
            "ai_endpoints": "endpoint",
            "risks": "risk"
        }
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            category = finding.get("category")
            value = finding.get("value")
            source_file = finding.get("source_file")
            if category not in key_map or not value or not source_file:
                continue

            source_path = Path(str(source_file))
            if not source_path.is_absolute():
                source_path = (self.project_path / source_path).resolve()

            payload = {
                key_map[category]: str(value),
                "source_file": str(source_path),
                "detection_method": detection_method
            }
            self._append(category, payload)

    def scan_ollama_semantic(self):
        # LLM-assisted enrichment over candidate code snippets.
        if not self.enable_ollama:
            return
        snippets = self._collect_candidate_snippets(max_snippets=80)
        if not snippets:
            return
        prompt = self._semantic_prompt(snippets)

        try:
            result = subprocess.run(
                ["ollama", "run", self.ollama_model],
                input=prompt,
                check=False,
                capture_output=True,
                text=True,
                timeout=45
            )
        except Exception:
            return

        if result.returncode != 0:
            return

        findings = self._extract_json_array(result.stdout)
        self._apply_semantic_findings(findings, "ollama_llm")

    def scan_openai_semantic(self):
        if not self.enable_openai:
            return
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            return

        snippets = self._collect_candidate_snippets(max_snippets=80)
        if not snippets:
            return
        prompt = self._semantic_prompt(snippets)

        payload = {
            "model": self.openai_model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0
        }
        req = urllib.request.Request(
            "https://api.openai.com/v1/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json"
            },
            method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=45) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError):
            return

        text = (
            data.get("choices", [{}])[0]
            .get("message", {})
            .get("content", "")
        )
        findings = self._extract_json_array(text)
        self._apply_semantic_findings(findings, "openai_llm")

    def scan_gemini_semantic(self):
        if not self.enable_gemini:
            return
        api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
        if not api_key:
            return

        snippets = self._collect_candidate_snippets(max_snippets=80)
        if not snippets:
            return
        prompt = self._semantic_prompt(snippets)

        url = (
            "https://generativelanguage.googleapis.com/v1beta/models/"
            f"{self.gemini_model}:generateContent?key={api_key}"
        )
        payload = {
            "contents": [
                {
                    "parts": [{"text": prompt}]
                }
            ],
            "generationConfig": {
                "temperature": 0
            }
        }
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=45) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError):
            return

        text = (
            data.get("candidates", [{}])[0]
            .get("content", {})
            .get("parts", [{}])[0]
            .get("text", "")
        )
        findings = self._extract_json_array(text)
        self._apply_semantic_findings(findings, "gemini_llm")

    def _scan_text_content(self, file_path, content):
        content_lower = content.lower()
        file_name_lower = file_path.name.lower()
        is_lockfile = file_name_lower.endswith(".lock") or "lock" in file_name_lower

        # Endpoint and provider domain detection.
        for endpoint in AI_ENDPOINTS:
            if endpoint in content_lower:
                self._append("ai_endpoints", {"endpoint": endpoint, "source_file": str(file_path)})

        # URL-based endpoint extraction.
        for url in re.findall(r"https?://[A-Za-z0-9.\-_/:%?=&]+", content):
            lower_url = url.lower()
            for endpoint in AI_ENDPOINTS:
                if endpoint in lower_url:
                    self._append("ai_endpoints", {"endpoint": endpoint, "source_file": str(file_path)})
                    break

        # Ollama-specific endpoint detection with stronger signals.
        if self.enable_ollama and "ollama" in content_lower:
            for endpoint in OLLAMA_ENDPOINTS:
                if endpoint in content_lower:
                    self._append("ai_endpoints", {
                        "endpoint": f"ollama:{endpoint}",
                        "source_file": str(file_path)
                    })
            self._append("ai_sdks", {
                "name": "ollama",
                "source_file": str(file_path),
                "detection_method": "ollama_usage"
            })

        # Ollama Modelfile detection.
        if self.enable_ollama and file_path.name == "Modelfile":
            self._append("local_models", {
                "name": "ollama_modelfile",
                "source_file": str(file_path)
            })
            from_match = re.search(r"^\s*FROM\s+([^\s]+)", content, flags=re.MULTILINE | re.IGNORECASE)
            if from_match:
                self._append("llm_models", {
                    "model": from_match.group(1),
                    "source_file": str(file_path)
                })

        # SDK signals from explicit import/require or installer commands.
        for dep_name in AI_PACKAGES:
            if not self.enable_ollama and "ollama" in dep_name.lower():
                continue
            escaped = re.escape(dep_name)
            dep_tail = dep_name.split("/")[-1]
            dep_tail = re.escape(dep_tail.replace("-", "_"))
            sdk_patterns = [
                rf"\bimport\s+.*\s+from\s+[\"']{escaped}(?:/[^\"']*)?[\"']",
                rf"\brequire\(\s*[\"']{escaped}(?:/[^\"']*)?[\"']\s*\)",
                rf"\bfrom\s+{dep_tail}(?:\.[A-Za-z0-9_]+)*\s+import\b",
                rf"\bimport\s+{dep_tail}(?:\.[A-Za-z0-9_]+)*\b",
                rf"\busing\s+{dep_tail}(?:\.[A-Za-z0-9_]+)*\s*;",
                rf"\buse\s+{dep_tail}(?:::[A-Za-z0-9_]+)*\s*;",
                rf"\bimport\s+[A-Za-z0-9_.*]+\s*;\s*//.*{dep_tail}",
                rf"\bgo\s+get\s+.*{escaped}",
                rf"\bcargo\s+add\s+.*{re.escape(dep_name.split('/')[-1])}",
                rf"\bcomposer\s+require\s+.*{escaped}",
                rf"\bgem\s+[\"']{re.escape(dep_name.split('/')[-1])}[\"']",
                rf"<artifactId>\s*{re.escape(dep_name.split('/')[-1])}\s*</artifactId>",
                rf"<groupId>\s*{re.escape(dep_name.split(':')[0])}\s*</groupId>",
                rf"\bpip\s+install\s+.*\b{re.escape(dep_name.split('/')[-1])}\b",
                rf"\bnpm\s+(?:i|install)\s+.*\b{re.escape(dep_name)}\b"
            ]
            if any(re.search(pattern, content, flags=re.IGNORECASE) for pattern in sdk_patterns):
                self._append("ai_sdks", {
                    "name": dep_name,
                    "source_file": str(file_path),
                    "detection_method": "text_pattern"
                })

        for vdb in VECTOR_DBS:
            if vdb.lower() in content_lower:
                self._append("vector_dbs", {"name": vdb, "source_file": str(file_path)})

        # Model name detection in non-lock files to reduce package name noise.
        if not is_lockfile:
            for model_pattern in MODEL_NAME_PATTERNS:
                for match in re.finditer(model_pattern, content, flags=re.IGNORECASE):
                    self._append("llm_models", {"model": match.group(0), "source_file": str(file_path)})
            if self.enable_ollama:
                for model_pattern in OLLAMA_MODEL_PATTERNS:
                    for match in re.finditer(model_pattern, content, flags=re.IGNORECASE):
                        model_name = match.group(1) if match.groups() else match.group(0)
                        self._append("llm_models", {"model": model_name, "source_file": str(file_path)})

        # Local model artifacts and from_pretrained references.
        if not is_lockfile:
            for model_pattern in LOCAL_MODEL_PATTERNS:
                for match in re.finditer(model_pattern, content, flags=re.IGNORECASE):
                    model_value = match.group(1) if match.groups() else match.group(0)
                    self._append("local_models", {"name": model_value, "source_file": str(file_path)})

        # Environment variable hints used for AI providers.
        for env_name in AI_ENV_HINTS:
            if not self.enable_ollama and env_name.startswith("OLLAMA_"):
                continue
            if env_name.lower() in content_lower:
                self._append("ai_sdks", {
                    "name": env_name,
                    "source_file": str(file_path),
                    "detection_method": "env_hint"
                })

        # Risk patterns.
        for risk_name, pattern in RISK_PATTERNS.items():
            if re.search(pattern, content):
                self._append("risks", {"risk": risk_name, "source_file": str(file_path)})

    # ----------------------------
    # Deduplicate Results
    # ----------------------------
    def deduplicate(self):
        for key in self.results:
            seen = set()
            unique = []
            for item in self.results[key]:
                identifier = tuple(sorted(item.items()))
                if identifier in seen:
                    continue
                seen.add(identifier)
                unique.append(item)
            self.results[key] = unique

    def aggregate_results(self):
        # Group findings by logical entity and attach occurrences as instances.
        grouping_keys = {
            "ai_sdks": "name",
            "llm_models": "model",
            "local_models": "name",
            "vector_dbs": "name",
            "ai_endpoints": "endpoint",
            "risks": "risk"
        }
        alias_map = {
            # Vector DB aliases
            "@pinecone-database/pinecone": "pinecone",
            "pinecone-client": "pinecone",
            "@qdrant/js-client-rest": "qdrant",
            "qdrant-client": "qdrant",
            "weaviate-client": "weaviate",
            "pymilvus": "milvus",
            "faiss-cpu": "faiss",
            "chroma": "chromadb",
            # SDK aliases (safe canonicalization)
            "@openai/openai": "openai",
            "openai-java": "openai",
            "openai-go": "openai",
            "openai-ruby": "openai",
            "ruby-openai": "openai",
            "ollama-python": "ollama",
            "ollama-js": "ollama",
            "github.com/ollama/ollama": "ollama"
        }

        def _canonical_name(category, entity_value):
            if category not in {"ai_sdks", "vector_dbs"}:
                return entity_value
            lowered = str(entity_value).strip().lower()
            if lowered in alias_map:
                return alias_map[lowered]
            # Heuristic fallback for scoped/vector names.
            for base in VECTOR_DBS:
                if base in lowered:
                    return base
            return entity_value

        for category, entity_key in grouping_keys.items():
            grouped = {}
            for item in self.results.get(category, []):
                entity_value = item.get(entity_key)
                if entity_value is None:
                    continue
                canonical_value = _canonical_name(category, entity_value)

                group = grouped.setdefault(canonical_value, {
                    entity_key: canonical_value,
                    "instances": 0,
                    "source_files": [],
                })
                group["instances"] += 1

                source_file = item.get("source_file")
                if source_file and source_file not in group["source_files"]:
                    group["source_files"].append(source_file)

                # Preserve useful metadata as unique lists where relevant.
                if "version" in item:
                    group.setdefault("versions", [])
                    if item["version"] not in group["versions"]:
                        group["versions"].append(item["version"])

                if "detection_method" in item:
                    group.setdefault("detection_methods", [])
                    if item["detection_method"] not in group["detection_methods"]:
                        group["detection_methods"].append(item["detection_method"])

            # Sort for stable output.
            aggregated = list(grouped.values())
            aggregated.sort(key=lambda x: str(x.get(entity_key, "")).lower())
            self.results[category] = aggregated

    # ----------------------------
    # Run Scanner
    # ----------------------------
    def run(self):
        self.scan_python_files()
        self.scan_requirements()
        self.scan_python_project_files()
        self.scan_polyglot_dependency_files()
        self.scan_package_json()
        self.scan_js_lockfiles()
        self.scan_source_code_patterns()
        self.scan_text_files()
        self.scan_ollama_runtime()
        self.scan_ollama_semantic()
        self.scan_openai_semantic()
        self.scan_gemini_semantic()
        self.deduplicate()
        self.aggregate_results()
        return self.results


def write_json_report(results, output_path):
    with open(output_path, "w", encoding="utf-8") as handle:
        json.dump(results, handle, indent=4)


def write_html_report(results, output_path, project_path):
    sections = CATEGORY_ORDER
    section_titles = CATEGORY_TITLES
    section_colors = CATEGORY_COLORS
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    section_counts = {section: len(results.get(section, [])) for section in sections}
    total_findings = sum(section_counts.values())
    project_root = project_path.resolve()
    project_name = project_root.name or str(project_root)
    report_title = f"AI-SBOM report for {project_name}"

    def _to_display_path(value):
        try:
            rel = Path(str(value)).resolve().relative_to(project_root)
            return str(rel)
        except Exception:
            return str(value)

    def _format_list(values, css_class):
        if not values:
            return "<span class=\"muted\">-</span>"
        items = "".join(
            f"<li class=\"{css_class}\">{html.escape(str(v))}</li>" for v in values
        )
        return f"<ul class=\"pill-list\">{items}</ul>"

    def _format_cell(col, value, section):
        if isinstance(value, list):
            if col == "source_files":
                display_values = [_to_display_path(v) for v in value]
                if len(display_values) <= 3:
                    return _format_list(display_values, "path-pill")
                top = _format_list(display_values[:3], "path-pill")
                rest = _format_list(display_values[3:], "path-pill")
                hidden_count = len(display_values) - 3
                return (
                    f"{top}<details class=\"cell-details\">"
                    f"<summary>+{hidden_count} more files</summary>{rest}</details>"
                )
            return _format_list(value, "meta-pill")
        if col in {"instances"}:
            return (
                "<span class=\"count-badge\" "
                f"style=\"background:{CATEGORY_LIGHT_COLORS[section]};color:{section_colors[section]};"
                f"border:1px solid {section_colors[section]}33;\">{html.escape(str(value))}</span>"
            )
        return html.escape(str(value if value is not None else ""))

    def _table_for_section(section):
        rows = results.get(section, [])
        if not rows:
            return "<div class=\"empty-state\">No findings in this section.</div>"
        columns = sorted({key for row in rows for key in row.keys()})
        header_html = "".join(f"<th>{html.escape(col)}</th>" for col in columns)
        body_rows = []
        for row in rows:
            cells = "".join(f"<td>{_format_cell(col, row.get(col, ''), section)}</td>" for col in columns)
            body_rows.append(f"<tr>{cells}</tr>")
        body_html = "".join(body_rows)
        return f"<div class=\"table-wrap\"><table><thead><tr>{header_html}</tr></thead><tbody>{body_html}</tbody></table></div>"

    summary_cards = "".join(
        (
            "<div class=\"summary-card\">"
            f"<div class=\"summary-label\">{html.escape(section_titles[s])}</div>"
            f"<div class=\"summary-dot\" style=\"background:{section_colors[s]};\"></div>"
            f"<div class=\"summary-value\">{section_counts[s]}</div>"
            "</div>"
        )
        for s in sections
    )
    section_html = "".join(
        (
            "<section class=\"report-section\">"
            f"<div class=\"section-accent\" style=\"background:{section_colors[s]};\"></div>"
            f"<h2>{html.escape(section_titles[s])}</h2>"
            f"<div class=\"section-count\">{section_counts[s]} findings</div>"
            f"{_table_for_section(s)}"
            "</section>"
        )
        for s in sections
    )

    chart_segments = []
    if total_findings > 0:
        start = 0.0
        for section in sections:
            count = section_counts[section]
            if count <= 0:
                continue
            span = (count / total_findings) * 360.0
            end = start + span
            chart_segments.append(f"{section_colors[section]} {start:.2f}deg {end:.2f}deg")
            start = end
        pie_background = f"conic-gradient({', '.join(chart_segments)})"
    else:
        pie_background = "conic-gradient(#cbd5e1 0deg 360deg)"

    chart_legend = "".join(
        (
            "<div class=\"legend-item\">"
            f"<span class=\"legend-swatch\" style=\"background:{section_colors[s]};\"></span>"
            f"<span class=\"legend-label\">{html.escape(section_titles[s])}</span>"
            f"<span class=\"legend-count\">{section_counts[s]}</span>"
            "</div>"
        )
        for s in sections
    )

    html_doc = (
        "<!doctype html>"
        "<html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        f"<title>{html.escape(report_title)}</title>"
        "<style>"
        ":root{--bg:#f0f4ff;--text:#111827;--muted:#64748b;--card:#ffffff;--line:#dbe3f4;--header:#0b1020;}"
        "*{box-sizing:border-box;}"
        "body{font-family:Inter,Segoe UI,Arial,sans-serif;margin:0;background:var(--bg);color:var(--text);}"
        ".container{max-width:1200px;margin:0 auto;padding:24px;}"
        ".hero{background:linear-gradient(135deg,#312e81,#1d4ed8,#0891b2);color:#fff;padding:24px;border-radius:14px;box-shadow:0 12px 28px rgba(37,99,235,0.28);}"
        ".hero h1{margin:0 0 8px 0;font-size:28px;}"
        ".meta{margin:0;color:#e0e7ff;font-size:14px;}"
        ".totals{margin-top:14px;font-size:14px;color:#eef2ff;}"
        ".insights-grid{display:grid;grid-template-columns:minmax(280px,380px) 1fr;gap:14px;margin:18px 0 10px 0;align-items:stretch;}"
        ".chart-card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px;box-shadow:0 3px 10px rgba(15,23,42,0.08);}"
        ".chart-title{margin:0 0 10px 0;font-size:14px;color:#334155;font-weight:600;}"
        ".pie-wrap{display:flex;gap:14px;align-items:center;flex-wrap:wrap;}"
        f".pie{{width:170px;height:170px;border-radius:50%;background:{pie_background};position:relative;box-shadow:inset 0 0 0 1px rgba(15,23,42,0.06);}}"
        ".pie::after{content:'';position:absolute;inset:38px;background:#fff;border-radius:50%;box-shadow:inset 0 0 0 1px #e2e8f0;}"
        ".pie-total{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;font-size:13px;font-weight:700;color:#334155;z-index:1;}"
        ".legend{display:grid;gap:8px;min-width:190px;}"
        ".legend-item{display:grid;grid-template-columns:14px 1fr auto;align-items:center;gap:8px;background:#f8fbff;border:1px solid #e7eefc;border-radius:8px;padding:6px 8px;}"
        ".legend-swatch{width:12px;height:12px;border-radius:3px;display:inline-block;}"
        ".legend-label{font-size:12px;color:#334155;}"
        ".legend-count{font-size:12px;color:#0f172a;font-weight:700;}"
        ".summary-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;}"
        ".summary-card{background:linear-gradient(180deg,#ffffff,#f8fbff);border:1px solid var(--line);border-radius:10px;padding:14px;box-shadow:0 2px 8px rgba(2,6,23,0.05);position:relative;overflow:hidden;}"
        ".summary-card::before{content:'';position:absolute;left:0;top:0;width:100%;height:4px;background:linear-gradient(90deg,#4f46e5,#06b6d4,#10b981,#f59e0b,#ef4444,#d946ef);opacity:.9;}"
        ".summary-label{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em;}"
        ".summary-dot{width:10px;height:10px;border-radius:50%;margin-top:8px;box-shadow:0 0 0 3px rgba(59,130,246,0.15);}"
        ".summary-value{margin-top:6px;font-size:28px;font-weight:700;color:var(--header);}"
        ".report-section{margin-top:18px;background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px;box-shadow:0 2px 8px rgba(2,6,23,0.04);}"
        ".section-accent{height:4px;border-radius:999px;margin:-4px -4px 10px -4px;}"
        ".report-section h2{margin:0;font-size:18px;color:var(--header);}"
        ".section-count{margin-top:4px;color:var(--muted);font-size:13px;}"
        ".table-wrap{margin-top:12px;overflow:auto;border:1px solid var(--line);border-radius:8px;}"
        "table{border-collapse:separate;border-spacing:0;width:100%;background:#fff;table-layout:auto;}"
        "th,td{padding:10px 12px;font-size:13px;text-align:left;vertical-align:top;border-bottom:1px solid #eef2f7;}"
        "th{position:sticky;top:0;background:#f8fafc;color:#334155;font-weight:600;border-bottom:1px solid #e2e8f0;}"
        "tr:hover td{background:#fafcff;}"
        ".muted{color:#94a3b8;}"
        ".count-badge{display:inline-flex;align-items:center;justify-content:center;min-width:30px;padding:4px 8px;border-radius:999px;background:#e8edff;color:#312e81;font-weight:700;font-size:12px;}"
        ".pill-list{list-style:none;padding:0;margin:0;display:flex;flex-wrap:wrap;gap:6px;}"
        ".path-pill,.meta-pill{display:inline-flex;align-items:center;max-width:520px;padding:3px 8px;border-radius:999px;font-size:11px;line-height:1.3;border:1px solid #e2e8f0;word-break:break-all;}"
        ".path-pill{background:#f8fafc;color:#334155;}"
        ".meta-pill{background:#f5f3ff;color:#5b21b6;border-color:#ddd6fe;}"
        ".cell-details{margin-top:6px;}"
        ".cell-details summary{cursor:pointer;color:#2563eb;font-size:12px;}"
        ".empty-state{margin-top:10px;padding:12px;border:1px dashed #cbd5e1;border-radius:8px;color:var(--muted);background:#f8fafc;}"
        "@media (max-width:900px){.insights-grid{grid-template-columns:1fr;}}"
        "@media (max-width:700px){.hero h1{font-size:22px;}.summary-value{font-size:24px;}.pie{width:150px;height:150px;}.pie::after{inset:32px;}}"
        "</style></head><body>"
        "<div class=\"container\">"
        "<div class=\"hero\">"
        f"<h1>{html.escape(report_title)}</h1>"
        f"<p class=\"meta\">Project: {html.escape(str(project_path.resolve()))}</p>"
        f"<p class=\"meta\">Generated at: {html.escape(generated_at)}</p>"
        f"<p class=\"totals\">Total findings: <strong>{total_findings}</strong></p>"
        "</div>"
        "<div class=\"insights-grid\">"
        "<div class=\"chart-card\">"
        "<h3 class=\"chart-title\">Findings Distribution</h3>"
        "<div class=\"pie-wrap\">"
        f"<div class=\"pie\"><div class=\"pie-total\">{total_findings}</div></div>"
        f"<div class=\"legend\">{chart_legend}</div>"
        "</div>"
        "</div>"
        f"<div class=\"summary-grid\">{summary_cards}</div>"
        "</div>"
        f"{section_html}"
        "</div>"
        "</body></html>"
    )

    with open(output_path, "w", encoding="utf-8") as handle:
        handle.write(html_doc)


def write_excel_report(results, output_path):
    # Excel-compatible SpreadsheetML (XML 2003) to avoid external dependencies.
    sections = CATEGORY_ORDER

    def xml_escape(value):
        return (
            str(value)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&apos;")
        )

    workbook_parts = [
        "<?xml version=\"1.0\"?>",
        "<?mso-application progid=\"Excel.Sheet\"?>",
        "<Workbook xmlns=\"urn:schemas-microsoft-com:office:spreadsheet\" "
        "xmlns:ss=\"urn:schemas-microsoft-com:office:spreadsheet\">",
        "<Styles>",
        "<Style ss:ID=\"default\"><Font ss:FontName=\"Calibri\" ss:Size=\"11\"/><Alignment ss:Vertical=\"Top\" ss:WrapText=\"1\"/></Style>",
        "<Style ss:ID=\"summary_header\"><Font ss:Bold=\"1\" ss:Color=\"#FFFFFF\"/><Interior ss:Color=\"#1D4ED8\" ss:Pattern=\"Solid\"/></Style>",
        "<Style ss:ID=\"empty\"><Font ss:Italic=\"1\" ss:Color=\"#64748B\"/></Style>",
    ]
    for section in sections:
        color = CATEGORY_COLORS[section]
        light = CATEGORY_LIGHT_COLORS[section]
        workbook_parts.append(
            f"<Style ss:ID=\"cat_{xml_escape(section)}\">"
            f"<Interior ss:Color=\"{xml_escape(light)}\" ss:Pattern=\"Solid\"/>"
            "</Style>"
        )
        workbook_parts.append(
            f"<Style ss:ID=\"cat_header_{xml_escape(section)}\">"
            "<Font ss:Bold=\"1\" ss:Color=\"#FFFFFF\"/>"
            f"<Interior ss:Color=\"{xml_escape(color)}\" ss:Pattern=\"Solid\"/>"
            "</Style>"
        )
    workbook_parts.append("</Styles>")

    # Summary sheet.
    workbook_parts.append("<Worksheet ss:Name=\"Summary\"><Table>")
    workbook_parts.append(
        "<Row>"
        "<Cell ss:StyleID=\"summary_header\"><Data ss:Type=\"String\">Section</Data></Cell>"
        "<Cell ss:StyleID=\"summary_header\"><Data ss:Type=\"String\">Count</Data></Cell>"
        "</Row>"
    )
    for section in sections:
        count = len(results.get(section, []))
        style_id = f"cat_{section}"
        workbook_parts.append(
            "<Row>"
            f"<Cell ss:StyleID=\"{xml_escape(style_id)}\"><Data ss:Type=\"String\">{xml_escape(CATEGORY_TITLES[section])}</Data></Cell>"
            f"<Cell ss:StyleID=\"{xml_escape(style_id)}\"><Data ss:Type=\"Number\">{count}</Data></Cell>"
            "</Row>"
        )
    workbook_parts.append("</Table></Worksheet>")

    # Detail sheets.
    for section in sections:
        rows = results.get(section, [])
        sheet_name = section[:31]  # Excel sheet name limit.
        workbook_parts.append(f"<Worksheet ss:Name=\"{xml_escape(sheet_name)}\"><Table>")

        if not rows:
            workbook_parts.append("<Row><Cell ss:StyleID=\"empty\"><Data ss:Type=\"String\">No findings</Data></Cell></Row>")
            workbook_parts.append("</Table></Worksheet>")
            continue

        columns = sorted({key for row in rows for key in row.keys()})
        header_style_id = f"cat_header_{section}"
        row_style_id = f"cat_{section}"
        header_cells = "".join(
            f"<Cell ss:StyleID=\"{xml_escape(header_style_id)}\"><Data ss:Type=\"String\">{xml_escape(col)}</Data></Cell>"
            for col in columns
        )
        workbook_parts.append(f"<Row>{header_cells}</Row>")

        for row in rows:
            value_cells = "".join(
                f"<Cell ss:StyleID=\"{xml_escape(row_style_id)}\"><Data ss:Type=\"String\">{xml_escape(row.get(col, ''))}</Data></Cell>"
                for col in columns
            )
            workbook_parts.append(f"<Row>{value_cells}</Row>")

        workbook_parts.append("</Table></Worksheet>")

    workbook_parts.append("</Workbook>")

    with open(output_path, "w", encoding="utf-8") as handle:
        handle.write("".join(workbook_parts))


def persist_scan_to_db(project_path, results, db_path):
    category_entity_key = {
        "ai_sdks": "name",
        "llm_models": "model",
        "local_models": "name",
        "vector_dbs": "name",
        "ai_endpoints": "endpoint",
        "risks": "risk",
    }

    db_file = Path(db_path)
    if not db_file.is_absolute():
        db_file = Path.cwd() / db_file

    conn = sqlite3.connect(str(db_file))
    try:
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS projects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                path TEXT NOT NULL UNIQUE
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_uid TEXT UNIQUE,
                project_id INTEGER NOT NULL,
                scanned_at TEXT NOT NULL,
                total_components INTEGER NOT NULL,
                total_instances INTEGER NOT NULL,
                FOREIGN KEY(project_id) REFERENCES projects(id)
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                category TEXT NOT NULL,
                entity TEXT NOT NULL,
                instances INTEGER NOT NULL,
                source_files_json TEXT NOT NULL,
                meta_json TEXT NOT NULL,
                FOREIGN KEY(scan_id) REFERENCES scans(id)
            )
            """
        )
        # Lightweight migration for older DBs created before scan_uid.
        existing_scan_cols = {row[1] for row in cur.execute("PRAGMA table_info(scans)").fetchall()}
        if "scan_uid" not in existing_scan_cols:
            cur.execute("ALTER TABLE scans ADD COLUMN scan_uid TEXT")

        cur.execute("CREATE INDEX IF NOT EXISTS idx_scans_project ON scans(project_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_scans_uid ON scans(scan_uid)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(category)")

        resolved_project = Path(project_path).resolve()
        cur.execute(
            "INSERT OR IGNORE INTO projects(name, path) VALUES(?, ?)",
            (resolved_project.name or str(resolved_project), str(resolved_project)),
        )
        cur.execute("SELECT id FROM projects WHERE path = ?", (str(resolved_project),))
        project_id = cur.fetchone()[0]

        total_components = sum(len(results.get(category, [])) for category in category_entity_key)
        total_instances = 0
        for category in category_entity_key:
            for item in results.get(category, []):
                total_instances += int(item.get("instances", 1))

        scanned_at = datetime.now().isoformat(timespec="seconds")
        scan_uid = f"SCAN-{datetime.now().strftime('%Y%m%d-%H%M%S-%f')}-{os.getpid()}"

        cur.execute(
            """
            INSERT INTO scans(scan_uid, project_id, scanned_at, total_components, total_instances)
            VALUES(?, ?, ?, ?, ?)
            """,
            (
                scan_uid,
                project_id,
                scanned_at,
                total_components,
                total_instances,
            ),
        )
        scan_id = cur.lastrowid

        for category, entity_key in category_entity_key.items():
            for item in results.get(category, []):
                entity = str(item.get(entity_key, ""))
                instances = int(item.get("instances", 1))
                source_files = item.get("source_files", [])
                if isinstance(source_files, str):
                    source_files = [source_files]
                meta = {
                    key: value
                    for key, value in item.items()
                    if key not in {entity_key, "instances", "source_files"}
                }
                cur.execute(
                    """
                    INSERT INTO findings(scan_id, category, entity, instances, source_files_json, meta_json)
                    VALUES(?, ?, ?, ?, ?, ?)
                    """,
                    (
                        scan_id,
                        category,
                        entity,
                        instances,
                        json.dumps(source_files),
                        json.dumps(meta),
                    ),
                )

        conn.commit()
        return db_file, scan_id, scan_uid
    finally:
        conn.close()


def get_active_db_path(link_file="ai_sbom_active_db.txt"):
    link_path = Path(link_file)
    if not link_path.is_absolute():
        link_path = Path.cwd() / link_path
    if not link_path.exists():
        return None, None
    try:
        target = link_path.read_text(encoding="utf-8").strip()
    except Exception:
        return None, f"Unable to read DB link file: {link_path}"
    if not target:
        return None, f"DB link file is empty: {link_path}"
    resolved = Path(target).resolve()
    if not resolved.exists():
        return None, (
            f"DB path not found in {link_path}: {resolved}\n"
            "Check path in that file or create a new DB with:\n"
            "python3 run-ui.py --new-db --port 8787"
        )
    return resolved, None


def get_active_ui_url(status_file="ai_sbom_ui_status.json"):
    status_path = Path(status_file)
    if not status_path.is_absolute():
        status_path = Path.cwd() / status_path
    if not status_path.exists():
        return None
    try:
        payload = json.loads(status_path.read_text(encoding="utf-8"))
    except Exception:
        return None
    host = payload.get("host")
    port = payload.get("port")
    url = payload.get("url")
    if not host or not port or not url:
        return None
    try:
        with socket.create_connection((str(host), int(port)), timeout=0.3):
            return str(url)
    except OSError:
        return None


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate AI SBOM reports from source code.")
    parser.add_argument("project_path", help="Path to the project to scan")
    parser.add_argument("--json", dest="json_report", action="store_true", help="Generate JSON report (default on)")
    parser.add_argument("--no-json", dest="json_report", action="store_false", help="Skip JSON report")
    parser.set_defaults(json_report=True)
    parser.add_argument("--html", dest="html_report", action="store_true", help="Generate HTML report")
    parser.add_argument("--excel", dest="excel_report", action="store_true", help="Generate Excel report (.xls)")
    parser.add_argument("--ollama", dest="ollama", action="store_true", help="Enable Ollama-specific detection")
    parser.add_argument("--ollama-model", dest="ollama_model", default="llama3.2:latest", help="Ollama model for semantic enrichment")
    parser.add_argument("--openai", dest="openai", action="store_true", help="Enable OpenAI semantic enrichment")
    parser.add_argument("--openai-model", dest="openai_model", default="gpt-4o-mini", help="OpenAI model for semantic enrichment")
    parser.add_argument("--gemini", dest="gemini", action="store_true", help="Enable Gemini semantic enrichment")
    parser.add_argument("--gemini-model", dest="gemini_model", default="gemini-1.5-flash", help="Gemini model for semantic enrichment")
    parser.add_argument("--db", dest="store_db", action="store_true", help="Store scan results in default local SQLite DB (ai_sbom.db)")

    args = parser.parse_args()
    project_path = Path(args.project_path)

    scanner = AICodeScanner(
        project_path,
        enable_ollama=args.ollama,
        ollama_model=args.ollama_model,
        enable_openai=args.openai,
        openai_model=args.openai_model,
        enable_gemini=args.gemini,
        gemini_model=args.gemini_model,
    )
    results = scanner.run()
    generated = []

    if args.json_report:
        json_output = project_path / "ai_sbom.json"
        write_json_report(results, json_output)
        generated.append(str(json_output))

    if args.html_report:
        html_output = project_path / "ai_sbom.html"
        write_html_report(results, html_output, project_path)
        generated.append(str(html_output))

    if args.excel_report:
        excel_output = project_path / "ai_sbom.xls"
        write_excel_report(results, excel_output)
        generated.append(str(excel_output))

    active_db, active_db_error = get_active_db_path()
    if active_db_error:
        print(f"Error: {active_db_error}")
        raise SystemExit(1)
    if active_db:
        db_file, scan_id, scan_uid = persist_scan_to_db(project_path, results, str(active_db))
        generated.append(f"DB (active link): {db_file} (scan_id={scan_id}, scan_uid={scan_uid})")
    elif args.store_db:
        db_file, scan_id, scan_uid = persist_scan_to_db(project_path, results, "ai_sbom.db")
        generated.append(f"DB: {db_file} (scan_id={scan_id}, scan_uid={scan_uid})")

    ui_url = get_active_ui_url()
    if ui_url:
        generated.append(f"UI (active): {ui_url}")

    if generated:
        print("AI SBOM generated:")
        for path in generated:
            print(f"- {path}")
    else:
        print("Scan complete. No reports selected.")
