#!/usr/bin/env python3
"""
ghsa_version_resolver.py — Resolve GHSA advisory to clone URL + vulnerable/fix SHAs
via version-to-git-tag matching.

Strategy:
  1. Query GitHub Global Advisory API for affected package versions
  2. Find repo URL from source_code_location or Maven Central SCM
  3. Clone/fetch the repo
  4. Match patched version to a git tag → FIX_SHA
  5. Find last vulnerable version tag → VULN_SHA (tag before patched, within range)

Usage:
  python3 ghsa_version_resolver.py GHSA-pchp-c5w8-47gc
  python3 ghsa_version_resolver.py GHSA-pchp-c5w8-47gc --json
  python3 ghsa_version_resolver.py GHSA-pchp-c5w8-47gc --repo-url https://github.com/jenkinsci/jenkins

Output (text):
  Clone URL: https://github.com/jenkinsci/jenkins
  Fix commit: <sha>
  Parent (likely vulnerable): <sha>
  Patched version: 1.447
  Vulnerable range: >= 1.425, < 1.447
  Fix tag: jenkins-1.447
  Vuln tag: jenkins-1.446

Output (JSON):
  { "clone_url": "...", "fix_sha": "...", "vuln_sha": "...", ... }

Requires: Python 3.10+, git on PATH, internet access to api.github.com
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class VersionRange:
    """Parsed version range from advisory."""
    raw: str
    lower_bound: Optional[str] = None
    lower_inclusive: bool = True
    upper_bound: Optional[str] = None
    upper_inclusive: bool = False


@dataclass
class AffectedPackage:
    """One affected package from a GHSA advisory."""
    ecosystem: str
    name: str
    vulnerable_range: str
    patched_version: Optional[str]
    ranges: list[VersionRange] = field(default_factory=list)


@dataclass
class AdvisoryInfo:
    """Parsed advisory from GHSA API."""
    ghsa_id: str
    cve_id: Optional[str]
    summary: str
    source_code_location: Optional[str]
    references: list[str]
    packages: list[AffectedPackage]


@dataclass
class ResolvedResult:
    """Final resolution result."""
    clone_url: str
    fix_sha: str
    vuln_sha: str
    patched_version: Optional[str]
    vulnerable_range: Optional[str]
    fix_tag: Optional[str]
    vuln_tag: Optional[str]
    package_name: Optional[str]
    ecosystem: Optional[str]
    method: str  # "tag_match", "tag_parent", etc.
    repo_path: Optional[str] = None  # local path where repo was cloned


# ---------------------------------------------------------------------------
# GHSA API
# ---------------------------------------------------------------------------

def fetch_advisory(ghsa_id: str) -> AdvisoryInfo:
    """Fetch advisory from GitHub Global Advisory API (unauthenticated)."""
    url = f"https://api.github.com/advisories/{ghsa_id}"
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    # Use token if available for higher rate limits
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"

    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            raise SystemExit(f"Advisory not found: {ghsa_id}")
        raise SystemExit(f"GitHub API error {e.code}: {e.reason}")

    packages = []
    for vuln in data.get("vulnerabilities") or []:
        pkg = vuln.get("package") or {}
        ecosystem = pkg.get("ecosystem") or ""
        name = pkg.get("name") or ""
        vr = vuln.get("vulnerable_version_range") or ""
        fpv = vuln.get("first_patched_version")
        patched = fpv if isinstance(fpv, str) else (fpv or {}).get("identifier") if isinstance(fpv, dict) else None

        ranges = parse_version_ranges(vr) if vr else []
        packages.append(AffectedPackage(
            ecosystem=ecosystem,
            name=name,
            vulnerable_range=vr,
            patched_version=patched,
            ranges=ranges,
        ))

    return AdvisoryInfo(
        ghsa_id=data.get("ghsa_id") or ghsa_id,
        cve_id=data.get("cve_id"),
        summary=data.get("summary") or "",
        source_code_location=data.get("source_code_location"),
        references=[r for r in (data.get("references") or []) if isinstance(r, str)],
        packages=packages,
    )


# ---------------------------------------------------------------------------
# Version parsing
# ---------------------------------------------------------------------------

def parse_version_ranges(raw: str) -> list[VersionRange]:
    """Parse version range string like '>= 1.425, < 1.447' into VersionRange objects."""
    # Split on comma for compound ranges
    parts = [p.strip() for p in raw.split(",") if p.strip()]
    ranges = []

    lower_bound = None
    lower_inclusive = True
    upper_bound = None
    upper_inclusive = False

    for part in parts:
        m = re.match(r"^\s*(>=|>|<=|<|=)\s*(.+)$", part)
        if not m:
            continue
        op, ver = m.group(1), m.group(2).strip()
        if op == ">=":
            lower_bound = ver
            lower_inclusive = True
        elif op == ">":
            lower_bound = ver
            lower_inclusive = False
        elif op == "<=":
            upper_bound = ver
            upper_inclusive = True
        elif op == "<":
            upper_bound = ver
            upper_inclusive = False
        elif op == "=":
            lower_bound = ver
            lower_inclusive = True
            upper_bound = ver
            upper_inclusive = True

    if lower_bound or upper_bound:
        ranges.append(VersionRange(
            raw=raw,
            lower_bound=lower_bound,
            lower_inclusive=lower_inclusive,
            upper_bound=upper_bound,
            upper_inclusive=upper_inclusive,
        ))

    return ranges


def parse_version_tuple(version_str: str) -> tuple[int, ...]:
    """Parse '1.447.2' → (1, 447, 2). Non-numeric segments get 0."""
    parts = re.split(r"[.\-_]", version_str)
    result = []
    for p in parts:
        m = re.match(r"^(\d+)", p)
        if m:
            result.append(int(m.group(1)))
        # skip non-numeric parts like "RELEASE", "SNAPSHOT" etc.
    return tuple(result) if result else (0,)

def normalize_version_str(v: str) -> str:
    """Normalize versions/tags like '6_8_0' or 'v6.8.0' into a comparable '6.8.0' form."""
    v = v.strip()
    # Drop leading v/V
    v = re.sub(r"^[vV]\s*", "", v)
    # Convert underscores to dots (Struts uses STRUTS_6_8_0)
    v = v.replace("_", ".")
    # Remove trailing non-numeric suffixes (best-effort)
    # e.g. '1.2.3-RC1' -> '1.2.3'
    v = re.sub(r"(\d+(?:\.\d+)*).*$", r"\1", v)
    return v

def version_less_than(a: str, b: str) -> bool:
    return parse_version_tuple(a) < parse_version_tuple(b)


def version_in_range(version: str, vr: VersionRange) -> bool:
    """Check if a version string falls within a VersionRange."""
    vt = parse_version_tuple(version)

    if vr.lower_bound:
        lb = parse_version_tuple(vr.lower_bound)
        if vr.lower_inclusive:
            if vt < lb:
                return False
        else:
            if vt <= lb:
                return False

    if vr.upper_bound:
        ub = parse_version_tuple(vr.upper_bound)
        if vr.upper_inclusive:
            if vt > ub:
                return False
        else:
            if vt >= ub:
                return False

    return True


# ---------------------------------------------------------------------------
# Repo discovery
# ---------------------------------------------------------------------------

def discover_repo_url(advisory: AdvisoryInfo, user_repo_url: Optional[str]) -> Optional[str]:
    """Find the git clone URL for the advisory's affected project."""
    # 1. User override
    if user_repo_url:
        return normalize_github_url(user_repo_url)

    # 2. source_code_location from advisory
    if advisory.source_code_location:
        url = normalize_github_url(advisory.source_code_location)
        if url:
            return url

    # 3. Scan references for GitHub URLs
    for ref in advisory.references:
        url = normalize_github_url(ref)
        if url and "/advisories/" not in url and "/nvd.nist.gov/" not in url:
            return url

    # Try package-specific strategies for each affected package
    for pkg in advisory.packages:
        # 4. Maven Central SCM lookup
        if pkg.ecosystem.lower() == "maven" and ":" in pkg.name:
            url = maven_scm_lookup(pkg.name)
            if url:
                return url

        # 5. GitHub org inference from Maven groupId
        if pkg.ecosystem.lower() == "maven" and ":" in pkg.name:
            url = infer_github_from_maven_groupid(pkg.name)
            if url:
                return url

        # 6. mvnrepository.com scraping (has SCM even when Central doesn't)
        if pkg.ecosystem.lower() == "maven" and ":" in pkg.name:
            url = mvnrepository_scm_lookup(pkg.name)
            if url:
                return url

        # 7. GitHub search API
        url = github_search_repo(pkg.name, pkg.ecosystem)
        if url:
            return url

    return None


def normalize_github_url(raw: str) -> Optional[str]:
    """Extract a clone-able GitHub URL from various URL formats."""
    raw = raw.strip()
    m = re.match(r"https?://github\.com/([^/]+/[^/]+?)(?:\.git)?(?:/.*)?$", raw)
    if m:
        return f"https://github.com/{m.group(1)}.git"
    return None


def maven_scm_lookup(coordinates: str) -> Optional[str]:
    """Look up SCM URL from Maven Central for groupId:artifactId."""
    parts = coordinates.split(":")
    if len(parts) < 2:
        return None
    group_id, artifact_id = parts[0], parts[1]
    group_path = group_id.replace(".", "/")

    # Try Maven Central search API
    url = (
        f"https://search.maven.org/solrsearch/select"
        f"?q=g:{group_id}+AND+a:{artifact_id}&rows=1&wt=json"
    )
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        docs = data.get("response", {}).get("docs", [])
        if not docs:
            return None
        # Try to get the POM for SCM info
        version = docs[0].get("latestVersion") or docs[0].get("v")
        if not version:
            return None
        pom_url = (
            f"https://repo1.maven.org/maven2/{group_path}/{artifact_id}"
            f"/{version}/{artifact_id}-{version}.pom"
        )
        pom_req = urllib.request.Request(pom_url)
        with urllib.request.urlopen(pom_req, timeout=15) as resp:
            pom_text = resp.read().decode("utf-8")
        # Extract SCM URL from POM
        m = re.search(
            r"<scm>\s*.*?<url>\s*(https?://github\.com/[^<]+?)\s*</url>",
            pom_text,
            re.DOTALL,
        )
        if m:
            return normalize_github_url(m.group(1))
        # Try connection/url
        m = re.search(
            r"<connection>\s*scm:git:(https?://github\.com/[^<]+?)\s*</connection>",
            pom_text,
            re.DOTALL,
        )
        if m:
            return normalize_github_url(m.group(1))
    except Exception:
        pass

    return None


# Well-known Maven groupId → GitHub org mappings that don't follow conventions
_KNOWN_MAVEN_GITHUB_ORGS: dict[str, str] = {
    "org.jenkins-ci": "jenkinsci",
    "org.jenkins-ci.main": "jenkinsci",
    "org.jenkins-ci.plugins": "jenkinsci",
    "io.jenkins": "jenkinsci",
    "io.jenkins.plugins": "jenkinsci",
    "com.google.code.gson": "google",
    "com.google.guava": "google",
    "com.google.protobuf": "protocolbuffers",
    "org.apache.commons": "apache",
    "org.apache.logging.log4j": "apache",
    "org.apache.struts": "apache",
    "com.fasterxml.jackson.core": "FasterXML",
    "com.fasterxml.jackson.dataformat": "FasterXML",
    "com.fasterxml.jackson.databind": "FasterXML",
    "org.eclipse.jetty": "jetty",
    "io.netty": "netty",
    "org.springframework": "spring-projects",
    "org.springframework.boot": "spring-projects",
    "org.springframework.security": "spring-projects",
}

# Well-known Maven coordinates → exact GitHub repo
_KNOWN_MAVEN_REPOS: dict[str, str] = {
    "org.jenkins-ci.main:jenkins-core": "https://github.com/jenkinsci/jenkins.git",
    "org.jenkins-ci.main:cli": "https://github.com/jenkinsci/jenkins.git",
    "org.jenkins-ci.main:remoting": "https://github.com/jenkinsci/remoting.git",
    "org.json:json": "https://github.com/stleary/JSON-java.git",
    "com.google.code.gson:gson": "https://github.com/google/gson.git",
    "com.fasterxml.jackson.core:jackson-databind": "https://github.com/FasterXML/jackson-databind.git",
    "com.fasterxml.jackson.core:jackson-core": "https://github.com/FasterXML/jackson-core.git",
    "org.yaml:snakeyaml": "https://github.com/snakeyaml/snakeyaml.git",
    "commons-io:commons-io": "https://github.com/apache/commons-io.git",
    "commons-codec:commons-codec": "https://github.com/apache/commons-codec.git",
    "org.apache.commons:commons-compress": "https://github.com/apache/commons-compress.git",
    "org.apache.commons:commons-text": "https://github.com/apache/commons-text.git",
    "ch.qos.logback:logback-core": "https://github.com/qos-ch/logback.git",
    "io.netty:netty-codec-http": "https://github.com/netty/netty.git",
    "io.netty:netty-handler": "https://github.com/netty/netty.git",
}


def infer_github_from_maven_groupid(coordinates: str) -> Optional[str]:
    """Infer GitHub URL from Maven groupId conventions.

    Strategy:
      1. Check known exact coordinate→repo mappings
      2. Check known groupId→org mappings + derive repo name from artifactId
      3. Heuristic: reverse-domain groupId → GitHub org + artifactId
      4. Probe the candidate URL to verify it exists
    """
    parts = coordinates.split(":")
    if len(parts) < 2:
        return None
    group_id, artifact_id = parts[0], parts[1]

    # 1. Exact mapping
    key = f"{group_id}:{artifact_id}"
    if key in _KNOWN_MAVEN_REPOS:
        url = _KNOWN_MAVEN_REPOS[key]
        print(f"[resolver] repo from known mapping: {key} → {url}", file=sys.stderr)
        return url

    # 2. Known org mapping
    org = None
    # Try progressively shorter prefixes (org.jenkins-ci.main → org.jenkins-ci → ...)
    gparts = group_id.split(".")
    for i in range(len(gparts), 0, -1):
        prefix = ".".join(gparts[:i])
        if prefix in _KNOWN_MAVEN_GITHUB_ORGS:
            org = _KNOWN_MAVEN_GITHUB_ORGS[prefix]
            break

    # 3. Heuristic: last segment of groupId as org
    if org is None:
        # org.example.foo → try "foo" as GitHub user, or "example" etc.
        candidates = [gparts[-1]]
        if len(gparts) >= 2:
            candidates.append(gparts[-2])
    else:
        candidates = []

    # Build candidate URLs to probe
    repo_candidates = [artifact_id]
    # For sub-modules, try the parent project name too
    # e.g. jenkins-core → jenkins, netty-codec-http → netty
    base = re.sub(r"[_-](core|common|impl|api|lib|main|base|server|client)$", "", artifact_id)
    if base != artifact_id:
        repo_candidates.append(base)

    urls_to_probe = []
    if org:
        for repo in repo_candidates:
            urls_to_probe.append(f"https://github.com/{org}/{repo}")
    else:
        for cand_org in candidates:
            for repo in repo_candidates:
                urls_to_probe.append(f"https://github.com/{cand_org}/{repo}")

    # 4. Probe URLs
    for url in urls_to_probe:
        if probe_github_repo_exists(url):
            clone_url = f"{url}.git"
            print(f"[resolver] repo from groupId inference: {coordinates} → {clone_url}", file=sys.stderr)
            return clone_url

    return None


def probe_github_repo_exists(url: str) -> bool:
    """Check if a GitHub repo URL exists (HEAD request)."""
    try:
        req = urllib.request.Request(url, method="HEAD")
        req.add_header("User-Agent", "ghsa-version-resolver/1.0")
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status == 200
    except Exception:
        return False


def mvnrepository_scm_lookup(coordinates: str) -> Optional[str]:
    """Look up SCM URL from mvnrepository.com (has SCM info even for sub-modules)."""
    parts = coordinates.split(":")
    if len(parts) < 2:
        return None
    group_id, artifact_id = parts[0], parts[1]

    url = f"https://mvnrepository.com/artifact/{group_id}/{artifact_id}"
    try:
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "Mozilla/5.0 (compatible; ghsa-resolver/1.0)")
        with urllib.request.urlopen(req, timeout=15) as resp:
            html = resp.read().decode("utf-8", errors="replace")

        # Look for GitHub URLs in the page
        for m in re.finditer(r'href="(https?://github\.com/[^"]+)"', html):
            candidate = m.group(1)
            # Skip badge URLs, CI links, etc.
            if "/actions/" in candidate or "/badge" in candidate or "/workflows/" in candidate:
                continue
            normalized = normalize_github_url(candidate)
            if normalized:
                print(f"[resolver] repo from mvnrepository.com: {coordinates} → {normalized}", file=sys.stderr)
                return normalized
    except Exception:
        pass

    return None


def github_search_repo(package_name: str, ecosystem: str) -> Optional[str]:
    """Search GitHub API for a repo matching the package name."""
    # Build search query
    if ecosystem.lower() == "maven" and ":" in package_name:
        # Use artifact name
        artifact = package_name.split(":")[1]
        query = artifact
    else:
        query = package_name

    # GitHub search API (unauthenticated, rate-limited)
    headers: dict[str, str] = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"

    search_url = f"https://api.github.com/search/repositories?q={urllib.request.quote(query)}+language:java&sort=stars&per_page=5"
    try:
        req = urllib.request.Request(search_url, headers=headers)
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        for item in data.get("items") or []:
            clone = item.get("clone_url") or item.get("html_url")
            if clone:
                normalized = normalize_github_url(clone)
                if normalized:
                    print(f"[resolver] repo from GitHub search: {package_name} → {normalized}", file=sys.stderr)
                    return normalized
    except Exception as e:
        print(f"[resolver] GitHub search failed: {e}", file=sys.stderr)

    return None


# ---------------------------------------------------------------------------
# Git tag resolution
# ---------------------------------------------------------------------------

def git_clone_or_fetch(clone_url: str, workdir: str, skip_fetch: bool = False, repo_dir: Optional[str] = None) -> str:
    """Clone or fetch a repo, return the repo path."""
    if repo_dir:
        dir_name = repo_dir
    else:
        dir_name = re.sub(r"\.git$", "", clone_url.rstrip("/").split("/")[-1])
    repo_path = os.path.join(workdir, dir_name)

    if os.path.isdir(os.path.join(repo_path, ".git")):
        if not skip_fetch:
            print(f"[resolver] fetching tags in {repo_path}", file=sys.stderr)
            subprocess.run(
                ["git", "fetch", "--all", "--tags", "--prune"],
                cwd=repo_path, capture_output=True, timeout=120,
            )
    else:
        print(f"[resolver] cloning {clone_url} → {repo_path}", file=sys.stderr)
        subprocess.run(
            ["git", "clone", "--no-checkout", clone_url, repo_path],
            capture_output=True, timeout=300, check=True,
        )

    return repo_path


@dataclass
class TagInfo:
    tag_name: str
    version: str
    sha: str


def list_version_tags_remote(clone_url: str) -> list[TagInfo]:
    """List all version tags from a remote repo WITHOUT cloning.

    Uses `git ls-remote --tags` which only downloads tag refs, not objects.
    This avoids cloning a 100MB+ repo just to scan tags.
    """
    print(f"[resolver] listing remote tags from {clone_url}", file=sys.stderr)
    result = subprocess.run(
        ["git", "ls-remote", "--tags", clone_url],
        capture_output=True, text=True, timeout=60,
    )
    if result.returncode != 0:
        raise SystemExit(
            f"git ls-remote failed for {clone_url}: {result.stderr.strip()}"
        )

    # Parse ls-remote output, preferring dereferenced SHAs (^{})
    tags_by_name: dict[str, TagInfo] = {}
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split("\t", 1)
        if len(parts) != 2:
            continue
        sha = parts[0].strip()
        ref = parts[1].strip()

        if not ref.startswith("refs/tags/"):
            continue

        is_deref = ref.endswith("^{}")
        tag_name = ref.removeprefix("refs/tags/")
        if is_deref:
            tag_name = tag_name.removesuffix("^{}")

        version = extract_version_from_tag(tag_name)
        if version is None:
            continue

        if tag_name in tags_by_name:
            if is_deref:
                # Dereferenced SHA is the actual commit — prefer it
                tags_by_name[tag_name] = TagInfo(tag_name=tag_name, version=version, sha=sha)
        else:
            tags_by_name[tag_name] = TagInfo(tag_name=tag_name, version=version, sha=sha)

    tags = list(tags_by_name.values())
    tags.sort(key=lambda t: parse_version_tuple(t.version))
    return tags


def list_version_tags(repo_path: str) -> list[TagInfo]:
    """List all tags that look like version numbers, sorted by version."""
    result = subprocess.run(
        ["git", "tag", "-l"],
        cwd=repo_path, capture_output=True, text=True, timeout=30,
    )
    tags = []
    for line in result.stdout.splitlines():
        tag = line.strip()
        if not tag:
            continue
        version = extract_version_from_tag(tag)
        if version is None:
            continue
        # Resolve tag to commit SHA
        sha_result = subprocess.run(
            ["git", "rev-list", "-n1", tag],
            cwd=repo_path, capture_output=True, text=True, timeout=10,
        )
        sha = sha_result.stdout.strip()
        if sha:
            tags.append(TagInfo(tag_name=tag, version=version, sha=sha))

    # Sort by parsed version tuple
    tags.sort(key=lambda t: parse_version_tuple(t.version))
    return tags


def extract_version_from_tag(tag: str) -> Optional[str]:
    """Extract a version string from a tag name.

    Handles: v1.447, 1.447, release-1.447, jenkins-1.447,
             project-name-1.2.3, ver1.0, etc.
    Also handles underscore-separated versions like STRUTS_6_8_0.
    """
    
    t = tag.strip()

    # 1) If the tag contains an obvious numeric run with separators (., _, -),
    #    extract the *last* such run and normalize underscores to dots.
    #
    # Examples:
    #   STRUTS_6_8_0     -> 6.8.0
    #   STRUTS_2_5_7     -> 2.5.7
    #   release-1.447    -> 1.447
    #   v1.2.3           -> 1.2.3
    #
    # We require at least "X.Y" (two components) to avoid matching just "..._8".
    m = re.search(r"(\d+(?:[._-]\d+)+)", t)
    if m:
        return normalize_version_str(m.group(1))

    # 2) Fallback: sometimes projects tag only a major version like "v2"
    m = re.match(r"^[vV]?(\d+)$", t)
    if m:
        return m.group(1)

    return None


def find_tag_for_version(tags: list[TagInfo], target_version: str) -> Optional[TagInfo]:
    """Find the tag that matches a specific version string."""
    target_version = normalize_version_str(target_version)
    target_tuple = parse_version_tuple(target_version)

    # Exact match first
    for t in tags:
        if parse_version_tuple(normalize_version_str(t.version)) == target_tuple:
            return t

    # Fuzzy: target_version might be "1.447" but tag version is "1.447.0"
    for t in tags:
        tv = parse_version_tuple(normalize_version_str(t.version))
        # Pad shorter tuple with zeros
        max_len = max(len(target_tuple), len(tv))
        padded_target = target_tuple + (0,) * (max_len - len(target_tuple))
        padded_tv = tv + (0,) * (max_len - len(tv))
        if padded_target == padded_tv:
            return t

    return None


def find_best_vulnerable_tag(
    tags: list[TagInfo],
    pkg: AffectedPackage,
    fix_tag: Optional[TagInfo],
) -> Optional[TagInfo]:
    """Find the best tag representing the last vulnerable version.

    Strategy:
      1. If fix_tag exists, walk backwards from fix_tag until a tag is IN the vulnerable range
      2. Otherwise, find the highest version within the vulnerable range
    """
    
    def in_any_range(ver: str) -> bool:
        if not pkg.ranges:
            return False
        vnorm = normalize_version_str(ver)
        for vr in pkg.ranges:
            if version_in_range(vnorm, vr):
                return True
        return False
    
    if fix_tag:
        fix_idx = None
        for i, t in enumerate(tags):
            if t.sha == fix_tag.sha and t.tag_name == fix_tag.tag_name:
                fix_idx = i
                break
        if fix_idx is not None and fix_idx > 0:
            # Walk back until we find something actually in the vulnerable range
            for j in range(fix_idx - 1, -1, -1):
                if in_any_range(tags[j].version):
                    return tags[j]

    # Fallback: find highest version in vulnerable range
    best = None
    for t in tags:
        if in_any_range(t.version):
            if best is None or parse_version_tuple(normalize_version_str(t.version)) > parse_version_tuple(normalize_version_str(best.version)):
                best = t

    return best


def resolve_parent_sha(repo_path: str, sha: str) -> Optional[str]:
    """Get the parent commit of a SHA (for getting the state just before a fix tag)."""
    result = subprocess.run(
        ["git", "rev-parse", f"{sha}~1"],
        cwd=repo_path, capture_output=True, text=True, timeout=10,
    )
    parent = result.stdout.strip()
    return parent if parent and result.returncode == 0 else None


# ---------------------------------------------------------------------------
# Main resolution
# ---------------------------------------------------------------------------

def resolve(
    ghsa_id: str,
    user_repo_url: Optional[str] = None,
    workdir: Optional[str] = None,
    repo_dir: Optional[str] = None,
    skip_fetch: bool = False,
    ecosystem_filter: Optional[str] = None,
) -> ResolvedResult:
    """Resolve a GHSA ID to clone URL + vulnerable/fix SHAs."""

    # 1. Fetch advisory
    print(f"[resolver] fetching advisory {ghsa_id}...", file=sys.stderr)
    advisory = fetch_advisory(ghsa_id)
    print(f"[resolver] {advisory.summary}", file=sys.stderr)

    if not advisory.packages:
        raise SystemExit(f"No affected packages found for {ghsa_id}")

    # 2. Select package (prefer maven for Java fuzzing, or use filter)
    pkg = None
    for p in advisory.packages:
        if ecosystem_filter and p.ecosystem.lower() != ecosystem_filter.lower():
            continue
        if p.patched_version:
            pkg = p
            if p.ecosystem.lower() == "maven":
                break  # prefer maven
    if pkg is None:
        pkg = advisory.packages[0]

    print(
        f"[resolver] package: {pkg.ecosystem}/{pkg.name} "
        f"range={pkg.vulnerable_range} patched={pkg.patched_version}",
        file=sys.stderr,
    )

    if not pkg.patched_version:
        raise SystemExit(
            f"No patched version found for {pkg.name}. "
            "Cannot resolve version-to-tag without a patched version."
        )

    # 3. Find repo URL
    clone_url = discover_repo_url(advisory, user_repo_url)
    if not clone_url:
        raise SystemExit(
            f"Cannot find repo URL for {pkg.name}. "
            "Set --repo-url manually or set CLONE_URL env var."
        )
    print(f"[resolver] repo: {clone_url}", file=sys.stderr)

    # 4. List version tags via ls-remote (NO CLONE — saves 100s of MB)
    tags = list_version_tags_remote(clone_url)
    if not tags:
        raise SystemExit(
            f"No version tags found via ls-remote for {clone_url}. "
            "The repository may use a non-standard tagging scheme."
        )
    print(f"[resolver] found {len(tags)} version tags", file=sys.stderr)

    # 5. Match patched version to tag
    fix_tag = find_tag_for_version(tags, pkg.patched_version)
    if not fix_tag:
        # Try with common prefixes
        for prefix in ["v", "V", ""]:
            candidate = f"{prefix}{pkg.patched_version}"
            fix_tag = find_tag_for_version(tags, candidate)
            if fix_tag:
                break

    if not fix_tag:
        raise SystemExit(
            f"Cannot find git tag for patched version {pkg.patched_version}. "
            f"Tags sample: {', '.join(t.tag_name for t in tags[-10:])}"
        )
    print(f"[resolver] fix tag: {fix_tag.tag_name} → {fix_tag.sha[:12]}", file=sys.stderr)

    # 6. Find vulnerable version tag
    vuln_tag = find_best_vulnerable_tag(tags, pkg, fix_tag)
    if vuln_tag:
        vuln_sha = vuln_tag.sha
        print(f"[resolver] vuln tag: {vuln_tag.tag_name} → {vuln_sha[:12]}", file=sys.stderr)
    else:
        # Fallback: need local clone to resolve parent commit
        print("[resolver] no vuln tag found, cloning to resolve fix parent...", file=sys.stderr)
        if workdir is None:
            workdir = os.environ.get("WORKDIR", "projects")
        os.makedirs(workdir, exist_ok=True)
        repo_path = git_clone_or_fetch(clone_url, workdir, skip_fetch=skip_fetch, repo_dir=repo_dir)
        parent = resolve_parent_sha(repo_path, fix_tag.sha)
        if not parent:
            raise SystemExit(
                f"Cannot find vulnerable version tag or parent of fix commit."
            )
        vuln_sha = parent
        vuln_tag = None
        print(f"[resolver] vuln sha (fix parent): {vuln_sha[:12]}", file=sys.stderr)

    return ResolvedResult(
        clone_url=clone_url,
        fix_sha=fix_tag.sha,
        vuln_sha=vuln_sha,
        patched_version=pkg.patched_version,
        vulnerable_range=pkg.vulnerable_range,
        fix_tag=fix_tag.tag_name,
        vuln_tag=vuln_tag.tag_name if vuln_tag else None,
        package_name=pkg.name,
        ecosystem=pkg.ecosystem,
        method="tag_match" if vuln_tag else "tag_parent",
        repo_path=None,  # no clone in the happy path
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Resolve GHSA advisory to clone URL + vulnerable/fix SHAs via version-to-tag matching."
    )
    parser.add_argument("ghsa_id", help="GHSA ID (e.g., GHSA-pchp-c5w8-47gc)")
    parser.add_argument("--repo-url", help="Override repository URL")
    parser.add_argument("--workdir", help="Clone directory (default: projects/)")
    parser.add_argument("--repo-dir", help="Override clone directory name under workdir (default: derived from clone URL)")
    parser.add_argument("--ecosystem", help="Filter by ecosystem (e.g., maven, npm)")
    parser.add_argument("--skip-fetch", action="store_true", help="Skip git fetch")
    parser.add_argument("--json", action="store_true", dest="json_output", help="JSON output")
    args = parser.parse_args()

    result = resolve(
        ghsa_id=args.ghsa_id,
        user_repo_url=args.repo_url,
        workdir=args.workdir,
        repo_dir=args.repo_dir,
        skip_fetch=args.skip_fetch,
        ecosystem_filter=args.ecosystem,
    )

    if args.json_output:
        print(json.dumps({
            "clone_url": result.clone_url,
            "fix_sha": result.fix_sha,
            "vuln_sha": result.vuln_sha,
            "patched_version": result.patched_version,
            "vulnerable_range": result.vulnerable_range,
            "fix_tag": result.fix_tag,
            "vuln_tag": result.vuln_tag,
            "package_name": result.package_name,
            "ecosystem": result.ecosystem,
            "method": result.method,
            "repo_path": result.repo_path,
        }, indent=2))
    else:
        print(f"Clone URL: {result.clone_url}")
        print(f"Fix commit: {result.fix_sha}")
        print(f"Parent (likely vulnerable): {result.vuln_sha}")
        print(f"Patched version: {result.patched_version}")
        print(f"Vulnerable range: {result.vulnerable_range}")
        print(f"Fix tag: {result.fix_tag}")
        print(f"Vuln tag: {result.vuln_tag or '(parent of fix)'}")
        print(f"Package: {result.ecosystem}/{result.package_name}")
        print(f"Method: {result.method}")
        if result.repo_path:
            print(f"Repo path: {result.repo_path}")


if __name__ == "__main__":
    main()