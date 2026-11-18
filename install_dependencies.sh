#!/usr/bin/env bash
# Set up a fresh Linux host (Amazon Linux 2023 or Ubuntu 22.04/24.04, x86_64) for the whole campaign:
# synthesis, library builds, fuzzing (Zest, PerfFuzz, DoSGuide, one-shot) and scoring. See README.md.
#
#   bash install_dependencies.sh            # everything (asks for sudo once, for OS packages)
#   bash install_dependencies.sh --check    # only report what is installed
#
# Installs, all versions pinned:
#   OS packages: git, gcc/g++, make, cmake, ninja, perl, go, jq, tmux, curl, unzip/zip, python3.12, Node.js/npm
#   JDKs: Corretto 8, 17 (default) and 21; Apache Maven, Gradle 7.6.4 (bc-java), sbt (msgpack, snappy-java)
#   Rust (rustup): for netty-incubator-codec-quic's native library (quiche)
#   Claude Code CLI (npm); log in afterwards with `claude` and your subscription (no API key needed)
#   Python virtualenv (.venv) with requirements.txt and a pinned claude-agent-sdk
#   JQF 2.1 (source build, for jqf-afl-fuzz) and PerfFuzz, under $TOOLS_DIR
#   the campaign launcher (tools/launch) and CheckPath (tools/checkpath)
# and writes env.sh (sourced from ~/.bashrc).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$SCRIPT_DIR"

TOOLS_DIR="${TOOLS_DIR:-$HOME/tools}"
VENV_DIR="${VENV_DIR:-$REPO_ROOT/.venv}"
ENV_FILE="${ENV_FILE:-$REPO_ROOT/env.sh}"

MAVEN_VERSION=3.9.9
GRADLE_VERSION=7.6.4
SBT_VERSION=1.10.7
CLAUDE_AGENT_SDK_VERSION=0.2.173
JQF_REPO_URL=https://github.com/rohanpadhye/JQF.git
JQF_COMMIT=245a453c457cc67422213c818cff29687de83864        # tag jqf-2.1
PERFFUZZ_REPO_URL=https://github.com/carolemieux/perffuzz.git
PERFFUZZ_COMMIT=f937f370555d0c54f2109e3b1aa5763f8defe337

log() { printf '[setup] %s\n' "$*"; }
fail() { printf '[setup] ERROR: %s\n' "$*" >&2; exit 1; }

run_as_root() {
  if [[ "${EUID}" -eq 0 ]]; then "$@"
  elif command -v sudo >/dev/null 2>&1; then sudo "$@"
  else fail "Need root or sudo to install system packages"; fi
}

# ---------------------------------------------------------------------------------------------------------------
# OS packages and JDKs
# ---------------------------------------------------------------------------------------------------------------
install_system_packages() {
  if command -v dnf >/dev/null 2>&1; then
    log "Installing OS packages with dnf"
    # strict=0: a package missing from this release is skipped (the check at the end reports it)
    run_as_root dnf install -y --allowerasing --setopt=strict=0 \
      git gcc gcc-c++ make cmake ninja-build perl golang jq tmux curl rsync unzip zip tar patch which util-linux \
      python3.12 python3.12-pip nodejs npm \
      java-1.8.0-amazon-corretto-devel java-17-amazon-corretto-devel java-21-amazon-corretto-devel
  elif command -v apt-get >/dev/null 2>&1; then
    log "Installing OS packages with apt"
    export DEBIAN_FRONTEND=noninteractive
    run_as_root apt-get update
    run_as_root apt-get install -y \
      git build-essential cmake ninja-build perl golang-go jq tmux curl rsync unzip zip tar patch util-linux \
      python3 python3-pip python3-venv nodejs npm gnupg ca-certificates
    # Corretto 8/17/21 from Amazon's apt repository (the same JDK builds as on Amazon Linux)
    if [[ ! -f /etc/apt/sources.list.d/corretto.list ]]; then
      curl -fsSL https://apt.corretto.aws/corretto.key | run_as_root gpg --dearmor -o /usr/share/keyrings/corretto-keyring.gpg
      echo "deb [signed-by=/usr/share/keyrings/corretto-keyring.gpg] https://apt.corretto.aws stable main" \
        | run_as_root tee /etc/apt/sources.list.d/corretto.list >/dev/null
      run_as_root apt-get update
    fi
    run_as_root apt-get install -y java-1.8.0-amazon-corretto-jdk java-17-amazon-corretto-jdk java-21-amazon-corretto-jdk
  else
    fail "Unsupported package manager (expected dnf or apt-get)"
  fi
}

jdk_home() {  # jdk_home 17 -> the Corretto 17 home
  local v="$1" d
  for d in /usr/lib/jvm/java-"$v"-amazon-corretto* /usr/lib/jvm/java-1."$v".0-amazon-corretto*; do
    [[ -x "$d/bin/javac" ]] && { printf '%s\n' "$d"; return 0; }
  done
  return 1
}

# ---------------------------------------------------------------------------------------------------------------
# Build tools (user level, under $TOOLS_DIR)
# ---------------------------------------------------------------------------------------------------------------
fetch_unpack() {  # fetch_unpack <url> <dest dir> : download an archive and unpack it into <dest dir>
  local url="$1" dest="$2" tmp
  tmp="$(mktemp -d)"
  curl -fsSL "$url" -o "$tmp/archive"
  mkdir -p "$dest"
  case "$url" in
    *.zip) unzip -q -o "$tmp/archive" -d "$dest" ;;
    *) tar -xzf "$tmp/archive" -C "$dest" ;;
  esac
  rm -rf "$tmp"
}

install_build_tools() {
  mkdir -p "$TOOLS_DIR"
  [[ -x "$TOOLS_DIR/apache-maven-$MAVEN_VERSION/bin/mvn" ]] || {
    log "Installing Apache Maven $MAVEN_VERSION"
    fetch_unpack "https://archive.apache.org/dist/maven/maven-3/$MAVEN_VERSION/binaries/apache-maven-$MAVEN_VERSION-bin.tar.gz" "$TOOLS_DIR"
  }
  [[ -x "$TOOLS_DIR/gradle-$GRADLE_VERSION/bin/gradle" ]] || {
    log "Installing Gradle $GRADLE_VERSION"
    fetch_unpack "https://services.gradle.org/distributions/gradle-$GRADLE_VERSION-bin.zip" "$TOOLS_DIR"
  }
  [[ -x "$TOOLS_DIR/sbt/bin/sbt" ]] || {
    log "Installing sbt $SBT_VERSION"
    fetch_unpack "https://github.com/sbt/sbt/releases/download/v$SBT_VERSION/sbt-$SBT_VERSION.tgz" "$TOOLS_DIR"
  }
  if [[ ! -x "$HOME/.cargo/bin/cargo" ]]; then
    log "Installing Rust (rustup, stable)"
    curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal
  fi
}

install_claude_code() {
  if [[ ! -x "$HOME/.npm-global/bin/claude" ]]; then
    log "Installing the Claude Code CLI"
    npm install -g --prefix "$HOME/.npm-global" @anthropic-ai/claude-code
  fi
}

setup_python_env() {
  local py
  py="$(command -v python3.12 || command -v python3)" || fail "Python 3.10+ is required"
  "$py" -c 'import sys; sys.exit(sys.version_info < (3, 10))' || fail "Python 3.10+ is required ($py)"
  [[ -x "$VENV_DIR/bin/python" ]] || { log "Creating the virtualenv $VENV_DIR"; "$py" -m venv "$VENV_DIR"; }
  "$VENV_DIR/bin/python" -m pip install -q --upgrade pip setuptools wheel
  "$VENV_DIR/bin/pip" install -q -r "$REPO_ROOT/requirements.txt" "claude-agent-sdk==$CLAUDE_AGENT_SDK_VERSION"
}

checkout_pinned() {  # checkout_pinned <url> <dir> <commit>
  local url="$1" dir="$2" commit="$3"
  [[ -d "$dir/.git" ]] || git clone --quiet "$url" "$dir"
  git -C "$dir" fetch --quiet origin
  git -C "$dir" checkout --quiet "$commit"
}

setup_jqf_and_perffuzz() {
  checkout_pinned "$PERFFUZZ_REPO_URL" "$TOOLS_DIR/perffuzz" "$PERFFUZZ_COMMIT"
  log "Building PerfFuzz"
  make -s -C "$TOOLS_DIR/perffuzz" >/dev/null
  checkout_pinned "$JQF_REPO_URL" "$TOOLS_DIR/jqf" "$JQF_COMMIT"
  log "Building JQF 2.1 (jqf-afl-fuzz for PerfFuzz)"
  # what JQF's setup.sh does (afl-proxy, then the Maven build), without running JQF's tests
  (cd "$TOOLS_DIR/jqf" && make -s >/dev/null && mvn -q -B -DskipTests package)
  # At the release commit, scripts/jqf-driver.sh still names the 2.1-SNAPSHOT jars and ASM 9.5, but the build makes
  # 2.1 jars and copies ASM 9.8 (JQF fixed its scripts after the release). With the wrong jar the JVM behind
  # jqf-afl-fuzz cannot load its javaagent and AFL aborts ("Timeout while initializing fork server"); with the wrong
  # ASM no class is instrumented and AFL sees no coverage. Point the driver at what the build made.
  local version asm
  version="$(sed -n 's:^    <version>\(.*\)</version>:\1:p' "$TOOLS_DIR/jqf/pom.xml" | head -1)"
  asm="$(cd "$TOOLS_DIR/jqf/instrument/target/dependency" && ls asm-[0-9]*.jar | head -1)"
  sed -i -e "s/^version=\".*\"/version=\"$version\"/" -e "s#dependency/asm-[0-9.]*\.jar#dependency/$asm#" \
    "$TOOLS_DIR/jqf/scripts/jqf-driver.sh"
}

build_repo_tools() {
  log "Building the campaign launcher and CheckPath"
  (cd "$REPO_ROOT/tools/launch" && mvn -q -B -DskipTests package)
  (cd "$REPO_ROOT/tools/checkpath" && mvn -q -B -DskipTests package)
}

write_env_file() {
  local j8 j17 j21
  j8="$(jdk_home 8)" || fail "Corretto 8 not found"
  j17="$(jdk_home 17)" || fail "Corretto 17 not found"
  j21="$(jdk_home 21)" || fail "Corretto 21 not found"
  log "Writing $ENV_FILE"
  cat > "$ENV_FILE" <<EOF
#!/usr/bin/env bash
# Written by install_dependencies.sh
export DOS_FUZZING_ROOT="$REPO_ROOT"
export JAVA8_HOME="$j8" JAVA17_HOME="$j17" JAVA21_HOME="$j21"
export JAVA_HOME="$j17"
export MAVEN_HOME="$TOOLS_DIR/apache-maven-$MAVEN_VERSION"
export GRADLE7_HOME="$TOOLS_DIR/gradle-$GRADLE_VERSION"
export SBT_HOME="$TOOLS_DIR/sbt"
export JQF_DIR="$TOOLS_DIR/jqf" JQF_HOME="$TOOLS_DIR/jqf"
export AFL_DIR="$TOOLS_DIR/perffuzz" PERFUZZ_HOME="$TOOLS_DIR/perffuzz"
export VIRTUAL_ENV="$VENV_DIR"
export PYTHON_BIN="$VENV_DIR/bin/python"
# Big builds (elasticsearch, OpenSearch) do not fit the small tmpfs /tmp of Amazon Linux 2023.
export TMPDIR="\$HOME/tmp"; mkdir -p "\$TMPDIR"
export PATH="\$JAVA_HOME/bin:\$MAVEN_HOME/bin:\$SBT_HOME/bin:\$HOME/.cargo/bin:\$HOME/.npm-global/bin:$VENV_DIR/bin:\$JQF_DIR/bin:\$PATH"
EOF
  chmod +x "$ENV_FILE"
  grep -Fqx "source \"$ENV_FILE\"" "$HOME/.bashrc" 2>/dev/null || printf 'source "%s"\n' "$ENV_FILE" >> "$HOME/.bashrc"
}

# ---------------------------------------------------------------------------------------------------------------
# Check
# ---------------------------------------------------------------------------------------------------------------
check() {
  local ok=1
  item() {  # item <label> <command...>: print the first line of the command's output, or MISSING
    local label="$1"; shift
    local out
    # the first non-empty line (gradle --version starts with an empty one); the command's own exit status decides
    if out="$("$@" 2>&1)" && out="$(printf '%s\n' "$out" | sed -n '/[^[:space:]]/{p;q;}')" && [[ -n "$out" ]]; then
      printf '  %-22s %s\n' "$label" "$out"
    else printf '  %-22s MISSING\n' "$label"; ok=0; fi
  }
  [[ -f "$ENV_FILE" ]] && source "$ENV_FILE"
  log "Installed:"
  item "Java 8" "${JAVA8_HOME:-/nonexistent}/bin/java" -version
  item "Java 17 (default)" java -version
  item "Java 21" "${JAVA21_HOME:-/nonexistent}/bin/java" -version
  item "Maven" mvn -v
  item "Gradle 7" bash -c "\"${GRADLE7_HOME:-/nonexistent}/bin/gradle\" --version | grep '^Gradle '"
  item "sbt" sbt --script-version
  item "cargo" cargo --version
  item "cmake" cmake --version
  item "go" go version
  item "node" node --version
  item "claude" claude --version
  item "python (venv)" "$VENV_DIR/bin/python" --version
  item "claude-agent-sdk" "$VENV_DIR/bin/python" -c "import importlib.metadata as m; print(m.version('claude-agent-sdk'))"
  item "PerfFuzz afl-fuzz" ls "${AFL_DIR:-/nonexistent}/afl-fuzz"
  item "jqf-afl-fuzz" ls "${JQF_DIR:-/nonexistent}/bin/jqf-afl-fuzz"
  item "jqf-afl driver jars" bash -c "d=\"${JQF_DIR:-/nonexistent}\"; v=\$(sed -n 's/^version=\"\(.*\)\"/\1/p' \"\$d/scripts/jqf-driver.sh\"); a=\$(grep -o 'dependency/asm-[0-9.]*\.jar' \"\$d/scripts/jqf-driver.sh\"); ls \"\$d/instrument/target/jqf-instrument-\$v.jar\" \"\$d/fuzz/target/jqf-fuzz-\$v.jar\" \"\$d/instrument/target/\$a\""
  item "campaign launcher" ls "$REPO_ROOT/tools/launch/target/campaign-launcher.jar"
  item "CheckPath" ls "$REPO_ROOT/tools/checkpath/target/checkpath.jar"
  item "flock" flock --version
  [[ $ok == 1 ]] && log "All present. Next: run \`claude\` once and log in with the subscription (README.md)." \
    || log "Some items are missing (see above)."
}

main() {
  if [[ "${1:-}" == "--check" ]]; then check; return; fi
  install_system_packages
  install_build_tools
  install_claude_code
  write_env_file
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  setup_python_env
  setup_jqf_and_perffuzz
  build_repo_tools
  check
}

main "$@"
