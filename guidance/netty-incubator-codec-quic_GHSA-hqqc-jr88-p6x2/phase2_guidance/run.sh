#!/usr/bin/env bash
# Usage: ./run.sh [seconds per target (default 60; 0 = infinite)] [targets...]
#   ./run.sh 60              -> V1 then PkgRisk1, 60 s each
#   ./run.sh 0 V1            -> V1 forever
# Replay:  java -Xmx1g -Xss1m -cp "$CP" dosguide.run.ReplayFeeder out/V1/meta/id_000010.json
# Origin:  java -Xmx1g -Xss1m -javaagent:target/dosguide-agent.jar -cp "$CP" dosguide.run.ClassOriginCheck
set -euo pipefail
cd "$(dirname "$0")"
SECS="${1:-60}"
shift || true
TARGETS=("$@")
if [ ${#TARGETS[@]} -eq 0 ]; then TARGETS=(V1 PkgRisk1); fi

mvn compile -q 2>&1 | tail -30
./build.sh 2>&1 | tail -30

CP="target/test-classes:target/classes:$(ls lib/*.jar target/deps/*.jar | tr '\n' ':')"
java -Xmx1g -Xss1m -javaagent:target/dosguide-agent.jar -cp "$CP" dosguide.run.ClassOriginCheck 2>&1 | tail -20
for T in "${TARGETS[@]}"; do
  java -Xmx1g -Xss1m -javaagent:target/dosguide-agent.jar -cp "$CP" dosguide.run.FuzzRunner "$T" "$SECS" out 2>&1 | tail -50
done
