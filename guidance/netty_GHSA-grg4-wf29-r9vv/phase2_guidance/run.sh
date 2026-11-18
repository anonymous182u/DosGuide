#!/usr/bin/env bash
# Build + run the V1 fuzzing campaign (Bzip2Decoder multi-block decompression bomb).
# Usage: ./run.sh [seconds] [target-or-method]   (seconds=0 -> infinite)
set -euo pipefail
cd "$(dirname "$0")"
SECS="${1:-60}"
TARGET="${2:-V1}"

# 1. compile (main + tests), copy deps into target/dependency
mvn compile -q 2>&1 | tail -30
mvn -q -DskipTests package 2>&1 | tail -30

# 2. build the measurement agent jar
jar cfm target/v1-agent.jar agent/MANIFEST.MF \
    -C target/test-classes fuzzing/agent \
    -C target/test-classes fuzzing/v1/V1Counters.class

CP="target/test-classes:target/classes:$(ls target/dependency/*.jar | tr '\n' ':')"
JVM="-Xmx1g -Xss1m"

# 3. class origin check (must point at lib/ / target/dependency netty jars, not target/classes)
java $JVM -cp "$CP" fuzzing.ClassOriginCheck 2>&1 | tail -10

# 4. fuzz
java $JVM -javaagent:target/v1-agent.jar -cp "$CP" fuzzing.FuzzRunner "$TARGET" "$SECS" 2>&1 | tail -50

# Reproduce one input:   java $JVM -cp "$CP" fuzzing.ReproV1 out/V1/corpus/id_000000.bin
# Replay from metadata:  java $JVM -cp "$CP" fuzzing.ReplayV1 out/V1/corpus/id_000000.json
