#!/usr/bin/env bash
# Builds test classes, copies dependencies (target/deps) and assembles the measurement agent jar.
set -euo pipefail
cd "$(dirname "$0")"
mvn -q -DskipTests package 2>&1 | tail -30
mkdir -p target/agent
printf 'Premain-Class: dosguide.agent.DoSMeasureAgent\nAgent-Class: dosguide.agent.DoSMeasureAgent\nCan-Retransform-Classes: true\nCan-Redefine-Classes: true\nClass-Path: deps/asm-9.8.jar\n' > target/agent/MANIFEST.MF
jar cfm target/dosguide-agent.jar target/agent/MANIFEST.MF -C target/test-classes dosguide/agent
echo "built target/dosguide-agent.jar"
