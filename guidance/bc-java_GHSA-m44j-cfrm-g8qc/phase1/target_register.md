{
  "ordered_targets": [
    {
      "slot": 1,
      "id": "V1",
      "name": "Scalar25519.reduceBasisVar unbounded loop via crafted Ed25519 verification input",
      "entrypoint": "Ed25519FuzzTest.fuzzEd25519Verify(InputStream) → Ed25519.verify(byte[], int, byte[], int, byte[], int, int) → Ed25519.implVerify(byte[], int, byte[], int, byte[], byte, byte[], int, int) → Scalar25519.reduceBasisVar(int[], int[], int[])",
      "source_path": "core/src/main/java/org/bouncycastle/math/ec/rfc8032/Scalar25519.java",
      "sink": "Scalar25519#reduceBasisVar",
      "mechanism": "The while loop 'while (len_Nv > TARGET_LENGTH)' in reduceBasisVar performs lattice basis reduction on a scalar nA derived from SHA-512(R||A||m). The 'last' index variable controls array processing bounds but is only updated on swaps. When addShifted_NP/subShifted_NP produce carries beyond index 'last', carries are silently dropped, corrupting the reduction invariants. For pathological scalar values, this causes the loop to oscillate without converging, running indefinitely.",
      "resource": "CPU time: number of iterations of the while loop in reduceBasisVar; for pathological scalars the iteration count is unbounded",
      "failure_mode": "timeout",
      "scale": "Measured base verification cost is ~14 ms constant for all input sizes (no growth with message_length; the parameter does not control the mechanism). The vulnerability is binary: the hash SHA-512(R||A||m) mod L either produces a scalar that triggers the carry-truncation bug in reduceBasisVar (loop oscillates indefinitely → timeout at 20,000 ms) or it does not (~14 ms, ~300 loop iterations). The loop cost per iteration is negligible (nanoseconds); the pathology is non-convergence, not per-iteration expense. The fuzzer must search across different sig/pk/msg byte combinations to find one whose hash yields a pathological scalar; any input ≥97 bytes that passes point-validity checks can potentially trigger it.",
      "input_bytes": 97,
      "cwe": "CWE-835",
      "checkpath_status": "PASS",
      "normalized_path": [
        {
          "kind": "hop",
          "method": "com.fuzzer.Ed25519FuzzTest#fuzzEd25519Verify(InputStream)",
          "location": "harness/src/test/java/com/fuzzer/harness/Ed25519FuzzTest.java:32"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "harness/src/test/java/com/fuzzer/harness/Ed25519FuzzTest.java:42"
        },
        {
          "kind": "hop",
          "method": "org.bouncycastle.math.ec.rfc8032.Ed25519#verify(byte[],int,byte[],int,byte[],int,int)",
          "location": "core/src/main/java/org/bouncycastle/math/ec/rfc8032/Ed25519.java:1551"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "core/src/main/java/org/bouncycastle/math/ec/rfc8032/Ed25519.java:1556"
        },
        {
          "kind": "hop",
          "method": "org.bouncycastle.math.ec.rfc8032.Ed25519#implVerify(byte[],int,byte[],int,byte[],byte,byte[],int,int)",
          "location": "core/src/main/java/org/bouncycastle/math/ec/rfc8032/Ed25519.java:512"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "core/src/main/java/org/bouncycastle/math/ec/rfc8032/Ed25519.java:569"
        },
        {
          "kind": "hop",
          "method": "org.bouncycastle.math.ec.rfc8032.Scalar25519#reduceBasisVar(int[],int[],int[])",
          "location": "core/src/main/java/org/bouncycastle/math/ec/rfc8032/Scalar25519.java:298"
        }
      ],
      "harness_entry": "com.fuzzer.Ed25519FuzzTest#fuzzEd25519Verify",
      "scale_measurement": [
        {
          "value": 1,
          "input_bytes": 97,
          "outcome": "completed",
          "cpu_ms": 13.867911,
          "allocated_bytes": 1267704,
          "peak_heap_bytes": 2097152
        },
        {
          "value": 2,
          "input_bytes": 98,
          "outcome": "completed",
          "cpu_ms": 14.014267,
          "allocated_bytes": 1267704,
          "peak_heap_bytes": 2097152
        },
        {
          "value": 4,
          "input_bytes": 100,
          "outcome": "completed",
          "cpu_ms": 14.084013,
          "allocated_bytes": 1267704,
          "peak_heap_bytes": 2097152
        },
        {
          "value": 8,
          "input_bytes": 104,
          "outcome": "completed",
          "cpu_ms": 13.84343,
          "allocated_bytes": 1261128,
          "peak_heap_bytes": 2097152
        },
        {
          "value": 16,
          "input_bytes": 112,
          "outcome": "completed",
          "cpu_ms": 18.408586,
          "allocated_bytes": 1261144,
          "peak_heap_bytes": 2097152
        },
        {
          "value": 32,
          "input_bytes": 128,
          "outcome": "completed",
          "cpu_ms": 14.057567,
          "allocated_bytes": 1267984,
          "peak_heap_bytes": 2097152
        }
      ]
    }
  ]
}
