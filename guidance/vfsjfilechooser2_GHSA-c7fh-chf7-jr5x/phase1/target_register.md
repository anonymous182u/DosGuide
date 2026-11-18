{
  "ordered_targets": [
    {
      "slot": 1,
      "id": "V1",
      "name": "ReDoS in VFSURIValidator.isValid() via p_ftp2 regex (.+:.+@)* catastrophic backtracking",
      "entrypoint": "VFSURIValidatorFuzzTest.fuzzVFSURIValidatorIsValid(InputStream) → VFSURIValidator.isValid(String) → Matcher.matches()",
      "source_path": "src/main/java/com/googlecode/vfsjfilechooser2/utils/VFSURIValidator.java",
      "sink": "java.util.regex.Matcher#matches",
      "mechanism": "The regex pattern p_ftp2 contains (.+:.+@)* where each greedy .+ matches any character including : and @. When the overall regex fails (no / for terminal (/.*) group), the NFA engine backtracks through exponentially many partitions of x:x@ sequences among group repetitions. Each additional a:a@ repetition roughly doubles the backtracking states.",
      "resource": "CPU time: regex backtracking steps grow as O(2^k) where k is the number of x:x@ repetitions in the input",
      "failure_mode": "timeout",
      "scale": "Measured growth with the alternating a:a@ pattern was near-linear (4.0ms at k=5 to 7.1ms at k=22), dominated by Pattern.compile() overhead (~4ms). The alternating shape produces only O(k²) backtracking because [^:]+? in the hostname group immediately hits a colon after 1 char. The effective attack shape is SEGREGATED: ftp:// + k×'a:' + k×'a@' + '!' (all colons before all @-signs). This creates k² valid (colon,@) pairs in (.+:.+@)*, and for each pair the [^:]+? reluctant quantifier traverses the entire colon-free remainder (average O(k) positions), yielding O(k³) total matching cost. Calibrating from the measured ~3µs per regex step, the 20s timeout is reached at k≈170–310 (input 700–1250 bytes). Densest encoding: 2 bytes per colon unit + 2 bytes per @-unit, so input = 4k+7 bytes.",
      "input_bytes": 2000,
      "cwe": "CWE-1333",
      "checkpath_status": "PASS",
      "normalized_path": [
        {
          "kind": "hop",
          "method": "com.googlecode.vfsjfilechooser2.fuzz.harness.VFSURIValidatorFuzzTest#fuzzVFSURIValidatorIsValid(InputStream)",
          "location": "harness/src/test/java/com/googlecode/vfsjfilechooser2/fuzz/harness/VFSURIValidatorFuzzTest.java:28"
        },
        {
          "kind": "connection",
          "type": "INDIRECT",
          "evidence": "1 omitted call(s)"
        },
        {
          "kind": "hop",
          "provenance": "checkpath (omitted call)",
          "method": "com.googlecode.vfsjfilechooser2.fuzz.harness.VFSURIValidatorFuzzTest#validate(InputStream)",
          "location": "harness/src/test/java/com/googlecode/vfsjfilechooser2/fuzz/harness/VFSURIValidatorFuzzTest.java:44"
        },
        {
          "kind": "hop",
          "method": "com.googlecode.vfsjfilechooser2.utils.VFSURIValidator#isValid(String)",
          "location": "src/main/java/com/googlecode/vfsjfilechooser2/utils/VFSURIValidator.java:122"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "src/main/java/com/googlecode/vfsjfilechooser2/utils/VFSURIValidator.java:154"
        },
        {
          "kind": "hop",
          "method": "Matcher.matches()",
          "location": "outside the source tree"
        }
      ],
      "harness_entry": "com.googlecode.vfsjfilechooser2.fuzz.harness.VFSURIValidatorFuzzTest#fuzzVFSURIValidatorIsValid",
      "scale_measurement": [
        {
          "value": 5,
          "input_bytes": 27,
          "outcome": "completed",
          "cpu_ms": 3.989083,
          "allocated_bytes": 310832,
          "peak_heap_bytes": 0
        },
        {
          "value": 10,
          "input_bytes": 47,
          "outcome": "completed",
          "cpu_ms": 4.561276,
          "allocated_bytes": 311008,
          "peak_heap_bytes": 0
        },
        {
          "value": 15,
          "input_bytes": 67,
          "outcome": "completed",
          "cpu_ms": 5.658737,
          "allocated_bytes": 311160,
          "peak_heap_bytes": 1048576
        },
        {
          "value": 18,
          "input_bytes": 79,
          "outcome": "completed",
          "cpu_ms": 6.51914,
          "allocated_bytes": 311936,
          "peak_heap_bytes": 1048576
        },
        {
          "value": 20,
          "input_bytes": 87,
          "outcome": "completed",
          "cpu_ms": 6.471605,
          "allocated_bytes": 311992,
          "peak_heap_bytes": 1048576
        },
        {
          "value": 22,
          "input_bytes": 95,
          "outcome": "completed",
          "cpu_ms": 7.112091,
          "allocated_bytes": 312048,
          "peak_heap_bytes": 1048576
        }
      ]
    }
  ]
}
