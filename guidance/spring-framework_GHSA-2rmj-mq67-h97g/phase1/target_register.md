{
  "ordered_targets": [
    {
      "slot": 1,
      "id": "V1",
      "name": "ETAG_HEADER_VALUE_PATTERN quadratic regex backtracking in getIfNoneMatch",
      "entrypoint": "HttpHeadersFuzzTest.fuzzHttpHeadersGetIfNoneMatch(InputStream) → HttpHeaders.getIfNoneMatch() → HttpHeaders.getETagValuesAsList(String) → java.util.regex.Matcher.find()",
      "source_path": "spring-web/src/main/java/org/springframework/http/HttpHeaders.java",
      "sink": "java.util.regex.Matcher#find",
      "mechanism": "The regex \\*|\\s*((W\\/)?('[^']*'))\\s*,? is applied with java.util.regex.Matcher.find() in a while loop. When the input is N bytes of whitespace (no quote or asterisk characters), the leading \\s* greedily consumes all remaining characters at each of N starting positions, then backtracks through O(N-i) lengths when the required '\"' delimiter is absent. Total regex VM steps: N(N+1)/2 = O(N²).",
      "resource": "CPU time: O(N²) regex backtracking steps where N is the whitespace input length in characters",
      "failure_mode": "timeout",
      "scale": "Measured quadratic growth: ~6.2 ns per N² (quadratic coefficient from fitting N=4096 at 138 ms and N=8192 at 452 ms, with ~34 ms constant overhead). Growth ratios approach 4× per doubling (3.26× from 4096→8192), confirming O(N²). Extrapolating time = 6.2e-6·N² + 34 ms to the 20,000 ms timeout: N ≈ 57,000 whitespace bytes. Encoding is 1 byte per whitespace character (ISO-8859-1), which is the densest possible.",
      "input_bytes": 57000,
      "cwe": "CWE-1333",
      "checkpath_status": "PASS",
      "normalized_path": [
        {
          "kind": "hop",
          "method": "com.fuzzing.httpheaders.HttpHeadersFuzzTest#fuzzHttpHeadersGetIfNoneMatch(InputStream)",
          "location": "harness/src/test/java/com/fuzzing/httpheaders/HttpHeadersFuzzTest.java:31"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "harness/src/test/java/com/fuzzing/httpheaders/HttpHeadersFuzzTest.java:36"
        },
        {
          "kind": "hop",
          "method": "org.springframework.http.HttpHeaders#getIfNoneMatch()",
          "location": "spring-web/src/main/java/org/springframework/http/HttpHeaders.java:1231"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "spring-web/src/main/java/org/springframework/http/HttpHeaders.java:1232"
        },
        {
          "kind": "hop",
          "method": "org.springframework.http.HttpHeaders#getETagValuesAsList(String)",
          "location": "spring-web/src/main/java/org/springframework/http/HttpHeaders.java:1576"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "spring-web/src/main/java/org/springframework/http/HttpHeaders.java:1583"
        },
        {
          "kind": "hop",
          "method": "java.util.regex.Matcher.find()",
          "location": "outside the source tree"
        }
      ],
      "harness_entry": "com.fuzzing.httpheaders.HttpHeadersFuzzTest#fuzzHttpHeadersGetIfNoneMatch",
      "scale_measurement": [
        {
          "value": 512,
          "input_bytes": 512,
          "outcome": "completed",
          "cpu_ms": 13.652351,
          "allocated_bytes": 485256,
          "peak_heap_bytes": 1048576
        },
        {
          "value": 1024,
          "input_bytes": 1024,
          "outcome": "completed",
          "cpu_ms": 24.193908,
          "allocated_bytes": 486808,
          "peak_heap_bytes": 1048576
        },
        {
          "value": 2048,
          "input_bytes": 2048,
          "outcome": "completed",
          "cpu_ms": 49.848959,
          "allocated_bytes": 489776,
          "peak_heap_bytes": 1048576
        },
        {
          "value": 4096,
          "input_bytes": 4096,
          "outcome": "completed",
          "cpu_ms": 138.337121,
          "allocated_bytes": 495920,
          "peak_heap_bytes": 1048576
        },
        {
          "value": 8192,
          "input_bytes": 8192,
          "outcome": "completed",
          "cpu_ms": 451.522441,
          "allocated_bytes": 503256,
          "peak_heap_bytes": 1048576
        },
        {
          "value": 16384,
          "input_bytes": 16384,
          "outcome": "time_cap"
        },
        {
          "value": 32768,
          "input_bytes": 32768,
          "outcome": "time_cap"
        }
      ]
    }
  ]
}
