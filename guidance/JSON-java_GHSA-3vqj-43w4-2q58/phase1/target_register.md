{
  "ordered_targets": [
    {
      "slot": 1,
      "id": "V1",
      "name": "JSONML.parse() unbounded recursive descent on nested XML",
      "entrypoint": "XmlFuzzTest.fuzzJSONMLToJSONArray(InputStream) → JSONML.toJSONArray(String) → JSONML.parse(XMLTokener, boolean, JSONArray, boolean)",
      "source_path": "src/main/java/org/json/JSONML.java",
      "sink": "JSONML#parse",
      "mechanism": "Each nested XML element (e.g. <a>) triggers a recursive call to JSONML.parse() at line 184 without any depth limit, unlike XML.parse() which enforces maxNestingDepth (default 512). Unbounded nesting causes unbounded recursion.",
      "resource": "stack depth: one JSONML.parse() frame (~250 bytes) per XML nesting level",
      "failure_mode": "stack_overflow",
      "scale": "Measured: 512 nesting levels fit in 256 KB stack; 1024 levels exceed it. Estimated ~276 bytes per recursive JSONML.parse() frame. Extrapolating to 1 MB stack (-Xss1m): approximately 3500 nesting levels trigger StackOverflowError. Each level is '<a>' (3 bytes), so about 10500 bytes of input.",
      "input_bytes": 10500,
      "cwe": "CWE-674",
      "checkpath_status": "PASS",
      "normalized_path": [
        {
          "kind": "hop",
          "method": "fuzzing.harness.XmlFuzzTest#fuzzJSONMLToJSONArray(InputStream)",
          "location": "harness/src/test/java/fuzzing/harness/XmlFuzzTest.java:35"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "harness/src/test/java/fuzzing/harness/XmlFuzzTest.java:37"
        },
        {
          "kind": "hop",
          "method": "org.json.JSONML#toJSONArray(String)",
          "location": "src/main/java/org/json/JSONML.java:226"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "src/main/java/org/json/JSONML.java:227"
        },
        {
          "kind": "hop",
          "method": "org.json.JSONML#parse(XMLTokener,boolean,JSONArray,boolean)",
          "location": "src/main/java/org/json/JSONML.java:26"
        }
      ],
      "harness_entry": "fuzzing.harness.XmlFuzzTest#fuzzJSONMLToJSONArray",
      "scale_measurement": [
        {
          "value": 64,
          "input_bytes": 192,
          "outcome": "completed",
          "cpu_ms": 5.426584,
          "allocated_bytes": 453448,
          "peak_heap_bytes": 1048576
        },
        {
          "value": 128,
          "input_bytes": 384,
          "outcome": "completed",
          "cpu_ms": 5.627964,
          "allocated_bytes": 459112,
          "peak_heap_bytes": 1048576
        },
        {
          "value": 256,
          "input_bytes": 768,
          "outcome": "completed",
          "cpu_ms": 6.594138,
          "allocated_bytes": 509368,
          "peak_heap_bytes": 1048576
        },
        {
          "value": 512,
          "input_bytes": 1536,
          "outcome": "completed",
          "cpu_ms": 10.623816,
          "allocated_bytes": 583944,
          "peak_heap_bytes": 2097152
        },
        {
          "value": 1024,
          "input_bytes": 3072,
          "outcome": "stack_cap"
        },
        {
          "value": 2048,
          "input_bytes": 6144,
          "outcome": "stack_cap"
        }
      ]
    }
  ]
}
