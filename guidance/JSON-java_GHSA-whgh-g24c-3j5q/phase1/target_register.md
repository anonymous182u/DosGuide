{
  "ordered_targets": [
    {
      "slot": 1,
      "id": "V1",
      "name": "JSON recursive descent parsing — unbounded nesting depth causing StackOverflowError",
      "entrypoint": "JsonFuzzTest.fuzzJSONObjectAndJSONArrayConstructors(InputStream) → JSONArray.<init>(String) → JSONArray.<init>(JSONTokener) → JSONTokener.nextValue() → JSONArray.<init>(JSONTokener)",
      "source_path": "src/main/java/org/json/JSONTokener.java",
      "sink": "JSONTokener#nextValue",
      "mechanism": "Mutual recursion between JSONArray(JSONTokener)/JSONObject(JSONTokener) and JSONTokener.nextValue() with no depth limit; each nested '[' or '{' adds stack frames until overflow",
      "resource": "stack depth: two stack frames per nesting level (JSONArray constructor + nextValue), approximately 300-400 bytes per level",
      "failure_mode": "stack_overflow",
      "scale": "Measured: 512 nesting levels complete within the 256 KB stack probe cap; 1024 levels exceed it. Estimated stack cost: ~310 bytes per nesting level (two frames: JSONArray(JSONTokener) + JSONTokener.nextValue()). With ~30 KB JVM/harness overhead, extrapolating to the 1 MB evaluation stack: (1,048,576 − 30,000) / 310 ≈ 3,286 nesting levels cause StackOverflowError. Encoding: 1 byte per '[' → approximately 3,300 bytes of input.",
      "input_bytes": 3300,
      "cwe": "CWE-674",
      "checkpath_status": "PASS",
      "normalized_path": [
        {
          "kind": "hop",
          "method": "fuzzing.harness.JsonFuzzTest#fuzzJSONObjectAndJSONArrayConstructors(InputStream)",
          "location": "harness/src/test/java/fuzzing/harness/JsonFuzzTest.java:36"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "harness/src/test/java/fuzzing/harness/JsonFuzzTest.java:46"
        },
        {
          "kind": "hop",
          "method": "org.json.JSONArray#JSONArray(String)",
          "location": "src/main/java/org/json/JSONArray.java:161"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "src/main/java/org/json/JSONArray.java:162"
        },
        {
          "kind": "hop",
          "method": "org.json.JSONArray#JSONArray(JSONTokener)",
          "location": "src/main/java/org/json/JSONArray.java:106"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "src/main/java/org/json/JSONArray.java:125"
        },
        {
          "kind": "hop",
          "method": "org.json.JSONTokener#nextValue()",
          "location": "src/main/java/org/json/JSONTokener.java:421"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "src/main/java/org/json/JSONTokener.java:434"
        },
        {
          "kind": "hop",
          "method": "org.json.JSONArray#JSONArray(JSONTokener)",
          "location": "src/main/java/org/json/JSONArray.java:106"
        }
      ],
      "harness_entry": "fuzzing.harness.JsonFuzzTest#fuzzJSONObjectAndJSONArrayConstructors",
      "scale_measurement": [
        {
          "value": 64,
          "input_bytes": 64,
          "outcome": "completed",
          "cpu_ms": 4.333285,
          "allocated_bytes": 343928,
          "peak_heap_bytes": 1048576
        },
        {
          "value": 128,
          "input_bytes": 128,
          "outcome": "completed",
          "cpu_ms": 4.635788,
          "allocated_bytes": 349336,
          "peak_heap_bytes": 1048576
        },
        {
          "value": 256,
          "input_bytes": 256,
          "outcome": "completed",
          "cpu_ms": 7.283442,
          "allocated_bytes": 360184,
          "peak_heap_bytes": 0
        },
        {
          "value": 512,
          "input_bytes": 512,
          "outcome": "completed",
          "cpu_ms": 5.74908,
          "allocated_bytes": 381136,
          "peak_heap_bytes": 1048576
        },
        {
          "value": 1024,
          "input_bytes": 1024,
          "outcome": "stack_cap"
        },
        {
          "value": 2048,
          "input_bytes": 2048,
          "outcome": "stack_cap"
        }
      ]
    },
    {
      "slot": 2,
      "id": "V2",
      "name": "XML recursive parsing — unbounded element nesting depth causing StackOverflowError",
      "entrypoint": "JsonFuzzTest.fuzzXMLToJSONObject(InputStream) → XML.toJSONObject(String) → XML.toJSONObject(Reader, XMLParserConfiguration) → XML.parse(XMLTokener, JSONObject, String, XMLParserConfiguration) → XML.parse(XMLTokener, JSONObject, String, XMLParserConfiguration)",
      "source_path": "src/main/java/org/json/XML.java",
      "sink": "XML#parse",
      "mechanism": "Self-recursive XML.parse() call at line 426 when encountering nested '<' elements inside tag content, with no depth limit; each nested '<a>' adds one parse() stack frame",
      "resource": "stack depth: one parse() frame per nesting level, approximately 200-400 bytes per level",
      "failure_mode": "stack_overflow",
      "scale": "Measured: 512 nesting levels complete within the 256 KB stack probe cap; 853 levels exceed it. Estimated stack cost: ~341 bytes per nesting level (one XML.parse() frame with 8+ local variables). With ~30 KB JVM/harness overhead, extrapolating to the 1 MB evaluation stack: (1,048,576 − 30,000) / 341 ≈ 2,987 nesting levels cause StackOverflowError. Encoding: 3 bytes per '<a>' → approximately 8,960 bytes of input.",
      "input_bytes": 8960,
      "cwe": "CWE-674",
      "checkpath_status": "PASS",
      "normalized_path": [
        {
          "kind": "hop",
          "method": "fuzzing.harness.JsonFuzzTest#fuzzXMLToJSONObject(InputStream)",
          "location": "harness/src/test/java/fuzzing/harness/JsonFuzzTest.java:57"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "harness/src/test/java/fuzzing/harness/JsonFuzzTest.java:59"
        },
        {
          "kind": "hop",
          "method": "org.json.XML#toJSONObject(String)",
          "location": "src/main/java/org/json/XML.java:601"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "src/main/java/org/json/XML.java:602"
        },
        {
          "kind": "hop",
          "method": "org.json.XML#toJSONObject(Reader,XMLParserConfiguration)",
          "location": "src/main/java/org/json/XML.java:673"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "src/main/java/org/json/XML.java:679"
        },
        {
          "kind": "hop",
          "method": "org.json.XML#parse(XMLTokener,JSONObject,String,XMLParserConfiguration)",
          "location": "src/main/java/org/json/XML.java:256"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "src/main/java/org/json/XML.java:426"
        },
        {
          "kind": "hop",
          "method": "org.json.XML#parse(XMLTokener,JSONObject,String,XMLParserConfiguration)",
          "location": "src/main/java/org/json/XML.java:256"
        }
      ],
      "harness_entry": "fuzzing.harness.JsonFuzzTest#fuzzXMLToJSONObject",
      "scale_measurement": [
        {
          "value": 64,
          "input_bytes": 192,
          "outcome": "completed",
          "cpu_ms": 5.100378,
          "allocated_bytes": 360528,
          "peak_heap_bytes": 1048576
        },
        {
          "value": 128,
          "input_bytes": 384,
          "outcome": "completed",
          "cpu_ms": 5.365255,
          "allocated_bytes": 373024,
          "peak_heap_bytes": 1048576
        },
        {
          "value": 256,
          "input_bytes": 768,
          "outcome": "completed",
          "cpu_ms": 8.380776,
          "allocated_bytes": 398016,
          "peak_heap_bytes": 1048576
        },
        {
          "value": 512,
          "input_bytes": 1536,
          "outcome": "completed",
          "cpu_ms": 6.479708,
          "allocated_bytes": 448016,
          "peak_heap_bytes": 1048576
        },
        {
          "value": 853,
          "input_bytes": 2559,
          "outcome": "stack_cap"
        }
      ]
    }
  ]
}
