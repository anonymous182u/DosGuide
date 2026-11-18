{
  "ordered_targets": [
    {
      "slot": 1,
      "id": "V1",
      "name": "Deep JSON array nesting causes StackOverflowError (MODE_PERMISSIVE)",
      "entrypoint": "JsonSmartFuzzTest.fuzzJSONParserParsePermissive(InputStream) → JSONParser.parse(String) → JSONParserString.parse(String, JsonReaderI) → JSONParserBase.parse(JsonReaderI) → JSONParserBase.readFirst(JsonReaderI) → JSONParserBase.readArray(JsonReaderI) → JSONParserBase.readMain(JsonReaderI, boolean[]) → JSONParserBase.readArray(JsonReaderI)",
      "source_path": "json-smart/src/main/java/net/minidev/json/parser/JSONParserBase.java",
      "sink": "JSONParserBase#readArray",
      "mechanism": "Mutual recursion between readArray and readMain with no depth limit; each nested '[' triggers readArray→readMain→readArray, consuming two stack frames per level",
      "resource": "stack depth: one readArray + one readMain frame per nesting level, approximately 300 bytes per level",
      "failure_mode": "stack_overflow",
      "scale": "Measured: 512 levels (1024 bytes) completes within the 256 KB stack probe cap; 1024 levels (2048 bytes) exceeds it. Per-level stack cost approximately 250 bytes (two frames: readArray + readMain). Extrapolating linearly to the evaluation 1 MB stack with approximately 50 KB base overhead: about 4000 nesting levels to cause StackOverflowError. Densest encoding is one byte per opening bracket (overflow occurs during descent before closing brackets are reached), so approximately 4000 bytes.",
      "input_bytes": 4000,
      "cwe": "CWE-674",
      "checkpath_status": "PASS",
      "normalized_path": [
        {
          "kind": "hop",
          "method": "edu.berkeley.cs.jqf.examples.json.JsonSmartFuzzTest#fuzzJSONParserParsePermissive(InputStream)",
          "location": "harness/src/test/java/edu/berkeley/cs/jqf/examples/json/JsonSmartFuzzTest.java:31"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "harness/src/test/java/edu/berkeley/cs/jqf/examples/json/JsonSmartFuzzTest.java:34"
        },
        {
          "kind": "hop",
          "method": "net.minidev.json.parser.JSONParser#parse(String)",
          "location": "json-smart/src/main/java/net/minidev/json/parser/JSONParser.java:269"
        },
        {
          "kind": "connection",
          "type": "INDIRECT",
          "evidence": "1 omitted call(s)"
        },
        {
          "kind": "hop",
          "provenance": "checkpath (omitted call)",
          "method": "net.minidev.json.parser.JSONParserString#parse(String)",
          "location": "json-smart/src/main/java/net/minidev/json/parser/JSONParserString.java:38"
        },
        {
          "kind": "hop",
          "method": "net.minidev.json.parser.JSONParserString#parse(String,JsonReaderI)",
          "location": "json-smart/src/main/java/net/minidev/json/parser/JSONParserString.java:54"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "json-smart/src/main/java/net/minidev/json/parser/JSONParserString.java:58"
        },
        {
          "kind": "hop",
          "method": "net.minidev.json.parser.JSONParserBase#parse(JsonReaderI)",
          "location": "json-smart/src/main/java/net/minidev/json/parser/JSONParserBase.java:201"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "json-smart/src/main/java/net/minidev/json/parser/JSONParserBase.java:206"
        },
        {
          "kind": "hop",
          "method": "net.minidev.json.parser.JSONParserBase#readFirst(JsonReaderI)",
          "location": "json-smart/src/main/java/net/minidev/json/parser/JSONParserBase.java:332"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "json-smart/src/main/java/net/minidev/json/parser/JSONParserBase.java:352"
        },
        {
          "kind": "hop",
          "method": "net.minidev.json.parser.JSONParserBase#readArray(JsonReaderI)",
          "location": "json-smart/src/main/java/net/minidev/json/parser/JSONParserBase.java:286"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "json-smart/src/main/java/net/minidev/json/parser/JSONParserBase.java:321"
        },
        {
          "kind": "hop",
          "method": "net.minidev.json.parser.JSONParserBase#readMain(JsonReaderI,boolean[])",
          "location": "json-smart/src/main/java/net/minidev/json/parser/JSONParserBase.java:434"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "json-smart/src/main/java/net/minidev/json/parser/JSONParserBase.java:454"
        },
        {
          "kind": "hop",
          "method": "net.minidev.json.parser.JSONParserBase#readArray(JsonReaderI)",
          "location": "json-smart/src/main/java/net/minidev/json/parser/JSONParserBase.java:286"
        }
      ],
      "harness_entry": "edu.berkeley.cs.jqf.examples.json.JsonSmartFuzzTest#fuzzJSONParserParsePermissive",
      "scale_measurement": [
        {
          "value": 64,
          "input_bytes": 128,
          "outcome": "completed",
          "cpu_ms": 11.334024,
          "allocated_bytes": 987976,
          "peak_heap_bytes": 1048576
        },
        {
          "value": 128,
          "input_bytes": 256,
          "outcome": "completed",
          "cpu_ms": 8.020036,
          "allocated_bytes": 993384,
          "peak_heap_bytes": 1048576
        },
        {
          "value": 256,
          "input_bytes": 512,
          "outcome": "completed",
          "cpu_ms": 11.78188,
          "allocated_bytes": 1004136,
          "peak_heap_bytes": 2097152
        },
        {
          "value": 512,
          "input_bytes": 1024,
          "outcome": "completed",
          "cpu_ms": 9.130267,
          "allocated_bytes": 1094856,
          "peak_heap_bytes": 1048576
        },
        {
          "value": 1024,
          "input_bytes": 2048,
          "outcome": "stack_cap"
        }
      ]
    },
    {
      "slot": 2,
      "id": "V2",
      "name": "Deep JSON array nesting causes StackOverflowError (MODE_RFC4627)",
      "entrypoint": "JsonSmartFuzzTest.fuzzJSONParserParseRFC4627(InputStream) → JSONParser.parse(String) → JSONParserString.parse(String, JsonReaderI) → JSONParserBase.parse(JsonReaderI) → JSONParserBase.readFirst(JsonReaderI) → JSONParserBase.readArray(JsonReaderI) → JSONParserBase.readMain(JsonReaderI, boolean[]) → JSONParserBase.readArray(JsonReaderI)",
      "source_path": "json-smart/src/main/java/net/minidev/json/parser/JSONParserBase.java",
      "sink": "JSONParserBase#readArray",
      "mechanism": "Mutual recursion between readArray and readMain with no depth limit; identical code path as V1 since MODE_RFC4627 flags do not guard nesting depth",
      "resource": "stack depth: one readArray + one readMain frame per nesting level, approximately 300 bytes per level",
      "failure_mode": "stack_overflow",
      "scale": "Measured: 512 levels (1024 bytes) completes within the 256 KB stack probe cap; 1024 levels (2048 bytes) exceeds it. Per-level stack cost approximately 250 bytes (two frames: readArray + readMain). Extrapolating linearly to the evaluation 1 MB stack with approximately 50 KB base overhead: about 4000 nesting levels to cause StackOverflowError. Densest encoding is one byte per opening bracket (overflow occurs during descent before closing brackets are reached), so approximately 4000 bytes.",
      "input_bytes": 4000,
      "cwe": "CWE-674",
      "checkpath_status": "PASS",
      "normalized_path": [
        {
          "kind": "hop",
          "method": "edu.berkeley.cs.jqf.examples.json.JsonSmartFuzzTest#fuzzJSONParserParseRFC4627(InputStream)",
          "location": "harness/src/test/java/edu/berkeley/cs/jqf/examples/json/JsonSmartFuzzTest.java:42"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "harness/src/test/java/edu/berkeley/cs/jqf/examples/json/JsonSmartFuzzTest.java:45"
        },
        {
          "kind": "hop",
          "method": "net.minidev.json.parser.JSONParser#parse(String)",
          "location": "json-smart/src/main/java/net/minidev/json/parser/JSONParser.java:269"
        },
        {
          "kind": "connection",
          "type": "INDIRECT",
          "evidence": "1 omitted call(s)"
        },
        {
          "kind": "hop",
          "provenance": "checkpath (omitted call)",
          "method": "net.minidev.json.parser.JSONParserString#parse(String)",
          "location": "json-smart/src/main/java/net/minidev/json/parser/JSONParserString.java:38"
        },
        {
          "kind": "hop",
          "method": "net.minidev.json.parser.JSONParserString#parse(String,JsonReaderI)",
          "location": "json-smart/src/main/java/net/minidev/json/parser/JSONParserString.java:54"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "json-smart/src/main/java/net/minidev/json/parser/JSONParserString.java:58"
        },
        {
          "kind": "hop",
          "method": "net.minidev.json.parser.JSONParserBase#parse(JsonReaderI)",
          "location": "json-smart/src/main/java/net/minidev/json/parser/JSONParserBase.java:201"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "json-smart/src/main/java/net/minidev/json/parser/JSONParserBase.java:206"
        },
        {
          "kind": "hop",
          "method": "net.minidev.json.parser.JSONParserBase#readFirst(JsonReaderI)",
          "location": "json-smart/src/main/java/net/minidev/json/parser/JSONParserBase.java:332"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "json-smart/src/main/java/net/minidev/json/parser/JSONParserBase.java:352"
        },
        {
          "kind": "hop",
          "method": "net.minidev.json.parser.JSONParserBase#readArray(JsonReaderI)",
          "location": "json-smart/src/main/java/net/minidev/json/parser/JSONParserBase.java:286"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "json-smart/src/main/java/net/minidev/json/parser/JSONParserBase.java:321"
        },
        {
          "kind": "hop",
          "method": "net.minidev.json.parser.JSONParserBase#readMain(JsonReaderI,boolean[])",
          "location": "json-smart/src/main/java/net/minidev/json/parser/JSONParserBase.java:434"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "json-smart/src/main/java/net/minidev/json/parser/JSONParserBase.java:454"
        },
        {
          "kind": "hop",
          "method": "net.minidev.json.parser.JSONParserBase#readArray(JsonReaderI)",
          "location": "json-smart/src/main/java/net/minidev/json/parser/JSONParserBase.java:286"
        }
      ],
      "harness_entry": "edu.berkeley.cs.jqf.examples.json.JsonSmartFuzzTest#fuzzJSONParserParseRFC4627",
      "scale_measurement": [
        {
          "value": 64,
          "input_bytes": 128,
          "outcome": "completed",
          "cpu_ms": 12.649395,
          "allocated_bytes": 987952,
          "peak_heap_bytes": 2097152
        },
        {
          "value": 128,
          "input_bytes": 256,
          "outcome": "completed",
          "cpu_ms": 13.352414,
          "allocated_bytes": 1062560,
          "peak_heap_bytes": 1048576
        },
        {
          "value": 256,
          "input_bytes": 512,
          "outcome": "completed",
          "cpu_ms": 11.790504,
          "allocated_bytes": 1004112,
          "peak_heap_bytes": 2097152
        },
        {
          "value": 512,
          "input_bytes": 1024,
          "outcome": "completed",
          "cpu_ms": 12.799166,
          "allocated_bytes": 1094832,
          "peak_heap_bytes": 2097152
        },
        {
          "value": 1024,
          "input_bytes": 2048,
          "outcome": "stack_cap"
        }
      ]
    }
  ]
}
