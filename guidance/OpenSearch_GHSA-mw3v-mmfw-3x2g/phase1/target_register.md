{
  "ordered_targets": [
    {
      "slot": 1,
      "id": "V2",
      "name": "query_string regexp term with unbounded repeat count {n} expands into n concatenated automaton copies (heap exhaustion)",
      "entrypoint": "QueryParserFuzzTest.fuzzQueryStringQueryBuilderToQuery(InputStream) → AbstractQueryBuilder.toQuery(QueryShardContext) → QueryStringQueryBuilder.doToQuery(QueryShardContext) → QueryStringQueryParser.parse(String) → QueryParserBase.parse(String) → QueryParser.TopLevelQuery(String) → QueryParser.Clause(String) → QueryParserBase.handleBareTokenQuery(String, Token, Token, boolean, boolean, boolean, boolean) → QueryStringQueryParser.getRegexpQuery(String, String) → QueryStringQueryParser.getRegexpQuerySingle(String, String) → QueryParserBase.getRegexpQuery(String, String) → QueryParserBase.newRegexpQuery(Term) → RegexpQuery.<init>(Term, int, int, AutomatonProvider, int, RewriteMethod) → RegExp.toAutomaton(AutomatonProvider, int) → RegExp.toAutomatonInternal(Map, AutomatonProvider, int) → Operations.repeat(Automaton, int) → Operations.concatenate(List)",
      "source_path": "server/src/main/java/org/opensearch/index/search/QueryStringQueryParser.java",
      "sink": "org.apache.lucene.util.automaton.Operations#repeat",
      "mechanism": "QueryStringQueryParser.getRegexpQuery bounds only the regex character length (index.max_regex_length=1000) and forwards the term to Lucene RegExp; parseRepeatExp accepts any int repeat count via Integer.parseInt, and Operations.repeat/concatenate materialize n copies of the sub-automaton (list of n refs + concatenated states/transitions) before minimize/determinize applies the 10000 work limit",
      "resource": "heap memory: automaton states/transitions and list entries allocated linearly in the repeat count n inside Operations.repeat/concatenate",
      "failure_mode": "out_of_memory",
      "scale": "CANNOT FAIL IN THIS EVALUATION (confirmed). Measured: no growth. Allocation (4.1 MB), peak heap (4-5 MB) and CPU (~50 ms) stay constant from repeat count 16,384 to 1,048,576 (64x), so Operations.repeat never builds the n copies. Likely cause, from the bytecode: RegExp.toAutomatonInternal (lucene-core 9.12.2) checks the sub-automaton's state count against the determinize work limit (getNumStates plus TooComplexToDeterminizeException) before repeating. In the default all-fields mode, query_string is lenient, so QueryStringQueryParser.getRegexpQuerySingle turns that exception into a lenient query. Nested repeats are checked the same way at each level, and regexes are limited to 1,000 characters (index.max_regex_length). No input up to the 131,072-byte limit makes heap use grow with the repeat count, so out_of_memory cannot be reached. input_bytes is set above the limit on purpose to record this.",
      "input_bytes": 131073,
      "cwe": "CWE-770",
      "checkpath_status": "PASS",
      "normalized_path": [
        {
          "kind": "hop",
          "method": "org.opensearch.fuzz.tests.QueryParserFuzzTest#fuzzQueryStringQueryBuilderToQuery(InputStream)",
          "location": "harness/src/test/java/org/opensearch/fuzz/tests/QueryParserFuzzTest.java:126"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "harness/src/test/java/org/opensearch/fuzz/tests/QueryParserFuzzTest.java:128"
        },
        {
          "kind": "hop",
          "method": "org.opensearch.index.query.AbstractQueryBuilder#toQuery(QueryShardContext)",
          "location": "server/src/main/java/org/opensearch/index/query/AbstractQueryBuilder.java:116"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "server/src/main/java/org/opensearch/index/query/AbstractQueryBuilder.java:117"
        },
        {
          "kind": "hop",
          "method": "org.opensearch.index.query.QueryStringQueryBuilder#doToQuery(QueryShardContext)",
          "location": "server/src/main/java/org/opensearch/index/query/QueryStringQueryBuilder.java:882"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "server/src/main/java/org/opensearch/index/query/QueryStringQueryBuilder.java:958"
        },
        {
          "kind": "hop",
          "method": "org.opensearch.index.search.QueryStringQueryParser#parse(String)",
          "location": "server/src/main/java/org/opensearch/index/search/QueryStringQueryParser.java:859"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "server/src/main/java/org/opensearch/index/search/QueryStringQueryParser.java:863"
        },
        {
          "kind": "hop",
          "method": "QueryParserBase.parse(String)",
          "location": "outside the source tree"
        },
        {
          "kind": "connection",
          "type": "UNCHECKED",
          "evidence": "hop 5 is outside the source tree, so calls made inside it cannot be inspected"
        },
        {
          "kind": "hop",
          "method": "QueryParser.TopLevelQuery(String)",
          "location": "outside the source tree"
        },
        {
          "kind": "connection",
          "type": "UNCHECKED",
          "evidence": "hop 6 is outside the source tree, so calls made inside it cannot be inspected"
        },
        {
          "kind": "hop",
          "method": "QueryParser.Clause(String)",
          "location": "outside the source tree"
        },
        {
          "kind": "connection",
          "type": "UNCHECKED",
          "evidence": "hop 7 is outside the source tree, so calls made inside it cannot be inspected"
        },
        {
          "kind": "hop",
          "method": "QueryParserBase.handleBareTokenQuery(String, Token, Token, boolean, boolean, boolean, boolean)",
          "location": "outside the source tree"
        },
        {
          "kind": "connection",
          "type": "UNCHECKED",
          "evidence": "hop 8 is outside the source tree, so calls made inside it cannot be inspected"
        },
        {
          "kind": "hop",
          "method": "org.opensearch.index.search.QueryStringQueryParser#getRegexpQuery(String,String)",
          "location": "server/src/main/java/org/opensearch/index/search/QueryStringQueryParser.java:752"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "server/src/main/java/org/opensearch/index/search/QueryStringQueryParser.java:772"
        },
        {
          "kind": "hop",
          "method": "org.opensearch.index.search.QueryStringQueryParser#getRegexpQuerySingle(String,String)",
          "location": "server/src/main/java/org/opensearch/index/search/QueryStringQueryParser.java:784"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "server/src/main/java/org/opensearch/index/search/QueryStringQueryParser.java:792"
        },
        {
          "kind": "hop",
          "method": "QueryParserBase.getRegexpQuery(String, String)",
          "location": "outside the source tree"
        },
        {
          "kind": "connection",
          "type": "UNCHECKED",
          "evidence": "hop 11 is outside the source tree, so calls made inside it cannot be inspected"
        },
        {
          "kind": "hop",
          "method": "QueryParserBase.newRegexpQuery(Term)",
          "location": "outside the source tree"
        },
        {
          "kind": "connection",
          "type": "UNCHECKED",
          "evidence": "hop 12 is outside the source tree, so calls made inside it cannot be inspected"
        },
        {
          "kind": "hop",
          "method": "RegexpQuery(Term, int, int, AutomatonProvider, int, RewriteMethod)",
          "location": "outside the source tree"
        },
        {
          "kind": "connection",
          "type": "UNCHECKED",
          "evidence": "hop 13 is outside the source tree, so calls made inside it cannot be inspected"
        },
        {
          "kind": "hop",
          "method": "RegExp.toAutomaton(AutomatonProvider, int)",
          "location": "outside the source tree"
        },
        {
          "kind": "connection",
          "type": "UNCHECKED",
          "evidence": "hop 14 is outside the source tree, so calls made inside it cannot be inspected"
        },
        {
          "kind": "hop",
          "method": "RegExp.toAutomatonInternal(Map, AutomatonProvider, int)",
          "location": "outside the source tree"
        },
        {
          "kind": "connection",
          "type": "UNCHECKED",
          "evidence": "hop 15 is outside the source tree, so calls made inside it cannot be inspected"
        },
        {
          "kind": "hop",
          "method": "Operations.repeat(Automaton, int)",
          "location": "outside the source tree"
        },
        {
          "kind": "connection",
          "type": "UNCHECKED",
          "evidence": "hop 16 is outside the source tree, so calls made inside it cannot be inspected"
        },
        {
          "kind": "hop",
          "method": "Operations.concatenate(List)",
          "location": "outside the source tree"
        }
      ],
      "harness_entry": "org.opensearch.fuzz.tests.QueryParserFuzzTest#fuzzQueryStringQueryBuilderToQuery",
      "scale_measurement": [
        {
          "value": 16384,
          "input_bytes": 10,
          "outcome": "completed",
          "cpu_ms": 49.020044,
          "allocated_bytes": 4261208,
          "peak_heap_bytes": 5242880
        },
        {
          "value": 32768,
          "input_bytes": 10,
          "outcome": "completed",
          "cpu_ms": 48.059059,
          "allocated_bytes": 4261208,
          "peak_heap_bytes": 5242880
        },
        {
          "value": 65536,
          "input_bytes": 10,
          "outcome": "completed",
          "cpu_ms": 46.922721,
          "allocated_bytes": 4261208,
          "peak_heap_bytes": 4194304
        },
        {
          "value": 131072,
          "input_bytes": 11,
          "outcome": "completed",
          "cpu_ms": 58.121146,
          "allocated_bytes": 4262136,
          "peak_heap_bytes": 5242880
        },
        {
          "value": 262144,
          "input_bytes": 11,
          "outcome": "completed",
          "cpu_ms": 52.750319,
          "allocated_bytes": 4262136,
          "peak_heap_bytes": 4194304
        },
        {
          "value": 524288,
          "input_bytes": 11,
          "outcome": "completed",
          "cpu_ms": 51.826299,
          "allocated_bytes": 4262136,
          "peak_heap_bytes": 5242880
        },
        {
          "value": 1048576,
          "input_bytes": 12,
          "outcome": "completed",
          "cpu_ms": 53.696881,
          "allocated_bytes": 4262344,
          "peak_heap_bytes": 5242880
        }
      ]
    },
    {
      "slot": 2,
      "id": "V1",
      "name": "query_string deeply nested parenthesized groups cause unbounded recursive descent in classic QueryParser (stack exhaustion)",
      "entrypoint": "QueryParserFuzzTest.fuzzQueryStringQueryBuilderToQuery(InputStream) → AbstractQueryBuilder.toQuery(QueryShardContext) → QueryStringQueryBuilder.doToQuery(QueryShardContext) → QueryStringQueryParser.parse(String) → QueryParserBase.parse(String) → QueryParser.TopLevelQuery(String) → QueryParser.Clause(String) → QueryParser.Clause(String)",
      "source_path": "server/src/main/java/org/opensearch/index/search/QueryStringQueryParser.java",
      "sink": "QueryStringQueryParser#parse",
      "mechanism": "recursive descent: each '(' makes Clause() call Query() which calls Clause() again; QueryStringQueryParser.parse/QueryStringQueryBuilder.doToQuery impose no nesting limit and only catch ParseException",
      "resource": "stack depth: two parser frames (Query + Clause) per nesting level, accumulated beneath QueryStringQueryParser.parse",
      "failure_mode": "stack_overflow",
      "scale": "Measured: 256 nesting levels fit in the 256 KB probe stack, 512 do not, so the classic QueryParser recursion costs about 0.5-1 KB of stack per '(' level (interpreted frames; the parser's per-level cost is higher than the 200-300 B estimate). CPU and heap stay flat (~50 ms, ~5 MB), so stack depth is the only growing resource. Extrapolated to the fixed 1 MB stack (4x the cap): about 1,000-2,000 levels overflow with interpreted frames. JIT-compiled frames are smaller and may need up to ~2-3x more levels. One '(' byte per level is already the densest encoding, so about 2 KB of input, with up to ~4-6 KB if the frames are compiled.",
      "input_bytes": 2048,
      "cwe": "CWE-674",
      "checkpath_status": "PASS",
      "normalized_path": [
        {
          "kind": "hop",
          "method": "org.opensearch.fuzz.tests.QueryParserFuzzTest#fuzzQueryStringQueryBuilderToQuery(InputStream)",
          "location": "harness/src/test/java/org/opensearch/fuzz/tests/QueryParserFuzzTest.java:126"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "harness/src/test/java/org/opensearch/fuzz/tests/QueryParserFuzzTest.java:128"
        },
        {
          "kind": "hop",
          "method": "org.opensearch.index.query.AbstractQueryBuilder#toQuery(QueryShardContext)",
          "location": "server/src/main/java/org/opensearch/index/query/AbstractQueryBuilder.java:116"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "server/src/main/java/org/opensearch/index/query/AbstractQueryBuilder.java:117"
        },
        {
          "kind": "hop",
          "method": "org.opensearch.index.query.QueryStringQueryBuilder#doToQuery(QueryShardContext)",
          "location": "server/src/main/java/org/opensearch/index/query/QueryStringQueryBuilder.java:882"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "server/src/main/java/org/opensearch/index/query/QueryStringQueryBuilder.java:958"
        },
        {
          "kind": "hop",
          "method": "org.opensearch.index.search.QueryStringQueryParser#parse(String)",
          "location": "server/src/main/java/org/opensearch/index/search/QueryStringQueryParser.java:859"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "server/src/main/java/org/opensearch/index/search/QueryStringQueryParser.java:863"
        },
        {
          "kind": "hop",
          "method": "QueryParserBase.parse(String)",
          "location": "outside the source tree"
        },
        {
          "kind": "connection",
          "type": "UNCHECKED",
          "evidence": "hop 5 is outside the source tree, so calls made inside it cannot be inspected"
        },
        {
          "kind": "hop",
          "method": "QueryParser.TopLevelQuery(String)",
          "location": "outside the source tree"
        },
        {
          "kind": "connection",
          "type": "UNCHECKED",
          "evidence": "hop 6 is outside the source tree, so calls made inside it cannot be inspected"
        },
        {
          "kind": "hop",
          "method": "QueryParser.Clause(String)",
          "location": "outside the source tree"
        },
        {
          "kind": "connection",
          "type": "UNCHECKED",
          "evidence": "hop 7 is outside the source tree, so calls made inside it cannot be inspected"
        },
        {
          "kind": "hop",
          "method": "QueryParser.Clause(String)",
          "location": "outside the source tree"
        }
      ],
      "harness_entry": "org.opensearch.fuzz.tests.QueryParserFuzzTest#fuzzQueryStringQueryBuilderToQuery",
      "scale_measurement": [
        {
          "value": 128,
          "input_bytes": 129,
          "outcome": "completed",
          "cpu_ms": 43.185313,
          "allocated_bytes": 4861080,
          "peak_heap_bytes": 5242880
        },
        {
          "value": 256,
          "input_bytes": 257,
          "outcome": "completed",
          "cpu_ms": 56.68462,
          "allocated_bytes": 5028584,
          "peak_heap_bytes": 6291456
        },
        {
          "value": 512,
          "input_bytes": 513,
          "outcome": "stack_cap"
        },
        {
          "value": 1024,
          "input_bytes": 1025,
          "outcome": "stack_cap"
        },
        {
          "value": 2048,
          "input_bytes": 2049,
          "outcome": "stack_cap"
        },
        {
          "value": 4096,
          "input_bytes": 4097,
          "outcome": "stack_cap"
        },
        {
          "value": 8192,
          "input_bytes": 8193,
          "outcome": "stack_cap"
        }
      ]
    }
  ]
}
