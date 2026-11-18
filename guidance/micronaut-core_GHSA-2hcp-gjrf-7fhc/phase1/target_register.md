{
  "ordered_targets": [
    {
      "slot": 1,
      "id": "V1",
      "name": "Unbounded ConcurrentHashMap cache growth in DefaultHtmlErrorResponseBodyProvider",
      "entrypoint": "SanitizerFuzzTest.fuzzHtmlErrorResponseBodyProviderBody(InputStream) → DefaultHtmlErrorResponseBodyProvider.body(ErrorContext, HttpResponse) → ConcurrentHashMap.computeIfAbsent(HtmlErrorPage, Function) → DefaultHtmlErrorResponseBodyProvider.html(HtmlErrorPage)",
      "source_path": "http-server/src/main/java/io/micronaut/http/server/exceptions/response/DefaultHtmlErrorResponseBodyProvider.java",
      "sink": "ConcurrentHashMap#computeIfAbsent",
      "mechanism": "Each unique error message line in the input creates a distinct HtmlErrorPage record key in the ConcurrentHashMap cache. On each cache miss, html() renders a full HTML page (~3.4KB including CSS) and stores it. With many unique lines, the cache grows unboundedly, exhausting heap memory.",
      "resource": "heap memory: ~3600 bytes per cache entry (3400B HTML string value + 200B HtmlErrorPage key/list/message + 32B ConcurrentHashMap.Node)",
      "failure_mode": "out_of_memory",
      "scale": "measured allocation grows linearly at ~42.5 KB per unique line (total allocation including temporaries); retained cache per entry is ~4 KB (HTML string with CSS + key/node overhead). With 1 GB heap and ~200 MB JVM/context baseline, ~800 MB available for cache entries; OOM at ~200K unique lines. At 4 bytes per line (3-byte unique content + 1-byte newline), about 800 KB of input",
      "input_bytes": 800000,
      "cwe": "CWE-770",
      "checkpath_status": "PASS",
      "normalized_path": [
        {
          "kind": "hop",
          "method": "com.fuzzing.harness.SanitizerFuzzTest#fuzzHtmlErrorResponseBodyProviderBody(InputStream)",
          "location": "harness/src/test/java/com/fuzzing/harness/SanitizerFuzzTest.java:53"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "harness/src/test/java/com/fuzzing/harness/SanitizerFuzzTest.java:67"
        },
        {
          "kind": "hop",
          "method": "io.micronaut.http.server.exceptions.response.DefaultHtmlErrorResponseBodyProvider#body(ErrorContext,HttpResponse)",
          "location": "http-server/src/main/java/io/micronaut/http/server/exceptions/response/DefaultHtmlErrorResponseBodyProvider.java:145"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "http-server/src/main/java/io/micronaut/http/server/exceptions/response/DefaultHtmlErrorResponseBodyProvider.java:147"
        },
        {
          "kind": "hop",
          "method": "ConcurrentHashMap.computeIfAbsent(HtmlErrorPage, Function)",
          "location": "outside the source tree"
        },
        {
          "kind": "connection",
          "type": "UNCHECKED",
          "evidence": "hop 3 is outside the source tree, so calls made inside it cannot be inspected"
        },
        {
          "kind": "hop",
          "method": "io.micronaut.http.server.exceptions.response.DefaultHtmlErrorResponseBodyProvider#html(HtmlErrorPage)",
          "location": "http-server/src/main/java/io/micronaut/http/server/exceptions/response/DefaultHtmlErrorResponseBodyProvider.java:150"
        }
      ],
      "harness_entry": "com.fuzzing.harness.SanitizerFuzzTest#fuzzHtmlErrorResponseBodyProviderBody",
      "scale_measurement": [
        {
          "value": 64,
          "input_bytes": 256,
          "outcome": "completed",
          "cpu_ms": 39.466531,
          "allocated_bytes": 4631712,
          "peak_heap_bytes": 6291456
        },
        {
          "value": 128,
          "input_bytes": 512,
          "outcome": "completed",
          "cpu_ms": 55.967929,
          "allocated_bytes": 7467792,
          "peak_heap_bytes": 0
        },
        {
          "value": 256,
          "input_bytes": 1024,
          "outcome": "completed",
          "cpu_ms": 69.364368,
          "allocated_bytes": 13139056,
          "peak_heap_bytes": 14680064
        },
        {
          "value": 512,
          "input_bytes": 2048,
          "outcome": "completed",
          "cpu_ms": 62.791593,
          "allocated_bytes": 24482624,
          "peak_heap_bytes": 10485760
        },
        {
          "value": 1024,
          "input_bytes": 4096,
          "outcome": "completed",
          "cpu_ms": 105.920312,
          "allocated_bytes": 47179728,
          "peak_heap_bytes": 25165824
        },
        {
          "value": 2048,
          "input_bytes": 8192,
          "outcome": "completed",
          "cpu_ms": 149.358245,
          "allocated_bytes": 92753272,
          "peak_heap_bytes": 28311552
        }
      ]
    }
  ]
}
