{
  "ordered_targets": [
    {
      "slot": 1,
      "id": "V1",
      "name": "Unbounded recursion in DTD content spec parsing",
      "entrypoint": "WoodstoxFuzzTest.fuzzXMLStreamReaderNextNonValidating(InputStream) → BasicStreamReader.next() → BasicStreamReader.nextFromProlog(boolean) → BasicStreamReader.skipToken() → ValidatingStreamReader.finishDTD(boolean) → FullDTDReader.readInternalSubset(WstxInputData, WstxInputSource, ReaderConfig, boolean, int) → FullDTDReader.parseDTD() → FullDTDReader.parseDirective() → FullDTDReader.handleDeclaration(char) → FullDTDReader.handleElementDecl() → FullDTDReader.readContentSpec(PrefixedName, boolean, boolean)",
      "source_path": "src/main/java/com/ctc/wstx/dtd/FullDTDReader.java",
      "sink": "FullDTDReader#readContentSpec",
      "mechanism": "Each opening parenthesis in a DTD ELEMENT content specification triggers one recursive call to readContentSpec (line 3090). There is no recursion depth limit. Deep nesting exhausts the call stack.",
      "resource": "stack depth: one readContentSpec frame (~200-400 bytes) per nesting level",
      "failure_mode": "stack_overflow",
      "scale": "Measured: stack overflows between 512 and 1024 nesting levels at 256 KB stack cap; CPU time and allocation are flat (not depth-dependent). Estimated per-frame cost ~277 bytes (with ~60 KB base stack for JVM/framework/reader chain). Extrapolating to 1 MB evaluation stack: ~3500 nesting levels cause StackOverflowError. Encoding: 2 bytes per nesting level (one open + one close paren) plus 54 bytes boilerplate. For 3500 levels: 7056 bytes.",
      "input_bytes": 7056,
      "cwe": "CWE-674",
      "checkpath_status": "PASS",
      "normalized_path": [
        {
          "kind": "hop",
          "method": "fuzzing.harness.WoodstoxFuzzTest#fuzzXMLStreamReaderNextNonValidating(InputStream)",
          "location": "harness/src/test/java/fuzzing/harness/WoodstoxFuzzTest.java:29"
        },
        {
          "kind": "connection",
          "type": "INDIRECT",
          "evidence": "1 omitted call(s); WoodstoxFuzzTest#readAll(XMLInputFactory,InputStream) calls next on a javax.xml.stream.XMLStreamReader (outside the source tree) at harness/src/test/java/fuzzing/harness/WoodstoxFuzzTest.java:66, which may dispatch to BasicStreamReader#next() (src/main/java/com/ctc/wstx/sr/BasicStreamReader.java:1105), overriding javax.xml.stream.XMLStreamReader#next(); BasicStreamReader's supertype org.codehaus.stax2.DTDInfo, org.codehaus.stax2.LocationInfo, org.codehaus.stax2.XMLStreamReader2 could not be resolved, so BasicStreamReader is not confirmed to be a javax.xml.stream.XMLStreamReader (unresolved ancestor)",
          "site": "harness/src/test/java/fuzzing/harness/WoodstoxFuzzTest.java:66"
        },
        {
          "kind": "hop",
          "provenance": "checkpath (omitted call)",
          "method": "fuzzing.harness.WoodstoxFuzzTest#readAll(XMLInputFactory,InputStream)",
          "location": "harness/src/test/java/fuzzing/harness/WoodstoxFuzzTest.java:63"
        },
        {
          "kind": "hop",
          "method": "com.ctc.wstx.sr.BasicStreamReader#next()",
          "location": "src/main/java/com/ctc/wstx/sr/BasicStreamReader.java:1105"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "src/main/java/com/ctc/wstx/sr/BasicStreamReader.java:1179"
        },
        {
          "kind": "hop",
          "method": "com.ctc.wstx.sr.BasicStreamReader#nextFromProlog(boolean)",
          "location": "src/main/java/com/ctc/wstx/sr/BasicStreamReader.java:2063"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "src/main/java/com/ctc/wstx/sr/BasicStreamReader.java:2071"
        },
        {
          "kind": "hop",
          "method": "com.ctc.wstx.sr.BasicStreamReader#skipToken()",
          "location": "src/main/java/com/ctc/wstx/sr/BasicStreamReader.java:3403"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "src/main/java/com/ctc/wstx/sr/BasicStreamReader.java:3445"
        },
        {
          "kind": "hop",
          "method": "com.ctc.wstx.sr.ValidatingStreamReader#finishDTD(boolean)",
          "location": "src/main/java/com/ctc/wstx/sr/ValidatingStreamReader.java:253"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "src/main/java/com/ctc/wstx/sr/ValidatingStreamReader.java:277"
        },
        {
          "kind": "hop",
          "method": "com.ctc.wstx.dtd.FullDTDReader#readInternalSubset(WstxInputData,WstxInputSource,ReaderConfig,boolean,int)",
          "location": "src/main/java/com/ctc/wstx/dtd/FullDTDReader.java:414"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "src/main/java/com/ctc/wstx/dtd/FullDTDReader.java:427"
        },
        {
          "kind": "hop",
          "method": "com.ctc.wstx.dtd.FullDTDReader#parseDTD()",
          "location": "src/main/java/com/ctc/wstx/dtd/FullDTDReader.java:552"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "src/main/java/com/ctc/wstx/dtd/FullDTDReader.java:581"
        },
        {
          "kind": "hop",
          "method": "com.ctc.wstx.dtd.FullDTDReader#parseDirective()",
          "location": "src/main/java/com/ctc/wstx/dtd/FullDTDReader.java:675"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "src/main/java/com/ctc/wstx/dtd/FullDTDReader.java:708"
        },
        {
          "kind": "hop",
          "method": "com.ctc.wstx.dtd.FullDTDReader#handleDeclaration(char)",
          "location": "src/main/java/com/ctc/wstx/dtd/FullDTDReader.java:2061"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "src/main/java/com/ctc/wstx/dtd/FullDTDReader.java:2100"
        },
        {
          "kind": "hop",
          "method": "com.ctc.wstx.dtd.FullDTDReader#handleElementDecl()",
          "location": "src/main/java/com/ctc/wstx/dtd/FullDTDReader.java:2246"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "src/main/java/com/ctc/wstx/dtd/FullDTDReader.java:2274"
        },
        {
          "kind": "hop",
          "method": "com.ctc.wstx.dtd.FullDTDReader#readContentSpec(PrefixedName,boolean,boolean)",
          "location": "src/main/java/com/ctc/wstx/dtd/FullDTDReader.java:3055"
        }
      ],
      "harness_entry": "fuzzing.harness.WoodstoxFuzzTest#fuzzXMLStreamReaderNextNonValidating",
      "scale_measurement": [
        {
          "value": 64,
          "input_bytes": 184,
          "outcome": "completed",
          "cpu_ms": 25.947249,
          "allocated_bytes": 2298568,
          "peak_heap_bytes": 2097152
        },
        {
          "value": 128,
          "input_bytes": 312,
          "outcome": "completed",
          "cpu_ms": 17.271616,
          "allocated_bytes": 2303688,
          "peak_heap_bytes": 3145728
        },
        {
          "value": 256,
          "input_bytes": 568,
          "outcome": "completed",
          "cpu_ms": 19.548318,
          "allocated_bytes": 2313928,
          "peak_heap_bytes": 2097152
        },
        {
          "value": 512,
          "input_bytes": 1080,
          "outcome": "completed",
          "cpu_ms": 18.239815,
          "allocated_bytes": 2334424,
          "peak_heap_bytes": 2097152
        },
        {
          "value": 1024,
          "input_bytes": 2104,
          "outcome": "stack_cap"
        }
      ]
    }
  ]
}
