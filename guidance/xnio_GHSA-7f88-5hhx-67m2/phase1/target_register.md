{
  "ordered_targets": [
    {
      "slot": 1,
      "id": "V1",
      "name": "Recursive notifyDone chain overflow in AbstractIoFuture (addNotifier + setResult path)",
      "entrypoint": "XnioFuzzTest.fuzzIoFutureAddNotifier(InputStream) → FutureResult.setResult(String) → AbstractIoFuture.setResult(Object) → NotifierState.notifyDone(AbstractIoFuture, Object)",
      "source_path": "api/src/main/java/org/xnio/AbstractIoFuture.java",
      "sink": "AbstractIoFuture.NotifierState#notifyDone",
      "mechanism": "Each addNotifier call wraps the current state in a new NotifierState, forming a singly-linked chain. When setResult is called, notifyDone walks the chain recursively via next.notifyDone(future, result), with recursion depth equal to the number of registered notifiers.",
      "resource": "stack depth: one notifyDone stack frame per NotifierState in the chain (~200 bytes per frame)",
      "failure_mode": "stack_overflow",
      "scale": "At the 256 KB probe stack cap, 1000 notifiers (1000 bytes) completed and 2000 (2000 bytes) overflowed, giving a per-frame cost of ~130-230 bytes. Extrapolating linearly to the 1 MB evaluation stack (4x the probe cap, minus ~30 KB base overhead): overflow threshold is approximately 4,400-8,800 notifiers; conservatively about 5,000 notifiers overflow the 1 MB stack. One input byte per notifier (all bytes >= 0x80), so about 5,000 bytes of input. This is the densest encoding: the fuzz test reads one byte per loop iteration.",
      "input_bytes": 5000,
      "cwe": "CWE-674",
      "checkpath_status": "PASS",
      "normalized_path": [
        {
          "kind": "hop",
          "method": "org.xnio.fuzz.XnioFuzzTest#fuzzIoFutureAddNotifier(InputStream)",
          "location": "harness/src/test/java/org/xnio/fuzz/XnioFuzzTest.java:31"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "harness/src/test/java/org/xnio/fuzz/XnioFuzzTest.java:43"
        },
        {
          "kind": "hop",
          "method": "org.xnio.FutureResult#setResult(T)",
          "location": "api/src/main/java/org/xnio/FutureResult.java:74"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "api/src/main/java/org/xnio/FutureResult.java:75"
        },
        {
          "kind": "hop",
          "method": "org.xnio.AbstractIoFuture#setResult(T)",
          "location": "api/src/main/java/org/xnio/AbstractIoFuture.java:605"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "api/src/main/java/org/xnio/AbstractIoFuture.java:619"
        },
        {
          "kind": "hop",
          "method": "org.xnio.AbstractIoFuture.State#notifyDone(AbstractIoFuture,T)",
          "location": "api/src/main/java/org/xnio/AbstractIoFuture.java:46"
        }
      ],
      "harness_entry": "org.xnio.fuzz.XnioFuzzTest#fuzzIoFutureAddNotifier",
      "scale_measurement": [
        {
          "value": 500,
          "input_bytes": 500,
          "outcome": "completed",
          "cpu_ms": 9.177135,
          "allocated_bytes": 534080,
          "peak_heap_bytes": 2097152
        },
        {
          "value": 1000,
          "input_bytes": 1000,
          "outcome": "completed",
          "cpu_ms": 9.849669,
          "allocated_bytes": 558072,
          "peak_heap_bytes": 2097152
        },
        {
          "value": 2000,
          "input_bytes": 2000,
          "outcome": "stack_cap"
        },
        {
          "value": 4000,
          "input_bytes": 4000,
          "outcome": "stack_cap"
        },
        {
          "value": 8000,
          "input_bytes": 8000,
          "outcome": "stack_cap"
        },
        {
          "value": 16000,
          "input_bytes": 16000,
          "outcome": "stack_cap"
        }
      ]
    },
    {
      "slot": 2,
      "id": "V2",
      "name": "Recursive cancel chain overflow in AbstractIoFuture (addCancelHandler + cancel path)",
      "entrypoint": "XnioFuzzTest.fuzzFutureResultAddCancelHandler(InputStream) → FutureResult.getIoFuture() → AbstractIoFuture.cancel() → CancellableState.cancel()",
      "source_path": "api/src/main/java/org/xnio/AbstractIoFuture.java",
      "sink": "AbstractIoFuture.CancellableState#cancel",
      "mechanism": "Each addCancelHandler call wraps the current state in a new CancellableState, forming a singly-linked chain. When cancel is called, CancellableState.cancel walks the chain recursively via next.cancel(), with recursion depth equal to the number of registered cancel handlers.",
      "resource": "stack depth: one cancel stack frame per CancellableState in the chain (~150-200 bytes per frame)",
      "failure_mode": "stack_overflow",
      "scale": "At the 256 KB probe stack cap, 1000 cancel handlers (1000 bytes) completed and 2000 (2000 bytes) overflowed, giving a per-frame cost of ~130-230 bytes (same as V1). Extrapolating linearly to the 1 MB evaluation stack (4x the probe cap, minus ~30 KB base overhead): overflow threshold is approximately 4,400-8,800 cancel handlers; conservatively about 5,000 cancel handlers overflow the 1 MB stack. One input byte per handler (all bytes >= 0x80), so about 5,000 bytes of input. This is the densest encoding: the fuzz test reads one byte per loop iteration.",
      "input_bytes": 5000,
      "cwe": "CWE-674",
      "checkpath_status": "PASS",
      "normalized_path": [
        {
          "kind": "hop",
          "method": "org.xnio.fuzz.XnioFuzzTest#fuzzFutureResultAddCancelHandler(InputStream)",
          "location": "harness/src/test/java/org/xnio/fuzz/XnioFuzzTest.java:52"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "harness/src/test/java/org/xnio/fuzz/XnioFuzzTest.java:62"
        },
        {
          "kind": "hop",
          "method": "org.xnio.FutureResult#getIoFuture()",
          "location": "api/src/main/java/org/xnio/FutureResult.java:54"
        },
        {
          "kind": "connection",
          "type": "SEQUENCE",
          "evidence": "JsseXnioSsl#connectSsl(XnioWorker,InetSocketAddress,InetSocketAddress,ChannelListener,ChannelListener,OptionMap) (api/src/main/java/org/xnio/ssl/JsseXnioSsl.java:123) calls FutureResult#getIoFuture() at line 143 and cancel at line 145",
          "site": "api/src/main/java/org/xnio/ssl/JsseXnioSsl.java:123"
        },
        {
          "kind": "hop",
          "method": "org.xnio.AbstractIoFuture#cancel()",
          "location": "api/src/main/java/org/xnio/AbstractIoFuture.java:654"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "api/src/main/java/org/xnio/AbstractIoFuture.java:660"
        },
        {
          "kind": "hop",
          "method": "org.xnio.AbstractIoFuture.State#cancel()",
          "location": "api/src/main/java/org/xnio/AbstractIoFuture.java:52"
        }
      ],
      "harness_entry": "org.xnio.fuzz.XnioFuzzTest#fuzzFutureResultAddCancelHandler",
      "scale_measurement": [
        {
          "value": 500,
          "input_bytes": 500,
          "outcome": "completed",
          "cpu_ms": 14.419724,
          "allocated_bytes": 510008,
          "peak_heap_bytes": 2097152
        },
        {
          "value": 1000,
          "input_bytes": 1000,
          "outcome": "completed",
          "cpu_ms": 11.047518,
          "allocated_bytes": 521904,
          "peak_heap_bytes": 1048576
        },
        {
          "value": 2000,
          "input_bytes": 2000,
          "outcome": "stack_cap"
        },
        {
          "value": 4000,
          "input_bytes": 4000,
          "outcome": "stack_cap"
        },
        {
          "value": 8000,
          "input_bytes": 8000,
          "outcome": "stack_cap"
        },
        {
          "value": 16000,
          "input_bytes": 16000,
          "outcome": "stack_cap"
        }
      ]
    }
  ]
}
