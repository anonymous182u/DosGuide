{
  "ordered_targets": [
    {
      "slot": 1,
      "id": "V1",
      "name": "Unchecked allocation in looseUnmarshalByteArray via PartialCommand",
      "entrypoint": "OpenWireFuzzTest.fuzzOpenWireFormatUnmarshal(InputStream) → OpenWireFormat.unmarshal(ByteSequence) → OpenWireFormat.doUnmarshal(DataInput) → PartialCommandMarshaller.looseUnmarshal(OpenWireFormat, Object, DataInput) → BaseDataStreamMarshaller.looseUnmarshalByteArray(DataInput)",
      "source_path": "activemq-client/src/main/java/org/apache/activemq/openwire/v12/BaseDataStreamMarshaller.java",
      "sink": "BaseDataStreamMarshaller#looseUnmarshalByteArray",
      "mechanism": "Attacker-controlled 4-byte int size field used as allocation size for new byte[size] without any bounds check; the custom DataByteArrayInputStream.readFully() silently succeeds on short reads, so the allocation always persists",
      "resource": "heap memory: one allocation of up to 2 GB from a single 4-byte int field in the input",
      "failure_mode": "out_of_memory",
      "scale": "Measured: allocated bytes = allocation_size + 1.5 MB (linear, 1:1). A 256 MB allocation exceeded the 256 MB probe heap cap, confirming the mechanism. Extrapolating to -Xmx1g: JVM baseline uses ~50-100 MB, leaving ~925-975 MB for the array. An int value of 0x3C000000 (960 MB) in the 4-byte size field causes new byte[1006632960] which exceeds available heap. The entire input is 14 bytes: 4-byte frame prefix + 1-byte type(60) + 4-byte commandId + 1-byte boolean(true) + 4-byte allocation size.",
      "input_bytes": 14,
      "cwe": "CWE-770",
      "checkpath_status": "PASS",
      "normalized_path": [
        {
          "kind": "hop",
          "method": "com.fuzz.activemq.OpenWireFuzzTest#fuzzOpenWireFormatUnmarshal(InputStream)",
          "location": "harness/src/test/java/com/fuzz/activemq/OpenWireFuzzTest.java:63"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "harness/src/test/java/com/fuzz/activemq/OpenWireFuzzTest.java:66"
        },
        {
          "kind": "hop",
          "method": "org.apache.activemq.openwire.OpenWireFormat#unmarshal(ByteSequence)",
          "location": "activemq-client/src/main/java/org/apache/activemq/openwire/OpenWireFormat.java:192"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "activemq-client/src/main/java/org/apache/activemq/openwire/OpenWireFormat.java:209"
        },
        {
          "kind": "hop",
          "method": "org.apache.activemq.openwire.OpenWireFormat#doUnmarshal(DataInput)",
          "location": "activemq-client/src/main/java/org/apache/activemq/openwire/OpenWireFormat.java:366"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "activemq-client/src/main/java/org/apache/activemq/openwire/OpenWireFormat.java:379"
        },
        {
          "kind": "hop",
          "method": "org.apache.activemq.openwire.v12.PartialCommandMarshaller#looseUnmarshal(OpenWireFormat,Object,DataInput)",
          "location": "activemq-client/src/main/java/org/apache/activemq/openwire/v12/PartialCommandMarshaller.java:111"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "activemq-client/src/main/java/org/apache/activemq/openwire/v12/PartialCommandMarshaller.java:116"
        },
        {
          "kind": "hop",
          "method": "org.apache.activemq.openwire.v1.BaseDataStreamMarshaller#looseUnmarshalByteArray(DataInput)",
          "location": "activemq-client/src/main/java/org/apache/activemq/openwire/v1/BaseDataStreamMarshaller.java:621"
        }
      ],
      "harness_entry": "com.fuzz.activemq.OpenWireFuzzTest#fuzzOpenWireFormatUnmarshal",
      "scale_measurement": [
        {
          "value": 1048576,
          "input_bytes": 14,
          "outcome": "completed",
          "cpu_ms": 11.137949,
          "allocated_bytes": 2640568,
          "peak_heap_bytes": 4194304
        },
        {
          "value": 4194304,
          "input_bytes": 14,
          "outcome": "completed",
          "cpu_ms": 12.627524,
          "allocated_bytes": 5786296,
          "peak_heap_bytes": 7340032
        },
        {
          "value": 16777216,
          "input_bytes": 14,
          "outcome": "completed",
          "cpu_ms": 13.698608,
          "allocated_bytes": 18369208,
          "peak_heap_bytes": 19922944
        },
        {
          "value": 67108864,
          "input_bytes": 14,
          "outcome": "completed",
          "cpu_ms": 33.488269,
          "allocated_bytes": 68700856,
          "peak_heap_bytes": 15524464
        },
        {
          "value": 134217728,
          "input_bytes": 14,
          "outcome": "completed",
          "cpu_ms": 31.530563,
          "allocated_bytes": 135809720,
          "peak_heap_bytes": 79253176
        },
        {
          "value": 268435456,
          "input_bytes": 14,
          "outcome": "heap_cap"
        }
      ]
    },
    {
      "slot": 2,
      "id": "V2",
      "name": "Unbounded recursive Throwable cause chain in looseUnmarsalThrowable",
      "entrypoint": "OpenWireFuzzTest.fuzzOpenWireFormatUnmarshalStackTraceEnabled(InputStream) → OpenWireFormat.unmarshal(ByteSequence) → OpenWireFormat.doUnmarshal(DataInput) → ExceptionResponseMarshaller.looseUnmarshal(OpenWireFormat, Object, DataInput) → BaseDataStreamMarshaller.looseUnmarsalThrowable(OpenWireFormat, DataInput)",
      "source_path": "activemq-client/src/main/java/org/apache/activemq/openwire/v12/BaseDataStreamMarshaller.java",
      "sink": "BaseDataStreamMarshaller#looseUnmarsalThrowable",
      "mechanism": "Recursive self-call via o.initCause(looseUnmarsalThrowable(...)) with no depth limit when stackTraceEnabled is true; each boolean-true in the input stream triggers another recursion level at a cost of 5 bytes per level; additionally each level invokes fillInStackTrace() at depth N costing O(N) time, so total CPU is O(N²)",
      "resource": "stack depth: one looseUnmarsalThrowable frame (~200-400 bytes) per recursion level; also CPU time quadratic in depth due to fillInStackTrace()",
      "failure_mode": "stack_overflow",
      "scale": "Measured: CPU grows linearly at ~0.025 ms per recursion level (extrapolated ~62 ms at max 2045 levels, well under 20000 ms timeout). Stack: 500 levels completed within the 256 KB probe cap; with base stack >= 10 KB, per-frame cost <= 492 bytes, but overflow at 2045 levels requires per-frame > 509 bytes — mathematically impossible given the measurement. Allocated grows ~O(N^1.5): ~56 MB at 2045 levels, under 1 GB. Failure (stack_overflow or timeout) is not achievable within the 10240-byte input limit and evaluation JVM options: the 5 bytes/level encoding yields at most 2045 levels, which is insufficient to overflow the 1 MB stack or exhaust the 20-second timeout.",
      "input_bytes": 10240,
      "cwe": "CWE-674",
      "checkpath_status": "PASS",
      "normalized_path": [
        {
          "kind": "hop",
          "method": "com.fuzz.activemq.OpenWireFuzzTest#fuzzOpenWireFormatUnmarshalStackTraceEnabled(InputStream)",
          "location": "harness/src/test/java/com/fuzz/activemq/OpenWireFuzzTest.java:50"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "harness/src/test/java/com/fuzz/activemq/OpenWireFuzzTest.java:55"
        },
        {
          "kind": "hop",
          "method": "org.apache.activemq.openwire.OpenWireFormat#unmarshal(ByteSequence)",
          "location": "activemq-client/src/main/java/org/apache/activemq/openwire/OpenWireFormat.java:192"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "activemq-client/src/main/java/org/apache/activemq/openwire/OpenWireFormat.java:209"
        },
        {
          "kind": "hop",
          "method": "org.apache.activemq.openwire.OpenWireFormat#doUnmarshal(DataInput)",
          "location": "activemq-client/src/main/java/org/apache/activemq/openwire/OpenWireFormat.java:366"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "activemq-client/src/main/java/org/apache/activemq/openwire/OpenWireFormat.java:379"
        },
        {
          "kind": "hop",
          "method": "org.apache.activemq.openwire.v12.ExceptionResponseMarshaller#looseUnmarshal(OpenWireFormat,Object,DataInput)",
          "location": "activemq-client/src/main/java/org/apache/activemq/openwire/v12/ExceptionResponseMarshaller.java:109"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "activemq-client/src/main/java/org/apache/activemq/openwire/v12/ExceptionResponseMarshaller.java:113"
        },
        {
          "kind": "hop",
          "method": "org.apache.activemq.openwire.v1.BaseDataStreamMarshaller#looseUnmarsalThrowable(OpenWireFormat,DataInput)",
          "location": "activemq-client/src/main/java/org/apache/activemq/openwire/v1/BaseDataStreamMarshaller.java:514"
        }
      ],
      "harness_entry": "com.fuzz.activemq.OpenWireFuzzTest#fuzzOpenWireFormatUnmarshalStackTraceEnabled",
      "scale_measurement": [
        {
          "value": 64,
          "input_bytes": 335,
          "outcome": "completed",
          "cpu_ms": 12.391398,
          "allocated_bytes": 1854264,
          "peak_heap_bytes": 2097152
        },
        {
          "value": 128,
          "input_bytes": 655,
          "outcome": "completed",
          "cpu_ms": 13.204314,
          "allocated_bytes": 2252872,
          "peak_heap_bytes": 3145728
        },
        {
          "value": 256,
          "input_bytes": 1295,
          "outcome": "completed",
          "cpu_ms": 16.08563,
          "allocated_bytes": 3587096,
          "peak_heap_bytes": 4194304
        },
        {
          "value": 500,
          "input_bytes": 2515,
          "outcome": "completed",
          "cpu_ms": 23.443466,
          "allocated_bytes": 8063400,
          "peak_heap_bytes": 8388608
        }
      ]
    },
    {
      "slot": 3,
      "id": "V3",
      "name": "Unbounded recursive nested DataResponse object deserialization",
      "entrypoint": "OpenWireFuzzTest.fuzzOpenWireFormatUnmarshal(InputStream) → OpenWireFormat.unmarshal(ByteSequence) → OpenWireFormat.doUnmarshal(DataInput) → DataResponseMarshaller.looseUnmarshal(OpenWireFormat, Object, DataInput) → BaseDataStreamMarshaller.looseUnmarsalNestedObject(OpenWireFormat, DataInput) → OpenWireFormat.looseUnmarshalNestedObject(DataInput)",
      "source_path": "activemq-client/src/main/java/org/apache/activemq/openwire/OpenWireFormat.java",
      "sink": "OpenWireFormat#looseUnmarshalNestedObject",
      "mechanism": "DataResponse (type 32) contains a nested DataStructure field deserialized via looseUnmarshalNestedObject; if the nested type is also DataResponse, recursion occurs through looseUnmarshal → looseUnmarsalNestedObject → looseUnmarshalNestedObject → looseUnmarshal with no depth limit; each level adds 3 stack frames",
      "resource": "stack depth: 3 stack frames per nesting level (DataResponseMarshaller.looseUnmarshal + looseUnmarsalNestedObject + looseUnmarshalNestedObject), ~150-200 bytes each",
      "failure_mode": "stack_overflow",
      "scale": "Measured: CPU grows linearly at ~0.018 ms per nesting level (extrapolated ~27 ms at max 929 levels, well under timeout). Stack: 200 levels (600 frames) completed within 256 KB; estimated per-frame cost ~130-170 bytes from code analysis, giving ~484 KB at 929 levels (2787 frames), well under 1 MB. Allocated stays flat at ~1.5 MB. Failure (stack_overflow) is not achievable: the 11 bytes/level encoding yields at most 929 levels, which produces ~2787 frames consuming approximately 400-500 KB of stack, well under the 1 MB limit.",
      "input_bytes": 10240,
      "cwe": "CWE-674",
      "checkpath_status": "PASS",
      "normalized_path": [
        {
          "kind": "hop",
          "method": "com.fuzz.activemq.OpenWireFuzzTest#fuzzOpenWireFormatUnmarshal(InputStream)",
          "location": "harness/src/test/java/com/fuzz/activemq/OpenWireFuzzTest.java:63"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "harness/src/test/java/com/fuzz/activemq/OpenWireFuzzTest.java:66"
        },
        {
          "kind": "hop",
          "method": "org.apache.activemq.openwire.OpenWireFormat#unmarshal(ByteSequence)",
          "location": "activemq-client/src/main/java/org/apache/activemq/openwire/OpenWireFormat.java:192"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "activemq-client/src/main/java/org/apache/activemq/openwire/OpenWireFormat.java:209"
        },
        {
          "kind": "hop",
          "method": "org.apache.activemq.openwire.OpenWireFormat#doUnmarshal(DataInput)",
          "location": "activemq-client/src/main/java/org/apache/activemq/openwire/OpenWireFormat.java:366"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "activemq-client/src/main/java/org/apache/activemq/openwire/OpenWireFormat.java:379"
        },
        {
          "kind": "hop",
          "method": "org.apache.activemq.openwire.v1.DataResponseMarshaller#looseUnmarshal(OpenWireFormat,Object,DataInput)",
          "location": "activemq-client/src/main/java/org/apache/activemq/openwire/v1/DataResponseMarshaller.java:110"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "activemq-client/src/main/java/org/apache/activemq/openwire/v1/DataResponseMarshaller.java:114"
        },
        {
          "kind": "hop",
          "method": "org.apache.activemq.openwire.v1.BaseDataStreamMarshaller#looseUnmarsalNestedObject(OpenWireFormat,DataInput)",
          "location": "activemq-client/src/main/java/org/apache/activemq/openwire/v1/BaseDataStreamMarshaller.java:470"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "activemq-client/src/main/java/org/apache/activemq/openwire/v1/BaseDataStreamMarshaller.java:472"
        },
        {
          "kind": "hop",
          "method": "org.apache.activemq.openwire.OpenWireFormat#looseUnmarshalNestedObject(DataInput)",
          "location": "activemq-client/src/main/java/org/apache/activemq/openwire/OpenWireFormat.java:477"
        }
      ],
      "harness_entry": "com.fuzz.activemq.OpenWireFuzzTest#fuzzOpenWireFormatUnmarshal",
      "scale_measurement": [
        {
          "value": 32,
          "input_bytes": 367,
          "outcome": "completed",
          "cpu_ms": 11.463274,
          "allocated_bytes": 1603872,
          "peak_heap_bytes": 2097152
        },
        {
          "value": 64,
          "input_bytes": 719,
          "outcome": "completed",
          "cpu_ms": 11.812754,
          "allocated_bytes": 1612880,
          "peak_heap_bytes": 1048576
        },
        {
          "value": 128,
          "input_bytes": 1423,
          "outcome": "completed",
          "cpu_ms": 12.843347,
          "allocated_bytes": 1608680,
          "peak_heap_bytes": 2097152
        },
        {
          "value": 200,
          "input_bytes": 2215,
          "outcome": "completed",
          "cpu_ms": 15.02733,
          "allocated_bytes": 1612352,
          "peak_heap_bytes": 2097152
        }
      ]
    }
  ]
}
