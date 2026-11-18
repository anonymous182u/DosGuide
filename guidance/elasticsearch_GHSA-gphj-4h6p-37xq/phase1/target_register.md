{
  "ordered_targets": [
    {
      "slot": 1,
      "id": "V1",
      "name": "IntBlockBuilder constructor integer overflow bypasses circuit breaker → OOM",
      "entrypoint": "BlockBuilderFuzzTest.fuzzBlockFactoryNewIntBlockBuilder(InputStream) → BlockFactory.newIntBlockBuilder(int) → IntBlockBuilder.<init>(int, BlockFactory) → AbstractBlockBuilder.adjustBreaker(long)",
      "source_path": "x-pack/plugin/esql/compute/src/main/generated-src/org/elasticsearch/compute/data/IntBlockBuilder.java",
      "sink": "IntBlockBuilder#<init>(int, BlockFactory)",
      "mechanism": "estimatedSize from input bytes flows to Math.max(estimatedSize, 2) → initialSize; the expression initialSize * elementSize() (int * int) overflows for initialSize >= 536870912 (elementSize=4), producing a negative or small value; adjustBreaker receives the overflowed value and does not trip; the subsequent new int[initialSize] allocates 2+ GB exceeding the 1 GB heap",
      "resource": "heap memory: allocated array bytes = initialSize * 4 (true value), grows linearly with estimatedSize",
      "failure_mode": "out_of_memory",
      "scale": "Measured 4 bytes of heap allocation per unit of estimatedSize (linear, matches elementSize=4). Circuit breaker correctly trips at estimatedSize ~153 million (~614 MB). At estimatedSize = 536870912 (2^29), int product 536870912*4 overflows 32-bit int to -2147483648, breaker registers negative delta and does not trip, new int[536870912] requests 2 GB exceeding 1 GB heap → OutOfMemoryError. 8 bytes of input suffice.",
      "input_bytes": 8,
      "cwe": "CWE-190",
      "checkpath_status": "PASS",
      "normalized_path": [
        {
          "kind": "hop",
          "method": "org.elasticsearch.compute.data.fuzz.BlockBuilderFuzzTest#fuzzBlockFactoryNewIntBlockBuilder(InputStream)",
          "location": "harness/src/test/java/org/elasticsearch/compute/data/fuzz/BlockBuilderFuzzTest.java:56"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "harness/src/test/java/org/elasticsearch/compute/data/fuzz/BlockBuilderFuzzTest.java:63"
        },
        {
          "kind": "hop",
          "method": "org.elasticsearch.compute.data.BlockFactory#newIntBlockBuilder(int)",
          "location": "x-pack/plugin/esql/compute/src/main/java/org/elasticsearch/compute/data/BlockFactory.java:171"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "x-pack/plugin/esql/compute/src/main/java/org/elasticsearch/compute/data/BlockFactory.java:172"
        },
        {
          "kind": "hop",
          "method": "org.elasticsearch.compute.data.IntBlockBuilder#IntBlockBuilder(int,BlockFactory)",
          "location": "x-pack/plugin/esql/compute/src/main/generated-src/org/elasticsearch/compute/data/IntBlockBuilder.java:29"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "x-pack/plugin/esql/compute/src/main/generated-src/org/elasticsearch/compute/data/IntBlockBuilder.java:32"
        },
        {
          "kind": "hop",
          "method": "org.elasticsearch.compute.data.AbstractBlockBuilder#adjustBreaker(long)",
          "location": "x-pack/plugin/esql/compute/src/main/java/org/elasticsearch/compute/data/AbstractBlockBuilder.java:169"
        }
      ],
      "harness_entry": "org.elasticsearch.compute.data.fuzz.BlockBuilderFuzzTest#fuzzBlockFactoryNewIntBlockBuilder",
      "scale_measurement": [
        {
          "value": 1024,
          "input_bytes": 8,
          "outcome": "completed",
          "cpu_ms": 557.892593,
          "allocated_bytes": 64547904,
          "peak_heap_bytes": 8388608
        },
        {
          "value": 4096,
          "input_bytes": 8,
          "outcome": "completed",
          "cpu_ms": 598.113307,
          "allocated_bytes": 64508120,
          "peak_heap_bytes": 47185920
        },
        {
          "value": 16384,
          "input_bytes": 8,
          "outcome": "completed",
          "cpu_ms": 559.963874,
          "allocated_bytes": 64585672,
          "peak_heap_bytes": 28311552
        },
        {
          "value": 65536,
          "input_bytes": 8,
          "outcome": "completed",
          "cpu_ms": 507.762854,
          "allocated_bytes": 64770896,
          "peak_heap_bytes": 47185920
        },
        {
          "value": 262144,
          "input_bytes": 8,
          "outcome": "completed",
          "cpu_ms": 714.32118,
          "allocated_bytes": 65439824,
          "peak_heap_bytes": 29360128
        },
        {
          "value": 1048576,
          "input_bytes": 8,
          "outcome": "completed",
          "cpu_ms": 715.588435,
          "allocated_bytes": 68575184,
          "peak_heap_bytes": 47185920
        }
      ]
    },
    {
      "slot": 2,
      "id": "V2",
      "name": "LongBlockBuilder constructor integer overflow bypasses circuit breaker → OOM",
      "entrypoint": "BlockBuilderFuzzTest.fuzzBlockFactoryNewLongBlockBuilder(InputStream) → BlockFactory.newLongBlockBuilder(int) → LongBlockBuilder.<init>(int, BlockFactory) → AbstractBlockBuilder.adjustBreaker(long)",
      "source_path": "x-pack/plugin/esql/compute/src/main/generated-src/org/elasticsearch/compute/data/LongBlockBuilder.java",
      "sink": "LongBlockBuilder#<init>(int, BlockFactory)",
      "mechanism": "estimatedSize from input bytes flows to Math.max(estimatedSize, 2) → initialSize; the expression initialSize * elementSize() (int * int) overflows for initialSize >= 268435456 (elementSize=8), producing a negative or small value; adjustBreaker receives the overflowed value and does not trip; the subsequent new long[initialSize] allocates 2+ GB exceeding the 1 GB heap",
      "resource": "heap memory: allocated array bytes = initialSize * 8 (true value), grows linearly with estimatedSize",
      "failure_mode": "out_of_memory",
      "scale": "Measured 8 bytes of heap allocation per unit of estimatedSize (linear, matches elementSize=8). Circuit breaker correctly trips at estimatedSize ~76 million (~614 MB). At estimatedSize = 268435456 (2^28), int product 268435456*8 overflows 32-bit int to -2147483648, breaker registers negative delta and does not trip, new long[268435456] requests 2 GB exceeding 1 GB heap → OutOfMemoryError. 8 bytes of input suffice.",
      "input_bytes": 8,
      "cwe": "CWE-190",
      "checkpath_status": "PASS",
      "normalized_path": [
        {
          "kind": "hop",
          "method": "org.elasticsearch.compute.data.fuzz.BlockBuilderFuzzTest#fuzzBlockFactoryNewLongBlockBuilder(InputStream)",
          "location": "harness/src/test/java/org/elasticsearch/compute/data/fuzz/BlockBuilderFuzzTest.java:76"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "harness/src/test/java/org/elasticsearch/compute/data/fuzz/BlockBuilderFuzzTest.java:83"
        },
        {
          "kind": "hop",
          "method": "org.elasticsearch.compute.data.BlockFactory#newLongBlockBuilder(int)",
          "location": "x-pack/plugin/esql/compute/src/main/java/org/elasticsearch/compute/data/BlockFactory.java:290"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "x-pack/plugin/esql/compute/src/main/java/org/elasticsearch/compute/data/BlockFactory.java:291"
        },
        {
          "kind": "hop",
          "method": "org.elasticsearch.compute.data.LongBlockBuilder#LongBlockBuilder(int,BlockFactory)",
          "location": "x-pack/plugin/esql/compute/src/main/generated-src/org/elasticsearch/compute/data/LongBlockBuilder.java:29"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "x-pack/plugin/esql/compute/src/main/generated-src/org/elasticsearch/compute/data/LongBlockBuilder.java:32"
        },
        {
          "kind": "hop",
          "method": "org.elasticsearch.compute.data.AbstractBlockBuilder#adjustBreaker(long)",
          "location": "x-pack/plugin/esql/compute/src/main/java/org/elasticsearch/compute/data/AbstractBlockBuilder.java:169"
        }
      ],
      "harness_entry": "org.elasticsearch.compute.data.fuzz.BlockBuilderFuzzTest#fuzzBlockFactoryNewLongBlockBuilder",
      "scale_measurement": [
        {
          "value": 1024,
          "input_bytes": 8,
          "outcome": "completed",
          "cpu_ms": 657.162918,
          "allocated_bytes": 64449432,
          "peak_heap_bytes": 30408704
        },
        {
          "value": 4096,
          "input_bytes": 8,
          "outcome": "completed",
          "cpu_ms": 667.99112,
          "allocated_bytes": 64593000,
          "peak_heap_bytes": 10485760
        },
        {
          "value": 16384,
          "input_bytes": 8,
          "outcome": "completed",
          "cpu_ms": 643.261279,
          "allocated_bytes": 64628672,
          "peak_heap_bytes": 4194304
        },
        {
          "value": 65536,
          "input_bytes": 8,
          "outcome": "completed",
          "cpu_ms": 512.358094,
          "allocated_bytes": 64708920,
          "peak_heap_bytes": 4194304
        },
        {
          "value": 262144,
          "input_bytes": 8,
          "outcome": "completed",
          "cpu_ms": 602.898082,
          "allocated_bytes": 66645840,
          "peak_heap_bytes": 7340032
        },
        {
          "value": 1048576,
          "input_bytes": 8,
          "outcome": "completed",
          "cpu_ms": 598.295365,
          "allocated_bytes": 72512456,
          "peak_heap_bytes": 24117248
        }
      ]
    }
  ]
}
