{
  "ordered_targets": [
    {
      "slot": 1,
      "id": "V1",
      "name": "Vaadin v7 EmailValidator ReDoS — exponential backtracking in TLD quantifier",
      "entrypoint": "EmailValidatorFuzzTest.fuzzEmailValidatorIsValid(InputStream) → EmailValidator.isValid(Object) → AbstractValidator.validate(Object) → RegexpValidator.isValidValue(String) → Matcher.matches()",
      "source_path": "compatibility-server/src/main/java/com/vaadin/v7/data/validator/EmailValidator.java",
      "sink": "java.util.regex.Matcher#matches",
      "mechanism": "The regex TLD part ([a-zA-Z0-9]{2,4})+$ has a nested quantifier: variable-length group {2,4} repeated by +. When N alphanumeric chars precede a non-matching trailer, the engine tries every partition of N into groups of 2-4, giving exponential backtracking (~1.3247^N partitions).",
      "resource": "CPU time: number of regex engine backtracking steps grows exponentially with TLD length",
      "failure_mode": "timeout",
      "scale": "Measured: CPU time essentially flat 3.6–5.2 ms for N=10 to N=60 (TLD alphanumeric length). The theoretical exponential backtracking in ([a-zA-Z0-9]{2,4})+$ does NOT manifest on JDK 17: the regex engine applies a dead-state optimization recognizing that all partitions of the TLD group terminate at the same non-matchable character, making $ deterministically fail without exploring partitions. Measured growth rate ~0.03 ms/char (attributable to string creation overhead, not backtracking). Linear extrapolation to maximum input N≈10235: ~310 ms, which is 64× below the 20,000 ms timeout. Triggering a timeout with input shape a@b.<alphanums><non-alphanum> appears infeasible under these evaluation limits on this JDK.",
      "input_bytes": 10240,
      "cwe": "CWE-1333",
      "checkpath_status": "PASS",
      "normalized_path": [
        {
          "kind": "hop",
          "method": "com.vaadin.fuzz.EmailValidatorFuzzTest#fuzzEmailValidatorIsValid(InputStream)",
          "location": "harness/src/test/java/com/vaadin/fuzz/EmailValidatorFuzzTest.java:34"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "harness/src/test/java/com/vaadin/fuzz/EmailValidatorFuzzTest.java:38"
        },
        {
          "kind": "hop",
          "method": "com.vaadin.v7.data.validator.AbstractValidator#isValid(Object)",
          "location": "compatibility-server/src/main/java/com/vaadin/v7/data/validator/AbstractValidator.java:77"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "compatibility-server/src/main/java/com/vaadin/v7/data/validator/AbstractValidator.java:79"
        },
        {
          "kind": "hop",
          "method": "com.vaadin.v7.data.validator.AbstractValidator#validate(Object)",
          "location": "compatibility-server/src/main/java/com/vaadin/v7/data/validator/AbstractValidator.java:100"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "compatibility-server/src/main/java/com/vaadin/v7/data/validator/AbstractValidator.java:102"
        },
        {
          "kind": "hop",
          "method": "com.vaadin.v7.data.validator.RegexpValidator#isValidValue(String)",
          "location": "compatibility-server/src/main/java/com/vaadin/v7/data/validator/RegexpValidator.java:89"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "compatibility-server/src/main/java/com/vaadin/v7/data/validator/RegexpValidator.java:94"
        },
        {
          "kind": "hop",
          "method": "Matcher.matches()",
          "location": "outside the source tree"
        }
      ],
      "harness_entry": "com.vaadin.fuzz.EmailValidatorFuzzTest#fuzzEmailValidatorIsValid",
      "scale_measurement": [
        {
          "value": 10,
          "input_bytes": 15,
          "outcome": "completed",
          "cpu_ms": 3.636466,
          "allocated_bytes": 311328,
          "peak_heap_bytes": 1048576
        },
        {
          "value": 20,
          "input_bytes": 25,
          "outcome": "completed",
          "cpu_ms": 3.828815,
          "allocated_bytes": 311720,
          "peak_heap_bytes": 1048576
        },
        {
          "value": 30,
          "input_bytes": 35,
          "outcome": "completed",
          "cpu_ms": 3.941117,
          "allocated_bytes": 311736,
          "peak_heap_bytes": 1048576
        },
        {
          "value": 40,
          "input_bytes": 45,
          "outcome": "completed",
          "cpu_ms": 4.445822,
          "allocated_bytes": 327104,
          "peak_heap_bytes": 1048576
        },
        {
          "value": 50,
          "input_bytes": 55,
          "outcome": "completed",
          "cpu_ms": 4.049412,
          "allocated_bytes": 312448,
          "peak_heap_bytes": 1048576
        },
        {
          "value": 60,
          "input_bytes": 65,
          "outcome": "completed",
          "cpu_ms": 5.207343,
          "allocated_bytes": 312480,
          "peak_heap_bytes": 1048576
        }
      ]
    },
    {
      "slot": 2,
      "id": "V2",
      "name": "Vaadin v8 EmailValidator ReDoS — polynomial backtracking in domain/TLD overlap",
      "entrypoint": "EmailValidatorFuzzTest.fuzzEmailValidatorApply(InputStream) → EmailValidator.apply(String, ValueContext) → RegexpValidator.isValid(String) → Matcher.matches()",
      "source_path": "server/src/main/java/com/vaadin/data/validator/EmailValidator.java",
      "sink": "java.util.regex.Matcher#matches",
      "mechanism": "The regex domain part [a-zA-Z0-9-.]+\\.[a-zA-Z0-9-]{2,}$ has overlapping character classes between domain and TLD. When input ends with a non-matching char, the engine backtracks through dot positions trying domain/TLD splits. No nested quantifiers, so backtracking is O(N) to O(N^2).",
      "resource": "CPU time: number of regex engine backtracking steps grows linearly or quadratically with domain length",
      "failure_mode": "timeout",
      "scale": "Measured: CPU time nearly flat 10.6–14.0 ms for N=100 to N=2400 (domain TLD length). Growth ~0.0015 ms/char (sublinear, dominated by string allocation). Extrapolated to max N≈10235: ~26 ms, 770× below the 20,000 ms timeout. The v8 regex has no nested quantifiers; backtracking is at most O(N). Confirmed not triggerable under these evaluation limits.",
      "input_bytes": 10240,
      "cwe": "CWE-1333",
      "checkpath_status": "PASS",
      "normalized_path": [
        {
          "kind": "hop",
          "method": "com.vaadin.fuzz.EmailValidatorFuzzTest#fuzzEmailValidatorApply(InputStream)",
          "location": "harness/src/test/java/com/vaadin/fuzz/EmailValidatorFuzzTest.java:46"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "harness/src/test/java/com/vaadin/fuzz/EmailValidatorFuzzTest.java:50"
        },
        {
          "kind": "hop",
          "method": "com.vaadin.data.validator.RegexpValidator#apply(String,ValueContext)",
          "location": "server/src/main/java/com/vaadin/data/validator/RegexpValidator.java:74"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "server/src/main/java/com/vaadin/data/validator/RegexpValidator.java:75"
        },
        {
          "kind": "hop",
          "method": "com.vaadin.data.validator.RegexpValidator#isValid(String)",
          "location": "server/src/main/java/com/vaadin/data/validator/RegexpValidator.java:90"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "server/src/main/java/com/vaadin/data/validator/RegexpValidator.java:95"
        },
        {
          "kind": "hop",
          "method": "Matcher.matches()",
          "location": "outside the source tree"
        }
      ],
      "harness_entry": "com.vaadin.fuzz.EmailValidatorFuzzTest#fuzzEmailValidatorApply",
      "scale_measurement": [
        {
          "value": 100,
          "input_bytes": 105,
          "outcome": "completed",
          "cpu_ms": 10.604574,
          "allocated_bytes": 1364360,
          "peak_heap_bytes": 2097152
        },
        {
          "value": 200,
          "input_bytes": 205,
          "outcome": "completed",
          "cpu_ms": 11.064329,
          "allocated_bytes": 1425600,
          "peak_heap_bytes": 2097152
        },
        {
          "value": 400,
          "input_bytes": 405,
          "outcome": "completed",
          "cpu_ms": 11.603447,
          "allocated_bytes": 1364984,
          "peak_heap_bytes": 2097152
        },
        {
          "value": 800,
          "input_bytes": 805,
          "outcome": "completed",
          "cpu_ms": 12.241271,
          "allocated_bytes": 1365784,
          "peak_heap_bytes": 1048576
        },
        {
          "value": 1600,
          "input_bytes": 1605,
          "outcome": "completed",
          "cpu_ms": 12.805261,
          "allocated_bytes": 1367400,
          "peak_heap_bytes": 2097152
        },
        {
          "value": 2400,
          "input_bytes": 2405,
          "outcome": "completed",
          "cpu_ms": 13.996114,
          "allocated_bytes": 1369000,
          "peak_heap_bytes": 1048576
        }
      ]
    }
  ]
}
