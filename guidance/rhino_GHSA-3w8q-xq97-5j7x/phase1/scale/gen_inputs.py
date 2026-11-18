#!/usr/bin/env python3
"""Generate scale-measurement inputs for each target."""
import struct, os, json

# === V1: fuzzNumberToFixed ===
# Input: bytes[0..7] = double (big-endian IEEE 754), bytes[8] = precision byte
# Growing parameter: precision (0..100)
# We use a double near 1e20 to maximize k (=20) and BigInteger iterations.
# 9.999e20 ≈ 9.999e20. We pick a value just below 1e21.
# Let's use d = 9.99e20 = 999000000000000000000.0
# For simple known values, use 1e20 = 10^20
# IEEE 754 of 1e20: struct.pack('>d', 1e20)

V1_DIR = "V1"
d_v1 = 1e20  # k ≈ 20 for this value (just below 1e21 boundary)
d_v1_bytes = struct.pack('>d', d_v1)

# Vary precision: 10, 20, 40, 60, 80, 100
# bytes[8] value: (byte & 0xFF) % 101 = precision
v1_precisions = [10, 20, 40, 60, 80, 100]
v1_inputs = []
for p in v1_precisions:
    fname = f"p{p}.bin"
    data = d_v1_bytes + bytes([p])
    with open(os.path.join(V1_DIR, fname), 'wb') as f:
        f.write(data)
    v1_inputs.append({"file": fname, "value": p})

with open(os.path.join(V1_DIR, "series.json"), 'w') as f:
    json.dump({
        "parameter": "toFixed precision (BigInteger iterations = precision + k + 1, k≈20)",
        "inputs": v1_inputs
    }, f, indent=2)

print(f"V1: wrote {len(v1_inputs)} inputs, double = {d_v1}, bytes = {d_v1_bytes.hex()}")

# === V2: fuzzNumberToStringRadix ===
# Input: bytes[0..7] = double (big-endian IEEE 754), bytes[8] = radix byte
# Growing parameter: inverse of radix (smaller radix → more fractional iterations)
# Encoding: radix = (byte & 0xFF) % 35 + 2
# Use d = 0.1 (has infinite binary representation → many iterations)
# For radix=2: byte=0 (0%35+2=2), radix=3: byte=1, radix=5: byte=3, etc.

V2_DIR = "V2"
d_v2 = 0.1
d_v2_bytes = struct.pack('>d', d_v2)

# Vary radix from large (fast) to small (slow)
# radix = (byte % 35) + 2
# radix 36: byte=34, radix 18: byte=16, radix 9: byte=7, radix 5: byte=3, radix 3: byte=1, radix 2: byte=0
v2_configs = [
    (36, 34),
    (18, 16),
    (9, 7),
    (5, 3),
    (3, 1),
    (2, 0),
]
v2_inputs = []
for radix, byte_val in v2_configs:
    fname = f"r{radix}.bin"
    data = d_v2_bytes + bytes([byte_val])
    with open(os.path.join(V2_DIR, fname), 'wb') as f:
        f.write(data)
    # The "value" is approx iterations = 1074 / log2(radix), but let's use radix as the parameter
    # (lower radix = more iterations)
    import math
    approx_iters = int(1074 / math.log2(radix))
    v2_inputs.append({"file": fname, "value": approx_iters})

with open(os.path.join(V2_DIR, "series.json"), 'w') as f:
    json.dump({
        "parameter": "approximate fractional digit iterations (1074/log2(radix))",
        "inputs": v2_inputs
    }, f, indent=2)

print(f"V2: wrote {len(v2_inputs)} inputs, double = {d_v2}, bytes = {d_v2_bytes.hex()}")

# === V3: fuzzNumberFormatMethods (toExponential) ===
# Input: bytes[0..7] = double, bytes[8] = param, bytes[9] = methodSel
# methodSel: (byte & 0xFF) % 4 == 2 for toExponential, so byte=2
# precision for toExponential: param % 101
# Growing parameter: exponent magnitude (vary double from small to MAX_VALUE)
# Higher exponent → larger BigIntegers (5^k where k = floor(log10(d)))
# Use precision=100 (byte=100) and methodSel=2 (byte=2)

V3_DIR = "V3"
param_byte = 100  # precision = 100 % 101 = 100 for toExponential
method_byte = 2   # (2 & 0xFF) % 4 = 2 → toExponential

# Vary the double's exponent: 1e10, 1e20, 1e50, 1e100, 1e200, 1e308
v3_doubles = [
    (1e10, "1e10"),
    (1e20, "1e20"),
    (1e50, "1e50"),
    (1e100, "1e100"),
    (1e200, "1e200"),
    (1.7e308, "1.7e308"),
]
v3_inputs = []
for dval, label in v3_doubles:
    fname = f"d{label}.bin"
    data = struct.pack('>d', dval) + bytes([param_byte, method_byte])
    with open(os.path.join(V3_DIR, fname), 'wb') as f:
        f.write(data)
    import math
    k = int(math.log10(abs(dval)))  # approx floor(log10(d))
    v3_inputs.append({"file": fname, "value": k})

with open(os.path.join(V3_DIR, "series.json"), 'w') as f:
    json.dump({
        "parameter": "decimal exponent k (controls BigInteger size: 5^k bits ≈ k*2.32)",
        "inputs": v3_inputs
    }, f, indent=2)

print(f"V3: wrote {len(v3_inputs)} inputs")
print("Done.")
