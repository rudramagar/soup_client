# OUCH Fixed-Point Price Scaling

## Why prices are scaled

The OUCH `Price` field on the wire is a **4-byte unsigned integer** — it can
only hold whole numbers. Real prices have fractional parts (e.g. `21607.800`).
So the protocol uses an **implied decimal point**: the integer sent on the wire
is the real price multiplied by a fixed power of 10. Both sides agree where the
decimal "really" sits. **The wire never carries an actual `.` character.**

Each exchange publishes how many decimal places its price field uses, in the
spec's *Data Types* section. That number is the only thing you need — everything
else is derived from it.

---

## The formula

```
scale     = 10 ^ decimals          (a 1 followed by `decimals` zeros)
wire_value = round(human_price * scale)
human_price = wire_value / scale
```

The number of **zeros in the scale** always equals the number of **decimal
places**.

---

## Scale table (0 to 4 decimals)

| Decimals | Scale (10^d) | Zeros | Meaning                          |
|----------|--------------|-------|----------------------------------|
| 0        | 1            | 0     | No scaling — integer *is* the price |
| 1        | 10           | 1     | Resolves to 0.1                  |
| 2        | 100          | 2     | Resolves to 0.01                 |
| 3        | 1000         | 3     | Resolves to 0.001                |
| 4        | 10000        | 4     | Resolves to 0.0001               |

---

## Worked examples

Using human price `21607.8` across each convention:

| Decimals | Scale | human_price | wire_value (= price × scale) | read back (wire / scale) |
|----------|-------|-------------|------------------------------|--------------------------|
| 0        | 1     | 21607       | 21607                        | 21607                    |
| 1        | 10    | 21607.8     | 216078                       | 21607.8                  |
| 2        | 100   | 21607.8     | 2160780                      | 21607.80                 |
| 3        | 1000  | 21607.8     | 21607800                     | 21607.800                |
| 4        | 10000 | 21607.8     | 216078000                    | 21607.8000               |

**Key point:** the *same* human input produces a *different* wire integer under
each convention. That is why the scale must come from the spec, not be
hardcoded.

---

## Per-exchange conventions

| Exchange | Decimals | Scale | Doc-stated max human price | Cross-check (2147483646 / scale) |
|----------|----------|-------|----------------------------|----------------------------------|
| Japannext (JNX) equities | 1 | 10   | 214,748,364.6  | 2147483646 / 10   = 214748364.6  |
| Osaka Dojima (ODEX)      | 3 | 1000 | 2,147,483.646  | 2147483646 / 1000 = 2147483.646  |

The raw 4-byte max is always `0x7FFFFFFE = 2,147,483,646` (same integer for both,
since both are uint32). Dividing that raw max by the scale gives exactly the
doc's stated max human price — a handy way to confirm you picked the right
decimal count.

---

## Determining the values (the whole logic in one place)

1. **Read the spec's Data Types section** → it states the number of decimal
   places (JNX = 1, ODEX = 3). This is published, not computed.
2. **Derive the scale**: `scale = 10 ^ decimals` (1 followed by that many zeros).
3. **(Optional) verify**: `raw_max (2147483646) / scale` should equal the doc's
   stated max human price.

---

## Code snippet (scale for any decimal count)

```cpp
// Works for any number of decimals stated by the spec — no lookup table.
long scale = 1;
for (int i = 0; i < decimals; i++) scale *= 10;

// human_price is a double parsed from the scenario value, e.g. 21607.8
uint32_t wire_value = (uint32_t)llround(human_price * scale);
```

---

## Worked conversion, step by step (ODEX, 3 decimals)

```
input human price : 21607.800
decimals (spec)   : 3
scale = 10^3      : 1000
wire = 21607.800 * 1000 = 21607800
wire as 4 bytes (big-endian) = 01 49 B5 78
```

To decode a received price of `21607800`:

```
21607800 / 1000 = 21607.800
```
