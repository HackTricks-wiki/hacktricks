# Secure Desktop Accessibility Registry Propagation LPE (RegPwn)

{{#include ../../banners/hacktricks-training.md}}

## Muhtasari

Windows Accessibility features huhifadhi configuration ya mtumiaji chini ya HKCU na kuieneza kwenye maeneo ya HKLM ya kila session. Wakati wa mabadiliko ya **Secure Desktop** (lock screen au UAC prompt), vipengele vya **SYSTEM** hu-copy tena values hizi. Ikiwa **per-session HKLM key** inaweza kuandikwa na mtumiaji, huwa sehemu ya privileged write inayoweza kuelekezwa upya kwa kutumia **registry symbolic links**, na hivyo kutoa **arbitrary SYSTEM registry write**.<sup>[[1]](#references)</sup>

Mbinu ya RegPwn hutumia vibaya propagation chain hiyo kwa kutumia race window ndogo inayodhibitiwa kupitia **opportunistic lock (oplock)** kwenye file inayotumiwa na `osk.exe`.<sup>[[1]](#references)</sup>

## Registry Propagation Chain (Accessibility -> Secure Desktop)

Mfano wa feature: **On-Screen Keyboard** (`osk`). Maeneo husika ni:

- **Orodha ya feature ya mfumo mzima**:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs`
- **Configuration ya kila mtumiaji (user-writable)**:
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
- **Per-session HKLM config (inayoundwa na `winlogon.exe`, user-writable)**:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- **Secure desktop/default user hive (SYSTEM context)**:
- `HKU\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`

Propagation wakati wa mabadiliko ya secure desktop (kwa muhtasari):

1. **User `atbroker.exe`** hu-copy `HKCU\...\ATConfig\osk` kwenda `HKLM\...\Session<session id>\ATConfig\osk`.
2. **SYSTEM `atbroker.exe`** hu-copy `HKLM\...\Session<session id>\ATConfig\osk` kwenda `HKU\.DEFAULT\...\ATConfig\osk`.
3. **SYSTEM `osk.exe`** hu-copy `HKU\.DEFAULT\...\ATConfig\osk` kurudi `HKLM\...\Session<session id>\ATConfig\osk`.

Ikiwa HKLM subtree ya session inaweza kuandikwa na mtumiaji, hatua ya 2/3 hutoa SYSTEM write kupitia location ambayo mtumiaji anaweza kuibadilisha.<sup>[[1]](#references)</sup>

## Primitive: Arbitrary SYSTEM Registry Write via Registry Links

Badilisha per-session key inayoweza kuandikwa na mtumiaji iwe **registry symbolic link** inayoelekeza kwenye destination iliyochaguliwa na attacker. SYSTEM copy inapotokea, hufuata link hiyo na kuandika values zinazodhibitiwa na attacker ndani ya target key yoyote.

Wazo kuu:

- Victim write target (user-writable):
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- Attacker hubadilisha key hiyo kuwa **registry link** inayoelekeza kwenye key nyingine yoyote.
- SYSTEM hutekeleza copy na kuandika kwenye key iliyochaguliwa na attacker kwa SYSTEM permissions.

Hii hutoa **arbitrary SYSTEM registry write** primitive.<sup>[[1]](#references)</sup>

## Winning the Race Window with Oplocks

Kuna timing window fupi kati ya kuanza kwa **SYSTEM `osk.exe`** na kuandika per-session key. Ili kuifanya iwe reliable, exploit huweka **oplock** kwenye:
```
C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml
```
Wakati oplock inapo-trigger, mshambuliaji hubadilisha per-session HKLM key kuwa registry link, huruhusu uandishi wa SYSTEM kufanyika, kisha huondoa link.<sup>[[1]](#references)</sup>

## Mtiririko wa Mfano wa Exploitation (Kiwango cha Juu)

1. Pata **session ID** ya sasa kutoka kwenye access token.
2. Anzisha instance iliyofichwa ya `osk.exe` na ulale kwa muda mfupi (hakikisha oplock ita-trigger).
3. Andika values zinazodhibitiwa na mshambuliaji kwenye:
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
4. Weka **oplock** kwenye `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`.
5. Trigger **Secure Desktop** (`LockWorkstation()`), na kusababisha SYSTEM `atbroker.exe` / `osk.exe` kuanza.
6. Oplock inapo-trigger, badilisha `HKLM\...\Session<session id>\ATConfig\osk` iwe **registry link** inayoelekeza kwenye target yoyote.
7. Subiri kwa muda mfupi ili SYSTEM copy ikamilike, kisha ondoa link.<sup>[[1]](#references)</sup>

## Kubadilisha Primitive Kuwa SYSTEM Execution

Chain moja ya moja kwa moja ni ku-overwrite value ya **service configuration** (kwa mfano, `ImagePath`) kisha kuanzisha service. RegPwn PoC hu-overwrite `ImagePath` ya **`msiserver`** na ku-trigger service hiyo kwa ku-instantiate **MSI COM object**, hivyo kusababisha **SYSTEM** code execution.<sup>[[1]](#references)[[2]](#references)</sup>

## Zinazohusiana

Kwa tabia nyingine za Secure Desktop / UIAccess, angalia:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

## References

- [1] [RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [2] [RegPwn PoC](https://github.com/mdsecactivebreach/RegPwn)

{{#include ../../banners/hacktricks-training.md}}
