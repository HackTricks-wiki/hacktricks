# Secure Desktop Accessibility Registry Propagation LPE (RegPwn)

{{#include ../../banners/hacktricks-training.md}}

## Muhtasari

Vipengele vya Windows Accessibility huhifadhi usanidi wa mtumiaji chini ya HKCU na kuvisambaza kwenye maeneo ya kila kikao ya HKLM. Wakati wa mabadiliko ya **Secure Desktop** (lock screen au UAC prompt), vipengele vya **SYSTEM** vinarekopia tena thamani hizi. Ikiwa **key ya HKLM ya kila kikao inayoandikwa na mtumiaji**, inageuka kuwa sehemu ya udhibiti wa kuandika yenye cheo ambayo inaweza kuelekezwa kwa **registry symbolic links**, na kutoa **arbitrary SYSTEM registry write**.

Mbinu ya RegPwn inadanganya mnyororo huo wa usambazaji kwa dirisha dogo la ushindani, lililothibitishwa kwa kutumia **opportunistic lock (oplock)** kwenye faili inayotumiwa na `osk.exe`.

## Registry Propagation Chain (Accessibility -> Secure Desktop)

Mfano wa kipengele: **On-Screen Keyboard** (`osk`). Maeneo yanayohusika ni:

- Orodha ya vipengele kwa mfumo wote:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs`
- Usanidi wa mtumiaji (user-writable):
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
- Usanidi wa HKLM wa kila kikao (umeundwa na `winlogon.exe`, user-writable):
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- Secure desktop/default user hive (SYSTEM context):
- `HKU\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`

Usambazaji wakati wa mabadiliko ya Secure Desktop (imefupishwa):

1. **User `atbroker.exe`** anakopa `HKCU\...\ATConfig\osk` hadi `HKLM\...\Session<session id>\ATConfig\osk`.
2. **SYSTEM `atbroker.exe`** anakopa `HKLM\...\Session<session id>\ATConfig\osk` hadi `HKU\.DEFAULT\...\ATConfig\osk`.
3. **SYSTEM `osk.exe`** anakopa `HKU\.DEFAULT\...\ATConfig\osk` kurudi `HKLM\...\Session<session id>\ATConfig\osk`.

Ikiwa mti wa HKLM wa kikao unaweza kuandikwa na mtumiaji, hatua 2/3 hutoa uandishi wa SYSTEM kupitia eneo ambalo mtumiaji anaweza kulibadilisha.

## Primitive: Arbitrary SYSTEM Registry Write via Registry Links

Badilisha key ya per-session inayoweza kuandikwa na mtumiaji na **registry symbolic link** inayorejelea lengo lolote lililochaguliwa na mshambuliaji. Wakati nakala ya SYSTEM inapotendeka, inafuata link hiyo na inaandika thamani zinazoongozwa na mshambuliaji kwenye key ya lengo hiyo.

Wazo kuu:

- Lengo la uandishi la mwathiriwa (user-writable):
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- Mshambuliaji anabadilisha key hiyo na **registry link** kuelekea key nyingine yoyote.
- SYSTEM inafanya nakala na inaandika kwenye key iliyochaguliwa na mshambuliaji kwa ruhusa za SYSTEM.

Hii inatoa primitive ya **arbitrary SYSTEM registry write**.

## Winning the Race Window with Oplocks

Kuna dirisha fupi la wakati kati ya kuanzishwa kwa **SYSTEM `osk.exe`** na uandishi wa key ya per-session. Ili kuifanya iwe ya kuaminika, exploit inaweka **oplock** kwenye:
```
C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml
```
Wakati oplock inapochochea, mshambuliaji anabadilisha funguo la HKLM la kwa kila kikao kwa registry link, anaruhusu SYSTEM kuandika, kisha anaondoa link.

## Mfano wa Mtiririko wa Exploitation (High Level)

1. Pata **session ID** ya sasa kutoka access token.
2. Anzisha mfano uliyo fichwa wa `osk.exe` na lala kwa muda mfupi (hakikisha oplock itachochea).
3. Andika thamani zinazodhibitiwa na mshambuliaji kwa:
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
4. Weka **oplock** kwenye `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`.
5. Chochea **Secure Desktop** (`LockWorkstation()`), ikisababisha SYSTEM `atbroker.exe` / `osk.exe` kuanza.
6. Wakati oplock inachochea, badilisha `HKLM\...\Session<session id>\ATConfig\osk` na **registry link** kwenda lengo lolote.
7. Subiri kwa muda mfupi kwa ajili ya nakala ya SYSTEM kukamilika, kisha ondoa link.

## Kubadilisha Primitive kuwa Utekelezaji wa SYSTEM

Mnyororo mmoja rahisi ni kuandika juu (overwrite) thamani ya **service configuration** (kwa mfano, `ImagePath`) kisha kuanzisha service. The RegPwn PoC inaandika juu `ImagePath` ya **`msiserver`** na kuidhibiti kwa kutengeneza mfano wa **MSI COM object**, na kusababisha utekelezaji wa msimbo chini ya **SYSTEM**.

## Related

Kwa tabia nyingine za Secure Desktop / UIAccess, angalia:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

## Marejeo

- [RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [RegPwn PoC](https://github.com/mdsecactivebreach/RegPwn)

{{#include ../../banners/hacktricks-training.md}}
