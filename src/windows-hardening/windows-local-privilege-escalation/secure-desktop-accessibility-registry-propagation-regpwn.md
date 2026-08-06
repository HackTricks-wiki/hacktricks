# Secure Desktop Accessibility Registry Propagation LPE (RegPwn)

{{#include ../../banners/hacktricks-training.md}}

## Oorsig

Windows Accessibility-features behou gebruikerconfigurasie onder HKCU en versprei dit na per-sessie HKLM-liggings. Tydens ’n **Secure Desktop**-oorgang (sluitskerm of UAC-prompt) kopieer **SYSTEM**-komponente hierdie waardes weer. Indien die **per-sessie HKLM-sleutel deur die gebruiker skryfbaar** is, word dit ’n bevoorregte skryf-knooppunt wat met **registry symbolic links** herlei kan word, wat ’n **arbitrary SYSTEM registry write** moontlik maak.<sup>[[1]](#references)</sup>

Die RegPwn-tegniek misbruik hierdie propagasieketting met ’n klein race window wat deur ’n **opportunistic lock (oplock)** op ’n lêer wat deur `osk.exe` gebruik word, gestabiliseer word.<sup>[[1]](#references)</sup>

## Registry Propagation Chain (Accessibility -> Secure Desktop)

Voorbeeldfeature: **On-Screen Keyboard** (`osk`). Die relevante liggings is:

- **Stelselwye feature-lys**:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs`
- **Per-gebruiker-konfigurasie (user-writable)**:
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
- **Per-sessie HKLM-konfigurasie (geskep deur `winlogon.exe`, user-writable)**:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- **Secure desktop/default user hive (SYSTEM-konteks)**:
- `HKU\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`

Propagasie tydens ’n secure desktop-oorgang (vereenvoudig):

1. **Gebruiker se `atbroker.exe`** kopieer `HKCU\...\ATConfig\osk` na `HKLM\...\Session<session id>\ATConfig\osk`.
2. **SYSTEM se `atbroker.exe`** kopieer `HKLM\...\Session<session id>\ATConfig\osk` na `HKU\.DEFAULT\...\ATConfig\osk`.
3. **SYSTEM se `osk.exe`** kopieer `HKU\.DEFAULT\...\ATConfig\osk` terug na `HKLM\...\Session<session id>\ATConfig\osk`.

Indien die session HKLM-subtree deur die gebruiker skryfbaar is, bied stap 2/3 ’n SYSTEM-skrywing deur ’n ligging wat die gebruiker kan vervang.<sup>[[1]](#references)</sup>

## Primitive: Arbitrary SYSTEM Registry Write via Registry Links

Vervang die user-writable per-session-sleutel met ’n **registry symbolic link** wat na ’n deur die attacker gekose bestemming wys. Wanneer die SYSTEM-kopie plaasvind, volg dit die link en skryf attacker-beheerde waardes na die arbitrêre teikensleutel.

Kernidee:

- Slagoffer se skryfteiken (user-writable):
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- Attacker vervang daardie sleutel met ’n **registry link** na enige ander sleutel.
- SYSTEM voer die kopie uit en skryf met SYSTEM-permissies na die deur die attacker gekose sleutel.

Dit lewer ’n **arbitrary SYSTEM registry write**-primitive.<sup>[[1]](#references)</sup>

## Winning the Race Window with Oplocks

Daar is ’n kort tydsvenster tussen die **SYSTEM `osk.exe`**-begin en die skryf na die per-session-sleutel. Om dit betroubaar te maak, plaas die exploit ’n **oplock** op:
```
C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml
```
Wanneer die oplock trigger, vervang die attacker die per-session HKLM-sleutel met ’n registry link, laat die SYSTEM-skrywing land, en verwyder dan die link.<sup>[[1]](#references)</sup>

## Voorbeeld van Exploitation Flow (Hoëvlak)

1. Kry die huidige **session ID** vanaf die access token.
2. Start ’n versteekte `osk.exe`-instansie en slaap kortliks (om te verseker dat die oplock sal trigger).
3. Skryf attacker-beheerde waardes na:
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
4. Stel ’n **oplock** op `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`.
5. Trigger **Secure Desktop** (`LockWorkstation()`), wat veroorsaak dat SYSTEM `atbroker.exe` / `osk.exe` start.
6. Wanneer die oplock trigger, vervang `HKLM\...\Session<session id>\ATConfig\osk` met ’n **registry link** na ’n arbitrêre teiken.
7. Wag kortliks totdat die SYSTEM-kopie voltooi is, en verwyder dan die link.<sup>[[1]](#references)</sup>

## Omskakeling van die Primitive na SYSTEM Execution

Een eenvoudige ketting is om ’n **service configuration**-waarde (byvoorbeeld `ImagePath`) te oorskryf en dan die service te start. Die RegPwn PoC oorskryf die `ImagePath` van **`msiserver`** en trigger dit deur die **MSI COM object** te instansieer, wat tot **SYSTEM** code execution lei.<sup>[[1]](#references)[[2]](#references)</sup>

## Verwant

Vir ander Secure Desktop / UIAccess-gedrag, sien:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

## Verwysings

- [1] [RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [2] [RegPwn PoC](https://github.com/mdsecactivebreach/RegPwn)

{{#include ../../banners/hacktricks-training.md}}
