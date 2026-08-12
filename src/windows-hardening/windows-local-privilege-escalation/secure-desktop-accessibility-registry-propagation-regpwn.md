# Secure Desktop Accessibility Registry Propagation LPE (RegPwn)

{{#include ../../banners/hacktricks-training.md}}

## Oorsig

Windows Accessibility-kenmerke behou gebruikerskonfigurasie onder HKCU en versprei dit na per-sessie HKLM-liggings. Tydens ’n **Secure Desktop**-oorgang (sluitskerm of UAC-prompt) kopieer **SYSTEM**-komponente hierdie waardes weer. As die **per-sessie HKLM-sleutel deur die gebruiker skryfbaar** is, word dit ’n bevoorregte skryf-knooppunt wat met **registry symbolic links** herlei kan word, wat ’n **arbitrary SYSTEM registry write** oplewer.<sup>[[1]](#references)</sup>

Die RegPwn-tegniek misbruik hierdie propagasieketting met ’n klein race window wat deur ’n **opportunistic lock (oplock)** op ’n lêer wat deur `osk.exe` gebruik word, gestabiliseer word.<sup>[[1]](#references)</sup>

## Registry Propagation Chain (Accessibility -> Secure Desktop)

Voorbeeldkenmerk: **On-Screen Keyboard** (`osk`). Die relevante liggings is:

- **Stelselwye kenmerklys**:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs`
- **Per-gebruiker-konfigurasie (user-writable)**:
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
- **Per-sessie HKLM-konfigurasie (geskep deur `winlogon.exe`, user-writable)**:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- **Secure desktop/default user hive (SYSTEM-konteks)**:
- `HKU\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`

Propagasie tydens ’n secure desktop-oorgang (vereenvoudig):

1. **User `atbroker.exe`** kopieer `HKCU\...\ATConfig\osk` na `HKLM\...\Session<session id>\ATConfig\osk`.
2. **SYSTEM `atbroker.exe`** kopieer `HKLM\...\Session<session id>\ATConfig\osk` na `HKU\.DEFAULT\...\ATConfig\osk`.
3. **SYSTEM `osk.exe`** kopieer `HKU\.DEFAULT\...\ATConfig\osk` terug na `HKLM\...\Session<session id>\ATConfig\osk`.

As die session HKLM-subtree deur die gebruiker skryfbaar is, bied stap 2/3 ’n SYSTEM-skryfaksie deur ’n ligging wat die gebruiker kan vervang.<sup>[[1]](#references)</sup>

## Primitive: Arbitrary SYSTEM Registry Write via Registry Links

Vervang die user-writable per-session-sleutel met ’n **registry symbolic link** wat na ’n aanvallergekose bestemming wys. Wanneer die SYSTEM-kopiëring plaasvind, volg dit die skakel en skryf aanvallerbeheerde waardes na die arbitrêre teikensleutel.

Kernidee:

- Victim write target (user-writable):
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- Attacker vervang daardie sleutel met ’n **registry link** na enige ander sleutel.
- SYSTEM voer die kopiëring uit en skryf met SYSTEM-permissions na die aanvallergekose sleutel.

Dit lewer ’n **arbitrary SYSTEM registry write**-primitive.<sup>[[1]](#references)</sup>

## Winning the Race Window with Oplocks

Daar is ’n kort timing window tussen die begin van **SYSTEM `osk.exe`** en die skryf van die per-session-sleutel. Om dit betroubaar te maak, plaas die exploit ’n **oplock** op:
```
C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml
```
Wanneer die oplock aktiveer, vervang die aanvaller die per-sessie HKLM-sleutel met ’n registry link, laat die SYSTEM-skrywing plaasvind, en verwyder dan die link.<sup>[[1]](#references)</sup>

## Voorbeeld van Exploitation Flow (Hoë Vlak)

1. Kry die huidige **session ID** uit die access token.
2. Begin ’n versteekte `osk.exe`-instansie en wag kortliks (om te verseker dat die oplock aktiveer).
3. Skryf aanvaller-beheerde waardes na:
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
4. Stel ’n **oplock** op `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`.
5. Aktiveer **Secure Desktop** (`LockWorkstation()`), wat veroorsaak dat SYSTEM `atbroker.exe` / `osk.exe` begin.
6. Wanneer die oplock aktiveer, vervang `HKLM\...\Session<session id>\ATConfig\osk` met ’n **registry link** na ’n arbitrêre teiken.
7. Wag kortliks totdat die SYSTEM-kopie voltooi is, en verwyder dan die link.<sup>[[1]](#references)</sup>

## Omskakeling van die Primitive na SYSTEM Execution

Een eenvoudige ketting is om ’n **service configuration**-waarde (byvoorbeeld `ImagePath`) te oorskryf en dan die service te begin. Die RegPwn PoC oorskryf die `ImagePath` van **`msiserver`** en aktiveer dit deur die **MSI COM object** te instansieer, wat **SYSTEM** code execution tot gevolg het.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

## Verwant

Vir ander Secure Desktop / UIAccess-gedrag, sien:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

## References

- [1] [RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [2] [RegPwn PoC](https://github.com/mdsecactivebreach/RegPwn)
{{#include ../../banners/hacktricks-training.md}}
