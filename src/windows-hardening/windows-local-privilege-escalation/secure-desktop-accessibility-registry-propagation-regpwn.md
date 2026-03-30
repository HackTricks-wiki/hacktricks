# Secure Desktop Accessibility Registry Propagation LPE (RegPwn)

{{#include ../../banners/hacktricks-training.md}}

## Oorsig

Windows Accessibility-funksies behou gebruikerskonfigurasie onder HKCU en propagereer dit na per-sessie HKLM-ligginge. Tydens 'n **Secure Desktop**-oorgang (lock screen of UAC-prompt) kopieer **SYSTEM**-komponente hierdie waardes weer. As die **per-sessie HKLM-sleutel deur die gebruiker geskryf kan word**, word dit 'n bevoorregte skryfpunt wat met **registry symbolic links** omgerig kan word, wat 'n **arbitrary SYSTEM registry write** tot gevolg het.

Die RegPwn-tegniek misbruik daardie propagasieketting met 'n klein wedrenvenster wat gestabiliseer word deur 'n **opportunistic lock (oplock)** op 'n lêer wat deur `osk.exe` gebruik word.

## Registerpropagasiereeks (Accessibility -> Secure Desktop)

Voorbeeldfunksie: **On-Screen Keyboard** (`osk`). Die relevante ligginge is:

- **Stelselwye funksielys**:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs`
- **Per-gebruiker konfigurasie (user-writable)**:
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
- **Per-sessie HKLM konfigurasie (created by `winlogon.exe`, user-writable)**:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- **Secure desktop/default user hive (SYSTEM context)**:
- `HKU\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`

Propagasiery tydens 'n Secure Desktop-oorgang (vereenvoudig):

1. **User `atbroker.exe`** kopieer `HKCU\...\ATConfig\osk` na `HKLM\...\Session<session id>\ATConfig\osk`.
2. **SYSTEM `atbroker.exe`** kopieer `HKLM\...\Session<session id>\ATConfig\osk` na `HKU\.DEFAULT\...\ATConfig\osk`.
3. **SYSTEM `osk.exe`** kopieer `HKU\.DEFAULT\...\ATConfig\osk` terug na `HKLM\...\Session<session id>\ATConfig\osk`.

As die sessie-HKLM-subboom deur die gebruiker geskryf kan word, bied stap 2/3 'n SYSTEM-skrywing deur 'n ligging wat die gebruiker kan vervang.

## Primitive: Arbitrary SYSTEM Registry Write via Registry Links

Vervang die per-sessie sleutel wat deur die gebruiker geskryf kan word met 'n **registry symbolic link** wat na 'n deur die aanvaller-gekose bestemming wys. Wanneer die SYSTEM-kopie plaasvind, volg dit die skakel en skryf aanvaller-beheerde waardes in die arbitrêre teiken sleutel.

Kernidee:

- Victim write target (user-writable):
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- Attacker replaces that key with a **registry link** to any other key.
- SYSTEM performs the copy and writes into the attacker-chosen key with SYSTEM permissions.

Dit lewer 'n **arbitrary SYSTEM registry write**-primitive op.

## Wen die tydvenster met Oplocks

Daar is 'n kort tydvenster tussen die begin van **SYSTEM `osk.exe`** en die skryf van die per-sessie sleutel. Om dit betroubaar te maak, plaas die exploit 'n **oplock** op:
```
C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml
```
Wanneer die oplock getrigger word, ruil die aanvaller die per-sessie HKLM-sleutel vir 'n registry link, laat die SYSTEM skryf, en verwyder dan die link.

## Voorbeeld Uitbuitingvloei (Hoëvlak)

1. Kry die huidige **session ID** van die access token.
2. Begin 'n verborge `osk.exe`-instansie en slaap kortliks (verseker dat die oplock sal trigger).
3. Skryf aanvaller-beheerde waardes na:
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
4. Stel 'n **oplock** op `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`.
5. Aktiveer **Secure Desktop** (`LockWorkstation()`), wat veroorsaak dat SYSTEM `atbroker.exe` / `osk.exe` begin.
6. Wanneer die oplock getrigger word, vervang `HKLM\...\Session<session id>\ATConfig\osk` met 'n **registry link** na 'n ewekansige teiken.
7. Wag kortliks vir die SYSTEM-kopie om te voltooi, verwyder dan die link.

## Om die primitief na SYSTEM-uitvoering om te skakel

Een eenvoudige ketting is om 'n **service configuration** waarde oor te skryf (bv. `ImagePath`) en dan die diens te begin. Die RegPwn PoC skryf die `ImagePath` van **`msiserver`** oor en trigger dit deur die **MSI COM object** te instantier, wat lei tot **SYSTEM** kode-uitvoering.

## Verwante

Vir ander Secure Desktop / UIAccess-gedrag, sien:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

## Verwysings

- [RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [RegPwn PoC](https://github.com/mdsecactivebreach/RegPwn)

{{#include ../../banners/hacktricks-training.md}}
