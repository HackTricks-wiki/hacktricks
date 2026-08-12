# macOS NVRAM

{{#include ../../../banners/hacktricks-training.md}}

## Grundlegende Informationen

**NVRAM** (Non-Volatile Random-Access Memory) speichert Firmware- und frühen Boot-Status außerhalb des normalen macOS-Dateisystems. Die Auswirkungen auf die Sicherheit hängen sowohl von der Variable als auch von der Boot-Architektur ab:

| Variable | Zweck / Sicherheitsrelevanz |
|---|---|
| `boot-args` | An den Kernel übergebene Argumente. Debug- oder sicherheitsreduzierende Argumente werden herausgefiltert, sofern die Boot-Richtlinie sie nicht zulässt. |
| `csr-active-config` | SIP-Bitmaske auf Intel-Macs. Auf Apple silicon wird die entsprechende Richtlinie in der volumenbezogenen `LocalPolicy` gespeichert und nicht direkt anhand dieser Variable als vertrauenswürdig eingestuft. |
| `efi-boot-device` / `efi-boot-device-data` | Intel-EFI-Bootziel. |
| `boot-volume` | Auswahlstatus des Boot-Volumes auf Apple silicon. |
| `SystemAudioVolume`, `prev-lang:kbd` | Beispiele für gewöhnliche persistente Einstellungen. |

Der wichtige Unterschied besteht zwischen **in NVRAM gespeicherten Daten** und einer **von der Boot-Kette akzeptierten Sicherheitsrichtlinie**. Auf Apple silicon signiert die Secure Enclave eine `LocalPolicy` für jede Boot-Volume-Gruppe; ein im Secure Storage Component gespeicherter Nonce bietet Anti-Replay-Schutz. Daher schreibt das Ändern einer ähnlich benannten NVRAM-Eigenschaft die akzeptierte Boot-Richtlinie nicht automatisch neu.<sup>[[1]](#references)[[4]](#references)</sup>

## NVRAM-Zugriff aus dem User Space

### Auslesen und Erfassung einer Baseline
```bash
# List variables (values are separated from names by a tab)
nvram -p

# Read individual variables. Absence is normal on many configurations.
nvram boot-args
nvram csr-active-config

# Export typed values as an XML plist; useful for diffing two acquisitions
nvram -xp > "nvram-$(date +%Y%m%d-%H%M%S).plist"

# The same properties as exposed through the IODeviceTree plane
ioreg -lw0 -p IODeviceTree -n options

# Effective SIP status
csrutil status
```
Klassifiziere nicht jeden unbekannten Schlüssel als bösartig. Hardware, recoveryOS, Updates, Find My und fehlgeschlagene Bootvorgänge erzeugen allesamt modell- und versionsabhängige Variablen. Vergleiche einen Mitschnitt mit einer früheren Baseline desselben **Macs** und betrachte unerwartete Binärdaten, eine geänderte Bootauswahl oder sicherheitsreduzierende Argumente als Hinweise und nicht als Beweis für eine Kompromittierung.

### NVRAM schreiben

Root kann viele gewöhnliche Variablen erstellen oder ändern, aber geschützte Variablen hängen zusätzlich vom Variablen-Namespace, SIP, Kernelregeln für die jeweilige Variable und eingeschränkten Apple-Entitlements ab. Daher beweist ein erfolgreiches `sudo` für einen harmlosen benutzerdefinierten Schlüssel **nicht**, dass der Prozess `boot-args`, SIP oder Variablen der Systemregion ändern kann.
```bash
# Harmless test variable (perform only on a disposable test host)
sudo nvram HTTest='persistence-value'
nvram HTTest
sudo nvram -d HTTest

# Delete one variable
sudo nvram -d variable-name
```
> [!CAUTION]
> Vermeide `nvram -c` während des Testens: Der Befehl fordert die Löschung aller löschbaren Variablen an und kann das Boot-/Recovery-Verhalten ändern. Einige Variablen sind nur für den Kernel bestimmt, durch Entitlements geschützt, beim Lesen verborgen oder nur während eines NVRAM-Resets löschbar.

## NVRAM-Entitlements und `CS_NVRAM_UNRESTRICTED`

Zum Zeitpunkt von exec mappt XNU `com.apple.rootless.restricted-nvram-variables.heritable` auf das Prozess-Flag **`CS_NVRAM_UNRESTRICTED`** (`0x00008000`). Dies entspricht nicht der gewöhnlichen Prüfung der effektiven UID 0. Außerdem gibt es engere private Entitlements für bestimmte Variablen oder Operationen.

Untersuche die Entitlements, statt dich auf die allgemeine Flags-Zeile zu verlassen, die von `codesign` ausgegeben wird:
```bash
# Static entitlements embedded in a Mach-O signature
codesign -d --entitlements :- /path/to/binary 2>&1

# Quickly highlight NVRAM-related entitlements
codesign -d --entitlements :- /path/to/binary 2>&1 |
grep -Ei 'nvram|restricted-nvram'

# The nvram CLI itself normally asks the IOKit service to enforce the caller's
# privilege; possession of /usr/sbin/nvram is not an entitlement bypass.
codesign -d --entitlements :- /usr/sbin/nvram 2>&1
```
Beim Audit eines privilegierten Helpers sollten Sie die **tatsächliche Client-Identität und den Anfragepfad** verfolgen. Ein confused-deputy bug in einem mit Berechtigungen versehenen Service kann nützlicher sein als der direkte Aufruf von `nvram`, aber die erreichbare Variable bzw. Operation kann weiterhin durch XNU eingeschränkt sein.

## Intel-SIP-Status vs. Apple-Silicon-`LocalPolicy`

### Intel: `csr-active-config`

Unter Intel codiert `csr-active-config` die `CSR_ALLOW_*`-Ausnahmen. Die üblicherweise relevanten Bitpositionen sind:
```text
0x001  untrusted kexts                 0x002  unrestricted filesystem
0x004  task_for_pid                    0x008  kernel debugger
0x010  Apple-internal behavior         0x020  unrestricted DTrace
0x040  unrestricted NVRAM              0x080  device configuration
0x100  any recovery OS                 0x200  unapproved kexts
0x400  executable-policy override      0x800  unauthenticated root (SSV)
```
Lesen Sie die aktive Einstellung mit `csrutil status`; die rohe `nvram`-Ausgabe kann prozentkodierte Little-Endian-Bytes verwenden. Siehe [macOS SIP](../macos-security-protections/macos-sip.md) für die Auswirkungen auf Schutz und Bypass.
```bash
nvram csr-active-config 2>/dev/null
csrutil status
```
### Apple Silicon: die akzeptierte Boot-Richtlinie prüfen

Auf Apple silicon enthält `sip0` in der von der Secure Enclave signierten `LocalPolicy` die SIP-Richtlinienbits, die zuvor in NVRAM gespeichert waren. Die anderen relevanten Richtlinienfelder sind `sip1` (einen Fehler bei der Überprüfung des SSV-Root-Hash zulassen), `sip2` (den Kernel-Speicher nicht mit CTRR sperren) und `sip3` (die `boot-args`-Allowlist von iBoot deaktivieren). Diese Felder können nur aus einer gekoppelten One True recoveryOS (1TR) heraus geändert werden; das Aktivieren von `sip3` erfordert außerdem ein Downgrade auf Permissive Security.<sup>[[4]](#references)</sup>

Verwende während der Enumeration ausschließlich die Anzeigeoperationen:
```bash
# Apple silicon: show the selected volume group's LocalPolicy
sudo bputil -d

# Machine-readable display, or display every bootable OS policy
sudo bputil -d -j
sudo bputil -e -j

# Map policy output to APFS volume groups when multiple OSes are installed
diskutil apfs listVolumeGroups
```
> [!WARNING]
> Verwende während eines Audits keine richtlinienändernden Optionen von `bputil`. Ein normaler macOS-Compromise sollte nicht in der Lage sein, die oben genannten Felder unbemerkt zu aktivieren: Der Downgrade-Pfad erfordert absichtlich physischen Zugriff auf das gekoppelte 1TR sowie eine Owner-Authentifizierung.<sup>[[4]](#references)</sup>

## Security Implications

### `boot-args` als Verstärker nach einem Compromise

Argumente wie Kernel-Debugging-Optionen, `kcsuffix=development` oder `amfi_get_out_of_my_way=1` können spätere Boot-Phasen schwächen, jedoch nur, wenn die Plattform sie akzeptiert. Auf Apple silicon filtert iBoot bei Full oder Reduced Security sicherheitsreduzierende Argumente; uneingeschränkte Argumente erfordern den oben beschriebenen `sip3`-Policy-Downgrade. Auf Intel verhindert die NVRAM-Beschränkung von SIP ebenfalls, dass eine root shell automatisch als Kontrolle über `boot-args` betrachtet wird.
```bash
# Enumerate, do not assume that a value shown here was accepted by iBoot
nvram boot-args 2>/dev/null

# Confirm what the running kernel reports it received
sysctl kern.bootargs

# Search for common security-reducing/debug strings
{ nvram boot-args 2>/dev/null; sysctl -n kern.bootargs 2>/dev/null; } |
grep -Ei 'amfi|cs_enforcement|debug|kcsuffix|keepsyms|ktrace|rc\.trampoline'
```
Siehe stattdessen [AMFI](../macos-security-protections/macos-amfi-applemobilefileintegrity.md) und [kernel debugging](macos-kernel-extensions.md), anstatt davon auszugehen, dass sich ein historisches Argument in jeder macOS-Version identisch verhält.

### Ausführung von NVRAM-gestütztem `rc.trampoline`

Aktuelle Untersuchungen dokumentierten einen konkreten Verbraucher von NVRAM-Daten: die Apple-Plattform-Binärdatei `/System/Library/CoreServices/rc.trampoline`. Wenn launchd das Boot-Argument `rc.trampoline=1` erkennt, liest diese Boot-Aufgabe die Eigenschaft `apple-trusted-trampoline` aus `IODeviceTree:/options`, schreibt sie in eine temporäre ausführbare Datei, startet diese angehalten, prüft ihren Code-Signierstatus, entfernt die Datei und setzt sie anschließend fort. Die Boot-Aufgabe blockiert launchd, bis der Kindprozess beendet wird.<sup>[[5]](#references)</sup>

Dies ist ein **Persistenz-Primitive nach einem Downgrade, kein SIP-Bypass**. Der demonstrierte Pfad erforderte, dass SIP deaktiviert war, damit die Boot-Aufgabe ausgeführt und `boot-args` gesetzt werden konnte. Die Untersuchung stellte außerdem eine ungefähre Obergrenze von 390 KB für die Größe des Werts fest. Der Nutzen besteht darin, dass ausführbare Bytes außerhalb des normalen Dateisystems gespeichert und während des Bootvorgangs materialisiert werden können, nachdem ein Angreifer bereits die erforderliche Sicherheitsabsenkung erlangt hat.<sup>[[5]](#references)</sup>

Suche nach beiden erforderlichen Artefakten und dem launchd-Ereignis:
```bash
# Print names only so a large binary value is not dumped to the terminal
nvram -p | cut -f1 | grep -E '^(apple-trusted-trampoline|boot-args)$'
nvram boot-args 2>/dev/null | grep -F 'rc.trampoline='

# The research-observed execution produces an rc.trampoline boot-task event
log show --last 30d --style compact \
--predicate 'eventMessage CONTAINS[c] "rc.trampoline"'
```
Beliebige benutzerdefinierte NVRAM-Variablen sind ansonsten nur **Speicher**: Sie führen nichts aus, solange sie nicht von der Firmware, einer Apple-Boot-Komponente oder einem separaten Persistence-Mechanismus verarbeitet werden. Diese Unterscheidung verhindert, dass ein Marker wie `nvram attacker-config=...` fälschlicherweise als Codeausführung durch die Firmware dargestellt wird.

## Enumeration-Skript

<details>
<summary>Audit der NVRAM- und Apple-Silicon-Boot-Richtlinien</summary>
```bash
#!/bin/bash
set -u

echo '=== NVRAM / boot-policy audit ==='
echo '[*] Architecture:'
uname -m

echo '[*] Effective SIP:'
csrutil status 2>&1

echo '[*] Stored and effective boot arguments:'
nvram boot-args 2>/dev/null || echo 'boot-args: <not set/readable>'
sysctl kern.bootargs 2>/dev/null || true

echo '[*] Intel SIP variable (absence on Apple silicon is expected):'
nvram csr-active-config 2>/dev/null || echo 'csr-active-config: <not set/readable>'

echo '[*] High-signal NVRAM names:'
nvram -p 2>/dev/null | cut -f1 |
grep -E '^(apple-trusted-trampoline|boot-args|csr-active-config|efi-boot-device(-data)?|boot-volume)$' || true

echo '[*] rc.trampoline log evidence:'
log show --last 30d --style compact \
--predicate 'eventMessage CONTAINS[c] "rc.trampoline"' 2>/dev/null | tail -20

if [[ "$(uname -m)" == 'arm64' ]] && command -v bputil >/dev/null; then
echo '[*] Apple silicon LocalPolicy (read-only display):'
bputil -d -j 2>&1
fi
```
</details>



## References

- [1] [Apple Platform Security Guide — Bootprozess](https://support.apple.com/guide/security/boot-process-secac71d5623/web)
- [2] [Apple Security Updates — NVRAM-bezogene CVEs](https://support.apple.com/en-us/HT201222)
- [3] [Duo Labs — Apple T2 Security](https://duo.com/labs/research/apple-t2-xpc)
- [4] [Apple Platform Security — Inhalt einer LocalPolicy-Datei für einen Mac mit Apple silicon](https://support.apple.com/guide/security/contents-a-localpolicy-file-mac-apple-silicon-secc745a0845/web)
- [5] [Beyond the good ol' LaunchAgents — Persistenz durch NVRAM mit apple-trusted-trampoline](https://theevilbit.github.io/beyond/beyond_0035/)
{{#include ../../../banners/hacktricks-training.md}}
