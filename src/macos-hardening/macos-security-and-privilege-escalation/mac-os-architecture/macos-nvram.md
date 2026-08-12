# macOS NVRAM

{{#include ../../../banners/hacktricks-training.md}}

## Basiese Inligting

**NVRAM** (Non-Volatile Random-Access Memory) stoor firmware en vroeë-boottoestand buite die normale macOS-lêerstelsel. Die sekuriteitsimpak daarvan hang af van beide die veranderlike en die bootargitektuur:

| Veranderlike | Doel / sekuriteitsrelevansie |
|---|---|
| `boot-args` | Argumente wat aan die kernel gebied word. Debug- of sekuriteitsverminderende argumente word gefiltreer, tensy die boot policy dit toelaat. |
| `csr-active-config` | SIP-bitmasker op Intel Macs. Op Apple silicon word die ekwivalente policy in die per-volume `LocalPolicy` gestoor en nie direk vanaf hierdie veranderlike vertrou nie. |
| `efi-boot-device` / `efi-boot-device-data` | Intel EFI-bootteiken. |
| `boot-volume` | Apple silicon se toestand vir boot-volume-seleksie. |
| `SystemAudioVolume`, `prev-lang:kbd` | Voorbeelde van gewone persistente instellings. |

Die belangrike onderskeid is tussen **data wat in NVRAM gestoor word** en ’n **sekuriteitspolicy wat deur die boot chain aanvaar word**. Op Apple silicon onderteken die Secure Enclave ’n per-boot-volumegroep `LocalPolicy`; ’n nonce wat in die Secure Storage Component gehou word, bied anti-replay. Gevolglik herskryf die verandering van ’n NVRAM-eienskap met ’n soortgelyke naam nie op sigself die aanvaarde boot policy nie.<sup>[[1]](#references)[[4]](#references)</sup>

## NVRAM-toegang vanaf Gebruikersruimte

### Lees en Baseline-insameling
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
Moenie elke onbekende sleutel as kwaadwillig klassifiseer nie. Hardware, recoveryOS, updates, Find My en selflaaifoute skep almal model- en weergawe-afhanklike veranderlikes. Vergelyk ’n capture met ’n vroeëre basislyn van **dieselfde Mac**, en beskou onverwagte binary blobs, veranderde selflaaiseleksie of sekuriteitverlagende argumente as leidrade eerder as bewys van kompromittering.

### Skryf na NVRAM

Root kan baie gewone veranderlikes skep of verander, maar beskermde veranderlikes hang ook af van die veranderlikenaamruimte, SIP, kernreëls per veranderlike en beperkte Apple-entitlements. Daarom bewys `sudo` wat vir ’n onskadelike pasgemaakte sleutel slaag **nie** dat die proses `boot-args`, SIP of stelselstreekveranderlikes kan wysig nie.
```bash
# Harmless test variable (perform only on a disposable test host)
sudo nvram HTTest='persistence-value'
nvram HTTest
sudo nvram -d HTTest

# Delete one variable
sudo nvram -d variable-name
```
> [!CAUTION]
> Vermy `nvram -c` tydens testing: dit versoek die verwydering van alle verwyderbare veranderlikes en kan boot-/recovery-gedrag verander. Sommige veranderlikes is slegs vir die kernel, word deur entitlements beskerm, word tydens lees versteek, of kan slegs tydens ’n NVRAM-reset verwyder word.

## NVRAM Entitlements en `CS_NVRAM_UNRESTRICTED`

Tydens exec-tyd karteer XNU `com.apple.rootless.restricted-nvram-variables.heritable` na die prosesvlag **`CS_NVRAM_UNRESTRICTED`** (`0x00008000`). Dit is nie gelykstaande aan die gewone kontrole van effektiewe UID 0 nie. Daar is ook nouer private entitlements vir spesifieke veranderlikes of operasies.

Inspekteer die entitlements eerder as om op die generiese flags-reël wat deur `codesign` gedruk word, staat te maak:
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
Wanneer jy ’n privileged helper oudit, volg die **werklike kliëntidentiteit en request path**. ’n Confused-deputy-bug in ’n entitled service kan nuttiger wees as om `nvram` direk aan te roep, maar die veranderlike/operasie wat bereikbaar is, kan steeds deur XNU beperk word.

## Intel SIP-toestand vs Apple Silicon `LocalPolicy`

### Intel: `csr-active-config`

Op Intel enkodeer `csr-active-config` die `CSR_ALLOW_*`-uitsonderings. Die algemeen relevante bitposisies is:
```text
0x001  untrusted kexts                 0x002  unrestricted filesystem
0x004  task_for_pid                    0x008  kernel debugger
0x010  Apple-internal behavior         0x020  unrestricted DTrace
0x040  unrestricted NVRAM              0x080  device configuration
0x100  any recovery OS                 0x200  unapproved kexts
0x400  executable-policy override      0x800  unauthenticated root (SSV)
```
Lees die effektiewe instelling met `csrutil status`; rou `nvram`-uitset kan persentasie-geënkodeerde little-endian-grepe gebruik. Sien [macOS SIP](../macos-security-protections/macos-sip.md) vir die beskermings- en bypass-implikasies.
```bash
nvram csr-active-config 2>/dev/null
csrutil status
```
### Apple Silicon: inspekteer die aanvaarde boot policy

Op Apple silicon bevat `sip0` in die Secure Enclave-ondertekende `LocalPolicy` die SIP-beleidsbisse wat voorheen in NVRAM gestoor is. Die ander relevante beleidsvelde is `sip1` (laat ’n SSV root-hash-verifikasiefout toe), `sip2` (moenie kernel-geheue met CTRR sluit nie), en `sip3` (deaktiveer iBoot se `boot-args`-allowlist). Hierdie velde kan slegs vanaf gepaarde One True recoveryOS (1TR) verander word; om `sip3` te aktiveer, vereis ook ’n downgrade na Permissive Security.<sup>[[4]](#references)</sup>

Gebruik slegs die display-bewerkings tydens enumerasie:
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
> Moenie `bputil`-opsies wat beleide verander tydens ’n oudit gebruik nie. ’n Normale macOS-kompromittering behoort nie die bogenoemde velde stilweg te kan aktiveer nie: die afgraderingspad vereis doelbewus fisiese toegang tot gepaarde 1TR en eienaarverifikasie.<sup>[[4]](#references)</sup>

## Sekuriteitsimplikasies

### `boot-args` as ’n Versterker ná Kompromittering

Argumente soos kernelfoutopsporingsopsies, `kcsuffix=development`, of `amfi_get_out_of_my_way=1` kan latere selflaaistadiums verswak, maar slegs wanneer die platform dit aanvaar. Op Apple silicon, in Full of Reduced Security, filter iBoot sekuriteitsverlagende argumente; onbeperkte argumente vereis die `sip3`-beleidsafgradering wat hierbo beskryf word. Op Intel voorkom SIP se NVRAM-beperking insgelyks dat ’n root-shell outomatiese beheer oor `boot-args` beteken.
```bash
# Enumerate, do not assume that a value shown here was accepted by iBoot
nvram boot-args 2>/dev/null

# Confirm what the running kernel reports it received
sysctl kern.bootargs

# Search for common security-reducing/debug strings
{ nvram boot-args 2>/dev/null; sysctl -n kern.bootargs 2>/dev/null; } |
grep -Ei 'amfi|cs_enforcement|debug|kcsuffix|keepsyms|ktrace|rc\.trampoline'
```
Sien eerder [AMFI](../macos-security-protections/macos-amfi-applemobilefileintegrity.md) en [kernel debugging](macos-kernel-extensions.md) as om aan te neem dat ’n historiese argument op elke macOS-vrystelling identies optree.

### NVRAM-backed `rc.trampoline` Execution

Onlangse navorsing het ’n konkrete verbruiker van NVRAM-data gedokumenteer: die Apple-platformbinêre `/System/Library/CoreServices/rc.trampoline`. Wanneer launchd die `rc.trampoline=1`-boot-argument sien, lees hierdie boot-taak die `apple-trusted-trampoline`-eienskap vanaf `IODeviceTree:/options`, skryf dit na ’n tydelike uitvoerbare lêer, begin dit suspended, kontroleer die code-signing-status daarvan, ontkoppel dit en hervat dit dan. Die boot-taak blokkeer launchd totdat die child afsluit.<sup>[[5]](#references)</sup>

Dit is ’n **post-downgrade persistence primitive, nie ’n SIP bypass nie**. Die gedemonstreerde pad het vereis dat SIP gedeaktiveer is sodat die boot-taak kon loop en `boot-args` gestel kon word. Die navorsing het ook ’n benaderde limiet van 390 KB vir die waarde-grootte waargeneem. Die waarde daarvan is dat uitvoerbare grepe buite die normale lêerstelsel kan bestaan en tydens boot gematerialiseer kan word nadat ’n aanvaller reeds die vereiste security downgrade verkry het.<sup>[[5]](#references)</sup>

Soek na albei vereiste artefakte en die launchd-gebeurtenis:
```bash
# Print names only so a large binary value is not dumped to the terminal
nvram -p | cut -f1 | grep -E '^(apple-trusted-trampoline|boot-args)$'
nvram boot-args 2>/dev/null | grep -F 'rc.trampoline='

# The research-observed execution produces an rc.trampoline boot-task event
log show --last 30d --style compact \
--predicate 'eventMessage CONTAINS[c] "rc.trampoline"'
```
Arbitrêre pasgemaakte NVRAM-veranderlikes is andersins slegs **storage**: hulle voer niks uit nie, tensy firmware, ’n Apple boot-komponent of ’n afsonderlike persistence-meganisme dit verwerk. Hierdie onderskeid voorkom dat ’n merker soos `nvram attacker-config=...` oorgewaardeer word as firmware code execution.

## Enumerasie-skrip

<details>
<summary>NVRAM- en Apple silicon boot-policy-oudit</summary>
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

- [1] [Apple Platform Security Guide — Opstartproses](https://support.apple.com/guide/security/boot-process-secac71d5623/web)
- [2] [Apple Security Updates — NVRAM-verwante CVE's](https://support.apple.com/en-us/HT201222)
- [3] [Duo Labs — Apple T2-sekuriteit](https://duo.com/labs/research/apple-t2-xpc)
- [4] [Apple Platform Security — Inhoud van 'n LocalPolicy-lêer vir 'n Mac met Apple silicon](https://support.apple.com/guide/security/contents-a-localpolicy-file-mac-apple-silicon-secc745a0845/web)
- [5] [Beyond the goeie ou LaunchAgents — Behou persistence deur NVRAM met apple-trusted-trampoline](https://theevilbit.github.io/beyond/beyond_0035/)
{{#include ../../../banners/hacktricks-training.md}}
