# macOS NVRAM

{{#include ../../../banners/hacktricks-training.md}}

## Osnovne informacije

**NVRAM** (Non-Volatile Random-Access Memory) čuva firmware i stanje ranog pokretanja sistema izvan uobičajenog macOS sistema datoteka. Njegov bezbednosni uticaj zavisi i od promenljive i od boot arhitekture:

| Promenljiva | Namena / bezbednosni značaj |
|---|---|
| `boot-args` | Argumenti prosleđeni kernelu. Argumenti za debug ili oni koji smanjuju bezbednost filtriraju se osim ako ih boot policy dozvoljava. |
| `csr-active-config` | SIP bitmask na Intel Mac računarima. Na Apple silicon računarima ekvivalentna policy se čuva u `LocalPolicy` po volumenu i ne veruje se direktno ovoj promenljivoj. |
| `efi-boot-device` / `efi-boot-device-data` | Intel EFI boot odredište. |
| `boot-volume` | Stanje izbora boot volumena na Apple silicon računarima. |
| `SystemAudioVolume`, `prev-lang:kbd` | Primeri uobičajenih trajnih podešavanja. |

Važna je razlika između **podataka uskladištenih u NVRAM-u** i **security policy koju prihvata boot lanac**. Na Apple silicon računarima, Secure Enclave potpisuje `LocalPolicy` za svaku grupu boot volumena; nonce koji čuva Secure Storage Component obezbeđuje zaštitu od replay napada. Zbog toga promena NVRAM svojstva sa sličnim nazivom sama po sebi ne menja prihvaćenu boot policy.<sup>[[1]](#references)[[4]](#references)</sup>

## Pristup NVRAM-u iz korisničkog prostora

### Čitanje i prikupljanje početnog stanja
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
Ne klasifikujte svaki nepoznati ključ kao zlonameran. Hardver, recoveryOS, ažuriranja, Find My i neuspešna pokretanja sistema stvaraju promenljive zavisne od modela i verzije. Uporedite snimak sa ranijom osnovom sa **istog Mac računara** i tretirajte neočekivane binarne blokove, promenjen izbor pokretanja ili argumente koji smanjuju bezbednost kao tragove, a ne kao dokaz kompromitovanja.

### Pisanje NVRAM-a

Root može da kreira ili menja mnoge uobičajene promenljive, ali zaštićene promenljive dodatno zavise od namespace-a promenljive, SIP-a, kernel pravila za pojedinačne promenljive i ograničenih Apple entitlements. Zato uspešno izvršavanje `sudo` za bezopasan prilagođeni ključ **ne** dokazuje da proces može da menja `boot-args`, SIP ili promenljive iz sistemskog regiona.
```bash
# Harmless test variable (perform only on a disposable test host)
sudo nvram HTTest='persistence-value'
nvram HTTest
sudo nvram -d HTTest

# Delete one variable
sudo nvram -d variable-name
```
> [!CAUTION]
> Izbegavajte `nvram -c` tokom testiranja: zahteva brisanje svih promenljivih koje se mogu obrisati i može promeniti ponašanje pri pokretanju sistema ili oporavku. Neke promenljive su dostupne samo kernelu, zaštićene entitlement-om, skrivene prilikom čitanja ili se mogu obrisati samo tokom NVRAM resetovanja.

## NVRAM Entitlements i `CS_NVRAM_UNRESTRICTED`

Prilikom exec-a, XNU mapira `com.apple.rootless.restricted-nvram-variables.heritable` na oznaku procesa **`CS_NVRAM_UNRESTRICTED`** (`0x00008000`). Ovo nije ekvivalent uobičajenoj proveri efektivnog UID-a 0. Postoje i uži privatni entitlements za određene promenljive ili operacije.

Proverite entitlements umesto da se oslanjate na generičku liniju sa zastavicama koju ispisuje `codesign`:
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
Prilikom auditovanja **privileged helper** komponente, pratite **stvarni identitet klijenta i putanju zahteva**. **confused-deputy** bug u servisu sa odgovarajućim entitlement-om može biti korisniji od direktnog pozivanja `nvram`, ali XNU i dalje može ograničavati dostupnu promenljivu/operaciju.

## Intel SIP State naspram Apple Silicon `LocalPolicy`

### Intel: `csr-active-config`

Na Intel-u, `csr-active-config` kodira `CSR_ALLOW_*` izuzetke. Uobičajeno relevantne pozicije bitova su:
```text
0x001  untrusted kexts                 0x002  unrestricted filesystem
0x004  task_for_pid                    0x008  kernel debugger
0x010  Apple-internal behavior         0x020  unrestricted DTrace
0x040  unrestricted NVRAM              0x080  device configuration
0x100  any recovery OS                 0x200  unapproved kexts
0x400  executable-policy override      0x800  unauthenticated root (SSV)
```
Pročitajte aktivno podešavanje pomoću `csrutil status`; sirovi izlaz komande `nvram` može koristiti percent-enkodovane little-endian bajtove. Pogledajte [macOS SIP](../macos-security-protections/macos-sip.md) za informacije o zaštiti i implikacijama zaobilaženja.
```bash
nvram csr-active-config 2>/dev/null
csrutil status
```
### Apple Silicon: provera prihvaćene politike pokretanja

Na uređajima sa Apple silicon, `sip0` u `LocalPolicy` potpisanom od strane Secure Enclave-a sadrži bitove SIP politike koji su se ranije čuvali u NVRAM-u. Druga relevantna polja politike su `sip1` (dozvoljava neuspeh verifikacije root-hash vrednosti SSV-a), `sip2` (ne zaključava kernel memoriju pomoću CTRR-a) i `sip3` (onemogućava iBoot-ovu allowlistu za `boot-args`). Ova polja mogu da se menjaju samo iz uparenog One True recoveryOS-a (1TR); omogućavanje opcije `sip3` takođe zahteva prelazak na Permissive Security.<sup>[[4]](#references)</sup>

Tokom enumeracije koristite samo operacije za prikaz:
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
> Nemojte koristiti opcije `bputil` koje menjaju policy tokom audita. Uobičajeni macOS kompromis ne bi trebalo da može nečujno da uključi navedena polja: putanja za downgrade namerno zahteva fizički pristup u upareni 1TR i autentifikaciju vlasnika.<sup>[[4]](#references)</sup>

## Security Implications

### `boot-args` kao pojačivač nakon kompromitovanja

Argumenti kao što su opcije za kernel debugging, `kcsuffix=development` ili `amfi_get_out_of_my_way=1` mogu oslabiti kasnije faze boot procesa, ali samo kada ih platforma prihvati. Na Apple silicon uređajima sa Full ili Reduced Security, iBoot filtrira argumente koji smanjuju bezbednost; unrestricted argumenti zahtevaju prethodno opisani downgrade `sip3` policy-ja. Na Intel uređajima, SIP-ovo ograničenje NVRAM-a na sličan način sprečava da se root shell tretira kao automatska kontrola nad `boot-args`.
```bash
# Enumerate, do not assume that a value shown here was accepted by iBoot
nvram boot-args 2>/dev/null

# Confirm what the running kernel reports it received
sysctl kern.bootargs

# Search for common security-reducing/debug strings
{ nvram boot-args 2>/dev/null; sysctl -n kern.bootargs 2>/dev/null; } |
grep -Ei 'amfi|cs_enforcement|debug|kcsuffix|keepsyms|ktrace|rc\.trampoline'
```
Pogledajte [AMFI](../macos-security-protections/macos-amfi-applemobilefileintegrity.md) i [kernel debugging](macos-kernel-extensions.md), umesto da pretpostavite da se istorijski argument ponaša identično u svakom macOS izdanju.

### Izvršavanje `rc.trampoline` podržano pomoću NVRAM-a

Nedavna istraživanja dokumentovala su konkretnog potrošača NVRAM podataka: Apple platform binary `/System/Library/CoreServices/rc.trampoline`. Kada launchd vidi boot argument `rc.trampoline=1`, ovaj boot task čita property `apple-trusted-trampoline` iz `IODeviceTree:/options`, upisuje ga u privremeni executable, pokreće ga suspendovanog, proverava njegovo code-signing stanje, unlinkuje ga, a zatim ga nastavlja. Boot task blokira launchd dok se child ne završi.<sup>[[5]](#references)</sup>

Ovo je **post-downgrade persistence primitive, a ne SIP bypass**. Demonstrirani put zahtevao je da SIP bude onemogućen kako bi se boot task pokrenuo i kako bi `boot-args` mogao da bude postavljen. Istraživanje je takođe utvrdilo približno ograničenje veličine vrednosti od 390 KB. Njegova vrednost je u tome što executable bytes mogu postojati izvan uobičajenog filesystem-a i biti materijalizovani tokom boot-a nakon što je attacker već dobio zahtevani security downgrade.<sup>[[5]](#references)</sup>

Tražite oba zahtevana artifact-a i launchd event:
```bash
# Print names only so a large binary value is not dumped to the terminal
nvram -p | cut -f1 | grep -E '^(apple-trusted-trampoline|boot-args)$'
nvram boot-args 2>/dev/null | grep -F 'rc.trampoline='

# The research-observed execution produces an rc.trampoline boot-task event
log show --last 30d --style compact \
--predicate 'eventMessage CONTAINS[c] "rc.trampoline"'
```
Arbitrary custom NVRAM variables are otherwise only **skladište**: ne izvršavaju ništa osim ako ih firmware, Apple boot komponenta ili zaseban persistence mehanizam ne koristi. Ova razlika sprečava preuveličavanje markera kao što je `nvram attacker-config=...` u firmware code execution.

## Skripta za enumeraciju

<details>
<summary>Revizija NVRAM-a i boot-policy-ja za Apple silicon</summary>
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

- [1] [Apple vodič za bezbednost platforme — Proces pokretanja](https://support.apple.com/guide/security/boot-process-secac71d5623/web)
- [2] [Apple bezbednosna ažuriranja — CVE-ovi povezani sa NVRAM-om](https://support.apple.com/en-us/HT201222)
- [3] [Duo Labs — Apple T2 bezbednost](https://duo.com/labs/research/apple-t2-xpc)
- [4] [Apple bezbednost platforme — Sadržaj LocalPolicy datoteke za Mac sa Apple silicon](https://support.apple.com/guide/security/contents-a-localpolicy-file-mac-apple-silicon-secc745a0845/web)
- [5] [Iza dobrih starih LaunchAgents — Održavanje postojanosti kroz NVRAM pomoću apple-trusted-trampoline](https://theevilbit.github.io/beyond/beyond_0035/)
{{#include ../../../banners/hacktricks-training.md}}
