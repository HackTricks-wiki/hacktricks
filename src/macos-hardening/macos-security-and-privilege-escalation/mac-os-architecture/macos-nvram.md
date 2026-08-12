# macOS NVRAM

{{#include ../../../banners/hacktricks-training.md}}

## Taarifa za Msingi

**NVRAM** (Non-Volatile Random-Access Memory) huhifadhi firmware na hali ya awali ya kuwasha mfumo nje ya macOS filesystem ya kawaida. Athari yake kiusalama hutegemea variable na boot architecture:

| Variable | Madhumuni / umuhimu wa kiusalama |
|---|---|
| `boot-args` | Arguments zinazotolewa kwa kernel. Arguments za debug au zinazopunguza usalama huchujwa isipokuwa boot policy iruhusu. |
| `csr-active-config` | SIP bitmask kwenye Intel Macs. Kwenye Apple silicon, policy inayolingana huhifadhiwa katika `LocalPolicy` ya kila volume, na haiaminiki moja kwa moja kutoka kwenye variable hii. |
| `efi-boot-device` / `efi-boot-device-data` | Intel EFI boot target. |
| `boot-volume` | Hali ya uteuzi wa boot-volume kwenye Apple silicon. |
| `SystemAudioVolume`, `prev-lang:kbd` | Mifano ya settings za kawaida zinazoendelea kuhifadhiwa. |

Tofauti muhimu ni kati ya **data iliyohifadhiwa kwenye NVRAM** na **security policy inayokubaliwa na boot chain**. Kwenye Apple silicon, Secure Enclave husaini `LocalPolicy` ya kila boot-volume-group; nonce iliyohifadhiwa katika Secure Storage Component hutoa ulinzi dhidi ya replay. Kwa hiyo, kubadilisha NVRAM property yenye jina linalofanana hakubadilishi yenyewe boot policy inayokubaliwa.<sup>[[1]](#references)[[4]](#references)</sup>

## Kufikia NVRAM kutoka User Space

### Kusoma na Kukusanya Baseline
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
Usiainishe kila key usiyoijua kama ni malicious. Hardware, recoveryOS, updates, Find My na boot failures zote huunda variables zinazotegemea model na version. Linganisha capture na baseline ya awali kutoka kwenye **Mac hiyo hiyo**, na chukulia binary blobs zisizotarajiwa, boot selection iliyobadilika, au arguments zinazopunguza usalama kama dalili za kufuatilia, si uthibitisho wa compromise.

### Kuandika NVRAM

Root anaweza kuunda au kubadilisha variables nyingi za kawaida, lakini variables zilizolindwa hutegemea pia variable namespace, SIP, kernel rules za kila variable na Apple entitlements zilizowekewa vikwazo. Kwa hiyo, `sudo` kufanikiwa kwa custom key isiyo na madhara **hakuthibitishi** kwamba process inaweza kubadilisha `boot-args`, SIP au system-region variables.
```bash
# Harmless test variable (perform only on a disposable test host)
sudo nvram HTTest='persistence-value'
nvram HTTest
sudo nvram -d HTTest

# Delete one variable
sudo nvram -d variable-name
```
> [!CAUTION]
> Epuka `nvram -c` wakati wa testing: inaomba kufutwa kwa variables zote zinazoweza kufutwa na inaweza kubadilisha tabia ya boot/recovery. Baadhi ya variables zinapatikana kwa kernel pekee, zinalindwa na entitlement, hufichwa wakati wa kusomwa, au zinaweza kufutwa tu wakati wa NVRAM reset.

## NVRAM Entitlements and `CS_NVRAM_UNRESTRICTED`

Wakati wa exec, XNU hu-map `com.apple.rootless.restricted-nvram-variables.heritable` kwenye process flag **`CS_NVRAM_UNRESTRICTED`** (`0x00008000`). Hii si sawa na ordinary effective UID 0 check. Pia kuna private entitlements nyembamba zaidi kwa variables au operations mahususi.

Kagua entitlements badala ya kutegemea generic flags line inayochapishwa na `codesign`:
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
Wakati wa kukagua helper yenye privileges, fuatilia **utambulisho halisi wa client na njia ya request**. Bug ya **confused-deputy** katika service yenye entitlement inaweza kuwa na manufaa zaidi kuliko kuinvoke `nvram` moja kwa moja, lakini variable/operation inayoweza kufikiwa bado inaweza kuzuiwa na XNU.

## Hali ya Intel SIP dhidi ya Apple Silicon `LocalPolicy`

### Intel: `csr-active-config`

Kwenye Intel, `csr-active-config` hu-encode exceptions za `CSR_ALLOW_*`. Bit positions zinazohusika kwa kawaida ni:
```text
0x001  untrusted kexts                 0x002  unrestricted filesystem
0x004  task_for_pid                    0x008  kernel debugger
0x010  Apple-internal behavior         0x020  unrestricted DTrace
0x040  unrestricted NVRAM              0x080  device configuration
0x100  any recovery OS                 0x200  unapproved kexts
0x400  executable-policy override      0x800  unauthenticated root (SSV)
```
Soma setting inayotumika kwa `csrutil status`; output ghafi ya `nvram` inaweza kutumia byte za little-endian zilizo-encode kwa asilimia. Tazama [macOS SIP](../macos-security-protections/macos-sip.md) kwa maelezo kuhusu ulinzi na athari za bypass.
```bash
nvram csr-active-config 2>/dev/null
csrutil status
```
### Apple Silicon: kagua boot policy inayokubaliwa

Kwenye Apple silicon, `sip0` katika `LocalPolicy` iliyotiwa sahihi na Secure Enclave huhifadhi bits za policy ya SIP ambazo hapo awali zilihifadhiwa kwenye NVRAM. Sehemu nyingine muhimu za policy ni `sip1` (ruhusu kushindwa kwa uthibitishaji wa root-hash ya SSV), `sip2` (usifunge memory ya kernel kwa CTRR), na `sip3` (zima allowlist ya `boot-args` ya iBoot). Sehemu hizi zinaweza kubadilishwa tu kutoka kwenye One True recoveryOS (1TR) iliyooanishwa; kuwezesha `sip3` pia kunahitaji kushusha hadi Permissive Security.<sup>[[4]](#references)</sup>

Tumia operations za kuonyesha pekee wakati wa enumeration:
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
> Usitumie chaguo za kubadilisha policy za `bputil` wakati wa audit. Compromise ya kawaida ya macOS haipaswi kuwa na uwezo wa kuwasha fields zilizo hapo juu kimya kimya: njia ya downgrade inahitaji kwa makusudi kuingizwa kimwili kwenye 1TR iliyooanishwa pamoja na uthibitishaji wa owner.<sup>[[4]](#references)</sup>

## Athari za Usalama

### `boot-args` kama Amplifier wa Baada ya Compromise

Arguments kama chaguo za kernel-debugging, `kcsuffix=development`, au `amfi_get_out_of_my_way=1` zinaweza kudhoofisha hatua za baadaye za boot, lakini tu pale platform inapozikubali. Kwenye Apple silicon yenye Full au Reduced Security, iBoot huchuja arguments zinazopunguza usalama; arguments zisizo na vizuizi zinahitaji policy downgrade ya `sip3` iliyoelezwa hapo juu. Kwenye Intel, kizuizi cha NVRAM cha SIP vilevile huzuia kuchukulia root shell kama udhibiti wa moja kwa moja wa `boot-args`.
```bash
# Enumerate, do not assume that a value shown here was accepted by iBoot
nvram boot-args 2>/dev/null

# Confirm what the running kernel reports it received
sysctl kern.bootargs

# Search for common security-reducing/debug strings
{ nvram boot-args 2>/dev/null; sysctl -n kern.bootargs 2>/dev/null; } |
grep -Ei 'amfi|cs_enforcement|debug|kcsuffix|keepsyms|ktrace|rc\.trampoline'
```
Tazama [AMFI](../macos-security-protections/macos-amfi-applemobilefileintegrity.md) na [kernel debugging](macos-kernel-extensions.md) badala ya kudhani kuwa hoja ya kihistoria hufanya kazi kwa njia ileile kwenye kila toleo la macOS.

### Utekelezaji wa `rc.trampoline` unaotegemea NVRAM

Utafiti wa hivi karibuni uliandika consumer maalum wa data ya NVRAM: Apple platform binary `/System/Library/CoreServices/rc.trampoline`. launchd inapoona boot argument `rc.trampoline=1`, boot task hii husoma property ya `apple-trusted-trampoline` kutoka `IODeviceTree:/options`, huiandika kwenye executable ya muda, huianzisha ikiwa suspended, hukagua hali yake ya code-signing, huiondoa kwa unlink na kisha huiendeleza. Boot task huzuia launchd hadi child imalize.<sup>[[5]](#references)</sup>

Hii ni **post-downgrade persistence primitive, si SIP bypass**. Njia iliyoonyeshwa ilihitaji SIP izimwe ili boot task iendeshe na `boot-args` iweze kuwekwa. Utafiti pia ulibaini ceiling ya takribani KB 390 kwa ukubwa wa value. Umuhimu wake ni kwamba executable bytes zinaweza kuwekwa nje ya filesystem ya kawaida na kutengenezwa wakati wa boot baada ya attacker kuwa tayari amepata security downgrade inayohitajika.<sup>[[5]](#references)</sup>

Tafuta artifacts zote mbili zinazohitajika pamoja na launchd event:
```bash
# Print names only so a large binary value is not dumped to the terminal
nvram -p | cut -f1 | grep -E '^(apple-trusted-trampoline|boot-args)$'
nvram boot-args 2>/dev/null | grep -F 'rc.trampoline='

# The research-observed execution produces an rc.trampoline boot-task event
log show --last 30d --style compact \
--predicate 'eventMessage CONTAINS[c] "rc.trampoline"'
```
Arbitrary custom NVRAM variables are otherwise only **uhifadhi**: hazitekelezi chochote isipokuwa firmware, Apple boot component, au persistence mechanism tofauti izitumie. Tofauti hii huepuka kutia chumvi alama kama `nvram attacker-config=...` kana kwamba ni utekelezaji wa code ya firmware.

## Script ya Enumeration

<details>
<summary>Ukaguzi wa NVRAM na boot-policy ya Apple silicon</summary>
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

- [1] [Apple Platform Security Guide — Mchakato wa boot](https://support.apple.com/guide/security/boot-process-secac71d5623/web)
- [2] [Apple Security Updates — CVEs zinazohusiana na NVRAM](https://support.apple.com/en-us/HT201222)
- [3] [Duo Labs — Usalama wa Apple T2](https://duo.com/labs/research/apple-t2-xpc)
- [4] [Apple Platform Security — Yaliyomo kwenye faili ya LocalPolicy ya Mac yenye Apple silicon](https://support.apple.com/guide/security/contents-a-localpolicy-file-mac-apple-silicon-secc745a0845/web)
- [5] [Zaidi ya LaunchAgents za zamani — Persist kupitia NVRAM kwa apple-trusted-trampoline](https://theevilbit.github.io/beyond/beyond_0035/)
{{#include ../../../banners/hacktricks-training.md}}
