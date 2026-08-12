# macOS NVRAM

{{#include ../../../banners/hacktricks-training.md}}

## Informazioni di base

**NVRAM** (Non-Volatile Random-Access Memory) memorizza il firmware e lo stato della fase di avvio iniziale al di fuori del normale filesystem di macOS. Il suo impatto sulla sicurezza dipende sia dalla variabile sia dall'architettura di avvio:

| Variabile | Scopo / rilevanza per la sicurezza |
|---|---|
| `boot-args` | Argomenti forniti al kernel. Gli argomenti di debug o quelli che riducono la sicurezza vengono filtrati, a meno che la boot policy non ne consenta l'uso. |
| `csr-active-config` | Bitmask di SIP sui Mac Intel. Sui Mac con Apple silicon, la policy equivalente è contenuta nella `LocalPolicy` specifica del volume e non viene considerata attendibile direttamente da questa variabile. |
| `efi-boot-device` / `efi-boot-device-data` | Target di avvio EFI sui Mac Intel. |
| `boot-volume` | Stato di selezione del volume di avvio sui Mac con Apple silicon. |
| `SystemAudioVolume`, `prev-lang:kbd` | Esempi di impostazioni persistenti ordinarie. |

La distinzione importante è tra i **dati memorizzati nella NVRAM** e una **security policy accettata dalla boot chain**. Sui Mac con Apple silicon, il Secure Enclave firma una `LocalPolicy` specifica per ogni gruppo di volumi di avvio; un nonce conservato nel Secure Storage Component fornisce protezione dal replay. Di conseguenza, la modifica di una proprietà NVRAM con un nome simile non riscrive di per sé la boot policy accettata.<sup>[[1]](#references)[[4]](#references)</sup>

## Accesso alla NVRAM dallo spazio utente

### Lettura e raccolta della baseline
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
Non classificare ogni chiave sconosciuta come dannosa. Hardware, recoveryOS, aggiornamenti, Find My e gli errori di avvio creano tutti variabili dipendenti dal modello e dalla versione. Confronta un'acquisizione con una baseline precedente dello **stesso Mac** e considera i blob binari imprevisti, la selezione di avvio modificata o gli argomenti che riducono la sicurezza come indizi, non come prova di compromissione.

### Scrittura della NVRAM

Root può creare o modificare molte variabili ordinarie, ma le variabili protette dipendono inoltre dal namespace della variabile, da SIP, dalle regole del kernel specifiche per variabile e dagli entitlement Apple con restrizioni. Pertanto, il successo di `sudo` per una chiave personalizzata innocua **non** dimostra che il processo possa modificare `boot-args`, SIP o le variabili della system-region.
```bash
# Harmless test variable (perform only on a disposable test host)
sudo nvram HTTest='persistence-value'
nvram HTTest
sudo nvram -d HTTest

# Delete one variable
sudo nvram -d variable-name
```
> [!CAUTION]
> Evita `nvram -c` durante i test: richiede l'eliminazione di tutte le variabili eliminabili e può modificare il comportamento di avvio/ripristino. Alcune variabili sono solo kernel, protette da entitlement, nascoste durante la lettura o eliminabili solo durante un reset NVRAM.

## Entitlement NVRAM e `CS_NVRAM_UNRESTRICTED`

Al momento dell'exec, XNU associa `com.apple.rootless.restricted-nvram-variables.heritable` al flag di processo **`CS_NVRAM_UNRESTRICTED`** (`0x00008000`). Questo non equivale al normale controllo dell'UID effettivo 0. Esistono inoltre entitlement private più specifici per determinate variabili o operazioni.

Ispeziona gli entitlement invece di fare affidamento sulla riga generica dei flags stampata da `codesign`:
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
Quando esegui l’audit di un **privileged helper**, traccia l’**identità effettiva del client e il percorso della richiesta**. Un bug di tipo **confused-deputy** in un servizio con entitlement può essere più utile dell’invocazione diretta di `nvram`, ma la variabile o l’operazione raggiungibile potrebbe essere comunque limitata da XNU.

## Stato SIP su Intel vs `LocalPolicy` su Apple Silicon

### Intel: `csr-active-config`

Su Intel, `csr-active-config` codifica le eccezioni `CSR_ALLOW_*`. Le posizioni dei bit comunemente rilevanti sono:
```text
0x001  untrusted kexts                 0x002  unrestricted filesystem
0x004  task_for_pid                    0x008  kernel debugger
0x010  Apple-internal behavior         0x020  unrestricted DTrace
0x040  unrestricted NVRAM              0x080  device configuration
0x100  any recovery OS                 0x200  unapproved kexts
0x400  executable-policy override      0x800  unauthenticated root (SSV)
```
Leggi l'impostazione effettiva con `csrutil status`; l'output grezzo di `nvram` può utilizzare byte little-endian codificati in percentuale. Consulta [macOS SIP](../macos-security-protections/macos-sip.md) per le implicazioni relative alla protezione e ai bypass.
```bash
nvram csr-active-config 2>/dev/null
csrutil status
```
### Apple Silicon: esaminare la boot policy accettata

Su Apple silicon, `sip0` nella `LocalPolicy` firmata dal Secure Enclave contiene i bit della policy SIP precedentemente archiviati in NVRAM. Gli altri campi della policy rilevanti sono `sip1` (consentire un errore nella verifica del root hash di un SSV), `sip2` (non bloccare la memoria del kernel con CTRR) e `sip3` (disabilitare l'allowlist `boot-args` di iBoot). Questi campi sono modificabili solo da una paired One True recoveryOS (1TR); l'abilitazione di `sip3` richiede inoltre un downgrade a Permissive Security.<sup>[[4]](#references)</sup>

Usare solo le operazioni di visualizzazione durante l'enumerazione:
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
> Non usare le opzioni di `bputil` che modificano le policy durante un audit. Un normale compromesso di macOS non dovrebbe poter attivare silenziosamente i campi sopra indicati: il percorso di downgrade richiede deliberatamente l'accesso fisico a 1TR associato e l'autenticazione del proprietario.<sup>[[4]](#references)</sup>

## Implicazioni di sicurezza

### `boot-args` come amplificatore post-compromissione

Argomenti come le opzioni di kernel-debugging, `kcsuffix=development` o `amfi_get_out_of_my_way=1` possono indebolire le fasi successive del boot, ma solo quando la piattaforma li accetta. Sui dispositivi Apple silicon con Full o Reduced Security, iBoot filtra gli argomenti che riducono la sicurezza; gli argomenti senza restrizioni richiedono il downgrade della policy `sip3` descritto sopra. Su Intel, la restrizione NVRAM di SIP impedisce analogamente di considerare una root shell come controllo automatico di `boot-args`.
```bash
# Enumerate, do not assume that a value shown here was accepted by iBoot
nvram boot-args 2>/dev/null

# Confirm what the running kernel reports it received
sysctl kern.bootargs

# Search for common security-reducing/debug strings
{ nvram boot-args 2>/dev/null; sysctl -n kern.bootargs 2>/dev/null; } |
grep -Ei 'amfi|cs_enforcement|debug|kcsuffix|keepsyms|ktrace|rc\.trampoline'
```
Consulta [AMFI](../macos-security-protections/macos-amfi-applemobilefileintegrity.md) e il [kernel debugging](macos-kernel-extensions.md) invece di presumere che un argomento storico si comporti in modo identico in ogni release di macOS.

### Esecuzione di `rc.trampoline` supportata da NVRAM

Ricerche recenti hanno documentato un consumer concreto dei dati NVRAM: il platform binary Apple `/System/Library/CoreServices/rc.trampoline`. Quando launchd rileva l'argomento di boot `rc.trampoline=1`, questo boot task legge la proprietà `apple-trusted-trampoline` da `IODeviceTree:/options`, la scrive in un eseguibile temporaneo, lo avvia in stato sospeso, verifica il relativo stato code-signing, lo scollega e quindi lo riprende. Il boot task blocca launchd fino all'uscita del child.<sup>[[5]](#references)</sup>

Questa è una **post-downgrade persistence primitive, non un SIP bypass**. Il percorso dimostrato richiedeva che SIP fosse disabilitato, in modo che il boot task venisse eseguito e che `boot-args` potesse essere impostato. La ricerca ha inoltre osservato un limite approssimativo di 390 KB per la dimensione del valore. La sua utilità consiste nel fatto che i byte dell'eseguibile possono risiedere al di fuori del filesystem normale ed essere materializzati durante il boot dopo che un attacker ha già ottenuto il downgrade di sicurezza richiesto.<sup>[[5]](#references)</sup>

Cerca entrambi gli artifact richiesti e l'evento di launchd:
```bash
# Print names only so a large binary value is not dumped to the terminal
nvram -p | cut -f1 | grep -E '^(apple-trusted-trampoline|boot-args)$'
nvram boot-args 2>/dev/null | grep -F 'rc.trampoline='

# The research-observed execution produces an rc.trampoline boot-task event
log show --last 30d --style compact \
--predicate 'eventMessage CONTAINS[c] "rc.trampoline"'
```
Le variabili NVRAM personalizzate arbitrarie sono altrimenti solo **storage**: non eseguono nulla a meno che il firmware, un componente di avvio Apple o un meccanismo di persistenza separato non le utilizzi. Questa distinzione evita di presentare in modo eccessivo un marker come `nvram attacker-config=...` come esecuzione di codice firmware.

## Script di enumerazione

<details>
<summary>Audit di NVRAM e della boot-policy Apple silicon</summary>
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

- [1] [Apple Platform Security Guide — Processo di avvio](https://support.apple.com/guide/security/boot-process-secac71d5623/web)
- [2] [Apple Security Updates — CVE relativi a NVRAM](https://support.apple.com/en-us/HT201222)
- [3] [Duo Labs — Sicurezza Apple T2](https://duo.com/labs/research/apple-t2-xpc)
- [4] [Apple Platform Security — Contenuto di un file LocalPolicy per un Mac con Apple silicon](https://support.apple.com/guide/security/contents-a-localpolicy-file-mac-apple-silicon-secc745a0845/web)
- [5] [Oltre i vecchi cari LaunchAgents — Persistenza tramite NVRAM con apple-trusted-trampoline](https://theevilbit.github.io/beyond/beyond_0035/)
{{#include ../../../banners/hacktricks-training.md}}
