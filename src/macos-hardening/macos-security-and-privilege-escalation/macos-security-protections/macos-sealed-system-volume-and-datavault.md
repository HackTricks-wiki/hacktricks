# macOS Sealed System Volume i DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Sealed System Volume (SSV)

### Osnovne informacije

Počevši od **macOS Big Sur (11.0)**, sistemski volumen je kriptografski zapečaćen pomoću **APFS snapshot hash tree**. Ovo se naziva **Sealed System Volume (SSV)**. Sistemska particija se montira kao **read-only**, a svaka izmena narušava pečat, što se proverava tokom pokretanja sistema.<sup>[[11]](#references)</sup>

SSV obezbeđuje:
- **Detekciju neovlašćenih izmena** — svaka izmena sistemskih binarnih datoteka/frameworka menja koren Merkle stabla i poništava pečat koji je potpisao Apple
- **Autentikaciju tokom pokretanja** — lanac pokretanja proverava izabrani system snapshot pre nego što on postane root filesystem
- **Otpornost na rootkit** — čak ni root ne može trajno da zameni datoteke u autentifikovanom system snapshot-u bez onemogućavanja authenticated root-a ili kompromitovanja autorizovanog puta za ažuriranje

SSV štiti volumen **System**, a ne upisivi volumen **Data** uparen s njim. Firmlink-ovi spajaju oba volumena u namespace vidljiv na `/`, pa putanja koja izgleda kao upisiva ne dokazuje da osnovni objekat pripada zapečaćenom snapshot-u. FileVault i Data Protection štite poverljivost podataka u stanju mirovanja; oni su odvojeni od SSV integriteta.<sup>[[11]](#references)</sup>

### Provera statusa SSV
```bash
# Check if authenticated root is enabled (SSV seal verification)
csrutil authenticated-root status

# List APFS snapshots (the sealed snapshot is the boot volume)
diskutil apfs listSnapshots disk3s1

# Check mount status (should show read-only)
mount | grep " / "

# Show the volume group and the current Sealed field
diskutil apfs listVolumeGroups
diskutil apfs list | grep -B 8 -A 8 'Sealed:'
```
### Efektivni prikaz sistema: SSV + Cryptex grafts

Na novijim izdanjima macOS-a, nije svaka izvršna datoteka vidljiva ispod `/System` nužno deo snapshot-a pokrenutog SSV-a. **Cryptexes** su zasebne autentifikovane APFS diskovne slike čiji se sadržaj graftuje preko odabranih direktorijuma; Rapid Security Responses zato mogu zameniti komponente osetljive sa stanovišta bezbednosti bez ponovne izgradnje osnovnog SSV-a. Prilikom triage-a persistence-a ili diffing-a system code-a, popišite aktivne mount-ove i Preboot Cryptex store umesto da hashing-ujete samo osnovni snapshot:
```bash
mount | grep -Ei 'cryptex|graft'
find /System/Volumes/Preboot/Cryptexes -maxdepth 4 -type d 2>/dev/null
```
Detalji o boot-chain-u i Rapid Security Response-u opisani su u [macOS Architecture — Cryptexes](../mac-os-architecture/README.md#cryptexes-and-rapid-security-responses); ovaj odeljak se fokusira na samu SSV granicu.

### Entitlements za SSV Writer-e

Određeni Apple sistemski binarni fajlovi imaju entitlements koji im omogućavaju da menjaju ili upravljaju zapečaćenim sistemskim volumenom:

| Entitlement | Svrha |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | Vraćanje sistemskog volumena na prethodni snapshot |
| `com.apple.private.apfs.create-sealed-snapshot` | Kreiranje novog zapečaćenog snapshot-a nakon ažuriranja sistema |
| `com.apple.rootless.install.heritable` | Upisivanje u putanje zaštićene pomoću SIP-a (nasleđuju ga child procesi) |
| `com.apple.rootless.install` | Upisivanje u putanje zaštićene pomoću SIP-a |

### Pronalaženje SSV Writer-a
```bash
# Search for binaries with SSV-related entitlements
find /System /usr -type f -perm +111 -exec sh -c '
ents=$(codesign -d --entitlements - "{}" 2>&1)
echo "$ents" | grep -q "apfs.revert-to-snapshot\|apfs.create-sealed-snapshot\|rootless.install" && echo "{}"
' \; 2>/dev/null

# Using the scanner database
sqlite3 /tmp/executables.db "
SELECT e.path, c.name
FROM executables e
JOIN executable_capabilities ec ON e.id = ec.executable_id
JOIN capabilities c ON ec.capability_id = c.id
WHERE c.name = 'ssv_writer';"
```
### Scenariji napada

#### Napad vraćanja snapshot-a

Ako napadač kompromituje binarni fajl sa `com.apple.private.apfs.revert-to-snapshot`, može **da vrati sistemski volume u stanje pre ažuriranja**, čime se ponovo uspostavljaju poznate ranjivosti:
```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```
> [!WARNING]
> Vraćanje snapshot-a efektivno **poništava security update-ove**, obnavljajući prethodno zakrpljene ranjivosti kernela i sistema. Ovo je jedna od najopasnijih mogućih operacija na modernom macOS-u.

#### Zamena sistemskih binarnih datoteka

Uz SIP bypass + SSV write capability, napadač može da:

1. Montira system volume sa read-write pravima
2. Zameni sistemski daemon ili framework library trojanizovanom verzijom
3. Ponovo zapečati snapshot (ili prihvatiti neispravan seal ako je SIP već degradiran)
4. Rootkit opstaje nakon reboot-a i nevidljiv je userland alatima za detekciju

### Stvarni CVE-ovi

| CVE | Opis |
|---|---|
| CVE-2021-30892 | **Shrootless** — SIP bypass koji zloupotrebljava `system_installd` entitlement `com.apple.rootless.install.heritable` za pokretanje proizvoljnih post-install skripti ([Microsoft](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/))<sup>[[1]](#references)</sup> |
| CVE-2022-22583 | SIP bypass: `system_installd` je post-install skriptu smestio u SIP-zaštićeni folder unutar `/tmp`, ali sam `/tmp` nije SIP-zaštićen, pa je folder mogao biti zamenjen montiranjem image-a preko njega ([Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html))<sup>[[2]](#references)</sup> |
| CVE-2022-46689 | **MacDirtyCow** — copy-on-write race u XNU koji omogućava upisivanje u read-only fajlove u vlasništvu root-a ([Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/))<sup>[[3]](#references)</sup> |

---

## DataVault

### Osnovne informacije

**DataVault** je entitlement-gated filesystem zaštita za osetljive fajlove i direktorijume. BSD flag `UF_DATAVAULT` (`0x00000080`) označava objekat koji zahteva entitlement i za čitanje i za upis; za razliku od uobičajenog DAC-a, samo dobijanje **root** privilegija ili Full Disk Access-a ne zadovoljava tu proveru dok je zaštita aktivna.<sup>[[4]](#references)[[13]](#references)</sup>

Nemojte koristiti „DataVault“ kao sinonim za svaku zaštićenu bazu podataka. TCC baze podataka uređuju TCC/FDA i SIP-specific politika (pogledajte [macOS TCC](macos-tcc/README.md)), dok pristup stavkama keychain-a takođe zavisi od Keychain ACL-ova i kriptografske zaštite (pogledajte [macOS Keychain](../../macos-red-teaming/macos-keychain.md)). Stvarni DataVault primeri često se nalaze kao store-ovi u vlasništvu servisa ispod `/private/var/folders/.../0/`, kao što je Screen Time store; flag je vidljiv kao `datavault` u BSD file flags kada se parent može proveriti pomoću `stat`.

### Entitlement-i DataVault Controller-a

| Entitlement | Granica |
|---|---|
| `com.apple.rootless.datavault.controller` | Pristupanje i upravljanje `UF_DATAVAULT` objektima<sup>[[13]](#references)</sup> |
| `com.apple.private.tcc.manager` | Upravljanje TCC odlukama; ovo je povezana, ali odvojena privacy granica |
| `com.apple.private.tcc.allow` | Zaobilaženje izabranih TCC servisa navedenih u vrednosti entitlement-a |
| `com.apple.rootless.storage.TCC` | Upisivanje u SIP-zaštićeni TCC store |

Proces koji kombinuje DataVault-controller entitlement sa FDA, backup, indexing ili IPC funkcionalnošću naročito je zanimljiv: potražite confused-deputy primitiv koji kopira zaštićeni objekat na običnu putanju, umesto pokušaja direktnog otvaranja vault-a.<sup>[[14]](#references)</sup>

### Pronalaženje DataVault Controller-a
```bash
# BSD flags: a protected object is printed with the `datavault` keyword
ls -ldeO@ /private/var/folders/*/*/0/com.apple.ScreenTimeAgent 2>/dev/null
sudo find /private/var/folders -flags +datavault -print 2>/dev/null

# Find Apple binaries carrying DataVault/TCC controller entitlements
find /System /usr -type f -perm +111 -exec sh -c '
ents=$(codesign -d --entitlements - "{}" 2>&1)
echo "$ents" | grep -q "datavault.controller\|private.tcc\|rootless.storage.TCC" && echo "{}"
' \; 2>/dev/null

# Using the scanner
sqlite3 /tmp/executables.db "
SELECT e.path, c.name
FROM executables e
JOIN executable_capabilities ec ON e.id = ec.executable_id
JOIN capabilities c ON ec.capability_id = c.id
WHERE c.name = 'datavault_controller';"
```
### Scenariji napada

#### Direktna izmena TCC baze podataka (odvojena TCC granica)

Ako napadač kompromituje TCC manager proces (npr. putem code injection-a u proces koji poseduje `com.apple.private.tcc.manager`), može **direktno da izmeni TCC bazu podataka** i dodeli bilo kojoj aplikaciji bilo koju TCC dozvolu:<sup>[[12]](#references)</sup>
```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```
> [!CAUTION]
> Izmena TCC baze podataka predstavlja **krajnji bypass privatnosti** — nečujno dodeljuje bilo koju dozvolu, bez korisničkog upita ili vidljivog indikatora. Istorijski gledano, više macOS privilege escalation lanaca završilo se upisom u TCC bazu podataka kao završnim payloadom.

#### Pristup Keychain bazi podataka

Direktan pristup backing bazi podataka za keychain nije ekvivalentan pristupu secretima u plaintext obliku. Ako druga privilege boundary omogućava napadaču da kopira bazu podataka, key material i ACL-ovi stavki i dalje moraju biti napadnuti; pogledajte namensku stranicu za [macOS Keychain](../../macos-red-teaming/macos-keychain.md), umesto da pretpostavite da je DataVault-controller entitlement dovoljan.

#### Granica kopije backup-a: Time Machine

Analiza iz 2026. godine pokazala je koristan opšti obrazac: `backupd` poseduje i `com.apple.rootless.datavault.controller` i Full Disk Access, kako bi mogao da kopira zaštićene store-ove. U testiranoj konfiguraciji, `/private/var/folders` bio je uključen u Time Machine, a montirana kopija backup-a nije primenjivala aktivnu DataVault granicu. Istraživač je ovo iskoristio da pronađe SQLite store za Screen Time i pročita njegov PIN za ograničenja u plaintext obliku, bez otvaranja aktivnog vault-a. Tretirajte ovo kao **copy-boundary attack**: enumerišite backup, export, migration, indexing i diagnostic deputies koji mogu materijalizovati podatke iz vault-a ispod slabije mount ili path granice.<sup>[[13]](#references)[[14]](#references)</sup>
```bash
# Confirm the deputy's privileges and whether the source tree is included
codesign -d --entitlements - /System/Library/CoreServices/TimeMachine/backupd 2>&1
tmutil isexcluded /private/var/folders

# Inspect the newest mounted backup; paths vary per host
backup="$(tmutil latestbackup)"
db="$(find "$backup/Data/private/var/folders" -path '*/com.apple.ScreenTimeAgent/Store/RMAdminStore-Local.sqlite' -print -quit 2>/dev/null)"
sqlite3 "$db" 'SELECT ZPASSCODE1 FROM ZCOREORGANIZATIONSETTINGS WHERE ZPASSCODE1 IS NOT NULL LIMIT 1;'
```
Ovo ponašanje zavisi od verzije i rasporeda backup-a. Proverite ga na ciljnoj build verziji i imajte na umu da šifrovana Time Machine destinacija štiti kopiju samo dok je zaključana; kada se mount-uje, njene kontrole pristupa postaju deo attack surface-a.

### CVEs iz stvarnog sveta koje uključuju DataVault/TCC Bypass

| CVE | Opis |
|---|---|
| CVE-2024-44131 | FileProvider symlink race koji privilegovanom helper-u omogućava pristup TCC-zaštićenim podacima ([Jamf](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/))<sup>[[5]](#references)</sup> |
| CVE-2023-40424 | Kao root, **kreiranje novog korisnika čiji `NFSHomeDirectory` pokazuje na `TCC.db` kojim upravlja napadač**; prilikom prijavljivanja `tccd` ga učitava i primenjuje grant-ove, čime se dolazi do podataka drugih korisnika ([Kandji](https://blog.kandji.io/malware-bypass-tcc))<sup>[[6]](#references)</sup> |
| CVE-2021-30970 | "powerdir": promena korisnikovog home direktorijuma radi postavljanja TCC.db fajla kojim upravlja napadač ([Microsoft](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/))<sup>[[7]](#references)</sup> |
| CVE-2021-30713 | Greška pri zaključivanju bundle-a koja aplikaciji omogućava da **nasledi TCC grant-ove donor bundle-a** bez prompt-a; u praksi ju je koristio **XCSSET** za pravljenje screenshot-a desktopa ([Jamf](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/))<sup>[[8]](#references)</sup> |
| CVE-2020-9934 | `tccd` je formirao putanju do DB-a na osnovu `$HOME`, pa ju je `launchctl setenv HOME` preusmerio na `TCC.db` kojim upravlja napadač ([Matt Shockley](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8))<sup>[[9]](#references)</sup> |
| CVE-2020-29621 | `coreaudiod` je posedovao `com.apple.private.tcc.manager` **i imao isključenu library validation**, pa je HAL plug-in ubačen u `/Library/Audio/Plug-Ins/HAL` mogao da dodeli proizvoljna TCC prava ([Wojciech Reguła](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/))<sup>[[10]](#references)</sup> |



## References

- [1] [Microsoft pronalazi novu macOS ranjivost, Shrootless, koja može da zaobiđe System Integrity Protection](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)
- [2] [Tehnička analiza: CVE-2022-22583 - Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html)
- [3] [MacDirtyCow - Vredi raditi loše](https://worthdoingbadly.com/macdirtycow/)
- [4] [Apple Platform Security — Zaštita podataka](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
- [5] [Jamf Threat Labs - CVE-2024-44131: TCC bypass krade podatke iz iCloud-a](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [Kandji - Otkrivanje macOS malware-a: Zaobilaženje TCC-a](https://blog.kandji.io/malware-bypass-tcc)
- [7] [Nova macOS ranjivost, "powerdir", može dovesti do neovlašćenog pristupa korisničkim podacima](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [8] [Zero-Day TCC bypass otkriven u XCSSET malware-u](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [9] [CVE-2020–9934: Zaobilaženje macOS Transparency, Consent, and Control (TCC) Framework-a](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [10] [Pustite muziku i zaobiđite TCC, odnosno CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [11] [Noćna mora Apple OTA Updates-a (APFS Snapshots)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [12] [Objective-See — TCC Exploitation](https://objective-see.org/blog/blog_0x4C.html)
- [13] [XNU `stat.h` — `UF_DATAVAULT`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/stat.h)
- [14] [Kako zaobići sopstveni Screen Time passcode — analiza source koda i Time Machine/DataVault-a](https://tangled.org/dunkirk.sh/zera/commit/e6b6236c395e5c9ec1a27ad2a76217d8cc2b4312)
{{#include ../../../banners/hacktricks-training.md}}
