# macOS Sealed System Volume & DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Sealed System Volume (SSV)

### Osnovne informacije

Počev od **macOS Big Sur (11.0)**, sistemski volumen je kriptografski zapečaćen pomoću **APFS snapshot hash stabla**. Ovo se naziva **Sealed System Volume (SSV)**. Sistemska particija se montira **samo za čitanje**, a svaka izmena narušava pečat, što se proverava tokom pokretanja sistema.<sup>[[11]](#references)</sup>

SSV obezbeđuje:
- **Detekciju neovlašćenih izmena** — svaka izmena sistemskih binarnih datoteka/frameworka može da se otkrije putem narušenog kriptografskog pečata
- **Zaštitu od vraćanja na prethodno stanje** — proces pokretanja sistema proverava integritet sistemskog snapshot-a
- **Sprečavanje rootkit-a** — čak ni root ne može trajno da izmeni datoteke na sistemskom volumenu (bez narušavanja pečata)

### Provera statusa SSV-a
```bash
# Check if authenticated root is enabled (SSV seal verification)
csrutil authenticated-root status

# List APFS snapshots (the sealed snapshot is the boot volume)
diskutil apfs listSnapshots disk3s1

# Check mount status (should show read-only)
mount | grep " / "

# Verify the system volume seal
diskutil apfs listVolumeGroups
```
### Entitlements za SSV Writer-e

Određeni Apple sistemski binarni fajlovi imaju entitlements koji im omogućavaju da menjaju ili upravljaju sealed system volume-om:

| Entitlement | Svrha |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | Vraćanje sistemskog volumena na prethodni snapshot |
| `com.apple.private.apfs.create-sealed-snapshot` | Kreiranje novog sealed snapshot-a nakon ažuriranja sistema |
| `com.apple.rootless.install.heritable` | Upisivanje u SIP-zaštićene putanje (nasleđuju ih child procesi) |
| `com.apple.rootless.install` | Upisivanje u SIP-zaštićene putanje |

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
### Scenario napada

#### Snapshot Rollback Attack

Ako napadač kompromituje binarni fajl sa `com.apple.private.apfs.revert-to-snapshot`, može **vratiti sistemski volumen u stanje pre ažuriranja**, čime se ponovo aktiviraju poznate ranjivosti:
```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```
> [!WARNING]
> Vraćanje snapshot-a efektivno **poništava security updates**, obnavljajući prethodno zakrpljene kernel i sistemske ranjivosti. Ovo je jedna od najopasnijih mogućih operacija na modernom macOS-u.

#### Zamena sistemskih binarnih datoteka

Uz SIP bypass + SSV write capability, attacker može da:

1. Montira system volume sa read-write dozvolama
2. Zameni sistemski daemon ili framework library trojanizovanom verzijom
3. Ponovo zapečati snapshot (ili prihvati neispravan seal ako je SIP već degradiran)
4. Rootkit opstaje nakon reboot-a i nevidljiv je userland alatima za detekciju

### CVE ranjivosti iz stvarnog sveta

| CVE | Opis |
|---|---|
| CVE-2021-30892 | **Shrootless** — SIP bypass koji zloupotrebljava `system_installd` entitlement `com.apple.rootless.install.heritable` za pokretanje proizvoljnih post-install skripti ([Microsoft](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/))<sup>[[1]](#references)</sup> |
| CVE-2022-22583 | SIP bypass: `system_installd` je post-install skriptu smestio u SIP-protected folder unutar `/tmp`, ali sam `/tmp` nije SIP-protected, pa je folder mogao biti zamenjen montiranjem image-a preko njega ([Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html))<sup>[[2]](#references)</sup> |
| CVE-2022-46689 | **MacDirtyCow** — copy-on-write race u XNU-u koji omogućava upisivanje u read-only fajlove čiji je vlasnik root ([Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/))<sup>[[3]](#references)</sup> |

---

## DataVault

### Osnovne informacije

**DataVault** je Apple-ov protection layer za osetljive sistemske baze podataka. Čak ni **root ne može da pristupi DataVault-protected fajlovima** — samo procesi sa određenim entitlement-ima mogu da ih čitaju ili menjaju.<sup>[[4]](#references)</sup> Zaštićeni store-ovi obuhvataju:

| Zaštićena baza podataka | Putanja | Sadržaj |
|---|---|---|
| TCC (system) | `/Library/Application Support/com.apple.TCC/TCC.db` | TCC privacy odluke na nivou celog sistema |
| TCC (user) | `~/Library/Application Support/com.apple.TCC/TCC.db` | TCC privacy odluke po korisniku |
| Keychain (system) | `/Library/Keychains/System.keychain` | System keychain |
| Keychain (user) | `~/Library/Keychains/login.keychain-db` | User keychain |

DataVault zaštita se sprovodi na **filesystem nivou** korišćenjem extended attributes i volume protection flags, koje kernel proverava.

### Entitlements DataVault Controller-a
```
com.apple.private.tcc.manager         — Full TCC database read/write
com.apple.private.tcc.manager.check-by-audit-token — TCC checks via audit token
com.apple.private.tcc.allow           — Access specific TCC-protected resources
com.apple.rootless.storage.TCC        — Write to TCC database (SIP-related)
```
### Pronalaženje DataVault kontrolera
```bash
# Check DataVault protection on the TCC database
ls -le@ "/Library/Application Support/com.apple.TCC/TCC.db"

# Find binaries with TCC management entitlements
find /System /usr -type f -perm +111 -exec sh -c '
ents=$(codesign -d --entitlements - "{}" 2>&1)
echo "$ents" | grep -q "private.tcc\|datavault\|rootless.storage.TCC" && echo "{}"
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

#### Direktna izmena TCC baze podataka

Ako napadač kompromituje binarni fajl kontrolera DataVault-a (npr. putem code injection-a u proces sa `com.apple.private.tcc.manager`, može **direktno izmeniti TCC bazu podataka** i dodeliti bilo kojoj aplikaciji bilo koju TCC dozvolu:<sup>[[12]](#references)</sup>
```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```
> [!CAUTION]
> Izmena TCC baze podataka je **ultimativni bypass privatnosti** — nečujno dodeljuje bilo koju dozvolu, bez ikakvog korisničkog upita ili vidljivog indikatora. Istorijski gledano, više macOS lanaca za privilege escalation završilo se upisivanjem u TCC bazu kao finalnim payloadom.

#### Pristup keychain bazi podataka

DataVault takođe štiti prateće keychain datoteke. Kompromitovani DataVault kontroler može da:

1. Čita sirove datoteke keychain baze podataka
2. Izdvoji šifrovane keychain stavke
3. Pokuša offline dešifrovanje koristeći korisničku lozinku ili oporavljene ključeve

### CVE-ovi iz stvarnog sveta koji uključuju DataVault/TCC bypass

| CVE | Opis |
|---|---|
| CVE-2024-44131 | FileProvider symlink race koji privilegovanom helperu omogućava pristup TCC-zaštićenim podacima ([Jamf](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/))<sup>[[5]](#references)</sup> |
| CVE-2023-40424 | Kao root, **kreiranje novog korisnika čiji `NFSHomeDirectory` pokazuje na `TCC.db` pod kontrolom napadača**; pri prijavljivanju `tccd` ga učitava i primenjuje grantove, čime se dolazi do podataka drugih korisnika ([Kandji](https://blog.kandji.io/malware-bypass-tcc))<sup>[[6]](#references)</sup> |
| CVE-2021-30970 | "powerdir": promena korisnikovog home direktorijuma radi postavljanja TCC.db pod kontrolom napadača ([Microsoft](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/))<sup>[[7]](#references)</sup> |
| CVE-2021-30713 | Greška u zaključivanju bundlea koja aplikaciji omogućava da **nasledi TCC grantove donor bundlea** bez upita; u stvarnom svetu ju je **XCSSET** iskoristio za pravljenje screenshotova desktopa ([Jamf](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/))<sup>[[8]](#references)</sup> |
| CVE-2020-9934 | `tccd` je konstruisao putanju do baze iz `$HOME`, pa je `launchctl setenv HOME` preusmeravao na `TCC.db` pod kontrolom napadača ([Matt Shockley](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8))<sup>[[9]](#references)</sup> |
| CVE-2020-29621 | `coreaudiod` je posedovao `com.apple.private.tcc.manager` **i** imao onemogućenu validaciju biblioteka, pa je HAL plug-in ubačen u `/Library/Audio/Plug-Ins/HAL` mogao da dodeli proizvoljna TCC prava ([Wojciech Reguła](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/))<sup>[[10]](#references)</sup> |

## Reference

- [1] [Microsoft pronalazi novu macOS ranjivost, Shrootless, koja može da zaobiđe System Integrity Protection](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)
- [2] [Tehnička analiza: CVE-2022-22583 - Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html)
- [3] [MacDirtyCow - Vredi raditi loše](https://worthdoingbadly.com/macdirtycow/)
- [4] [Apple Platform Security — Data Protection](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
- [5] [Jamf Threat Labs - CVE-2024-44131: TCC bypass krade podatke iz iClouda](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [Kandji - Otkrivanje macOS malwarea: Bypassing TCC](https://blog.kandji.io/malware-bypass-tcc)
- [7] [Nova macOS ranjivost, "powerdir", mogla bi da omogući neovlašćen pristup korisničkim podacima](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [8] [Zero-Day TCC bypass otkriven u XCSSET malwareu](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [9] [CVE-2020–9934: Bypassing macOS Transparency, Consent, and Control (TCC) Framework](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [10] [Puštanje muzike i bypass TCC-a, poznat i kao CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [11] [Noćna mora Apple OTA ažuriranja (APFS Snapshots)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [12] [Objective-See — TCC Exploitation](https://objective-see.org/blog/blog_0x4C.html)

{{#include ../../../banners/hacktricks-training.md}}
