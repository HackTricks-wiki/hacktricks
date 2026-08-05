# macOS Sealed System Volume & DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Sealed System Volume (SSV)

### Osnovne informacije

Počev od **macOS Big Sur (11.0)**, sistemski volumen je kriptografski zapečaćen pomoću **APFS snapshot hash tree**. Ovo se naziva **Sealed System Volume (SSV)**. Sistemska particija se montira kao **read-only**, a svaka izmena narušava pečat, što se proverava tokom pokretanja sistema.

SSV obezbeđuje:
- **Detekciju neovlašćenih izmena** — svaka izmena sistemskih binarnih datoteka/frameworka može se otkriti na osnovu narušenog kriptografskog pečata
- **Zaštitu od vraćanja na prethodno stanje** — proces pokretanja sistema proverava integritet sistemskog snapshot-a
- **Prevenciju rootkit-a** — čak ni root ne može trajno da izmeni datoteke na sistemskom volumenu (bez narušavanja pečata)

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
### Entitlements SSV Writer-a

Određeni Apple sistemski binarni fajlovi imaju entitlements koji im omogućavaju da menjaju ili upravljaju sealed system volume-om:

| Entitlement | Svrha |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | Vraćanje system volume-a na prethodni snapshot |
| `com.apple.private.apfs.create-sealed-snapshot` | Kreiranje novog sealed snapshot-a nakon system update-a |
| `com.apple.rootless.install.heritable` | Pisanje u SIP-protected putanje (nasleđuju ih child procesi) |
| `com.apple.rootless.install` | Pisanje u SIP-protected putanje |

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

#### Napad vraćanja snapshot-a

Ako napadač kompromituje binarni fajl sa `com.apple.private.apfs.revert-to-snapshot`, može da **vrati sistemski volumen u stanje pre ažuriranja**, čime se ponovo aktiviraju poznate ranjivosti:
```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```
> [!WARNING]
> Vraćanje snapshot-a efektivno **poništava bezbednosne ispravke**, obnavljajući prethodno zakrpljene ranjivosti kernela i sistema. Ovo je jedna od najopasnijih mogućih operacija na modernom macOS-u.

#### Zamena sistemskih binarnih datoteka

Uz SIP bypass + SSV write capability, napadač može da:

1. Montira system volume read-write
2. Zameni sistemski daemon ili framework library trojanizovanom verzijom
3. Ponovo zapečati snapshot (ili prihvati neispravan seal ako je SIP već degradiran)
4. Rootkit opstaje nakon reboot-a i nevidljiv je alatima za detekciju u userland-u

### CVE-ovi iz stvarnog sveta

| CVE | Opis |
|---|---|
| CVE-2021-30892 | **Shrootless** — SIP bypass koji zloupotrebljava `system_installd` entitlement `com.apple.rootless.install.heritable` za pokretanje proizvoljnih post-install skripti ([Microsoft](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)) |
| CVE-2022-22583 | SIP bypass: `system_installd` je smestio post-install skriptu u SIP-zaštićeni folder unutar `/tmp`, ali sam `/tmp` nije SIP-zaštićen, pa je folder mogao biti zamenjen montiranjem image-a preko njega ([Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html)) |
| CVE-2022-46689 | **MacDirtyCow** — copy-on-write race u XNU-u koji omogućava upis u read-only fajlove čiji je vlasnik root ([Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/)) |

---

## DataVault

### Osnovne informacije

**DataVault** je Apple-ov zaštitni sloj za osetljive sistemske baze podataka. Čak ni **root ne može da pristupi fajlovima zaštićenim pomoću DataVault-a** — samo procesi sa specifičnim entitlement-ima mogu da ih čitaju ili menjaju.<sup>[1]</sup> Zaštićeni store-ovi uključuju:

| Zaštićena baza podataka | Putanja | Sadržaj |
|---|---|---|
| TCC (system) | `/Library/Application Support/com.apple.TCC/TCC.db` | TCC odluke o privatnosti na nivou sistema |
| TCC (user) | `~/Library/Application Support/com.apple.TCC/TCC.db` | TCC odluke o privatnosti po korisniku |
| Keychain (system) | `/Library/Keychains/System.keychain` | Sistemski keychain |
| Keychain (user) | `~/Library/Keychains/login.keychain-db` | Korisnički keychain |

DataVault zaštita se primenjuje na **nivou filesystem-a** pomoću extended attributes i volume protection flags, koje kernel verifikuje.

### Entitlement-i DataVault Controller-a
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

Ako napadač kompromituje DataVault controller binary (npr. putem code injection u proces sa `com.apple.private.tcc.manager`), može **direktno izmeniti TCC bazu podataka** i dodeliti bilo kojoj aplikaciji bilo koju TCC dozvolu:
```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```
> [!CAUTION]
> Izmena TCC baze podataka je **konačni zaobilažak zaštite privatnosti** — nečujno dodeljuje bilo koju dozvolu, bez korisničkog upita ili vidljivog indikatora. Istorijski gledano, više lanaca eskalacije privilegija na macOS-u završavalo se upisivanjem u TCC bazu podataka kao završnim payloadom.

#### Pristup keychain bazi podataka

DataVault takođe štiti prateće keychain datoteke. Kompromitovani DataVault kontroler može da:

1. Čita sirove datoteke keychain baze podataka
2. Izdvoji šifrovane keychain stavke
3. Pokuša offline dešifrovanje pomoću korisničke lozinke ili vraćenih ključeva

### CVE ranjivosti iz stvarnog sveta koje uključuju DataVault/TCC bypass

| CVE | Opis |
|---|---|
| CVE-2024-44131 | FileProvider symlink race koji privilegovanom helperu omogućava pristup podacima zaštićenim TCC-om ([Jamf](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)) |
| CVE-2023-40424 | Kao root, **kreiranje novog korisnika čiji `NFSHomeDirectory` pokazuje na TCC.db pod kontrolom napadača**; prilikom prijavljivanja `tccd` ga koristi, pa se dozvole primenjuju i omogućavaju pristup podacima drugih korisnika ([Kandji](https://blog.kandji.io/malware-bypass-tcc)) |
| CVE-2021-30970 | "powerdir": promena korisničkog matičnog direktorijuma radi postavljanja TCC.db pod kontrolom napadača ([Microsoft](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)) |
| CVE-2021-30713 | Greška u zaključivanju bundlea koja aplikaciji omogućava da **nasledi TCC dozvole donor bundlea** bez upita; u divljini ju je iskorišćavao **XCSSET** za pravljenje snimaka ekrana radne površine ([Jamf](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)) |
| CVE-2020-9934 | `tccd` je formirao putanju do baze na osnovu `$HOME`, pa je `launchctl setenv HOME` preusmeravao na TCC.db pod kontrolom napadača ([Matt Shockley](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)) |
| CVE-2020-29621 | `coreaudiod` je imao `com.apple.private.tcc.manager` **i** onemogućenu validaciju biblioteka, pa je HAL plug-in postavljen u `/Library/Audio/Plug-Ins/HAL` mogao da dodeli proizvoljna TCC prava ([Wojciech Reguła](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)) |

## Reference

- [1] [Apple Platform Security — Zaštita podataka](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
- [2] [Apple OTA ažuriranja — noćna mora (APFS snapshots)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [3] [Objective-See — TCC exploitation](https://objective-see.org/blog/blog_0x4C.html)

{{#include ../../../banners/hacktricks-training.md}}
