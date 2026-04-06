# macOS Zapečaćeni sistemski volumen & DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Zapečaćeni sistemski volumen (SSV)

### Osnovne informacije

Počevši od **macOS Big Sur (11.0)**, sistemski volumen je kriptografski zapečaćen korišćenjem **APFS snapshot hash tree**. Ovo se naziva **Zapečaćeni sistemski volumen (SSV)**. Sistemsku particiju montira se kao **samo za čitanje** i svaka izmena prekida pečat, koji se proverava pri pokretanju sistema.

SSV pruža:
- **Otkrivanje neovlašćenih izmena** — svaka izmena sistemskih binaries/framework-ova može se otkriti preko prekinutog kriptografskog pečata
- **Zaštita od rollback-a** — proces podizanja sistema proverava integritet sistemskog snapshot-a
- **Sprečavanje rootkita** — čak ni root ne može trajno da izmeni fajlove na sistemskom volumenu (bez prekida pečata)

### Provera statusa SSV
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
### Dozvole SSV Writer-a

Neki Apple sistemski binarni fajlovi imaju dozvole koje im omogućavaju da menjaju ili upravljaju sealed system volume:

| Dozvola | Svrha |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | Vratiti sistemski volume na prethodni snapshot |
| `com.apple.private.apfs.create-sealed-snapshot` | Kreirati novi sealed snapshot nakon sistemskih ažuriranja |
| `com.apple.rootless.install.heritable` | Pisati u SIP-zaštićene putanje (nasleđeno u podprocesima) |
| `com.apple.rootless.install` | Pisati u SIP-zaštićene putanje |

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

#### Snapshot Rollback Attack

Ako napadač kompromituje binarni fajl sa `com.apple.private.apfs.revert-to-snapshot`, može **vratiti sistemski volumen u stanje pre ažuriranja**, obnavljajući poznate ranjivosti:
```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```
> [!WARNING]
> Vraćanje snapshot-a efektivno **poništava sigurnosne nadogradnje**, vraćajući ranije zakrpljene ranjivosti kernela i sistema. Ovo je jedna od najopasnijih operacija na modernom macOS-u.

#### Zamena sistemskih binarnih datoteka

Sa SIP bypass + SSV write capability, napadač može:

1. Montirati sistemski volumen u režimu čitanja i pisanja
2. Zameniti sistemski daemon ili framework biblioteku trojanskom verzijom
3. Ponovo zapečatiti snapshot (ili prihvatiti pokidani seal ako je SIP već degradiran)
4. Rootkit opstaje preko restartovanja i nevidljiv je userland detekcionim alatima

### Real-World CVEs

| CVE | Description |
|---|---|
| CVE-2021-30892 | **Shrootless** — zaobilaženje SIP-a koje omogućava izmenu SSV-a preko `system_installd` |
| CVE-2022-22583 | SSV bypass kroz PackageKit-ovo rukovanje snapshot-ovima |
| CVE-2022-46689 | Race condition koja omogućava pisanje u fajlove zaštićene SIP-om |

---

## DataVault

### Osnovne informacije

**DataVault** je Apple-ov sloj zaštite za osetljive sistemske baze podataka. Čak ni **root ne može pristupiti datotekama zaštićenim od strane DataVault-a** — samo procesi sa specifičnim entitlements mogu da ih čitaju ili menjaju. Zaštićena skladišta uključuju:

| Zaštićena baza | Putanja | Sadržaj |
|---|---|---|
| TCC (system) | `/Library/Application Support/com.apple.TCC/TCC.db` | Sistemske TCC odluke o privatnosti |
| TCC (user) | `~/Library/Application Support/com.apple.TCC/TCC.db` | TCC odluke o privatnosti po korisniku |
| Keychain (system) | `/Library/Keychains/System.keychain` | Sistem keychain |
| Keychain (user) | `~/Library/Keychains/login.keychain-db` | Korisnički keychain |

Zaštita DataVault-a se sprovodi na nivou **filesystem-a** koristeći extended attributes i volume protection flags, koje verifikuje kernel.

### DataVault Controller Entitlements
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

Ako napadač kompromituje binarni fajl kontrolera DataVault (npr. putem injektovanja koda u proces sa `com.apple.private.tcc.manager`), može **direktno izmeniti TCC bazu podataka** kako bi dodelio bilo kojoj aplikaciji bilo koju TCC dozvolu:
```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```
> [!CAUTION]
> Izmena TCC baze podataka je **krajnji bypass privatnosti** — dodeljuje bilo koju dozvolu tiho, bez bilo kakvog korisničkog upita ili vidljivog indikatora. Istorijski, više macOS lanaca eskalacije privilegija završilo je zapisima u TCC bazi podataka kao konačnim payload-om.

#### Pristup Keychain baze podataka

DataVault takođe štiti keychain backing fajlove. Kompromitovan DataVault controller može:

1. Pročitati sirove keychain database fajlove
2. Izvući enkriptovane keychain stavke
3. Pokušati offline dekripciju koristeći korisničku lozinku ili povraćene ključeve

### Stvarni CVE-ovi koji uključuju DataVault/TCC bypass

| CVE | Description |
|---|---|
| CVE-2023-40424 | TCC bypass via symlink to DataVault-protected file |
| CVE-2023-32364 | Sandbox bypass leading to TCC database modification |
| CVE-2021-30713 | TCC bypass via XCSSET malware modifying TCC.db |
| CVE-2020-9934 | TCC bypass via environment variable manipulation |
| CVE-2020-29621 | Music app TCC bypass reaching DataVault |

## Reference

* [Apple Platform Security — Data Protection](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
* [The Nightmare of Apple OTA Updates (APFS Snapshots)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
* [Objective-See — TCC Exploitation](https://objective-see.org/blog/blog_0x4C.html)

{{#include ../../../banners/hacktricks-training.md}}
