# KIOSK'lardan Kaçış

{{#include ../banners/hacktricks-training.md}}

---

## Fiziksel cihazı kontrol edin

| Bileşen     | Eylem                                                              |
| ----------- | ------------------------------------------------------------------ |
| Güç düğmesi | Cihazı kapatıp yeniden açmak başlangıç ekranını görünür kılabilir |
| Güç kablosu | Güç kısa süreliğine kesildiğinde cihazın yeniden başlayıp başlamadığını kontrol edin |
| USB bağlantı noktaları | Daha fazla kısayol için fiziksel klavye bağlayın             |
| Ethernet    | Network scan veya sniffing daha ileri exploitation sağlayabilir  |

## GUI uygulaması içindeki olası eylemleri kontrol edin

**Yaygın Dialoglar**, **dosya kaydetme**, **dosya açma**, yazı tipi veya renk seçme seçenekleridir... Bunların çoğu **tam bir Explorer işlevselliği sunar**. Bu, aşağıdaki seçeneklere erişebiliyorsanız Explorer işlevlerine erişebileceğiniz anlamına gelir:

- Kapat/Kapat olarak
- Aç/Birlikte aç
- Yazdır
- Export/Import
- Search
- Scan

Şunları yapıp yapamadığınızı kontrol etmelisiniz:

- Dosyaları değiştirme veya yeni dosyalar oluşturma
- Symbolic link'ler oluşturma
- Kısıtlı alanlara erişim sağlama
- Diğer uygulamaları çalıştırma

### Komut Çalıştırma

Belki de **`Open with`** seçeneğini kullanarak bir tür shell açabilir/çalıştırabilirsiniz.

#### Windows

Örneğin _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ komut çalıştırmak (ve beklenmedik eylemler gerçekleştirmek) için kullanılabilecek daha fazla binary'yi burada bulabilirsiniz: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

#### \*NIX \_\_

_bash, sh, zsh..._ Daha fazlası burada: [https://gtfobins.github.io/](https://gtfobins.github.io)

## Windows

### Path kısıtlamalarını aşma

- **Environment variable'lar**: Birçok environment variable belirli bir path'i gösterir
- **Diğer protokoller**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
- **Symbolic link'ler**
- **Kısayollar**: CTRL+N (yeni oturum aç), CTRL+R (komutları çalıştır), CTRL+SHIFT+ESC (Task Manager), Windows+E (Explorer'ı aç), CTRL-B, CTRL-I (Favoriler), CTRL-H (Geçmiş), CTRL-L, CTRL-O (Dosya/Aç Dialog'u), CTRL-P (Yazdırma Dialog'u), CTRL-S (Farklı Kaydet)
- Gizli Administrative menüsü: CTRL-ALT-F8, CTRL-ESC-F9
- **Shell URI'leri**: _shell:Administrative Tools, shell:DocumentsLibrary, shell:Librariesshell:UserProfiles, shell:Personal, shell:SearchHomeFolder, shell:Systemshell:NetworkPlacesFolder, shell:SendTo, shell:UsersProfiles, shell:Common Administrative Tools, shell:MyComputerFolder, shell:InternetFolder_
- **UNC path'leri**: Paylaşılan klasörlere bağlanmak için kullanılan path'ler. Yerel makinenin C$ paylaşımına bağlanmayı denemelisiniz ("\\\127.0.0.1\c$\Windows\System32")
- **Daha fazla UNC path'i:**

| UNC                       | UNC            | UNC                  |
| ------------------------- | -------------- | -------------------- |
| %ALLUSERSPROFILE%         | %APPDATA%      | %CommonProgramFiles% |
| %COMMONPROGRAMFILES(x86)% | %COMPUTERNAME% | %COMSPEC%            |
| %HOMEDRIVE%              | %HOMEPATH%     | %LOCALAPPDATA%       |
| %LOGONSERVER%             | %PATH%         | %PATHEXT%            |
| %ProgramData%             | %ProgramFiles% | %ProgramFiles(x86)%  |
| %PROMPT%                  | %PSModulePath% | %Public%             |
| %SYSTEMDRIVE%             | %SYSTEMROOT%   | %TEMP%               |
| %TMP%                     | %USERDOMAIN%   | %USERNAME%           |
| %USERPROFILE%             | %WINDIR%       |                      |

### Kısıtlı Desktop Breakout'ları (Citrix/RDS/VDI)

- **Dialog-box pivoting**: *Open/Save/Print-to-file* dialog'larını Explorer-lite olarak kullanın. Dosya adı alanında `*.*` / `*.exe` kullanmayı deneyin, **Open in new window** için klasörlere sağ tıklayın ve navigasyonu genişletmek için **Properties → Open file location** seçeneğini kullanın.<sup>[[1]](#references)</sup>
- **Dialog'lardan execution path'leri oluşturma**: Yeni bir dosya oluşturup adını `.CMD` veya `.BAT` olarak değiştirin ya da `%WINDIR%\System32` (veya `%WINDIR%\System32\cmd.exe` gibi belirli bir binary'ye) işaret eden bir shortcut oluşturun.
- **Shell launch pivot'ları**: `cmd.exe` dosyasına browse edebiliyorsanız herhangi bir dosyayı **drag-and-drop** ile üzerine bırakarak bir prompt başlatmayı deneyin. Task Manager'a erişilebiliyorsa (`CTRL+SHIFT+ESC`), **Run new task** seçeneğini kullanın.
- **Task Scheduler bypass**: Interactive shell'ler engellenmiş ancak scheduling'e izin veriliyorsa `cmd.exe` çalıştıran bir task oluşturun (GUI `taskschd.msc` veya `schtasks.exe`).
- **Zayıf allowlist'ler**: Execution **filename/extension** ile izin veriliyorsa payload'unuzun adını izin verilen bir adla değiştirin. **Directory** ile izin veriliyorsa payload'u izin verilen bir program klasörüne kopyalayıp orada çalıştırın.
- **Yazılabilir staging path'lerini bulun**: `%TEMP%` ile başlayın ve Sysinternals AccessChk ile yazılabilir klasörleri enumerate edin.
```cmd
echo %TEMP%
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
```
- **Sonraki adım**: Bir shell elde ederseniz Windows LPE checklist'ine geçin:
{{#ref}}
../windows-hardening/checklist-windows-privilege-escalation.md
{{#endref}}

### Binary'lerinizi İndirin

Console: [https://sourceforge.net/projects/console/](https://sourceforge.net/projects/console/)\
Explorer: [https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/](https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/)\
Registry editor: [https://sourceforge.net/projects/uberregedit/](https://sourceforge.net/projects/uberregedit/)

### Browser'dan filesystem'e erişme

| PATH                | PATH              | PATH               | PATH                |
| ------------------- | ----------------- | ------------------ | ------------------- |
| File:/C:/windows    | File:/C:/windows/ | File:/C:/windows\\ | File:/C:\windows    |
| File:/C:\windows\\  | File:/C:\windows/ | File://C:/windows  | File://C:/windows/  |
| File://C:/windows\\ | File://C:\windows | File://C:\windows/ | File://C:\windows\\ |
| C:/windows          | C:/windows/       | C:/windows\\       | C:\windows          |
| C:\windows\\        | C:\windows/       | %WINDIR%           | %TMP%               |
| %TEMP%              | %SYSTEMDRIVE%     | %SYSTEMROOT%       | %APPDATA%           |
| %HOMEDRIVE%         | %HOMESHARE        |                    | <p><br></p>         |

### Kısayollar

- Sticky Keys – SHIFT'e 5 kez basın
- Mouse Keys – SHIFT+ALT+NUMLOCK
- High Contrast – SHIFT+ALT+PRINTSCN
- Toggle Keys – NUMLOCK'u 5 saniye basılı tutun
- Filter Keys – sağ SHIFT'i 12 saniye basılı tutun
- WINDOWS+F1 – Windows Search
- WINDOWS+D – Desktop'u göster
- WINDOWS+E – Windows Explorer'ı başlat
- WINDOWS+R – Run
- WINDOWS+U – Ease of Access Centre
- WINDOWS+F – Search
- SHIFT+F10 – Context Menu
- CTRL+SHIFT+ESC – Task Manager
- CTRL+ALT+DEL – Yeni Windows sürümlerinde açılış ekranı
- F1 – Help F3 – Search
- F6 – Address Bar
- F11 – Internet Explorer içinde full screen'i açıp kapat
- CTRL+H – Internet Explorer History
- CTRL+T – Internet Explorer – New Tab
- CTRL+N – Internet Explorer – New Page
- CTRL+O – Open File
- CTRL+S – Save CTRL+N – New RDP / Citrix

### Kaydırma hareketleri

- Tüm açık Windows'ları görmek, KIOSK app'ini küçültmek ve doğrudan tüm OS'e erişmek için sol taraftan sağa kaydırın;
- Action Center'ı açmak, KIOSK app'ini küçültmek ve doğrudan tüm OS'e erişmek için sağ taraftan sola kaydırın;
- Full screen modunda açılmış bir app için title bar'ı görünür yapmak üzere üst kenardan içeri doğru kaydırın;
- Full screen app'te taskbar'ı göstermek için alttan yukarı doğru kaydırın.

### Internet Explorer Tricks

#### 'Image Toolbar'

Bir image'a tıklandığında sol üstünde görünen bir toolbar'dır. Explorer'da Save, Print, Mailto ve "My Pictures"ı açma seçeneklerine erişebilirsiniz. Kiosk'un Internet Explorer kullanıyor olması gerekir.

#### Shell Protocol

Explorer görünümü elde etmek için bu URL'leri yazın:

- `shell:Administrative Tools`
- `shell:DocumentsLibrary`
- `shell:Libraries`
- `shell:UserProfiles`
- `shell:Personal`
- `shell:SearchHomeFolder`
- `shell:NetworkPlacesFolder`
- `shell:SendTo`
- `shell:UserProfiles`
- `shell:Common Administrative Tools`
- `shell:MyComputerFolder`
- `shell:InternetFolder`
- `Shell:Profile`
- `Shell:ProgramFiles`
- `Shell:System`
- `Shell:ControlPanelFolder`
- `Shell:Windows`
- `shell:::{21EC2020-3AEA-1069-A2DD-08002B30309D}` --> Control Panel
- `shell:::{20D04FE0-3AEA-1069-A2D8-08002B30309D}` --> My Computer
- `shell:::{{208D2C60-3AEA-1069-A2D7-08002B30309D}}` --> My Network Places
- `shell:::{871C5380-42A0-1069-A2EA-08002B30309D}` --> Internet Explorer

### File Extension'larını Gösterme

Daha fazla bilgi için bu sayfaya bakın: [https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)<sup>[[7]](#references)</sup>

## Browser tricks

iKat versions yedekleri:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)

JavaScript kullanarak common dialog oluşturun ve file explorer'a erişin: `document.write('<input/type=file>')`<sup>[[2]](#references)</sup>\
Source: https://medium.com/@Rend\_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

## iPad

### Gestures ve buttons

- Dört (veya beş) parmakla yukarı kaydırın / Home button'a çift tıklayın: Multitask görünümünü görüntülemek ve App değiştirmek için
- Dört veya beş parmakla bir yöne kaydırın: Sonraki/önceki App'e geçmek için
- Beş parmakla ekranı pinch yapın / Home button'a dokunun / Ekranın altından 1 parmakla hızlıca yukarı kaydırın: Home'a erişmek için
- Ekranın altından 1 parmakla yalnızca 1-2 inch yavaşça kaydırın: Dock görünür
- Display'in üstünden 1 parmakla aşağı kaydırın: Bildirimlerinizi görmek için
- Ekranın sağ üst köşesinden 1 parmakla aşağı kaydırın: iPad Pro'nun control centre'ını görmek için
- Ekranın solundan 1 parmakla 1-2 inch kaydırın: Today görünümünü görmek için
- Ekranın merkezinden sağa veya sola 1 parmakla hızlıca kaydırın: Sonraki/önceki App'e geçmek için
- **iPad +**'in sağ üst köşesindeki On/**Off**/Sleep button'a basılı tutun + Slide to **power off** slider'ını tamamen sağa taşıyın: Kapatmak için
- **iPad'in sağ üst köşesindeki On/**Off**/Sleep button'a ve Home button'a birkaç saniye basın**: Zorla hard power off yapmak için
- **iPad'in sağ üst köşesindeki On/**Off**/Sleep button'a ve Home button'a hızlıca basın**: Display'in sol alt köşesinde açılacak bir screenshot almak için. Her iki button'a aynı anda çok kısa süreyle basın; birkaç saniye basılı tutarsanız hard power off gerçekleştirilir.<sup>[[3]](#references)</sup>

### Kısayollar

Bir iPad keyboard'ına veya USB keyboard adaptor'ına sahip olmalısınız. Burada yalnızca app'ten çıkmaya yardımcı olabilecek kısayollar gösterilecektir.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

| Key | Name         |
| --- | ------------ |
| ⌘   | Command      |
| ⌥   | Option (Alt) |
| ⇧   | Shift        |
| ↩   | Return       |
| ⇥   | Tab          |
| ^   | Control      |
| ←   | Left Arrow   |
| →   | Right Arrow  |
| ↑   | Up Arrow     |
| ↓   | Down Arrow   |

#### System shortcuts

Bu kısayollar, iPad'in kullanımına bağlı olarak visual settings ve sound settings içindir.

| Shortcut | Action                                                                         |
| -------- | ------------------------------------------------------------------------------ |
| F1       | Ekranı karart                                                                    |
| F2       | Ekranı aydınlat                                                                |
| F7       | Bir önceki şarkı                                                                  |
| F8       | Oynat/duraklat                                                                     |
| F9       | Şarkıyı atla                                                                      |
| F10      | Sessize al                                                                           |
| F11      | Sesi azalt                                                                |
| F12      | Sesi artır                                                                |
| ⌘ Space  | Kullanılabilir dillerin listesini gösterir; birini seçmek için space bar'a tekrar dokunun. |

#### iPad navigation

| Shortcut                                           | Action                                                  |
| -------------------------------------------------- | ------------------------------------------------------- |
| ⌘H                                                 | Home'a git                                              |
| ⌘⇧H (Command-Shift-H)                              | Home'a git                                              |
| ⌘ (Space)                                          | Spotlight'ı aç                                          |
| ⌘⇥ (Command-Tab)                                   | Son kullanılan on app'i listele                                 |
| ⌘\~                                                | Son App'e git                                       |
| ⌘⇧3 (Command-Shift-3)                              | Screenshot (kaydetmek veya işlem yapmak için sol altta görünür) |
| ⌘⇧4                                                | Screenshot al ve editor'de aç                    |
| Press and hold ⌘                                   | App için kullanılabilir kısayolların listesi                 |
| ⌘⌥D (Command-Option/Alt-D)                         | Dock'u getir                                      |
| ^⌥H (Control-Option-H)                             | Home button                                             |
| ^⌥H H (Control-Option-H-H)                         | Multitask bar'ını göster                                      |
| ^⌥I (Control-Option-i)                             | Item chooser                                            |
| Escape                                             | Back button                                             |
| → (Right arrow)                                    | Sonraki item                                               |
| ← (Left arrow)                                     | Önceki item                                           |
| ↑↓ (Up arrow, Down arrow)                          | Seçili item'a aynı anda dokun                        |
| ⌥ ↓ (Option-Down arrow)                            | Aşağı scroll et                                             |
| ⌥↑ (Option-Up arrow)                               | Yukarı scroll et                                               |
| ⌥← veya ⌥→ (Option-Left arrow veya Option-Right arrow) | Sola veya sağa scroll et                                    |
| ^⌥S (Control-Option-S)                             | VoiceOver speech'i aç veya kapat                         |
| ⌘⇧⇥ (Command-Shift-Tab)                            | Önceki app'e geç                              |
| ⌘⇥ (Command-Tab)                                   | Original app'e geri dön                         |
| ←+→, ardından Option + ← veya Option+→                   | Dock'ta gezin                                   |

#### Safari shortcuts

| Shortcut                | Action                                           |
| ----------------------- | ------------------------------------------------ |
| ⌘L (Command-L)          | Location'ı aç                                    |
| ⌘T                      | Yeni bir tab aç                                   |
| ⌘W                      | Mevcut tab'ı kapat                            |
| ⌘R                      | Mevcut tab'ı yenile                          |
| ⌘.                      | Mevcut tab'ın yüklenmesini durdur                     |
| ^⇥                      | Sonraki tab'a geç                           |
| ^⇧⇥ (Control-Shift-Tab) | Önceki tab'a geç                         |
| ⌘L                      | Değiştirmek üzere text input/URL field'ını seç     |
| ⌘⇧T (Command-Shift-T)   | Son kapatılan tab'ı aç (birkaç kez kullanılabilir) |
| ⌘\[                     | Browsing history'de bir sayfa geri git      |
| ⌘]                      | Browsing history'de bir sayfa ileri git   |
| ⌘⇧R                     | Reader Mode'u etkinleştir                             |

#### Mail shortcuts

| Shortcut                   | Action                       |
| -------------------------- | ---------------------------- |
| ⌘L                         | Location'ı aç                |
| ⌘T                         | Yeni bir tab aç               |
| ⌘W                         | Mevcut tab'ı kapat               |
| ⌘R                         | Mevcut tab'ı yenile               |
| ⌘.                         | Mevcut tab'ın yüklenmesini durdur |
| ⌘⌥F (Command-Option/Alt-F) | Mailbox'ında ara       |

## References

- [1] [Citrix ve diğer Restricted Desktop Environments'tan çıkış](https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/)
- [2] [Bana bir browser verin, size bir shell vereyim](https://medium.com/@Rend_/give-me-a-browser-ill-give-you-a-shell-de19811defa0)
- [3] [Bilmeniz gereken yalnızca iPad'e özgü 6 gesture](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
- [4] [iPad shortcuts guide](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
- [5] [En iyi iPad Keyboard Shortcuts](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
- [6] [iPad Keyboard Shortcuts](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)
- [7] [howtohaven.com - Windows Explorer'da File Extension'larını Gösterme](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

{{#include ../banners/hacktricks-training.md}}
