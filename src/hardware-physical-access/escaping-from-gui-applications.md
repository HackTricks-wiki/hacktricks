# KIOSK'lardan Kaçış

{{#include ../banners/hacktricks-training.md}}

---

## Fiziksel cihazı kontrol et

| Component    | Action                                                             |
| ------------ | ------------------------------------------------------------------ |
| Power button | Turning the device off and on again may expose the start screen    |
| Power cable  | Check whether the device reboots when the power is cut off briefly |
| USB ports    | Connect physical keyboard with more shortcuts                      |
| Ethernet     | Network scan or sniffing may enable further exploitation           |

## GUI uygulaması içinde olası eylemleri kontrol et

**Sık kullanılan diyaloglar** (Common Dialogs), **dosya kaydetme**, **dosya açma**, yazı tipi veya renk seçme gibi seçeneklerdir. Bu diyalogların çoğu **tam bir Explorer işlevselliği** sunar. Bu, bu seçeneklere erişebiliyorsanız Explorer işlevlerine erişebileceğiniz anlamına gelir:

- Close/Close as
- Open/Open with
- Print
- Export/Import
- Search
- Scan

Şunları kontrol edin:

- Dosyaları değiştirme veya yeni dosyalar oluşturma
- Sembolik bağlantılar oluşturma
- Kısıtlı alanlara erişim sağlama
- Diğer uygulamaları çalıştırma

### Komut çalıştırma

Belki **`Open with`** seçeneğini kullanarak bir shell açabilir/çalıştırabilirsiniz.

#### Windows

Örneğin _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ komut çalıştırmak (ve beklenmeyen işlemler gerçekleştirmek) için kullanılabilecek daha fazla binary'yi şuradan bulabilirsiniz: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

#### \*NIX \_\_

_bash, sh, zsh..._ Daha fazla bilgi: [https://gtfobins.github.io/](https://gtfobins.github.io)

## Windows

### Path kısıtlamalarını atlatma

- **Çevresel değişkenler**: Bazı dizinlere işaret eden birçok environment variable vardır
- **Diğer protokoller**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
- **Sembolik bağlantılar**
- **Kısayollar**: CTRL+N (yeni oturum aç), CTRL+R (Komutları Çalıştır), CTRL+SHIFT+ESC (Görev Yöneticisi), Windows+E (explorer aç), CTRL-B, CTRL-I (Favourites), CTRL-H (History), CTRL-L, CTRL-O (File/Open Dialog), CTRL-P (Print Dialog), CTRL-S (Save As)
- Gizli Yönetici menüsü: CTRL-ALT-F8, CTRL-ESC-F9
- **Shell URI'leri**: _shell:Administrative Tools, shell:DocumentsLibrary, shell:Librariesshell:UserProfiles, shell:Personal, shell:SearchHomeFolder, shell:Systemshell:NetworkPlacesFolder, shell:SendTo, shell:UsersProfiles, shell:Common Administrative Tools, shell:MyComputerFolder, shell:InternetFolder_
- **UNC paths**: Paylaşılan klasörlere bağlanmak için yollar. Yerel makinenin C$'ine bağlanmayı deneyin ("\\\127.0.0.1\c$\Windows\System32")
- **Daha fazla UNC yolu:**

| UNC                       | UNC            | UNC                  |
| ------------------------- | -------------- | -------------------- |
| %ALLUSERSPROFILE%         | %APPDATA%      | %CommonProgramFiles% |
| %COMMONPROGRAMFILES(x86)% | %COMPUTERNAME% | %COMSPEC%            |
| %HOMEDRIVE%               | %HOMEPATH%     | %LOCALAPPDATA%       |
| %LOGONSERVER%             | %PATH%         | %PATHEXT%            |
| %ProgramData%             | %ProgramFiles% | %ProgramFiles(x86)%  |
| %PROMPT%                  | %PSModulePath% | %Public%             |
| %SYSTEMDRIVE%             | %SYSTEMROOT%   | %TEMP%               |
| %TMP%                     | %USERDOMAIN%   | %USERNAME%           |
| %USERPROFILE%             | %WINDIR%       |                      |

### Kısıtlı Masaüstü Kaçışları (Citrix/RDS/VDI)

- **Dialog-box pivoting**: *Open/Save/Print-to-file* diyaloglarını Explorer-lite olarak kullanın. Dosya adı alanına `*.*` / `*.exe` deneyin, klasörlere sağ tıklayarak **Open in new window** seçeneğini kullanın ve navigasyonu genişletmek için **Properties → Open file location** kullanın.
- **Create execution paths from dialogs**: Yeni bir dosya oluşturup adını `.CMD` veya `.BAT` olarak değiştirin veya `%WINDIR%\System32`'yi (veya `%WINDIR%\System32\cmd.exe` gibi belirli bir binary'yi) işaret eden bir kısayol oluşturun.
- **Shell launch pivots**: Eğer `cmd.exe`'ye göz atabiliyorsanız, herhangi bir dosyayı üzerine **drag-and-drop** yaparak bir komut istemi başlatmayı deneyin. Görev Yöneticisi ulaşılabiliyorsa (`CTRL+SHIFT+ESC`), **Run new task** kullanın.
- **Task Scheduler bypass**: İnteraktif shell'ler engellenmiş ama planlama izinliyse, `cmd.exe` çalıştıracak bir görev oluşturun (GUI `taskschd.msc` veya `schtasks.exe`).
- **Weak allowlists**: Eğer yürütme **dosya adı/uzantı** ile izinliyse, payload'unuzu izin verilen bir isme yeniden adlandırın. Eğer **dizin** ile izinliyse, payload'u izin verilen bir program klasörüne kopyalayın ve orada çalıştırın.
- **Yazılabilir staging yollarını bulun**: `%TEMP%` ile başlayın ve yazılabilir klasörleri Sysinternals AccessChk ile sayın.
```cmd
echo %TEMP%
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
```
- **Sonraki adım**: Eğer shell elde ederseniz, Windows LPE kontrol listesine pivot yapın:
{{#ref}}
../windows-hardening/checklist-windows-privilege-escalation.md
{{#endref}}

### İkili Dosyalarınızı İndirin

Console: [https://sourceforge.net/projects/console/](https://sourceforge.net/projects/console/)\
Explorer: [https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/](https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/)\
Registry editor: [https://sourceforge.net/projects/uberregedit/](https://sourceforge.net/projects/uberregedit/)

### Tarayıcıdan dosya sistemine erişim

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

- Sticky Keys – SHIFT tuşuna 5 kez basın
- Mouse Keys – SHIFT+ALT+NUMLOCK
- High Contrast – SHIFT+ALT+PRINTSCN
- Toggle Keys – NUMLOCK tuşunu 5 saniye basılı tutun
- Filter Keys – sağ SHIFT tuşunu 12 saniye basılı tutun
- WINDOWS+F1 – Windows Arama
- WINDOWS+D – Masaüstünü göster
- WINDOWS+E – Windows Explorer'ı başlat
- WINDOWS+R – Çalıştır
- WINDOWS+U – Ease of Access Center
- WINDOWS+F – Arama
- SHIFT+F10 – İçerik menüsü
- CTRL+SHIFT+ESC – Görev Yöneticisi
- CTRL+ALT+DEL – Yeni Windows sürümlerinde splash ekranı
- F1 – Yardım F3 – Arama
- F6 – Adres Çubuğu
- F11 – Internet Explorer içinde tam ekrana geçiş
- CTRL+H – Internet Explorer Geçmişi
- CTRL+T – Internet Explorer – Yeni Sekme
- CTRL+N – Internet Explorer – Yeni Sayfa
- CTRL+O – Dosya Aç
- CTRL+S – Kaydet CTRL+N – Yeni RDP / Citrix

### Kaydırma hareketleri

- Sol taraftan sağa kaydırarak açık tüm pencereleri görün, KIOSK uygulamasını küçültün ve doğrudan tüm OS'ye erişin;
- Sağ taraftan sola kaydırarak Action Center'ı açın, KIOSK uygulamasını küçültün ve doğrudan tüm OS'ye erişin;
- Üst kenardan içeri doğru kaydırarak tam ekranda açılmış bir uygulamanın başlık çubuğunu görünür hale getirin;
- Alt kenardan yukarı kaydırarak tam ekran uygulamada görev çubuğunu gösterin.

### Internet Explorer İpuçları

#### 'Image Toolbar'

Bir görsele tıklandığında sol üstte beliren bir araç çubuğudur. Kaydetme (Save), Yazdırma (Print), Mailto, Explorer'da "My Pictures"ı Açma gibi işlemleri yapabilmenizi sağlar. Kiosk'un Internet Explorer kullanıyor olması gerekir.

#### Shell Protokolü

Aşağıdaki URL'leri yazarak Explorer görünümü elde edin:

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
- `shell:::{21EC2020-3AEA-1069-A2DD-08002B30309D}` --> Kontrol Paneli
- `shell:::{20D04FE0-3AEA-1069-A2D8-08002B30309D}` --> Bilgisayarım
- `shell:::{{208D2C60-3AEA-1069-A2D7-08002B30309D}}` --> My Network Places
- `shell:::{871C5380-42A0-1069-A2EA-08002B30309D}` --> Internet Explorer

### Dosya Uzantılarını Göster

Daha fazla bilgi için bu sayfayı kontrol edin: [https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

## Tarayıcı püf noktaları

Yedek iKat sürümleri:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)

JavaScript kullanarak ortak bir dialog oluşturun ve dosya gezginine erişin: `document.write('<input/type=file>')`\
Source: https://medium.com/@Rend\_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

## iPad

### Jestler ve düğmeler

- Dört (veya beş) parmakla yukarı kaydırma / Ana düğmeye çift dokunma: Çoklu görev görünümünü görüntüleyip uygulama değiştirmek için
- Dört veya beş parmakla bir yönde kaydırma: Sonraki/önceki uygulamaya geçmek için
- Beş parmakla ekranı sıkıştırma / Ana düğmeye dokunma / Alt kenardan hızlı bir hareketle tek parmakla yukarı kaydırma: Ana ekrana erişmek için
- Alt kenardan tek parmakla 1-2 inç (yavaş) kaydırma: Dock görünür olur
- Üst ekrandan tek parmakla aşağı kaydırma: Bildirimleri görüntülemek için
- Ekranın sağ üst köşesinden tek parmakla aşağı kaydırma: iPad Pro kontrol merkezini görmek için
- Ekranın solundan tek parmakla 1-2 inç kaydırma: Today görünümünü görmek için
- Ekranın ortasından sağa veya sola hızlı tek parmak kaydırma: Sonraki/önceki uygulamaya geçmek için
- iPad'in üst sağ köşesindeki On/Off/Uykudan Çıkarma düğmesine basılı tutun + Slide to power off kaydırıcısını tamamen sağa kaydırın: Kapatmak için
- iPad'in üst sağ köşesindeki On/Off/Uykudan Çıkarma düğmesine ve Home düğmesine birkaç saniye basılı tutun: Zorla kapatma yapmak için
- iPad'in üst sağ köşesindeki On/Off/Uykudan Çıkarma düğmesine ve Home düğmesine hızlıca basın: Ekranın sol alt köşesinde açılan ekran görüntüsü almak için. Her iki düğmeye çok kısa süreli birlikte basın; birkaç saniye tutulursa zorla kapatma gerçekleşir.

### Kısayollar

Bir iPad klavyesine veya bir USB klavye adaptörüne sahip olmalısınız. Sadece uygulamadan kaçmaya yardımcı olabilecek kısayollar burada gösterilmiştir.

| Tuş | İsim         |
| --- | ------------ |
| ⌘   | Command      |
| ⌥   | Option (Alt) |
| ⇧   | Shift        |
| ↩   | Return       |
| ⇥   | Tab          |
| ^   | Control      |
| ←   | Sol Ok       |
| →   | Sağ Ok       |
| ↑   | Yukarı Ok    |
| ↓   | Aşağı Ok     |

#### Sistem kısayolları

Bu kısayollar görsel ve ses ayarları içindir; iPad kullanımına bağlı olarak değişebilir.

| Kısayol | İşlem                                                                          |
| ------- | ------------------------------------------------------------------------------ |
| F1      | Ekranı karart                                                                  |
| F2      | Ekranı parlaklaştır                                                             |
| F7      | Bir önceki şarkı                                                               |
| F8      | Oynatma/duraklatma                                                              |
| F9      | Şarkıyı atla                                                                    |
| F10     | Sesi kapat                                                                      |
| F11     | Sesi azalt                                                                      |
| F12     | Sesi artır                                                                      |
| ⌘ Space | Kullanılabilir dillerin listesini görüntüler; birini seçmek için tekrar space tuşuna dokunun. |

#### iPad gezintisi

| Kısayol                                           | İşlem                                              |
| ------------------------------------------------- | --------------------------------------------------- |
| ⌘H                                               | Ana ekrana git                                     |
| ⌘⇧H (Command-Shift-H)                            | Ana ekrana git                                     |
| ⌘ (Space)                                        | Spotlight'ı aç                                     |
| ⌘⇥ (Command-Tab)                                 | Son kullanılan on uygulamayı listele               |
| ⌘\~                                              | Son uygulamaya git                                 |
| ⌘⇧3 (Command-Shift-3)                            | Ekran görüntüsü (kaydetme veya işlem için sol altta yüzer) |
| ⌘⇧4                                             | Ekran görüntüsü al ve düzenleyicide aç              |
| ⌘ tuşuna basılı tut                                 | Uygulamaya özel kullanılabilir kısayolların listesi |
| ⌘⌥D (Command-Option/Alt-D)                       | Dock'u göster                                      |
| ^⌥H (Control-Option-H)                           | Home düğmesi                                       |
| ^⌥H H (Control-Option-H-H)                       | Çoklu görev çubuğunu göster                        |
| ^⌥I (Control-Option-i)                           | Öğe seçici                                         |
| Escape                                           | Geri düğmesi                                       |
| → (Sağ ok)                                       | Sonraki öğe                                        |
| ← (Sol ok)                                       | Önceki öğe                                         |
| ↑↓ (Yukarı ok, Aşağı ok)                         | Seçili öğeye aynı anda dokunma                     |
| ⌥ ↓ (Option-Aşağı ok)                            | Aşağı kaydır                                        |
| ⌥↑ (Option-Yukarı ok)                            | Yukarı kaydır                                       |
| ⌥← veya ⌥→ (Option-Sol ok veya Option-Sağ ok)    | Sola veya sağa kaydır                              |
| ^⌥S (Control-Option-S)                           | VoiceOver konuşmasını açıp kapat                   |
| ⌘⇧⇥ (Command-Shift-Tab)                          | Önceki uygulamaya geç                              |
| ⌘⇥ (Command-Tab)                                 | Orijinal uygulamaya geri dön                       |
| ←+→, sonra Option + ← veya Option+→              | Dock içinde gezinme                                |

#### Safari kısayolları

| Kısayol                | İşlem                                           |
| ---------------------- | ------------------------------------------------ |
| ⌘L (Command-L)         | Konum alanını aç                                 |
| ⌘T                    | Yeni sekme aç                                    |
| ⌘W                    | Mevcut sekmeyi kapat                             |
| ⌘R                    | Mevcut sekmeyi yenile                            |
| ⌘.                    | Mevcut sekmenin yüklenmesini durdur               |
| ^⇥                    | Sonraki sekmeye geç                               |
| ^⇧⇥ (Control-Shift-Tab) | Önceki sekmeye geç                                |
| ⌘L                    | Metin giriş/URL alanını seç ve düzenle            |
| ⌘⇧T (Command-Shift-T) | Son kapatılan sekmeyi tekrar aç (birkaç kez kullanılabilir) |
| ⌘\[                   | Geçmişte bir sayfa geri git                       |
| ⌘]                    | Geçmişte bir sayfa ileri git                      |
| ⌘⇧R                  | Reader Modu'nu etkinleştir                        |

#### Mail kısayolları

| Kısayol                   | İşlem                       |
| ------------------------- | --------------------------- |
| ⌘L                        | Konumu aç                   |
| ⌘T                        | Yeni sekme aç               |
| ⌘W                        | Mevcut sekmeyi kapat        |
| ⌘R                        | Mevcut sekmeyi yenile       |
| ⌘.                        | Mevcut sekmenin yüklenmesini durdur |
| ⌘⌥F (Command-Option/Alt-F) | Posta kutusunda ara         |

## Kaynaklar

- [https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/](https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/)
- [https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
- [https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
- [https://thesweetsetup.com/best-ipad-keyboard-shortcuts/](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
- [http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)

{{#include ../banners/hacktricks-training.md}}
