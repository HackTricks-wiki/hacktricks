# KIOSK'lerden Kaçış

{{#include ../banners/hacktricks-training.md}}

---

## Fiziksel cihazı kontrol et

| Component    | Action                                                             |
| ------------ | ------------------------------------------------------------------ |
| Power button | Cihazı kapatıp tekrar açmak başlangıç ekranını ortaya çıkarabilir   |
| Power cable  | Güç kısa süreli kesildiğinde cihazın yeniden başlatılıp başlatılmadığını kontrol et |
| USB ports    | Daha fazla kısayola sahip fiziksel bir klavye bağla                |
| Ethernet     | Ağ taraması veya sniffing ek istismar imkanları sağlayabilir       |

## GUI uygulaması içinde mümkün eylemleri kontrol et

**Yaygın Diyaloglar** bunlar bir dosyayı kaydetme, bir dosyayı açma, bir font seçme, bir renk seçme... gibi seçeneklerdir. Çoğu tam bir Explorer işlevselliği sunar. Bu, bu seçeneklere erişebilirseniz Explorer işlevlerine erişebileceğiniz anlamına gelir:

- Close/Close as
- Open/Open with
- Print
- Export/Import
- Search
- Scan

Şu kontrolleri yapmalısınız:

- Dosyaları değiştirmek veya yeni dosyalar oluşturmak
- Sembolik linkler oluşturmak
- Kısıtlı alanlara erişim sağlamak
- Diğer uygulamaları çalıştırmak

### Komut Çalıştırma

Belki `Open with` seçeneğini kullanarak bir tür shell açabilir/çalıştırabilirsiniz.

#### Windows

Örneğin _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ komut yürütmek için kullanılabilecek (ve beklenmeyen eylemler gerçekleştirebilecek) daha fazla binary için buraya bakın: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

#### \*NIX \_\_

_bash, sh, zsh..._ Daha fazlası burada: [https://gtfobins.github.io/](https://gtfobins.github.io)

## Windows

### Yol kısıtlamalarını atlatma

- **Environment variables**: Birçok çevresel değişken belirli bir yola işaret eder
- **Diğer protokoller**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
- **Sembolik linkler**
- **Kısayollar**: CTRL+N (yeni oturum aç), CTRL+R (Komut Çalıştır), CTRL+SHIFT+ESC (Görev Yöneticisi), Windows+E (Explorer'ı aç), CTRL-B, CTRL-I (Sık Kullanılanlar), CTRL-H (Geçmiş), CTRL-L, CTRL-O (Dosya/Aç diyaloğu), CTRL-P (Yazdırma diyaloğu), CTRL-S (Farklı Kaydet)
- Gizli Yönetici menüsü: CTRL-ALT-F8, CTRL-ESC-F9
- **Shell URIs**: _shell:Administrative Tools, shell:DocumentsLibrary, shell:Librariesshell:UserProfiles, shell:Personal, shell:SearchHomeFolder, shell:Systemshell:NetworkPlacesFolder, shell:SendTo, shell:UsersProfiles, shell:Common Administrative Tools, shell:MyComputerFolder, shell:InternetFolder_
- **UNC paths**: Paylaşılan klasörlere bağlanmak için yollar. Yerel makinenin C$'ine bağlanmayı denemelisiniz ("\\\127.0.0.1\c$\Windows\System32")
- **More UNC paths:**

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

- **Dialog-box pivoting**: *Open/Save/Print-to-file* diyaloglarını Explorer-lite olarak kullanın. Dosya adı alanına `*.*` / `*.exe` yazmayı deneyin, klasörlerde sağ tıklayıp **Open in new window** seçeneğini kullanın ve navigasyonu genişletmek için **Properties → Open file location**'ı kullanın.
- **Create execution paths from dialogs**: Yeni bir dosya oluşturup `.CMD` veya `.BAT` olarak yeniden adlandırın veya `%WINDIR%\System32`'i (veya `%WINDIR%\System32\cmd.exe` gibi belirli bir binary'i) işaret eden bir kısayol oluşturun.
- **Shell launch pivots**: Eğer `cmd.exe`'e göz atabiliyorsanız, herhangi bir dosyayı üzerine sürükle-bırak (drag-and-drop) yaparak bir komut istemi başlatmayı deneyin. Eğer Görev Yöneticisi erişilebiliyorsa (`CTRL+SHIFT+ESC`), **Run new task**'ı kullanın.
- **Task Scheduler bypass**: Eğer etkileşimli shell'ler engellenmiş ama zamanlama izinliyse, `cmd.exe` çalıştıracak bir görev oluşturun (GUI `taskschd.msc` veya `schtasks.exe`).
- **Zayıf allowlist'ler**: Eğer yürütme **filename/extension** ile izin veriliyorsa, payload'unuzu izinli bir isimle yeniden adlandırın. Eğer **directory** ile izin veriliyorsa, payload'u izin verilen bir program klasörüne kopyalayıp orada çalıştırın.
- **Yazılabilir staging yolları bulma**: `%TEMP%` ile başlayın ve yazılabilir klasörleri Sysinternals AccessChk ile listeleyin.
```cmd
echo %TEMP%
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
```
- **Sonraki adım**: Eğer shell elde ederseniz, Windows LPE checklist'e pivot yapın:
{{#ref}}
../windows-hardening/checklist-windows-privilege-escalation.md
{{#endref}}

### İkili Dosyalarınızı İndirin

Console: [https://sourceforge.net/projects/console/](https://sourceforge.net/projects/console/)\
Explorer: [https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/](https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/)\
Registry editor: [https://sourceforge.net/projects/uberregedit/](https://sourceforge.net/projects/uberregedit/)

### Tarayıcıdan dosya sistemine erişme

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
- Toggle Keys – NUMLOCK tuşunu 5 saniye basılı tutun
- Filter Keys – Sağ SHIFT tuşunu 12 saniye basılı tutun
- WINDOWS+F1 – Windows Arama
- WINDOWS+D – Masaüstünü Göster
- WINDOWS+E – Windows Explorer'ı Başlat
- WINDOWS+R – Çalıştır
- WINDOWS+U – Ease of Access Merkezi
- WINDOWS+F – Ara
- SHIFT+F10 – Bağlam Menüsü
- CTRL+SHIFT+ESC – Görev Yöneticisi
- CTRL+ALT+DEL – Yeni Windows sürümlerinde açılış ekranı
- F1 – Yardım F3 – Ara
- F6 – Adres Çubuğu
- F11 – Internet Explorer içinde tam ekran geçişi
- CTRL+H – Internet Explorer Geçmişi
- CTRL+T – Internet Explorer – Yeni Sekme
- CTRL+N – Internet Explorer – Yeni Sayfa
- CTRL+O – Dosya Aç
- CTRL+S – Kaydet CTRL+N – Yeni RDP / Citrix

### Kaydırma Hareketleri

- Sol taraftan sağa kaydırarak açık tüm pencereleri görün; KIOSK uygulamasını küçültür ve doğrudan tüm OS'e erişim sağlar;
- Sağ taraftan sola kaydırarak Action Center'ı açın; KIOSK uygulamasını küçültür ve doğrudan tüm OS'e erişim sağlar;
- Üst kenardan içeri kaydırarak tam ekran açılmış bir uygulama için başlık çubuğunu görünür yapın;
- Alt taraftan yukarı kaydırarak tam ekran uygulamada görev çubuğunu gösterin.

### Internet Explorer İpuçları

#### 'Image Toolbar'

Bir resme tıklandığında resmin sol üstünde görünen bir araç çubuğudur. Save, Print, Mailto, Explorer'da "My Pictures"i Aç gibi işlemleri yapabileceksiniz. KIOSK'un Internet Explorer kullanıyor olması gerekir.

#### Shell Protokolü

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
- `shell:::{21EC2020-3AEA-1069-A2DD-08002B30309D}` --> Denetim Masası
- `shell:::{20D04FE0-3AEA-1069-A2D8-08002B30309D}` --> Bilgisayarım
- `shell:::{{208D2C60-3AEA-1069-A2D7-08002B30309D}}` --> Ağ Komşuları
- `shell:::{871C5380-42A0-1069-A2EA-08002B30309D}` --> Internet Explorer

### Dosya Uzantılarını Göster

Daha fazla bilgi için bu sayfayı kontrol edin: [https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

## Tarayıcı ipuçları

Yedek iKat sürümleri:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)

JavaScript kullanarak ortak bir dialog oluşturup file explorer'a erişin: `document.write('<input/type=file>')`\
Source: https://medium.com/@Rend\_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

## iPad

### Hareketler ve düğmeler

- Dört (veya beş) parmakla yukarı kaydır / Ana ekran düğmesine çift dokun: Çoklu görev görünümünü görüntüleyip uygulamalar arasında geçiş yapmak için
- Dört veya beş parmakla bir yönde kaydırma: Sonraki/önceki uygulamaya geçmek için
- Beş parmakla ekranı sıkıştırma / Ana düğmeye dokunma / Alt kenardan tek parmakla hızlıca yukarı kaydırma: Ana ekrana erişmek için
- Alt kenardan tek parmakla 1-2 inç kadar yavaşça kaydırma: Dock görünür olur
- Ekranın üstünden tek parmakla aşağı kaydırma: Bildirimlerinizi görüntülemek için
- Ekranın sağ üst köşesinden tek parmakla aşağı kaydırma: iPad Pro kontrol merkezini görmek için
- Ekranın solundan tek parmakla 1-2 inç kaydırma: Bugün görünümünü görmek için
- Ekranın ortasından sağa veya sola hızlıca tek parmakla kaydırma: Sonraki/önceki uygulamaya geçmek için
- iPad'in sağ üst köşesindeki Açık/Kapat/Uyku düğmesini basılı tutun + Gücü kapat kaydırıcısını tamamen sağa kaydırın: Kapatmak için
- iPad'in sağ üst köşesindeki Açık/Kapat/Uyku düğmesini ve Ana düğmeyi birkaç saniye basılı tutun: Zorla kapatma yapmak için
- iPad'in sağ üst köşesindeki Açık/Kapat/Uyku düğmesini ve Ana düğmeyi hızlıca basın: Ekranın sol alt köşesinde belirecek bir ekran görüntüsü almak için. Her iki düğmeye çok kısa süre basın; birkaç saniye basılı tutarsanız zorla kapatma gerçekleşir.

### Kısayollar

Bir iPad klavyeniz veya bir USB klavye adaptörünüz olmalıdır. Yalnızca uygulamadan kaçmaya yardımcı olabilecek kısayollar burada gösterilecektir.

| Key | Name         |
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

Bu kısayollar görsel ayarlar ve ses ayarları içindir, iPad kullanımına bağlı olarak değişir.

| Shortcut | Action                                                                 |
| -------- | ---------------------------------------------------------------------- |
| F1       | Ekranı karartır                                                        |
| F2       | Ekranı parlaklaştırır                                                  |
| F7       | Bir önceki şarkı                                                      |
| F8       | Oynat/duraklat                                                         |
| F9       | Şarkıyı atla                                                           |
| F10      | Sessiz yap                                                              |
| F11      | Sesi azalt                                                              |
| F12      | Sesi artır                                                              |
| ⌘ Space  | Kullanılabilir dillerin listesini gösterir; birini seçmek için tekrar boşluk çubuğuna dokunun. |

#### iPad gezintisi

| Shortcut                                           | Action                                                             |
| -------------------------------------------------- | ------------------------------------------------------------------ |
| ⌘H                                                 | Ana ekrana git                                                     |
| ⌘⇧H (Command-Shift-H)                              | Ana ekrana git                                                     |
| ⌘ (Space)                                          | Spotlight'u aç                                                     |
| ⌘⇥ (Command-Tab)                                   | Son kullanılan on uygulamayı listeler                              |
| ⌘\~                                                | Son uygulamaya git                                                  |
| ⌘⇧3 (Command-Shift-3)                              | Ekran görüntüsü (kaydetmek veya işlem yapmak için sol alt köşede yüzer) |
| ⌘⇧4                                                | Ekran görüntüsü alır ve düzenleyicide açar                         |
| Press and hold ⌘                                   | Uygulama için kullanılabilir kısayolların listesini gösterir       |
| ⌘⌥D (Command-Option/Alt-D)                         | Dock'u getirir                                                     |
| ^⌥H (Control-Option-H)                             | Ana düğme                                                          |
| ^⌥H H (Control-Option-H-H)                         | Çoklu görev çubuğunu göster                                         |
| ^⌥I (Control-Option-i)                             | Öğe seçici                                                          |
| Escape                                             | Geri düğmesi                                                       |
| → (Right arrow)                                    | Sonraki öğe                                                         |
| ← (Left arrow)                                     | Önceki öğe                                                          |
| ↑↓ (Up arrow, Down arrow)                          | Seçili öğeye aynı anda dokunmak                                      |
| ⌥ ↓ (Option-Down arrow)                            | Aşağı kaydır                                                         |
| ⌥↑ (Option-Up arrow)                               | Yukarı kaydır                                                        |
| ⌥← or ⌥→ (Option-Left arrow or Option-Right arrow) | Sola veya sağa kaydır                                               |
| ^⌥S (Control-Option-S)                             | VoiceOver konuşmasını açıp kapatır                                  |
| ⌘⇧⇥ (Command-Shift-Tab)                            | Önceki uygulamaya geç                                                 |
| ⌘⇥ (Command-Tab)                                   | Orijinal uygulamaya geri dön                                         |
| ←+→, then Option + ← or Option+→                   | Dock arasında gezinmek                                               |

#### Safari kısayolları

| Shortcut                | Action                                           |
| ----------------------- | ------------------------------------------------ |
| ⌘L (Command-L)          | Konumu aç                                        |
| ⌘T                      | Yeni sekme aç                                    |
| ⌘W                      | Mevcut sekmeyi kapat                             |
| ⌘R                      | Mevcut sekmeyi yenile                            |
| ⌘.                      | Mevcut sekmenin yüklenmesini durdur               |
| ^⇥                      | Bir sonraki sekmeye geç                           |
| ^⇧⇥ (Control-Shift-Tab) | Önceki sekmeye geç                                |
| ⌘L                      | Metin girişini/URL alanını seç ve düzenle         |
| ⌘⇧T (Command-Shift-T)   | Son kapatılan sekmeyi aç (birden fazla kez kullanılabilir) |
| ⌘\[                     | Tarama geçmişinde bir sayfa geri gider            |
| ⌘]                      | Tarama geçmişinde bir sayfa ileri gider           |
| ⌘⇧R                     | Reader Modunu etkinleştir                         |

#### Mail kısayolları

| Shortcut                   | Action                       |
| -------------------------- | ---------------------------- |
| ⌘L                         | Konumu aç                    |
| ⌘T                         | Yeni sekme aç                |
| ⌘W                         | Mevcut sekmeyi kapat         |
| ⌘R                         | Mevcut sekmeyi yenile        |
| ⌘.                         | Mevcut sekmenin yüklenmesini durdur |
| ⌘⌥F (Command-Option/Alt-F) | Posta kutunuzda arama yapar  |

## Kaynaklar

- [https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/](https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/)
- [https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
- [https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
- [https://thesweetsetup.com/best-ipad-keyboard-shortcuts/](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
- [http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)

{{#include ../banners/hacktricks-training.md}}
