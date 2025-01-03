# KIOSK'lerden Kaçış

{{#include ../banners/hacktricks-training.md}}

---

## Fiziksel cihazı kontrol et

| Bileşen      | Eylem                                                              |
| ------------ | ------------------------------------------------------------------ |
| Güç düğmesi  | Cihazı kapatıp açmak başlangıç ekranını açabilir                    |
| Güç kablosu  | Güç kesildiğinde cihazın yeniden başlatılıp başlatılmadığını kontrol et |
| USB portları  | Daha fazla kısayol ile fiziksel klavye bağla                       |
| Ethernet      | Ağ taraması veya dinleme daha fazla istismar imkanı sağlayabilir    |

## GUI uygulaması içinde olası eylemleri kontrol et

**Ortak Diyaloglar**, **bir dosyayı kaydetme**, **bir dosyayı açma**, bir yazı tipi, bir renk seçme gibi seçeneklerdir... Bunların çoğu **tam bir Gezgini işlevselliği sunar**. Bu, bu seçeneklere erişebiliyorsanız Gezgini işlevselliğine erişebileceğiniz anlamına gelir:

- Kapat/Kapat olarak
- Aç/Aç ile
- Yazdır
- Dışa aktar/Içe aktar
- Ara
- Tara

Şunları kontrol etmelisin:

- Dosyaları değiştirme veya yeni dosyalar oluşturma
- Sembolik bağlantılar oluşturma
- Kısıtlı alanlara erişim sağlama
- Diğer uygulamaları çalıştırma

### Komut Yürütme

Belki **`Aç ile`** seçeneğini kullanarak bazı türde bir shell açabilir/çalıştırabilirsin.

#### Windows

Örneğin _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ burada komutları çalıştırmak (ve beklenmedik eylemler gerçekleştirmek) için kullanılabilecek daha fazla ikili dosya bul: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

#### \*NIX \_\_

_bash, sh, zsh..._ Daha fazla burada: [https://gtfobins.github.io/](https://gtfobins.github.io)

## Windows

### Yol kısıtlamalarını aşma

- **Ortam değişkenleri**: Bazı yollara işaret eden birçok ortam değişkeni vardır
- **Diğer protokoller**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
- **Sembolik bağlantılar**
- **Kısayollar**: CTRL+N (yeni oturum aç), CTRL+R (Komutları Çalıştır), CTRL+SHIFT+ESC (Görev Yöneticisi), Windows+E (gezgini aç), CTRL-B, CTRL-I (Favoriler), CTRL-H (Geçmiş), CTRL-L, CTRL-O (Dosya/Aç Diyaloğu), CTRL-P (Yazdırma Diyaloğu), CTRL-S (Farklı Kaydet)
- Gizli Yönetici menüsü: CTRL-ALT-F8, CTRL-ESC-F9
- **Shell URI'leri**: _shell:Administrative Tools, shell:DocumentsLibrary, shell:Librariesshell:UserProfiles, shell:Personal, shell:SearchHomeFolder, shell:Systemshell:NetworkPlacesFolder, shell:SendTo, shell:UsersProfiles, shell:Common Administrative Tools, shell:MyComputerFolder, shell:InternetFolder_
- **UNC yolları**: Paylaşılan klasörlere bağlanmak için yollar. Yerel makinenin C$'sine bağlanmayı denemelisin ("\\\127.0.0.1\c$\Windows\System32")
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

### İkili Dosyalarınızı İndirin

Konsol: [https://sourceforge.net/projects/console/](https://sourceforge.net/projects/console/)\
Gezgini: [https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/](https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/)\
Kayıt defteri düzenleyici: [https://sourceforge.net/projects/uberregedit/](https://sourceforge.net/projects/uberregedit/)

### Tarayıcıdan dosya sistemine erişim

| YOL                | YOL              | YOL               | YOL                |
| ------------------- | ----------------- | ------------------ | ------------------- |
| File:/C:/windows    | File:/C:/windows/ | File:/C:/windows\\ | File:/C:\windows    |
| File:/C:\windows\\  | File:/C:\windows/ | File://C:/windows  | File://C:/windows/  |
| File://C:/windows\\ | File://C:\windows | File://C:\windows/ | File://C:\windows\\ |
| C:/windows          | C:/windows/       | C:/windows\\       | C:\windows          |
| C:\windows\\        | C:\windows/       | %WINDIR%           | %TMP%               |
| %TEMP%              | %SYSTEMDRIVE%     | %SYSTEMROOT%       | %APPDATA%           |
| %HOMEDRIVE%         | %HOMESHARE        |                    | <p><br></p>         |

### Kısayollar

- Yapışkan Tuşlar – SHIFT tuşuna 5 kez bas
- Fare Tuşları – SHIFT+ALT+NUMLOCK
- Yüksek Kontrast – SHIFT+ALT+PRINTSCN
- Anahtarları Değiştir – NUMLOCK tuşuna 5 saniye basılı tut
- Filtre Tuşları – sağ SHIFT tuşuna 12 saniye basılı tut
- WINDOWS+F1 – Windows Arama
- WINDOWS+D – Masaüstünü Göster
- WINDOWS+E – Windows Gezgini'ni Başlat
- WINDOWS+R – Çalıştır
- WINDOWS+U – Erişim Kolaylığı Merkezi
- WINDOWS+F – Ara
- SHIFT+F10 – Bağlam Menüsü
- CTRL+SHIFT+ESC – Görev Yöneticisi
- CTRL+ALT+DEL – Daha yeni Windows sürümlerinde açılış ekranı
- F1 – Yardım F3 – Ara
- F6 – Adres Çubuğu
- F11 – Internet Explorer'da tam ekranı aç/kapat
- CTRL+H – Internet Explorer Geçmişi
- CTRL+T – Internet Explorer – Yeni Sekme
- CTRL+N – Internet Explorer – Yeni Sayfa
- CTRL+O – Dosya Aç
- CTRL+S – Kaydet CTRL+N – Yeni RDP / Citrix

### Kaydırmalar

- Sol taraftan sağa kaydırarak tüm açık pencereleri görmek, KIOSK uygulamasını küçültmek ve tüm işletim sistemine doğrudan erişmek için;
- Sağ taraftan sola kaydırarak Eylem Merkezi'ni açmak, KIOSK uygulamasını küçültmek ve tüm işletim sistemine doğrudan erişmek için;
- Üst kenardan kaydırarak tam ekran modunda açılan bir uygulamanın başlık çubuğunu görünür hale getirmek için;
- Alt taraftan yukarı kaydırarak tam ekran uygulamasında görev çubuğunu göstermek için.

### Internet Explorer Hileleri

#### 'Resim Araç Çubuğu'

Tıklandığında resmin sol üst kısmında beliren bir araç çubuğudur. Kaydetme, Yazdırma, Mailto, "Resimlerim"i Gezginde Açma işlemlerini yapabileceksiniz. Kiosk'un Internet Explorer kullanması gerekir.

#### Shell Protokolü

Bir Gezgini görünümü elde etmek için bu URL'leri yazın:

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
- `shell:::{{208D2C60-3AEA-1069-A2D7-08002B30309D}}` --> Ağ Yerlerim
- `shell:::{871C5380-42A0-1069-A2EA-08002B30309D}` --> Internet Explorer

### Dosya Uzantılarını Göster

Daha fazla bilgi için bu sayfayı kontrol edin: [https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

## Tarayıcı hileleri

Yedek iKat sürümleri:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)\\

JavaScript kullanarak ortak bir diyalog oluşturun ve dosya gezgini erişin: `document.write('<input/type=file>')`\
Kaynak: https://medium.com/@Rend\_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

## iPad

### Hareketler ve düğmeler

- Dört (veya beş) parmakla yukarı kaydır / Ana ekran düğmesine çift tıklayın: Çoklu görev görünümünü görmek ve Uygulamayı değiştirmek için
- Dört veya beş parmakla bir yöne kaydır: Bir sonraki/son uygulamaya geçmek için
- Beş parmakla ekranı sıkıştır / Ana ekran düğmesine dokun / Ekranın altından yukarı doğru hızlı bir hareketle 1 parmakla kaydır: Ana ekrana erişmek için
- Ekranın altından 1-2 inç (yavaş) yukarı kaydır: Dock görünecektir
- Ekranın üst kısmından 1 parmakla aşağı kaydır: Bildirimlerinizi görmek için
- Ekranın sağ üst köşesinden 1 parmakla aşağı kaydır: iPad Pro'nun kontrol merkezini görmek için
- Ekranın sol tarafından 1-2 inç 1 parmakla kaydır: Bugün görünümünü görmek için
- Ekranın ortasından sağa veya sola hızlı bir şekilde 1 parmakla kaydır: Bir sonraki/son uygulamaya geçmek için
- **iPad**'in sağ üst köşesindeki Açık/**Kapat**/Uyku düğmesine basılı tutun + **kapatmak için** kaydırıcıyı tamamen sağa kaydırın: Kapatmak için
- **iPad**'in sağ üst köşesindeki Açık/**Kapat**/Uyku düğmesine ve Ana ekran düğmesine birkaç saniye basın: Sert bir şekilde kapatmak için
- **iPad**'in sağ üst köşesindeki Açık/**Kapat**/Uyku düğmesine ve Ana ekran düğmesine hızlıca basın: Ekranın sol alt kısmında belirecek bir ekran görüntüsü almak için. Her iki düğmeye aynı anda çok kısa bir süre basın, birkaç saniye basılı tutarsanız sert bir kapatma işlemi yapılır.

### Kısayollar

Bir iPad klavyesine veya bir USB klavye adaptörüne sahip olmalısınız. Uygulamadan kaçışa yardımcı olabilecek yalnızca kısayollar burada gösterilecektir.

| Tuş | Adı         |
| --- | ------------ |
| ⌘   | Komut      |
| ⌥   | Seçenek (Alt) |
| ⇧   | Shift        |
| ↩   | Geri       |
| ⇥   | Sekme      |
| ^   | Kontrol      |
| ←   | Sol Ok   |
| →   | Sağ Ok  |
| ↑   | Yukarı Ok     |
| ↓   | Aşağı Ok     |

#### Sistem kısayolları

Bu kısayollar, iPad'in kullanımına bağlı olarak görsel ayarlar ve ses ayarları içindir.

| Kısayol | Eylem                                                                         |
| -------- | ------------------------------------------------------------------------------ |
| F1       | Ekranı Kısma                                                                    |
| F2       | Ekranı Parlaklaştırma                                                            |
| F7       | Bir şarkı geri alma                                                                  |
| F8       | Oynat/durdur                                                                     |
| F9       | Şarkıyı atlama                                                                  |
| F10      | Ses kapatma                                                                       |
| F11      | Ses seviyesini azaltma                                                            |
| F12      | Ses seviyesini artırma                                                            |
| ⌘ Boşluk  | Mevcut dillerin listesini gösterir; birini seçmek için boşluk tuşuna tekrar basın. |

#### iPad navigasyonu

| Kısayol                                           | Eylem                                                  |
| -------------------------------------------------- | ------------------------------------------------------- |
| ⌘H                                                 | Ana ekrana git                                          |
| ⌘⇧H (Komut-Shift-H)                              | Ana ekrana git                                          |
| ⌘ (Boşluk)                                        | Spotlight'ı aç                                          |
| ⌘⇥ (Komut-Sekme)                                   | Son on kullanılan uygulamayı listele                    |
| ⌘\~                                                | Son uygulamaya git                                       |
| ⌘⇧3 (Komut-Shift-3)                              | Ekran görüntüsü (sol altta kaydetmek veya üzerinde işlem yapmak için) |
| ⌘⇧4                                                | Ekran görüntüsü al ve düzenleyicide aç                  |
| ⌘ tuşuna basılı tut                                 | Uygulama için mevcut kısayolların listesini gösterir     |
| ⌘⌥D (Komut-Seçenek/Alt-D)                         | Dock'u açar                                            |
| ^⌥H (Kontrol-Seçenek-H)                             | Ana ekran düğmesi                                       |
| ^⌥H H (Kontrol-Seçenek-H-H)                         | Çoklu görev çubuğunu gösterir                            |
| ^⌥I (Kontrol-Seçenek-i)                             | Öğe seçici                                              |
| Escape                                             | Geri düğmesi                                           |
| → (Sağ ok)                                        | Sonraki öğe                                            |
| ← (Sol ok)                                         | Önceki öğe                                            |
| ↑↓ (Yukarı ok, Aşağı ok)                          | Seçilen öğeye aynı anda dokun                           |
| ⌥ ↓ (Seçenek-Aşağı ok)                            | Aşağı kaydır                                            |
| ⌥↑ (Seçenek-Yukarı ok)                           | Yukarı kaydır                                          |
| ⌥← veya ⌥→ (Seçenek-Sol ok veya Seçenek-Sağ ok) | Sola veya sağa kaydır                                   |
| ^⌥S (Kontrol-Seçenek-S)                             | VoiceOver konuşmasını aç veya kapat                     |
| ⌘⇧⇥ (Komut-Shift-Sekme)                            | Önceki uygulamaya geç                                    |
| ⌘⇥ (Komut-Sekme)                                   | Orijinal uygulamaya geri dön                             |
| ←+→, ardından Seçenek + ← veya Seçenek+→           | Dock'ta gezin                                           |

#### Safari kısayolları

| Kısayol                | Eylem                                           |
| ----------------------- | ------------------------------------------------ |
| ⌘L (Komut-L)          | Konum Aç                                        |
| ⌘T                      | Yeni bir sekme aç                               |
| ⌘W                      | Mevcut sekmeyi kapat                           |
| ⌘R                      | Mevcut sekmeyi yenile                          |
| ⌘.                      | Mevcut sekmenin yüklenmesini durdur            |
| ^⇥                      | Sonraki sekmeye geç                             |
| ^⇧⇥ (Kontrol-Shift-Sekme) | Önceki sekmeye geç                             |
| ⌘L                      | Metin girişi/URL alanını seçip düzenlemek için  |
| ⌘⇧T (Komut-Shift-T)   | En son kapatılan sekmeyi aç (birkaç kez kullanılabilir) |
| ⌘\[                     | Tarayıcı geçmişinizde bir sayfaya geri dön      |
| ⌘]                      | Tarayıcı geçmişinizde bir sayfaya ileri git     |
| ⌘⇧R                     | Okuyucu Modunu etkinleştir                      |

#### Mail kısayolları

| Kısayol                   | Eylem                       |
| -------------------------- | ---------------------------- |
| ⌘L                         | Konum Aç                    |
| ⌘T                         | Yeni bir sekme aç           |
| ⌘W                         | Mevcut sekmeyi kapat        |
| ⌘R                         | Mevcut sekmeyi yenile       |
| ⌘.                         | Mevcut sekmenin yüklenmesini durdur |
| ⌘⌥F (Komut-Seçenek/Alt-F) | Posta kutunuzda arama yap   |

## Referanslar

- [https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
- [https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
- [https://thesweetsetup.com/best-ipad-keyboard-shortcuts/](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
- [http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)

{{#include ../banners/hacktricks-training.md}}
