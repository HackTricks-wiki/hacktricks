# FISSURE - RF Çerçevesi

{{#include /banners/hacktricks-training.md}}

**Frekansa Bağlı Olmayan SDR Tabanlı Sinyal Anlama ve Tersine Mühendislik**

FISSURE, sinyal tespiti ve sınıflandırması, protokol keşfi, saldırı yürütme, IQ manipülasyonu, zafiyet analizi, otomasyon ve AI/ML için kancalarla tasarlanmış, tüm beceri seviyeleri için açık kaynaklı bir RF ve tersine mühendislik çerçevesidir. Çerçeve, yazılım modüllerinin, radyoların, protokollerin, sinyal verilerinin, betiklerin, akış grafiklerinin, referans materyallerin ve üçüncü taraf araçların hızlı entegrasyonunu teşvik etmek için inşa edilmiştir. FISSURE, yazılımı tek bir yerde tutan ve ekiplerin belirli Linux dağıtımları için aynı kanıtlanmış temel yapılandırmayı paylaşırken hızla uyum sağlamasını sağlayan bir iş akışı sağlayıcısıdır.

FISSURE ile birlikte gelen çerçeve ve araçlar, RF enerjisinin varlığını tespit etmek, bir sinyalin özelliklerini anlamak, örnekler toplamak ve analiz etmek, iletim ve/veya enjeksiyon teknikleri geliştirmek ve özel yükler veya mesajlar oluşturmak için tasarlanmıştır. FISSURE, tanımlama, paket oluşturma ve fuzzing konusunda yardımcı olmak için büyüyen bir protokol ve sinyal bilgisi kütüphanesi içerir. Sinyal dosyalarını indirmek ve trafik simüle etmek ve sistemleri test etmek için çalma listeleri oluşturmak için çevrimiçi arşiv yetenekleri mevcuttur.

Kullanıcı dostu Python kod tabanı ve kullanıcı arayüzü, acemilerin RF ve tersine mühendislik ile ilgili popüler araçlar ve teknikler hakkında hızla bilgi edinmelerini sağlar. Siber güvenlik ve mühendislik alanındaki eğitimciler, yerleşik materyali kullanabilir veya kendi gerçek dünya uygulamalarını göstermek için çerçeveyi kullanabilir. Geliştiriciler ve araştırmacılar, FISSURE'ı günlük görevleri için veya keskin çözümlerini daha geniş bir kitleye sunmak için kullanabilir. FISSURE'ın toplulukta farkındalığı ve kullanımı arttıkça, yetenekleri ve kapsadığı teknolojinin kapsamı da artacaktır.

**Ek Bilgiler**

* [AIS Sayfası](https://www.ainfosec.com/technologies/fissure/)
* [GRCon22 Slaytları](https://events.gnuradio.org/event/18/contributions/246/attachments/84/164/FISSURE\_Poore\_GRCon22.pdf)
* [GRCon22 Makalesi](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE\_Paper\_Poore\_GRCon22.pdf)
* [GRCon22 Videosu](https://www.youtube.com/watch?v=1f2umEKhJvE)
* [Hack Chat Transkripti](https://hackaday.io/event/187076-rf-hacking-hack-chat/log/212136-hack-chat-transcript-part-1)

## Başlarken

**Desteklenen**

FISSURE içinde dosya navigasyonunu kolaylaştırmak ve kod tekrarını azaltmak için üç dal bulunmaktadır. Python2\_maint-3.7 dalı, Python2, PyQt4 ve GNU Radio 3.7 etrafında inşa edilmiş bir kod tabanı içerir; Python3\_maint-3.8 dalı, Python3, PyQt5 ve GNU Radio 3.8 etrafında inşa edilmiştir; ve Python3\_maint-3.10 dalı, Python3, PyQt5 ve GNU Radio 3.10 etrafında inşa edilmiştir.

|   İşletim Sistemi   |   FISSURE Dalı   |
| :------------------: | :--------------: |
|  Ubuntu 18.04 (x64)  | Python2\_maint-3.7 |
| Ubuntu 18.04.5 (x64) | Python2\_maint-3.7 |
| Ubuntu 18.04.6 (x64) | Python2\_maint-3.7 |
| Ubuntu 20.04.1 (x64) | Python3\_maint-3.8 |
| Ubuntu 20.04.4 (x64) | Python3\_maint-3.8 |
|  KDE neon 5.25 (x64) | Python3\_maint-3.8 |

**Devam Eden (beta)**

Bu işletim sistemleri hala beta durumundadır. Geliştirme aşamasındadır ve birkaç özelliğin eksik olduğu bilinmektedir. Yükleyicideki öğeler mevcut programlarla çakışabilir veya durum kaldırılana kadar yüklenemeyebilir.

|     İşletim Sistemi     |    FISSURE Dalı   |
| :----------------------: | :---------------: |
| DragonOS Focal (x86\_64) |  Python3\_maint-3.8 |
|    Ubuntu 22.04 (x64)    | Python3\_maint-3.10 |

Not: Belirli yazılım araçları her işletim sistemi için çalışmamaktadır. [Yazılım ve Çakışmalar](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Help/Markdown/SoftwareAndConflicts.md) bölümüne bakın.

**Kurulum**
```
git clone https://github.com/ainfosec/FISSURE.git
cd FISSURE
git checkout <Python2_maint-3.7> or <Python3_maint-3.8> or <Python3_maint-3.10>
git submodule update --init
./install
```
Bu, yükleme GUI'lerini başlatmak için gereken PyQt yazılım bağımlılıklarını yükleyecektir, eğer bulunamazsa.

Sonra, işletim sisteminize en uygun seçeneği seçin (eğer işletim sisteminiz bir seçenekle eşleşiyorsa otomatik olarak algılanmalıdır).

|                                          Python2\_maint-3.7                                          |                                          Python3\_maint-3.8                                          |                                          Python3\_maint-3.10                                         |
| :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: |
| ![install1b](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1b.png) | ![install1a](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1a.png) | ![install1c](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1c.png) |

FISSURE'ı mevcut çatışmaları önlemek için temiz bir işletim sistemine kurmanız önerilir. FISSURE içindeki çeşitli araçları kullanırken hataları önlemek için tüm önerilen onay kutularını (Varsayılan buton) seçin. Yükleme sırasında, çoğunlukla yükseltilmiş izinler ve kullanıcı adları isteyen birden fazla istem olacaktır. Bir öğe sonunda "Doğrula" bölümü içeriyorsa, yükleyici takip eden komutu çalıştıracak ve komut tarafından herhangi bir hata üretilip üretilmediğine bağlı olarak onay kutusu öğesini yeşil veya kırmızı olarak vurgulayacaktır. "Doğrula" bölümü olmayan onaylı öğeler yüklemeden sonra siyah kalacaktır.

![install2](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install2.png)

**Kullanım**

Bir terminal açın ve girin:
```
fissure
```
Referans için FISSURE Yardım menüsüne bakın.

## Detaylar

**Bileşenler**

* Gösterge Paneli
* Merkezi Hub (HIPRFISR)
* Hedef Sinyal Tanımlama (TSI)
* Protokol Keşfi (PD)
* Akış Grafiği & Script Yürütücüsü (FGE)

![components](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/components.png)

**Yetenekler**

| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/detector.png)_**Sinyal Dedektörü**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/iq.png)_**IQ Manipülasyonu**_      | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/library.png)_**Sinyal Arama**_          | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/pd.png)_**Desen Tanıma**_ |
| --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/attack.png)_**Saldırılar**_           | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/fuzzing.png)_**Fuzzing**_         | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/archive.png)_**Sinyal Çalma Listeleri**_       | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/gallery.png)_**Görüntü Galerisi**_  |
| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/packet.png)_**Paket Oluşturma**_   | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/scapy.png)_**Scapy Entegrasyonu**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/crc\_calculator.png)_**CRC Hesaplayıcı**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/log.png)_**Günlükleme**_            |

**Donanım**

Aşağıda, farklı entegrasyon seviyelerine sahip "desteklenen" donanımların bir listesi bulunmaktadır:

* USRP: X3xx, B2xx, B20xmini, USRP2, N2xx
* HackRF
* RTL2832U
* 802.11 Adaptörleri
* LimeSDR
* bladeRF, bladeRF 2.0 mikro
* Open Sniffer
* PlutoSDR

## Dersler

FISSURE, farklı teknolojiler ve tekniklerle tanışmak için birkaç yararlı kılavuz ile birlikte gelir. Birçoğu, FISSURE'a entegre edilmiş çeşitli araçların kullanımına yönelik adımlar içerir.

* [Ders1: OpenBTS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson1\_OpenBTS.md)
* [Ders2: Lua Çözümleyicileri](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson2\_LuaDissectors.md)
* [Ders3: Ses eXchange](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson3\_Sound\_eXchange.md)
* [Ders4: ESP Kartları](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson4\_ESP\_Boards.md)
* [Ders5: Radiosonde Takibi](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson5\_Radiosonde\_Tracking.md)
* [Ders6: RFID](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson6\_RFID.md)
* [Ders7: Veri Türleri](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson7\_Data\_Types.md)
* [Ders8: Özel GNU Radio Blokları](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson8\_Custom\_GNU\_Radio\_Blocks.md)
* [Ders9: TPMS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson9\_TPMS.md)
* [Ders10: Amatör Radyo Sınavları](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson10\_Ham\_Radio\_Exams.md)
* [Ders11: Wi-Fi Araçları](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson11\_WiFi\_Tools.md)

## Yol Haritası

* [ ] Daha fazla donanım türü, RF protokolleri, sinyal parametreleri, analiz araçları ekleyin
* [ ] Daha fazla işletim sistemi desteği
* [ ] FISSURE etrafında ders materyali geliştirin (RF Saldırıları, Wi-Fi, GNU Radio, PyQt, vb.)
* [ ] Seçilebilir AI/ML teknikleri ile bir sinyal düzenleyici, özellik çıkarıcı ve sinyal sınıflandırıcı oluşturun
* [ ] Bilinmeyen sinyallerden bir bit akışı üretmek için özyinelemeli demodülasyon mekanizmaları uygulayın
* [ ] Ana FISSURE bileşenlerini genel bir sensör düğümü dağıtım şemasına geçirin

## Katkıda Bulunma

FISSURE'ı geliştirmek için öneriler şiddetle teşvik edilmektedir. Aşağıdaki konularla ilgili düşünceleriniz varsa, [Tartışmalar](https://github.com/ainfosec/FISSURE/discussions) sayfasında veya Discord Sunucusunda bir yorum bırakın:

* Yeni özellik önerileri ve tasarım değişiklikleri
* Kurulum adımları ile yazılım araçları
* Yeni dersler veya mevcut dersler için ek materyal
* İlgi alanındaki RF protokolleri
* Entegrasyon için daha fazla donanım ve SDR türleri
* Python'da IQ analiz scriptleri
* Kurulum düzeltmeleri ve iyileştirmeleri

FISSURE'ı geliştirmek için katkılar, gelişimini hızlandırmak açısından kritik öneme sahiptir. Yaptığınız her katkı büyük takdirle karşılanır. Kod geliştirme yoluyla katkıda bulunmak isterseniz, lütfen repo'yu fork edin ve bir pull request oluşturun:

1. Projeyi fork edin
2. Özellik dalınızı oluşturun (`git checkout -b feature/AmazingFeature`)
3. Değişikliklerinizi kaydedin (`git commit -m 'Add some AmazingFeature'`)
4. Dala itme yapın (`git push origin feature/AmazingFeature`)
5. Bir pull request açın

Hatalara dikkat çekmek için [Sorunlar](https://github.com/ainfosec/FISSURE/issues) oluşturmak da memnuniyetle karşılanır.

## İşbirliği

FISSURE işbirliği fırsatlarını önermek ve resmileştirmek için Assured Information Security, Inc. (AIS) İş Geliştirme ile iletişime geçin; bu, yazılımınızı entegre etmek için zaman ayırmak, AIS'teki yetenekli kişilerin teknik zorluklarınız için çözümler geliştirmesi veya FISSURE'ı diğer platformlara/uygulamalara entegre etmek olabilir.

## Lisans

GPL-3.0

Lisans detayları için LICENSE dosyasına bakın.

## İletişim

Discord Sunucusuna katılın: [https://discord.gg/JZDs5sgxcG](https://discord.gg/JZDs5sgxcG)

Twitter'da takip edin: [@FissureRF](https://twitter.com/fissurerf), [@AinfoSec](https://twitter.com/ainfosec)

Chris Poore - Assured Information Security, Inc. - poorec@ainfosec.com

İş Geliştirme - Assured Information Security, Inc. - bd@ainfosec.com

## Krediler

Bu geliştiricilere teşekkür ederiz:

[Credits](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/CREDITS.md)

## Teşekkürler

Bu projeye katkılarından dolayı Dr. Samuel Mantravadi ve Joseph Reith'e özel teşekkürler.

{{#include /banners/hacktricks-training.md}}
