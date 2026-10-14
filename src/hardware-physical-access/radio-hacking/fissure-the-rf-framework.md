# FISSURE - The RF Framework

{{#include ../../banners/hacktricks-training.md}}

**Frequency Independent SDR-based Signal Understanding and Reverse Engineering**

FISSURE, her seviyedeki kullanıcı için tasarlanmış; sinyal tespiti ve sınıflandırma, protokol keşfi, saldırı yürütme, IQ manipülasyonu, zafiyet analizi, otomasyon ve AI/ML özellikleri sunan açık kaynaklı bir RF ve reverse engineering framework’üdür. Framework; yazılım modüllerinin, radyoların, protokollerin, sinyal verilerinin, script’lerin, flow graph’ların, referans materyallerinin ve üçüncü taraf araçların hızla entegre edilmesini teşvik etmek için geliştirilmiştir. FISSURE, yazılımları tek bir yerde tutan ve ekiplerin belirli Linux dağıtımları için aynı denenmiş temel yapılandırmayı paylaşırken hızlıca işe koyulmasını sağlayan bir workflow kolaylaştırıcısıdır.<sup>[[1]](#references)[[2]](#references)</sup>

FISSURE ile sunulan framework ve araçlar; RF enerjisini tespit etmek, sinyalleri nitelendirmek, örnekler toplamak ve analiz etmek, iletim veya injection teknikleri geliştirmek ve özel payload’lar ya da mesajlar oluşturmak için tasarlanmıştır. FISSURE ayrıca tanımlama, paket oluşturma ve fuzzing için protokol ve sinyal bilgileri; trafik simülasyonu ve testleri için arşivler ve playlist’ler sunar.<sup>[[1]](#references)[[2]](#references)</sup>

Python kod tabanı ve grafik arayüz, yeni başlayanların RF ve reverse-engineering araçlarını öğrenmesine yardımcı olur. Eğitimciler yerleşik derslerden yararlanabilir; geliştiriciler ve araştırmacılar ise kendi modüllerini ve workflow’larını entegre edebilir. Güncel sürümler ayrıca dağıtık sensör düğümlerini, TAK entegrasyonunu, geolocation workflow’larını ve role-specific Apptainer dağıtımlarını destekler.<sup>[[1]](#references)[[3]](#references)</sup>

**Ek Bilgiler**

* [AIS Page](https://www.ainfosec.com/technologies/fissure/)
* [GRCon22 Slides](https://events.gnuradio.org/event/18/contributions/246/attachments/84/164/FISSURE\_Poore\_GRCon22.pdf)
* [GRCon22 Paper](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE\_Paper\_Poore\_GRCon22.pdf)
* [GRCon22 Video](https://www.youtube.com/watch?v=1f2umEKhJvE)
* [Hack Chat Transcript](https://hackaday.io/event/187076-rf-hacking-hack-chat/log/212136-hack-chat-transcript-part-1)

## Başlarken

**Desteklenen**

Güncel FISSURE, PyQt5 ve GNU Radio 3.8 veya 3.10 ile aktif geliştirme için **`Python3`** branch’ini kullanır. Kullanımdan kaldırılmış olan **`Python2_maint-3.7`** branch’i, GNU Radio 3.7 gerektiren eski işletim sistemleri ve üçüncü taraf araçlar için kullanılabilir durumda kalır. Önceki `Python3_maint-3.8` ve `Python3_maint-3.10` branch adları artık tarihîdir; GNU Radio bakım sürümü seçimi artık `Python3` branch’i üzerinden yapılır.<sup>[[1]](#references)[[3]](#references)</sup>

| İşletim Sistemi | FISSURE Branch’i | Varsayılan GNU Radio branch’i |
| :--: | :--: | :--: |
| DragonOS Noble (24.04) | Python3 | maint-3.10 |
| Kali | Python3 | maint-3.10 |
| Raspberry Pi OS | Python3 | maint-3.10 |
| Ubuntu 18.04 | Python2\_maint-3.7 | maint-3.7 |
| Ubuntu 20.04 | Python3 | maint-3.8 |
| Ubuntu 22.04 | Python3 | maint-3.10 |
| Ubuntu 24.04 / Ubuntu ARM | Python3 | maint-3.10 |
| Windows 11 WSL2 | desteklenen bir Linux sürümünü kullanın | eşleşen sürümü kullanın |

**Geliştirme Aşamasında (beta)**

Bu işletim sistemleri hâlâ beta durumundadır. Geliştirme aşamasındadırlar ve bazı özelliklerin eksik olduğu bilinmektedir. Yükleyicideki öğeler mevcut programlarla çakışabilir veya beta durumu kaldırılana kadar yüklenemeyebilir.

| İşletim Sistemi | FISSURE Branch’i | Varsayılan GNU Radio branch’i |
| :--: | :--: | :--: |
| BackBox Linux | Python3 | maint-3.10 |
| KDE neon | Python3 | maint-3.10 |
| Parrot Security 6.1 | Python3 | maint-3.10 |

Bazı üçüncü taraf araçlar her işletim sisteminde çalışmaz. Yüklemeden önce güncel [Known Conflicts and Third-Party Software](https://fissure.readthedocs.io/en/latest/pages/installation.html#known-conflicts) belgelerini inceleyin.<sup>[[3]](#references)</sup>

**Yükleme**

```
git clone https://github.com/ainfosec/FISSURE.git
cd FISSURE
git checkout Python3  # optional; use Python2_maint-3.7 only for legacy requirements
git submodule update --init
./install
```

Alt modül adımı, FISSURE tarafından kullanılan GNU Radio out-of-tree modüllerini indirir ve bu modülleri yüklemek için gereklidir. Yükleyici, kurulum arayüzlerini başlatmak için gereken eksik PyQt bağımlılıklarını da yükler.<sup>[[3]](#references)</sup>

Ardından işletim sisteminize en uygun seçeneği belirleyin (işletim sisteminiz seçeneklerden biriyle eşleşiyorsa otomatik olarak algılanmalıdır).

|                                          Python2\_maint-3.7                                          |                                          Python3\_maint-3.8                                          |                                          Python3\_maint-3.10                                         |
| :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: |
| ![install1b](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1b.png) | ![install1a](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1a.png) | ![install1c](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1c.png) |

Mevcut çakışmaları önlemek için FISSURE'ı temiz bir işletim sistemine kurmanız önerilir. FISSURE içindeki çeşitli araçları kullanırken hata oluşmasını önlemek için önerilen tüm onay kutularını (Default düğmesi) seçin. Kurulum sırasında, çoğunlukla yükseltilmiş izinler ve kullanıcı adları isteyen birden fazla istem görüntülenir. Bir öğenin sonunda "Verify" bölümü varsa yükleyici, bu bölümde belirtilen komutu çalıştırır ve komutun hata üretip üretmediğine bağlı olarak onay kutusu öğesini yeşil veya kırmızı renkle vurgular. "Verify" bölümü olmayan işaretli öğeler, kurulum tamamlandıktan sonra siyah kalır.

![install2](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install2.png)

**Kullanım**

Bir terminal açın ve şunu girin:

```
fissure
```

FISSURE Help menüsüne başvurarak kullanım hakkında daha fazla bilgi edinebilirsiniz.

## Ayrıntılar

**Bileşenler**

* Dashboard
* Central Hub (HIPRFISR)
* Target Signal Identification (TSI)
* Protocol Discovery (PD)
* Flow Graph & Script Executor (FGE)

![bileşenler](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/components.png)

**Özellikler**

| ![Sinyal Dedektörü simgesi](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/detector.png)_**Sinyal Dedektörü**_ | ![IQ Manipülasyonu simgesi](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/iq.png)_**IQ Manipülasyonu**_      | ![Sinyal Arama simgesi](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/library.png)_**Sinyal Arama**_          | ![Örüntü Tanıma simgesi](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/pd.png)_**Örüntü Tanıma**_ |
| --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| ![Saldırılar simgesi](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/attack.png)_**Saldırılar**_           | ![Fuzzing simgesi](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/fuzzing.png)_**Fuzzing**_         | ![Sinyal Çalma Listeleri simgesi](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/archive.png)_**Sinyal Çalma Listeleri**_       | ![Görsel Galerisi simgesi](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/gallery.png)_**Görsel Galerisi**_  |
| ![Paket Oluşturma simgesi](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/packet.png)_**Paket Oluşturma**_   | ![Scapy Entegrasyonu simgesi](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/scapy.png)_**Scapy Entegrasyonu**_ | ![CRC Hesaplayıcı simgesi](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/crc\_calculator.png)_**CRC Hesaplayıcı**_ | ![Günlük Kaydı simgesi](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/log.png)_**Günlük Kaydı**_            |

**Donanım**

Aşağıdaki donanımlar FISSURE ile farklı düzeylerde entegre edilmiştir:<sup>[[1]](#references)[[3]](#references)</sup>

* USRP: X3xx, B2xx, B20xmini, USRP2, N2xx, X410
* HackRF
* RTL2832U
* 802.11 Adaptörleri
* LimeSDR
* bladeRF, bladeRF 2.0 micro
* Open Sniffer
* PlutoSDR
* SDRplay: RSPduo, RSPdx, RSPdx R2

## Dersler

FISSURE, farklı teknolojileri ve teknikleri öğrenmenize yardımcı olacak çeşitli kılavuzlarla birlikte gelir. Birçoğunda, FISSURE ile entegre çeşitli araçların kullanımına yönelik adımlar bulunur.

* [Ders1: OpenBTS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson1\_OpenBTS.md)
* [Ders2: Lua Ayrıştırıcıları](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson2\_LuaDissectors.md)
* [Ders3: Sound eXchange](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson3\_Sound\_eXchange.md)
* [Ders4: ESP Kartları](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson4\_ESP\_Boards.md)
* [Ders5: Radiosonde Takibi](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson5\_Radiosonde\_Tracking.md)
* [Ders6: RFID](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson6\_RFID.md)
* [Ders7: Veri Türleri](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson7\_Data\_Types.md)
* [Ders8: Özel GNU Radio Blokları](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson8\_Custom\_GNU\_Radio\_Blocks.md)
* [Ders9: TPMS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson9\_TPMS.md)
* [Ders10: Amatör Telsiz Sınavları](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson10\_Ham\_Radio\_Exams.md)
* [Ders11: Wi-Fi Araçları](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson11\_WiFi\_Tools.md)
* [Ders12: Önyüklenebilir USB Oluşturma](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson12_Creating_Bootable_USBs.md)
* [Ders13: Z-Wave](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson13_Z-Wave.md)
* [Ders14: Tavan Vantilatörleri](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson14_Ceiling_Fans.md)

## Yol Haritası

* [ ] Daha fazla donanım türü, RF protokolü, sinyal parametresi ve analiz aracı eklemek
* [ ] Daha fazla işletim sistemini desteklemek
* [ ] FISSURE etrafında ders materyalleri geliştirmek (RF Saldırıları, Wi-Fi, GNU Radio, PyQt vb.)
* [ ] Seçilebilir AI/ML teknikleriyle bir sinyal koşullandırıcı, özellik çıkarıcı ve sinyal sınıflandırıcı oluşturmak
* [ ] Bilinmeyen sinyallerden bit akışı üretmek için özyinelemeli demodülasyon mekanizmaları uygulamak
* [ ] Ana FISSURE bileşenlerini genel bir sensör düğümü dağıtım şemasına geçirmek

## Katkıda Bulunma

FISSURE'ı geliştirmeye yönelik önerileriniz memnuniyetle karşılanır. Aşağıdaki konularda fikirleriniz varsa [Tartışmalar](https://github.com/ainfosec/FISSURE/discussions) sayfasına veya Discord Sunucusuna yorum bırakın:

* Yeni özellik önerileri ve tasarım değişiklikleri
* Kurulum adımlarıyla birlikte yazılım araçları
* Yeni dersler veya mevcut derslere eklenecek materyaller
* İlgi çekici RF protokolleri
* Entegrasyon için daha fazla donanım ve SDR türü
* Python'da IQ analiz betikleri
* Kurulum düzeltmeleri ve iyileştirmeleri

FISSURE'ın geliştirilmesine yönelik katkılar, gelişimini hızlandırmak açısından çok önemlidir. Yapacağınız her türlü katkı için minnettarız. Kod geliştirerek katkıda bulunmak istiyorsanız depoyu fork edip bir pull request oluşturun:

1. Projeyi fork edin
2. Özellik dalınızı oluşturun (`git checkout -b feature/AmazingFeature`)
3. Değişikliklerinizi commit edin (`git commit -m 'Add some AmazingFeature'`)
4. Dalınıza push edin (`git push origin feature/AmazingFeature`)
5. Bir pull request açın

Hatalara dikkat çekmek için [Issues](https://github.com/ainfosec/FISSURE/issues) oluşturmanız da memnuniyetle karşılanır.

## İş Birliği

Yazılımınızı entegre etmek için zaman ayırarak, AIS'in yetenekli çalışanlarından teknik zorluklarınıza yönelik çözümler geliştirmelerini isteyerek veya FISSURE'ı başka platformlara/uygulamalara entegre ederek FISSURE iş birliği fırsatları önermek ve resmîleştirmek için Assured Information Security, Inc. (AIS) İş Geliştirme ekibiyle iletişime geçin.

## Lisans

GPL-3.0

Lisans ayrıntıları için LICENSE dosyasına bakın.

## İletişim

Discord Sunucusuna katılın: [https://discord.gg/JZDs5sgxcG](https://discord.gg/JZDs5sgxcG)

Twitter'da takip edin: [@FissureRF](https://twitter.com/fissurerf), [@AinfoSec](https://twitter.com/ainfosec)

Chris Poore - Assured Information Security, Inc. - poorec@ainfosec.com

İş Geliştirme - Assured Information Security, Inc. - bd@ainfosec.com

## Katkıda Bulunanlar

Aşağıdaki geliştiricilere teşekkür eder, katkılarını takdir ederiz:

[Katkıda Bulunanlar](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/CREDITS.md)

## Teşekkürler

Bu projeye katkılarından dolayı Dr. Samuel Mantravadi ve Joseph Reith'e özel teşekkürlerimizi sunarız.

## References

- [1] [FISSURE - RF Framework'ü (GitHub)](https://github.com/ainfosec/FISSURE)
- [2] [FISSURE Makalesi (GRCon22)](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE_Paper_Poore_GRCon22.pdf)
- [3] [FISSURE belgeleri - Kurulum](https://fissure.readthedocs.io/en/latest/pages/installation.html)
{{#include ../../banners/hacktricks-training.md}}
