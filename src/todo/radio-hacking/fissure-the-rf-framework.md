# FISSURE - RF Framework'ü

{{#include ../../banners/hacktricks-training.md}}

**Frequency Independent SDR-based Signal Understanding and Reverse Engineering**

FISSURE, tüm beceri seviyeleri için tasarlanmış; signal detection ve classification, protocol discovery, attack execution, IQ manipulation, vulnerability analysis, automation ve AI/ML özellikleri için kancalar içeren, open-source bir RF ve reverse engineering framework'üdür. Framework; software modules, radios, protocols, signal data, scripts, flow graphs, reference material ve third-party tools entegrasyonunu hızlı bir şekilde desteklemek amacıyla oluşturulmuştur. FISSURE, software'ı tek bir konumda tutan ve ekiplerin belirli Linux dağıtımları için kanıtlanmış aynı temel yapılandırmayı paylaşırken hızla çalışmaya başlamasını sağlayan bir workflow enabler'dır.<sup>[[1]](#references)[[2]](#references)</sup>

FISSURE ile birlikte sunulan framework ve tools; RF energy varlığını tespit etmek, bir signal'ın özelliklerini anlamak, samples toplamak ve analiz etmek, transmit ve/veya injection techniques geliştirmek ve custom payloads veya messages oluşturmak üzere tasarlanmıştır. FISSURE, identification, packet crafting ve fuzzing işlemlerine yardımcı olmak için sürekli büyüyen bir protocol ve signal information library içerir. Signal files indirmek, traffic simülasyonu yapmak ve system'leri test etmek için playlist'ler oluşturmak üzere online archive özellikleri de mevcuttur.

Kullanıcı dostu Python codebase'i ve user interface, beginners'ın RF ve reverse engineering ile ilgili popüler tools ve techniques'i hızlıca öğrenmesini sağlar. Cybersecurity ve engineering alanlarındaki educators, yerleşik material'dan yararlanabilir veya framework'ü kendi gerçek dünya uygulamalarını göstermek için kullanabilir. Developers ve researchers, FISSURE'ü günlük görevleri için kullanabilir veya cutting-edge çözümlerini daha geniş bir kitleye sunabilir. FISSURE'e yönelik farkındalık ve kullanım community içinde arttıkça, yeteneklerinin kapsamı ve içerdiği technology'nin genişliği de artacaktır.

**Ek Bilgiler**

* [AIS Page](https://www.ainfosec.com/technologies/fissure/)
* [GRCon22 Slides](https://events.gnuradio.org/event/18/contributions/246/attachments/84/164/FISSURE\_Poore\_GRCon22.pdf)
* [GRCon22 Paper](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE\_Paper\_Poore\_GRCon22.pdf)
* [GRCon22 Video](https://www.youtube.com/watch?v=1f2umEKhJvE)
* [Hack Chat Transcript](https://hackaday.io/event/187076-rf-hacking-hack-chat/log/212136-hack-chat-transcript-part-1)

## Başlarken

**Desteklenen**

FISSURE içinde file navigation'ı kolaylaştırmak ve code redundancy'yi azaltmak için üç branch bulunur. Python2\_maint-3.7 branch'i Python2, PyQt4 ve GNU Radio 3.7 üzerine kurulmuş bir codebase içerir; Python3\_maint-3.8 branch'i Python3, PyQt5 ve GNU Radio 3.8 üzerine kuruludur; Python3\_maint-3.10 branch'i ise Python3, PyQt5 ve GNU Radio 3.10 üzerine kuruludur.

|   İşletim Sistemi   |   FISSURE Branch'i   |
| :------------------: | :----------------: |
|  Ubuntu 18.04 (x64)  | Python2\_maint-3.7 |
| Ubuntu 18.04.5 (x64) | Python2\_maint-3.7 |
| Ubuntu 18.04.6 (x64) | Python2\_maint-3.7 |
| Ubuntu 20.04.1 (x64) | Python3\_maint-3.8 |
| Ubuntu 20.04.4 (x64) | Python3\_maint-3.8 |
|  KDE neon 5.25 (x64) | Python3\_maint-3.8 |

**Devam Ediyor (beta)**

Bu işletim sistemleri hâlâ beta durumundadır. Geliştirme aşamasındadırlar ve bazı özelliklerin eksik olduğu bilinmektedir. Installer'daki öğeler mevcut programlarla conflict edebilir veya durum kaldırılana kadar install edilemeyebilir.

|     İşletim Sistemi     |    FISSURE Branch'i   |
| :----------------------: | :-----------------: |
| DragonOS Focal (x86\_64) |  Python3\_maint-3.8 |
|    Ubuntu 22.04 (x64)    | Python3\_maint-3.10 |

Not: Bazı software tools her OS'te çalışmaz. [Software And Conflicts](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Help/Markdown/SoftwareAndConflicts.md) bölümüne bakın.

**Installation**
```
git clone https://github.com/ainfosec/FISSURE.git
cd FISSURE
git checkout <Python2_maint-3.7> or <Python3_maint-3.8> or <Python3_maint-3.10>
git submodule update --init
./install
```
Bu işlem, bulunamadıkları takdirde kurulum GUI'lerini başlatmak için gereken PyQt software dependencies'i kurar.

Ardından işletim sisteminize en uygun seçeneği belirleyin (işletim sisteminiz seçeneklerden biriyle eşleşiyorsa otomatik olarak algılanmalıdır).

|                                          Python2\_maint-3.7                                          |                                          Python3\_maint-3.8                                          |                                          Python3\_maint-3.10                                         |
| :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: |
| ![install1b](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1b.png) | ![install1a](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1a.png) | ![install1c](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1c.png) |

Mevcut çakışmaları önlemek için FISSURE'ı temiz bir işletim sistemine kurmanız önerilir. FISSURE içindeki çeşitli araçları kullanırken oluşabilecek hataları önlemek için önerilen tüm checkbox'ları (Default düğmesi) seçin. Kurulum boyunca çoğunlukla yükseltilmiş izinler ve kullanıcı adları isteyen birden fazla istem görüntülenir. Bir öğenin sonunda "Verify" bölümü varsa installer, ardından gelen command'i çalıştırır ve command tarafından herhangi bir hata üretilip üretilmediğine bağlı olarak checkbox öğesini yeşil veya kırmızı renkle vurgular. "Verify" bölümü olmayan işaretli öğeler, kurulumun ardından siyah renkte kalır.

![install2](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install2.png)

**Kullanım**

Bir terminal açın ve şunu girin:
```
fissure
```
Daha fazla kullanım ayrıntısı için FISSURE Help menüsüne bakın.

## Ayrıntılar

**Bileşenler**

* Dashboard
* Central Hub (HIPRFISR)
* Target Signal Identification (TSI)
* Protocol Discovery (PD)
* Flow Graph & Script Executor (FGE)

![bileşenler](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/components.png)

**Yetenekler**

| ![Signal Detector simgesi](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/detector.png)_**Signal Detector**_ | ![IQ Manipulation simgesi](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/iq.png)_**IQ Manipulation**_      | ![Signal Lookup simgesi](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/library.png)_**Signal Lookup**_          | ![Pattern Recognition simgesi](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/pd.png)_**Pattern Recognition**_ |
| --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| ![Attacks simgesi](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/attack.png)_**Attacks**_           | ![Fuzzing simgesi](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/fuzzing.png)_**Fuzzing**_         | ![Signal Playlists simgesi](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/archive.png)_**Signal Playlists**_       | ![Image Gallery simgesi](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/gallery.png)_**Image Gallery**_  |
| ![Packet Crafting simgesi](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/packet.png)_**Packet Crafting**_   | ![Scapy Integration simgesi](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/scapy.png)_**Scapy Integration**_ | ![CRC Calculator simgesi](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/crc\_calculator.png)_**CRC Calculator**_ | ![Logging simgesi](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/log.png)_**Logging**_            |

**Donanım**

Aşağıda, farklı düzeylerde entegrasyona sahip "desteklenen" donanımların listesi yer almaktadır:

* USRP: X3xx, B2xx, B20xmini, USRP2, N2xx
* HackRF
* RTL2832U
* 802.11 Adaptörleri
* LimeSDR
* bladeRF, bladeRF 2.0 micro
* Open Sniffer
* PlutoSDR

## Dersler

FISSURE, farklı teknolojilere ve tekniklere aşina olmanızı sağlayacak çeşitli yararlı kılavuzlarla birlikte gelir. Bunların çoğu, FISSURE ile entegre edilmiş çeşitli araçların kullanımına yönelik adımlar içerir.

* [Ders1: OpenBTS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson1\_OpenBTS.md)
* [Ders2: Lua Dissectors](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson2\_LuaDissectors.md)
* [Ders3: Sound eXchange](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson3\_Sound\_eXchange.md)
* [Ders4: ESP Boards](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson4\_ESP\_Boards.md)
* [Ders5: Radiosonde Tracking](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson5\_Radiosonde\_Tracking.md)
* [Ders6: RFID](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson6\_RFID.md)
* [Ders7: Data Types](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson7\_Data\_Types.md)
* [Ders8: Custom GNU Radio Blocks](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson8\_Custom\_GNU\_Radio\_Blocks.md)
* [Ders9: TPMS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson9\_TPMS.md)
* [Ders10: Ham Radio Exams](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson10\_Ham\_Radio\_Exams.md)
* [Ders11: Wi-Fi Tools](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson11\_WiFi\_Tools.md)

## Yol Haritası

* [ ] Daha fazla donanım türü, RF protokolü, sinyal parametresi ve analiz aracı eklemek
* [ ] Daha fazla işletim sistemini desteklemek
* [ ] FISSURE çevresinde ders materyalleri geliştirmek (RF Attacks, Wi-Fi, GNU Radio, PyQt vb.)
* [ ] Seçilebilir AI/ML teknikleriyle bir sinyal conditioner, feature extractor ve signal classifier oluşturmak
* [ ] Bilinmeyen sinyallerden bitstream üretmek için recursive demodulation mekanizmaları uygulamak
* [ ] Ana FISSURE bileşenlerini generic sensor node deployment scheme'e geçirmek

## Katkıda Bulunma

FISSURE'ı geliştirmeye yönelik önerileriniz önemle teşvik edilmektedir. Aşağıdaki konulardan herhangi biriyle ilgili düşünceleriniz varsa [Discussions](https://github.com/ainfosec/FISSURE/discussions) sayfasında veya Discord Server'da yorum bırakın:

* Yeni özellik önerileri ve tasarım değişiklikleri
* Kurulum adımlarını içeren software tools
* Mevcut dersler için yeni dersler veya ek materyaller
* İlgi çekici RF protokolleri
* Entegrasyon için daha fazla donanım ve SDR türü
* Python'da IQ analiz script'leri
* Kurulum düzeltmeleri ve iyileştirmeleri

FISSURE'ı geliştirmeye yönelik katkılar, geliştirme sürecini hızlandırmak için kritik öneme sahiptir. Yapacağınız tüm katkılar büyük takdir görür. Code development yoluyla katkıda bulunmak istiyorsanız repo'yu fork edin ve bir pull request oluşturun:

1. Projeyi fork edin
2. Feature branch'inizi oluşturun (`git checkout -b feature/AmazingFeature`)
3. Değişikliklerinizi commit edin (`git commit -m 'Add some AmazingFeature'`)
4. Branch'e push edin (`git push origin feature/AmazingFeature`)
5. Bir pull request açın

Hatalara dikkat çekmek için [Issues](https://github.com/ainfosec/FISSURE/issues) oluşturmanız da memnuniyetle karşılanır.

## İş Birliği

Herhangi bir FISSURE collaboration fırsatını önermek ve resmileştirmek için Assured Information Security, Inc. (AIS) Business Development ile iletişime geçin. Bu fırsatlar; software'inizi entegre etmeye zaman ayırmak, AIS'deki yetenekli kişilerin teknik zorluklarınız için çözümler geliştirmesini sağlamak veya FISSURE'ı diğer platformlara/uygulamalara entegre etmek şeklinde olabilir.

## Lisans

GPL-3.0

Lisans ayrıntıları için LICENSE file'a bakın.

## İletişim

Discord Server'a katılın: [https://discord.gg/JZDs5sgxcG](https://discord.gg/JZDs5sgxcG)

Twitter'da takip edin: [@FissureRF](https://twitter.com/fissurerf), [@AinfoSec](https://twitter.com/ainfosec)

Chris Poore - Assured Information Security, Inc. - poorec@ainfosec.com

Business Development - Assured Information Security, Inc. - bd@ainfosec.com

## Katkıda Bulunanlar

Aşağıdaki geliştiricileri takdir ediyor ve kendilerine teşekkür ediyoruz:

[Katkıda Bulunanlar](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/CREDITS.md)

## Teşekkürler

Bu projeye katkılarından dolayı Dr. Samuel Mantravadi ve Joseph Reith'e özel teşekkürlerimizi sunarız.

## Referanslar

- [1] [FISSURE - The RF Framework (GitHub)](https://github.com/ainfosec/FISSURE)
- [2] [FISSURE Paper (GRCon22)](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE_Paper_Poore_GRCon22.pdf)

{{#include ../../banners/hacktricks-training.md}}
