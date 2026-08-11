# FISSURE - RF Framework'ü

{{#include ../../banners/hacktricks-training.md}}

**Frequency Independent SDR-based Signal Understanding and Reverse Engineering**

FISSURE, her seviyedeki yetkinlik için tasarlanmış; signal detection ve classification, protocol discovery, attack execution, IQ manipulation, vulnerability analysis, automation ve AI/ML özellikleri sunan, açık kaynaklı bir RF ve reverse engineering framework'üdür. Framework; software modules, radios, protocols, signal data, scripts, flow graphs, reference material ve third-party tools'un hızlı entegrasyonunu desteklemek amacıyla oluşturulmuştur. FISSURE, software'ı tek bir konumda tutan ve ekiplerin belirli Linux dağıtımları için aynı doğrulanmış baseline configuration'ı paylaşırken hızla çalışmaya başlamasını sağlayan bir workflow enabler'dır.<sup>[[1]](#references)[[2]](#references)</sup>

FISSURE ile birlikte gelen framework ve tools; RF energy'yi tespit etmek, sinyalleri karakterize etmek, sample'ları toplamak ve analiz etmek, transmit veya injection teknikleri geliştirmek ve özel payload veya message'lar oluşturmak üzere tasarlanmıştır. FISSURE ayrıca identification, packet crafting ve fuzzing için protocol ve signal information; traffic simulation ve testing için de archive ve playlist'ler sağlar.<sup>[[1]](#references)[[2]](#references)</sup>

Python codebase ve graphical interface, beginner'ların RF ve reverse-engineering tools öğrenmesine yardımcı olur. Educator'lar yerleşik lesson'ları kullanabilir; developer ve researcher'lar ise kendi module ve workflow'larını entegre edebilir. Güncel release'ler ayrıca distributed sensor node'larını, TAK integration'ını, geolocation workflow'larını ve role-specific Apptainer deployment'larını destekler.<sup>[[1]](#references)[[3]](#references)</sup>

**Additional Information**

* [AIS Page](https://www.ainfosec.com/technologies/fissure/)
* [GRCon22 Slides](https://events.gnuradio.org/event/18/contributions/246/attachments/84/164/FISSURE\_Poore\_GRCon22.pdf)
* [GRCon22 Paper](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE\_Paper\_Poore\_GRCon22.pdf)
* [GRCon22 Video](https://www.youtube.com/watch?v=1f2umEKhJvE)
* [Hack Chat Transcript](https://hackaday.io/event/187076-rf-hacking-hack-chat/log/212136-hack-chat-transcript-part-1)

## Getting Started

**Supported**

Güncel FISSURE, PyQt5 ve GNU Radio 3.8 veya 3.10 ile aktif development için **`Python3`** branch'ini kullanır. Kullanımdan kaldırılmış **`Python2_maint-3.7`** branch'i, GNU Radio 3.7 gerektiren eski operating system'ler ve third-party tools için kullanılabilir olmaya devam etmektedir. Önceki `Python3_maint-3.8` ve `Python3_maint-3.10` branch adları tarihîdir; GNU Radio maintenance seçimi artık `Python3` branch'i üzerinden yapılmaktadır.<sup>[[1]](#references)[[3]](#references)</sup>

| Operating System | FISSURE Branch | Default GNU Radio branch |
| :--: | :--: | :--: |
| DragonOS Noble (24.04) | Python3 | maint-3.10 |
| Kali | Python3 | maint-3.10 |
| Raspberry Pi OS | Python3 | maint-3.10 |
| Ubuntu 18.04 | Python2\_maint-3.7 | maint-3.7 |
| Ubuntu 20.04 | Python3 | maint-3.8 |
| Ubuntu 22.04 | Python3 | maint-3.10 |
| Ubuntu 24.04 / Ubuntu ARM | Python3 | maint-3.10 |
| Windows 11 WSL2 | use a supported Linux version | use the matching version |

**In-Progress (beta)**

Bu operating system'ler hâlâ beta durumundadır. Development aşamasındadır ve çeşitli feature'ların eksik olduğu bilinmektedir. Installer'daki item'lar mevcut programlarla çakışabilir veya durum kaldırılana kadar install edilemeyebilir.

| Operating System | FISSURE Branch | Default GNU Radio branch |
| :--: | :--: | :--: |
| BackBox Linux | Python3 | maint-3.10 |
| KDE neon | Python3 | maint-3.10 |
| Parrot Security 6.1 | Python3 | maint-3.10 |

Bazı third-party tools her OS'te çalışmaz. Install etmeden önce güncel [Known Conflicts and Third-Party Software](https://fissure.readthedocs.io/en/latest/pages/installation.html#known-conflicts) documentation'ını kontrol edin.<sup>[[3]](#references)</sup>

**Installation**
```
git clone https://github.com/ainfosec/FISSURE.git
cd FISSURE
git checkout Python3  # optional; use Python2_maint-3.7 only for legacy requirements
git submodule update --init
./install
```
submodule adımı, FISSURE tarafından kullanılan GNU Radio out-of-tree modules modüllerini indirir ve bu modüller yüklenirken gereklidir. Installer ayrıca kurulum GUI'lerini başlatmak için gereken eksik PyQt bağımlılıklarını da yükler.<sup>[[3]](#references)</sup>

Ardından işletim sisteminize en uygun seçeneği belirleyin (işletim sisteminiz seçeneklerden biriyle eşleşiyorsa otomatik olarak algılanmalıdır).

|                                          Python2\_maint-3.7                                          |                                          Python3\_maint-3.8                                          |                                          Python3\_maint-3.10                                         |
| :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: |
| ![install1b](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1b.png) | ![install1a](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1a.png) | ![install1c](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1c.png) |

Mevcut çakışmaları önlemek için FISSURE'ı temiz bir işletim sistemine yüklemeniz önerilir. FISSURE içindeki çeşitli araçları kullanırken oluşabilecek hataları önlemek için önerilen tüm onay kutularını (Default düğmesi) seçin. Kurulum boyunca çoğunlukla yükseltilmiş izinler ve kullanıcı adları isteyen birden fazla istem görüntülenir. Bir öğenin sonunda "Verify" bölümü varsa installer, devamındaki komutu çalıştırır ve komut tarafından hata üretilip üretilmediğine bağlı olarak onay kutusu öğesini yeşil veya kırmızı renkle vurgular. "Verify" bölümü olmayan işaretli öğeler, kurulumdan sonra siyah olarak kalır.

![install2](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install2.png)

**Kullanım**

Bir terminal açın ve şunu girin:
```
fissure
```
Kullanım hakkında daha fazla bilgi için FISSURE Help menüsüne bakın.

## Ayrıntılar

**Bileşenler**

* Dashboard
* Central Hub (HIPRFISR)
* Target Signal Identification (TSI)
* Protocol Discovery (PD)
* Flow Graph & Script Executor (FGE)

![components](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/components.png)

**Yetenekler**

| ![Signal Detector icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/detector.png)_**Signal Detector**_ | ![IQ Manipulation icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/iq.png)_**IQ Manipulation**_      | ![Signal Lookup icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/library.png)_**Signal Lookup**_          | ![Pattern Recognition icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/pd.png)_**Pattern Recognition**_ |
| --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| ![Attacks icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/attack.png)_**Attacks**_           | ![Fuzzing icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/fuzzing.png)_**Fuzzing**_         | ![Signal Playlists icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/archive.png)_**Signal Playlists**_       | ![Image Gallery icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/gallery.png)_**Image Gallery**_  |
| ![Packet Crafting icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/packet.png)_**Packet Crafting**_   | ![Scapy Integration icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/scapy.png)_**Scapy Integration**_ | ![CRC Calculator icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/crc\_calculator.png)_**CRC Calculator**_ | ![Logging icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/log.png)_**Logging**_            |

**Donanım**

Aşağıdaki donanımlar FISSURE ile farklı düzeylerde entegrasyona sahiptir:<sup>[[1]](#references)[[3]](#references)</sup>

* USRP: X3xx, B2xx, B20xmini, USRP2, N2xx, X410
* HackRF
* RTL2832U
* 802.11 Adapters
* LimeSDR
* bladeRF, bladeRF 2.0 micro
* Open Sniffer
* PlutoSDR
* SDRplay: RSPduo, RSPdx, RSPdx R2

## Dersler

FISSURE, farklı teknolojilere ve tekniklere aşina olmanız için çeşitli yararlı kılavuzlarla birlikte gelir. Kılavuzların çoğu, FISSURE ile entegre çeşitli araçların kullanımına ilişkin adımlar içerir.

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
* [Ders12: Creating Bootable USBs](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson12_Creating_Bootable_USBs.md)
* [Ders13: Z-Wave](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson13_Z-Wave.md)
* [Ders14: Ceiling Fans](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson14_Ceiling_Fans.md)

## Yol Haritası

* [ ] Daha fazla donanım türü, RF protokolü, sinyal parametresi ve analiz aracı eklemek
* [ ] Daha fazla işletim sistemini desteklemek
* [ ] FISSURE etrafında sınıf materyali geliştirmek (RF Attacks, Wi-Fi, GNU Radio, PyQt vb.)
* [ ] Seçilebilir AI/ML teknikleriyle bir sinyal conditioner, feature extractor ve signal classifier oluşturmak
* [ ] Bilinmeyen sinyallerden bitstream üretmek için recursive demodulation mekanizmalarını uygulamak
* [ ] Ana FISSURE bileşenlerini generic sensor node deployment scheme'e geçirmek

## Katkıda Bulunma

FISSURE'ı geliştirmeye yönelik önerileriniz özellikle teşvik edilmektedir. Aşağıdaki konulardan biri hakkında düşünceniz varsa [Discussions](https://github.com/ainfosec/FISSURE/discussions) sayfasına veya Discord Server'a yorum bırakın:

* Yeni özellik önerileri ve tasarım değişiklikleri
* Kurulum adımlarını içeren software tools
* Yeni dersler veya mevcut dersler için ek materyaller
* İlgi duyulan RF protokolleri
* Entegrasyon için daha fazla donanım ve SDR türü
* Python'da IQ analysis scripts
* Kurulum düzeltmeleri ve iyileştirmeleri

FISSURE'ı geliştirmeye yönelik katkılar, geliştirme sürecini hızlandırmak açısından kritik öneme sahiptir. Yaptığınız tüm katkılar büyük takdir görür. Code development yoluyla katkıda bulunmak istiyorsanız repo'yu fork edin ve bir pull request oluşturun:

1. Projeyi fork edin
2. Feature branch'inizi oluşturun (`git checkout -b feature/AmazingFeature`)
3. Değişikliklerinizi commit edin (`git commit -m 'Add some AmazingFeature'`)
4. Branch'e push edin (`git push origin feature/AmazingFeature`)
5. Bir pull request açın

Hatalara dikkat çekmek için [Issues](https://github.com/ainfosec/FISSURE/issues) oluşturmanız da memnuniyetle karşılanır.

## İş Birliği

Herhangi bir FISSURE iş birliği fırsatını önermek ve resmileştirmek için Assured Information Security, Inc. (AIS) Business Development ile iletişime geçin. Bu fırsatlar; yazılımınızı entegre etmeye zaman ayırmayı, AIS bünyesindeki yetenekli kişilerin teknik sorunlarınıza çözümler geliştirmesini veya FISSURE'ı diğer platformlara/uygulamalara entegre etmeyi kapsayabilir.

## Lisans

GPL-3.0

Lisans ayrıntıları için LICENSE file'a bakın.

## İletişim

Discord Server'a katılın: [https://discord.gg/JZDs5sgxcG](https://discord.gg/JZDs5sgxcG)

Twitter'da takip edin: [@FissureRF](https://twitter.com/fissurerf), [@AinfoSec](https://twitter.com/ainfosec)

Chris Poore - Assured Information Security, Inc. - poorec@ainfosec.com

Business Development - Assured Information Security, Inc. - bd@ainfosec.com

## Katkıda Bulunanlar

Aşağıdaki geliştiricileri kabul ediyor ve kendilerine minnettarlığımızı ifade ediyoruz:

[Credits](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/CREDITS.md)

## Teşekkürler

Bu projeye katkılarından dolayı Dr. Samuel Mantravadi ve Joseph Reith'e özel teşekkürlerimizi sunarız.

## References

- [1] [FISSURE - RF Framework (GitHub)](https://github.com/ainfosec/FISSURE)
- [2] [FISSURE Paper (GRCon22)](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE_Paper_Poore_GRCon22.pdf)
- [3] [FISSURE documentation - Installation](https://fissure.readthedocs.io/en/latest/pages/installation.html)
{{#include ../../banners/hacktricks-training.md}}
