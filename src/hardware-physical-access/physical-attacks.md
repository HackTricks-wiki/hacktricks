# Fiziksel Saldırılar

{{#include ../banners/hacktricks-training.md}}

## BIOS Şifre Kurtarma ve Sistem Güvenliği

**BIOS'u sıfırlamak**, birkaç şekilde gerçekleştirilebilir. Çoğu anakart, **30 dakika** kadar çıkarıldığında BIOS ayarlarını, şifreyi de içerecek şekilde sıfırlayan bir **pil** içerir. Alternatif olarak, bu ayarları sıfırlamak için anakart üzerindeki bir **jumper** belirli pinleri bağlayarak ayarlanabilir.

Donanım ayarlamalarının mümkün veya pratik olmadığı durumlar için, **yazılım araçları** bir çözüm sunar. **Kali Linux** gibi dağıtımlarla bir **Live CD/USB** üzerinden sistem çalıştırmak, BIOS şifre kurtarmaya yardımcı olabilecek **_killCmos_** ve **_CmosPWD_** gibi araçlara erişim sağlar.

BIOS şifresi bilinmediğinde, yanlış girildiğinde genellikle **üç kez** hata kodu ile sonuçlanır. Bu kod, kullanılabilir bir şifre elde etmek için [https://bios-pw.org](https://bios-pw.org) gibi web sitelerinde kullanılabilir.

### UEFI Güvenliği

Geleneksel BIOS yerine **UEFI** kullanan modern sistemler için, **chipsec** aracı UEFI ayarlarını analiz etmek ve değiştirmek, **Secure Boot**'u devre dışı bırakmak da dahil olmak üzere kullanılabilir. Bu, aşağıdaki komutla gerçekleştirilebilir:
```bash
python chipsec_main.py -module exploits.secure.boot.pk
```
---

## RAM Analizi ve Soğuk Başlatma Saldırıları

RAM, güç kesildiğinde verileri kısa bir süre saklar, genellikle **1 ila 2 dakika**. Bu süre, sıvı azot gibi soğuk maddeler uygulanarak **10 dakikaya** kadar uzatılabilir. Bu uzatılmış süre boyunca, analiz için **dd.exe** ve **volatility** gibi araçlar kullanılarak bir **bellek dökümü** oluşturulabilir.

---

## Doğrudan Bellek Erişimi (DMA) Saldırıları

**INCEPTION**, **FireWire** ve **Thunderbolt** gibi arayüzlerle uyumlu, **fiziksel bellek manipülasyonu** için tasarlanmış bir araçtır. Herhangi bir şifreyi kabul etmek için belleği yamanarak oturum açma prosedürlerini atlamaya olanak tanır. Ancak, **Windows 10** sistemlerine karşı etkisizdir.

---

## Sistem Erişimi için Canlı CD/USB

**_sethc.exe_** veya **_Utilman.exe_** gibi sistem ikili dosyalarını **_cmd.exe_** kopyasıyla değiştirmek, sistem ayrıcalıklarıyla bir komut istemcisi sağlayabilir. **chntpw** gibi araçlar, bir Windows kurulumunun **SAM** dosyasını düzenlemek için kullanılabilir ve şifre değişikliklerine olanak tanır.

**Kon-Boot**, Windows çekirdeğini veya UEFI'yi geçici olarak değiştirerek şifreyi bilmeden Windows sistemlerine giriş yapmayı kolaylaştıran bir araçtır. Daha fazla bilgi [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/) adresinde bulunabilir.

---

## Windows Güvenlik Özelliklerini Yönetme

### Başlatma ve Kurtarma Kısayolları

- **Supr**: BIOS ayarlarına erişim.
- **F8**: Kurtarma moduna girme.
- Windows banner'ından sonra **Shift** tuşuna basmak, otomatik oturumu atlayabilir.

### KÖTÜ USB Cihazları

**Rubber Ducky** ve **Teensyduino** gibi cihazlar, hedef bilgisayara bağlandıklarında önceden tanımlanmış yükleri çalıştırabilen **kötü USB** cihazları oluşturmak için platformlar olarak hizmet eder.

### Hacim Gölge Kopyası

Yönetici ayrıcalıkları, PowerShell aracılığıyla **SAM** dosyası da dahil olmak üzere hassas dosyaların kopyalarını oluşturma olanağı sağlar.

---

## BitLocker Şifrelemesini Atlatma

BitLocker şifrelemesi, **kurtarma şifresi** bir bellek döküm dosyasında (**MEMORY.DMP**) bulunursa potansiyel olarak atlatılabilir. Bu amaçla **Elcomsoft Forensic Disk Decryptor** veya **Passware Kit Forensic** gibi araçlar kullanılabilir.

---

## Kurtarma Anahtarı Ekleme için Sosyal Mühendislik

Yeni bir BitLocker kurtarma anahtarı, bir kullanıcıyı sıfırlanmış bir kurtarma anahtarı ekleyecek bir komutu çalıştırmaya ikna ederek sosyal mühendislik taktikleriyle eklenebilir, böylece şifre çözme süreci basitleştirilir.

---

## Şasi İhlali / Bakım Anahtarlarını Kullanarak BIOS'u Fabrika Ayarlarına Sıfırlama

Birçok modern dizüstü bilgisayar ve küçük form faktörlü masaüstü bilgisayar, Gömülü Kontrolör (EC) ve BIOS/UEFI yazılımı tarafından izlenen bir **şasi ihlali anahtarı** içerir. Anahtarın temel amacı, bir cihaz açıldığında bir uyarı vermektir, ancak satıcılar bazen anahtarın belirli bir desenle değiştirilmesi durumunda tetiklenen **belgelendirilmemiş bir kurtarma kısayolu** uygular.

### Saldırının Nasıl Çalıştığı

1. Anahtar, EC üzerindeki bir **GPIO kesintisine** bağlıdır.
2. EC üzerinde çalışan yazılım, **basma zamanını ve sayısını** takip eder.
3. Sabit bir desen tanındığında, EC bir *ana kart sıfırlama* rutinini çağırır ve **sistem NVRAM/CMOS'un içeriğini siler**.
4. Bir sonraki önyüklemede, BIOS varsayılan değerleri yükler – **yönetici şifresi, Güvenli Önyükleme anahtarları ve tüm özel yapılandırmalar silinir**.

> Güvenli Önyükleme devre dışı bırakıldığında ve yazılım şifresi kaybolduğunda, saldırgan herhangi bir harici işletim sistemi görüntüsünü önyükleyebilir ve dahili sürücülere sınırsız erişim elde edebilir.

### Gerçek Dünya Örneği – Framework 13 Dizüstü Bilgisayar

Framework 13 (11./12./13. nesil) için kurtarma kısayolu:
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
Onuncu döngüden sonra EC, BIOS'a bir sonraki yeniden başlatmada NVRAM'ı silmesi için bir bayrak ayarlar. Tüm prosedür yaklaşık 40 saniye sürer ve **sadece bir tornavida** gerektirir.

### Genel İstismar Prosedürü

1. Hedefi açın veya askıya alıp yeniden başlatın, böylece EC çalışır durumda olsun.
2. Giriş/ bakım anahtarını açığa çıkarmak için alt kapağı çıkarın.
3. Satıcıya özgü anahtar desenini yeniden oluşturun (belgelere, forumlara danışın veya EC yazılımını tersine mühendislik ile inceleyin).
4. Yeniden monte edin ve yeniden başlatın – yazılım korumaları devre dışı olmalıdır.
5. Canlı bir USB (örneğin Kali Linux) başlatın ve olağan sonrası istismar işlemlerini gerçekleştirin (kimlik bilgisi dökümü, veri sızdırma, kötü niyetli EFI ikili dosyaları yerleştirme vb.).

### Tespit ve Azaltma

* Şasi ihlali olaylarını işletim sistemi yönetim konsolunda kaydedin ve beklenmedik BIOS sıfırlamaları ile ilişkilendirin.
* Açılmayı tespit etmek için vidalar/kapaklar üzerinde **açılma kanıtı olan mühürler** kullanın.
* Cihazları **fiziksel olarak kontrol edilen alanlarda** tutun; fiziksel erişimin tam bir ihanet anlamına geldiğini varsayın.
* Mümkünse, satıcının "bakım anahtarı sıfırlama" özelliğini devre dışı bırakın veya NVRAM sıfırlamaları için ek bir kriptografik yetkilendirme gerektirin.

---

## Referanslar

- [Pentest Partners – “Framework 13. Press here to pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [FrameWiki – Mainboard Reset Guide](https://framewiki.net/guides/mainboard-reset)

{{#include ../banners/hacktricks-training.md}}
