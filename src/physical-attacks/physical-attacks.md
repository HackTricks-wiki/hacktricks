# Fiziksel Saldırılar

{{#include ../banners/hacktricks-training.md}}

## BIOS Şifre Kurtarma ve Sistem Güvenliği

**BIOS'u sıfırlamak**, birkaç şekilde gerçekleştirilebilir. Çoğu anakart, **30 dakika** kadar çıkarıldığında BIOS ayarlarını, şifreyi de içerecek şekilde sıfırlayan bir **pil** içerir. Alternatif olarak, belirli pinleri bağlayarak bu ayarları sıfırlamak için **anakart üzerindeki bir jumper** ayarlanabilir.

Donanım ayarlamalarının mümkün veya pratik olmadığı durumlar için, **yazılım araçları** bir çözüm sunar. **Kali Linux** gibi dağıtımlarla bir **Live CD/USB** üzerinden sistem çalıştırmak, BIOS şifre kurtarmaya yardımcı olabilecek **_killCmos_** ve **_CmosPWD_** gibi araçlara erişim sağlar.

BIOS şifresi bilinmediğinde, yanlış girildiğinde genellikle **üç kez** hata kodu ile sonuçlanır. Bu kod, kullanılabilir bir şifre elde etmek için [https://bios-pw.org](https://bios-pw.org) gibi web sitelerinde kullanılabilir.

### UEFI Güvenliği

Geleneksel BIOS yerine **UEFI** kullanan modern sistemler için, **chipsec** aracı UEFI ayarlarını analiz etmek ve değiştirmek için kullanılabilir, bu da **Secure Boot**'un devre dışı bırakılmasını içerir. Bu, aşağıdaki komutla gerçekleştirilebilir:

`python chipsec_main.py -module exploits.secure.boot.pk`

### RAM Analizi ve Soğuk Başlatma Saldırıları

RAM, güç kesildiğinde verileri kısa bir süre saklar, genellikle **1 ila 2 dakika**. Bu süre, sıvı nitrojen gibi soğuk maddeler uygulanarak **10 dakikaya** kadar uzatılabilir. Bu uzatılmış süre boyunca, analiz için **dd.exe** ve **volatility** gibi araçlar kullanılarak bir **bellek dökümü** oluşturulabilir.

### Doğrudan Bellek Erişimi (DMA) Saldırıları

**INCEPTION**, **FireWire** ve **Thunderbolt** gibi arayüzlerle uyumlu, **fiziksel bellek manipülasyonu** için tasarlanmış bir araçtır. Herhangi bir şifreyi kabul etmek için belleği yamanarak oturum açma prosedürlerini atlamaya olanak tanır. Ancak, **Windows 10** sistemlerine karşı etkisizdir.

### Sistem Erişimi için Live CD/USB

**_sethc.exe_** veya **_Utilman.exe_** gibi sistem ikili dosyalarını **_cmd.exe_** kopyası ile değiştirmek, sistem ayrıcalıkları ile bir komut istemcisi sağlar. **chntpw** gibi araçlar, bir Windows kurulumunun **SAM** dosyasını düzenlemek için kullanılabilir ve şifre değişikliklerine olanak tanır.

**Kon-Boot**, Windows çekirdeğini veya UEFI'yi geçici olarak değiştirerek şifreyi bilmeden Windows sistemlerine giriş yapmayı kolaylaştıran bir araçtır. Daha fazla bilgi [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/) adresinde bulunabilir.

### Windows Güvenlik Özelliklerini Yönetme

#### Başlatma ve Kurtarma Kısayolları

- **Supr**: BIOS ayarlarına erişim.
- **F8**: Kurtarma moduna girme.
- Windows afişinden sonra **Shift** tuşuna basmak, otomatik oturumu atlayabilir.

#### KÖTÜ USB Cihazları

**Rubber Ducky** ve **Teensyduino** gibi cihazlar, hedef bilgisayara bağlandıklarında önceden tanımlanmış yükleri çalıştırabilen **kötü USB** cihazları oluşturmak için platformlar olarak hizmet eder.

#### Hacim Gölge Kopyası

Yönetici ayrıcalıkları, PowerShell aracılığıyla **SAM** dosyası da dahil olmak üzere hassas dosyaların kopyalarını oluşturma imkanı sağlar.

### BitLocker Şifrelemesini Atlatma

BitLocker şifrelemesi, **kurtarma şifresi** bir bellek döküm dosyasında (**MEMORY.DMP**) bulunursa potansiyel olarak atlatılabilir. Bu amaçla **Elcomsoft Forensic Disk Decryptor** veya **Passware Kit Forensic** gibi araçlar kullanılabilir.

### Kurtarma Anahtarı Ekleme için Sosyal Mühendislik

Yeni bir BitLocker kurtarma anahtarı, bir kullanıcıyı sıfırlama anahtarı ekleyecek bir komutu çalıştırmaya ikna ederek sosyal mühendislik taktikleriyle eklenebilir; bu anahtar sıfırlardan oluşur ve böylece şifre çözme sürecini basitleştirir.

{{#include ../banners/hacktricks-training.md}}
