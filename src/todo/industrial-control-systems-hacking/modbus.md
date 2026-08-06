# Modbus Protokolü

{{#include ../../banners/hacktricks-training.md}}

## Modbus Protokolüne Giriş

Modbus protokolü, Endüstriyel Otomasyon ve Kontrol Sistemlerinde yaygın olarak kullanılan bir protokoldür. Modbus; programlanabilir mantık denetleyicileri (PLC'ler), sensörler, aktüatörler ve diğer endüstriyel cihazlar gibi çeşitli cihazlar arasında iletişim kurulmasını sağlar. Modbus Protokolünü anlamak önemlidir; çünkü ICS'de en çok kullanılan iletişim protokolüdür ve PLC'leri sniffing, hatta komut enjekte etme açısından geniş bir attack surface barındırır.

Burada kavramlar, protokolün bağlamını ve çalışma yapısını açıklayacak şekilde maddeler hâlinde sunulmuştur. ICS system security açısından en büyük zorluk, uygulama ve yükseltme maliyetidir. Bu protokoller ve standartlar 80'li ve 90'lı yılların başında tasarlanmış olup hâlâ yaygın olarak kullanılmaktadır. Bir endüstride çok sayıda cihaz ve bağlantı bulunduğundan, cihazları yükseltmek oldukça zordur. Bu durum, hacker'lara eski protokollerle uğraşma konusunda avantaj sağlar. Modbus'a yönelik saldırılar pratikte neredeyse kaçınılmazdır; çünkü işletimi endüstri açısından kritik olduğu sürece yükseltme yapılmadan kullanılmaya devam edecektir.

## Client-Server Mimarisi

Modbus Protokolü genellikle bir master cihazın (client), bir veya daha fazla slave cihazla (server) iletişimi başlattığı Client-Server Architecture yapısında kullanılır. Bu yapı, SPI, I2C vb. teknolojilerle electronics ve IoT alanlarında yaygın olarak kullanılan Master-Slave architecture olarak da adlandırılır.

## Serial ve Etherent Sürümleri

Modbus Protokolü hem Serial Communication hem de Ethernet Communications için tasarlanmıştır. Serial Communication legacy systems sistemlerinde yaygın olarak kullanılırken, modern cihazlar yüksek data rates sunan ve modern industrial networks için daha uygun olan Ethernet'i destekler.

## Veri Gösterimi

Veriler Modbus protokolünde ASCII veya Binary olarak iletilir; ancak eski cihazlarla uyumluluğu ve compactibility nedeniyle Binary format kullanılır.

## Fonksiyon Kodları

ModBus Protokolü, PLC'leri ve çeşitli control devices cihazlarını çalıştırmak için kullanılan belirli function codes iletimini temel alır. Bu bölümün anlaşılması önemlidir; çünkü replay attacks, function codes yeniden iletilerek gerçekleştirilebilir. Legacy devices, data transmission için herhangi bir encryption desteklemez ve genellikle kendilerini birbirine bağlayan uzun kablolara sahiptir. Bu durum, bu kabloların kurcalanmasına ve verilerin yakalanıp enjekte edilmesine yol açar.

## Modbus Adresleme

Ağdaki her cihaz, cihazlar arasındaki iletişim için gerekli olan benzersiz bir adrese sahiptir. Modbus RTU, Modbus TCP vb. protokoller adreslemeyi uygulamak için kullanılır ve data transmission için bir transport layer görevi görür. Aktarılan veriler, mesajı içeren Modbus protokolü formatındadır.

Ayrıca Modbus, iletilen verilerin bütünlüğünü sağlamak için error checks de uygular. Ancak her şeyden önce Modbus bir Open Standard'dır ve herkes bunu kendi cihazlarında uygulayabilir. Bu durum, protokolün global standard hâline gelmesini ve industrial automation industry genelinde yaygınlaşmasını sağlamıştır.

Yaygın kullanımı ve yükseltmelerin eksikliği nedeniyle Modbus'a saldırmak, attack surface açısından önemli bir avantaj sağlar. ICS, cihazlar arasındaki iletişime büyük ölçüde bağımlıdır ve bu cihazlara yönelik herhangi bir saldırı, industrial systems işletimi açısından tehlikeli olabilir. İletim ortamı attacker tarafından tespit edilirse replay, data injection, data sniffing ve leak, Denial of Service, data forgery vb. saldırılar gerçekleştirilebilir.

{{#include ../../banners/hacktricks-training.md}}
