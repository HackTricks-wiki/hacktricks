# Modbus Protokolü

{{#include /banners/hacktricks-training.md}}

## Modbus Protokolüne Giriş

Modbus protokolü, Endüstriyel Otomasyon ve Kontrol Sistemlerinde yaygın olarak kullanılan bir protokoldür. Modbus, programlanabilir mantık denetleyicileri (PLC'ler), sensörler, aktüatörler ve diğer endüstriyel cihazlar gibi çeşitli cihazlar arasında iletişim sağlar. Modbus Protokolünü anlamak, bu protokolün ICS'de en çok kullanılan iletişim protokolü olması ve PLC'lere komut enjekte etme ve dinleme için büyük bir saldırı yüzeyi sunması nedeniyle önemlidir.

Burada, protokolün bağlamını ve çalışma doğasını sağlayan kavramlar madde madde belirtilmiştir. ICS sistem güvenliğindeki en büyük zorluk, uygulama ve yükseltme maliyetidir. Bu protokoller ve standartlar 80'lerin ve 90'ların başında tasarlanmış olup hala yaygın olarak kullanılmaktadır. Bir endüstride birçok cihaz ve bağlantı olduğundan, cihazları yükseltmek çok zordur, bu da hacker'lara eski protokollerle başa çıkma avantajı sağlar. Modbus'a yönelik saldırılar, endüstrinin operasyonu için kritik olduğundan, yükseltme olmadan kullanılmaya devam edileceği için neredeyse kaçınılmazdır.

## İstemci-Sunucu Mimarisi

Modbus Protokolü genellikle bir ana cihazın (istemci) bir veya daha fazla köle cihazla (sunucu) iletişimi başlattığı İstemci Sunucu Mimarisi olarak kullanılır. Bu, elektronik ve IoT'de SPI, I2C vb. ile yaygın olarak kullanılan Ana-Köle mimarisi olarak da adlandırılır.

## Seri ve Ethernet Versiyonları

Modbus Protokolü, hem Seri İletişim hem de Ethernet İletişimi için tasarlanmıştır. Seri İletişim, eski sistemlerde yaygın olarak kullanılırken, modern cihazlar yüksek veri hızları sunan ve modern endüstriyel ağlar için daha uygun olan Ethernet'i destekler.

## Veri Temsili

Veri, Modbus protokolünde ASCII veya İkili olarak iletilir, ancak ikili format, eski cihazlarla uyumluluğu nedeniyle kullanılır.

## Fonksiyon Kodları

ModBus Protokolü, PLC'leri ve çeşitli kontrol cihazlarını çalıştırmak için kullanılan belirli fonksiyon kodlarının iletimi ile çalışır. Bu bölüm, fonksiyon kodlarının yeniden iletilmesiyle tekrar saldırılar yapılabileceği için önemlidir. Eski cihazlar veri iletimi için herhangi bir şifreleme desteklemez ve genellikle uzun tellerle bağlanır, bu da bu tellerin bozulmasına ve verilerin yakalanmasına/enjekte edilmesine yol açar.

## Modbus Adresleme

Ağdaki her cihazın, cihazlar arasında iletişim için gerekli olan benzersiz bir adresi vardır. Modbus RTU, Modbus TCP gibi protokoller adreslemeyi uygulamak için kullanılır ve veri iletimi için bir taşıma katmanı işlevi görür. Aktarılan veri, mesajı içeren Modbus protokol formatındadır.

Ayrıca, Modbus, iletilen verilerin bütünlüğünü sağlamak için hata kontrolleri de uygular. Ancak en önemlisi, Modbus bir Açık Standarttır ve herkes bunu cihazlarında uygulayabilir. Bu, bu protokolün küresel standart haline gelmesini sağladı ve endüstriyel otomasyon endüstrisinde yaygın olarak kullanılmaktadır.

Büyük ölçekli kullanımı ve yükseltme eksikliği nedeniyle, Modbus'a saldırmak, saldırı yüzeyi ile önemli bir avantaj sağlar. ICS, cihazlar arasındaki iletişime büyük ölçüde bağımlıdır ve bunlara yapılan herhangi bir saldırı, endüstriyel sistemlerin operasyonu için tehlikeli olabilir. Tekrar, veri enjekte etme, veri dinleme ve sızdırma, Hizmetin Engellenmesi, veri sahteciliği gibi saldırılar, iletim ortamı saldırgan tarafından tanımlanırsa gerçekleştirilebilir.

{{#include /banners/hacktricks-training.md}}
