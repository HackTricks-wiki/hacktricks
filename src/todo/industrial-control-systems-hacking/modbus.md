# Modbus Protocol

{{#include ../../banners/hacktricks-training.md}}

## Modbus'a Giriş

Modbus, PLC'ler, sensörler, aktüatörler ve diğer endüstriyel cihazlar tarafından yaygın olarak uygulanan açık bir application-layer protokolüdür. İstek/yanıt modeli, function code'lar aracılığıyla coil'leri ve register'ları dışa açar. Bu nedenle security testing yalnızca TCP portu 502'yi bulmaya değil; yetkisiz okuma/yazmalara, trafik gözlemine, replay'e ve güvenli olmayan cihaz davranışlarına odaklanır.<sup>[[1]](#references)</sup>

Birçok deployment, yükseltmeler downtime, yeniden sertifikalandırma veya field device'ların değiştirilmesini gerektirdiği için legacy serial ekipmanları kullanmaya devam eder. Geleneksel Modbus, confidentiality veya peer authentication sağlamaz; Modbus Security, X.509 certificate'ları ve TCP portu 802'yi kullanan, TLS tabanlı ayrı bir profildir. Specification herkese açık ve bağımsız olarak uygulanabilir olduğundan vendor davranışı ve optional-function desteği değişiklik gösterir; varsayılmamalı, bunun yerine fingerprinting yapılmalıdır.<sup>[[1]](#references)[[2]](#references)</sup>

## Client-Server Mimarisi

Güncel terminolojide bir **client** transaction'ı başlatır ve bir **server** yanıt döndürür. Eski documentation **master/slave** ifadelerini kullanır. Bu application ilişkisini SPI veya I2C ile karıştırmayın: bunlar farklı bus protocol'leridir.<sup>[[1]](#references)</sup>

## Serial ve Ethernet transport'ları

Aynı Modbus application data'sı serial varyantlar (RTU veya ASCII framing) ve Modbus TCP üzerinden taşınabilir. Modbus TCP bir MBAP header ekler ve normalde TCP portu 502'yi kullanır; serial RTU compact binary framing ve CRC kullanırken, serial ASCII byte'ları hexadecimal karakterler olarak temsil eder ve LRC kullanır.<sup>[[1]](#references)[[3]](#references)</sup>

## Data representation

Data model, single-bit coil/discrete input'lar ile 16-bit input/holding register'lardan oluşur. Multi-register değerleri, byte order, scaling ve semantic anlam cihaza özeldir ve vendor'ın register map'iyle doğrulanmalıdır.<sup>[[1]](#references)</sup>

## Function code'lar

Function code'lar coil'leri (`0x01`) okuma, holding register'ları (`0x03`) okuma, tek bir coil/register yazma (`0x05`/`0x06`) ve birden fazla coil/register yazma (`0x0F`/`0x10`) gibi işlemleri seçer. Yakalanan bir write request, deployment herhangi bir compensating authentication veya process-state check içermediğinde replay edilebilir. Uzun serial hatlara yetkili fiziksel erişimi olan bir assessor, electrical interface'i, termination'ı ve güvenli bağlantı yöntemini belirledikten sonra doğrudan kablolama üzerinden frame'leri de yakalayabilir veya inject edebilir. Her iki işlem de fiziksel process'i etkileyebilir; bu nedenle bir lab veya açık operational authorization kullanın.<sup>[[1]](#references)[[3]](#references)</sup>

## Addressing

Serial cihazlar bir unit address kullanır. Modbus TCP, IP addressing'e ek olarak MBAP header içinde bir Unit Identifier kullanır; bu, istekleri downstream unit'lere yönlendiren TCP-to-serial gateway'lerinde özellikle önemlidir. Product documentation tarafından gösterilen register reference'ları one-based (`40001`), protocol address'leri ise zero-based olabilir; bu durum off-by-one hatalarının yaygın bir kaynağıdır.<sup>[[1]](#references)[[3]](#references)</sup>

Serial framing transmission-error check'leri (RTU için CRC ve ASCII için LRC) içerir ve TCP normal transport checksum'ını sağlar. Bunlar accidental corruption'ı tespit eder; cryptographic integrity veya origin authentication sağlamaz.<sup>[[3]](#references)</sup>

Yetkili bir assessment sırasında exposure'ı, izin verilen function code'ları, yazılabilir address range'lerini, exception handling'i, rate limit'lerini ve network segmentation veya Modbus-aware firewall'ın client'ları kısıtlayıp kısıtlamadığını test edin. İlgili tehditler arasında passive disclosure, unauthorized command injection, replay, data forgery ve denial of service bulunur. Görünüşte küçük register değişiklikleri fiziksel bir process'i değiştirebileceğinden, tüm active test'leri process owner'larıyla koordine edin.

## References

- [1] [Modbus Organization — Modbus Application Protocol Specification V1.1b3](https://www.modbus.org/file/secure/modbusprotocolspecification.pdf)
- [2] [Modbus Organization — Modbus Security Protocol ve implementation guides](https://www.modbus.org/modbus-specifications)
- [3] [Modbus Organization — Modbus over Serial Line Specification ve Implementation Guide V1.02](https://www.modbus.org/file/secure/modbusoverserial.pdf)
{{#include ../../banners/hacktricks-training.md}}
