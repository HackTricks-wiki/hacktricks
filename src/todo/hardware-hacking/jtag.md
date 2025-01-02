# JTAG

{{#include ../../banners/hacktricks-training.md}}

## JTAGenum

[**JTAGenum** ](https://github.com/cyphunk/JTAGenum), bilinmeyen bir çipten JTAG pinlerini bulmak için Raspberry PI veya Arduino ile kullanılabilecek bir araçtır.\
**Arduino**'da, **2'den 11'e kadar olan pinleri JTAG'a ait olabilecek 10 pinle bağlayın**. Programı Arduino'ya yükleyin ve JTAG'a ait olan pinleri bulmak için tüm pinleri brute force ile denemeye çalışacaktır.\
**Raspberry PI**'da yalnızca **1'den 6'ya kadar olan pinleri** kullanabilirsiniz (6 pin, bu nedenle her potansiyel JTAG pinini test ederken daha yavaş ilerleyeceksiniz).

### Arduino

Arduino'da, kabloları bağladıktan sonra (pin 2'den 11'e kadar JTAG pinlerine ve Arduino GND'yi ana kart GND'ye bağlayarak), **Arduino'da JTAGenum programını yükleyin** ve Seri Monitörde **`h`** (yardım komutu) gönderin ve yardım metnini görmelisiniz:

![](<../../images/image (939).png>)

![](<../../images/image (578).png>)

**"No line ending" ve 115200baud** ayarlarını yapın.\
Tarama başlatmak için s komutunu gönderin:

![](<../../images/image (774).png>)

Eğer bir JTAG ile iletişim kuruyorsanız, JTAG pinlerini belirten **FOUND!** ile başlayan bir veya daha fazla **satır bulacaksınız**.

{{#include ../../banners/hacktricks-training.md}}
