# macOS Seri Numarası

{{#include ../../../banners/hacktricks-training.md}}

## Temel Bilgiler

2010 sonrası Apple cihazları, her biri belirli bilgileri ileten **12 alfanümerik karakterden** oluşan seri numaralarına sahiptir:

- **İlk 3 Karakter**: **üretim yerini** gösterir.
- **Karakterler 4 & 5**: **üretim yılı ve haftasını** belirtir.
- **Karakterler 6'dan 8'e**: Her cihaz için **benzersiz bir tanımlayıcı** olarak hizmet eder.
- **Son 4 Karakter**: **model numarasını** belirtir.

Örneğin, seri numarası **C02L13ECF8J2** bu yapıyı takip eder.

### **Üretim Yerleri (İlk 3 Karakter)**

Belirli kodlar, belirli fabrikaları temsil eder:

- **FC, F, XA/XB/QP/G8**: ABD'deki çeşitli yerler.
- **RN**: Meksika.
- **CK**: Cork, İrlanda.
- **VM**: Foxconn, Çek Cumhuriyeti.
- **SG/E**: Singapur.
- **MB**: Malezya.
- **PT/CY**: Kore.
- **EE/QT/UV**: Tayvan.
- **FK/F1/F2, W8, DL/DM, DN, YM/7J, 1C/4H/WQ/F7**: Çin'deki farklı yerler.
- **C0, C3, C7**: Çin'deki belirli şehirler.
- **RM**: Yenilenmiş cihazlar.

### **Üretim Yılı (4. Karakter)**

Bu karakter 'C' (2010'un ilk yarısını temsil eder) ile 'Z' (2019'un ikinci yarısını temsil eder) arasında değişir; farklı harfler farklı yarı yıl dönemlerini gösterir.

### **Üretim Haftası (5. Karakter)**

1-9 rakamları 1-9 haftalarına karşılık gelir. C-Y harfleri (sesli harfler ve 'S' hariç) 10-27 haftalarını temsil eder. Yılın ikinci yarısı için bu sayıya 26 eklenir.

{{#include ../../../banners/hacktricks-training.md}}
