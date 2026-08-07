# macOS Serial Number

{{#include ../../../banners/hacktricks-training.md}}

## Temel Bilgiler

2010 sonrası Apple cihazlarının seri numaraları, her bölümü belirli bilgiler içeren **12 alfanümerik karakterden** oluşur:

- **İlk 3 Karakter**: **Üretim konumunu** belirtir.
- **4. ve 5. Karakterler**: **Üretim yılını ve haftasını** belirtir.
- **6. ila 8. Karakterler**: Her cihaz için **benzersiz tanımlayıcı** görevi görür.
- **Son 4 Karakter**: **Model numarasını** belirtir.

Örneğin, **C02L13ECF8J2** seri numarası bu yapıyı izler.

### **Üretim Konumları (İlk 3 Karakter)**

Bazı kodlar belirli fabrikaları temsil eder:

- **FC, F, XA/XB/QP/G8**: ABD'deki çeşitli konumlar.
- **RN**: Meksika.
- **CK**: Cork, İrlanda.
- **VM**: Foxconn, Çek Cumhuriyeti.
- **SG/E**: Singapur.
- **MB**: Malezya.
- **PT/CY**: Kore.
- **EE/QT/UV**: Tayvan.
- **FK/F1/F2, W8, DL/DM, DN, YM/7J, 1C/4H/WQ/F7**: Çin'deki farklı konumlar.
- **C0, C3, C7**: Çin'deki belirli şehirler.
- **RM**: Refurbished cihazlar.

### **Üretim Yılı (4. Karakter)**

Bu karakter, 'C' (2010'un ilk yarısını temsil eder) ile 'Z' (2019'un ikinci yarısı) arasında değişir; farklı harfler farklı altı aylık dönemleri belirtir.

### **Üretim Haftası (5. Karakter)**

1-9 rakamları 1-9. haftalara karşılık gelir. Sesli harfler ve 'S' hariç C-Y harfleri 10-27. haftaları temsil eder. Yılın ikinci yarısı için bu sayıya 26 eklenir.

{{#include ../../../banners/hacktricks-training.md}}
