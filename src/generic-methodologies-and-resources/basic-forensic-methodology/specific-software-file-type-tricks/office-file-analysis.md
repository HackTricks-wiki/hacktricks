# Office dosyası analizi

{{#include ../../../banners/hacktricks-training.md}}

Daha fazla bilgi için [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/) adresini kontrol edin. Bu sadece bir özet:

Microsoft, iki ana türü **OLE formatları** (RTF, DOC, XLS, PPT gibi) ve **Office Open XML (OOXML) formatları** (DOCX, XLSX, PPTX gibi) olmak üzere birçok ofis belge formatı oluşturmuştur. Bu formatlar makrolar içerebilir, bu da onları kimlik avı ve kötü amaçlı yazılım hedefleri haline getirir. OOXML dosyaları, dosya ve klasör hiyerarşisini ve XML dosyası içeriklerini ortaya çıkaran zip konteynerleri olarak yapılandırılmıştır.

OOXML dosya yapılarını keşfetmek için bir belgeyi açmak için kullanılan komut ve çıktı yapısı verilmiştir. Bu dosyalarda veri gizleme teknikleri belgelenmiştir ve CTF zorlukları içinde veri gizleme konusunda devam eden yenilikleri göstermektedir.

Analiz için, **oletools** ve **OfficeDissector**, hem OLE hem de OOXML belgelerini incelemek için kapsamlı araç setleri sunar. Bu araçlar, genellikle kötü amaçlı yazılım dağıtım vektörleri olarak hizmet eden gömülü makroları tanımlama ve analiz etme konusunda yardımcı olur; genellikle ek kötü amaçlı yükleri indirme ve çalıştırma işlemleri gerçekleştirir. VBA makrolarının analizi, hata ayıklama için kesme noktaları ve izleme değişkenleri ile birlikte Libre Office kullanılarak Microsoft Office olmadan gerçekleştirilebilir.

**oletools**'un kurulumu ve kullanımı basittir; pip ile kurulum ve belgelerden makro çıkarma komutları sağlanmıştır. Makroların otomatik olarak çalıştırılması, `AutoOpen`, `AutoExec` veya `Document_Open` gibi işlevlerle tetiklenir.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
{{#include ../../../banners/hacktricks-training.md}}
