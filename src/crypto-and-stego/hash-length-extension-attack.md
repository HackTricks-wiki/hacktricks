# Hash Length Extension Attack

{{#include ../banners/hacktricks-training.md}}

## Saldırının Özeti

Bir sunucunun bazı bilinen düz metin verilerine bir **gizli** ekleyerek **imza** attığını ve ardından bu veriyi **hash**lediğini hayal edin. Eğer şunları biliyorsanız:

- **Gizlinin uzunluğu** (bu, verilen bir uzunluk aralığından da brute force ile elde edilebilir)
- **Düz metin veri**
- **Algoritma (ve bu saldırıya karşı savunmasız)**
- **Padding biliniyor**
- Genellikle varsayılan bir padding kullanılır, bu nedenle diğer 3 gereklilik karşılandığında, bu da geçerlidir
- Padding, gizli+veri uzunluğuna bağlı olarak değişir, bu yüzden gizlinin uzunluğu gereklidir

O zaman, bir **saldırgan** **veri** ekleyip **önceki veri + eklenen veri** için geçerli bir **imza** **üretebilir**.

### Nasıl?

Temelde, savunmasız algoritmalar hash'leri önce bir **veri bloğunu hash'leyerek** oluşturur ve ardından, **önceden** oluşturulmuş **hash** (durum) üzerinden **bir sonraki veri bloğunu ekleyip** **hash'ler**.

O zaman, gizli "secret" ve veri "data" ise, "secretdata"nın MD5'i 6036708eba0d11f6ef52ad44e8b74d5b.\
Eğer bir saldırgan "append" dizesini eklemek isterse, şunları yapabilir:

- 64 "A"nın MD5'ini oluştur
- Önceden başlatılmış hash'in durumunu 6036708eba0d11f6ef52ad44e8b74d5b olarak değiştir
- "append" dizesini ekle
- Hash'i tamamla ve sonuçta elde edilen hash, **"secret" + "data" + "padding" + "append"** için geçerli bir hash olacaktır

### **Araç**

{{#ref}}
https://github.com/iagox86/hash_extender
{{#endref}}

### Referanslar

Bu saldırıyı iyi bir şekilde açıklanmış olarak [https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks) adresinde bulabilirsiniz.

{{#include ../banners/hacktricks-training.md}}
