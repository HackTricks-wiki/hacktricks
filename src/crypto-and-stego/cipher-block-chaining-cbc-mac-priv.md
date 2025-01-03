{{#include ../banners/hacktricks-training.md}}

# CBC

Eğer **cookie** **sadece** **kullanıcı adı** ise (veya cookie'nin ilk kısmı kullanıcı adıysa) ve "**admin**" kullanıcı adını taklit etmek istiyorsanız. O zaman **"bdmin"** kullanıcı adını oluşturabilir ve **cookie'nin ilk baytını** **bruteforce** edebilirsiniz.

# CBC-MAC

**Şifre blok zincirleme mesaj doğrulama kodu** (**CBC-MAC**) kriptografide kullanılan bir yöntemdir. Bu yöntem, bir mesajı alıp blok blok şifreleyerek çalışır; her bloğun şifrelemesi, bir önceki bloğa bağlıdır. Bu süreç, **blokların bir zincirini** oluşturur ve orijinal mesajın tek bir bitini değiştirmek bile, şifrelenmiş verinin son bloğunda öngörülemeyen bir değişikliğe yol açar. Böyle bir değişikliği yapmak veya geri almak için şifreleme anahtarı gereklidir, bu da güvenliği sağlar.

Mesaj m'nin CBC-MAC'ını hesaplamak için, m'yi sıfır başlangıç vektörü ile CBC modunda şifreler ve son bloğu saklarsınız. Aşağıdaki şekil, bir bloktan oluşan bir mesajın CBC-MAC'ının hesaplanmasını tasvir etmektedir![https://wikimedia.org/api/rest_v1/media/math/render/svg/bbafe7330a5e40a04f01cc776c9d94fe914b17f5](https://wikimedia.org/api/rest_v1/media/math/render/svg/bbafe7330a5e40a04f01cc776c9d94fe914b17f5) gizli anahtar k ve bir blok şifre E kullanarak:

![https://upload.wikimedia.org/wikipedia/commons/thumb/b/bf/CBC-MAC_structure_(en).svg/570px-CBC-MAC_structure_(en).svg.png](<https://upload.wikimedia.org/wikipedia/commons/thumb/b/bf/CBC-MAC_structure_(en).svg/570px-CBC-MAC_structure_(en).svg.png>)

# Güvenlik Açığı

CBC-MAC ile genellikle **kullanılan IV 0'dır**.\
Bu bir sorun çünkü 2 bilinen mesaj (`m1` ve `m2`) bağımsız olarak 2 imza (`s1` ve `s2`) üretecektir. Yani:

- `E(m1 XOR 0) = s1`
- `E(m2 XOR 0) = s2`

Sonra m1 ve m2'nin birleştirilmesiyle oluşan bir mesaj (m3) 2 imza (s31 ve s32) üretecektir:

- `E(m1 XOR 0) = s31 = s1`
- `E(m2 XOR s1) = s32`

**Bu, şifreleme anahtarını bilmeden hesaplanabilir.**

**Administrator** ismini **8bayt** bloklar halinde şifrelediğinizi hayal edin:

- `Administ`
- `rator\00\00\00`

**Administ** (m1) adında bir kullanıcı adı oluşturabilir ve imzayı (s1) alabilirsiniz.\
Sonra, `rator\00\00\00 XOR s1` sonucunu kullanarak bir kullanıcı adı oluşturabilirsiniz. Bu, `E(m2 XOR s1 XOR 0)` üretecektir ki bu da s32'dir.\
Artık s32'yi **Administrator** tam adı için imza olarak kullanabilirsiniz.

### Özet

1. **Administ** (m1) kullanıcı adının imzasını alın, bu s1'dir.
2. **rator\x00\x00\x00 XOR s1 XOR 0** kullanıcı adının imzasını alın, bu s32'dir.
3. Cookie'yi s32 olarak ayarlayın ve bu, **Administrator** kullanıcısı için geçerli bir cookie olacaktır.

# IV'yi Kontrol Etme Saldırısı

Kullanılan IV'yi kontrol edebiliyorsanız, saldırı çok kolay olabilir.\
Eğer cookie sadece şifrelenmiş kullanıcı adıysa, "**administrator**" kullanıcısını taklit etmek için "**Administrator**" kullanıcısını oluşturabilir ve onun cookie'sini alabilirsiniz.\
Şimdi, IV'yi kontrol edebiliyorsanız, IV'nin ilk baytını değiştirebilir ve **IV\[0] XOR "A" == IV'\[0] XOR "a"** yaparak **Administrator** kullanıcısı için cookie'yi yeniden üretebilirsiniz. Bu cookie, başlangıç **IV** ile **administrator** kullanıcısını **taklit etmek** için geçerli olacaktır.

## Referanslar

Daha fazla bilgi için [https://en.wikipedia.org/wiki/CBC-MAC](https://en.wikipedia.org/wiki/CBC-MAC)

{{#include ../banners/hacktricks-training.md}}
