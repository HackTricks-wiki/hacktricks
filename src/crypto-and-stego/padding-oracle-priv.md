# Padding Oracle

{{#include ../banners/hacktricks-training.md}}

## CBC - Cipher Block Chaining

CBC modunda **önceki şifrelenmiş blok IV olarak kullanılır** ve bir sonraki blokla XOR yapılır:

![https://defuse.ca/images/cbc_encryption.png](https://defuse.ca/images/cbc_encryption.png)

CBC'yi deşifrelemek için **ters** **işlemler** yapılır:

![https://defuse.ca/images/cbc_decryption.png](https://defuse.ca/images/cbc_decryption.png)

Bir **şifreleme** **anahtarı** ve bir **IV** kullanmanın gerekli olduğunu unutmayın.

## Mesaj Doldurma

Şifreleme **sabit** **boyut** **blokları** içinde gerçekleştirildiğinden, **son** **blokta** uzunluğunu tamamlamak için genellikle **doldurma** gereklidir.\
Genellikle **PKCS7** kullanılır, bu da bloğu tamamlamak için **gerekli** **bayt** **sayısını** **tekrarlayarak** bir doldurma oluşturur. Örneğin, son blokta 3 bayt eksikse, doldurma `\x03\x03\x03` olacaktır.

**8 bayt uzunluğunda 2 blok** ile daha fazla örneğe bakalım:

| byte #0 | byte #1 | byte #2 | byte #3 | byte #4 | byte #5 | byte #6 | byte #7 | byte #0  | byte #1  | byte #2  | byte #3  | byte #4  | byte #5  | byte #6  | byte #7  |
| ------- | ------- | ------- | ------- | ------- | ------- | ------- | ------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | 6        | **0x02** | **0x02** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | **0x03** | **0x03** | **0x03** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | **0x05** | **0x05** | **0x05** | **0x05** | **0x05** |
| P       | A       | S       | S       | W       | O       | R       | D       | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** |

Son örnekte **son bloğun dolu olduğunu ve sadece doldurma ile yeni bir bloğun oluşturulduğunu** unutmayın.

## Padding Oracle

Bir uygulama şifrelenmiş verileri deşifre ettiğinde, önce verileri deşifre eder; ardından doldurmayı kaldırır. Doldurmanın temizlenmesi sırasında, eğer **geçersiz bir doldurma tespit edilebilir bir davranış tetiklerse**, bir **padding oracle zafiyeti** vardır. Tespit edilebilir davranış bir **hata**, **sonuç eksikliği** veya **daha yavaş bir yanıt** olabilir.

Bu davranışı tespit ederseniz, **şifrelenmiş verileri deşifre edebilir** ve hatta **herhangi bir açık metni şifreleyebilirsiniz**.

### Nasıl istismar edilir

Bu tür bir zafiyeti istismar etmek için [https://github.com/AonCyberLabs/PadBuster](https://github.com/AonCyberLabs/PadBuster) kullanabilir veya sadece yapabilirsiniz.
```
sudo apt-get install padbuster
```
Bir sitenin çerezinin savunmasız olup olmadığını test etmek için şunları deneyebilirsiniz:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
**Encoding 0** demek **base64** kullanıldığı anlamına gelir (ancak diğerleri de mevcuttur, yardım menüsüne bakın).

Bu zafiyeti **yeni verileri şifrelemek için de kötüye kullanabilirsiniz. Örneğin, çerezin içeriği "**_**user=MyUsername**_**" ise, bunu "\_user=administrator\_" olarak değiştirebilir ve uygulama içinde yetkileri artırabilirsiniz. Bunu `paduster` kullanarak -plaintext** parametresini belirterek de yapabilirsiniz:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA==" -plaintext "user=administrator"
```
Eğer site savunmasızsa `padbuster` otomatik olarak padding hatasının ne zaman meydana geldiğini bulmaya çalışacaktır, ancak hata mesajını **-error** parametresi ile de belirtebilirsiniz.
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "" 8 -encoding 0 -cookies "hcon=RVJDQrwUdTRWJUVUeBKkEA==" -error "Invalid padding"
```
### Teori

**Özetle**, tüm **farklı padding'leri** oluşturmak için kullanılabilecek doğru değerleri tahmin ederek şifrelenmiş verileri çözmeye başlayabilirsiniz. Ardından, padding oracle saldırısı, 1, 2, 3, vb. **padding'leri oluşturan** doğru değerin ne olacağını tahmin ederek son byte'dan başlayarak byte'ları çözmeye başlayacaktır.

![](<../images/image (561).png>)

Şimdi, **E0'dan E15'e** kadar olan byte'lardan oluşan **2 blok** kaplayan bazı şifrelenmiş metinleriniz olduğunu hayal edin.\
**Son** **bloğu** (**E8**'den **E15**'e) **şifrelemek** için, tüm blok "blok şifre çözme" işleminden geçerek **I0'dan I15'e** kadar olan **ara byte'ları** üretir.\
Son olarak, her ara byte, önceki şifrelenmiş byte'larla (E0'dan E7'ye) **XOR'lanır**. Yani:

- `C15 = D(E15) ^ E7 = I15 ^ E7`
- `C14 = I14 ^ E6`
- `C13 = I13 ^ E5`
- `C12 = I12 ^ E4`
- ...

Artık **`E7`'yi `C15`'in `0x01`** olana kadar **değiştirmek** mümkündür, bu da doğru bir padding olacaktır. Yani, bu durumda: `\x01 = I15 ^ E'7`

E'7'yi bulduğumuzda, **I15'i hesaplamak** mümkündür: `I15 = 0x01 ^ E'7`

Bu da **C15'i hesaplamamıza** olanak tanır: `C15 = E7 ^ I15 = E7 ^ \x01 ^ E'7`

**C15**'i bildiğimizde, şimdi **C14'ü hesaplamak** mümkündür, ancak bu sefer padding'i `\x02\x02` ile brute-force yaparak.

Bu BF, `E''15` değerinin 0x02 olduğu hesaplanabildiği için önceki kadar karmaşıktır: `E''7 = \x02 ^ I15`, bu nedenle sadece **`E'14`**'ü bulmak gerekir ki bu da **`C14`'ün `0x02`** eşit olmasını sağlar.\
Ardından, C14'ü çözmek için aynı adımları izleyin: **`C14 = E6 ^ I14 = E6 ^ \x02 ^ E''6`**

**Tüm şifrelenmiş metni çözene kadar bu zinciri takip edin.**

### Açığın Tespiti

Bir hesap kaydedin ve bu hesapla giriş yapın.\
Eğer **birçok kez giriş yaparsanız** ve her seferinde **aynı çerezi** alıyorsanız, uygulamada muhtemelen **bir sorun** vardır. **Geri gönderilen çerez her seferinde benzersiz olmalıdır.** Eğer çerez **her zaman** **aynıysa**, muhtemelen her zaman geçerli olacaktır ve onu **geçersiz kılmanın** bir yolu olmayacaktır.

Artık çerezi **değiştirmeye** çalıştığınızda, uygulamadan bir **hata** aldığınızı görebilirsiniz.\
Ancak padding'i BF yaparsanız (örneğin padbuster kullanarak) farklı bir kullanıcı için geçerli başka bir çerez elde etmeyi başarırsınız. Bu senaryo, padbuster'a karşı yüksek ihtimalle savunmasızdır.

### Referanslar

- [https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation)


{{#include ../banners/hacktricks-training.md}}
