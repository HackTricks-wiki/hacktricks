# Hash'ler, MAC'ler ve KDF'ler

{{#include ../../banners/hacktricks-training.md}}

## Yaygın CTF kalıpları

- "İmza" aslında `hash(secret || message)` → length extension.
- Salt eklenmemiş password hash'leri → daha hızlı tekrarlı cracking ve önceden hesaplanmış lookup saldırıları.
- Hash'i MAC ile karıştırmak (hash != authentication).

## Seçilen girdilerle MD5 hash aramaları

Bu Python örnekleri iki farklı çıktı kalıbını arar: seçilen bir MD5 suffix'i ve yalnızca rakamlardan oluşan, `0e` ile başlayan bir MD5 değeri. İkinci kalıp, bir uygulama sayısal dizeleri gevşek biçimde karşılaştırdığında önem kazanır; PHP'ye özgü davranışlar ve sürüm uyarıları için bkz. [PHP gevşek karşılaştırmaları](../../network-services-pentesting/pentesting-web/php-tricks-esp/README.md#loose-comparisons-and-type-juggling).

### MD5 hash suffix brute force

```python
import hashlib

target = '2f2e2e' #/..
candidate = 0
while True:
    plaintext = str(candidate)
    hash = hashlib.md5(plaintext.encode('ascii')).hexdigest()
    if hash[-1*(len(target)):] == target: #End in target
        print('plaintext:"' + plaintext + '", md5:' + hash)
        break
    candidate = candidate + 1
```

### Gevşek karşılaştırmalar için MD5 0e hash üretimi

```python
#From isHaacK
import hashlib
from multiprocessing import Process, Queue, cpu_count


def loose_comparison(queue, num):
	target = '0e'
	plaintext = f"a_prefix{str(num)}a_suffix"
	hash = hashlib.md5(plaintext.encode('ascii')).hexdigest()

	if hash[:len(target)] == target and not any(x in "abcdef" for x in hash[2:]):
		print('plaintext: ' + plaintext + ', md5: ' + hash)
		queue.put("done") # triggers program exit

def worker(queue, thread_i, threads):
	for num in range(thread_i, 100**50, threads):
		loose_comparison(queue, num)

def main():
	procs = []
	queue = Queue()
	threads = cpu_count() # 2

	for thread_i in range(threads):
		proc = Process(target=worker, args=(queue, thread_i, threads ))
		proc.daemon = True # kill all subprocess when main process exits.
		procs.append(proc)
		proc.start()

	while queue.empty(): # exits when a subprocess is done
		pass
	return 0

main()
```

## Hash length extension saldırısı

### Teknik

Bir sunucu aşağıdaki gibi bir "imza" hesaplıyorsa:

`sig = HASH(secret || message)`

ve MD5, SHA-1 veya SHA-256 gibi bir Merkle-Damgård hash kullanıyorsa length-extension saldırısı mümkün olabilir.

Şunları biliyorsanız:

- `message`
- `sig`
- hash function
- (`len(secret)` değerini brute-force edebiliyorsanız da)

secret değerini bilmeden şu içerik için geçerli bir imza hesaplayabilirsiniz:

`message || padding || appended_data`<sup>[[1]](#references)</sup>

### Önemli sınırlama: HMAC etkilenmez

Length-extension saldırıları, `HASH(secret || message)` gibi savunmasız prefix yapılarına uygulanır. Anahtarı ayrı inner ve outer hash uygulamalarıyla birleştiren HMAC yapısını (örneğin, HMAC-SHA256) açığa çıkarmazlar.<sup>[[1]](#references)[[2]](#references)</sup>

### Araçlar

- [`hash_extender`](https://github.com/iagox86/hash_extender)<sup>[[3]](#references)</sup>
- [`hashpumpy`](https://pypi.org/project/hashpumpy/), HashPump length-extension aracı için Python bindings<sup>[[7]](#references)</sup>

### İyi bir açıklama

[Hash length extension saldırıları hakkında bilmeniz gereken her şey](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)<sup>[[1]](#references)</sup>

## Belirsiz tuple hashing ve MAC'ler

### Sınır karışıklığı saldırısı

Incremental hash API'leri çağrı sınırlarını doğrulamaz. `update(A); update(B)` ile, `update(A + B)` aynı byte string'i hash'ler. Bu nedenle, ham birleştirmeyi hash'lemek veya MAC'lemek bir tuple'ı doğrulamaz. Bitişik alanların uzunlukları değişkense, saldırgan temel hash'te collision bulmadan byte'ları farklı bir tuple oluşturacak şekilde yeniden bölebilir:<sup>[[8]](#references)[[9]](#references)</sup>

```python
import hashlib

def raw_hash(parts):
    h = hashlib.sha256()
    for part in parts:
        h.update(part)
    return h.digest()

assert raw_hash([b"alice", b"admin"]) == raw_hash([b"aliceadmin", b""])
```

Bu durum, doğrulayıcı digest'in alanların anlamlarını bağladığına inanırken saldırganın denetimindeki girdinin farklı sınırlar atayan başka bir ayrıştırıcıya veya protokol adımına ulaşabilmesiyle istismar edilebilir. Commitments alternatif açılımlar kazanabilir ve Fiat-Shamir transcript'leri farklı ifadeler olarak yorumlanabilir. HMAC, [hash length extension](#hash-length-extension-attack) saldırısını önler; ancak `HMAC(K, A || B)` yine de bu tuple kodlama belirsizliğine sahiptir, çünkü her iki tuple da aynı mesaj baytlarını üretir.<sup>[[8]](#references)[[9]](#references)</sup>

Belirsiz bir tuple kodlamasının güvenlik sınırını aşıp aşmadığını test etmek için bu denetim iş akışını kullanın.<sup>[[8]](#references)[[9]](#references)</sup>

1. `HASH(A || B)`, `HMAC(K, A || B)` ve iki veya daha fazla alan üzerinde art arda yapılan `update()`/`Write()` çağrılarını bulun.
2. Saldırgan denetimindeki veya değişken uzunluktaki tüm alanları işaretleyin. Birleştirilmiş toplam bayt dizisini aynı tutarken her sınırın ötesine bayt taşımayı deneyin. Boş alanları da dahil edin.
3. Ayraç şemalarında girdilerin içerebileceği ayraç baytlarını, kaçışlama konusundaki uyuşmazlıkları ve yalnızca bazı alanları uzunluk kodlayan tasarımları kontrol edin.
4. Kimliği doğrulanmış baytları her tüketicinin nasıl ayrıştırdığını izleyin. Alternatif bir bölümleme ancak bir güvenlik kararını, kanıt ifadesini, kaydı, işlemi veya commitment açılımını değiştiriyorsa anlamlıdır. Sabit genişlikli alanlar veya kanonik, bire bir bir serileştirme bu özel saldırıyı önler.
5. Aynı kodlanmış digest'in başka bir protokol sürümünde, mesaj türünde, turda veya uygulamada kabul edilip edilmediğini kontrol edin. Çağıranların bunları ayrı tutmasına güvenmek yerine bu bağlamları açıkça bağlayın.

### SequenceHash ve SequenceMAC

SequenceHash, bayt dizilerinden oluşan diziler için hash algoritmasından bağımsız bir yapıdır. Her `add()` işlemi atomiktir: değeri ve sabit uzunluktaki 16 baytlık little-endian uzunluk son ekini iç hash'e ekler. Boş değerler ayrı nesneler olarak kalır. Dış hash, uzunluk genişletilebilir bir iç durumun açığa çıkmasını önler; isteğe bağlı bir özelleştirme dizgesi ise domain separation sağlar. `add()` işlemini, temel hash API'sinin sıradan yazma çağrılarıyla değiştirmeyin.<sup>[[8]](#references)[[9]](#references)</sup>

```python
import sequencehash

h = sequencehash.SequenceHash.new("sha256")
h.add(b"alice")
h.add(b"admin")
digest = h.result_with_customizer(b"example:v1:user-record")
```

Customizer'ı protokol tanımının parçası olarak seçin ve uygulamayı, protokol sürümünü, ileti türünü ve turu ayırt etmeye yetecek bilgiyi ekleyin. SequenceHash yine de tüm tarafların alan sırası, bayt kodlaması ve kanonik serileştirme konusunda anlaşmasını gerektirir ve atlanan bir alanı koruyamaz. Uyarlamalar, C2SP ara ve nihai test vektörlerine göre denetlenmelidir.<sup>[[8]](#references)[[11]](#references)</sup>

Kimlik doğrulama için SequenceMAC aynı atomik kodlama ve özelleştirme arayüzünü sağlar. En az 32 baytlık bir anahtar gerektirir. HMAC anahtar ön işlemesinden farklı olarak, SequenceMAC başlıkları tam anahtar uzunluğunu bağlar: uzun bir ham anahtar, önceden hash'lenmiş hâliyle eşdeğer değildir ve sıfır bayt eklemek anahtarı değiştirir. Bu ayrım, bileşenler farklı anahtar gösterimlerini veya uzunluk meta verilerini kabul ettiğinde önemlidir.<sup>[[8]](#references)[[9]](#references)</sup>

```python
key = b"\x00" * 32
mac = sequencehash.SequenceMAC.new(key, digestmod="sha256")
mac.add(header_bytes)
mac.add(body_bytes)
tag = mac.result_with_customizer(b"example:v1:request-mac")
```

Python API ve eşdeğer Go ve Rust uygulamaları referans olarak mevcuttur; ancak protokol uygulamaları, bu özetteki kodlamayı yeniden oluşturmaya çalışmak yerine güncel C2SP spesifikasyonunu izlemelidir.<sup>[[8]](#references)[[10]](#references)</sup>

## Parola hashleme ve kırma

### İlk sorular<sup>[[4]](#references)</sup>

- **Salt eklenmiş mi**? (`salt$hash` biçimlerini arayın)
- **Hızlı bir hash** mi (MD5/SHA1/SHA256), yoksa **yavaş bir KDF** mi (bcrypt/scrypt/argon2/PBKDF2)?
- Bir **biçim ipucu** var mı (hashcat modu / John biçimi)?

### Uygulamalı iş akışı<sup>[[5]](#references)[[6]](#references)</sup>

1. Hash'i belirleyin:
   - `hashid <hash>`
   - `hashcat --example-hashes | rg -n "<pattern>"`
2. Salt eklenmemiş ve yaygın bir hash ise: çevrimiçi veritabanlarını ve crypto iş akışı bölümündeki tanımlama araçlarını deneyin.
3. Aksi durumda kırmayı deneyin:
   - `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
   - `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Yararlanabileceğiniz yaygın hatalar

- Aynı parolanın farklı kullanıcılarca yeniden kullanılması → birini kırıp diğerlerine pivot yapın.
- Kesilmiş hash'ler / özel dönüşümler → normalleştirip yeniden deneyin.
- Zayıf KDF parametreleri (ör. düşük PBKDF2 iterasyon sayısı) → yine de kırılabilir.

### Sona eklenmiş bir sır içeren, seçilmiş girdileri kabul eden bcrypt oracle'ı

`bcrypt(user_input || secret)` döndüren, çağrılabilir bir yardımcı; bcrypt uygulaması girdiyi 72 **bayttan** sonra sessizce kesiyorsa, sona eklenmiş sır hakkında bilgi açığa çıkarabilir. UTF-8 kodlamasından önce uygulanan karakter sayısı sınırı, bu bayt sınırını uygulamaz: çok baytlı karakterler bcrypt girdisini doldururken sırdan yalnızca küçük bir önek için yer bırakabilir. Seçilmiş girdiler ve bunlara döndürülen hash'ler, aday sonek baytlarının çevrimdışı olarak sınanmasına olanak verebilir. Bunun için yardımcının girdisi üzerinde denetim, uyguladığı dönüşümün ve kodlamanın tam olarak bilinmesi ve gerçekten kesme yapan bir uygulama gerekir; yardımcının çağrılabilir olması veya tek başına bir bcrypt hash'i bu zincirin varlığını kanıtlamaz. [pyca/bcrypt belgeleri](https://github.com/pyca/bcrypt#maximum-password-length), güncel `hashpw` işlevinin 72 baytı aşan girdilerde hata verdiğini; önceki davranışın ise girdiyi sessizce kestiğini belirtir. Diğer wrapper'lar girdileri önceden hash'leyebilir veya uzun girdileri reddedebilir; bu nedenle kesme olduğunu varsaymak yerine kurulu uygulamayı doğrulayın.

Elde edilen bir sırrı başka bir hesaba karşı kullanmak için ayrıca, açığa çıkan hash'in **aynı** sır ve dönüşümle üretildiğine dair kanıtın yanı sıra ayrı bir kimlik bilgisi veya oturum açma yolu gerekir. Root olarak çalışan bir hashleme yardımcısı, yalnızca düşük ayrıcalıklı kullanıcı etkin politika kapsamında onu çağırabiliyorsa oracle olarak incelenmelidir; pasif ana bilgisayar keşfi yardımcının çağrılmasını veya seçilmiş parolaların gönderilmesini gerektirmez.

## References

- [1] [SkullSecurity - Hash uzunluğu uzatma saldırıları hakkında bilmeniz gereken her şey](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
- [2] [NIST FIPS 198-1 - Anahtarlı Hash Mesaj Kimlik Doğrulama Kodu](https://csrc.nist.gov/pubs/fips/198-1/final)
- [3] [hash_extender](https://github.com/iagox86/hash_extender)
- [4] [OWASP Parola Depolama Hile Sayfası](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [5] [Hashcat örnek hash'leri](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [6] [John the Ripper komut satırı seçenekleri](https://www.openwall.com/john/doc/OPTIONS.shtml)
- [7] [PyPI: HashPump için `hashpumpy` Python bağlamaları](https://pypi.org/project/hashpumpy/)
- [8] [C2SP - SequenceHash ve SequenceMAC spesifikasyonu](https://c2sp.org/sequencehash)
- [9] [Trail of Bits - SequenceHash: herkes için çoklu hash](https://blog.trailofbits.com/2026/10/02/sequencehash-multihashing-for-the-rest-of-us/)
- [10] [Trail of Bits - SequenceHash Python uygulaması](https://github.com/trailofbits/sequencehash-py)
- [11] [C2SP CCTV - SequenceHash test vektörleri](https://github.com/C2SP/CCTV/tree/main/sequencehash)
