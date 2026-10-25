# Hash'ler, MAC'ler ve KDF'ler

{{#include ../../banners/hacktricks-training.md}}

## Yaygın CTF kalıpları

- "İmza" aslında `hash(secret || message)` → length extension.
- Salt kullanılmayan parola hash'leri → daha hızlı tekrarlı cracking ve önceden hesaplanmış lookup saldırıları.
- Hash ile MAC'i karıştırmak (hash != kimlik doğrulama).

## Seçilmiş girdilerle MD5 hash aramaları

Bu Python örnekleri iki farklı çıktı kalıbını arar: seçilen bir MD5 son eki ve yalnızca rakamlardan oluşan `0e` ile başlayan bir MD5 değeri. İkinci kalıp, bir uygulama sayısal dizeleri gevşek biçimde karşılaştırdığında önem kazanır; PHP'ye özgü davranış ve sürüm uyarıları için bkz. [PHP gevşek karşılaştırmaları](../../network-services-pentesting/pentesting-web/php-tricks-esp/README.md#loose-comparisons-and-type-juggling).

### MD5 hash son eki için brute force

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

## Hash length extension attack

### Teknik

Bir sunucu şu şekilde bir "imza" hesaplıyorsa:

`sig = HASH(secret || message)`

ve MD5, SHA-1 veya SHA-256 gibi Merkle-Damgård hash'leri kullanıyorsa, length-extension attack mümkün olabilir.

Şunları biliyorsanız:

- `message`
- `sig`
- hash fonksiyonu
- (veya brute-force uygulayarak) `len(secret)`

Gizli değeri bilmeden şu veri için geçerli bir imza hesaplayabilirsiniz:

`message || padding || appended_data`

<sup>[[1]](#references)</sup>

### Önemli sınırlama: HMAC etkilenmez

Length-extension attack'ler, `HASH(secret || message)` gibi savunmasız prefix yapıları için geçerlidir. HMAC yapısını (örneğin HMAC-SHA256) açığa çıkarmazlar; HMAC, bir anahtarı ayrı iç ve dış hash uygulamalarıyla birleştirir.<sup>[[1]](#references)[[2]](#references)</sup>

Web API'lerinde bu imzaları nasıl bulacağınız ve test edeceğiniz hakkında bilgi için [Request and parameter signatures](../../pentesting-web/web-api-pentesting.md#request-and-parameter-signatures) sayfasına bakın.

### Araçlar

- [`hash_extender`](https://github.com/iagox86/hash_extender)<sup>[[3]](#references)</sup>
- [`hashpumpy`](https://pypi.org/project/hashpumpy/), HashPump length-extension aracı için Python bindings<sup>[[7]](#references)</sup>

### İyi bir açıklama

[Hash length extension attack'ler hakkında bilmeniz gereken her şey](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)<sup>[[1]](#references)</sup>

## Belirsiz tuple hashing ve MAC'ler

### Boundary-confusion attack

Artımlı hash API'leri çağrı sınırlarını doğrulamaz. `update(A); update(B)`, `update(A + B)` ile aynı bayt dizisinin hash'ini hesaplar. Bu nedenle, ham birleştirme işlemini hash'lemek veya MAC'lemek bir tuple'ı doğrulamaz. Bitişik alanların uzunlukları değişkense, saldırgan temel hash'te collision bulmadan baytları farklı bir tuple oluşturacak şekilde yeniden bölümlendirebilir:<sup>[[8]](#references)[[9]](#references)</sup>

```python
import hashlib

def raw_hash(parts):
    h = hashlib.sha256()
    for part in parts:
        h.update(part)
    return h.digest()

assert raw_hash([b"alice", b"admin"]) == raw_hash([b"aliceadmin", b""])
```

Bu durum, doğrulayıcı digest'in alanların anlamlarını bağladığına inanırken saldırganın kontrolündeki girdinin farklı sınırlar belirleyen başka bir parser'a veya protokol adımına ulaşabilmesiyle istismar edilebilir. Commitment'lar alternatif açılımlar kazanabilir ve Fiat-Shamir transcript'leri farklı ifadeler olarak yorumlanabilir. HMAC, [hash length extension](#hash-length-extension-attack) saldırısını önler; ancak `HMAC(K, A || B)` de aynı mesaj baytlarını üreten iki tuple nedeniyle bu tuple kodlama belirsizliğine açıktır.<sup>[[8]](#references)[[9]](#references)</sup>

Belirsiz tuple kodlamasının bir güvenlik sınırını aşıp aşmadığını test etmek için bu denetim iş akışını kullanın.<sup>[[8]](#references)[[9]](#references)</sup>

1. `HASH(A || B)`, `HMAC(K, A || B)` kullanımlarını ve iki veya daha fazla alan üzerinde art arda yapılan `update()`/`Write()` çağrılarını bulun.
2. Saldırganın kontrolündeki veya değişken uzunluklu tüm alanları işaretleyin. Birleştirilmiş toplam bayt dizisini aynı tutarken her sınırın ötesine bayt taşımayı deneyin. Boş alanları da dahil edin.
3. Ayraç şemalarında girdilerin içerebileceği ayraç baytlarını, kaçışlama konusundaki uyuşmazlıkları ve uzunluk kodlamasının yalnızca bazı alanlara uygulandığı tasarımları kontrol edin.
4. Kimliği doğrulanmış baytları her tüketicinin nasıl ayrıştırdığını izleyin. Alternatif bir bölümleme ancak güvenlik kararını, ispat ifadesini, kaydı, işlemi veya commitment açılımını değiştiriyorsa anlamlıdır. Sabit genişlikli alanlar ya da kanonik ve birebir bir serileştirme bu özel saldırıyı önler.
5. Aynı kodlanmış digest'in başka bir protokol sürümünde, mesaj türünde, turda veya uygulamada kabul edilip edilmediğini kontrol edin. Çağıranların bunları ayrı tutmasına güvenmek yerine bu bağlamları açıkça bağlayın.

### SequenceHash ve SequenceMAC

SequenceHash, bayt dizilerinden oluşan diziler için hash algoritmasından bağımsız bir yapıdır. Her `add()` işlemi atomiktir: değeri ve sabit uzunluklu, little-endian biçiminde 16 baytlık bir uzunluk son ekini iç hash'e ekler. Boş değerler ayrı nesneler olarak kalır. Dış hash, uzunluk genişletmesine açık bir iç durumun açığa çıkmasını önler; isteğe bağlı bir özelleştirme dizesi ise domain separation sağlar. `add()` yerine temel hash API'sinin sıradan yazma işlemlerini kullanmayın.<sup>[[8]](#references)[[9]](#references)</sup>

```python
import sequencehash

h = sequencehash.SequenceHash.new("sha256")
h.add(b"alice")
h.add(b"admin")
digest = h.result_with_customizer(b"example:v1:user-record")
```

Customizer'ı protokol tanımının bir parçası olarak seçin; uygulamayı, protokol sürümünü, ileti türünü ve turu ayırt etmeye yetecek bilgileri dahil edin. SequenceHash yine de tüm tarafların alan sırası, bayt kodlaması ve kanonik serileştirme konusunda anlaşmasını gerektirir ve atlanmış bir alanı koruyamaz. Portlar, C2SP ara ve nihai test vektörlerine göre denetlenmelidir.<sup>[[8]](#references)[[11]](#references)</sup>

Kimlik doğrulama için SequenceMAC aynı atomik kodlama ve özelleştirme arayüzünü sunar. En az 32 baytlık bir anahtar gerektirir. HMAC anahtar ön işlemesinden farklı olarak başlıkları, anahtarın tam uzunluğunu taahhüt eder: uzun bir ham anahtar, önceden hash'lenmiş hâline eşdeğer değildir ve sıfır bayt eklemek anahtarı değiştirir. Bu ayrım, bileşenler farklı anahtar gösterimlerini veya uzunluk meta verilerini kabul ettiğinde önem taşır.<sup>[[8]](#references)[[9]](#references)</sup>

```python
key = b"\x00" * 32
mac = sequencehash.SequenceMAC.new(key, digestmod="sha256")
mac.add(header_bytes)
mac.add(body_bytes)
tag = mac.result_with_customizer(b"example:v1:request-mac")
```

Python API'si ve eşdeğer Go ve Rust uygulamaları referans olarak mevcuttur; ancak protokol uygulamaları, bu özetteki kodlamayı yeniden oluşturmaya çalışmak yerine güncel C2SP spesifikasyonunu izlemelidir.<sup>[[8]](#references)[[10]](#references)</sup>

## Parola hash'leme ve kırma

### İlk sorular<sup>[[4]](#references)</sup>

- **Salt'lı mı**? (`salt$hash` formatlarına bakın)
- **Hızlı bir hash** (MD5/SHA1/SHA256) mi, yoksa **yavaş bir KDF** (bcrypt/scrypt/argon2/PBKDF2) mi?
- Elinizde bir **format ipucu** var mı (hashcat mode / John format)?

### Pratik iş akışı<sup>[[5]](#references)[[6]](#references)</sup>

1. Hash'i belirleyin:
   - `hashid <hash>`
   - `hashcat --example-hashes | rg -n "<pattern>"`
2. Salt'sız ve yaygın bir hash ise çevrimiçi DB'leri ve crypto iş akışı bölümündeki tanımlama araçlarını deneyin.
3. Aksi hâlde kırmayı deneyin:
   - `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
   - `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### İstismar edebileceğiniz yaygın hatalar

- Aynı parolanın farklı kullanıcılar tarafından yeniden kullanılması → birini kırın, pivot yapın.
- Kesilmiş hash'ler / özel dönüşümler → normalleştirip tekrar deneyin.
- Zayıf KDF parametreleri (ör. düşük PBKDF2 yineleme sayısı) → yine de kırılabilir.

### Sonuna eklenen bir secret içeren seçilmiş girdili bcrypt oracle'ı

`bcrypt(user_input || secret)` döndüren çağrılabilir bir yardımcı, bcrypt uygulaması girdiyi 72 **byte** sonrasında sessizce kesiyorsa eklenmiş secret hakkında bilgi açığa çıkarabilir. UTF-8 kodlamasından önce uygulanan karakter sayısı sınırı, bu byte sınırını garanti etmez: çok baytlı karakterler bcrypt girdisini doldururken secret'ın yalnızca küçük bir öneki için yer bırakabilir. Seçilmiş girdiler ve döndürülen hash'ler, olası son ek byte'ları için çevrimdışı kontroller yapılmasına olanak sağlayabilir. Bunun için yardımcının girdisini kontrol edebilmek, tam dönüşümünü ve kodlamasını bilmek ve uygulamanın gerçekten kesme yapması gerekir; çağrılabilir bir yardımcı ya da tek başına bir bcrypt hash'i, bu zincirin varlığını kanıtlamaz. [pyca/bcrypt belgelerine göre](https://github.com/pyca/bcrypt#maximum-password-length), güncel `hashpw`, 72 byte'tan uzun girdilerde hata verirken önceki davranış girdiyi sessizce kesiyordu. Diğer sarmalayıcılar girdiyi önceden hash'leyebilir veya uzun girdileri reddedebilir; bu nedenle kesme olduğunu varsaymak yerine kurulu uygulamayı doğrulayın.

Ele geçirilen bir secret'ı başka bir hesapta kullanabilmek için, açığa çıkan hash'in **aynı** secret ve dönüşümle oluşturulduğuna dair kanıtın yanı sıra ayrı bir kimlik bilgisi veya oturum açma yolu da gerekir. Root yetkisiyle çalışan bir hash yardımcısı, yalnızca düşük yetkili kullanıcı onu etkin politika kapsamında çağırabiliyorsa oracle olarak incelenmelidir; pasif sunucu keşfi, bu yardımcının çağrılmasını veya seçilmiş parolaların gönderilmesini gerektirmez.

## References

- [1] [SkullSecurity - Hash length-extension saldırıları hakkında bilmeniz gereken her şey](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
- [2] [NIST FIPS 198-1 - Anahtarlı Hash Mesaj Kimlik Doğrulama Kodu](https://csrc.nist.gov/pubs/fips/198-1/final)
- [3] [hash_extender](https://github.com/iagox86/hash_extender)
- [4] [OWASP Parola Saklama Hile Sayfası](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [5] [Hashcat örnek hash'leri](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [6] [John the Ripper komut satırı seçenekleri](https://www.openwall.com/john/doc/OPTIONS.shtml)
- [7] [PyPI: HashPump için `hashpumpy` Python bağlamaları](https://pypi.org/project/hashpumpy/)
- [8] [C2SP - SequenceHash ve SequenceMAC spesifikasyonu](https://c2sp.org/sequencehash)
- [9] [Trail of Bits - SequenceHash: herkes için çoklu hashing](https://blog.trailofbits.com/2026/10/02/sequencehash-multihashing-for-the-rest-of-us/)
- [10] [Trail of Bits - SequenceHash Python uygulaması](https://github.com/trailofbits/sequencehash-py)
- [11] [C2SP CCTV - SequenceHash test vektörleri](https://github.com/C2SP/CCTV/tree/main/sequencehash)
