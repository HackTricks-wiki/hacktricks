{{#include ../../banners/hacktricks-training.md}}

# Paketlenmiş ikililerin tanımlanması

- **string eksikliği**: Paketlenmiş ikililerde neredeyse hiç string bulunmaması yaygındır.
- Birçok **kullanılmayan string**: Ayrıca, bir kötü amaçlı yazılım bazı ticari paketleyiciler kullanıyorsa, genellikle çapraz referanssız birçok string bulmak mümkündür. Bu stringler mevcut olsa bile, bu durum ikilinin paketlenmediği anlamına gelmez.
- Bir ikilinin hangi paketleyici ile paketlendiğini bulmak için bazı araçlar kullanabilirsiniz:
- [PEiD](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/PEiD-updated.shtml)
- [Exeinfo PE](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/ExEinfo-PE.shtml)
- [Language 2000](http://farrokhi.net/language/)

# Temel Öneriler

- Paketlenmiş ikiliyi **IDA'da alttan başlayarak analiz etmeye** **başlayın** ve yukarı doğru ilerleyin. Paket açıcılar, açılmış kod çıkınca çıkış yapar, bu nedenle paket açıcının açılmış koda başlangıçta yürütme geçirmesi olası değildir.
- **Kayıtlar** veya **bellek** **bölgelerine** **JMP** veya **CALL** arayın. Ayrıca, **argümanlar ve bir adres yönlendirmesi iten fonksiyonlar arayın ve ardından `retn` çağırın**, çünkü bu durumda fonksiyonun dönüşü, yığına itilen adresi çağırabilir.
- `VirtualAlloc` üzerinde bir **kesme noktası** koyun, çünkü bu, programın açılmış kod yazabileceği bellek alanı ayırır. "Kullanıcı koduna koş" veya F8 kullanarak **fonksiyonu çalıştırdıktan sonra EAX içindeki değere ulaşın** ve "**dump'taki o adresi takip edin**". Açılmış kodun kaydedileceği bölge olup olmadığını asla bilemezsiniz.
- **`VirtualAlloc`** ile "**40**" değeri argüman olarak, Okuma+Yazma+Çalıştırma anlamına gelir (buraya kopyalanacak bir kod var).
- **Kod açma** sırasında **birçok çağrı** ile **aritmetik işlemler** ve **`memcopy`** veya **`Virtual`**`Alloc` gibi fonksiyonlar bulmak normaldir. Eğer yalnızca aritmetik işlemler gerçekleştiren ve belki de bazı `memcopy` yapan bir fonksiyonda iseniz, **fonksiyonun sonunu bulmaya çalışmanız** (belki bir JMP veya bazı kayıtlar için bir çağrı) **veya** en azından **son fonksiyona yapılan çağrıyı bulup oraya koşmanız** önerilir, çünkü kod ilginç değildir.
- Kod açma sırasında **bellek bölgesini değiştirdiğinizde** not alın, çünkü bir bellek bölgesi değişikliği **açma kodunun başlangıcını** gösterebilir. Process Hacker kullanarak bir bellek bölgesini kolayca dökebilirsiniz (işlem --> özellikler --> bellek).
- Kod açmaya çalışırken, **açılmış kodla çalışıp çalışmadığınızı bilmenin** iyi bir yolu, **ikilinin stringlerini kontrol etmektir**. Eğer bir noktada bir atlama yaparsanız (belki bellek bölgesini değiştirerek) ve **çok daha fazla string eklendiğini** fark ederseniz, o zaman **açılmış kodla çalıştığınızı** bilebilirsiniz.\
Ancak, eğer paketleyici zaten birçok string içeriyorsa, "http" kelimesini içeren string sayısını görebilir ve bu sayının artıp artmadığını kontrol edebilirsiniz.
- Bir bellek bölgesinden bir yürütülebilir dosyayı döktüğünüzde, bazı başlıkları [PE-bear](https://github.com/hasherezade/pe-bear-releases/releases) kullanarak düzeltebilirsiniz.

{{#include ../../banners/hacktricks-training.md}}
