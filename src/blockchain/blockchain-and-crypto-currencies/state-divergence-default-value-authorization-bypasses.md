# State Divergence ve Default-Value Authorization Bypass'ları

{{#include ../../banners/hacktricks-training.md}}

Authorization bazen açık bir role değil, türetilmiş ekonomik duruma bağlıdır; örneğin, "caller tüm supply'ın sahibidir." Bu predicate'teki değerler farklı store'lardan geliyorsa, güncelliğini yitirmiş bir kopya meşru bir sahiplik kısayolunu authorization bypass'a dönüştürebilir. Provenance marker module, tehlikeli birleşimi gösterdi: canlı caller balance'ı, non-fixed-supply asset'ler için güncellenmeyen marker-local supply metadata'sıyla karşılaştırılıyordu.<sup>[[1]](#references)</sup>

## Authorization sınırı olarak yinelenen state'i denetleyin

Permission check'te kullanılan her değer için **tüm gösterimlerini** listeleyin: canonical module state, object alanları, cached aggregate'ler, index'ler, snapshot'lar, bridge kayıtları ve off-chain mirror'lar. Ardından her object mode'unda hangi kopyanın güncellendiğini belirlemek için tüm create, mint, burn, transfer, reset, migration ve synchronization yollarını izleyin. Bir alan bir mode için authoritative, başka bir mode için bilgilendirici olabilir.<sup>[[1]](#references)</sup>

Uygulanabilir bir inceleme iş akışı:<sup>[[1]](#references)</sup>

1. Korunan action'ları bulun ve her authorization branch'ini bir boolean predicate'e indirgeyin.
2. Her operand için store'unu, update yollarını, lifecycle state'lerini ve source of truth'unu kaydedin.
3. Yalnızca bir gösterimi güncelleyen geçişler oluşturun ve ardından tüm kopyaları karşılaştırın.
4. Her geçişten sonra korunan action'ı yeni bir account'tan gerçekleştirmeyi deneyin.
5. Bypass'ın ötesine geçin: action bir ACL'yi düzenliyorsa, kendinize kalıcı role'ler verin ve normal privileged API'leri çağırın.

Şüpheli örüntüler arasında `cachedSupply == balance`, `metadataOwner == caller` veya `snapshotShares == currentShares` bulunur; özellikle de iki tarafın synchronization kuralları farklıysa. Bir operand için authoritative bir değer sorgulamak, diğer operand güncelliğini yitirmişken karşılaştırmayı güvenli hâle getirmez.<sup>[[1]](#references)</sup>

## Default-value equality bypass

Her iki operand da birbirinden bağımsız olarak aynı default value'yu alabiliyorsa equality predicate'i de güvenli değildir. Aşağıdaki check, `supply` sıfır olduğunda, sıfırın güncelliğini yitirmiş metadata'dan mı yoksa meşru olarak fonlanmamış bir object'ten mi kaynaklandığına bakmaksızın, boş olan herhangi bir account'a "full supply control" verir.<sup>[[1]](#references)[[3]](#references)</sup>

```go
balance := bank.GetBalance(ctx, caller, denom)
supply := marker.GetSupply() // duplicate or stale representation
return balance.Amount.Equal(supply.Amount) // 0 == 0 -> true
```

Kanonik store'a geçmek divergence'ı düzeltir ancak **boş nesne sorununu** çözmez. Güvenlik özelliği bağımsız bir geçerlilik koşulu içermelidir; Provenance patch, canlı banka arzını kullanır ve çağıranın bakiyesini karşılaştırmadan önce nil veya sıfır arzı reddeder.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

```go
supply := bank.GetSupply(ctx, denom)
if supply.Amount.IsNil() || supply.Amount.IsZero() {
    return false
}
balance := bank.GetBalance(ctx, caller, denom)
return supply.Equal(NewCoin(denom, balance.Amount))
```

Quorum sayıları, sahiplik yüzdeleri, borç, teminat, epoch'lar, nonce'lar, zaman damgaları ve sayaçlar için de aynı mantığı uygulayın: `callerValue == protectedValue`, korunan değer bağımsız olarak geçerli olduğu ve beklenen etki alanına ait olduğu doğrulanmadan bir çağıran için yetki sağlamamalıdır.<sup>[[1]](#references)</sup>

## ACL devralma yoluyla meşru ayrıcalıklı işlemler

ACL düzenleme işlemindeki bir bypass, kalıcı bir ayrıcalık yükseltme aracıdır. Provenance vakasında, sıfır token'ı olan ayrıcalıksız bir hesap, eski `0 == 0` arz testini geçerek kendisine yönetim, mint ve para çekme izinleri verebilir; ardından normal mesaj işleyicilerini kullanarak varlık basabilir veya escrow'dan para çekebilirdi. Dolayısıyla exploit, ACL değişikliğinden sonra ikinci bir güvenlik açığı gerektirmiyordu.<sup>[[1]](#references)</sup>

Genel exploit sırası:<sup>[[1]](#references)</sup>

1. Yetkili olmayan alanı canlı durumdan farklı olan veya korunan değeri varsayılan olan bir nesne bulun.
2. Yerel değeri bu eski/varsayılan değerle eşleşen yeni/boş bir kimlik kullanın.
3. Rol yönetimi, sahiplik devri veya politika güncelleme endpoint'ini çağırıp kendinize kalıcı yetkiler verin.
4. ACL'yi kanonik durumdan okuyarak değişikliğin kalıcı olduğunu doğrulayın.
5. Meşru ve yüksek etkili işlemi (mint, para çekme, yükseltme, sahiplik devri veya politika değiştirme) gerçekleştirin.

Etkiyi değerlendirirken, yetkilendirme bypass'ında durmak yerine yeni rolden erişilebilen tüm yetkileri inceleyin. Escrow benzeri hesaplar, devralmayı mümkün kılan eski metadata'ya sahip nesneyle ilgisiz varlıkları da saklıyor olabilir.<sup>[[1]](#references)</sup>

## Invariant ve durumlu fuzzing hedefleri

Yetkilendirmeyi uygulamadan bağımsız biçimde tanımlayın. Tam arz için kullanılan bir kestirme işlemde asgari invariant şöyledir:<sup>[[1]](#references)[[2]](#references)</sup>

```text
controlsAllSupply(caller, asset) == true
    => authoritativeSupply(asset) > 0
    && authoritativeBalance(caller, asset) == authoritativeSupply(asset)
```

Bir model/durum makinesi fuzzer'ı kullanarak tekil çağrılar yerine diziler oluşturun; oluşturma, sıfır değerle başlatma, etkinleştirme/sonlandırma, mint etme, burn etme, transferler, sıfırlamalar, geçişler, sync çağrıları ve ACL değişikliklerini kapsayın. Her geçişten sonra yinelenen gösterimleri karşılaştırın ve yeni bir hesabın korumalı hiçbir işlemi gerçekleştiremediğini doğrulayın. Sıfır, bir birim, kısmi sahiplik, tam sahiplik, güncelliğini yitirmiş düşük ve güncelliğini yitirmiş yüksek değerler için açık test durumları ekleyin.<sup>[[1]](#references)[[2]](#references)</sup>

Yüksek sinyalli regresyon özellikleri şunlardır:<sup>[[1]](#references)[[2]](#references)</sup>

- Yetkili arzın sıfır olması, hiçbir zaman sahiplik veya yöneticilik anlamına gelmez.
- Yinelenen arz bakiyelerine eşit olduğunda kısmi sahipler yönetici olamaz.
- Gerçek bir tam sahip, mevcut arz pozitif olduğunda amaçlanan kısa yolu kullanabilir.
- Başarısız self-grant işlemleri ACL'yi değiştirmez veya sonraki ayrıcalıklı çağrıları etkinleştirmez.
- Mod değişiklikleri, yetkilendirme denetiminin hangi gösterimi yetkili kabul ettiğini sessizce değiştiremez.

## References

- [1] [Durum uyuşmazlığı yetkisiz erişimi mümkün kılıyor (Trail of Bits)](https://blog.trailofbits.com/2026/08/25/state-divergence-enables-unauthorized-access/)
- [2] [Provenance PR #2734 - Güncelliğini yitirmiş arz denetimlerini düzeltme](https://github.com/provenance-io/provenance/pull/2734)
- [3] [Provenance commit c81fd65 - Toplam arz yetkilendirme kısayolunda sıfır arzı reddetme](https://github.com/provenance-io/provenance/commit/c81fd65f8ad48de42d5a6d68e761a0851c7e72c4)
{{#include ../../banners/hacktricks-training.md}}
