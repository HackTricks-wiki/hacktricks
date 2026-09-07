# State Divergence ve Default-Value Authorization Bypasses

{{#include ../../banners/hacktricks-training.md}}

Authorization bazen açık bir role yerine türetilmiş ekonomik duruma bağlıdır; örneğin, "caller tüm supply'ye sahiptir." Bu predicate'teki değerler farklı store'larda tutuluyorsa, güncel olmayan bir duplicate, meşru bir ownership shortcut'ını authorization bypass'a dönüştürebilir. Provenance marker module, tehlikeli birleşimi göstermiştir: canlı caller balance değeri, non-fixed-supply asset'ler için güncellenmeyen marker-local supply metadata ile karşılaştırılmıştır.<sup>[[1]](#references)</sup>

## Authorization boundary olarak duplicated state'i denetleme

Bir permission check'te kullanılan her değer için **tüm temsilleri** listeleyin: canonical module state, object fields, cached aggregates, indexes, snapshots, bridge records ve off-chain mirrors. Ardından her object mode'da hangi kopyanın güncellendiğini belirlemek için tüm create, mint, burn, transfer, reset, migration ve synchronization path'lerini izleyin. Bir field bir mode için authoritative, başka bir mode için ise yalnızca informational olabilir.<sup>[[1]](#references)</sup>

Pratik bir review workflow şu şekildedir:<sup>[[1]](#references)</sup>

1. Protected action'ları bulun ve her authorization branch'ini bir boolean predicate'e indirgeyin.
2. Her operand için store'unu, update path'lerini, lifecycle state'lerini ve source of truth'u kaydedin.
3. Yalnızca tek bir representation'ı güncelleyen transition'lar oluşturun, ardından tüm kopyaları karşılaştırın.
4. Her transition'dan sonra protected action'ı fresh account ile gerçekleştirmeyi deneyin.
5. Bypass'ın ötesine geçin: action bir ACL'i düzenliyorsa self-grant persistent role'ler verin ve normal privileged API'leri çağırın.

Şüpheli pattern'ler arasında, iki tarafın farklı synchronization rule'larına sahip olduğu durumlarda `cachedSupply == balance`, `metadataOwner == caller` veya `snapshotShares == currentShares` bulunur. Bir operand için authoritative value sorgulamak, diğer operand güncel değilken karşılaştırmayı güvenli hale getirmez.<sup>[[1]](#references)</sup>

## Default-value equality bypass

Bir equality predicate, her iki operand da bağımsız olarak aynı default value'yu alabiliyorsa yine güvenli değildir. Aşağıdaki check, `supply` sıfırken, sıfır değerinin stale metadata'dan mı yoksa legitimate şekilde unfunded bir object'ten mi kaynaklandığına bakmaksızın, herhangi bir empty account'a "full supply control" verir.<sup>[[1]](#references)[[3]](#references)</sup>
```go
balance := bank.GetBalance(ctx, caller, denom)
supply := marker.GetSupply() // duplicate or stale representation
return balance.Amount.Equal(supply.Amount) // 0 == 0 -> true
```
Canonical store'a geçmek divergence'ı düzeltir ancak **empty-object case** sorununu çözmez. Güvenlik özelliği bağımsız bir geçerlilik koşulu içermelidir; Provenance patch, canlı banka arzını kullanır ve çağıranın bakiyesini karşılaştırmadan önce nil veya sıfır arzı reddeder.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
```go
supply := bank.GetSupply(ctx, denom)
if supply.Amount.IsNil() || supply.Amount.IsZero() {
return false
}
balance := bank.GetBalance(ctx, caller, denom)
return supply.Equal(NewCoin(denom, balance.Amount))
```
Quorum count'ları, ownership yüzdelerini, debt'i, collateral'ı, epoch'ları, nonce'ları, timestamp'leri ve counter'ları da aynı şekilde değerlendirin: `callerValue == protectedValue`, protected value bağımsız olarak geçerli ve beklenen domain'e ait olana kadar bir caller'ı authorize etmemelidir.<sup>[[1]](#references)</sup>

## ACL takeover ile legitimate privileged operations

Bir ACL düzenleme işlemindeki bypass, kalıcı bir privilege-escalation primitive'idir. Provenance vakasında, sıfır token'a sahip unprivileged bir hesap, güncel olmayan `0 == 0` supply testini geçebilir, kendisine administrative, mint ve withdrawal izinleri verebilir ve ardından asset'leri mint etmek veya escrow'dan withdrawal yapmak için ordinary message handler'ları kullanabilirdi. Bu nedenle exploit, ACL değişikliğinden sonra ikinci bir vulnerability gerektirmedi.<sup>[[1]](#references)</sup>

Genel exploitation sequence:<sup>[[1]](#references)</sup>

1. Non-authoritative field'ı live state'ten farklı olan veya protected value'su default olan bir object bulun.
2. Local value'su bu stale/default value ile eşleşecek şekilde yeni/empty bir identity kullanın.
3. Role-management, ownership-transfer veya policy-update endpoint'ini çağırın ve kendinize kalıcı capability'ler verin.
4. ACL'yi canonical state'ten okuyarak persistence'ı doğrulayın.
5. Legitimate high-impact operation'ı (mint, withdraw, upgrade, transfer ownership veya change policy) çağırın.

Impact'i triage ederken, authorization bypass'ta durmak yerine yeni role üzerinden erişilebilen her capability'yi inceleyin. Escrow benzeri hesaplar, stale metadata'sı takeover'ı mümkün kılan object ile ilgisiz asset'leri custody edebilir.<sup>[[1]](#references)</sup>

## Invariant ve stateful-fuzzing hedefleri

Authorization'ı implementation'dan bağımsız olarak belirtin. Bir full-supply shortcut için minimal invariant şudur:<sup>[[1]](#references)[[2]](#references)</sup>
```text
controlsAllSupply(caller, asset) == true
=> authoritativeSupply(asset) > 0
&& authoritativeBalance(caller, asset) == authoritativeSupply(asset)
```
Bir model/state-machine fuzzer kullanarak izole çağrılar yerine diziler oluşturun; oluşturma, zero-value initialization, activation/finalization, minting, burning, transfers, resets, migrations, sync calls ve ACL değişikliklerini kapsayın. Her geçişten sonra yinelenen temsilleri karşılaştırın ve yeni bir hesabın korumalı herhangi bir eylemi gerçekleştiremeyeceğini doğrulayın. Zero, one unit, partial ownership, full ownership, stale-low ve stale-high değerleri için açık durumlar ekleyin.<sup>[[1]](#references)[[2]](#references)</sup>

Yüksek sinyalli regression özellikleri şunlardır:<sup>[[1]](#references)[[2]](#references)</sup>

- Zero authoritative supply hiçbir zaman ownership veya administration anlamına gelmez.
- Partial holders, yinelenen supply kendi balance'larına eşit olduğunda administrator olamaz.
- Gerçek bir full holder, live supply pozitif olduğunda amaçlanan shortcut'ı korur.
- Başarısız self-grants ACL'yi değiştirmez veya sonraki privileged calls işlemlerini etkinleştirmez.
- Mode değişiklikleri, bir authorization check'in hangi representation'ı authoritative kabul ettiğini sessizce değiştiremez.

## References

- [1] [State divergence unauthorized access'i etkinleştirir (Trail of Bits)](https://blog.trailofbits.com/2026/08/25/state-divergence-enables-unauthorized-access/)
- [2] [Provenance PR #2734 - Stale supply kontrollerini düzeltme](https://github.com/provenance-io/provenance/pull/2734)
- [3] [Provenance commit c81fd65 - Total-supply authorization shortcut'ında zero supply'yi reddetme](https://github.com/provenance-io/provenance/commit/c81fd65f8ad48de42d5a6d68e761a0851c7e72c4)
{{#include ../../banners/hacktricks-training.md}}
