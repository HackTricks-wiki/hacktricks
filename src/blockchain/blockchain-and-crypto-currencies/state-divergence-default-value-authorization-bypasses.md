# State Divergence और Default-Value Authorization Bypasses

{{#include ../../banners/hacktricks-training.md}}

Authorization कभी-कभी explicit role के बजाय derived economic state पर निर्भर करता है—उदाहरण के लिए, "caller के पास पूरी supply का ownership है।" यदि उस predicate में उपयोग किए गए values अलग-अलग stores से आते हैं, तो एक stale duplicate legitimate ownership shortcut को authorization bypass में बदल सकता है। Provenance marker module ने इस खतरनाक combination को प्रदर्शित किया: live caller balance की तुलना marker-local supply metadata से की गई, जिसे non-fixed-supply assets के लिए update नहीं किया गया था।<sup>[[1]](#references)</sup>

## Authorization boundary के रूप में duplicated state का audit करें

Permission check में उपयोग किए गए हर value के लिए **सभी representations** की सूची बनाएं: canonical module state, object fields, cached aggregates, indexes, snapshots, bridge records और off-chain mirrors। फिर हर create, mint, burn, transfer, reset, migration और synchronization path को trace करके निर्धारित करें कि प्रत्येक object mode में कौन-सी copy update होती है। कोई field एक mode के लिए authoritative और दूसरे के लिए informational हो सकती है।<sup>[[1]](#references)</sup>

एक practical review workflow यह है:<sup>[[1]](#references)</sup>

1. Protected actions का पता लगाएं और प्रत्येक authorization branch को boolean predicate में बदलें।
2. प्रत्येक operand के लिए उसका store, update paths, lifecycle states और source of truth रिकॉर्ड करें।
3. ऐसे transitions generate करें जो केवल एक representation को update करें, फिर सभी copies की तुलना करें।
4. प्रत्येक transition के बाद fresh account से protected action करने का प्रयास करें।
5. Bypass के आगे भी जांच जारी रखें: यदि action किसी ACL को edit करता है, तो persistent roles को self-grant करें और सामान्य privileged APIs invoke करें।

संदिग्ध patterns में `cachedSupply == balance`, `metadataOwner == caller`, या `snapshotShares == currentShares` शामिल हैं, जब दोनों पक्षों के synchronization rules अलग हों। किसी एक operand के लिए authoritative value query करने से comparison safe नहीं हो जाता, यदि दूसरा operand stale हो।<sup>[[1]](#references)</sup>

## Default-value equality bypass

Equality predicate तब भी unsafe होता है, जब दोनों operands स्वतंत्र रूप से समान default value ले सकते हों। नीचे दिया गया check किसी भी empty account को "full supply control" दे देता है, जब `supply` zero हो—चाहे zero stale metadata के कारण आया हो या legitimately unfunded object के कारण।<sup>[[1]](#references)[[3]](#references)</sup>
```go
balance := bank.GetBalance(ctx, caller, denom)
supply := marker.GetSupply() // duplicate or stale representation
return balance.Amount.Equal(supply.Amount) // 0 == 0 -> true
```
canonical store पर switch करने से divergence ठीक हो जाता है, लेकिन **empty-object case** नहीं। Security property में एक स्वतंत्र validity condition शामिल होनी चाहिए; Provenance patch live bank supply का उपयोग करता है और caller balance की तुलना करने से पहले nil या zero supply को reject करता है।<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
```go
supply := bank.GetSupply(ctx, denom)
if supply.Amount.IsNil() || supply.Amount.IsZero() {
return false
}
balance := bank.GetBalance(ctx, caller, denom)
return supply.Equal(NewCoin(denom, balance.Amount))
```
Quorum counts, ownership percentages, debt, collateral, epochs, nonces, timestamps और counters पर भी यही reasoning लागू करें: `callerValue == protectedValue` को किसी caller को तब तक authorize नहीं करना चाहिए, जब तक protected value independently valid न हो और expected domain से संबंधित न हो।<sup>[[1]](#references)</sup>

## ACL takeover से legitimate privileged operations तक

ACL-editing operation में bypass एक durable privilege-escalation primitive होता है। Provenance मामले में, zero tokens वाला एक unprivileged account stale `0 == 0` supply test पास कर सकता था, स्वयं को administrative, mint और withdrawal permissions दे सकता था, और फिर assets mint करने या escrow withdraw करने के लिए ordinary message handlers का उपयोग कर सकता था। इसलिए ACL change के बाद exploit के लिए किसी दूसरी vulnerability की आवश्यकता नहीं थी।<sup>[[1]](#references)</sup>

General exploitation sequence:<sup>[[1]](#references)</sup>

1. ऐसा object खोजें जिसका non-authoritative field live state से अलग हो, या जिसका protected value default हो।
2. एक new/empty identity का उपयोग करें ताकि उसका local value उस stale/default value से match करे।
3. role-management, ownership-transfer या policy-update endpoint को call करें और स्वयं को durable capabilities प्रदान करें।
4. canonical state से ACL पढ़कर persistence की पुष्टि करें।
5. legitimate high-impact operation (mint, withdraw, upgrade, transfer ownership या change policy) invoke करें।

Impact triage करते समय, नए role से reachable हर capability का निरीक्षण करें और केवल authorization bypass पर न रुकें। Escrow-like accounts उन assets को custody में रख सकते हैं जो उस object से संबंधित नहीं हैं, जिसका stale metadata takeover को संभव बनाता है।<sup>[[1]](#references)</sup>

## Invariant और stateful-fuzzing targets

Authorization को implementation से independently specify करें। Full-supply shortcut के लिए minimal invariant यह है:<sup>[[1]](#references)[[2]](#references)</sup>
```text
controlsAllSupply(caller, asset) == true
=> authoritativeSupply(asset) > 0
&& authoritativeBalance(caller, asset) == authoritativeSupply(asset)
```
creation, zero-value initialization, activation/finalization, minting, burning, transfers, resets, migrations, sync calls और ACL changes को कवर करते हुए isolated calls के बजाय sequences generate करने के लिए model/state-machine fuzzer का उपयोग करें। हर transition के बाद duplicated representations की तुलना करें और assert करें कि कोई fresh account कोई protected action perform नहीं कर सकता। zero, one unit, partial ownership, full ownership, stale-low और stale-high values के लिए explicit cases seed करें।<sup>[[1]](#references)[[2]](#references)</sup>

High-signal regression properties हैं:<sup>[[1]](#references)[[2]](#references)</sup>

- Zero authoritative supply कभी भी ownership या administration imply नहीं करती।
- जब duplicate supply उनके balance के बराबर हो, तब partial holders administrators नहीं बन सकते।
- जब live supply positive हो, तब true full holder intended shortcut बनाए रखता है।
- Failed self-grants ACL को mutate नहीं करते और downstream privileged calls enable नहीं करते।
- Mode changes चुपचाप यह नहीं बदल सकते कि authorization check किस representation को authoritative मानता है।

## References

- [1] [State divergence enables unauthorized access (Trail of Bits)](https://blog.trailofbits.com/2026/08/25/state-divergence-enables-unauthorized-access/)
- [2] [Provenance PR #2734 - Fix stale supply checks](https://github.com/provenance-io/provenance/pull/2734)
- [3] [Provenance commit c81fd65 - Reject zero supply in the total-supply authorization shortcut](https://github.com/provenance-io/provenance/commit/c81fd65f8ad48de42d5a6d68e761a0851c7e72c4)
{{#include ../../banners/hacktricks-training.md}}
