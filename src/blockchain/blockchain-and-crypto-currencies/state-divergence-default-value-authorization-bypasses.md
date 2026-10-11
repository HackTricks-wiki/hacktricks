# State Divergence और Default-Value Authorization Bypasses

{{#include ../../banners/hacktricks-training.md}}

Authorization कभी-कभी किसी स्पष्ट role के बजाय derived economic state पर निर्भर करता है—उदाहरण के लिए, "caller के पास पूरी supply है।" अगर उस predicate की values अलग-अलग stores से आती हैं, तो कोई पुरानी duplicate value, ownership के वैध shortcut को authorization bypass में बदल सकती है। Provenance marker module ने इस खतरनाक संयोजन को दिखाया: live caller balance की तुलना marker-local supply metadata से की गई, जिसे non-fixed-supply assets के लिए update नहीं किया जाता था।<sup>[[1]](#references)</sup>

## Authorization boundary के रूप में duplicated state का audit करें

Permission check में इस्तेमाल की जाने वाली हर value के लिए उसकी **सभी representations** की सूची बनाएँ: canonical module state, object fields, cached aggregates, indexes, snapshots, bridge records और off-chain mirrors। फिर create, mint, burn, transfer, reset, migration और synchronization के हर path को trace करें, ताकि पता चल सके कि हर object mode में कौन-सी copy update होती है। कोई field एक mode में authoritative और दूसरे में केवल informational हो सकती है।<sup>[[1]](#references)</sup>

Review के लिए एक व्यावहारिक workflow यह है:<sup>[[1]](#references)</sup>

1. Protected actions ढूँढें और हर authorization branch को एक boolean predicate में सरल करें।
2. हर operand के लिए उसका store, update paths, lifecycle states और source of truth दर्ज करें।
3. ऐसे transitions बनाएँ जो केवल एक representation को update करें, फिर सभी copies की तुलना करें।
4. हर transition के बाद किसी नए account से protected action करने की कोशिश करें।
5. Bypass के बाद भी आगे जाँच करें: अगर action किसी ACL को edit करता है, तो खुद को persistent roles दें और सामान्य privileged APIs को invoke करें।

संदिग्ध patterns में `cachedSupply == balance`, `metadataOwner == caller`, या `snapshotShares == currentShares` शामिल हैं, जब दोनों पक्षों के synchronization rules अलग-अलग हों। एक operand के लिए authoritative value query करने से comparison सुरक्षित नहीं हो जाती, अगर दूसरा operand पुराना हो।<sup>[[1]](#references)</sup>

## Default-value equality bypass

Equality predicate तब भी असुरक्षित होती है, जब दोनों operands स्वतंत्र रूप से एक ही default value ले सकते हों। नीचे दी गई check, किसी भी empty account को "पूरी supply पर नियंत्रण" देती है, जब `supply` शून्य हो—चाहे शून्य का कारण पुराना metadata हो या किसी object को वैध रूप से funding न मिली हो।<sup>[[1]](#references)[[3]](#references)</sup>

```go
balance := bank.GetBalance(ctx, caller, denom)
supply := marker.GetSupply() // duplicate or stale representation
return balance.Amount.Equal(supply.Amount) // 0 == 0 -> true
```

canonical store पर स्विच करने से divergence ठीक हो जाता है, लेकिन **empty-object case** नहीं। सुरक्षा गुण में एक स्वतंत्र validity condition भी शामिल होनी चाहिए; Provenance patch caller balance की तुलना करने से पहले live bank supply की जाँच करता है और nil या zero supply को अस्वीकार करता है।<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

```go
supply := bank.GetSupply(ctx, denom)
if supply.Amount.IsNil() || supply.Amount.IsZero() {
    return false
}
balance := bank.GetBalance(ctx, caller, denom)
return supply.Equal(NewCoin(denom, balance.Amount))
```

Quorum counts, ownership percentages, debt, collateral, epochs, nonces, timestamps और counters पर भी यही तर्क लागू करें: `callerValue == protectedValue` से caller को तब तक authorize नहीं किया जाना चाहिए, जब तक protected value स्वतंत्र रूप से valid न हो और अपेक्षित domain से संबंधित न हो।<sup>[[1]](#references)</sup>

## ACL takeover से legitimate privileged operations तक

ACL-editing operation में bypass एक स्थायी privilege-escalation primitive है। Provenance मामले में, zero tokens वाले unprivileged account ने stale `0 == 0` supply test पास किया, खुद को administrative, mint और withdrawal permissions दीं, और फिर सामान्य message handlers का उपयोग करके assets mint किए या escrow से निकाले। इसलिए ACL बदलने के बाद exploit के लिए किसी दूसरी vulnerability की ज़रूरत नहीं थी।<sup>[[1]](#references)</sup>

सामान्य exploitation sequence:<sup>[[1]](#references)</sup>

1. ऐसा object खोजें जिसका non-authoritative field live state से अलग हो, या जिसकी protected value default हो।
2. नई/खाली identity का उपयोग करें, ताकि उसकी local value उस stale/default value से मेल खाए।
3. role-management, ownership-transfer या policy-update endpoint को call करके खुद को स्थायी capabilities दें।
4. canonical state से ACL पढ़कर पुष्टि करें कि बदलाव बना हुआ है।
5. वैध high-impact operation (mint, withdraw, upgrade, transfer ownership या change policy) चलाएँ।

Impact की triage करते समय, authorization bypass पर रुकने के बजाय नई role से उपलब्ध हर capability की जाँच करें। Escrow-जैसे accounts ऐसे assets की custody कर सकते हैं जो उस object से संबंधित नहीं हैं, जिसके stale metadata ने takeover संभव बनाया।<sup>[[1]](#references)</sup>

## Invariant और stateful-fuzzing के लक्ष्य

Authorization को implementation से स्वतंत्र रूप से specify करें। Full-supply shortcut के लिए न्यूनतम invariant यह है:<sup>[[1]](#references)[[2]](#references)</sup>

```text
controlsAllSupply(caller, asset) == true
    => authoritativeSupply(asset) > 0
    && authoritativeBalance(caller, asset) == authoritativeSupply(asset)
```

model/state-machine fuzzer का उपयोग करके अलग-अलग calls के बजाय sequences जनरेट करें—इनमें creation, zero-value initialization, activation/finalization, minting, burning, transfers, resets, migrations, sync calls और ACL changes शामिल हों। हर transition के बाद duplicated representations की तुलना करें और assert करें कि कोई नया account protected action नहीं कर सकता। zero, one unit, partial ownership, full ownership, stale-low और stale-high values के लिए explicit cases seed करें।<sup>[[1]](#references)[[2]](#references)</sup>

High-signal regression properties हैं:<sup>[[1]](#references)[[2]](#references)</sup>

- Zero authoritative supply का मतलब कभी भी ownership या administration नहीं होता।
- Partial holders administrator नहीं बन सकते, भले ही duplicate supply उनकी balance के बराबर हो।
- True full holder को live supply positive होने पर इच्छित shortcut मिलता रहना चाहिए।
- Failed self-grants से ACL mutate नहीं होना चाहिए और न ही downstream privileged calls enable होने चाहिए।
- Mode changes चुपचाप यह नहीं बदल सकते कि authorization check किस representation को authoritative मानता है।

## References

- [1] [State divergence से unauthorized access संभव होता है (Trail of Bits)](https://blog.trailofbits.com/2026/08/25/state-divergence-enables-unauthorized-access/)
- [2] [Provenance PR #2734 - stale supply checks ठीक करें](https://github.com/provenance-io/provenance/pull/2734)
- [3] [Provenance commit c81fd65 - total-supply authorization shortcut में zero supply अस्वीकार करें](https://github.com/provenance-io/provenance/commit/c81fd65f8ad48de42d5a6d68e761a0851c7e72c4)
{{#include ../../banners/hacktricks-training.md}}
