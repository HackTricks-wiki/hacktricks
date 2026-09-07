# Staatsdivergensie en Magtigingsomseilings deur Standaardwaardes

{{#include ../../banners/hacktricks-training.md}}

Magtiging berus soms op afgeleide ekonomiese toestand eerder as op ’n eksplisiete rol—for example, "the caller owns the entire supply." As the values in that predicate come from different stores, a stale duplicate can turn a legitimate ownership shortcut into an authorization bypass. The Provenance marker module demonstrated the dangerous combination: a live caller balance was compared with marker-local supply metadata that was not updated for non-fixed-supply assets.<sup>[[1]](#references)</sup>

## Oudit duplikaattoestand as ’n magtigingsgrens

For every value used by a permission check, enumerate **all representations**: canonical module state, object fields, cached aggregates, indexes, snapshots, bridge records, and off-chain mirrors. Trace then every create, mint, burn, transfer, reset, migration, and synchronization path to determine which copy is updated in each object mode. A field may be authoritative for one mode and informational for another.<sup>[[1]](#references)</sup>

A practical review workflow is:<sup>[[1]](#references)</sup>

1. Locate protected actions and reduce each authorization branch to a boolean predicate.
2. For every operand, record its store, update paths, lifecycle states, and source of truth.
3. Generate transitions that update only one representation, then compare all copies.
4. Attempt the protected action from a fresh account after each transition.
5. Continue beyond the bypass: if the action edits an ACL, self-grant persistent roles and invoke normal privileged APIs.

Suspicious patterns include `cachedSupply == balance`, `metadataOwner == caller`, or `snapshotShares == currentShares` when the two sides have different synchronization rules. Querying an authoritative value for one operand does not make the comparison safe when the other operand is stale.<sup>[[1]](#references)</sup>

## Omseiling deur gelykheid van standaardwaardes

An equality predicate is also unsafe when both operands can independently take the same default value. The check below grants "full supply control" to any empty account when `supply` is zero, regardless of whether zero results from stale metadata or a legitimately unfunded object.<sup>[[1]](#references)[[3]](#references)</sup>
```go
balance := bank.GetBalance(ctx, caller, denom)
supply := marker.GetSupply() // duplicate or stale representation
return balance.Amount.Equal(supply.Amount) // 0 == 0 -> true
```
Oorskakeling na die canonical store los divergence op, maar **nie** die empty-object-geval nie. Die security-eienskap moet ’n onafhanklike validity condition insluit; die Provenance patch gebruik live bank supply en verwerp nil of zero supply voordat die caller balance vergelyk word.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
```go
supply := bank.GetSupply(ctx, denom)
if supply.Amount.IsNil() || supply.Amount.IsZero() {
return false
}
balance := bank.GetBalance(ctx, caller, denom)
return supply.Equal(NewCoin(denom, balance.Amount))
```
Pas dieselfde redenasie toe op quorum-tellings, eienaarskappersentasies, skuld, kollateraal, epochs, nonces, tydstempels en tellers: `callerValue == protectedValue` mag nie ’n caller magtig totdat die beskermde waarde onafhanklik geldig is en aan die verwagte domein behoort nie.<sup>[[1]](#references)</sup>

## ACL-oorname tot legitieme bevoorregte bedrywighede

’n Bypass in ’n ACL-redigeringsbewerking is ’n blywende privilege-escalation-primitief. In die Provenance-saak kon ’n onbevoorregte rekening met nul tokens die verouderde `0 == 0`-aanbodtoets slaag, aan homself administratiewe, mint- en onttrekkingstoestemmings verleen, en daarna gewone message handlers gebruik om bates te mint of escrow te onttrek. Die exploit het dus geen tweede kwesbaarheid ná die ACL-verandering vereis nie.<sup>[[1]](#references)</sup>

Algemene exploitation-volgorde:<sup>[[1]](#references)</sup>

1. Vind ’n objek waarvan die nie-gesaghebbende veld van die lewendige toestand verskil, of waarvan die beskermde waarde die verstekwaarde is.
2. Gebruik ’n nuwe/leë identiteit sodat sy plaaslike waarde met daardie verouderde/verstekwaarde ooreenstem.
3. Roep die rolbestuur-, eienaarskapsoordrag- of beleidsopdaterings-endpoint aan en verleen aan jouself blywende vermoëns.
4. Bevestig volharding deur die ACL uit die kanonieke toestand te lees.
5. Roep die legitieme hoë-impak-bewerking aan (mint, onttrek, upgrade, dra eienaarskap oor, of verander beleid).

Wanneer jy impak triage, inspekteer elke vermoë wat vanaf die nuwe rol bereikbaar is eerder as om by die authorization-bypass te stop. Escrow-agtige rekeninge kan bates bewaar wat nie verband hou met die objek waarvan die verouderde metadata die oorname moontlik gemaak het nie.<sup>[[1]](#references)</sup>

## Invariant- en stateful-fuzzing-teikens

Spesifiseer authorization onafhanklik van die implementering. Vir ’n full-supply shortcut is die minimale invariant:<sup>[[1]](#references)[[2]](#references)</sup>
```text
controlsAllSupply(caller, asset) == true
=> authoritativeSupply(asset) > 0
&& authoritativeBalance(caller, asset) == authoritativeSupply(asset)
```
Gebruik ’n model/state-machine fuzzer om sekwense—nie geïsoleerde oproepe nie—te genereer wat skepping, zero-value initialization, aktivering/finalisering, minting, burning, transfers, resets, migrasies, sync calls en ACL-veranderings dek. Vergelyk gedupliseerde representasies ná elke transition en bevestig dat ’n nuwe account geen protected action kan uitvoer nie. Saai eksplisiete gevalle vir zero, een eenheid, gedeeltelike eienaarskap, volle eienaarskap, stale-low en stale-high waardes.<sup>[[1]](#references)[[2]](#references)</sup>

High-signal regression properties is:<sup>[[1]](#references)[[2]](#references)</sup>

- Zero authoritative supply impliseer nooit eienaarskap of administration nie.
- Partial holders kan nie administrators word wanneer ’n duplicate supply gelyk is aan hul balance nie.
- ’n Ware full holder behou die bedoelde shortcut wanneer live supply positief is.
- Mislukte self-grants verander nie die ACL nie en aktiveer nie downstream privileged calls nie.
- Mode changes kan nie stilweg verander watter representation ’n authorization check as authoritative beskou nie.

## References

- [1] [State divergence enables unauthorized access (Trail of Bits)](https://blog.trailofbits.com/2026/08/25/state-divergence-enables-unauthorized-access/)
- [2] [Provenance PR #2734 - Fix stale supply checks](https://github.com/provenance-io/provenance/pull/2734)
- [3] [Provenance commit c81fd65 - Reject zero supply in the total-supply authorization shortcut](https://github.com/provenance-io/provenance/commit/c81fd65f8ad48de42d5a6d68e761a0851c7e72c4)
{{#include ../../banners/hacktricks-training.md}}
