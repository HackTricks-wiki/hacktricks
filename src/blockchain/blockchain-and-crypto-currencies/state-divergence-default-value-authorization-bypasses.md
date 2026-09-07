# State Divergence na Default-Value Authorization Bypasses

{{#include ../../banners/hacktricks-training.md}}

Authorization wakati mwingine hutegemea state ya kiuchumi inayotokana na data badala ya role iliyo wazi—kwa mfano, "caller anamiliki supply yote." Ikiwa values katika predicate hiyo zinatoka kwenye stores tofauti, duplicate iliyopitwa na wakati inaweza kubadilisha shortcut halali ya umiliki kuwa authorization bypass. Provenance marker module ilionyesha mchanganyiko hatari: balance ya caller iliyo hai ililinganishwa na metadata ya supply iliyo katika marker-local ambayo haikusasishwa kwa assets zenye supply isiyobadilika.<sup>[[1]](#references)</sup>

## Kagua duplicated state kama mpaka wa authorization

Kwa kila value inayotumiwa na permission check, orodhesha **representations zote**: canonical module state, object fields, cached aggregates, indexes, snapshots, bridge records, na off-chain mirrors. Kisha fuatilia kila njia ya create, mint, burn, transfer, reset, migration, na synchronization ili kubaini ni copy ipi inayosasishwa katika kila object mode. Field inaweza kuwa authoritative kwa mode moja na ya taarifa tu kwa nyingine.<sup>[[1]](#references)</sup>

Mtiririko wa vitendo wa review ni:<sup>[[1]](#references)</sup>

1. Tafuta protected actions na punguza kila authorization branch kuwa boolean predicate.
2. Kwa kila operand, rekodi store yake, update paths, lifecycle states, na source of truth.
3. Tengeneza transitions zinazosasisha representation moja tu, kisha linganisha copies zote.
4. Jaribu protected action kutoka kwenye account mpya baada ya kila transition.
5. Endelea zaidi ya bypass: ikiwa action inahariri ACL, jipe persistent roles na invoke normal privileged APIs.

Mifumo ya kutiliwa shaka inajumuisha `cachedSupply == balance`, `metadataOwner == caller`, au `snapshotShares == currentShares` wakati pande hizo mbili zina synchronization rules tofauti. Kuuliza authoritative value kwa operand moja hakufanyi comparison iwe salama wakati operand nyingine imepitwa na wakati.<sup>[[1]](#references)</sup>

## Default-value equality bypass

Equality predicate pia si salama wakati operands zote mbili zinaweza kujitegemea kuchukua default value ileile. Check iliyo hapa chini inampa "control kamili ya supply" account yoyote tupu wakati `supply` ni zero, bila kujali kama zero imesababishwa na metadata iliyopitwa na wakati au object ambayo haijawahi kufadhiliwa kihalali.<sup>[[1]](#references)[[3]](#references)</sup>
```go
balance := bank.GetBalance(ctx, caller, denom)
supply := marker.GetSupply() // duplicate or stale representation
return balance.Amount.Equal(supply.Amount) // 0 == 0 -> true
```
Kubadilisha kwenda kwenye canonical store kunarekebisha divergence lakini **si hali ya empty-object**. Sifa ya usalama lazima ijumuishwe na sharti huru la uhalali; Provenance patch hutumia live bank supply na hukataa supply ya nil au sifuri kabla ya kulinganisha caller balance.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
```go
supply := bank.GetSupply(ctx, denom)
if supply.Amount.IsNil() || supply.Amount.IsZero() {
return false
}
balance := bank.GetBalance(ctx, caller, denom)
return supply.Equal(NewCoin(denom, balance.Amount))
```
Tumia mantiki hiyo hiyo kwa quorum counts, ownership percentages, debt, collateral, epochs, nonces, timestamps, na counters: `callerValue == protectedValue` haipaswi kuidhinisha caller hadi protected value ithibitishwe kwa kujitegemea kuwa valid na iko katika domain inayotarajiwa.<sup>[[1]](#references)</sup>

## ACL takeover hadi legitimate privileged operations

Bypass katika operesheni ya kuhariri ACL ni primitive ya kudumu ya privilege-escalation. Katika Provenance, account isiyo na privileges yenye tokens sifuri iliweza kupita jaribio la supply lililokuwa stale la `0 == 0`, kujipa ruhusa za administrative, mint, na withdrawal, kisha kutumia message handlers za kawaida kumint assets au kuwithdraw escrow. Kwa hiyo exploit haikuhitaji vulnerability ya pili baada ya mabadiliko ya ACL.<sup>[[1]](#references)</sup>

Mlolongo wa jumla wa exploitation:<sup>[[1]](#references)</sup>

1. Tafuta object ambayo non-authoritative field yake inatofautiana na live state, au ambayo protected value yake ni default.
2. Tumia identity mpya/iliyo tupu ili local value yake ilingane na stale/default value hiyo.
3. Ita role-management, ownership-transfer, au policy-update endpoint na ujipatie capabilities za kudumu.
4. Thibitisha persistence kwa kusoma ACL kutoka canonical state.
5. Tekeleza legitimate high-impact operation (mint, withdraw, upgrade, transfer ownership, au change policy).

Wakati wa kutathmini impact, kagua kila capability inayoweza kufikiwa kupitia role mpya badala ya kuishia kwenye authorization bypass. Accounts zinazofanya kazi kama escrow zinaweza kuhifadhi assets zisizohusiana na object ambayo stale metadata yake iliwezesha takeover.<sup>[[1]](#references)</sup>

## Invariant na stateful-fuzzing targets

Bainisha authorization bila kutegemea implementation. Kwa full-supply shortcut, invariant ya chini kabisa ni:<sup>[[1]](#references)[[2]](#references)</sup>
```text
controlsAllSupply(caller, asset) == true
=> authoritativeSupply(asset) > 0
&& authoritativeBalance(caller, asset) == authoritativeSupply(asset)
```
Tumia model/state-machine fuzzer kuzalisha mfuatano—sio miito iliyotengwa—unaofunika uundaji, uanzishaji wa thamani sifuri, activation/finalization, minting, burning, transfers, resets, migrations, sync calls, na mabadiliko ya ACL. Baada ya kila transition, linganisha representations zilizoigwa na uhakikishe kwamba akaunti mpya haiwezi kutekeleza protected action yoyote. Weka wazi visa vya zero, one unit, partial ownership, full ownership, stale-low, na stale-high values.<sup>[[1]](#references)[[2]](#references)</sup>

Sifa za regression zenye signal kubwa ni:<sup>[[1]](#references)[[2]](#references)</sup>

- Zero authoritative supply haimaanishi kamwe ownership au administration.
- Partial holders hawawezi kuwa administrators wakati duplicate supply ni sawa na salio lao.
- True full holder huhifadhi shortcut iliyokusudiwa wakati live supply ni positive.
- Failed self-grants hazibadilishi ACL wala kuwezesha downstream privileged calls.
- Mode changes haziwezi kubadilisha kimya kimya representation ambayo authorization check inachukulia kuwa authoritative.

## References

- [1] [State divergence huwezesha access isiyoidhinishwa (Trail of Bits)](https://blog.trailofbits.com/2026/08/25/state-divergence-enables-unauthorized-access/)
- [2] [Provenance PR #2734 - Rekebisha stale supply checks](https://github.com/provenance-io/provenance/pull/2734)
- [3] [Provenance commit c81fd65 - Kataa zero supply katika total-supply authorization shortcut](https://github.com/provenance-io/provenance/commit/c81fd65f8ad48de42d5a6d68e761a0851c7e72c4)
{{#include ../../banners/hacktricks-training.md}}
