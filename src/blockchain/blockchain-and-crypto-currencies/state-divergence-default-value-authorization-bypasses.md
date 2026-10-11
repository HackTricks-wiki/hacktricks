# State Divergence and Default-Value Authorization Bypasses

{{#include ../../banners/hacktricks-training.md}}

Uidhinishaji wakati mwingine hutegemea hali ya kiuchumi inayokokotolewa badala ya jukumu lililobainishwa wazi—kwa mfano, "mpigaji simu anamiliki supply yote." Ikiwa thamani katika sharti hilo zinatoka kwenye hifadhi tofauti, nakala rudufu iliyopitwa na wakati inaweza kubadilisha njia halali ya mkato ya umiliki na kuwa njia ya kukwepa uidhinishaji. Moduli ya Provenance marker ilionyesha mchanganyiko hatari: salio hai la mpigaji simu lililinganishwa na metadata ya supply ya marker ambayo haikusasishwa kwa assets zenye supply isiyobadilika.<sup>[[1]](#references)</sup>

## Kagua hali rudufu kama mpaka wa uidhinishaji

Kwa kila thamani inayotumiwa na ukaguzi wa ruhusa, orodhesha **uwakilishaji wote**: hali ya canonical module, sehemu za object, jumla zilizowekwa kwenye cache, indexes, snapshots, rekodi za bridge, na nakala za nje ya mfumo. Kisha fuatilia kila njia ya create, mint, burn, transfer, reset, migration, na synchronization ili kubaini ni nakala ipi inasasishwa katika kila hali ya object. Sehemu inaweza kuwa chanzo cha mamlaka katika hali moja na taarifa tu katika hali nyingine.<sup>[[1]](#references)</sup>

Mtiririko wa vitendo wa ukaguzi ni:<sup>[[1]](#references)</sup>

1. Tafuta vitendo vilivyolindwa na punguza kila tawi la uidhinishaji kuwa predicate ya boolean.
2. Kwa kila operand, rekodi hifadhi yake, njia za usasishaji, hali za mzunguko wa maisha, na chanzo cha ukweli.
3. Tengeneza mabadiliko yanayosasisha uwakilishaji mmoja pekee, kisha linganisha nakala zote.
4. Jaribu kutekeleza kitendo kilicholindwa kutoka kwa akaunti mpya baada ya kila mabadiliko.
5. Endelea baada ya bypass: ikiwa kitendo kinahariri ACL, jipe mwenyewe majukumu yanayoendelea na utumie API za kawaida zenye ruhusa za juu.

Miundo inayotia shaka ni pamoja na `cachedSupply == balance`, `metadataOwner == caller`, au `snapshotShares == currentShares` wakati pande hizo mbili zina sheria tofauti za synchronization. Kuuliza thamani iliyo mamlakani kwa operand moja hakufanyi ulinganisho kuwa salama ikiwa operand nyingine imepitwa na wakati.<sup>[[1]](#references)</sup>

## Bypass ya usawa wa thamani chaguomsingi

Predicate ya usawa pia si salama wakati operands zote mbili zinaweza kujitegemea kuchukua thamani ileile chaguomsingi. Ukaguzi ulio hapa chini humpa "udhibiti kamili wa supply" akaunti yoyote tupu wakati `supply` ni sifuri, bila kujali kama sifuri hiyo imetokana na metadata iliyopitwa na wakati au object ambayo haijawahi kufadhiliwa kihalali.<sup>[[1]](#references)[[3]](#references)</sup>

```go
balance := bank.GetBalance(ctx, caller, denom)
supply := marker.GetSupply() // duplicate or stale representation
return balance.Amount.Equal(supply.Amount) // 0 == 0 -> true
```

Kubadili hadi kwenye hifadhi kanoniki hurekebisha tofauti za hali, lakini **hakutatui hali ya kitu tupu**. Sifa ya usalama lazima ijumuishwe na sharti huru la uhalali; patch ya Provenance hutumia jumla ya sasa ya tokeni kwenye bank na hukataa supply iliyo nil au sifuri kabla ya kulinganisha salio la caller.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

```go
supply := bank.GetSupply(ctx, denom)
if supply.Amount.IsNil() || supply.Amount.IsZero() {
    return false
}
balance := bank.GetBalance(ctx, caller, denom)
return supply.Equal(NewCoin(denom, balance.Amount))
```

Tumia mantiki hiyo hiyo kwa hesabu za quorum, asilimia za umiliki, deni, dhamana, epochs, nonces, mihuri ya muda na vihesabu: `callerValue == protectedValue` haipaswi kumpa caller idhini hadi thamani iliyolindwa ithibitishwe kivyake kuwa halali na kuwa ya domain inayotarajiwa.<sup>[[1]](#references)</sup>

## Kuchukua ACL ili kupata ruhusa za kawaida zenye upendeleo

Bypass katika operesheni ya kuhariri ACL ni njia ya kudumu ya kuongeza marupurupu. Katika kisa cha Provenance, akaunti isiyo na upendeleo na tokens sifuri ingeweza kupita jaribio la supply lililopitwa na wakati la `0 == 0`, kujipa ruhusa za usimamizi, mint na withdrawal, kisha kutumia message handlers za kawaida kutengeneza assets au kutoa fedha zilizo kwenye escrow. Kwa hiyo, exploit haikuhitaji udhaifu mwingine baada ya mabadiliko ya ACL.<sup>[[1]](#references)</sup>

Mfuatano wa jumla wa exploitation:<sup>[[1]](#references)</sup>

1. Tafuta object ambayo field isiyo mamlaka inatofautiana na hali ya sasa, au ambayo thamani iliyolindwa ni ya msingi.
2. Tumia identity mpya/tupu ili thamani yake ya ndani ilingane na thamani hiyo ya zamani/msingi.
3. Ita endpoint ya usimamizi wa role, uhamishaji wa umiliki, au usasishaji wa policy na ujipe capabilities za kudumu.
4. Thibitisha kuwa mabadiliko yamedumu kwa kusoma ACL kutoka canonical state.
5. Tekeleza operesheni halali yenye athari kubwa (mint, withdraw, upgrade, kuhamisha umiliki, au kubadilisha policy).

Unapochunguza athari, kagua kila capability inayopatikana kupitia role mpya badala ya kusimama kwenye bypass ya authorization. Akaunti zinazofanana na escrow zinaweza kuhifadhi assets zisizohusiana na object ambayo metadata yake ya zamani iliwezesha takeover.<sup>[[1]](#references)</sup>

## Malengo ya invariant na stateful fuzzing

Bainisha authorization bila kutegemea implementation. Kwa njia ya mkato ya full-supply, invariant ya chini kabisa ni:<sup>[[1]](#references)[[2]](#references)</sup>

```text
controlsAllSupply(caller, asset) == true
    => authoritativeSupply(asset) > 0
    && authoritativeBalance(caller, asset) == authoritativeSupply(asset)
```

Tumia model/state-machine fuzzer kuzalisha mfuatano wa hatua—si miito ya pekee—unaoshughulikia uundaji, uanzishaji wa thamani sifuri, uanzishaji/ukamilishaji, kutengeneza tokeni, kuchoma tokeni, uhamishaji, uwekaji upya, uhamishaji wa data, miito ya sync na mabadiliko ya ACL. Baada ya kila hatua, linganisha uwakilishi unaorudiwa na uhakikishe kuwa akaunti mpya haiwezi kutekeleza kitendo chochote kinacholindwa. Weka kesi maalum za thamani sifuri, kitengo kimoja, umiliki wa sehemu, umiliki kamili, thamani iliyopitwa na wakati iliyo chini na thamani iliyopitwa na wakati iliyo juu.<sup>[[1]](#references)[[2]](#references)</sup>

Sifa muhimu za regression ni:<sup>[[1]](#references)[[2]](#references)</sup>

- Ugavi mamlaka wa sifuri haumaanishi umiliki au usimamizi.
- Wamiliki wa sehemu hawawezi kuwa wasimamizi wakati ugavi unaorudiwa unalingana na salio lao.
- Mmiliki halisi wa kila kitu huhifadhi njia ya mkato iliyokusudiwa wakati ugavi wa sasa ni chanya.
- Majaribio yaliyoshindwa ya kujipa ruhusa hayaibadilishi ACL wala kuwezesha miito ya baadaye yenye upendeleo.
- Mabadiliko ya mode hayawezi kubadilisha kimyakimya uwakilishi ambao ukaguzi wa idhini huchukulia kuwa wenye mamlaka.

## References

- [1] [Tofauti ya hali huwezesha ufikiaji usioidhinishwa (Trail of Bits)](https://blog.trailofbits.com/2026/08/25/state-divergence-enables-unauthorized-access/)
- [2] [Provenance PR #2734 - Rekebisha ukaguzi wa ugavi uliopitwa na wakati](https://github.com/provenance-io/provenance/pull/2734)
- [3] [Provenance commit c81fd65 - Kataa ugavi wa sifuri katika njia ya mkato ya idhini ya ugavi wa jumla](https://github.com/provenance-io/provenance/commit/c81fd65f8ad48de42d5a6d68e761a0851c7e72c4)
{{#include ../../banners/hacktricks-training.md}}
