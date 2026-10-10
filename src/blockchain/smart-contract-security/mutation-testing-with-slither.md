# Mutation Testing for Smart Contracts (slither-mutate, mewt, MuTON)

{{#include ../../banners/hacktricks-training.md}}

Mutation testing "hupima tests zako" kwa kuingiza kimfumo mabadiliko madogo (mutants) kwenye msimbo wa contract na kuendesha tena test suite. Test ikifeli, mutant huondolewa. Ikiwa tests bado zinapita, mutant husalia, na kufichua sehemu dhaifu ambazo line/branch coverage haziwezi kugundua.

Wazo kuu: Coverage huonyesha kuwa msimbo ulitekelezwa; mutation testing huonyesha ikiwa tabia yake imethibitishwa na tests.<sup>[[2]](#references)</sup>

## Kwa nini coverage inaweza kupotosha

Fikiria ukaguzi huu rahisi wa kizingiti:

```solidity
function verifyMinimumDeposit(uint256 deposit) public returns (bool) {
    if (deposit >= 1 ether) {
        return true;
    } else {
        return false;
    }
}
```

Majaribio ya unit yanayokagua tu thamani iliyo chini na thamani iliyo juu ya kizingiti yanaweza kufikia 100% ya line/branch coverage huku yakishindwa kuthibitisha mpaka wa usawa (`==`). Refactor ya `deposit >= 2 ether` bado ingefaulu majaribio hayo, na kuvunja kimyakimya mantiki ya itifaki.<sup>[[2]](#references)</sup>

Mutation testing hufichua pengo hili kwa kubadilisha condition na kuthibitisha kuwa majaribio yanafeli.

Kwa smart contracts, mutants wanaosalia mara nyingi huashiria ukosefu wa ukaguzi kuhusu:
- Uidhinishaji na mipaka ya role
- Invariants za uhasibu/uhamishaji wa thamani
- Masharti ya revert na njia za kushindwa
- Masharti ya mipaka (`==`, thamani za sifuri, arrays tupu, thamani za juu/chini kabisa)

## Mutation operators zenye ishara kubwa zaidi za usalama

Aina muhimu za mutation kwa ukaguzi wa contract:<sup>[[1]](#references)[[2]](#references)</sup>
- **Ukali wa juu**: badilisha statements kwa `revert()` ili kufichua njia ambazo hazijatekelezwa
- **Ukali wa wastani**: toa maoni kwenye mistari / ondoa logic ili kufichua side effects ambazo hazijathibitishwa
- **Ukali wa chini**: badilisha operators au constants kwa njia fiche, kama `>=` -> `>` au `+` -> `-`
- Mabadiliko mengine ya kawaida: kubadilisha assignment, kugeuza boolean, kukanusha condition, na kubadilisha type

Lengo la vitendo: ua mutants wote wenye maana, na utoe sababu wazi kwa mutants wanaosalia kwa kuwa hawahusiani au wana maana sawa.

## Kwa nini mutation inayotambua syntax ni bora kuliko regex

Mutation engines za zamani zilitumia regex au mabadiliko yanayolenga mistari. Mbinu hiyo hufanya kazi, lakini ina vikwazo muhimu:<sup>[[1]](#references)</sup>
- Ni vigumu kubadilisha statements za mistari mingi kwa usalama
- Muundo wa lugha haueleweki, kwa hiyo maoni/tokens zinaweza kulengwa vibaya
- Kutengeneza kila variant inayowezekana kwenye mstari dhaifu kunapoteza muda mwingi wa runtime

Zana zinazotegemea AST au Tree-sitter huboresha hili kwa kulenga nodes zenye muundo badala ya mistari ghafi:<sup>[[1]](#references)</sup>
- **slither-mutate** hutumia Solidity AST ya Slither.<sup>[[4]](#references)</sup>
- **mewt** hutumia Tree-sitter kama msingi unaojitegemea lugha.<sup>[[6]](#references)</sup>
- **MuTON** hujengwa juu ya `mewt` na kuongeza usaidizi wa moja kwa moja kwa lugha za TON kama FunC, Tolk, na Tact.<sup>[[7]](#references)</sup>

Hili hufanya miundo ya mistari mingi na mutations za kiwango cha expression ziwe za kuaminika zaidi kuliko mbinu zinazotumia regex pekee.

## Kuendesha mutation testing kwa slither-mutate

Mahitaji: Slither v0.10.2+.

- Orodhesha options na mutators:

```bash
slither-mutate --help
slither-mutate --list-mutators
```

- Mfano wa Foundry (hifadhi matokeo na uweke log kamili):<sup>[[2]](#references)</sup>

```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```

- Ikiwa hutumii Foundry, badilisha `--test-cmd` kwa amri unayotumia kuendesha majaribio (kwa mfano, `npx hardhat test`, `npm test`).

Artifacts huhifadhiwa kwenye `./mutation_campaign` kwa chaguomsingi. Mutants ambao hawakugunduliwa (walionusurika) hunakiliwa huko ili wakaguliwe.<sup>[[5]](#references)</sup>

### Kuelewa matokeo

Mistari ya ripoti huonekana hivi:

```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```

- Lebo iliyo kwenye mabano ni jina la utani la mutator (kwa mfano, `CR` = Ubadilishaji wa Maoni).
- `UNCAUGHT` inamaanisha kuwa tests zilifaulu chini ya tabia iliyobadilishwa → assertion haipo.

## Kupunguza muda wa utekelezaji: weka kipaumbele kwa mutants wenye athari kubwa

Kampeni za mutation zinaweza kuchukua saa au siku. Vidokezo vya kupunguza gharama:<sup>[[1]](#references)[[2]](#references)</sup>
- Wigo: Anza na contracts/directories muhimu pekee, kisha panua.
- Weka kipaumbele kwa mutators: Ikiwa mutant wa kipaumbele cha juu kwenye mstari atasalia (kwa mfano `revert()` au kuondoa maoni), ruka variants za kipaumbele cha chini za mstari huo.
- Tumia kampeni za awamu mbili: endesha tests maalum za haraka kwanza, kisha endesha tena mutants ambao hawakunaswa pekee kwa kutumia suite kamili.
- Ikiwezekana, linganisha malengo ya mutation na amri mahususi za test (kwa mfano, msimbo wa auth -> tests za auth).
- Muda unapokuwa finyu, punguza kampeni ziwe mutants wa ukali wa juu/wastani.
- Endesha tests sambamba ikiwa runner yako inaruhusu; hifadhi dependencies/builds kwenye cache.
- Simamisha mapema: acha mapema mabadiliko yanapoonyesha wazi pengo la assertion.

Hesabu ya muda ni kali: `1000 mutants x 5-minute tests ~= 83 hours`, kwa hiyo usanifu wa kampeni ni muhimu sawa na mutator yenyewe.<sup>[[1]](#references)</sup>

## Kampeni zinazoendelea na triage kwa kiwango kikubwa

Udhaifu mmoja wa workflows za zamani ni kuhifadhi matokeo kwenye `stdout` pekee. Kwa kampeni ndefu, hili hufanya kusitisha/kuendelea, kuchuja na kukagua kuwa kugumu zaidi.<sup>[[1]](#references)</sup>

`mewt`/`MuTON` huboresha hili kwa kuhifadhi mutants na matokeo kwenye kampeni zinazotumia SQLite. Faida:<sup>[[1]](#references)</sup>
- Sitisha na uendelee na runs ndefu bila kupoteza maendeleo
- Chuja mutants ambao hawakunaswa pekee katika faili au darasa mahususi la mutation
- Hamisha/tafsiri matokeo kuwa SARIF kwa ajili ya zana za ukaguzi
- Zipa triage inayosaidiwa na AI seti ndogo za matokeo zilizochujwa badala ya logs ghafi za terminal

Matokeo yanayoendelea kuhifadhiwa ni muhimu hasa mutation testing inapokuwa sehemu ya pipeline ya audit badala ya ukaguzi wa mara moja unaofanywa kwa mkono.

## Workflow ya triage kwa mutants wanaosalia

1) Kagua mstari uliobadilishwa na tabia yake.
   - Zalisha tena tatizo kwenye mazingira ya ndani kwa kutumia mstari uliobadilishwa na kuendesha test maalum.

2) Imarisha tests ili zithibitishe state, si thamani za matokeo pekee.
   - Ongeza ukaguzi wa mipaka ya usawa (kwa mfano, test threshold `==`).
   - Thibitisha post-conditions: balances, total supply, athari za authorization na events zinazotolewa.

3) Badilisha mocks zinazoruhusu kupita kiasi kwa tabia halisi zaidi.
   - Hakikisha mocks zinathibitisha transfers, njia za kushindwa na utoaji wa events unaotokea on-chain.

4) Ongeza invariants kwa fuzz tests.
   - Kwa mfano, uhifadhi wa thamani, balances zisizo hasi, invariants za authorization, na supply isiyopungua inapohusika.

5) Tofautisha true positives na semantic no-ops.
   - Mfano: `x > 0` -> `x != 0` haina maana pale `x` ni unsigned.

6) Endesha tena kampeni hadi survivors wauwawe au wahalalishwe waziwazi.

## Uchunguzi kifani: kufichua assertions za state zinazokosekana (Arkis protocol)

Kampeni ya mutation wakati wa audit ya Arkis DeFi protocol ilifichua survivors kama hawa:<sup>[[2]](#references)[[3]](#references)</sup>

```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```

Kutoa assignment kwenye comment hakukuvunja tests, ikathibitisha kuwa assertions za hali baada ya operesheni hazipo. Chanzo cha tatizo: code iliamini `_cmd.value` inayodhibitiwa na mtumiaji badala ya kuthibitisha uhamishaji halisi wa tokeni. Mshambulizi angeweza kufanya uhamishaji uliotarajiwa usilingane na uhamishaji halisi ili kutoa fedha zote. Matokeo: hatari kubwa kwa uwezo wa protocol kulipa madeni yake.<sup>[[2]](#references)[[3]](#references)</sup>

Mwongozo: Wachukulie mutants wanaosalia na kuathiri uhamishaji wa thamani, uhasibu au udhibiti wa ufikiaji kuwa hatari kubwa hadi waondolewe.

## Usitengeneze tests bila kufikiri ili kuondoa kila mutant

Uzalishaji wa tests unaoongozwa na mutation unaweza kuleta madhara ikiwa implementation ya sasa si sahihi. Mfano: kubadilisha `priority >= 2` kuwa `priority > 2` hubadilisha tabia, lakini suluhisho sahihi si lazima liwe "andika test ya `priority == 2`". Tabia hiyo yenyewe inaweza kuwa bug.<sup>[[1]](#references)</sup>

Mtiririko salama zaidi:
- Tumia mutants wanaosalia kutambua mahitaji yasiyoeleweka
- Thibitisha tabia inayotarajiwa kwa kutumia specs, nyaraka za protocol au wakaguzi
- Kisha tu, eleza tabia hiyo kama test/invariant

Vinginevyo, unaweza kuweka kwa nguvu makosa ya bahati mbaya ya implementation kwenye test suite na kupata imani isiyo ya kweli.

## Orodha hakiki ya vitendo

- Endesha kampeni inayolenga sehemu husika:
  - `slither-mutate ./src/contracts --test-cmd="forge test"`
- Ikiwezekana, pendelea mutators zinazotambua sintaksia (AST/Tree-sitter) badala ya zinazotegemea regex pekee.
- Chunguza mutants wanaosalia na uandike tests/invariants ambazo zingeshindwa kutokana na tabia iliyobadilishwa.
- Thibitisha salio, supply, authorizations na events.
- Ongeza tests za mipaka (`==`, overflow/underflow, anwani sifuri, kiasi sifuri, arrays tupu).
- Badilisha mocks zisizo halisi; iga hali za kushindwa.
- Hifadhi matokeo ikiwa tooling inaruhusu, na chuja mutants ambao hawakunaswa kabla ya uchunguzi.
- Tumia kampeni za awamu mbili au kwa kila lengo ili muda wa utekelezaji ubaki wa kudhibitiwa.
- Rudia hadi mutants wote waondolewe au uhalalishwe kwa maoni na sababu.

## References

- [1] [Upimaji wa mutation kwa enzi ya agentic](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [2] [Tumia upimaji wa mutation kupata bugs ambazo tests zako hazizigundui (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [3] [Ukaguzi wa Usalama wa Arkis DeFi Prime Brokerage (Kiambatisho C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [4] [Slither (GitHub)](https://github.com/crytic/slither)
- [5] [Nyaraka za Slither Mutator](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [6] [mewt](https://github.com/trailofbits/mewt)
- [7] [MuTON](https://github.com/trailofbits/muton)
{{#include ../../banners/hacktricks-training.md}}
