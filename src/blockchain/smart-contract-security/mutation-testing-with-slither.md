# Mutation Testing for Solidity with Slither (slither-mutate)

{{#include ../../banners/hacktricks-training.md}}

Mutation testing "tests your tests" kwa kuingiza mabadiliko madogo (mutants) kwa mfumo katika code yako ya Solidity na kuendesha tena test suite yako. Ikiwa test itashindwa, mutant anaangamizwa. Ikiwa tests bado zinafaulu, mutant huishi, ikifichua pengo la upofu katika test suite yako ambalo line/branch coverage haiwezi kugundua.

Wazo muhimu: Coverage inaonyesha code ilitekelezwa; mutation testing inaonyesha ikiwa tabia kwa kweli imethibitishwa.

## Kwa nini coverage inaweza kudanganya

Fikiria ukaguzi huu rahisi wa kikomo:
```solidity
function verifyMinimumDeposit(uint256 deposit) public returns (bool) {
if (deposit >= 1 ether) {
return true;
} else {
return false;
}
}
```
Unit tests ambazo zinachek tu thamani chini na thamani juu ya kizingiti zinaweza kufikia 100% line/branch coverage huku zikishindwa kuthibitisha mpaka wa usawa (==). Refactor kuwa `deposit >= 2 ether` bado ingepita mitihani hiyo, ikivunja mantiki ya protocol bila kuonekana.

Mutation testing inaonyesha pengo hili kwa kubadilisha condition na kuthibitisha kwamba mitihani yako inashindwa.

## Operator za mutation za kawaida za Solidity

Slither’s mutation engine inatumia mabadiliko madogo mengi yanayobadilisha semantiki, kama:
- Operator replacement: `+` ↔ `-`, `*` ↔ `/`, etc.
- Assignment replacement: `+=` → `=`, `-=` → `=`
- Constant replacement: non-zero → `0`, `true` ↔ `false`
- Condition negation/replacement inside `if`/loops
- Comment out whole lines (CR: Comment Replacement)
- Replace a line with `revert()`
- Data type swaps: e.g., `int128` → `int64`

Lengo: Ua 100% ya mutants waliotengenezwa, au toa sababu za wazi kwa wale wanaobaki.

## Kuendesha mutation testing na slither-mutate

Mahitaji: Slither v0.10.2+.

- List options and mutators:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Mfano wa Foundry (rekodi matokeo na uhifadhi logi kamili):
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Ikiwa hutoitumia Foundry, badilisha `--test-cmd` na jinsi unavyotekeleza majaribio (kwa mfano, `npx hardhat test`, `npm test`).

Artifacts na ripoti huhifadhiwa katika `./mutation_campaign` kwa chaguo-msingi. Mutants zisizogunduliwa (zilizo hai) zinakopishwa huko kwa uchunguzi.

### Kuelewa matokeo

Mistari ya ripoti zinaonekana kama:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- Tagi ndani ya mabano ni jina fupi la mutator (kwa mfano, `CR` = Comment Replacement).
- `UNCAUGHT` ina maana majaribio yalipita chini ya tabia iliyobadilishwa → ukosefu wa uthibitisho.

## Kupunguza muda wa utekelezaji: weka kipaumbele mutanti zenye athari

Kampeni za mutation zinaweza kuchukua masaa au siku. Vidokezo vya kupunguza gharama:
- Scope: Anza na mikataba/direktori muhimu tu, kisha panua.
- Prioritize mutators: Ikiwa mutanti wa kipaumbele juu kwenye mstari anakaa (kwa mfano, mstari mzima umekomentiwa), unaweza kupuuza tofauti zenye kipaumbele cha chini kwa mstari huo.
- Endesha majaribio kwa usawa ikiwa runner yako inaruhusu; tumia cache kwa dependencies/builds.
- Fail-fast: simama mapema wakati mabadiliko yanaonyesha wazi ukosefu wa uthibitisho.

## Mtiririko wa kazi wa triage kwa mutanti waliobaki

1) Angalia mstari uliobadilishwa na tabia yake.
- Rudia ndani ya mazingira ya ndani kwa kuingiza mstari uliobadilishwa na kuendesha test iliyojikita.

2) Imarisha majaribio ili yathibishe hali, si tu thamani zinazorejeshwa.
- Ongeza ukaguzi wa mipaka ya usawa (kwa mfano, test threshold `==`).
- Thibitisha masharti ya baada: salio, total supply, athari za idhini, na matukio yaliyotolewa.

3) Badilisha mocks zilizoruhusu mno kwa tabia halisi.
- Hakikisha mocks zinafanya enforced transfers, njia za kushindwa, na utoaji wa matukio yanayotokea on-chain.

4) Ongeza invariants kwa fuzz tests.
- Kwa mfano, uhifadhi wa thamani, salio zisizo hasi, invariants za idhini, supply monotonic pale inapofaa.

5) Rerun slither-mutate hadi mutanti waliobaki waondolewe au wathibitishwe wazi.

## Utafiti wa kesi: kufichua ukosefu wa uthibitisho wa hali (Arkis protocol)

Kampeni ya mutation wakati wa ukaguzi wa protokoli ya Arkis DeFi ilibaini mutanti waliobaki kama:
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Ku-comment out ugawaji hakukuvunja majaribio, ikathibitisha kukosekana kwa post-state assertions. Sababu ya msingi: msimbo uliamini `_cmd.value` inayoendeshwa na mtumiaji badala ya kuthibitisha uhamisho halisi wa tokeni. Mvamizi angeweza kusababisha kutolingana kati ya uhamisho uliotarajiwa na uhalisi ili kuchoma/mkamua fedha. Matokeo: hatari ya kiwango cha juu kwa uendelevu wa protocol.

Miongozo: Chukulia mabaki yanayoathiri uhamisho wa thamani, uhasibu, au udhibiti wa upatikanaji kama hatari kubwa hadi yatakaposhindwa/kufutwa.

## Orodha ya vitendo

- Endesha kampeni iliyolengwa:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Fanyia triage mabaki na andika tests/invariants zitakazoshindwa chini ya tabia iliyobadilishwa.
- Thibitisha salio, ugavi, idhini, na matukio.
- Ongeza mtihani wa mipaka (`==`, overflows/underflows, zero-address, zero-amount, empty arrays).
- Badilisha mocks zisizo halisi;iga njia za kushindwa.
- Rudia hadi mutants zote zimeshindikana/kufutwa (killed) au zimefafanuliwa kwa maoni na mantiki.

## Marejeo

- [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [Slither (GitHub)](https://github.com/crytic/slither)

{{#include ../../banners/hacktricks-training.md}}
