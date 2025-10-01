# Mutation Testing for Solidity with Slither (slither-mutate)

{{#include ../../banners/hacktricks-training.md}}

Mutation testing "tests your tests" kwa kuingiza kwa mfumo mabadiliko madogo (mutants) kwenye code yako ya Solidity na kuendesha tena test suite yako. Ikiwa jaribio linashindwa, mutant huuliwa. Ikiwa majaribio bado yanapita, mutant huishi, ikifichua doa (blind spot) katika test suite yako ambalo coverage ya mstari/tawi haiwezi kugundua.

Wazo kuu: Coverage inaonyesha kuwa code ilitekelezwa; mutation testing inaonyesha kama tabia (behavior) imedhibitishwa kwa kweli.

## Kwa nini coverage inaweza kudanganya

Angalia ukaguzi huu rahisi wa kikomo:
```solidity
function verifyMinimumDeposit(uint256 deposit) public returns (bool) {
if (deposit >= 1 ether) {
return true;
} else {
return false;
}
}
```
Jaribio za unit ambazo zinaangalia tu thamani chini na thamani juu ya kizingiti zinaweza kufikia 100% ujazo wa mistari/matawi, huku zikiwa hazijathibitisha ukomo wa usawa (==). Marekebisho ya `deposit >= 2 ether` bado yangepita katika mitihani hiyo, ikivunja kimya kimya mantiki ya protocol.

Mutation testing inaonyesha pengo hili kwa kubadilisha sharti na kuthibitisha kuwa mitihani yako itashindwa.

## Opereta za mutation za kawaida kwa Solidity

Slither’s mutation engine inatumia mabadiliko madogo yanayobadilisha semantiki, kama:
- Ubadilishaji wa operator: `+` ↔ `-`, `*` ↔ `/`, n.k.
- Ubadilishaji wa assignment: `+=` → `=`, `-=` → `=`
- Ubadilishaji wa constant: isiyo-sifuri → `0`, `true` ↔ `false`
- Kukanusha/kubadilisha sharti ndani ya `if`/loops
- Kuweka mstari mzima kama comment (CR: Comment Replacement)
- Badilisha mstari na `revert()`
- Kubadilisha aina za data: mfano, `int128` → `int64`

Lengo: Angamiza 100% ya mutants waliozalishwa, au toa sababu za wazi kwa waliobaki.

## Kuendesha mutation testing kwa slither-mutate

Mahitaji: Slither v0.10.2+.

- Orodhesha chaguzi na mutators:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Mfano wa Foundry (rekodi matokeo na uhifadhi kumbukumbu kamili):
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Ikiwa hautumii Foundry, badilisha `--test-cmd` na jinsi unavyokimbia majaribio (kwa mfano, `npx hardhat test`, `npm test`).

Artefakti na ripoti huhifadhiwa katika `./mutation_campaign` kwa chaguo-msingi. Mutants wasiokamatwa (waliodumu) hukopiwa huko kwa uchunguzi.

### Kuelewa matokeo

Mistari za ripoti zinaonekana kama ifuatavyo:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- Lebo ndani ya mabano ni mutator alias (kwa mfano, `CR` = Comment Replacement).
- `UNCAUGHT` ina maana majaribio yalipita chini ya tabia iliyobadilishwa → kukosa assertion.

## Kupunguza runtime: peana kipaumbele kwa mutants wenye athari

Kampeni za mutation zinaweza kuchukua saa au siku. Vidokezo vya kupunguza gharama:
- Scope: Anza na contracts/directories muhimu tu, kisha panua.
- Prioritize mutators: Ikiwa mutant wa kipaumbele juu ya mstari anaishi (kwa mfano, mstari mzima umewekwa kama comment), unaweza kuruka varianti zenye kipaumbele kidogo kwa mstari huo.
- Parallelize tests ikiwa runner yako inaruhusu; tumia cache ya dependencies/builds.
- Fail-fast: simama mapema wakati mabadiliko yanaonyesha wazi pengo la assertion.

## Triage workflow kwa mutants wastaajabika

1) Chunguza mstari uliobadilishwa na tabia.
- Reproduce locally kwa kutumia mstari uliobadilishwa na kuendesha test iliyolenga.

2) Imarisha tests ili kuassert state, si thamani za kurudisha tu.
- Ongeza checks za mipaka ya usawa (kwa mfano, test threshold `==`).
- Assert post-conditions: balances, total supply, athari za authorization, na event zilizotolewa.

3) Badilisha mocks zinazoruhusu kupita kiasi na tabia halisi.
- Hakikisha mocks zinetekeleza transfers, failure paths, na event emissions zinazotokea on-chain.

4) Ongeza invariants kwa fuzz tests.
- Mfano: conservation of value, non-negative balances, authorization invariants, monotonic supply pale inapofaa.

5) Endelea kuendesha slither-mutate hadi survivors waangushwe au wawe wamekosewa kwa uwazi.

## Case study: kufichua kukosekana kwa state assertions (Arkis protocol)

Kampeni ya mutation wakati wa audit ya Arkis DeFi protocol ilibaini survivors kama:
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Ku-comment nje assignment hakukuangusha tests, ikathibitisha ukosefu wa post-state assertions. Chanzo cha msingi: msimbo uliamini `_cmd.value` inayodhibitiwa na mtumiaji badala ya kuthibitisha transfers halisi za tokeni. Mshambuliaji angeweza kusababisha kutofanana kati ya transfers zilizotarajiwa na transfers halisi ili kuchoma fedha. Matokeo: hatari ya kiwango cha juu kwa uendelevu wa protocol.

Mwongozo: Chukulia mutants waliobaki ambao huathiri uhamishaji wa thamani, uhasibu, au udhibiti wa upatikanaji kama hatari kubwa hadi waangamizwe.

## Orodha ya vitendo

- Endesha kampeni iliyolenga:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Fanya triage ya mutants waliobaki na andika tests/invariants ambazo zingeshindwa chini ya tabia iliyobadilishwa.
- Thibitisha salio, supply, idhini, na matukio.
- Ongeza boundary tests (`==`, overflows/underflows, zero-address, zero-amount, empty arrays).
- Badilisha mocks zisizo za kweli; iga njia za kushindwa.
- Rudia hadi mutants wote waondolewe au wahakikishwe kwa maoni na mantiki.

## References

- [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [Slither (GitHub)](https://github.com/crytic/slither)

{{#include ../../banners/hacktricks-training.md}}
