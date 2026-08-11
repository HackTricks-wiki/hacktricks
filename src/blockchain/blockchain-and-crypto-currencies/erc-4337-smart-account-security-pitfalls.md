# ERC-4337 Smart Account-sekuriteitsvalkuilen

{{#include ../../banners/hacktricks-training.md}}

ERC-4337-rekeningabstraksie verander wallets in programmeerbare stelsels. Die kernvloei is **validate-then-execute** oor ’n hele bundle: die `EntryPoint` valideer elke `UserOperation` voordat enige daarvan uitgevoer word.<sup>[[5]](#references)</sup> Hierdie volgorde skep ’n nie-vanselfsprekende attack surface wanneer validasie permissief, stateful of inkonsekwent met bundler-simulasie-reëls is.

## 1) Direct-call-bypass van bevoorregte funksies
Enige ekstern-aanroeibare `execute`- (of fondsoordrag-)funksie wat nie tot `EntryPoint` (of ’n gekeurde executor-module) beperk is nie, kan direk aangeroep word om die rekening te drain.<sup>[[2]](#references)</sup>
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
Veilige patroon: beperk tot `EntryPoint`, en gebruik `msg.sender == address(this)` vir admin/self-bestuur-vloeie (module-installasie, validatorveranderinge, opgraderings).<sup>[[2]](#references)[[5]](#references)</sup>
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) Ongetekende of ongekontroleerde gas-velde -> fee drain
As signature validation slegs intent (`callData`) dek, maar nie gas-verwante velde nie, kan ’n bundler of frontrunner fooie verhoog en ETH dreineer. Die signed payload moet ten minste die volgende bind:<sup>[[2]](#references)</sup>

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

Defensive pattern: gebruik die `EntryPoint`-verskafde `userOpHash` (wat gas-velde insluit) en/of beperk elke veld streng.<sup>[[2]](#references)[[5]](#references)</sup>
```solidity
function validateUserOp(UserOperation calldata op, bytes32 userOpHash, uint256)
external
returns (uint256)
{
require(_isApprovedCall(userOpHash, op.signature), "bad sig");
return 0;
}
```
## 3) Stateful validation clobbering (bundle-semantiek)
Omdat alle validations voor enige execution uitgevoer word, is dit onveilig om validation-resultate in contract state te stoor. Nog ’n op in dieselfde bundle kan dit oorskryf, wat veroorsaak dat jou execution state gebruik wat deur ’n attacker beïnvloed word.<sup>[[2]](#references)</sup>

Vermy die skryf van storage in `validateUserOp`. Indien dit onvermydelik is, sleutel tydelike data volgens `userOpHash` en skrap dit deterministies ná gebruik (verkies stateless validation).<sup>[[2]](#references)</sup>

## 4) ERC-1271 replay across accounts/chains (ontbrekende domain separation)
`isValidSignature(bytes32 hash, bytes sig)` moet signatures aan **hierdie contract** en **hierdie chain** bind. Die herstel oor ’n raw hash laat signatures toe om oor accounts of chains heen hergebruik te word.<sup>[[1]](#references)[[4]](#references)</sup>

Gebruik EIP-712 typed data (domain sluit `verifyingContract` en `chainId` in) en return die presiese ERC-1271 magic value `0x1626ba7e` by sukses.<sup>[[3]](#references)[[4]](#references)</sup>

## 5) Reverts do not refund after validation
Sodra `validateUserOp` suksesvol is, is fees verbind, selfs al revert execution later. Attackers kan herhaaldelik ops indien wat sal fail en steeds fees van die account invorder.<sup>[[2]](#references)</sup>

Vir paymasters is betaling uit ’n shared pool in `validateUserOp` en die charging van users in `postOp` broos, omdat `postOp` kan revert sonder om die betaling ongedaan te maak. Beveilig fondse tydens validation (per-user escrow/deposit), hou `postOp` minimaal en nie-reverting, en begroot `paymasterPostOpGasLimit` vir die worst-case reimbursement path.<sup>[[2]](#references)[[5]](#references)</sup>

## 6) Counterfactual deployment / factory assumptions
Die eerste `UserOperation` bevat dikwels `initCode`, wat veroorsaak dat die account deur ’n **factory** tydens validation gedeploy word. Hierdie path word maklik onvoldoende ge-audit omdat dit slegs by eerste gebruik loop.<sup>[[5]](#references)</sup>

Algemene failures sluit in:<sup>[[5]](#references)</sup>

- Die factory/initializer vertrou op `msg.sender == entryPoint`, maar die ERC-4337 deployment path roep **nie** `initCode` direk vanaf `EntryPoint` nie.
- Die salt, owner, validator of module configuration is nie volledig aan signed intent gebind nie, dus kan ’n frontrunner die eerste deployment race en die counterfactual address met attacker-beheerde settings verbrand.
- Die factory is nie-idempotent nie, dus maak ’n herhaalde first-use flow die wallet onbruikbaar in plaas daarvan om die reeds-geskepte address terug te gee.

Veilige patroon: bereken die verwagte sender opnuut uit signed deployment parameters, maak deployment deterministies (tipies `CREATE2`), en maak initialization eenmalig.<sup>[[5]](#references)</sup>
```solidity
bytes32 salt = keccak256(abi.encode(owner, validator, saltNonce));
address predicted = Create2.computeAddress(salt, keccak256(initCode));
require(predicted == sender, "bad sender");
```
## 7) Valideringslogika wat bundlers verwerp
Valideringskode kan korrek wees in plaaslike toetse en steeds onbruikbaar wees in werklike bundlers. Bundlers voer validering verskeie kere uit en behoort ’n volledige traced-bundle-validering voor indiening uit te voer.<sup>[[6]](#references)</sup>

Onder daardie valideringsomvangreëls is hierdie patrone gevaarlik:<sup>[[6]](#references)</sup>

- Blokafhanklike opcodes soos `TIMESTAMP`, `NUMBER`, of `BLOCKHASH`
- Stoortoegang buite die toegelate rekening-/entiteitsomvang, of onbegrensde iterasie oor storage
- Eksterne oproepe of oracle-leesbewerkings wat afhanklik is van veranderlike toestand buite die toegelate valideringsomvang

Slegte voorbeeld:
```solidity
function validateUserOp(UserOperation calldata op, bytes32 userOpHash, uint256)
external
returns (uint256)
{
require(block.timestamp < expiry, "expired");
seen[userOpHash] = true; // stateful validation can be clobbered by another op
require(oracle.isAllowed(op.sender), "oracle changed");
return 0;
}
```
Behandel validation as 'n deterministiese, begrensde preflight-funksie. Indien shared state of external lookups nodig is, volg die staked-entity-reëls en toets dieselfde multi-pass bundler simulation path, nie net unit tests nie.<sup>[[6]](#references)</sup>

## 8) ERC-7702 initialization frontrun
ERC-7702 gee aan 'n EOA 'n permanente delegation na smart-account-kode; die delegation voer initialization nie atomies uit nie. Indien initialization extern callable is, kan 'n waarnemer dit front-run en homself as owner instel.<sup>[[7]](#references)</sup>

Mitigation: vereis dat initialization calldata deur die EOA gemagtig word en laat initialization slegs een keer toe. In 'n ERC-4337 EIP-7702-flow moet die caller ook tot `EntryPoint.senderCreator()` beperk word.<sup>[[5]](#references)[[7]](#references)</sup>
```solidity
function initialize(address newOwner, bytes calldata initSig) external {
require(owner == address(0), "already inited");
// Verify the EOA's signature over the complete initialization calldata.
require(_isAuthorizedByEOA(newOwner, initSig), "bad init auth");
owner = newOwner;
}
```
## Vinnige pre-merge checks
- Validateer handtekeninge met `EntryPoint` se `userOpHash` (bind gas-velde).
- Beperk bevoorregte funksies tot `EntryPoint` en/of `address(this)` soos toepaslik.
- Hou `validateUserOp` stateless, deterministies en versoenbaar met bundler-simulasie-reëls.
- Dwing EIP-712-domeinskeiding af vir ERC-1271 en gee `0x1626ba7e` terug by sukses.
- Hou `postOp` minimaal, begrens en non-reverting; beveilig fooie tydens validasie.
- Toets die eerste `initCode`-pad afsonderlik: deterministiese deployment, idempotente factory-gedrag en eenmalige initialisering.
- Voer die bundler se multi-pass-validasie en ’n traced full-bundle check uit voordat dit vrygestel word.
- Vir ERC-7702, bind init aan EOA-autorisering en laat dit slegs een keer toe; in ERC-4337-vloeie, beperk die caller tot `EntryPoint.senderCreator()`.

## References

- [1] [ERC1271 Replay - 15+ spanne geraak (curiousapple)](https://paragraph.com/@curiousapple/fwlBuaAuGsWwLRPTLKxB)
- [2] [Ses foute in ERC-4337 smart accounts (Trail of Bits)](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)
- [3] [ERC-1271: Standaardmetode vir handtekeningvalidasie vir kontrakte](https://eips.ethereum.org/EIPS/eip-1271)
- [4] [EIP-712: Hashing en ondertekening van getipeerde gestruktureerde data](https://eips.ethereum.org/EIPS/eip-712)
- [5] [ERC-4337: Account Abstraction met behulp van Alt Mempool](https://eips.ethereum.org/EIPS/eip-4337)
- [6] [ERC-7562: Reëls vir die validasies omvang van Account Abstraction](https://eips.ethereum.org/EIPS/eip-7562)
- [7] [EIP-7702: Stel kode vir EOA’s](https://eips.ethereum.org/EIPS/eip-7702)
{{#include ../../banners/hacktricks-training.md}}
