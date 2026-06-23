# Παγίδες Ασφάλειας Smart Account ERC-4337

{{#include ../../banners/hacktricks-training.md}}

Το ERC-4337 account abstraction μετατρέπει τα wallets σε προγραμματιζόμενα συστήματα. Η βασική ροή είναι **validate-then-execute** σε ολόκληρο το bundle: το `EntryPoint` επικυρώνει κάθε `UserOperation` πριν εκτελέσει οποιοδήποτε από αυτά. Αυτή η σειρά δημιουργεί μη προφανή attack surface όταν το validation είναι permissive, stateful, ή ασύμβατο με τους κανόνες simulation του bundler.

## 1) Direct-call bypass of privileged functions
Οποιαδήποτε externally callable `execute` (ή fund-moving) function που δεν περιορίζεται στο `EntryPoint` (ή σε ένα vetted executor module) μπορεί να κληθεί άμεσα για να αδειάσει το account.
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
Ασφαλές μοτίβο: περιορίστε σε `EntryPoint`, και χρησιμοποιήστε `msg.sender == address(this)` για admin/self-management ροές (module install, validator changes, upgrades).
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) Μη υπογεγραμμένα ή μη ελεγχόμενα gas fields -> fee drain
Αν η επικύρωση της υπογραφής καλύπτει μόνο την πρόθεση (`callData`) αλλά όχι τα gas-related fields, ένας bundler ή frontrunner μπορεί να διογκώσει τα fees και να drain ETH. Το signed payload πρέπει να δένει τουλάχιστον τα εξής:

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

Defensive pattern: χρησιμοποίησε το `EntryPoint`-provided `userOpHash` (το οποίο περιλαμβάνει gas fields) και/ή όρισε αυστηρό cap σε κάθε field.
```solidity
function validateUserOp(UserOperation calldata op, bytes32 userOpHash, uint256)
external
returns (uint256)
{
require(_isApprovedCall(userOpHash, op.signature), "bad sig");
return 0;
}
```
## 3) Stateful validation clobbering (bundle semantics)
Επειδή όλες οι validations τρέχουν πριν από οποιαδήποτε execution, η αποθήκευση validation results στο contract state είναι unsafe. Ένα άλλο op στο ίδιο bundle μπορεί να το overwrite, προκαλώντας η execution σου να χρησιμοποιήσει attacker-influenced state.

Απόφυγε να γράφεις storage στο `validateUserOp`. Αν είναι αναπόφευκτο, κλείδωσε προσωρινά δεδομένα με `userOpHash` και διέγραψέ τα deterministically μετά τη χρήση (προτίμησε stateless validation).

## 4) ERC-1271 replay across accounts/chains (missing domain separation)
Το `isValidSignature(bytes32 hash, bytes sig)` πρέπει να δένει signatures με **αυτό το contract** και **αυτή την chain**. Η ανάκτηση πάνω σε raw hash επιτρέπει σε signatures να replay across accounts ή chains.

Χρησιμοποίησε EIP-712 typed data (το domain περιλαμβάνει `verifyingContract` και `chainId`) και επέστρεψε την ακριβή ERC-1271 magic value `0x1626ba7e` on success.

## 5) Reverts do not refund after validation
Μόλις το `validateUserOp` πετύχει, τα fees δεσμεύονται ακόμη κι αν η execution αργότερα revert. Attackers μπορούν επανειλημμένα να submit ops που θα fail και παρ’ όλα αυτά να collect fees από το account.

Για paymasters, το να πληρώνεις από ένα shared pool στο `validateUserOp` και να χρεώνεις users στο `postOp` είναι fragile γιατί το `postOp` μπορεί να revert χωρίς να αναιρέσει την πληρωμή. Ασφάλισε funds κατά τη validation (per-user escrow/deposit), κράτα το `postOp` minimal και non-reverting, και προϋπολόγισε `paymasterPostOpGasLimit` για τη χειρότερη πιθανή reimbursement path.

## 6) Counterfactual deployment / factory assumptions
Το πρώτο `UserOperation` συχνά φέρει `initCode`, το οποίο προκαλεί το account να deploy μέσω ενός **factory** κατά τη validation. Αυτό το path είναι εύκολο να under-audit επειδή τρέχει μόνο στο πρώτο use.

Συνηθισμένα failures:

- Το factory/initializer trustάρει `msg.sender == entryPoint`, αλλά το ERC-4337 deployment path δεν καλεί το `initCode` directly από `EntryPoint`.
- Το salt, owner, validator, ή η module configuration δεν δένεται πλήρως με signed intent, οπότε ένας frontrunner μπορεί να race το πρώτο deployment και να burn το counterfactual address με attacker-controlled settings.
- Το factory είναι non-idempotent, οπότε ένα repeated first-use flow bricks το wallet αντί να επιστρέψει το ήδη-created address.

Safe pattern: υπολόγισε ξανά το expected sender από signed deployment parameters, κάνε το deployment deterministic (συνήθως `CREATE2`), και κάνε την initialization one-shot.
```solidity
bytes32 salt = keccak256(abi.encode(owner, validator, saltNonce));
address predicted = Create2.computeAddress(salt, keccak256(initCode));
require(predicted == sender, "bad sender");
```
## 7) Validation logic that bundlers reject
Ο κώδικας validation μπορεί να είναι σωστός σε τοπικά tests και παρ' όλα αυτά να είναι μη χρησιμοποιήσιμος σε πραγματικούς bundlers. Οι public bundlers προσομοιώνουν τα `validateUserOp()` / `validatePaymasterUserOp()` off-chain και συνήθως εκτελούν ένα πλήρες `debug_traceCall(handleOps)` πριν από την inclusion.

Αυτό κάνει αυτά τα patterns επικίνδυνα μέσα στο validation:

- Opcodes που εξαρτώνται από το Block, όπως `TIMESTAMP`, `NUMBER`, ή `BLOCKHASH`
- State writes όπως `SSTORE`
- Unbounded iteration πάνω σε storage
- Arbitrary external calls ή oracle reads που μπορούν να αλλάξουν μεταξύ simulation και inclusion

Bad example:
```solidity
function validateUserOp(UserOperation calldata op, bytes32 userOpHash, uint256)
external
returns (uint256)
{
require(block.timestamp < expiry, "expired");
seen[userOpHash] = true; // SSTORE in validation
require(oracle.isAllowed(op.sender), "oracle changed");
return 0;
}
```
Να αντιμετωπίζετε την επικύρωση ως μια ντετερμινιστική, περιορισμένη preflight function. Αν πραγματικά χρειάζεστε shared state ή external lookups, μεταφέρετε αυτή την πολυπλοκότητα σε staked/reputation-tracked entities και δοκιμάστε το exact bundler simulation path, όχι μόνο unit tests.

## 8) ERC-7702 initialization frontrun
Το ERC-7702 επιτρέπει σε ένα EOA να εκτελεί smart-account code για ένα μόνο tx. Αν η initialization είναι externally callable, ένας frontrunner μπορεί να ορίσει τον εαυτό του ως owner.

Mitigation: επιτρέψτε την initialization μόνο σε **self-call** και μόνο μία φορά.
```solidity
function initialize(address newOwner) external {
require(msg.sender == address(this), "init: only self");
require(owner == address(0), "already inited");
owner = newOwner;
}
```
## Γρήγοροι έλεγχοι πριν το merge
- Επικύρωσε τις υπογραφές χρησιμοποιώντας το `userOpHash` του `EntryPoint` (δένει τα gas fields).
- Περιορίστε τις privileged functions στο `EntryPoint` και/ή στο `address(this)` όπως αρμόζει.
- Κράτα το `validateUserOp` stateless, deterministic και συμβατό με τους bundler simulation rules.
- Εφάρμοσε EIP-712 domain separation για ERC-1271 και επέστρεφε `0x1626ba7e` σε επιτυχία.
- Κράτα το `postOp` minimal, bounded και non-reverting· ασφάλισε τα fees κατά τη validation.
- Δοκίμασε ξεχωριστά το πρώτο `initCode` path: deterministic deployment, idempotent factory behavior και one-shot initialization.
- Τρέξε πλήρες bundler simulation (`simulateValidation` plus ένα traced `handleOps`) πριν το shipping.
- Για ERC-7702, επέτρεψε init μόνο σε self-call και μόνο μία φορά.



## Αναφορές

- [https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)
- [https://eips.ethereum.org/EIPS/eip-4337](https://eips.ethereum.org/EIPS/eip-4337)
{{#include ../../banners/hacktricks-training.md}}
