# Παγίδες Ασφάλειας των Smart Account του ERC-4337

{{#include ../../banners/hacktricks-training.md}}

Το account abstraction του ERC-4337 μετατρέπει τα wallets σε προγραμματιζόμενα συστήματα. Η βασική ροή είναι **validate-then-execute** σε ολόκληρο το bundle: το `EntryPoint` επικυρώνει κάθε `UserOperation` πριν εκτελέσει οποιαδήποτε από αυτές. Αυτή η σειρά δημιουργεί μη προφανή attack surface όταν η validation είναι permissive, stateful ή ασυνεπής με τους κανόνες simulation των bundlers.

## 1) Παράκαμψη privileged functions μέσω direct call
Οποιαδήποτε externally callable `execute` (ή function που μετακινεί funds) δεν περιορίζεται στο `EntryPoint` (ή σε vetted executor module) μπορεί να κληθεί απευθείας για την αποστράγγιση του account.<sup>[[1]](#references)</sup>
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
Ασφαλές μοτίβο: περιορίστε το σε `EntryPoint` και χρησιμοποιήστε `msg.sender == address(this)` για ροές διαχείρισης/admin και αυτοδιαχείρισης (εγκατάσταση module, αλλαγές validator, upgrades).
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) Unsigned or unchecked gas fields -> fee drain
Εάν η επικύρωση της υπογραφής καλύπτει μόνο την πρόθεση (`callData`) αλλά όχι τα gas-related fields, ένας bundler ή frontrunner μπορεί να διογκώσει τις χρεώσεις και να αποστραγγίσει ETH. Το signed payload πρέπει να δεσμεύει τουλάχιστον:<sup>[[1]](#references)</sup>

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

Defensive pattern: χρησιμοποιήστε το `userOpHash` που παρέχεται από το `EntryPoint` (το οποίο περιλαμβάνει τα gas fields) και/ή θέστε αυστηρό ανώτατο όριο σε κάθε field.<sup>[[1]](#references)</sup>
```solidity
function validateUserOp(UserOperation calldata op, bytes32 userOpHash, uint256)
external
returns (uint256)
{
require(_isApprovedCall(userOpHash, op.signature), "bad sig");
return 0;
}
```
## 3) Clobbering stateful validation (σημασιολογία bundle)
Επειδή όλα τα validations εκτελούνται πριν από οποιοδήποτε execution, η αποθήκευση αποτελεσμάτων validation στο contract state δεν είναι ασφαλής. Ένα άλλο op στο ίδιο bundle μπορεί να το overwrite, με αποτέλεσμα το execution σας να χρησιμοποιεί state που επηρεάζεται από τον attacker.<sup>[[1]](#references)</sup>

Αποφύγετε την εγγραφή storage στο `validateUserOp`. Αν αυτό είναι αναπόφευκτο, χρησιμοποιήστε ως key για τα προσωρινά δεδομένα το `userOpHash` και διαγράψτε τα deterministically μετά τη χρήση τους (προτιμήστε stateless validation).<sup>[[1]](#references)</sup>

## 4) Replay ERC-1271 μεταξύ accounts/chains (missing domain separation)
Το `isValidSignature(bytes32 hash, bytes sig)` πρέπει να συνδέει τις signatures με **αυτό το contract** και **αυτό το chain**. Η ανάκτηση πάνω σε raw hash επιτρέπει το replay των signatures μεταξύ accounts ή chains.<sup>[[1]](#references)</sup>

Χρησιμοποιήστε EIP-712 typed data (το domain περιλαμβάνει `verifyingContract` και `chainId`) και επιστρέψτε την ακριβή ERC-1271 magic value `0x1626ba7e` σε περίπτωση επιτυχίας.<sup>[[1]](#references)</sup>

## 5) Τα reverts δεν κάνουν refund μετά το validation
Μόλις το `validateUserOp` ολοκληρωθεί επιτυχώς, τα fees δεσμεύονται ακόμη και αν το execution κάνει αργότερα revert. Οι attackers μπορούν να υποβάλλουν επανειλημμένα ops που θα αποτύχουν και παρ' όλα αυτά να εισπράττουν fees από το account.<sup>[[1]](#references)</sup>

Για paymasters, η πληρωμή από shared pool στο `validateUserOp` και η χρέωση των users στο `postOp` είναι fragile, επειδή το `postOp` μπορεί να κάνει revert χωρίς να αναιρέσει την πληρωμή. Ασφαλίστε τα funds κατά το validation (ανά-user escrow/deposit), διατηρήστε το `postOp` minimal και non-reverting και υπολογίστε το `paymasterPostOpGasLimit` για το worst-case reimbursement path.<sup>[[1]](#references)</sup>

## 6) Counterfactual deployment / assumptions του factory
Το πρώτο `UserOperation` συχνά περιλαμβάνει `initCode`, το οποίο προκαλεί το deployment του account μέσω ενός **factory** κατά το validation. Αυτό το path είναι εύκολο να μην ελεγχθεί επαρκώς, επειδή εκτελείται μόνο κατά την πρώτη χρήση.<sup>[[2]](#references)</sup>

Συνηθισμένες αστοχίες:

- Το factory/initializer εμπιστεύεται το `msg.sender == entryPoint`, όμως το ERC-4337 deployment path **δεν** καλεί απευθείας το `initCode` από το `EntryPoint`.
- Το salt, ο owner, ο validator ή η διαμόρφωση του module δεν συνδέονται πλήρως με το signed intent, επομένως ένας frontrunner μπορεί να προλάβει το πρώτο deployment και να δεσμεύσει τη counterfactual address με ρυθμίσεις ελεγχόμενες από τον attacker.
- Το factory δεν είναι idempotent, επομένως ένα επαναλαμβανόμενο first-use flow αχρηστεύει το wallet αντί να επιστρέψει τη διεύθυνση που έχει ήδη δημιουργηθεί.

Ασφαλές pattern: υπολογίστε ξανά τον expected sender από τα signed deployment parameters, κάντε το deployment deterministic (συνήθως με `CREATE2`) και κάντε το initialization one-shot.<sup>[[2]](#references)</sup>
```solidity
bytes32 salt = keccak256(abi.encode(owner, validator, saltNonce));
address predicted = Create2.computeAddress(salt, keccak256(initCode));
require(predicted == sender, "bad sender");
```
## 7) Validation logic που απορρίπτουν τα bundlers
Ο κώδικας validation μπορεί να είναι σωστός σε local tests και παρ' όλα αυτά να μην μπορεί να χρησιμοποιηθεί από πραγματικά bundlers. Τα δημόσια bundlers προσομοιώνουν τις `validateUserOp()` / `validatePaymasterUserOp()` off-chain και συνήθως εκτελούν ένα πλήρες `debug_traceCall(handleOps)` πριν από το inclusion.

Αυτό καθιστά τα παρακάτω patterns επικίνδυνα μέσα στο validation:

- Opcodes που εξαρτώνται από το block, όπως `TIMESTAMP`, `NUMBER` ή `BLOCKHASH`
- Εγγραφές στο state, όπως `SSTORE`
- Iteration χωρίς όριο πάνω σε storage
- Αυθαίρετες εξωτερικές κλήσεις ή αναγνώσεις από oracle που μπορούν να αλλάξουν μεταξύ simulation και inclusion

Κακό παράδειγμα:
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
Αντιμετωπίστε το validation ως deterministic, bounded preflight function. Αν χρειάζεστε πραγματικά shared state ή external lookups, μεταφέρετε αυτή την πολυπλοκότητα σε staked/reputation-tracked entities και δοκιμάστε την ακριβή διαδρομή bundler simulation, όχι μόνο unit tests.

## 8) ERC-7702 initialization frontrun
Το ERC-7702 επιτρέπει σε ένα EOA να εκτελεί smart-account code για ένα μόνο tx. Αν το initialization είναι externally callable, ένας frontrunner μπορεί να ορίσει τον εαυτό του ως owner.<sup>[[1]](#references)</sup>

Mitigation: επιτρέψτε το initialization μόνο μέσω **self-call** και μόνο μία φορά.<sup>[[1]](#references)</sup>
```solidity
function initialize(address newOwner) external {
require(msg.sender == address(this), "init: only self");
require(owner == address(0), "already inited");
owner = newOwner;
}
```
## Γρήγοροι έλεγχοι πριν από το merge
- Επικυρώστε τις υπογραφές χρησιμοποιώντας το `userOpHash` του `EntryPoint` (δεσμεύει τα πεδία gas).
- Περιορίστε τις privileged functions στο `EntryPoint` ή/και στο `address(this)`, ανάλογα με την περίπτωση.
- Διατηρήστε το `validateUserOp` stateless, deterministic και συμβατό με τους κανόνες simulation του bundler.
- Επιβάλετε διαχωρισμό domain EIP-712 για το ERC-1271 και επιστρέψτε `0x1626ba7e` σε περίπτωση επιτυχίας.
- Διατηρήστε το `postOp` minimal, bounded και non-reverting· ασφαλίστε τα fees κατά το validation.
- Ελέγξτε ξεχωριστά το πρώτο μονοπάτι `initCode`: deterministic deployment, idempotent συμπεριφορά του factory και one-shot initialization.
- Εκτελέστε πλήρες bundler simulation (`simulateValidation` συν ένα traced `handleOps`) πριν από το shipping.
- Για το ERC-7702, επιτρέψτε init μόνο σε self-call και μόνο μία φορά.



## Αναφορές

- [1] [Έξι λάθη σε ERC-4337 smart accounts (Trail of Bits)](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)
- [2] [ERC-4337: Account Abstraction Using Alt Mempool](https://eips.ethereum.org/EIPS/eip-4337)

{{#include ../../banners/hacktricks-training.md}}
