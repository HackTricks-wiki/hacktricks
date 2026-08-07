# Παγίδες ασφάλειας των Smart Account του ERC-4337

{{#include ../../banners/hacktricks-training.md}}

Η αφαίρεση λογαριασμού του ERC-4337 μετατρέπει τα wallets σε προγραμματιζόμενα συστήματα. Η βασική ροή είναι **validate-then-execute** σε ολόκληρο το bundle: το `EntryPoint` επικυρώνει κάθε `UserOperation` πριν από την εκτέλεση οποιουδήποτε από αυτά. Αυτή η σειρά δημιουργεί μη προφανή επιφάνεια επίθεσης όταν η επικύρωση είναι υπερβολικά permissive, stateful ή ασυνεπής με τους κανόνες προσομοίωσης του bundler.

## 1) Παράκαμψη μέσω direct call προνομιακών συναρτήσεων
Οποιαδήποτε externally callable συνάρτηση `execute` (ή συνάρτηση μεταφοράς κεφαλαίων) που δεν περιορίζεται στο `EntryPoint` (ή σε ένα ελεγμένο executor module) μπορεί να κληθεί απευθείας για την αποστράγγιση του λογαριασμού.<sup>[[1]](#references)</sup>
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
Ασφαλές pattern: περιορίστε το σε `EntryPoint` και χρησιμοποιήστε `msg.sender == address(this)` για ροές admin/self-management (εγκατάσταση module, αλλαγές validator, upgrades).
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) Μη υπογεγραμμένα ή μη ελεγμένα πεδία gas -> fee drain
Αν η επικύρωση της υπογραφής καλύπτει μόνο την πρόθεση (`callData`) αλλά όχι τα πεδία που σχετίζονται με το gas, ένα bundler ή frontrunner μπορεί να αυξήσει τις χρεώσεις και να αποστραγγίσει ETH. Το υπογεγραμμένο payload πρέπει να δεσμεύει τουλάχιστον:<sup>[[1]](#references)</sup>

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

Αμυντικό μοτίβο: χρησιμοποιήστε το `userOpHash` που παρέχεται από το `EntryPoint` (το οποίο περιλαμβάνει τα πεδία gas) ή/και θέστε αυστηρό ανώτατο όριο σε κάθε πεδίο.<sup>[[1]](#references)</sup>
```solidity
function validateUserOp(UserOperation calldata op, bytes32 userOpHash, uint256)
external
returns (uint256)
{
require(_isApprovedCall(userOpHash, op.signature), "bad sig");
return 0;
}
```
## 3) Καταστροφή stateful validation (bundle semantics)
Επειδή όλα τα validations εκτελούνται πριν από οποιοδήποτε execution, η αποθήκευση αποτελεσμάτων validation στο contract state δεν είναι ασφαλής. Ένα άλλο op στο ίδιο bundle μπορεί να το αντικαταστήσει, με αποτέλεσμα το execution σας να χρησιμοποιήσει state που ελέγχεται από τον attacker.<sup>[[1]](#references)</sup>

Αποφύγετε την εγγραφή στο storage μέσα στο `validateUserOp`. Αν αυτό είναι αναπόφευκτο, συνδέστε τα προσωρινά δεδομένα με το `userOpHash` και διαγράψτε τα deterministically μετά τη χρήση τους (προτιμήστε stateless validation).<sup>[[1]](#references)</sup>

## 4) ERC-1271 replay μεταξύ accounts/chains (missing domain separation)
Η `isValidSignature(bytes32 hash, bytes sig)` πρέπει να συνδέει τις υπογραφές με **αυτό το contract** και **αυτό το chain**. Η ανάκτηση πάνω σε ένα raw hash επιτρέπει το replay των υπογραφών μεταξύ accounts ή chains.<sup>[[1]](#references)</sup>

Χρησιμοποιήστε EIP-712 typed data (το domain περιλαμβάνει `verifyingContract` και `chainId`) και επιστρέψτε την ακριβή ERC-1271 magic value `0x1626ba7e` σε περίπτωση επιτυχίας.<sup>[[1]](#references)</sup>

## 5) Τα reverts δεν κάνουν refund μετά το validation
Μόλις το `validateUserOp` ολοκληρωθεί επιτυχώς, τα fees δεσμεύονται, ακόμη κι αν το execution κάνει revert αργότερα. Οι attackers μπορούν να υποβάλλουν επανειλημμένα ops που θα αποτύχουν και παρ' όλα αυτά να εισπράττουν fees από το account.<sup>[[1]](#references)</sup>

Για τα paymasters, η πληρωμή από ένα shared pool στο `validateUserOp` και η χρέωση των χρηστών στο `postOp` είναι εύθραυστη προσέγγιση, επειδή το `postOp` μπορεί να κάνει revert χωρίς να αναιρέσει την πληρωμή. Ασφαλίστε τα funds κατά το validation (με per-user escrow/deposit), διατηρήστε το `postOp` minimal και non-reverting και υπολογίστε το `paymasterPostOpGasLimit` για τη χειρότερη περίπτωση reimbursement path.<sup>[[1]](#references)</sup>

## 6) Counterfactual deployment / παραδοχές factory
Το πρώτο `UserOperation` συχνά περιέχει `initCode`, το οποίο προκαλεί το deployment του account μέσω ενός **factory** κατά το validation. Αυτό το path είναι εύκολο να ελεγχθεί ανεπαρκώς, επειδή εκτελείται μόνο κατά την πρώτη χρήση.<sup>[[2]](#references)</sup>

Συνηθισμένες αστοχίες:

- Το factory/initializer εμπιστεύεται το `msg.sender == entryPoint`, όμως το ERC-4337 deployment path **δεν** καλεί το `initCode` απευθείας από το `EntryPoint`.
- Τα salt, owner, validator ή η διαμόρφωση του module δεν συνδέονται πλήρως με το signed intent, επομένως ένας frontrunner μπορεί να ανταγωνιστεί το πρώτο deployment και να δεσμεύσει τη counterfactual address με settings που ελέγχει ο attacker.
- Το factory δεν είναι idempotent, επομένως ένα επαναλαμβανόμενο first-use flow αχρηστεύει το wallet αντί να επιστρέψει τη διεύθυνση που έχει ήδη δημιουργηθεί.

Ασφαλές pattern: υπολογίστε ξανά τον αναμενόμενο sender από τις signed παραμέτρους deployment, κάντε το deployment deterministic (συνήθως με `CREATE2`) και κάντε το initialization one-shot.<sup>[[2]](#references)</sup>
```solidity
bytes32 salt = keccak256(abi.encode(owner, validator, saltNonce));
address predicted = Create2.computeAddress(salt, keccak256(initCode));
require(predicted == sender, "bad sender");
```
## 7) Validation logic που απορρίπτουν οι bundlers
Ο κώδικας validation μπορεί να είναι σωστός σε local tests και παρ' όλα αυτά να μην μπορεί να χρησιμοποιηθεί σε πραγματικούς bundlers. Οι public bundlers προσομοιώνουν τα `validateUserOp()` / `validatePaymasterUserOp()` off-chain και συνήθως εκτελούν ένα πλήρες `debug_traceCall(handleOps)` πριν από την inclusion.<sup>[[3]](#references)</sup>

Αυτό καθιστά τα ακόλουθα patterns επικίνδυνα μέσα στο validation:

- Opcodes που εξαρτώνται από το block, όπως `TIMESTAMP`, `NUMBER` ή `BLOCKHASH`
- State writes, όπως `SSTORE`
- Unbounded iteration πάνω σε storage
- Arbitrary external calls ή oracle reads που μπορούν να αλλάξουν μεταξύ simulation και inclusion

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
Αντιμετωπίστε το validation ως μια deterministic, bounded preflight function. Αν χρειάζεστε πραγματικά shared state ή external lookups, μεταφέρετε αυτή την πολυπλοκότητα σε staked/reputation-tracked entities και δοκιμάστε το ακριβές bundler simulation path, όχι μόνο unit tests.

## 8) Frontrun κατά την αρχικοποίηση του ERC-7702
Το ERC-7702 επιτρέπει σε ένα EOA να εκτελεί κώδικα smart account για ένα μόνο tx. Αν η αρχικοποίηση είναι externally callable, ένας frontrunner μπορεί να ορίσει τον εαυτό του ως owner.<sup>[[1]](#references)</sup>

Mitigation: επιτρέψτε την αρχικοποίηση μόνο μέσω **self-call** και μόνο μία φορά.<sup>[[1]](#references)</sup>
```solidity
function initialize(address newOwner) external {
require(msg.sender == address(this), "init: only self");
require(owner == address(0), "already inited");
owner = newOwner;
}
```
## Γρήγοροι έλεγχοι πριν από το merge
- Επικυρώστε τις υπογραφές χρησιμοποιώντας το `userOpHash` του `EntryPoint` (δεσμεύει τα πεδία gas).
- Περιορίστε τις privileged functions στα `EntryPoint` και/ή `address(this)`, ανάλογα με την περίπτωση.
- Διατηρήστε το `validateUserOp` stateless, deterministic και συμβατό με τους κανόνες simulation του bundler.
- Επιβάλετε διαχωρισμό domain μέσω EIP-712 για το ERC-1271 και επιστρέψτε `0x1626ba7e` σε περίπτωση επιτυχίας.
- Διατηρήστε το `postOp` minimal, bounded και non-reverting· ασφαλίστε τα fees κατά την επικύρωση.
- Ελέγξτε ξεχωριστά το πρώτο μονοπάτι `initCode`: deterministic deployment, idempotent συμπεριφορά του factory και one-shot initialization.
- Εκτελέστε πλήρες bundler simulation (`simulateValidation` καθώς και ένα traced `handleOps`) πριν από το release.
- Για το ERC-7702, επιτρέψτε init μόνο σε self-call και μόνο μία φορά.

## Αναφορές

- [1] [Έξι λάθη σε ERC-4337 smart accounts (Trail of Bits)](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)
- [2] [ERC-4337: Account Abstraction με χρήση Alt Mempool](https://eips.ethereum.org/EIPS/eip-4337)
- [3] [ERC-7562: Κανόνες Scope επικύρωσης για Account Abstraction](https://eips.ethereum.org/EIPS/eip-7562)

{{#include ../../banners/hacktricks-training.md}}
