# Παγίδες ασφάλειας Smart Account του ERC-4337

Το account abstraction του ERC-4337 μετατρέπει τα wallets σε προγραμματιζόμενα συστήματα. Η βασική ροή είναι **validate-then-execute** σε ολόκληρο το bundle: το `EntryPoint` κάνει validate σε κάθε `UserOperation` πριν εκτελέσει οποιαδήποτε από αυτές.<sup>[[5]](#references)</sup> Αυτή η σειρά δημιουργεί μη προφανές attack surface όταν το validation είναι permissive, stateful ή ασυνεπές με τους κανόνες simulation του bundler.

## 1) Παράκαμψη direct-call προνομιακών συναρτήσεων
Οποιαδήποτε externally callable συνάρτηση `execute` (ή συνάρτηση μεταφοράς κεφαλαίων) που δεν περιορίζεται στο `EntryPoint` (ή σε ένα ελεγμένο executor module) μπορεί να κληθεί απευθείας για την αποστράγγιση του account.<sup>[[2]](#references)</sup>
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
Ασφαλές pattern: περιορίστε το στο `EntryPoint` και χρησιμοποιήστε `msg.sender == address(this)` για ροές admin/self-management (εγκατάσταση module, αλλαγές validator, upgrades).<sup>[[2]](#references)[[5]](#references)</sup>
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) Μη υπογεγραμμένα ή μη ελεγμένα πεδία gas -> εξάντληση χρημάτων μέσω fees
Αν η επικύρωση της υπογραφής καλύπτει μόνο την πρόθεση (`callData`) αλλά όχι τα πεδία που σχετίζονται με το gas, ένας bundler ή frontrunner μπορεί να διογκώσει τα fees και να εξαντλήσει το ETH. Το υπογεγραμμένο payload πρέπει να δεσμεύει τουλάχιστον τα εξής:<sup>[[2]](#references)</sup>

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

Αμυντικό μοτίβο: χρησιμοποιήστε το `userOpHash` που παρέχεται από το `EntryPoint` (και περιλαμβάνει τα πεδία gas) ή/και θέστε αυστηρό ανώτατο όριο σε κάθε πεδίο.<sup>[[2]](#references)[[5]](#references)</sup>
```solidity
function validateUserOp(UserOperation calldata op, bytes32 userOpHash, uint256)
external
returns (uint256)
{
require(_isApprovedCall(userOpHash, op.signature), "bad sig");
return 0;
}
```
## 3) Καταστροφή stateful validation (σημασιολογία bundle)
Επειδή όλα τα validations εκτελούνται πριν από οποιοδήποτε execution, η αποθήκευση αποτελεσμάτων validation στο contract state δεν είναι ασφαλής. Ένα άλλο op στο ίδιο bundle μπορεί να το αντικαταστήσει, με αποτέλεσμα το execution σας να χρησιμοποιεί state που επηρεάζεται από τον attacker.<sup>[[2]](#references)</sup>

Αποφύγετε την εγγραφή storage στο `validateUserOp`. Αν αυτό είναι αναπόφευκτο, συσχετίστε τα προσωρινά δεδομένα με το `userOpHash` και διαγράψτε τα ντετερμινιστικά μετά τη χρήση τους (προτιμήστε stateless validation).<sup>[[2]](#references)</sup>

## 4) Replay του ERC-1271 μεταξύ accounts/chains (έλλειψη domain separation)
Το `isValidSignature(bytes32 hash, bytes sig)` πρέπει να συνδέει τις signatures με **αυτό το contract** και **αυτό το chain**. Η ανάκτηση πάνω σε ένα raw hash επιτρέπει το replay των signatures μεταξύ accounts ή chains.<sup>[[1]](#references)[[4]](#references)</sup>

Χρησιμοποιήστε typed data του EIP-712 (το domain περιλαμβάνει `verifyingContract` και `chainId`) και επιστρέψτε την ακριβή magic value του ERC-1271 `0x1626ba7e` σε περίπτωση επιτυχίας.<sup>[[3]](#references)[[4]](#references)</sup>

## 5) Τα reverts δεν κάνουν refund μετά το validation
Μόλις το `validateUserOp` ολοκληρωθεί επιτυχώς, τα fees δεσμεύονται, ακόμη και αν το execution κάνει revert αργότερα. Οι attackers μπορούν να υποβάλλουν επανειλημμένα ops που θα αποτύχουν και παρ’ όλα αυτά να εισπράττουν fees από το account.<sup>[[2]](#references)</sup>

Για τα paymasters, η πληρωμή από ένα shared pool στο `validateUserOp` και η χρέωση των χρηστών στο `postOp` είναι εύθραυστη, επειδή το `postOp` μπορεί να κάνει revert χωρίς να αναιρέσει την πληρωμή. Ασφαλίστε τα funds κατά το validation (ανά-user escrow/deposit), διατηρήστε το `postOp` minimal και non-reverting και υπολογίστε το `paymasterPostOpGasLimit` για τη χειρότερη διαδρομή reimbursement.<sup>[[2]](#references)[[5]](#references)</sup>

## 6) Counterfactual deployment / υποθέσεις factory
Το πρώτο `UserOperation` συχνά περιέχει `initCode`, το οποίο προκαλεί το deployment του account μέσω ενός **factory** κατά το validation. Αυτό το path είναι εύκολο να ελεγχθεί ανεπαρκώς, επειδή εκτελείται μόνο κατά την πρώτη χρήση.<sup>[[5]](#references)</sup>

Συνηθισμένες αστοχίες περιλαμβάνουν:<sup>[[5]](#references)</sup>

- Το factory/initializer εμπιστεύεται ότι `msg.sender == entryPoint`, όμως το deployment path του ERC-4337 **δεν** καλεί απευθείας το `initCode` από το `EntryPoint`.
- Τα salt, owner, validator ή η διαμόρφωση του module δεν συνδέονται πλήρως με το signed intent, επομένως ένας frontrunner μπορεί να προλάβει το πρώτο deployment και να δεσμεύσει τη counterfactual address με ρυθμίσεις που ελέγχει ο attacker.
- Το factory δεν είναι idempotent, επομένως ένα επαναλαμβανόμενο flow πρώτης χρήσης αχρηστεύει το wallet αντί να επιστρέψει τη διεύθυνση που έχει ήδη δημιουργηθεί.

Ασφαλές pattern: υπολογίστε ξανά τον αναμενόμενο sender από τις signed παραμέτρους deployment, κάντε το deployment deterministic (συνήθως με `CREATE2`) και κάντε το initialization one-shot.<sup>[[5]](#references)</sup>
```solidity
bytes32 salt = keccak256(abi.encode(owner, validator, saltNonce));
address predicted = Create2.computeAddress(salt, keccak256(initCode));
require(predicted == sender, "bad sender");
```
## 7) Λογική validation που απορρίπτουν οι bundlers
Ο κώδικας validation μπορεί να είναι σωστός σε local tests και παρ' όλα αυτά να μην μπορεί να χρησιμοποιηθεί σε πραγματικούς bundlers. Οι bundlers εκτελούν τη validation πολλές φορές και πρέπει να πραγματοποιούν traced full-bundle validation πριν από την υποβολή.<sup>[[6]](#references)</sup>

Σύμφωνα με αυτούς τους κανόνες scope της validation, τα παρακάτω patterns είναι επικίνδυνα:<sup>[[6]](#references)</sup>

- Opcodes που εξαρτώνται από το block, όπως `TIMESTAMP`, `NUMBER` ή `BLOCKHASH`
- Πρόσβαση σε storage εκτός του επιτρεπόμενου scope του account/entity ή unbounded iteration πάνω σε storage
- External calls ή oracle reads που εξαρτώνται από mutable state εκτός του επιτρεπόμενου scope της validation

Κακό παράδειγμα:
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
Αν απαιτούνται shared state ή external lookups, ακολουθήστε τους κανόνες για staked entities και δοκιμάστε την ίδια διαδρομή multi-pass bundler simulation, όχι μόνο unit tests.<sup>[[6]](#references)</sup>

## 8) ERC-7702 initialization frontrun
Το ERC-7702 παρέχει σε ένα EOA persistent delegation προς smart-account code· η delegation δεν εκτελεί την αρχικοποίηση atomically. Αν η αρχικοποίηση μπορεί να κληθεί externally, ένας observer μπορεί να κάνει front-run και να ορίσει τον εαυτό του ως owner.<sup>[[7]](#references)</sup>

Mitigation: απαιτήστε τα initialization calldata να είναι authorized από το EOA και επιτρέψτε την αρχικοποίηση μόνο μία φορά. Σε ένα ERC-4337 EIP-7702 flow, περιορίστε επίσης τον caller στο `EntryPoint.senderCreator()`.<sup>[[5]](#references)[[7]](#references)</sup>
```solidity
function initialize(address newOwner, bytes calldata initSig) external {
require(owner == address(0), "already inited");
// Verify the EOA's signature over the complete initialization calldata.
require(_isAuthorizedByEOA(newOwner, initSig), "bad init auth");
owner = newOwner;
}
```
## Γρήγοροι έλεγχοι πριν το merge
- Επικυρώστε τις υπογραφές χρησιμοποιώντας το `userOpHash` του `EntryPoint` (δεσμεύει τα πεδία gas).
- Περιορίστε τις privileged functions στα `EntryPoint` και/ή `address(this)` κατάλληλα.
- Διατηρήστε το `validateUserOp` stateless, deterministic και συμβατό με τους κανόνες simulation του bundler.
- Επιβάλετε domain separation του EIP-712 για το ERC-1271 και επιστρέψτε `0x1626ba7e` σε περίπτωση επιτυχίας.
- Διατηρήστε το `postOp` minimal, bounded και non-reverting· ασφαλίστε τα fees κατά το validation.
- Ελέγξτε ξεχωριστά το πρώτο μονοπάτι `initCode`: deterministic deployment, idempotent συμπεριφορά του factory και one-shot initialization.
- Εκτελέστε το multi-pass validation του bundler και έναν traced full-bundle check πριν το shipping.
- Για το ERC-7702, δεσμεύστε το init στην authorization του EOA και επιτρέψτε το μόνο μία φορά· στα ERC-4337 flows, περιορίστε τον caller στο `EntryPoint.senderCreator()`.

## References

- [1] [ERC1271 Replay - Επηρεάζονται περισσότερες από 15 ομάδες (curiousapple)](https://paragraph.com/@curiousapple/fwlBuaAuGsWwLRPTLKxB)
- [2] [Έξι λάθη σε smart accounts του ERC-4337 (Trail of Bits)](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)
- [3] [ERC-1271: Πρότυπη μέθοδος επικύρωσης υπογραφών για Contracts](https://eips.ethereum.org/EIPS/eip-1271)
- [4] [EIP-712: Hashing και signing typed structured data](https://eips.ethereum.org/EIPS/eip-712)
- [5] [ERC-4337: Account Abstraction με χρήση Alt Mempool](https://eips.ethereum.org/EIPS/eip-4337)
- [6] [ERC-7562: Κανόνες scope για το Account Abstraction validation](https://eips.ethereum.org/EIPS/eip-7562)
- [7] [EIP-7702: Ορισμός Code για EOAs](https://eips.ethereum.org/EIPS/eip-7702)
{{#include ../../banners/hacktricks-training.md}}
