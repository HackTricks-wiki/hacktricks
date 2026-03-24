# ERC-4337 Smart Account: Παγίδες Ασφαλείας

{{#include ../../banners/hacktricks-training.md}}

Η account abstraction του ERC-4337 μετατρέπει τα wallets σε προγραμματιζόμενα συστήματα. Η βασική ροή είναι **validate-then-execute** σε ολόκληρο το bundle: το `EntryPoint` επικυρώνει κάθε `UserOperation` πριν εκτελέσει οποιαδήποτε εξ αυτών. Αυτή η σειρά δημιουργεί μη προφανές attack surface όταν η επικύρωση είναι επιεικής ή stateful.

## 1) Παράκαμψη μέσω άμεσης κλήσης των privileged functions
Κάθε εξωτερικά κλητή `execute` (ή συνάρτηση μετακίνησης κεφαλαίων) που δεν περιορίζεται στο `EntryPoint` (ή σε ένα ελεγμένο executor module) μπορεί να κληθεί απευθείας για να αδειάσει τον λογαριασμό.
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
Ασφαλές μοτίβο: περιορίστε σε `EntryPoint`, και χρησιμοποιήστε `msg.sender == address(this)` για admin/self-management flows (module install, validator changes, upgrades).
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) Μη υπογεγραμμένα ή μη ελεγχόμενα πεδία gas -> αποστράγγιση τελών
Αν η επικύρωση υπογραφής καλύπτει μόνο την πρόθεση (`callData`) αλλά όχι τα πεδία που σχετίζονται με gas, ένας bundler ή frontrunner μπορεί να διογκώσει τα τέλη και να εξαντλήσει ETH. Το υπογεγραμμένο payload πρέπει να δεσμεύει τουλάχιστον:

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

Αμυντικό μοτίβο: χρησιμοποιήστε το `EntryPoint`-παρεχόμενο `userOpHash` (το οποίο περιλαμβάνει τα πεδία gas) και/ή θέστε αυστηρά όρια για κάθε πεδίο.
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
Επειδή όλοι οι έλεγχοι τρέχουν πριν από οποιαδήποτε εκτέλεση, η αποθήκευση των αποτελεσμάτων επικύρωσης στο state του contract δεν είναι ασφαλής. Μια άλλη op στο ίδιο bundle μπορεί να το αντικαταστήσει, προκαλώντας την εκτέλεσή σας να χρησιμοποιήσει κατάσταση επηρεασμένη από τον επιτιθέμενο.

Αποφύγετε την εγγραφή σε storage μέσα στο `validateUserOp`. Αν δεν είναι δυνατό, κλειδώστε προσωρινά δεδομένα με κλειδί το `userOpHash` και διαγράψτε τα ντετερμινιστικά μετά τη χρήση (προτιμήστε stateless validation).

## 4) ERC-1271 replay across accounts/chains (missing domain separation)
`isValidSignature(bytes32 hash, bytes sig)` πρέπει να δένει τις υπογραφές με **αυτό το συμβόλαιο** και **αυτή την αλυσίδα**. Η ανάκτηση πάνω σε ένα ωμό hash επιτρέπει στις υπογραφές να επαναχρησιμοποιηθούν μεταξύ λογαριασμών ή αλυσίδων.

Χρησιμοποιήστε EIP-712 typed data (το domain πρέπει να περιλαμβάνει `verifyingContract` και `chainId`) και επιστρέψτε την ακριβή ERC-1271 magic τιμή `0x1626ba7e` σε επιτυχία.

## 5) Reverts do not refund after validation
Μόλις το `validateUserOp` πετύχει, τα fees δεσμεύονται ακόμη και αν η εκτέλεση στη συνέχεια κάνει revert. Οι επιτιθέμενοι μπορούν να υποβάλουν επανειλημμένα ops που θα αποτύχουν και παρ’ όλα αυτά να εισπράξουν τέλη από τον λογαριασμό.

Για paymasters, η πληρωμή από κοινό pool μέσα στο `validateUserOp` και η χρέωση των χρηστών στο `postOp` είναι εύθραυστη, επειδή το `postOp` μπορεί να κάνει revert χωρίς να αναιρεί την πληρωμή. Διασφαλίστε τα κεφάλαια κατά την επικύρωση (αποθήκευση/κατάθεση ανά χρήστη) και κρατήστε το `postOp` ελάχιστο και μη-reverting.

## 6) ERC-7702 initialization frontrun
Το ERC-7702 επιτρέπει σε ένα EOA να τρέξει κώδικα smart-account για ένα μεμονωμένο tx. Αν το initialization είναι externally callable, ένας frontrunner μπορεί να ορίσει τον εαυτό του ως owner.

Αντίμετρο: επιτρέψτε initialization μόνο σε **self-call** και μόνο μία φορά.
```solidity
function initialize(address newOwner) external {
require(msg.sender == address(this), "init: only self");
require(owner == address(0), "already inited");
owner = newOwner;
}
```
## Γρήγοροι έλεγχοι πριν το merge
- Επικυρώστε τις υπογραφές χρησιμοποιώντας το `userOpHash` του `EntryPoint` (δεσμεύει τα πεδία gas).
- Περιορίστε τις προνόμιες συναρτήσεις σε `EntryPoint` και/ή `address(this)` όπως αρμόζει.
- Διατηρήστε το `validateUserOp` χωρίς κατάσταση.
- Επιβάλετε διαχωρισμό domain EIP-712 για το ERC-1271 και επιστρέψτε `0x1626ba7e` σε περίπτωση επιτυχίας.
- Κρατήστε το `postOp` ελάχιστο, περιορισμένο και μη ανατρεπτό· ασφαλίστε τα τέλη κατά την επικύρωση.
- Για το ERC-7702, επιτρέψτε το init μόνο σε self-call και μόνο μία φορά.

## Αναφορές

- [https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)

{{#include ../../banners/hacktricks-training.md}}
