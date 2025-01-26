# Wide Source Code Search

{{#include ../../banners/hacktricks-training.md}}

Ο στόχος αυτής της σελίδας είναι να απαριθμήσει **πλατφόρμες που επιτρέπουν την αναζήτηση κώδικα** (κυριολεκτικά ή regex) σε χιλιάδες/εκατομμύρια αποθετήρια σε μία ή περισσότερες πλατφόρμες.

Αυτό βοηθά σε πολλές περιπτώσεις να **αναζητήσετε διαρροές πληροφοριών** ή για **μοτίβα ευπαθειών**.

- [**Sourcebot**](https://www.sourcebot.dev/): Εργαλείο αναζήτησης κώδικα ανοιχτού κώδικα. Ευρετηρίαση και αναζήτηση σε χιλιάδες από τα αποθετήριά σας μέσω μιας σύγχρονης διαδικτυακής διεπαφής.
- [**SourceGraph**](https://sourcegraph.com/search): Αναζητήστε σε εκατομμύρια αποθετήρια. Υπάρχει μια δωρεάν έκδοση και μια έκδοση επιχείρησης (με 15 ημέρες δωρεάν). Υποστηρίζει regexes.
- [**Github Search**](https://github.com/search): Αναζητήστε σε όλο το Github. Υποστηρίζει regexes.
- Ίσως είναι επίσης χρήσιμο να ελέγξετε και το [**Github Code Search**](https://cs.github.com/).
- [**Gitlab Advanced Search**](https://docs.gitlab.com/ee/user/search/advanced_search.html): Αναζητήστε σε έργα Gitlab. Υποστηρίζει regexes.
- [**SearchCode**](https://searchcode.com/): Αναζητήστε κώδικα σε εκατομμύρια έργα.

> [!WARNING]
> Όταν αναζητάτε διαρροές σε ένα αποθετήριο και εκτελείτε κάτι όπως `git log -p` μην ξεχάσετε ότι μπορεί να υπάρχουν **άλλες branches με άλλες commits** που περιέχουν μυστικά!

{{#include ../../banners/hacktricks-training.md}}
