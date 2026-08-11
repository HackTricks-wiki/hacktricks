# Προετοιμασία και αξιολόγηση δεδομένων μοντέλου

{{#include ../banners/hacktricks-training.md}}

Η προετοιμασία δεδομένων μοντέλου είναι ένα κρίσιμο βήμα στη διαδικασία machine learning, καθώς περιλαμβάνει τη μετατροπή ακατέργαστων δεδομένων σε μορφή κατάλληλη για την εκπαίδευση μοντέλων machine learning. Αυτή η διαδικασία περιλαμβάνει αρκετά βασικά βήματα:

1. **Συλλογή δεδομένων**: Συγκέντρωση δεδομένων από διάφορες πηγές, όπως βάσεις δεδομένων, APIs ή αρχεία. Τα δεδομένα μπορεί να είναι δομημένα (π.χ. πίνακες) ή μη δομημένα (π.χ. κείμενο, εικόνες).
2. **Καθαρισμός δεδομένων**: Αφαίρεση ή διόρθωση εσφαλμένων, ελλιπών ή άσχετων σημείων δεδομένων. Αυτό το βήμα μπορεί να περιλαμβάνει τη διαχείριση ελλιπών τιμών, την αφαίρεση διπλότυπων και το φιλτράρισμα ακραίων τιμών.
3. **Μετασχηματισμός δεδομένων**: Μετατροπή των δεδομένων σε κατάλληλη μορφή για modeling. Αυτό μπορεί να περιλαμβάνει normalization, scaling, encoding κατηγορικών μεταβλητών και τη δημιουργία νέων features μέσω τεχνικών όπως το feature engineering.
4. **Διαχωρισμός δεδομένων**: Διαίρεση του dataset σε training, validation και test sets, ώστε να διασφαλίζεται ότι το μοντέλο μπορεί να γενικεύει σωστά σε δεδομένα που δεν έχει δει.

## Συλλογή δεδομένων

Η συλλογή δεδομένων περιλαμβάνει τη συγκέντρωση δεδομένων από διάφορες πηγές, οι οποίες μπορεί να περιλαμβάνουν:
- **Βάσεις δεδομένων**: Εξαγωγή δεδομένων από relational databases (π.χ. SQL databases) ή NoSQL databases (π.χ. MongoDB).
- **APIs**: Ανάκτηση δεδομένων από web APIs, τα οποία μπορούν να παρέχουν δεδομένα σε πραγματικό χρόνο ή ιστορικά δεδομένα.
- **Αρχεία**: Ανάγνωση δεδομένων από αρχεία σε formats όπως CSV, JSON ή XML.
- **Web Scraping**: Συλλογή δεδομένων από websites με χρήση τεχνικών web scraping.

Ανάλογα με τον στόχο του project machine learning, τα δεδομένα θα εξαχθούν και θα συλλεχθούν από σχετικές πηγές, ώστε να είναι αντιπροσωπευτικά του domain του προβλήματος.

## Καθαρισμός δεδομένων <sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

Ο καθαρισμός δεδομένων είναι η διαδικασία εντοπισμού και διόρθωσης σφαλμάτων ή ασυνεπειών στο dataset. Αυτό το βήμα είναι απαραίτητο για τη διασφάλιση της ποιότητας των δεδομένων που χρησιμοποιούνται για την εκπαίδευση μοντέλων machine learning. Οι βασικές εργασίες στον καθαρισμό δεδομένων περιλαμβάνουν:
- **Διαχείριση ελλιπών τιμών**: Εντοπισμός και αντιμετώπιση ελλιπών σημείων δεδομένων. Οι συνήθεις στρατηγικές περιλαμβάνουν:
- Αφαίρεση γραμμών ή στηλών με ελλιπείς τιμές.
- Συμπλήρωση ελλιπών τιμών με χρήση τεχνικών όπως η συμπλήρωση με mean, median ή mode.
- Χρήση advanced μεθόδων όπως η συμπλήρωση με K-nearest neighbors (KNN) ή η συμπλήρωση μέσω regression.
- **Αφαίρεση διπλότυπων**: Εντοπισμός και αφαίρεση διπλότυπων records, ώστε κάθε σημείο δεδομένων να είναι μοναδικό.
- **Φιλτράρισμα ακραίων τιμών**: Εντοπισμός και αφαίρεση ακραίων τιμών που μπορεί να επηρεάσουν αρνητικά την απόδοση του μοντέλου. Για τον εντοπισμό ακραίων τιμών μπορούν να χρησιμοποιηθούν τεχνικές όπως το Z-score, το IQR (Interquartile Range) ή visualizations (π.χ. box plots).

### Παράδειγμα καθαρισμού δεδομένων
```python
import re

import numpy as np
import pandas as pd
from sklearn.impute import KNNImputer, SimpleImputer

# Load the dataset
df = pd.read_csv('data.csv')

# Finding invalid values based on a specific function
def is_valid_positive_int(num):
try:
num = int(num)
return 1 <= num <= 31
except ValueError:
return False

invalid_days = df[~df['days'].astype(str).apply(is_valid_positive_int)]

## Dropping rows with invalid days
df = df.drop(invalid_days.index, errors='ignore')



# Set "NaN" values to a specific value
## For example, setting NaN values in the 'days' column to 0
df['days'] = pd.to_numeric(df['days'], errors='coerce')

## For example, set "NaN" to not ips
def is_valid_ip(ip):
pattern = re.compile(r'^((25[0-5]|2[0-4][0-9]|[01]?\d?\d)\.){3}(25[0-5]|2[0-4]\d|[01]?\d?\d)$')
if pd.isna(ip) or not pattern.match(str(ip)):
return np.nan
return ip
df['ip'] = df['ip'].apply(is_valid_ip)

# Filling missing values based on different strategies
numeric_cols = ["days", "hours", "minutes"]
categorical_cols = ["ip", "status"]

## Filling missing values in numeric columns with the median
num_imputer = SimpleImputer(strategy='median')
df[numeric_cols] = num_imputer.fit_transform(df[numeric_cols])

## Filling missing values in categorical columns with the most frequent value
cat_imputer = SimpleImputer(strategy='most_frequent')
df[categorical_cols] = cat_imputer.fit_transform(df[categorical_cols])

## Filling missing values in numeric columns using KNN imputation
knn_imputer = KNNImputer(n_neighbors=5)
df[numeric_cols] = knn_imputer.fit_transform(df[numeric_cols])



# Filling missing values
df.fillna(df.mean(numeric_only=True), inplace=True)

# Removing duplicates
df.drop_duplicates(inplace=True)
# Filtering outliers using Z-score
from scipy import stats
z_scores = np.abs(stats.zscore(df.select_dtypes(include=['float64', 'int64']), nan_policy='omit'))
df = df[(z_scores < 3).all(axis=1)]
```
## Μετασχηματισμός δεδομένων <sup>[[1]](#references)</sup>

Ο μετασχηματισμός δεδομένων περιλαμβάνει τη μετατροπή των δεδομένων σε μορφή κατάλληλη για modeling. Αυτό το βήμα μπορεί να περιλαμβάνει:
- **Κανονικοποίηση και τυποποίηση**: Κλιμάκωση των αριθμητικών χαρακτηριστικών σε ένα κοινό εύρος, συνήθως [0, 1] ή [-1, 1]. Αυτό μπορεί να βελτιώσει τη σύγκλιση των αλγορίθμων βελτιστοποίησης.
- **Κλιμάκωση Min-Max**: Επανακλιμάκωση των χαρακτηριστικών σε ένα σταθερό εύρος, συνήθως [0, 1]. Αυτό γίνεται με τον τύπο: `X' = (X - X_{min}) / (X_{max} - X_{min})`
- **Κανονικοποίηση Z-Score**: Τυποποίηση των χαρακτηριστικών με αφαίρεση του μέσου όρου και διαίρεση με την τυπική απόκλιση, με αποτέλεσμα μια κατανομή με μέσο όρο 0 και τυπική απόκλιση 1. Αυτό γίνεται με τον τύπο: `X' = (X - μ) / σ`, όπου μ είναι ο μέσος όρος και σ είναι η τυπική απόκλιση.
- **Ασυμμετρία και κύρτωση**: Προσαρμογή των κατανομών των χαρακτηριστικών με μετασχηματισμούς όπως ο λογάριθμος, η τετραγωνική ρίζα ή ο Box-Cox. Για παράδειγμα, ένας λογαριθμικός μετασχηματισμός μπορεί να μειώσει τη θετική ασυμμετρία.
- **Κανονικοποίηση συμβολοσειρών**: Μετατροπή των συμβολοσειρών σε συνεπή μορφή, όπως:
- Μετατροπή σε πεζά
- Αφαίρεση ειδικών χαρακτήρων (διατηρώντας τους σχετικούς)
- Αφαίρεση stop words (κοινών λέξεων που δεν συμβάλλουν στο νόημα, όπως "the", "is" και "and")
- Αφαίρεση υπερβολικά συχνών και υπερβολικά σπάνιων λέξεων (π.χ. λέξεων που εμφανίζονται σε περισσότερο από το 90% των εγγράφων ή λιγότερες από 5 φορές στο corpus)
- Αφαίρεση κενών χαρακτήρων στην αρχή και στο τέλος
- Stemming/Lemmatization: Μείωση των λέξεων στη βασική ή ριζική μορφή τους (π.χ. "running" σε "run").

- **Κωδικοποίηση κατηγορικών μεταβλητών**: Μετατροπή των κατηγορικών μεταβλητών σε αριθμητικές αναπαραστάσεις. Οι συνήθεις τεχνικές περιλαμβάνουν:
- **One-Hot Encoding**: Δημιουργία δυαδικών στηλών για κάθε κατηγορία.
- Για παράδειγμα, αν ένα χαρακτηριστικό έχει τις κατηγορίες "red", "green" και "blue", θα μετατραπεί σε τρεις δυαδικές στήλες: `is_red`(100), `is_green`(010) και `is_blue`(001).
- **Label Encoding**: Αντιστοίχιση ενός μοναδικού ακέραιου αριθμού σε κάθε κατηγορία.
- Για παράδειγμα, "red" = 0, "green" = 1, "blue" = 2.
- **Ordinal Encoding**: Αντιστοίχιση ακεραίων με βάση τη σειρά των κατηγοριών.
- Για παράδειγμα, αν οι κατηγορίες είναι "low", "medium" και "high", μπορούν να κωδικοποιηθούν ως 0, 1 και 2 αντίστοιχα.
- **Hashing Encoding**: Χρήση μιας hash function για τη μετατροπή των κατηγοριών σε διανύσματα σταθερού μεγέθους, κάτι που μπορεί να είναι χρήσιμο για κατηγορικές μεταβλητές υψηλής cardinality.
- Για παράδειγμα, αν ένα χαρακτηριστικό έχει πολλές μοναδικές κατηγορίες, το hashing μπορεί να μειώσει τη dimensionality διατηρώντας ορισμένες πληροφορίες σχετικά με τις κατηγορίες.
- **Bag of Words (BoW)**: Αναπαράσταση δεδομένων κειμένου ως πίνακα καταμετρήσεων ή συχνοτήτων λέξεων, όπου κάθε γραμμή αντιστοιχεί σε ένα έγγραφο και κάθε στήλη αντιστοιχεί σε μια μοναδική λέξη στο corpus.
- Για παράδειγμα, αν το corpus περιέχει τις λέξεις "cat", "dog" και "fish", ένα έγγραφο που περιέχει τις λέξεις "cat" και "dog" θα αναπαριστανόταν ως [1, 1, 0]. Αυτή η συγκεκριμένη αναπαράσταση ονομάζεται "unigram" και δεν αποτυπώνει τη σειρά των λέξεων, επομένως χάνει σημασιολογικές πληροφορίες.
- **Bigram/Trigram**: Επέκταση του BoW για την αποτύπωση ακολουθιών λέξεων (bigrams ή trigrams), ώστε να διατηρείται μέρος του context. Για παράδειγμα, το "cat and dog" θα αναπαριστανόταν ως bigram [1, 1] για το "cat and" και [1, 1] για το "and dog". Σε αυτή την περίπτωση συγκεντρώνεται περισσότερη σημασιολογική πληροφορία (αυξάνοντας τη dimensionality της αναπαράστασης), αλλά μόνο για 2 ή 3 λέξεις κάθε φορά.
- **TF-IDF (Term Frequency-Inverse Document Frequency)**: Στατιστικό μέτρο που αξιολογεί τη σημασία μιας λέξης σε ένα έγγραφο σε σχέση με μια συλλογή εγγράφων (corpus). Συνδυάζει τη συχνότητα όρου (πόσο συχνά εμφανίζεται μια λέξη σε ένα έγγραφο) και την αντίστροφη συχνότητα εγγράφων (πόσο σπάνια είναι μια λέξη σε όλα τα έγγραφα).
- Για παράδειγμα, αν η λέξη "cat" εμφανίζεται συχνά σε ένα έγγραφο αλλά είναι σπάνια σε ολόκληρο το corpus, θα έχει υψηλή βαθμολογία TF-IDF, υποδεικνύοντας τη σημασία της σε αυτό το έγγραφο.

- **Μηχανική χαρακτηριστικών**: Δημιουργία νέων χαρακτηριστικών από υπάρχοντα, για την ενίσχυση της predictive power του model. Αυτό μπορεί να περιλαμβάνει συνδυασμό χαρακτηριστικών, εξαγωγή στοιχείων ημερομηνίας/ώρας ή εφαρμογή μετασχηματισμών ειδικών για τον εκάστοτε domain.

## Διαχωρισμός δεδομένων <sup>[[3]](#references)</sup>

Ο διαχωρισμός δεδομένων περιλαμβάνει τη διαίρεση του dataset σε ξεχωριστά υποσύνολα για training, validation και testing. Αυτό είναι απαραίτητο για την αξιολόγηση της απόδοσης του model σε δεδομένα που δεν έχει δει και για την αποτροπή του overfitting. Οι συνήθεις στρατηγικές περιλαμβάνουν:
- **Train-Test Split**: Διαίρεση του dataset σε training set (συνήθως 60-80% των δεδομένων), validation set (10-15% των δεδομένων) για τη ρύθμιση των hyperparameters και test set (10-15% των δεδομένων). Το model εκπαιδεύεται στο training set και αξιολογείται στο test set.
- Για παράδειγμα, αν έχετε dataset με 1000 δείγματα, μπορείτε να χρησιμοποιήσετε 700 δείγματα για training, 150 για validation και 150 για testing.
- **Stratified Sampling**: Διασφάλιση ότι η κατανομή των classes στα training και test sets είναι παρόμοια με εκείνη ολόκληρου του dataset. Αυτό είναι ιδιαίτερα σημαντικό για imbalanced datasets, όπου ορισμένες classes μπορεί να έχουν σημαντικά λιγότερα δείγματα από άλλες.
- **Time Series Split**: Για δεδομένα time series, το dataset διαχωρίζεται με βάση τον χρόνο, ώστε το training set να περιέχει δεδομένα από προγενέστερες χρονικές περιόδους και το test set να περιέχει δεδομένα από μεταγενέστερες περιόδους. Αυτό βοηθά στην αξιολόγηση της απόδοσης του model σε μελλοντικά δεδομένα.
- **K-Fold Cross-Validation**: Διαίρεση του dataset σε K υποσύνολα (folds) και training του model K φορές, χρησιμοποιώντας κάθε φορά ένα διαφορετικό fold ως test set και τα υπόλοιπα folds ως training set. Αυτό βοηθά να διασφαλιστεί ότι το model αξιολογείται σε διαφορετικά υποσύνολα δεδομένων, παρέχοντας μια πιο robust εκτίμηση της απόδοσής του.

## Αξιολόγηση model <sup>[[4]](#references)</sup>

Η αξιολόγηση model είναι η διαδικασία εκτίμησης της απόδοσης ενός machine learning model σε δεδομένα που δεν έχει δει. Περιλαμβάνει τη χρήση διαφόρων metrics για την ποσοτικοποίηση του βαθμού στον οποίο το model γενικεύεται σε νέα δεδομένα. Τα συνήθη metrics αξιολόγησης περιλαμβάνουν:

### Accuracy

Το Accuracy είναι το ποσοστό των σωστά προβλεφθέντων instances επί του συνολικού αριθμού των instances. Υπολογίζεται ως:
```plaintext
Accuracy = (Number of Correct Predictions) / (Total Number of Predictions)
```
> [!TIP]
> Η ακρίβεια είναι ένα απλό και διαισθητικό metric, αλλά μπορεί να μην είναι κατάλληλη για imbalanced datasets όπου μία κλάση κυριαρχεί έναντι των άλλων, καθώς μπορεί να δώσει παραπλανητική εικόνα για την απόδοση του model. Για παράδειγμα, αν το 90% των δεδομένων ανήκει στην κλάση A και το model προβλέπει όλες τις περιπτώσεις ως κλάση A, θα επιτύχει ακρίβεια 90%, αλλά δεν θα είναι χρήσιμο για την πρόβλεψη της κλάσης B.

### Precision

Το Precision είναι η αναλογία των true positive προβλέψεων προς όλες τις positive προβλέψεις που έκανε το model. Υπολογίζεται ως εξής:
```plaintext
Precision = (True Positives) / (True Positives + False Positives)
```
> [!TIP]
> Η ακρίβεια είναι ιδιαίτερα σημαντική σε σενάρια όπου τα false positives είναι δαπανηρά ή ανεπιθύμητα, όπως στις ιατρικές διαγνώσεις ή στον εντοπισμό απάτης. Για παράδειγμα, αν ένα model προβλέψει 100 instances ως positive, αλλά μόνο 80 από αυτά είναι στην πραγματικότητα positive, η ακρίβεια θα ήταν 0.8 (80%).

### Ανάκληση (Ευαισθησία)

Η ανάκληση, γνωστή επίσης ως ευαισθησία ή true positive rate, είναι η αναλογία των true positive predictions προς όλα τα πραγματικά positive instances. Υπολογίζεται ως εξής:
```plaintext
Recall = (True Positives) / (True Positives + False Negatives)
```
> [!TIP]
> Η ανάκληση είναι κρίσιμη σε σενάρια όπου τα false negatives είναι δαπανηρά ή ανεπιθύμητα, όπως στην ανίχνευση ασθενειών ή στο filtering ανεπιθύμητης αλληλογραφίας. Για παράδειγμα, αν ένα μοντέλο εντοπίζει 80 από 100 πραγματικές θετικές περιπτώσεις, η ανάκληση θα ήταν 0,8 (80%).

### F1 Score

Το F1 score είναι ο αρμονικός μέσος όρος του precision και της ανάκλησης, παρέχοντας ισορροπία μεταξύ των δύο μετρικών. Υπολογίζεται ως:
```plaintext
F1 Score = 2 * (Precision * Recall) / (Precision + Recall)
```
> [!TIP]
> Το F1 score είναι ιδιαίτερα χρήσιμο όταν εργάζεστε με μη ισορροπημένα datasets, καθώς λαμβάνει υπόψη τόσο τα false positives όσο και τα false negatives. Παρέχει ένα ενιαίο metric που αποτυπώνει τον συμβιβασμό μεταξύ precision και recall. Για παράδειγμα, αν ένα model έχει precision 0.8 και recall 0.6, το F1 score θα είναι περίπου 0.69.

### ROC-AUC (Receiver Operating Characteristic - Area Under the Curve)

Το metric ROC-AUC αξιολογεί την ικανότητα του model να διακρίνει μεταξύ classes, απεικονίζοντας το true positive rate (sensitivity) σε σχέση με το false positive rate για διάφορες ρυθμίσεις threshold. Το εμβαδόν κάτω από την καμπύλη ROC (AUC) ποσοτικοποιεί την απόδοση του model, με την τιμή 1 να υποδεικνύει τέλεια ταξινόμηση και την τιμή 0.5 να υποδεικνύει τυχαία πρόβλεψη.

> [!TIP]
> Το ROC-AUC είναι ιδιαίτερα χρήσιμο για προβλήματα binary classification και παρέχει μια ολοκληρωμένη εικόνα της απόδοσης του model σε διαφορετικά thresholds. Είναι λιγότερο ευαίσθητο στην ανισορροπία των classes σε σύγκριση με το accuracy. Για παράδειγμα, ένα model με AUC 0.9 υποδεικνύει ότι έχει υψηλή ικανότητα να διακρίνει μεταξύ θετικών και αρνητικών instances.

### Specificity

Το specificity, γνωστό και ως true negative rate, είναι το ποσοστό των true negative predictions επί του συνόλου των πραγματικών αρνητικών instances. Υπολογίζεται ως εξής:
```plaintext
Specificity = (True Negatives) / (True Negatives + False Positives)
```
> [!TIP]
> Η ειδικότητα είναι σημαντική σε σενάρια όπου τα false positives είναι δαπανηρά ή ανεπιθύμητα, όπως στις ιατρικές εξετάσεις ή στον εντοπισμό απάτης. Βοηθά στην αξιολόγηση του πόσο καλά το model εντοπίζει τις αρνητικές περιπτώσεις. Για παράδειγμα, αν ένα model εντοπίζει σωστά 90 από 100 πραγματικές αρνητικές περιπτώσεις, η ειδικότητα θα ήταν 0.9 (90%).

### Συντελεστής Συσχέτισης Matthews (MCC)
Ο Συντελεστής Συσχέτισης Matthews (MCC) είναι ένα μέτρο της ποιότητας των δυαδικών ταξινομήσεων. Λαμβάνει υπόψη τα true και false positives και negatives, παρέχοντας μια ισορροπημένη εικόνα της απόδοσης του model. Το MCC υπολογίζεται ως εξής:
```plaintext
MCC = (TP * TN - FP * FN) / sqrt((TP + FP) * (TP + FN) * (TN + FP) * (TN + FN))
```
όπου:
- **TP**: True Positives
- **TN**: True Negatives
- **FP**: False Positives
- **FN**: False Negatives

> [!TIP]
> Το MCC κυμαίνεται από -1 έως 1, όπου το 1 υποδεικνύει τέλεια ταξινόμηση, το 0 υποδεικνύει τυχαία πρόβλεψη και το -1 υποδεικνύει πλήρη ασυμφωνία μεταξύ πρόβλεψης και παρατήρησης. Είναι ιδιαίτερα χρήσιμο για μη ισορροπημένα datasets, καθώς λαμβάνει υπόψη και τα τέσσερα στοιχεία του confusion matrix.

### Μέσο Απόλυτο Σφάλμα (MAE)
Το Μέσο Απόλυτο Σφάλμα (MAE) είναι μια μετρική παλινδρόμησης που μετρά την平均τη απόλυτη διαφορά μεταξύ των προβλεπόμενων και των πραγματικών τιμών. Υπολογίζεται ως:
```plaintext
MAE = (1/n) * Σ|y_i - ŷ_i|
```
όπου:
- **n**: Αριθμός instances
- **y_i**: Πραγματική τιμή για το instance i
- **ŷ_i**: Προβλεπόμενη τιμή για το instance i

> [!TIP]
> Το MAE παρέχει μια απλή ερμηνεία του μέσου σφάλματος στις προβλέψεις, καθιστώντας το εύκολο στην κατανόηση. Είναι λιγότερο ευαίσθητο στα outliers σε σύγκριση με άλλα metrics, όπως το Mean Squared Error (MSE). Για παράδειγμα, αν ένα model έχει MAE ίσο με 5, αυτό σημαίνει ότι, κατά μέσο όρο, οι προβλέψεις του model αποκλίνουν από τις πραγματικές τιμές κατά 5 μονάδες.

### Confusion Matrix

Το confusion matrix είναι ένας πίνακας που συνοψίζει την απόδοση ενός classification model, εμφανίζοντας τον αριθμό των true positive, true negative, false positive και false negative προβλέψεων. Παρέχει μια λεπτομερή εικόνα του πόσο καλά αποδίδει το model σε κάθε class.

|               | Predicted Positive | Predicted Negative |
|---------------|---------------------|---------------------|
| Actual Positive| True Positive (TP)  | False Negative (FN)  |
| Actual Negative| False Positive (FP) | True Negative (TN)   |

- **True Positive (TP)**: Το model προέβλεψε σωστά τη positive class.
- **True Negative (TN)**: Το model προέβλεψε σωστά τη negative class.
- **False Positive (FP)**: Το model προέβλεψε εσφαλμένα τη positive class (Type I error).
- **False Negative (FN)**: Το model προέβλεψε εσφαλμένα τη negative class (Type II error).

Το confusion matrix μπορεί να χρησιμοποιηθεί για τον υπολογισμό evaluation metrics, όπως accuracy, precision, recall και F1 score.

## References

- [1] [scikit-learn - Προεπεξεργασία δεδομένων](https://scikit-learn.org/stable/modules/preprocessing.html)
- [2] [scikit-learn - Συμπλήρωση ελλιπών τιμών](https://scikit-learn.org/stable/modules/impute.html)
- [3] [scikit-learn - Cross-validation: αξιολόγηση της απόδοσης του estimator](https://scikit-learn.org/stable/modules/cross_validation.html)
- [4] [scikit-learn - Metrics και scoring](https://scikit-learn.org/stable/modules/model_evaluation.html)
{{#include ../banners/hacktricks-training.md}}
