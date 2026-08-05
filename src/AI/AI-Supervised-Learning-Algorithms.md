# Αλγόριθμοι Επιβλεπόμενης Μάθησης

{{#include ../banners/hacktricks-training.md}}

## Βασικές Πληροφορίες

Η επιβλεπόμενη μάθηση χρησιμοποιεί δεδομένα με ετικέτες για την εκπαίδευση μοντέλων που μπορούν να κάνουν προβλέψεις σε νέα, μη εμφανισμένα προηγουμένως δεδομένα εισόδου. Στην κυβερνοασφάλεια, η supervised machine learning εφαρμόζεται ευρέως σε εργασίες όπως η ανίχνευση εισβολών (ταξινόμηση της κίνησης δικτύου ως *normal* ή *attack*), η ανίχνευση malware (διάκριση κακόβουλου λογισμικού από benign), η ανίχνευση phishing (εντοπισμός fraudulent websites ή emails) και το spam filtering, μεταξύ άλλων. Κάθε algorithm έχει τα δικά του πλεονεκτήματα και είναι κατάλληλο για διαφορετικούς τύπους προβλημάτων (classification ή regression). Παρακάτω εξετάζουμε βασικούς supervised learning algorithms, εξηγούμε τον τρόπο λειτουργίας τους και παρουσιάζουμε τη χρήση τους σε πραγματικά cybersecurity datasets. Συζητάμε επίσης πώς ο συνδυασμός μοντέλων (ensemble learning) μπορεί συχνά να βελτιώσει την predictive performance.

## Algorithms

-   **Linear Regression:** Ένας θεμελιώδης regression algorithm για την πρόβλεψη αριθμητικών αποτελεσμάτων μέσω προσαρμογής μιας γραμμικής εξίσωσης στα δεδομένα.

-   **Logistic Regression:** Ένας classification algorithm (παρά το όνομά του) που χρησιμοποιεί logistic function για τη μοντελοποίηση της πιθανότητας ενός binary αποτελέσματος.

-   **Decision Trees:** Μοντέλα με δενδροειδή δομή που διαχωρίζουν τα δεδομένα βάσει features για να κάνουν προβλέψεις· χρησιμοποιούνται συχνά λόγω της interpretability τους.

-   **Random Forests:** Ένα ensemble από decision trees (μέσω bagging) που βελτιώνει την accuracy και μειώνει το overfitting.

-   **Support Vector Machines (SVM):** Max-margin classifiers που βρίσκουν το βέλτιστο separating hyperplane· μπορούν να χρησιμοποιήσουν kernels για non-linear δεδομένα.

-   **Naive Bayes:** Ένας probabilistic classifier που βασίζεται στο θεώρημα του Bayes και στην υπόθεση ανεξαρτησίας των features, γνωστός για τη χρήση του στο spam filtering.

-   **k-Nearest Neighbors (k-NN):** Ένας απλός "instance-based" classifier που αποδίδει label σε ένα sample βάσει της majority class των κοντινότερων neighbors του.

-   **Gradient Boosting Machines:** Ensemble models (π.χ. XGBoost, LightGBM) που δημιουργούν έναν ισχυρό predictor προσθέτοντας διαδοχικά weaker learners (συνήθως decision trees).

Κάθε ενότητα παρακάτω παρέχει μια βελτιωμένη περιγραφή του algorithm και ένα **Python code example** που χρησιμοποιεί libraries όπως `pandas` και `scikit-learn` (και `PyTorch` για το παράδειγμα του neural network). Τα παραδείγματα χρησιμοποιούν δημόσια διαθέσιμα cybersecurity datasets (όπως το NSL-KDD για intrusion detection και ένα Phishing Websites dataset) και ακολουθούν μια συνεπή δομή:

1.  **Load the dataset** (download μέσω URL, εφόσον είναι διαθέσιμο).

2.  **Preprocess the data** (π.χ. encode των categorical features, scale των τιμών, διαχωρισμός σε train/test sets).

3.  **Train the model** στα training data.

4.  **Evaluate** σε test set χρησιμοποιώντας metrics: accuracy, precision, recall, F1-score και ROC AUC για classification (και mean squared error για regression).

Ας εξετάσουμε κάθε algorithm:

### Linear Regression

Η linear regression είναι ένας **regression** algorithm που χρησιμοποιείται για την πρόβλεψη συνεχών αριθμητικών τιμών. Υποθέτει μια γραμμική σχέση μεταξύ των input features (independent variables) και του output (dependent variable). Το μοντέλο προσπαθεί να προσαρμόσει μια ευθεία γραμμή (ή hyperplane σε υψηλότερες διαστάσεις) που περιγράφει με τον καλύτερο τρόπο τη σχέση μεταξύ των features και του target. Αυτό γίνεται συνήθως με την ελαχιστοποίηση του αθροίσματος των τετραγώνων των σφαλμάτων μεταξύ των predicted και actual τιμών (Ordinary Least Squares method).<sup>[[8]](#references)</sup>

Ο απλούστερος τρόπος αναπαράστασης της linear regression είναι με μια γραμμή:
```plaintext
y = mx + b
```
Όπου:

- `y` είναι η προβλεπόμενη τιμή (έξοδος)
- `m` είναι η κλίση της γραμμής (συντελεστής)
- `x` είναι το χαρακτηριστικό εισόδου
- `b` είναι η y-τομή

Ο στόχος της linear regression είναι να βρεθεί η γραμμή βέλτιστης προσαρμογής, η οποία ελαχιστοποιεί τη διαφορά μεταξύ των προβλεπόμενων και των πραγματικών τιμών στο dataset. Φυσικά, αυτό είναι πολύ απλό· θα ήταν μια ευθεία γραμμή που διαχωρίζει 2 κατηγορίες, αλλά αν προστεθούν περισσότερες διαστάσεις, η γραμμή γίνεται πιο σύνθετη:
```plaintext
y = w1*x1 + w2*x2 + ... + wn*xn + b
```
> [!TIP]
> *Περιπτώσεις χρήσης στην κυβερνοασφάλεια:* Η Linear regression είναι λιγότερο συνηθισμένη για βασικές εργασίες ασφάλειας (οι οποίες συχνά αφορούν classification), αλλά μπορεί να εφαρμοστεί για την πρόβλεψη αριθμητικών αποτελεσμάτων. Για παράδειγμα, θα μπορούσε να χρησιμοποιηθεί για την **πρόβλεψη του όγκου της κίνησης δικτύου** ή την **εκτίμηση του αριθμού των επιθέσεων σε μια χρονική περίοδο** με βάση ιστορικά δεδομένα. Θα μπορούσε επίσης να προβλέψει ένα risk score ή τον αναμενόμενο χρόνο μέχρι τον εντοπισμό μιας επίθεσης, με βάση συγκεκριμένα metrics του συστήματος. Στην πράξη, οι classification algorithms (όπως η logistic regression ή τα trees) χρησιμοποιούνται συχνότερα για τον εντοπισμό intrusions ή malware, αλλά η linear regression αποτελεί θεμέλιο και είναι χρήσιμη για analyses που προσανατολίζονται στο regression.

#### **Βασικά χαρακτηριστικά της Linear Regression:**

-   **Τύπος προβλήματος:** Regression (πρόβλεψη συνεχών τιμών). Δεν είναι κατάλληλη για άμεσο classification, εκτός αν εφαρμοστεί ένα threshold στην έξοδο.

-   **Ερμηνευσιμότητα:** Υψηλή -- οι coefficients είναι εύκολο να ερμηνευτούν, δείχνοντας τη γραμμική επίδραση κάθε feature.

-   **Πλεονεκτήματα:** Απλή και γρήγορη· αποτελεί καλό baseline για regression tasks· λειτουργεί καλά όταν η πραγματική σχέση είναι περίπου γραμμική.

-   **Περιορισμοί:** Δεν μπορεί να αποτυπώσει σύνθετες ή μη γραμμικές σχέσεις (χωρίς manual feature engineering)· είναι επιρρεπής σε underfitting όταν οι σχέσεις είναι μη γραμμικές· είναι ευαίσθητη σε outliers, οι οποίοι μπορούν να παραμορφώσουν τα αποτελέσματα.

-   **Εύρεση της καλύτερης προσαρμογής:** Για να βρούμε τη γραμμή με την καλύτερη προσαρμογή, η οποία διαχωρίζει τις πιθανές κατηγορίες, χρησιμοποιούμε μια μέθοδο που ονομάζεται **Ordinary Least Squares (OLS)**. Αυτή η μέθοδος ελαχιστοποιεί το άθροισμα των τετραγώνων των διαφορών μεταξύ των παρατηρούμενων τιμών και των τιμών που προβλέπονται από το γραμμικό μοντέλο.

<details>
<summary>Παράδειγμα -- Πρόβλεψη διάρκειας σύνδεσης (Regression) σε ένα intrusion dataset
</summary>
Παρακάτω παρουσιάζουμε τη χρήση της linear regression με το NSL-KDD cybersecurity dataset. Θα το αντιμετωπίσουμε ως regression problem, προβλέποντας το `duration` των network connections με βάση άλλα features. (Στην πραγματικότητα, το `duration` είναι ένα feature του NSL-KDD· το χρησιμοποιούμε εδώ απλώς για να παρουσιάσουμε το regression.) Φορτώνουμε το dataset, κάνουμε preprocessing σε αυτό (κωδικοποιούμε τα categorical features), εκπαιδεύουμε ένα linear regression model και αξιολογούμε το Mean Squared Error (MSE) και το R² score σε ένα test set.
```python
import pandas as pd
from sklearn.preprocessing import LabelEncoder
from sklearn.linear_model import LinearRegression
from sklearn.metrics import mean_squared_error, r2_score

# ── 1. Column names taken from the NSL‑KDD documentation ──────────────
col_names = [
"duration","protocol_type","service","flag","src_bytes","dst_bytes","land",
"wrong_fragment","urgent","hot","num_failed_logins","logged_in",
"num_compromised","root_shell","su_attempted","num_root",
"num_file_creations","num_shells","num_access_files","num_outbound_cmds",
"is_host_login","is_guest_login","count","srv_count","serror_rate",
"srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate",
"diff_srv_rate","srv_diff_host_rate","dst_host_count",
"dst_host_srv_count","dst_host_same_srv_rate","dst_host_diff_srv_rate",
"dst_host_same_src_port_rate","dst_host_srv_diff_host_rate",
"dst_host_serror_rate","dst_host_srv_serror_rate","dst_host_rerror_rate",
"dst_host_srv_rerror_rate","class","difficulty_level"
]

# ── 2. Load data *without* header row ─────────────────────────────────
train_url = "https://raw.githubusercontent.com/Mamcose/NSL-KDD-Network-Intrusion-Detection/master/NSL_KDD_Train.csv"
test_url  = "https://raw.githubusercontent.com/Mamcose/NSL-KDD-Network-Intrusion-Detection/master/NSL_KDD_Test.csv"

df_train = pd.read_csv(train_url, header=None, names=col_names)
df_test  = pd.read_csv(test_url,  header=None, names=col_names)

# ── 3. Encode the 3 nominal features ─────────────────────────────────
for col in ['protocol_type', 'service', 'flag']:
le = LabelEncoder()
le.fit(pd.concat([df_train[col], df_test[col]], axis=0))
df_train[col] = le.transform(df_train[col])
df_test[col]  = le.transform(df_test[col])

# ── 4. Prepare features / target ─────────────────────────────────────
X_train = df_train.drop(columns=['class', 'difficulty_level', 'duration'])
y_train = df_train['duration']

X_test  = df_test.drop(columns=['class', 'difficulty_level', 'duration'])
y_test  = df_test['duration']

# ── 5. Train & evaluate simple Linear Regression ─────────────────────
model = LinearRegression().fit(X_train, y_train)
y_pred = model.predict(X_test)

print(f"Test MSE: {mean_squared_error(y_test, y_pred):.2f}")
print(f"Test R² : {r2_score(y_test, y_pred):.3f}")

"""
Test MSE: 3021333.56
Test R² : -0.526
"""
```
Σε αυτό το παράδειγμα, το μοντέλο γραμμικής παλινδρόμησης προσπαθεί να προβλέψει το `duration` της σύνδεσης από άλλα χαρακτηριστικά του δικτύου. Μετράμε την απόδοση με το Mean Squared Error (MSE) και το R². Ένα R² κοντά στο 1.0 υποδεικνύει ότι το μοντέλο εξηγεί το μεγαλύτερο μέρος της διακύμανσης του `duration`, ενώ ένα χαμηλό ή αρνητικό R² υποδεικνύει κακή προσαρμογή. (Μην εκπλαγείτε αν το R² είναι χαμηλό εδώ -- η πρόβλεψη του `duration` μπορεί να είναι δύσκολη με βάση τα συγκεκριμένα χαρακτηριστικά και η γραμμική παλινδρόμηση μπορεί να μην αποτυπώνει τα μοτίβα, αν αυτά είναι σύνθετα.)
</details>

### Λογιστική παλινδρόμηση

Η λογιστική παλινδρόμηση είναι ένας αλγόριθμος **classification** που μοντελοποιεί την πιθανότητα ένα στιγμιότυπο να ανήκει σε μια συγκεκριμένη κλάση (συνήθως την "positive" κλάση). Παρά το όνομά της, η *λογιστική* παλινδρόμηση χρησιμοποιείται για διακριτά αποτελέσματα (σε αντίθεση με τη γραμμική παλινδρόμηση, η οποία χρησιμοποιείται για συνεχή αποτελέσματα). Χρησιμοποιείται ιδιαίτερα για **binary classification** (δύο κλάσεις, π.χ. malicious έναντι benign), αλλά μπορεί να επεκταθεί σε προβλήματα multi-class (με τη χρήση των προσεγγίσεων softmax ή one-vs-rest).<sup>[[1]](#references)</sup>

Η λογιστική παλινδρόμηση χρησιμοποιεί τη λογιστική συνάρτηση (γνωστή επίσης ως sigmoid συνάρτηση) για να αντιστοιχίσει τις προβλεπόμενες τιμές σε πιθανότητες. Σημειώστε ότι η sigmoid συνάρτηση είναι μια συνάρτηση με τιμές μεταξύ 0 και 1, η οποία αυξάνεται σε καμπύλη σχήματος S ανάλογα με τις ανάγκες της classification, κάτι που είναι χρήσιμο για εργασίες binary classification. Επομένως, κάθε χαρακτηριστικό κάθε εισόδου πολλαπλασιάζεται με το αντίστοιχο weight που του έχει εκχωρηθεί και το αποτέλεσμα περνά από τη sigmoid συνάρτηση για να παραχθεί μια πιθανότητα:
```plaintext
p(y=1|x) = 1 / (1 + e^(-z))
```
Where:

- `p(y=1|x)` είναι η πιθανότητα η έξοδος `y` να είναι 1 δεδομένης της εισόδου `x`
- `e` είναι η βάση του φυσικού λογαρίθμου
- `z` είναι ένας γραμμικός συνδυασμός των χαρακτηριστικών εισόδου, που συνήθως αναπαρίσταται ως `z = w1*x1 + w2*x2 + ... + wn*xn + b`. Παρατηρήστε ότι και στην απλούστερη μορφή του είναι μια ευθεία γραμμή, αλλά σε πιο σύνθετες περιπτώσεις γίνεται ένα υπερεπίπεδο με πολλές διαστάσεις (μία ανά χαρακτηριστικό).

> [!TIP]
> *Use cases in cybersecurity:* Επειδή πολλά προβλήματα ασφάλειας είναι ουσιαστικά αποφάσεις ναι/όχι, η Logistic Regression χρησιμοποιείται ευρέως. Για παράδειγμα, ένα σύστημα intrusion detection μπορεί να χρησιμοποιήσει Logistic Regression για να αποφασίσει αν μια σύνδεση δικτύου αποτελεί επίθεση, με βάση τα χαρακτηριστικά αυτής της σύνδεσης. Στην ανίχνευση phishing, η Logistic Regression μπορεί να συνδυάσει χαρακτηριστικά ενός website (μήκος URL, παρουσία του συμβόλου "@", κ.λπ.) σε μια πιθανότητα το website να είναι phishing. Έχει χρησιμοποιηθεί σε φίλτρα spam πρώτης γενιάς και παραμένει ένα ισχυρό baseline για πολλές εργασίες classification.

#### Logistic Regression για non binary classification

Η Logistic Regression έχει σχεδιαστεί για binary classification, αλλά μπορεί να επεκταθεί ώστε να διαχειρίζεται multi-class προβλήματα χρησιμοποιώντας τεχνικές όπως **one-vs-rest** (OvR) ή **softmax regression**. Στην OvR, εκπαιδεύεται ένα ξεχωριστό μοντέλο Logistic Regression για κάθε class, αντιμετωπίζοντάς την ως positive class έναντι όλων των υπόλοιπων. Η class με την υψηλότερη predicted probability επιλέγεται ως η τελική πρόβλεψη. Η softmax regression γενικεύει τη Logistic Regression σε πολλαπλές classes εφαρμόζοντας τη συνάρτηση softmax στο output layer και παράγοντας μια κατανομή πιθανοτήτων για όλες τις classes.

#### **Βασικά χαρακτηριστικά της Logistic Regression:**

-   **Τύπος προβλήματος:** Classification (συνήθως binary). Προβλέπει την πιθανότητα της positive class.

-   **Ερμηνευσιμότητα:** Υψηλή -- όπως και στη linear regression, οι συντελεστές των χαρακτηριστικών μπορούν να δείξουν πώς κάθε χαρακτηριστικό επηρεάζει τα log-odds του αποτελέσματος. Αυτή η διαφάνεια εκτιμάται συχνά στην ασφάλεια για την κατανόηση των παραγόντων που συμβάλλουν σε ένα alert.

-   **Πλεονεκτήματα:** Απλή και γρήγορη στην εκπαίδευση· λειτουργεί καλά όταν η σχέση μεταξύ των χαρακτηριστικών και των log-odds του αποτελέσματος είναι γραμμική. Παράγει probabilities, επιτρέποντας risk scoring. Με κατάλληλη regularization, γενικεύεται καλά και μπορεί να διαχειριστεί την multicollinearity καλύτερα από την απλή linear regression.

-   **Περιορισμοί:** Υποθέτει ένα γραμμικό decision boundary στον χώρο των χαρακτηριστικών (αποτυγχάνει αν το πραγματικό boundary είναι σύνθετο/μη γραμμικό). Μπορεί να έχει χαμηλότερη απόδοση σε προβλήματα όπου οι αλληλεπιδράσεις ή τα μη γραμμικά effects είναι κρίσιμα, εκτός αν προσθέσετε χειροκίνητα polynomial ή interaction features. Επίσης, η Logistic Regression είναι λιγότερο αποτελεσματική όταν οι classes δεν μπορούν να διαχωριστούν εύκολα μέσω ενός γραμμικού συνδυασμού χαρακτηριστικών.


<details>
<summary>Παράδειγμα -- Phishing Website Detection με Logistic Regression:</summary>

Θα χρησιμοποιήσουμε ένα **Phishing Websites Dataset** (από το UCI repository), το οποίο περιέχει extracted features websites (όπως αν το URL έχει IP address, την ηλικία του domain, την παρουσία ύποπτων στοιχείων σε HTML κ.λπ.) και ένα label που υποδεικνύει αν το site είναι phishing ή legitimate. Εκπαιδεύουμε ένα μοντέλο Logistic Regression για την ταξινόμηση websites και, στη συνέχεια, αξιολογούμε τα accuracy, precision, recall, F1-score και ROC AUC σε ένα test split.
```python
import pandas as pd
from sklearn.datasets import fetch_openml
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score

# 1. Load dataset
data = fetch_openml(data_id=4534, as_frame=True)  # PhishingWebsites
df   = data.frame
print(df.head())

# 2. Target mapping ─ legitimate (1) → 0, everything else → 1
df['Result'] = df['Result'].astype(int)
y = (df['Result'] != 1).astype(int)

# 3. Features
X = df.drop(columns=['Result'])

# 4. Train/test split with stratify
## Stratify ensures balanced classes in train/test sets
X_train, X_test, y_train, y_test = train_test_split(
X, y, test_size=0.20, random_state=42, stratify=y)

# 5. Scale
scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test  = scaler.transform(X_test)

# 6. Logistic Regression
## L‑BFGS is a modern, memory‑efficient “quasi‑Newton” algorithm that works well for medium/large datasets and supports multiclass natively.
## Upper bound on how many optimization steps the solver may take before it gives up.	Not all steps are guaranteed to be taken, but would be the maximum before a "failed to converge" error.
clf = LogisticRegression(max_iter=1000, solver='lbfgs', random_state=42)
clf.fit(X_train, y_train)

# 7. Evaluation
y_pred = clf.predict(X_test)
y_prob = clf.predict_proba(X_test)[:, 1]

print(f"Accuracy : {accuracy_score(y_test, y_pred):.3f}")
print(f"Precision: {precision_score(y_test, y_pred):.3f}")
print(f"Recall   : {recall_score(y_test, y_pred):.3f}")
print(f"F1-score : {f1_score(y_test, y_pred):.3f}")
print(f"ROC AUC  : {roc_auc_score(y_test, y_prob):.3f}")

"""
Accuracy : 0.928
Precision: 0.934
Recall   : 0.901
F1-score : 0.917
ROC AUC  : 0.979
"""
```
Σε αυτό το παράδειγμα ανίχνευσης phishing, η logistic regression παράγει μια πιθανότητα για κάθε website να είναι phishing. Αξιολογώντας τα accuracy, precision, recall και F1, αποκτούμε μια εικόνα για την απόδοση του μοντέλου. Για παράδειγμα, υψηλό recall σημαίνει ότι εντοπίζει τα περισσότερα phishing sites (σημαντικό για την ασφάλεια, ώστε να ελαχιστοποιούνται οι επιθέσεις που δεν εντοπίζονται), ενώ υψηλό precision σημαίνει ότι παράγει λίγους false alarms (σημαντικό για την αποφυγή κόπωσης των analysts). Το ROC AUC (Area Under the ROC Curve) παρέχει ένα μέτρο απόδοσης ανεξάρτητο από το threshold (το 1.0 είναι ιδανικό, ενώ το 0.5 δεν είναι καλύτερο από την τυχαία πρόβλεψη). Η logistic regression συχνά αποδίδει καλά σε τέτοιες εργασίες, αλλά αν το decision boundary μεταξύ phishing και νόμιμων sites είναι σύνθετο, μπορεί να χρειαστούν ισχυρότερα μη γραμμικά μοντέλα.

</details>

### Decision Trees

Ένα decision tree είναι ένας ευέλικτος **supervised learning algorithm** που μπορεί να χρησιμοποιηθεί τόσο για εργασίες classification όσο και regression. Μαθαίνει ένα ιεραρχικό μοντέλο αποφάσεων σε μορφή δέντρου, βασισμένο στα features των δεδομένων. Κάθε internal node του δέντρου αντιπροσωπεύει έναν έλεγχο σε ένα συγκεκριμένο feature, κάθε branch αντιπροσωπεύει ένα αποτέλεσμα αυτού του ελέγχου και κάθε leaf node αντιπροσωπεύει μια προβλεπόμενη κλάση (για classification) ή τιμή (για regression).<sup>[[2]](#references)</sup>

Για την κατασκευή ενός δέντρου, algorithms όπως το CART (Classification and Regression Tree) χρησιμοποιούν μέτρα όπως το **Gini impurity** ή το **information gain (entropy)**, ώστε να επιλέξουν το καλύτερο feature και threshold για τον διαχωρισμό των δεδομένων σε κάθε βήμα. Ο στόχος σε κάθε διαχωρισμό είναι η κατάτμηση των δεδομένων με τρόπο που αυξάνει την ομοιογένεια της target variable στα resulting subsets (για classification, κάθε node πρέπει να είναι όσο το δυνατόν πιο pure, περιέχοντας κατά κύριο λόγο μία μόνο κλάση).

Τα decision trees είναι **highly interpretable** -- μπορεί κανείς να ακολουθήσει τη διαδρομή από το root έως το leaf, για να κατανοήσει τη λογική πίσω από μια prediction (π.χ., *"IF `service = telnet` AND `src_bytes > 1000` AND `failed_logins > 3` THEN classify as attack"*). Αυτό είναι πολύτιμο στο cybersecurity για την εξήγηση του λόγου για τον οποίο δημιουργήθηκε ένα συγκεκριμένο alert. Τα trees μπορούν να διαχειριστούν φυσικά τόσο numerical όσο και categorical data και απαιτούν ελάχιστο preprocessing (π.χ. δεν χρειάζεται feature scaling).

Ωστόσο, ένα μεμονωμένο decision tree μπορεί εύκολα να κάνει overfit στα training data, ειδικά αν αναπτυχθεί σε μεγάλο βάθος (πολλά splits). Τεχνικές όπως το pruning (περιορισμός του βάθους του δέντρου ή απαίτηση για έναν ελάχιστο αριθμό samples ανά leaf) χρησιμοποιούνται συχνά για την αποφυγή του overfitting.

Υπάρχουν 3 κύρια components ενός decision tree:
- **Root Node**: Ο ανώτατος node του δέντρου, που αντιπροσωπεύει ολόκληρο το dataset.
- **Internal Nodes**: Nodes που αντιπροσωπεύουν features και decisions βασισμένα σε αυτά τα features.
- **Leaf Nodes**: Nodes που αντιπροσωπεύουν το τελικό outcome ή prediction.

Ένα tree μπορεί τελικά να μοιάζει κάπως έτσι:
```plaintext
[Root Node]
/   \
[Node A]  [Node B]
/   \      /   \
[Leaf 1] [Leaf 2] [Leaf 3] [Leaf 4]
```
> [!TIP]
> *Περιπτώσεις χρήσης στην κυβερνοασφάλεια:* Τα Decision Trees έχουν χρησιμοποιηθεί σε intrusion detection systems για την εξαγωγή **κανόνων** αναγνώρισης επιθέσεων. Για παράδειγμα, πρώιμα IDS βασισμένα στα ID3/C4.5 δημιουργούσαν ευανάγνωστους κανόνες για να διακρίνουν την κανονική από την κακόβουλη κίνηση. Χρησιμοποιούνται επίσης στην ανάλυση malware για να αποφασιστεί αν ένα αρχείο είναι κακόβουλο, με βάση τα χαρακτηριστικά του (μέγεθος αρχείου, entropy των sections, κλήσεις API κ.λπ.). Η σαφήνεια των Decision Trees τα καθιστά χρήσιμα όταν απαιτείται διαφάνεια -- ένας analyst μπορεί να επιθεωρήσει το tree για να επικυρώσει τη λογική detection.

#### **Βασικά χαρακτηριστικά των Decision Trees:**

-   **Τύπος προβλήματος:** Τόσο classification όσο και regression. Χρησιμοποιούνται συχνά για classification επιθέσεων έναντι κανονικής κίνησης κ.λπ.

-   **Ερμηνευσιμότητα:** Πολύ υψηλή -- οι αποφάσεις του model μπορούν να οπτικοποιηθούν και να γίνουν κατανοητές ως ένα σύνολο κανόνων if-then. Αυτό αποτελεί σημαντικό πλεονέκτημα στην ασφάλεια για την εμπιστοσύνη και την επαλήθευση της συμπεριφοράς του model.

-   **Πλεονεκτήματα:** Μπορούν να αποτυπώσουν μη γραμμικές σχέσεις και αλληλεπιδράσεις μεταξύ features (κάθε split μπορεί να θεωρηθεί αλληλεπίδραση). Δεν χρειάζεται scaling των features ή one-hot encoding των categorical variables -- τα trees τα διαχειρίζονται εγγενώς. Γρήγορο inference (η πρόβλεψη είναι απλώς η ακολούθηση μιας διαδρομής στο tree).

-   **Περιορισμοί:** Είναι επιρρεπή σε overfitting αν δεν ελεγχθούν (ένα βαθύ tree μπορεί να απομνημονεύσει το training set). Μπορεί να είναι ασταθή -- μικρές αλλαγές στα δεδομένα ενδέχεται να οδηγήσουν σε διαφορετική δομή tree. Ως μεμονωμένα models, η ακρίβειά τους μπορεί να μην είναι αντίστοιχη πιο προηγμένων μεθόδων (ensembles όπως τα Random Forests συνήθως αποδίδουν καλύτερα, μειώνοντας το variance).

-   **Εύρεση του καλύτερου split:**
- **Gini Impurity**: Μετρά την impurity ενός node. Μικρότερη Gini impurity υποδεικνύει καλύτερο split. Ο τύπος είναι:

```plaintext
Gini = 1 - Σ(p_i^2)
```

Όπου το `p_i` είναι η αναλογία των instances στην κλάση `i`.

- **Entropy**: Μετρά την αβεβαιότητα στο dataset. Μικρότερη entropy υποδεικνύει καλύτερο split. Ο τύπος είναι:

```plaintext
Entropy = -Σ(p_i * log2(p_i))
```

Όπου το `p_i` είναι η αναλογία των instances στην κλάση `i`.

- **Information Gain**: Η μείωση της entropy ή της Gini impurity μετά από ένα split. Όσο μεγαλύτερο είναι το information gain, τόσο καλύτερο είναι το split. Υπολογίζεται ως εξής:

```plaintext
Information Gain = Entropy(parent) - (Weighted Average of Entropy(children))
```

Επιπλέον, ένα tree τερματίζεται όταν:
- Όλα τα instances σε ένα node ανήκουν στην ίδια κλάση. Αυτό μπορεί να οδηγήσει σε overfitting.
- Επιτευχθεί το μέγιστο βάθος (hardcoded) του tree. Αυτό είναι ένας τρόπος αποτροπής του overfitting.
- Ο αριθμός των instances σε ένα node είναι μικρότερος από ένα συγκεκριμένο threshold. Αυτός είναι επίσης ένας τρόπος αποτροπής του overfitting.
- Το information gain από περαιτέρω splits είναι μικρότερο από ένα συγκεκριμένο threshold. Αυτός είναι επίσης ένας τρόπος αποτροπής του overfitting.

<details>
<summary>Παράδειγμα -- Decision Tree για Intrusion Detection:</summary>
Θα εκπαιδεύσουμε ένα decision tree στο dataset NSL-KDD για να ταξινομήσουμε τις network connections είτε ως *normal* είτε ως *attack*. Το NSL-KDD είναι μια βελτιωμένη έκδοση του κλασικού dataset KDD Cup 1999, με features όπως protocol type, service, duration, αριθμό αποτυχημένων logins κ.λπ., και ένα label που υποδεικνύει τον τύπο επίθεσης ή την ένδειξη "normal". Θα αντιστοιχίσουμε όλους τους τύπους επιθέσεων στην κλάση "anomaly" (binary classification: normal έναντι anomaly). Μετά την εκπαίδευση, θα αξιολογήσουμε την απόδοση του tree στο test set.
```python
import pandas as pd
from sklearn.tree import DecisionTreeClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score

# 1️⃣  NSL‑KDD column names (41 features + class + difficulty)
col_names = [
"duration","protocol_type","service","flag","src_bytes","dst_bytes","land",
"wrong_fragment","urgent","hot","num_failed_logins","logged_in","num_compromised",
"root_shell","su_attempted","num_root","num_file_creations","num_shells",
"num_access_files","num_outbound_cmds","is_host_login","is_guest_login","count",
"srv_count","serror_rate","srv_serror_rate","rerror_rate","srv_rerror_rate",
"same_srv_rate","diff_srv_rate","srv_diff_host_rate","dst_host_count",
"dst_host_srv_count","dst_host_same_srv_rate","dst_host_diff_srv_rate",
"dst_host_same_src_port_rate","dst_host_srv_diff_host_rate","dst_host_serror_rate",
"dst_host_srv_serror_rate","dst_host_rerror_rate","dst_host_srv_rerror_rate",
"class","difficulty_level"
]

# 2️⃣  Load data ➜ *headerless* CSV
train_url = "https://raw.githubusercontent.com/Mamcose/NSL-KDD-Network-Intrusion-Detection/master/NSL_KDD_Train.csv"
test_url  = "https://raw.githubusercontent.com/Mamcose/NSL-KDD-Network-Intrusion-Detection/master/NSL_KDD_Test.csv"

df_train = pd.read_csv(train_url, header=None, names=col_names)
df_test  = pd.read_csv(test_url,  header=None, names=col_names)

# 3️⃣  Encode the 3 nominal features
for col in ['protocol_type', 'service', 'flag']:
le = LabelEncoder().fit(pd.concat([df_train[col], df_test[col]]))
df_train[col] = le.transform(df_train[col])
df_test[col]  = le.transform(df_test[col])

# 4️⃣  Prepare X / y   (binary: 0 = normal, 1 = attack)
X_train = df_train.drop(columns=['class', 'difficulty_level'])
y_train = (df_train['class'].str.lower() != 'normal').astype(int)

X_test  = df_test.drop(columns=['class', 'difficulty_level'])
y_test  = (df_test['class'].str.lower() != 'normal').astype(int)

# 5️⃣  Train Decision‑Tree
clf = DecisionTreeClassifier(max_depth=10, random_state=42)
clf.fit(X_train, y_train)

# 6️⃣  Evaluate
y_pred = clf.predict(X_test)
y_prob = clf.predict_proba(X_test)[:, 1]

print(f"Accuracy : {accuracy_score(y_test, y_pred):.3f}")
print(f"Precision: {precision_score(y_test, y_pred):.3f}")
print(f"Recall   : {recall_score(y_test, y_pred):.3f}")
print(f"F1‑score : {f1_score(y_test, y_pred):.3f}")
print(f"ROC AUC  : {roc_auc_score(y_test, y_prob):.3f}")


"""
Accuracy : 0.772
Precision: 0.967
Recall   : 0.621
F1‑score : 0.756
ROC AUC  : 0.758
"""
```
Σε αυτό το παράδειγμα decision tree, περιορίσαμε το βάθος του tree στο 10 για να αποφύγουμε το ακραίο overfitting (η παράμετρος `max_depth=10`). Τα metrics δείχνουν πόσο καλά το tree διακρίνει την κανονική από την attack traffic. Το υψηλό recall σημαίνει ότι εντοπίζει τις περισσότερες attacks (κάτι σημαντικό για ένα IDS), ενώ το υψηλό precision σημαίνει λίγους false alarms. Τα decision trees συχνά επιτυγχάνουν ικανοποιητική accuracy σε structured data, όμως ένα μεμονωμένο tree μπορεί να μην πετύχει την καλύτερη δυνατή performance. Παρ' όλα αυτά, η *interpretability* του model αποτελεί σημαντικό πλεονέκτημα -- θα μπορούσαμε να εξετάσουμε τα splits του tree για να δούμε, για παράδειγμα, ποια features (π.χ. `service`, `src_bytes` κ.λπ.) επηρεάζουν περισσότερο την επισήμανση μιας connection ως malicious.

</details>

### Random Forests

Το Random Forest είναι μια μέθοδος **ensemble learning** που βασίζεται σε decision trees για τη βελτίωση της performance. Ένα random forest εκπαιδεύει πολλαπλά decision trees (εξ ου και το "forest") και συνδυάζει τα outputs τους για να κάνει μια τελική πρόβλεψη (για classification, συνήθως μέσω majority vote). Οι δύο βασικές ιδέες σε ένα random forest είναι το **bagging** (bootstrap aggregating) και η **feature randomness**:

-   **Bagging:** Κάθε tree εκπαιδεύεται σε ένα τυχαίο bootstrap sample των training data (με sampling with replacement). Αυτό εισάγει diversity μεταξύ των trees.

-   **Feature Randomness:** Σε κάθε split ενός tree, εξετάζεται ένα τυχαίο subset των features για το splitting (αντί για όλα τα features). Αυτό αποσυσχετίζει ακόμη περισσότερο τα trees.

Με τον υπολογισμό του average των results πολλών trees, το random forest μειώνει το variance που μπορεί να έχει ένα μεμονωμένο decision tree. Με απλά λόγια, τα μεμονωμένα trees μπορεί να κάνουν overfit ή να είναι noisy, όμως ένας μεγάλος αριθμός διαφορετικών trees που ψηφίζουν από κοινού εξομαλύνει αυτά τα errors. Το αποτέλεσμα είναι συχνά ένα model με **υψηλότερη accuracy** και καλύτερο generalization από ένα μεμονωμένο decision tree. Επιπλέον, τα random forests μπορούν να παρέχουν μια εκτίμηση του feature importance (εξετάζοντας πόσο κάθε feature split μειώνει κατά μέσο όρο το impurity).

Τα random forests έχουν εξελιχθεί σε **workhorse στην cybersecurity** για tasks όπως intrusion detection, malware classification και spam detection. Συνήθως έχουν καλή performance out-of-the-box με ελάχιστο tuning και μπορούν να διαχειριστούν μεγάλα feature sets. Για παράδειγμα, στο intrusion detection, ένα random forest μπορεί να ξεπεράσει ένα μεμονωμένο decision tree εντοπίζοντας πιο subtle patterns attacks με λιγότερα false positives. Research έχει δείξει ότι τα random forests έχουν ευνοϊκή performance σε σύγκριση με άλλους algorithms στην ταξινόμηση attacks σε datasets όπως τα NSL-KDD και UNSW-NB15.<sup>[[3]](#references)[[9]](#references)</sup>

#### **Βασικά χαρακτηριστικά των Random Forests:**

-   **Τύπος προβλήματος:** Κυρίως classification (χρησιμοποιείται επίσης για regression). Είναι ιδιαίτερα κατάλληλο για high-dimensional structured data, τα οποία συναντώνται συχνά σε security logs.

-   **Interpretability:** Χαμηλότερη από ενός μεμονωμένου decision tree -- δεν μπορείτε εύκολα να visualise ή να εξηγήσετε εκατοντάδες trees ταυτόχρονα. Ωστόσο, τα feature importance scores παρέχουν κάποια εικόνα για το ποια attributes επηρεάζουν περισσότερο το αποτέλεσμα.

-   **Πλεονεκτήματα:** Γενικά υψηλότερη accuracy από τα single-tree models λόγω του ensemble effect. Είναι robust απέναντι στο overfitting -- ακόμη και αν μεμονωμένα trees κάνουν overfit, το ensemble κάνει καλύτερο generalization. Διαχειρίζεται numerical και categorical features και μπορεί να διαχειριστεί missing data σε κάποιο βαθμό. Είναι επίσης σχετικά robust σε outliers.

-   **Περιορισμοί:** Το model size μπορεί να είναι μεγάλο (πολλά trees, καθένα από τα οποία μπορεί να είναι deep). Οι predictions είναι πιο αργές από ενός single tree (καθώς πρέπει να γίνει aggregation σε πολλά trees). Είναι λιγότερο interpretable -- ενώ γνωρίζετε τα important features, η ακριβής logic δεν μπορεί εύκολα να trace-αριστεί όπως ένας απλός rule. Αν το dataset είναι extremely high-dimensional και sparse, η εκπαίδευση ενός πολύ μεγάλου forest μπορεί να απαιτεί σημαντικούς computational resources.

-   **Training Process:**
1. **Bootstrap Sampling**: Κάντε τυχαίο sample των training data με replacement για να δημιουργήσετε πολλαπλά subsets (bootstrap samples).
2. **Tree Construction**: Για κάθε bootstrap sample, δημιουργήστε ένα decision tree χρησιμοποιώντας ένα random subset των features σε κάθε split. Αυτό εισάγει diversity μεταξύ των trees.
3. **Aggregation**: Για classification tasks, η τελική prediction πραγματοποιείται με majority vote μεταξύ των predictions όλων των trees. Για regression tasks, η τελική prediction είναι ο average των predictions όλων των trees.

<details>
<summary>Παράδειγμα -- Random Forest για Intrusion Detection (NSL-KDD):</summary>
Θα χρησιμοποιήσουμε το ίδιο NSL-KDD dataset (με binary labels ως normal ή anomaly) και θα εκπαιδεύσουμε έναν Random Forest classifier. Αναμένουμε ότι το random forest θα έχει performance ίση ή καλύτερη από το single decision tree, χάρη στο ensemble averaging που μειώνει το variance. Θα το αξιολογήσουμε με τα ίδια metrics.
```python
import pandas as pd
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, precision_score,
recall_score, f1_score, roc_auc_score)

# ──────────────────────────────────────────────
# 1. LOAD DATA  ➜  files have **no header row**, so we
#                 pass `header=None` and give our own column names.
# ──────────────────────────────────────────────
col_names = [                       # 41 features + 2 targets
"duration","protocol_type","service","flag","src_bytes","dst_bytes","land",
"wrong_fragment","urgent","hot","num_failed_logins","logged_in",
"num_compromised","root_shell","su_attempted","num_root","num_file_creations",
"num_shells","num_access_files","num_outbound_cmds","is_host_login",
"is_guest_login","count","srv_count","serror_rate","srv_serror_rate",
"rerror_rate","srv_rerror_rate","same_srv_rate","diff_srv_rate",
"srv_diff_host_rate","dst_host_count","dst_host_srv_count",
"dst_host_same_srv_rate","dst_host_diff_srv_rate",
"dst_host_same_src_port_rate","dst_host_srv_diff_host_rate",
"dst_host_serror_rate","dst_host_srv_serror_rate","dst_host_rerror_rate",
"dst_host_srv_rerror_rate","class","difficulty_level"
]

train_url = "https://raw.githubusercontent.com/Mamcose/NSL-KDD-Network-Intrusion-Detection/master/NSL_KDD_Train.csv"
test_url  = "https://raw.githubusercontent.com/Mamcose/NSL-KDD-Network-Intrusion-Detection/master/NSL_KDD_Test.csv"

df_train = pd.read_csv(train_url, header=None, names=col_names)
df_test  = pd.read_csv(test_url,  header=None, names=col_names)

# ──────────────────────────────────────────────
# 2. PRE‑PROCESSING
# ──────────────────────────────────────────────
# 2‑a) Encode the three categorical columns so that the model
#      receives integers instead of strings.
#      LabelEncoder gives an int to each unique value in the column: {'icmp':0, 'tcp':1, 'udp':2}
for col in ['protocol_type', 'service', 'flag']:
le = LabelEncoder().fit(pd.concat([df_train[col], df_test[col]]))
df_train[col] = le.transform(df_train[col])
df_test[col]  = le.transform(df_test[col])

# 2‑b) Build feature matrix X  (drop target & difficulty)
X_train = df_train.drop(columns=['class', 'difficulty_level'])
X_test  = df_test.drop(columns=['class', 'difficulty_level'])

# 2‑c) Convert multi‑class labels to binary
#      label 0 → 'normal' traffic, label 1 → any attack
y_train = (df_train['class'].str.lower() != 'normal').astype(int)
y_test  = (df_test['class'].str.lower() != 'normal').astype(int)

# ──────────────────────────────────────────────
# 3. MODEL: RANDOM FOREST
# ──────────────────────────────────────────────
# • n_estimators = 100 ➜ build 100 different decision‑trees.
# • max_depth=None  ➜ let each tree grow until pure leaves
#                    (or until it hits other stopping criteria).
# • random_state=42 ➜ reproducible randomness.
model = RandomForestClassifier(
n_estimators=100,
max_depth=None,
random_state=42,
bootstrap=True          # default: each tree is trained on a
# bootstrap sample the same size as
# the original training set.
# max_samples           # ← you can set this (float or int) to
#     use a smaller % of samples per tree.
)

model.fit(X_train, y_train)

# ──────────────────────────────────────────────
# 4. EVALUATION
# ──────────────────────────────────────────────
y_pred = model.predict(X_test)
y_prob = model.predict_proba(X_test)[:, 1]

print(f"Accuracy : {accuracy_score(y_test, y_pred):.3f}")
print(f"Precision: {precision_score(y_test, y_pred):.3f}")
print(f"Recall   : {recall_score(y_test, y_pred):.3f}")
print(f"F1‑score : {f1_score(y_test, y_pred):.3f}")
print(f"ROC AUC  : {roc_auc_score(y_test, y_prob):.3f}")

"""
Accuracy:  0.770
Precision: 0.966
Recall:    0.618
F1-score:  0.754
ROC AUC:   0.962
"""
```
Το random forest συνήθως επιτυγχάνει ισχυρά αποτελέσματα σε αυτή την εργασία ανίχνευσης εισβολών. Ενδέχεται να παρατηρήσουμε βελτίωση σε metrics όπως το F1 ή το AUC σε σύγκριση με το μεμονωμένο decision tree, ειδικά στο recall ή το precision, ανάλογα με τα δεδομένα. Αυτό συμφωνεί με την αντίληψη ότι το *"Random Forest (RF) είναι ένας ensemble classifier και αποδίδει καλά σε σύγκριση με άλλους traditional classifiers για την αποτελεσματική classification επιθέσεων."*. Σε ένα security operations context, ένα μοντέλο random forest μπορεί να εντοπίζει επιθέσεις με μεγαλύτερη αξιοπιστία, μειώνοντας παράλληλα τους false alarms, χάρη στον μέσο όρο πολλών decision rules. Η feature importance από το forest θα μπορούσε να μας δείξει ποια network features είναι περισσότερο ενδεικτικά επιθέσεων (π.χ. συγκεκριμένες network services ή ασυνήθιστοι αριθμοί από packets).

</details>

### Support Vector Machines (SVM)

Τα Support Vector Machines είναι ισχυρά supervised learning models που χρησιμοποιούνται κυρίως για classification (και επίσης για regression ως SVR). Ένα SVM προσπαθεί να βρει το **optimal separating hyperplane** που μεγιστοποιεί το margin μεταξύ δύο classes. Μόνο ένα υποσύνολο των training points (τα "support vectors" που βρίσκονται πιο κοντά στο boundary) καθορίζει τη θέση αυτού του hyperplane. Με τη μεγιστοποίηση του margin (της απόστασης μεταξύ των support vectors και του hyperplane), τα SVM τείνουν να επιτυγχάνουν καλή γενίκευση.<sup>[[4]](#references)</sup>

Κλειδί για την ισχύ των SVM είναι η δυνατότητα χρήσης **kernel functions** για τον χειρισμό non-linear relationships. Τα δεδομένα μπορούν να μετασχηματιστούν implicit σε έναν feature space υψηλότερης διάστασης, όπου μπορεί να υπάρχει ένας linear separator. Συνήθη kernels είναι τα polynomial, radial basis function (RBF) και sigmoid. Για παράδειγμα, αν οι classes του network traffic δεν είναι linearly separable στον raw feature space, ένα RBF kernel μπορεί να τις αντιστοιχίσει σε υψηλότερη διάσταση, όπου το SVM βρίσκει ένα linear split (το οποίο αντιστοιχεί σε non-linear boundary στον αρχικό space). Η ευελιξία επιλογής kernels επιτρέπει στα SVM να αντιμετωπίζουν μια ποικιλία προβλημάτων.

Τα SVM είναι γνωστό ότι αποδίδουν καλά σε περιπτώσεις με high-dimensional feature spaces (όπως text data ή malware opcode sequences) και σε περιπτώσεις όπου ο αριθμός των features είναι μεγάλος σε σχέση με τον αριθμό των samples. Ήταν δημοφιλή σε πολλές πρώιμες cybersecurity εφαρμογές, όπως το malware classification και το anomaly-based intrusion detection τη δεκαετία του 2000, παρουσιάζοντας συχνά υψηλό accuracy.

Ωστόσο, τα SVM δεν κλιμακώνονται εύκολα σε πολύ μεγάλα datasets (η training complexity είναι super-linear ως προς τον αριθμό των samples και η memory usage μπορεί να είναι υψηλή, καθώς ενδέχεται να χρειάζεται να αποθηκεύσουν πολλά support vectors). Στην πράξη, για εργασίες όπως το network intrusion detection με εκατομμύρια records, ένα SVM μπορεί να είναι υπερβολικά αργό χωρίς προσεκτικό subsampling ή τη χρήση approximate methods.

#### **Βασικά χαρακτηριστικά του SVM:**

-   **Τύπος προβλήματος:** Classification (binary ή multiclass μέσω one-vs-one/one-vs-rest) και regression variants. Χρησιμοποιείται συχνά σε binary classification με σαφή margin separation.

-   **Interpretability:** Medium -- Τα SVM δεν είναι τόσο interpretable όσο τα decision trees ή το logistic regression. Παρότι μπορείτε να προσδιορίσετε ποια data points είναι support vectors και να αποκτήσετε κάποια εικόνα για το ποια features μπορεί να είναι influential (μέσω των weights στην περίπτωση του linear kernel), στην πράξη τα SVM (ειδικά με non-linear kernels) αντιμετωπίζονται ως black-box classifiers.

-   **Πλεονεκτήματα:** Effective σε high-dimensional spaces· μπορούν να μοντελοποιήσουν complex decision boundaries με το kernel trick· robust απέναντι στο overfitting όταν μεγιστοποιείται το margin (ειδικά με κατάλληλη regularization parameter C)· λειτουργούν καλά ακόμη και όταν οι classes δεν διαχωρίζονται με μεγάλη απόσταση (βρίσκουν το καλύτερο compromise boundary).

-   **Περιορισμοί:** **Computationally intensive** για μεγάλα datasets (τόσο το training όσο και το prediction κλιμακώνονται ανεπαρκώς καθώς αυξάνονται τα δεδομένα). Απαιτούν προσεκτικό tuning των kernel και regularization parameters (C, kernel type, gamma για RBF κ.λπ.). Δεν παρέχουν άμεσα probabilistic outputs (αν και μπορεί να χρησιμοποιηθεί Platt scaling για την απόκτηση probabilities). Επίσης, τα SVM μπορεί να είναι ευαίσθητα στην επιλογή των kernel parameters --- μια κακή επιλογή μπορεί να οδηγήσει σε underfit ή overfit.

*Use cases in cybersecurity:* Τα SVM έχουν χρησιμοποιηθεί στο **malware detection** (π.χ. για την ταξινόμηση files με βάση extracted features ή opcode sequences), στο **network anomaly detection** (classification του traffic ως normal ή malicious) και στο **phishing detection** (με χρήση features των URLs). Για παράδειγμα, ένα SVM θα μπορούσε να λάβει features ενός email (counts συγκεκριμένων keywords, sender reputation scores κ.λπ.) και να το ταξινομήσει ως phishing ή legitimate. Έχουν επίσης εφαρμοστεί στο **intrusion detection** σε feature sets όπως το KDD, επιτυγχάνοντας συχνά υψηλό accuracy με κόστος σε computation.

<details>
<summary>Παράδειγμα -- SVM για Malware Classification:</summary>
Θα χρησιμοποιήσουμε ξανά το phishing website dataset, αυτή τη φορά με ένα SVM. Επειδή τα SVM μπορεί να είναι αργά, θα χρησιμοποιήσουμε ένα subset των δεδομένων για το training, αν χρειαστεί (το dataset περιλαμβάνει περίπου 11k instances, τα οποία ένα SVM μπορεί να διαχειριστεί reasonably). Θα χρησιμοποιήσουμε ένα RBF kernel, το οποίο αποτελεί συνηθισμένη επιλογή για non-linear data, και θα ενεργοποιήσουμε τα probability estimates για να υπολογίσουμε το ROC AUC.
```python
import pandas as pd
from sklearn.datasets import fetch_openml
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC
from sklearn.metrics import (accuracy_score, precision_score,
recall_score, f1_score, roc_auc_score)

# ─────────────────────────────────────────────────────────────
# 1️⃣  LOAD DATASET   (OpenML id 4534: “PhishingWebsites”)
#     • as_frame=True  ➜  returns a pandas DataFrame
# ─────────────────────────────────────────────────────────────
data = fetch_openml(data_id=4534, as_frame=True)   # or data_name="PhishingWebsites"
df   = data.frame
print(df.head())          # quick sanity‑check

# ─────────────────────────────────────────────────────────────
# 2️⃣  TARGET: 0 = legitimate, 1 = phishing
#     The raw column has values {1, 0, -1}:
#       1  → legitimate   → 0
#       0  &  -1          → phishing    → 1
# ─────────────────────────────────────────────────────────────
y = (df["Result"].astype(int) != 1).astype(int)
X = df.drop(columns=["Result"])

# Train / test split  (stratified keeps class proportions)
X_train, X_test, y_train, y_test = train_test_split(
X, y, test_size=0.20, random_state=42, stratify=y)

# ─────────────────────────────────────────────────────────────
# 3️⃣  PRE‑PROCESS: Standardize features (mean‑0 / std‑1)
# ─────────────────────────────────────────────────────────────
scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test  = scaler.transform(X_test)

# ─────────────────────────────────────────────────────────────
# 4️⃣  MODEL: RBF‑kernel SVM
#     • C=1.0         (regularization strength)
#     • gamma='scale' (1 / [n_features × var(X)])
#     • probability=True  → enable predict_proba for ROC‑AUC
# ─────────────────────────────────────────────────────────────
clf = SVC(kernel="rbf", C=1.0, gamma="scale",
probability=True, random_state=42)
clf.fit(X_train, y_train)

# ─────────────────────────────────────────────────────────────
# 5️⃣  EVALUATION
# ─────────────────────────────────────────────────────────────
y_pred = clf.predict(X_test)
y_prob = clf.predict_proba(X_test)[:, 1]   # P(class 1)

print(f"Accuracy : {accuracy_score(y_test, y_pred):.3f}")
print(f"Precision: {precision_score(y_test, y_pred):.3f}")
print(f"Recall   : {recall_score(y_test, y_pred):.3f}")
print(f"F1‑score : {f1_score(y_test, y_pred):.3f}")
print(f"ROC AUC  : {roc_auc_score(y_test, y_prob):.3f}")

"""
Accuracy : 0.956
Precision: 0.963
Recall   : 0.937
F1‑score : 0.950
ROC AUC  : 0.989
"""
```
Το μοντέλο SVM θα输出 métrics που μπορούμε να συγκρίνουμε με το logistic regression στην ίδια εργασία. Ίσως διαπιστώσουμε ότι το SVM επιτυγχάνει υψηλή accuracy και AUC, αν τα δεδομένα διαχωρίζονται καλά από τα features. Από την άλλη πλευρά, αν το dataset περιείχε πολύ θόρυβο ή επικαλυπτόμενες κλάσεις, το SVM μπορεί να μην υπερέχει σημαντικά του logistic regression. Στην πράξη, τα SVM μπορούν να προσφέρουν βελτίωση όταν υπάρχουν σύνθετες, μη γραμμικές σχέσεις μεταξύ των features και της κλάσης -- ο kernel RBF μπορεί να αποτυπώσει καμπύλα όρια απόφασης που το logistic regression θα έχανε. Όπως συμβαίνει με όλα τα μοντέλα, απαιτείται προσεκτική ρύθμιση των παραμέτρων `C` (regularization) και των παραμέτρων του kernel (όπως το `gamma` για το RBF), ώστε να επιτευχθεί ισορροπία μεταξύ bias και variance.

</details>

#### Διαφορά μεταξύ Logistic Regression & SVM

| Aspect | **Logistic Regression** | **Support Vector Machines** |
|---|---|---|
| **Objective function** | Ελαχιστοποιεί το **log‑loss** (cross-entropy). | Μεγιστοποιεί το **margin**, ελαχιστοποιώντας παράλληλα το **hinge‑loss**. |
| **Decision boundary** | Βρίσκει το **best‑fit hyperplane** που μοντελοποιεί το _P(y\|x)_. | Βρίσκει το **maximum‑margin hyperplane** (το μεγαλύτερο κενό από τα κοντινότερα σημεία). |
| **Output** | **Probabilistic** – παρέχει βαθμονομημένες πιθανότητες κλάσεων μέσω του σ(w·x + b). | **Deterministic** – επιστρέφει labels κλάσεων· οι πιθανότητες απαιτούν επιπλέον επεξεργασία (π.χ. Platt scaling). |
| **Regularisation** | L2 (default) ή L1, εξισορροπεί άμεσα το under/over‑fitting. | Η παράμετρος C ανταλλάσσει το πλάτος του margin με τις εσφαλμένες ταξινομήσεις· οι παράμετροι του kernel προσθέτουν πολυπλοκότητα. |
| **Kernels / Non‑linear** | Η εγγενής μορφή είναι **linear**· η μη γραμμικότητα προστίθεται μέσω feature engineering. | Το ενσωματωμένο **kernel trick** (RBF, poly κ.λπ.) του επιτρέπει να μοντελοποιεί σύνθετα όρια σε χώρο υψηλών διαστάσεων. |
| **Scalability** | Επιλύει μια convex optimisation σε **O(nd)**· διαχειρίζεται καλά πολύ μεγάλα n. | Η εκπαίδευση μπορεί να απαιτεί **O(n²–n³)** σε memory/time χωρίς specialised solvers· είναι λιγότερο κατάλληλη για τεράστιο n. |
| **Interpretability** | **Υψηλή** – τα weights δείχνουν την επιρροή των features· το odds ratio είναι διαισθητικό. | **Χαμηλή** για μη γραμμικούς kernels· τα support vectors είναι sparse, αλλά δεν εξηγούνται εύκολα. |
| **Sensitivity to outliers** | Χρησιμοποιεί ομαλό log‑loss → λιγότερο ευαίσθητο. | Το hinge‑loss με hard margin μπορεί να είναι **ευαίσθητο**· το soft‑margin (C) το μετριάζει. |
| **Typical use cases** | Credit scoring, ιατρικός κίνδυνος, A/B testing – όπου έχουν σημασία οι **πιθανότητες και η explainability**. | Image/text classification, bio-informatics – όπου έχουν σημασία τα **σύνθετα όρια** και τα **high‑dimensional data**. |

* **Αν χρειάζεστε calibrated probabilities, interpretability ή εργάζεστε με τεράστια datasets — επιλέξτε Logistic Regression.**
* **Αν χρειάζεστε ένα ευέλικτο μοντέλο που μπορεί να αποτυπώσει μη γραμμικές σχέσεις χωρίς χειροκίνητο feature engineering — επιλέξτε SVM (με kernels).**
* Και τα δύο βελτιστοποιούν convex objectives, επομένως **τα global minima είναι εγγυημένα**, αλλά οι kernels του SVM προσθέτουν hyper‑parameters και computational cost.

### Naive Bayes

Το Naive Bayes είναι μια οικογένεια **probabilistic classifiers** που βασίζεται στην εφαρμογή του Bayes' Theorem, με μια ισχυρή υπόθεση ανεξαρτησίας μεταξύ των features. Παρά αυτήν τη "naive" υπόθεση, το Naive Bayes συχνά λειτουργεί εκπληκτικά καλά σε ορισμένες εφαρμογές, ιδιαίτερα σε εκείνες που περιλαμβάνουν text ή categorical data, όπως η ανίχνευση spam.<sup>[[5]](#references)</sup>


#### Bayes' Theorem

Το θεώρημα του Bayes αποτελεί τη βάση των Naive Bayes classifiers. Συσχετίζει τις conditional και marginal probabilities τυχαίων γεγονότων. Ο τύπος είναι ο εξής:
```plaintext
P(A|B) = (P(B|A) * P(A)) / P(B)
```
Where:
- `P(A|B)` είναι η posterior probability της κλάσης `A` δεδομένου του feature `B`.
- `P(B|A)` είναι η likelihood του feature `B` δεδομένης της κλάσης `A`.
- `P(A)` είναι η prior probability της κλάσης `A`.
- `P(B)` είναι η prior probability του feature `B`.

Για παράδειγμα, αν θέλουμε να ταξινομήσουμε αν ένα κείμενο έχει γραφτεί από παιδί ή ενήλικα, μπορούμε να χρησιμοποιήσουμε τις λέξεις του κειμένου ως features. Με βάση κάποια αρχικά δεδομένα, ο Naive Bayes classifier θα υπολογίσει εκ των προτέρων τις πιθανότητες κάθε λέξης να ανήκει σε κάθε πιθανή κλάση (παιδί ή ενήλικας). Όταν δοθεί ένα νέο κείμενο, θα υπολογίσει την πιθανότητα κάθε πιθανής κλάσης δεδομένων των λέξεων του κειμένου και θα επιλέξει την κλάση με τη μεγαλύτερη πιθανότητα.

Όπως μπορείτε να δείτε σε αυτό το παράδειγμα, ο Naive Bayes classifier είναι πολύ απλός και γρήγορος, αλλά υποθέτει ότι τα features είναι ανεξάρτητα, κάτι που δεν ισχύει πάντα σε δεδομένα του πραγματικού κόσμου.


#### Τύποι Naive Bayes Classifiers

Υπάρχουν αρκετοί τύποι Naive Bayes classifiers, ανάλογα με τον τύπο των δεδομένων και την κατανομή των features:
- **Gaussian Naive Bayes**: Υποθέτει ότι τα features ακολουθούν Gaussian (normal) κατανομή. Είναι κατάλληλος για συνεχή δεδομένα.
- **Multinomial Naive Bayes**: Υποθέτει ότι τα features ακολουθούν multinomial κατανομή. Είναι κατάλληλος για διακριτά δεδομένα, όπως οι μετρήσεις λέξεων σε text classification.
- **Bernoulli Naive Bayes**: Υποθέτει ότι τα features είναι δυαδικά (0 ή 1). Είναι κατάλληλος για δυαδικά δεδομένα, όπως η παρουσία ή απουσία λέξεων σε text classification.
- **Categorical Naive Bayes**: Υποθέτει ότι τα features είναι categorical variables. Είναι κατάλληλος για categorical δεδομένα, όπως η ταξινόμηση φρούτων με βάση το χρώμα και το σχήμα τους.


#### **Βασικά χαρακτηριστικά του Naive Bayes:**

-   **Τύπος προβλήματος:** Classification (binary ή multi-class). Χρησιμοποιείται συχνά σε text classification tasks στην κυβερνοασφάλεια (spam, phishing κ.λπ.).

-   **Interpretability:** Medium -- δεν είναι τόσο άμεσα ερμηνεύσιμος όσο ένα decision tree, αλλά μπορεί κανείς να εξετάσει τις learned probabilities (π.χ. ποιες λέξεις είναι πιθανότερο να εμφανίζονται σε spam σε σύγκριση με ham emails). Η μορφή του model (πιθανότητες για κάθε feature δεδομένης της κλάσης) μπορεί να γίνει κατανοητή, αν χρειαστεί.

-   **Πλεονεκτήματα:** **Πολύ γρήγορο** training και prediction, ακόμη και σε μεγάλα datasets (γραμμική πολυπλοκότητα ως προς τον αριθμό των instances * τον αριθμό των features). Απαιτεί σχετικά μικρή ποσότητα δεδομένων για την αξιόπιστη εκτίμηση των πιθανοτήτων, ειδικά με σωστό smoothing. Συχνά είναι εκπληκτικά ακριβής ως baseline, ιδιαίτερα όταν τα features συνεισφέρουν ανεξάρτητα evidence στην κλάση. Λειτουργεί καλά με high-dimensional data (π.χ. χιλιάδες features από text). Δεν απαιτεί σύνθετο tuning, πέρα από τον ορισμό μιας smoothing parameter.

-   **Περιορισμοί:** Η υπόθεση ανεξαρτησίας μπορεί να περιορίσει την ακρίβεια αν τα features έχουν ισχυρή συσχέτιση. Για παράδειγμα, σε network data, features όπως τα `src_bytes` και `dst_bytes` μπορεί να συσχετίζονται· ο Naive Bayes δεν θα καταγράψει αυτή την αλληλεπίδραση. Καθώς το μέγεθος των δεδομένων αυξάνεται σημαντικά, πιο expressive models (όπως ensembles ή neural nets) μπορούν να ξεπεράσουν τον NB μαθαίνοντας τις dependencies μεταξύ των features. Επίσης, αν απαιτείται ένας συγκεκριμένος συνδυασμός features για την αναγνώριση μιας επίθεσης (και όχι απλώς μεμονωμένα features ανεξάρτητα), ο NB θα δυσκολευτεί.

> [!TIP]
> *Use cases στην κυβερνοασφάλεια:* Η κλασική χρήση είναι το **spam detection** -- ο Naive Bayes αποτέλεσε τον πυρήνα των πρώτων spam filters, χρησιμοποιώντας τις συχνότητες συγκεκριμένων tokens (λέξεις, φράσεις, IP addresses) για να υπολογίσει την πιθανότητα ένα email να είναι spam. Χρησιμοποιείται επίσης σε **phishing email detection** και **URL classification**, όπου η παρουσία συγκεκριμένων keywords ή χαρακτηριστικών (όπως το "login.php" σε ένα URL ή το `@` σε ένα URL path) συνεισφέρει στην πιθανότητα phishing. Στο malware analysis, θα μπορούσε κανείς να φανταστεί έναν Naive Bayes classifier που χρησιμοποιεί την παρουσία συγκεκριμένων API calls ή permissions σε software για να προβλέψει αν πρόκειται για malware. Παρότι οι πιο advanced algorithms συχνά αποδίδουν καλύτερα, ο Naive Bayes παραμένει ένα καλό baseline χάρη στην ταχύτητα και την απλότητά του.

<details>
<summary>Παράδειγμα -- Naive Bayes για Phishing Detection:</summary>
Για να παρουσιάσουμε τον Naive Bayes, θα χρησιμοποιήσουμε Gaussian Naive Bayes στο NSL-KDD intrusion dataset (με binary labels). Το Gaussian NB θα αντιμετωπίσει κάθε feature σαν να ακολουθεί normal distribution ανά κλάση. Αυτή είναι μια πρόχειρη επιλογή, καθώς πολλά network features είναι διακριτά ή έχουν έντονη ασυμμετρία, αλλά δείχνει πώς θα εφάρμοζε κανείς τον NB σε continuous feature data. Θα μπορούσαμε επίσης να επιλέξουμε Bernoulli NB σε ένα dataset από binary features (όπως ένα σύνολο από triggered alerts), αλλά εδώ θα παραμείνουμε στο NSL-KDD για λόγους συνέχειας.
```python
import pandas as pd
from sklearn.naive_bayes import GaussianNB
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score

# 1. Load NSL-KDD data
col_names = [                       # 41 features + 2 targets
"duration","protocol_type","service","flag","src_bytes","dst_bytes","land",
"wrong_fragment","urgent","hot","num_failed_logins","logged_in",
"num_compromised","root_shell","su_attempted","num_root","num_file_creations",
"num_shells","num_access_files","num_outbound_cmds","is_host_login",
"is_guest_login","count","srv_count","serror_rate","srv_serror_rate",
"rerror_rate","srv_rerror_rate","same_srv_rate","diff_srv_rate",
"srv_diff_host_rate","dst_host_count","dst_host_srv_count",
"dst_host_same_srv_rate","dst_host_diff_srv_rate",
"dst_host_same_src_port_rate","dst_host_srv_diff_host_rate",
"dst_host_serror_rate","dst_host_srv_serror_rate","dst_host_rerror_rate",
"dst_host_srv_rerror_rate","class","difficulty_level"
]

train_url = "https://raw.githubusercontent.com/Mamcose/NSL-KDD-Network-Intrusion-Detection/master/NSL_KDD_Train.csv"
test_url  = "https://raw.githubusercontent.com/Mamcose/NSL-KDD-Network-Intrusion-Detection/master/NSL_KDD_Test.csv"

df_train = pd.read_csv(train_url, header=None, names=col_names)
df_test  = pd.read_csv(test_url,  header=None, names=col_names)

# 2. Preprocess (encode categorical features, prepare binary labels)
from sklearn.preprocessing import LabelEncoder
for col in ['protocol_type', 'service', 'flag']:
le = LabelEncoder()
le.fit(pd.concat([df_train[col], df_test[col]], axis=0))
df_train[col] = le.transform(df_train[col])
df_test[col]  = le.transform(df_test[col])
X_train = df_train.drop(columns=['class', 'difficulty_level'], errors='ignore')
y_train = df_train['class'].apply(lambda x: 0 if x.strip().lower() == 'normal' else 1)
X_test  = df_test.drop(columns=['class', 'difficulty_level'], errors='ignore')
y_test  = df_test['class'].apply(lambda x: 0 if x.strip().lower() == 'normal' else 1)

# 3. Train Gaussian Naive Bayes
model = GaussianNB()
model.fit(X_train, y_train)

# 4. Evaluate on test set
y_pred = model.predict(X_test)
# For ROC AUC, need probability of class 1:
y_prob = model.predict_proba(X_test)[:, 1] if hasattr(model, "predict_proba") else y_pred
print(f"Accuracy:  {accuracy_score(y_test, y_pred):.3f}")
print(f"Precision: {precision_score(y_test, y_pred):.3f}")
print(f"Recall:    {recall_score(y_test, y_pred):.3f}")
print(f"F1-score:  {f1_score(y_test, y_pred):.3f}")
print(f"ROC AUC:   {roc_auc_score(y_test, y_prob):.3f}")

"""
Accuracy:  0.450
Precision: 0.937
Recall:    0.037
F1-score:  0.071
ROC AUC:   0.867
"""
```
Αυτός ο κώδικας εκπαιδεύει έναν classifier Naive Bayes για την ανίχνευση επιθέσεων. Ο Naive Bayes υπολογίζει τιμές όπως `P(service=http | Attack)` και `P(Service=http | Normal)` με βάση τα training data, υποθέτοντας ανεξαρτησία μεταξύ των features. Στη συνέχεια χρησιμοποιεί αυτές τις πιθανότητες για να ταξινομήσει νέες συνδέσεις είτε ως normal είτε ως attack, με βάση τα features που παρατηρούνται. Η απόδοση του NB στο NSL-KDD ενδέχεται να μην είναι τόσο υψηλή όσο εκείνη πιο προηγμένων μοντέλων (επειδή παραβιάζεται η ανεξαρτησία των features), αλλά είναι συχνά ικανοποιητική και προσφέρει το πλεονέκτημα της εξαιρετικά υψηλής ταχύτητας. Σε σενάρια όπως το real-time email filtering ή το αρχικό triage URLs, ένα μοντέλο Naive Bayes μπορεί να επισημάνει γρήγορα τις προφανώς κακόβουλες περιπτώσεις με χαμηλή χρήση πόρων.

</details>

### k-Nearest Neighbors (k-NN)

Ο k-Nearest Neighbors είναι ένας από τους απλούστερους αλγορίθμους machine learning. Είναι μια **μη παραμετρική, instance-based** μέθοδος που πραγματοποιεί προβλέψεις με βάση την ομοιότητα με παραδείγματα από το training set. Η ιδέα για classification είναι η εξής: για να ταξινομηθεί ένα νέο data point, βρίσκουμε τα **k** κοντινότερα points στα training data (τους «κοντινότερους γείτονές» του) και του αναθέτουμε την πλειοψηφούσα class μεταξύ αυτών των γειτόνων. Η «εγγύτητα» ορίζεται από ένα distance metric, συνήθως την Ευκλείδεια απόσταση για numeric data (μπορούν να χρησιμοποιηθούν και άλλες αποστάσεις για διαφορετικούς τύπους features ή προβλημάτων).<sup>[[10]](#references)</sup>

Ο K-NN δεν απαιτεί *ρητή εκπαίδευση* -- η φάση του «training» consiste απλώς στην αποθήκευση του dataset. Όλη η εργασία πραγματοποιείται κατά τη διάρκεια του query (prediction): ο αλγόριθμος πρέπει να υπολογίσει τις αποστάσεις από το query point προς όλα τα training points, ώστε να βρει τα κοντινότερα. Αυτό καθιστά τον χρόνο prediction **γραμμικό ως προς τον αριθμό των training samples**, κάτι που μπορεί να είναι κοστοβόρο για μεγάλα datasets. Για τον λόγο αυτό, ο k-NN είναι καταλληλότερος για μικρότερα datasets ή για σενάρια όπου μπορείτε να ανταλλάξετε μνήμη και ταχύτητα με απλότητα.

Παρά την απλότητά του, ο k-NN μπορεί να μοντελοποιήσει πολύ σύνθετα decision boundaries (επειδή, ουσιαστικά, το decision boundary μπορεί να έχει οποιοδήποτε σχήμα, το οποίο καθορίζεται από την κατανομή των παραδειγμάτων). Τείνει να αποδίδει καλά όταν το decision boundary είναι πολύ ακανόνιστο και διαθέτετε πολλά data -- επιτρέποντας, ουσιαστικά, στα data να «μιλήσουν από μόνα τους». Ωστόσο, σε υψηλές διαστάσεις, τα distance metrics μπορεί να γίνουν λιγότερο σημαντικά (curse of dimensionality), και η μέθοδος μπορεί να δυσκολευτεί, εκτός αν διαθέτετε πολύ μεγάλο αριθμό samples.

*Use cases στο cybersecurity:* Ο k-NN έχει εφαρμοστεί σε anomaly detection -- για παράδειγμα, ένα intrusion detection system μπορεί να χαρακτηρίσει ένα network event ως malicious αν οι περισσότεροι από τους κοντινότερους γείτονές του (προηγούμενα events) ήταν malicious. Αν η normal traffic σχηματίζει clusters και οι επιθέσεις είναι outliers, μια προσέγγιση K-NN (με k=1 ή μικρό k) πραγματοποιεί ουσιαστικά **nearest-neighbor anomaly detection**. Ο K-NN έχει επίσης χρησιμοποιηθεί για την ταξινόμηση malware families μέσω binary feature vectors: ένα νέο file μπορεί να ταξινομηθεί ως μέλος μιας συγκεκριμένης malware family αν βρίσκεται πολύ κοντά (στο feature space) σε γνωστά instances αυτής της family. Στην πράξη, ο k-NN δεν είναι τόσο συνηθισμένος όσο πιο scalable algorithms, αλλά είναι εννοιολογικά απλός και χρησιμοποιείται μερικές φορές ως baseline ή για προβλήματα μικρής κλίμακας.

#### **Βασικά χαρακτηριστικά του k-NN:**

-   **Τύπος προβλήματος:** Classification (και υπάρχουν variants για regression). Είναι μια μέθοδος *lazy learning* -- δεν πραγματοποιείται ρητό model fitting.

-   **Ερμηνευσιμότητα:** Χαμηλή έως μέτρια -- δεν υπάρχει global model ή συνοπτική εξήγηση, αλλά τα αποτελέσματα μπορούν να ερμηνευτούν εξετάζοντας τους κοντινότερους γείτονες που επηρέασαν μια απόφαση (π.χ. «αυτό το network flow ταξινομήθηκε ως malicious επειδή είναι παρόμοιο με αυτά τα 3 γνωστά malicious flows»). Επομένως, οι εξηγήσεις μπορούν να βασίζονται σε παραδείγματα.

-   **Πλεονεκτήματα:** Πολύ απλός στην υλοποίηση και την κατανόηση. Δεν κάνει υποθέσεις σχετικά με την κατανομή των data (μη παραμετρικός). Μπορεί να χειριστεί φυσικά multi-class προβλήματα. Είναι **adaptive**, με την έννοια ότι τα decision boundaries μπορούν να είναι πολύ σύνθετα και να διαμορφώνονται από την κατανομή των data.

-   **Περιορισμοί:** Το prediction μπορεί να είναι αργό για μεγάλα datasets (πρέπει να υπολογιστούν πολλές αποστάσεις). Απαιτεί πολλή μνήμη -- αποθηκεύει όλα τα training data. Η απόδοση μειώνεται σε feature spaces υψηλών διαστάσεων, επειδή όλα τα points τείνουν να γίνονται σχεδόν ισαπέχοντα (καθιστώντας λιγότερο ουσιαστική την έννοια του «κοντινότερου»). Πρέπει να επιλεγεί κατάλληλα το *k* (ο αριθμός των γειτόνων) -- ένα πολύ μικρό k μπορεί να είναι noisy, ενώ ένα πολύ μεγάλο k μπορεί να περιλαμβάνει άσχετα points από άλλες classes. Επίσης, τα features πρέπει να έχουν γίνει κατάλληλο scaling, επειδή οι υπολογισμοί απόστασης είναι ευαίσθητοι στην κλίμακα.

<details>
<summary>Παράδειγμα -- Phishing Detection:</summary>

Θα χρησιμοποιήσουμε ξανά το NSL-KDD (binary classification). Επειδή ο k-NN απαιτεί πολλούς υπολογιστικούς πόρους, θα χρησιμοποιήσουμε ένα subset των training data, ώστε η διαδικασία να παραμείνει διαχειρίσιμη σε αυτή την επίδειξη. Θα επιλέξουμε, για παράδειγμα, 20.000 training samples από τα συνολικά 125k και θα χρησιμοποιήσουμε k=5 neighbors. Μετά το training (στην πραγματικότητα, απλώς αποθηκεύοντας τα data), θα αξιολογήσουμε το μοντέλο στο test set. Θα κάνουμε επίσης scale στα features για τον υπολογισμό των αποστάσεων, ώστε κανένα feature να μην κυριαρχεί λόγω της κλίμακάς του.
```python
import pandas as pd
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score

# 1. Load NSL-KDD and preprocess similarly
col_names = [                       # 41 features + 2 targets
"duration","protocol_type","service","flag","src_bytes","dst_bytes","land",
"wrong_fragment","urgent","hot","num_failed_logins","logged_in",
"num_compromised","root_shell","su_attempted","num_root","num_file_creations",
"num_shells","num_access_files","num_outbound_cmds","is_host_login",
"is_guest_login","count","srv_count","serror_rate","srv_serror_rate",
"rerror_rate","srv_rerror_rate","same_srv_rate","diff_srv_rate",
"srv_diff_host_rate","dst_host_count","dst_host_srv_count",
"dst_host_same_srv_rate","dst_host_diff_srv_rate",
"dst_host_same_src_port_rate","dst_host_srv_diff_host_rate",
"dst_host_serror_rate","dst_host_srv_serror_rate","dst_host_rerror_rate",
"dst_host_srv_rerror_rate","class","difficulty_level"
]

train_url = "https://raw.githubusercontent.com/Mamcose/NSL-KDD-Network-Intrusion-Detection/master/NSL_KDD_Train.csv"
test_url  = "https://raw.githubusercontent.com/Mamcose/NSL-KDD-Network-Intrusion-Detection/master/NSL_KDD_Test.csv"

df_train = pd.read_csv(train_url, header=None, names=col_names)
df_test  = pd.read_csv(test_url,  header=None, names=col_names)

from sklearn.preprocessing import LabelEncoder
for col in ['protocol_type', 'service', 'flag']:
le = LabelEncoder()
le.fit(pd.concat([df_train[col], df_test[col]], axis=0))
df_train[col] = le.transform(df_train[col])
df_test[col]  = le.transform(df_test[col])
X = df_train.drop(columns=['class', 'difficulty_level'], errors='ignore')
y = df_train['class'].apply(lambda x: 0 if x.strip().lower() == 'normal' else 1)
# Use a random subset of the training data for K-NN (to reduce computation)
X_train = X.sample(n=20000, random_state=42)
y_train = y[X_train.index]
# Use the full test set for evaluation
X_test = df_test.drop(columns=['class', 'difficulty_level'], errors='ignore')
y_test = df_test['class'].apply(lambda x: 0 if x.strip().lower() == 'normal' else 1)

# 2. Feature scaling for distance-based model
from sklearn.preprocessing import StandardScaler
scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test  = scaler.transform(X_test)

# 3. Train k-NN classifier (store data)
model = KNeighborsClassifier(n_neighbors=5, n_jobs=-1)
model.fit(X_train, y_train)

# 4. Evaluate on test set
y_pred = model.predict(X_test)
y_prob = model.predict_proba(X_test)[:, 1]
print(f"Accuracy:  {accuracy_score(y_test, y_pred):.3f}")
print(f"Precision: {precision_score(y_test, y_pred):.3f}")
print(f"Recall:    {recall_score(y_test, y_pred):.3f}")
print(f"F1-score:  {f1_score(y_test, y_pred):.3f}")
print(f"ROC AUC:   {roc_auc_score(y_test, y_prob):.3f}")

"""
Accuracy:  0.780
Precision: 0.972
Recall:    0.632
F1-score:  0.766
ROC AUC:   0.837
"""
```
Το μοντέλο k-NN θα ταξινομήσει μια σύνδεση εξετάζοντας τις 5 κοντινότερες συνδέσεις στο υποσύνολο του training set. Αν, για παράδειγμα, 4 από αυτούς τους γείτονες είναι attacks (anomalies) και 1 είναι normal, η νέα σύνδεση θα ταξινομηθεί ως attack. Η απόδοση μπορεί να είναι ικανοποιητική, αν και συχνά όχι τόσο υψηλή όσο ενός καλά ρυθμισμένου Random Forest ή SVM στα ίδια δεδομένα. Ωστόσο, το k-NN μπορεί μερικές φορές να υπερέχει όταν οι κατανομές των κλάσεων είναι πολύ irregular και complex -- λειτουργώντας ουσιαστικά ως memory-based lookup. Στην κυβερνοασφάλεια, το k-NN (με k=1 ή μικρό k) θα μπορούσε να χρησιμοποιηθεί για την ανίχνευση γνωστών attack patterns μέσω παραδειγμάτων ή ως συστατικό πιο σύνθετων συστημάτων (π.χ. για clustering και στη συνέχεια ταξινόμηση με βάση τη συμμετοχή σε cluster).
</details>

### Gradient Boosting Machines (π.χ. XGBoost)

Τα Gradient Boosting Machines συγκαταλέγονται στους ισχυρότερους αλγορίθμους για structured data. Το **gradient boosting** αναφέρεται στην τεχνική δημιουργίας ενός ensemble από weak learners (συχνά decision trees) με sequential τρόπο, όπου κάθε νέο model διορθώνει τα errors του προηγούμενου ensemble. Σε αντίθεση με το bagging (Random Forests), το οποίο δημιουργεί trees παράλληλα και υπολογίζει τον μέσο όρο τους, το boosting δημιουργεί trees *one by one*, με καθένα να επικεντρώνεται περισσότερο στα instances που τα προηγούμενα trees mis-predicted.

Οι δημοφιλέστερες implementations τα τελευταία χρόνια είναι τα **XGBoost**, **LightGBM** και **CatBoost**, τα οποία είναι βιβλιοθήκες gradient boosting decision tree (GBDT). Έχουν σημειώσει εξαιρετική επιτυχία σε machine learning competitions και εφαρμογές, συχνά **επιτυγχάνοντας state-of-the-art performance σε tabular datasets**. Στην κυβερνοασφάλεια, researchers και practitioners έχουν χρησιμοποιήσει gradient boosted trees για tasks όπως **malware detection** (με features που εξάγονται από αρχεία ή runtime behavior) και **network intrusion detection**. Για παράδειγμα, ένα gradient boosting model μπορεί να συνδυάσει πολλούς weak rules (trees), όπως "αν υπάρχουν πολλά SYN packets και ασυνήθιστο port -> πιθανό scan", σε έναν ισχυρό composite detector που λαμβάνει υπόψη πολλά subtle patterns.<sup>[[6]](#references)</sup>

Γιατί είναι τόσο αποτελεσματικά τα boosted trees; Κάθε tree στη sequence εκπαιδεύεται πάνω στα *residual errors* (gradients) των predictions του τρέχοντος ensemble. Με αυτόν τον τρόπο, το model σταδιακά **"boosts"** τις περιοχές όπου είναι weak. Η χρήση decision trees ως base learners επιτρέπει στο final model να καταγράφει complex interactions και non-linear relations. Επιπλέον, το boosting διαθέτει εγγενώς μια μορφή built-in regularization: προσθέτοντας πολλά small trees (και χρησιμοποιώντας learning rate για την κλιμάκωση της συνεισφοράς τους), συχνά γενικεύει καλά χωρίς σημαντικό overfitting, υπό την προϋπόθεση ότι έχουν επιλεγεί οι σωστές παράμετροι.

#### **Βασικά χαρακτηριστικά του Gradient Boosting:**

-   **Τύπος προβλήματος:** Κυρίως classification και regression. Στην ασφάλεια, συνήθως classification (π.χ. binary classification μιας σύνδεσης ή ενός αρχείου). Υποστηρίζει binary, multi-class (με το κατάλληλο loss), ακόμη και ranking problems.

-   **Ερμηνευσιμότητα:** Low έως medium. Ενώ ένα single boosted tree είναι μικρό, ένα πλήρες model μπορεί να έχει εκατοντάδες trees, επομένως δεν είναι human-interpretable ως σύνολο. Ωστόσο, όπως το Random Forest, μπορεί να παρέχει feature importance scores, ενώ tools όπως το SHAP (SHapley Additive exPlanations) μπορούν να χρησιμοποιηθούν για την ερμηνεία individual predictions σε κάποιο βαθμό.

-   **Πλεονεκτήματα:** Συχνά ο **αλγόριθμος με την καλύτερη απόδοση** για structured/tabular data. Μπορεί να ανιχνεύσει complex patterns και interactions. Διαθέτει πολλά tuning knobs (αριθμός trees, depth των trees, learning rate, regularization terms) για την προσαρμογή της model complexity και την αποτροπή του overfitting. Οι σύγχρονες implementations είναι optimized για speed (π.χ. το XGBoost χρησιμοποιεί second-order gradient info και efficient data structures). Τείνει να χειρίζεται imbalanced data καλύτερα όταν συνδυάζεται με appropriate loss functions ή με την προσαρμογή των sample weights.

-   **Περιορισμοί:** Είναι πιο complex στο tuning από τα simpler models. Το training μπορεί να είναι slow αν τα trees είναι deep ή ο αριθμός των trees είναι μεγάλος (αν και συνήθως παραμένει ταχύτερο από το training ενός αντίστοιχου deep neural network στα ίδια δεδομένα). Το model μπορεί να κάνει overfit αν δεν ρυθμιστεί σωστά (π.χ. υπερβολικά πολλά deep trees με ανεπαρκές regularization). Λόγω των πολλών hyperparameters, η αποτελεσματική χρήση του gradient boosting μπορεί να απαιτεί περισσότερη expertise ή experimentation. Επίσης, όπως οι tree-based methods, δεν χειρίζεται εγγενώς πολύ sparse high-dimensional data τόσο αποδοτικά όσο τα linear models ή το Naive Bayes (αν και μπορεί να εφαρμοστεί, π.χ. σε text classification, αλλά ίσως να μην είναι η πρώτη επιλογή χωρίς feature engineering).

> [!TIP]
> *Use cases στην κυβερνοασφάλεια:* Σχεδόν οπουδήποτε θα μπορούσε να χρησιμοποιηθεί ένα decision tree ή random forest, ένα gradient boosting model μπορεί να επιτύχει καλύτερη accuracy. Για παράδειγμα, σε competitions για **Microsoft's malware detection** έχει γίνει εκτεταμένη χρήση του XGBoost σε engineered features από binary files. Η έρευνα για **Network intrusion detection** συχνά αναφέρει κορυφαία αποτελέσματα με GBDTs (π.χ. XGBoost στα CIC-IDS2017 ή UNSW-NB15 datasets). Αυτά τα models μπορούν να λάβουν ένα ευρύ φάσμα features (protocol types, frequency συγκεκριμένων events, statistical features της traffic κ.λπ.) και να τα συνδυάσουν για την ανίχνευση threats. Στο phishing detection, το gradient boosting μπορεί να συνδυάσει lexical features των URLs, domain reputation features και page content features, επιτυγχάνοντας πολύ υψηλή accuracy. Η ensemble approach βοηθά στην κάλυψη πολλών corner cases και subtleties των δεδομένων.

<details>
<summary>Παράδειγμα -- XGBoost για Phishing Detection:</summary>
Θα χρησιμοποιήσουμε έναν gradient boosting classifier στο phishing dataset. Για να διατηρήσουμε τα πράγματα απλά και self-contained, θα χρησιμοποιήσουμε το `sklearn.ensemble.GradientBoostingClassifier` (το οποίο είναι μια πιο slow αλλά straightforward implementation). Κανονικά, θα μπορούσε κανείς να χρησιμοποιήσει τις βιβλιοθήκες `xgboost` ή `lightgbm` για καλύτερη performance και επιπλέον features. Θα εκπαιδεύσουμε το model και θα το αξιολογήσουμε με παρόμοιο τρόπο όπως πριν.
```python
import pandas as pd
from sklearn.datasets import fetch_openml
from sklearn.model_selection import train_test_split
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score

# 1️⃣ Load the “Phishing Websites” data directly from OpenML
data = fetch_openml(data_id=4534, as_frame=True)   # or data_name="PhishingWebsites"
df   = data.frame

# 2️⃣ Separate features/target & make sure everything is numeric
X = df.drop(columns=["Result"])
y = df["Result"].astype(int).apply(lambda v: 1 if v == 1 else 0)  # map {-1,1} → {0,1}

# (If any column is still object‑typed, coerce it to numeric.)
X = X.apply(pd.to_numeric, errors="coerce").fillna(0)

# 3️⃣ Train/test split
X_train, X_test, y_train, y_test = train_test_split(
X.values, y, test_size=0.20, random_state=42
)

# 4️⃣ Gradient Boosting model
model = GradientBoostingClassifier(
n_estimators=100, learning_rate=0.1, max_depth=3, random_state=42
)
model.fit(X_train, y_train)

# 5️⃣ Evaluation
y_pred = model.predict(X_test)
y_prob = model.predict_proba(X_test)[:, 1]

print(f"Accuracy:  {accuracy_score(y_test, y_pred):.3f}")
print(f"Precision: {precision_score(y_test, y_pred):.3f}")
print(f"Recall:    {recall_score(y_test, y_pred):.3f}")
print(f"F1‑score:  {f1_score(y_test, y_pred):.3f}")
print(f"ROC AUC:   {roc_auc_score(y_test, y_prob):.3f}")

"""
Accuracy:  0.951
Precision: 0.949
Recall:    0.965
F1‑score:  0.957
ROC AUC:   0.990
"""
```
Το gradient boosting model πιθανότατα θα επιτύχει πολύ υψηλή ακρίβεια και AUC σε αυτό το phishing dataset (συχνά αυτά τα models μπορούν να ξεπεράσουν το 95% accuracy με σωστό tuning σε τέτοια δεδομένα, όπως φαίνεται στη σχετική βιβλιογραφία). Αυτό καταδεικνύει γιατί τα GBDTs θεωρούνται *«το state-of-the-art model για tabular dataset»* -- συχνά ξεπερνούν απλούστερους αλγορίθμους, επειδή εντοπίζουν σύνθετα patterns. Σε ένα cybersecurity context, αυτό θα μπορούσε να σημαίνει τον εντοπισμό περισσότερων phishing sites ή attacks με λιγότερα misses. Φυσικά, πρέπει να είμαστε προσεκτικοί με το overfitting -- συνήθως θα χρησιμοποιούσαμε τεχνικές όπως cross-validation και θα παρακολουθούσαμε την απόδοση σε ένα validation set κατά την ανάπτυξη ενός τέτοιου model για deployment.

</details>

### Συνδυασμός Models: Ensemble Learning και Stacking

Το ensemble learning είναι μια στρατηγική **συνδυασμού πολλαπλών models** για τη βελτίωση της συνολικής απόδοσης. Έχουμε ήδη δει συγκεκριμένες ensemble methods: Random Forest (ένα ensemble από trees μέσω bagging) και Gradient Boosting (ένα ensemble από trees μέσω sequential boosting). Ωστόσο, ensembles μπορούν να δημιουργηθούν και με άλλους τρόπους, όπως **voting ensembles** ή **stacked generalization (stacking)**. Η βασική ιδέα είναι ότι διαφορετικά models μπορεί να εντοπίζουν διαφορετικά patterns ή να έχουν διαφορετικές αδυναμίες· συνδυάζοντάς τα, μπορούμε να **αντισταθμίσουμε τα errors κάθε model με τα strengths κάποιου άλλου**.<sup>[[13]](#references)</sup>

-   **Voting Ensemble:** Σε έναν απλό voting classifier, εκπαιδεύουμε πολλαπλά diverse models (για παράδειγμα, ένα logistic regression, ένα decision tree και ένα SVM) και τα βάζουμε να ψηφίσουν για την τελική πρόβλεψη (majority vote για classification). Αν σταθμίσουμε τις ψήφους (π.χ. δώσουμε μεγαλύτερο βάρος στα πιο accurate models), έχουμε ένα weighted voting scheme. Αυτό συνήθως βελτιώνει την απόδοση όταν τα individual models είναι αρκετά καλά και independent -- το ensemble μειώνει τον κίνδυνο ενός λάθους από ένα individual model, καθώς τα άλλα μπορεί να το διορθώσουν. Είναι σαν να έχουμε ένα panel από experts αντί για μία μόνο γνώμη.

-   **Stacking (Stacked Ensemble):** Το stacking προχωρά ένα βήμα παραπέρα. Αντί για μια απλή ψηφοφορία, εκπαιδεύει ένα **meta-model** ώστε να **μάθει πώς να συνδυάζει καλύτερα τις predictions** των base models. Για παράδειγμα, εκπαιδεύεις 3 διαφορετικούς classifiers (base learners) και στη συνέχεια τροφοδοτείς τα outputs τους (ή τις probabilities) ως features σε έναν meta-classifier (συχνά ένα απλό model, όπως το logistic regression), ο οποίος μαθαίνει τον βέλτιστο τρόπο συνδυασμού τους. Το meta-model εκπαιδεύεται σε ένα validation set ή μέσω cross-validation, ώστε να αποφεύγεται το overfitting. Το stacking συχνά μπορεί να ξεπεράσει το simple voting, μαθαίνοντας *ποια models να εμπιστεύεται περισσότερο υπό ποιες συνθήκες*. Στο cybersecurity, ένα model μπορεί να είναι καλύτερο στον εντοπισμό network scans, ενώ ένα άλλο στον εντοπισμό malware beaconing· ένα stacking model θα μπορούσε να μάθει να βασίζεται κατάλληλα στο καθένα.

Τα ensembles, είτε μέσω voting είτε μέσω stacking, τείνουν να **ενισχύουν την accuracy** και την robustness. Το μειονέκτημα είναι η αυξημένη πολυπλοκότητα και, σε ορισμένες περιπτώσεις, η μειωμένη interpretability (αν και ορισμένες ensemble approaches, όπως ένας μέσος όρος από decision trees, μπορούν να παρέχουν κάποια insight, π.χ. feature importance). Στην πράξη, αν το επιτρέπουν οι operational constraints, η χρήση ενός ensemble μπορεί να οδηγήσει σε υψηλότερα detection rates. Πολλές winning solutions σε cybersecurity challenges (και γενικά σε Kaggle competitions) χρησιμοποιούν ensemble techniques για να αποσπάσουν και το τελευταίο bit απόδοσης.

<details>
<summary>Παράδειγμα -- Voting Ensemble για Phishing Detection:</summary>
Για να παρουσιάσουμε το model stacking, ας συνδυάσουμε μερικά από τα models που συζητήσαμε στο phishing dataset. Θα χρησιμοποιήσουμε ένα logistic regression, ένα decision tree και ένα k-NN ως base learners και ένα Random Forest ως meta-learner για να συγκεντρώσουμε τις predictions τους. Το meta-learner θα εκπαιδευτεί στα outputs των base learners (χρησιμοποιώντας cross-validation στο training set). Περιμένουμε το stacked model να αποδώσει εξίσου καλά ή ελαφρώς καλύτερα από τα individual models.
```python
import pandas as pd
from sklearn.datasets import fetch_openml
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.ensemble import StackingClassifier, RandomForestClassifier
from sklearn.metrics import (accuracy_score, precision_score,
recall_score, f1_score, roc_auc_score)

# ──────────────────────────────────────────────
# 1️⃣  LOAD DATASET (OpenML id 4534)
# ──────────────────────────────────────────────
data = fetch_openml(data_id=4534, as_frame=True)     # “PhishingWebsites”
df   = data.frame

# Target mapping:  1 → legitimate (0),   0/‑1 → phishing (1)
y = (df["Result"].astype(int) != 1).astype(int)
X = df.drop(columns=["Result"])

# Train / test split (stratified to keep class balance)
X_train, X_test, y_train, y_test = train_test_split(
X, y, test_size=0.20, random_state=42, stratify=y)

# ──────────────────────────────────────────────
# 2️⃣  DEFINE BASE LEARNERS
#     • LogisticRegression and k‑NN need scaling ➜ wrap them
#       in a Pipeline(StandardScaler → model) so that scaling
#       happens inside each CV fold of StackingClassifier.
# ──────────────────────────────────────────────
base_learners = [
('lr',  make_pipeline(StandardScaler(),
LogisticRegression(max_iter=1000,
solver='lbfgs',
random_state=42))),
('dt',  DecisionTreeClassifier(max_depth=5, random_state=42)),
('knn', make_pipeline(StandardScaler(),
KNeighborsClassifier(n_neighbors=5)))
]

# Meta‑learner (level‑2 model)
meta_learner = RandomForestClassifier(n_estimators=50, random_state=42)

stack_model = StackingClassifier(
estimators      = base_learners,
final_estimator = meta_learner,
cv              = 5,        # 5‑fold CV to create meta‑features
passthrough     = False     # only base learners’ predictions go to meta‑learner
)

# ──────────────────────────────────────────────
# 3️⃣  TRAIN ENSEMBLE
# ──────────────────────────────────────────────
stack_model.fit(X_train, y_train)

# ──────────────────────────────────────────────
# 4️⃣  EVALUATE
# ──────────────────────────────────────────────
y_pred = stack_model.predict(X_test)
y_prob = stack_model.predict_proba(X_test)[:, 1]   # P(phishing)

print(f"Accuracy : {accuracy_score(y_test, y_pred):.3f}")
print(f"Precision: {precision_score(y_test, y_pred):.3f}")
print(f"Recall   : {recall_score(y_test, y_pred):.3f}")
print(f"F1‑score : {f1_score(y_test, y_pred):.3f}")
print(f"ROC AUC  : {roc_auc_score(y_test, y_prob):.3f}")

"""
Accuracy : 0.954
Precision: 0.951
Recall   : 0.946
F1‑score : 0.948
ROC AUC  : 0.992
"""
```
Το stacked ensemble αξιοποιεί τα συμπληρωματικά πλεονεκτήματα των base models. Για παράδειγμα, η logistic regression μπορεί να χειρίζεται τις γραμμικές πτυχές των δεδομένων, το decision tree μπορεί να εντοπίζει συγκεκριμένες αλληλεπιδράσεις που μοιάζουν με κανόνες και το k-NN μπορεί να αποδίδει εξαιρετικά στις τοπικές περιοχές του feature space. Το meta-model (εδώ ένα random forest) μπορεί να μάθει πώς να σταθμίζει αυτές τις εισόδους. Οι resulting metrics συχνά δείχνουν βελτίωση (ακόμη και μικρή) σε σχέση με τα metrics οποιουδήποτε μεμονωμένου model. Στο παράδειγμα phishing, αν το logistic είχε μόνο του F1, για παράδειγμα, 0.95 και το tree 0.94, το stack θα μπορούσε να πετύχει 0.96, αξιοποιώντας τα σημεία στα οποία κάθε model κάνει λάθος.

Μέθοδοι ensemble όπως αυτή καταδεικνύουν την αρχή ότι *"ο συνδυασμός πολλαπλών models συνήθως οδηγεί σε καλύτερη γενίκευση"*. Στην κυβερνοασφάλεια, αυτό μπορεί να υλοποιηθεί με τη χρήση πολλαπλών detection engines (μία μπορεί να βασίζεται σε rules, μία σε machine learning και μία σε anomaly detection) και στη συνέχεια ενός layer που συγκεντρώνει τα alerts τους -- ουσιαστικά μια μορφή ensemble -- για τη λήψη τελικής απόφασης με μεγαλύτερη confidence. Κατά την ανάπτυξη τέτοιων συστημάτων, πρέπει να λαμβάνεται υπόψη η πρόσθετη πολυπλοκότητα και να διασφαλίζεται ότι το ensemble δεν θα γίνει υπερβολικά δύσκολο στη διαχείριση ή την επεξήγηση. Ωστόσο, από άποψη accuracy, τα ensembles και το stacking είναι ισχυρά εργαλεία για τη βελτίωση της απόδοσης των models.

</details>


## Παραπομπές

- [1] [Logistic Regression](https://madhuramiah.medium.com/logistic-regression-6e55553cc003)
- [2] [Decision Tree - Introduction with example](https://www.geeksforgeeks.org/decision-tree-introduction-example/)
- [3] [Denial of Services Attack Detection using Random Forest Classifier with Information Gain](https://rjwave.org/ijedr/viewpaperforall.php?paper=IJEDR1703132)
- [4] [What are Support Vector Machines (SVMs)? (IBM)](https://www.ibm.com/think/topics/support-vector-machine)
- [5] [Naive Bayes spam filtering (Wikipedia)](https://en.m.wikipedia.org/wiki/Naive_Bayes_spam_filtering)
- [6] [GBDT Demystified: How LightGBM, XGBoost, and CatBoost Work](https://medium.com/@rupalipatelkvc/gbdt-demystified-how-lightgbm-xgboost-and-catboost-work-9479b7262644)
- [7] [AI and Machine Learning in Cybersecurity (zvelo)](https://zvelo.com/ai-and-machine-learning-in-cybersecurity/)
- [8] [Linear Regression Explained](https://medium.com/@chaandram/linear-regression-explained-28d5bf1934ae)
- [9] [Performance analysis of machine learning models for intrusion detection system using Gini Impurity-based Weighted Random Forest (GIWRF) feature selection technique](https://cybersecurity.springeropen.com/articles/10.1186/s42400-021-00103-8)
- [10] [What is the k-nearest neighbors (KNN) algorithm? (IBM)](https://www.ibm.com/think/topics/knn)
- [11] [Phishing Attacks and Websites Classification Using Machine Learning and Multiple Datasets (A Comparative Analysis)](https://arxiv.org/pdf/2101.02552)
- [12] [How Deep Learning Enhances Intrusion Detection Systems](https://cybersecurity-magazine.com/how-deep-learning-enhances-intrusion-detection-systems/)
- [13] [Ensemble Learning: Boosting Model Performance by Combining Strengths](https://medium.com/@sarahzouinina/ensemble-learning-boosting-model-performance-by-combining-strengths-02e56165b901)

{{#include ../banners/hacktricks-training.md}}
