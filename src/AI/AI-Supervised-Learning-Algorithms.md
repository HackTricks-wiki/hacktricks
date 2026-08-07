# Αλγόριθμοι Supervised Learning

{{#include ../banners/hacktricks-training.md}}

## Βασικές πληροφορίες

Το Supervised Learning χρησιμοποιεί δεδομένα με labels για την εκπαίδευση μοντέλων που μπορούν να κάνουν προβλέψεις σε νέα, άγνωστα inputs. Στην κυβερνοασφάλεια, το supervised machine learning εφαρμόζεται ευρέως σε εργασίες όπως η ανίχνευση εισβολών (ταξινόμηση της κίνησης δικτύου ως *normal* ή *attack*), η ανίχνευση malware (διάκριση κακόβουλου λογισμικού από benign), η ανίχνευση phishing (εντοπισμός fraudulent websites ή emails) και το spam filtering, μεταξύ άλλων.<sup>[[1]](#references)</sup> Κάθε αλγόριθμος έχει τα δικά του πλεονεκτήματα και είναι κατάλληλος για διαφορετικούς τύπους προβλημάτων (classification ή regression). Παρακάτω εξετάζουμε βασικούς αλγόριθμους supervised learning, εξηγούμε πώς λειτουργούν και παρουσιάζουμε τη χρήση τους σε πραγματικά cybersecurity datasets. Εξετάζουμε επίσης πώς ο συνδυασμός μοντέλων (ensemble learning) μπορεί συχνά να βελτιώσει την predictive performance.

## Αλγόριθμοι

-   **Linear Regression:** Ένας θεμελιώδης αλγόριθμος regression για την πρόβλεψη αριθμητικών αποτελεσμάτων μέσω προσαρμογής μιας γραμμικής εξίσωσης στα δεδομένα.

-   **Logistic Regression:** Ένας αλγόριθμος classification (παρά το όνομά του) που χρησιμοποιεί μια logistic function για να μοντελοποιήσει την πιθανότητα ενός binary outcome.

-   **Decision Trees:** Μοντέλα με δενδρική δομή που διαχωρίζουν τα δεδομένα βάσει features για να κάνουν προβλέψεις· χρησιμοποιούνται συχνά λόγω της interpretability τους.

-   **Random Forests:** Ένα ensemble από decision trees (μέσω bagging) που βελτιώνει την accuracy και μειώνει το overfitting.

-   **Support Vector Machines (SVM):** Classifiers μέγιστου περιθωρίου που εντοπίζουν το βέλτιστο separating hyperplane· μπορούν να χρησιμοποιούν kernels για non-linear δεδομένα.

-   **Naive Bayes:** Ένας probabilistic classifier που βασίζεται στο θεώρημα του Bayes και στην υπόθεση ανεξαρτησίας των features, ο οποίος χρησιμοποιείται ευρέως στο spam filtering.

-   **k-Nearest Neighbors (k-NN):** Ένας απλός "instance-based" classifier που αποδίδει label σε ένα sample βάσει της πλειοψηφικής κλάσης των κοντινότερων neighbors του.

-   **Gradient Boosting Machines:** Ensemble models (π.χ. XGBoost, LightGBM) που δημιουργούν έναν ισχυρό predictor προσθέτοντας διαδοχικά ασθενέστερους learners (συνήθως decision trees).

Κάθε ενότητα παρακάτω παρέχει μια βελτιωμένη περιγραφή του αλγορίθμου και ένα **Python code example** χρησιμοποιώντας libraries όπως `pandas` και `scikit-learn` (και `PyTorch` για το neural network example). Τα examples χρησιμοποιούν δημόσια διαθέσιμα cybersecurity datasets (όπως το NSL-KDD για intrusion detection και ένα Phishing Websites dataset) και ακολουθούν μια συνεπή δομή:

1.  **Φόρτωση του dataset** (download μέσω URL, εφόσον είναι διαθέσιμο).

2.  **Preprocess των δεδομένων** (π.χ. encode των categorical features, scale των τιμών, διαχωρισμός σε train/test sets).

3.  **Εκπαίδευση του μοντέλου** στα training data.

4.  **Αξιολόγηση** σε test set χρησιμοποιώντας metrics: accuracy, precision, recall, F1-score και ROC AUC για classification (και mean squared error για regression).

Ας εξετάσουμε κάθε αλγόριθμο:

### Linear Regression

Η Linear Regression είναι ένας αλγόριθμος **regression** που χρησιμοποιείται για την πρόβλεψη συνεχών αριθμητικών τιμών. Υποθέτει μια γραμμική σχέση μεταξύ των input features (independent variables) και του output (dependent variable). Το μοντέλο προσπαθεί να προσαρμόσει μια ευθεία γραμμή (ή hyperplane σε υψηλότερες διαστάσεις) που περιγράφει με τον καλύτερο τρόπο τη σχέση μεταξύ των features και του target. Αυτό γίνεται συνήθως με την ελαχιστοποίηση του αθροίσματος των squared errors μεταξύ των predicted και actual values (μέθοδος Ordinary Least Squares).<sup>[[2]](#references)</sup>

Ο απλούστερος τρόπος αναπαράστασης της linear regression είναι με μια γραμμή:
```plaintext
y = mx + b
```
Όπου:

- `y` είναι η προβλεπόμενη τιμή (έξοδος)
- `m` είναι η κλίση της γραμμής (συντελεστής)
- `x` είναι το χαρακτηριστικό εισόδου
- `b` είναι η τομή με τον άξονα y

Ο στόχος της γραμμικής παλινδρόμησης είναι να βρεθεί η γραμμή που προσαρμόζεται καλύτερα και ελαχιστοποιεί τη διαφορά μεταξύ των προβλεπόμενων και των πραγματικών τιμών στο σύνολο δεδομένων. Φυσικά, αυτό είναι πολύ απλό, καθώς θα ήταν μια ευθεία γραμμή που διαχωρίζει 2 κατηγορίες, αλλά αν προστεθούν περισσότερες διαστάσεις, η γραμμή γίνεται πιο σύνθετη:
```plaintext
y = w1*x1 + w2*x2 + ... + wn*xn + b
```
> [!TIP]
> *Περιπτώσεις χρήσης στην κυβερνοασφάλεια:* Η γραμμική παλινδρόμηση από μόνη της είναι λιγότερο συνηθισμένη για βασικές εργασίες ασφάλειας (οι οποίες είναι συχνά εργασίες classification), αλλά μπορεί να χρησιμοποιηθεί για την πρόβλεψη αριθμητικών αποτελεσμάτων. Για παράδειγμα, θα μπορούσε να χρησιμοποιηθεί γραμμική παλινδρόμηση για την **πρόβλεψη του όγκου της κίνησης δικτύου** ή την **εκτίμηση του αριθμού των επιθέσεων σε μια χρονική περίοδο**, με βάση ιστορικά δεδομένα. Θα μπορούσε επίσης να προβλέψει ένα risk score ή τον αναμενόμενο χρόνο μέχρι τον εντοπισμό μιας επίθεσης, με δεδομένες ορισμένες μετρικές του συστήματος. Στην πράξη, οι αλγόριθμοι classification (όπως η logistic regression ή τα trees) χρησιμοποιούνται συχνότερα για τον εντοπισμό intrusions ή malware, αλλά η γραμμική παλινδρόμηση αποτελεί θεμέλιο και είναι χρήσιμη για analyses που προσανατολίζονται σε regression.

#### **Βασικά χαρακτηριστικά της Γραμμικής Παλινδρόμησης:**

-   **Τύπος προβλήματος:** Regression (πρόβλεψη συνεχών τιμών). Δεν είναι κατάλληλη για άμεσο classification, εκτός αν εφαρμοστεί threshold στην έξοδο.

-   **Ερμηνευσιμότητα:** Υψηλή -- οι coefficients είναι εύκολο να ερμηνευτούν, δείχνοντας τη γραμμική επίδραση κάθε feature.

-   **Πλεονεκτήματα:** Απλή και γρήγορη· αποτελεί ένα καλό baseline για regression tasks· λειτουργεί καλά όταν η πραγματική σχέση είναι περίπου γραμμική.

-   **Περιορισμοί:** Δεν μπορεί να καταγράψει σύνθετες ή μη γραμμικές σχέσεις (χωρίς χειροκίνητο feature engineering)· είναι επιρρεπής σε underfitting όταν οι σχέσεις είναι μη γραμμικές· είναι ευαίσθητη σε outliers, οι οποίοι μπορούν να παραμορφώσουν τα αποτελέσματα.

-   **Εύρεση της καλύτερης προσαρμογής:** Για να βρούμε τη γραμμή καλύτερης προσαρμογής που διαχωρίζει τις πιθανές κατηγορίες, χρησιμοποιούμε μια μέθοδο που ονομάζεται **Ordinary Least Squares (OLS)**. Αυτή η μέθοδος ελαχιστοποιεί το άθροισμα των τετραγωνικών διαφορών μεταξύ των παρατηρούμενων τιμών και των τιμών που προβλέπονται από το γραμμικό model.

<details>
<summary>Παράδειγμα -- Πρόβλεψη της διάρκειας σύνδεσης (Regression) σε ένα Intrusion Dataset
</summary>
Παρακάτω παρουσιάζουμε τη γραμμική παλινδρόμηση χρησιμοποιώντας το cybersecurity dataset NSL-KDD. Θα το χειριστούμε ως regression problem, προβλέποντας το `duration` των network connections με βάση άλλα features. (Στην πραγματικότητα, το `duration` είναι ένα feature του NSL-KDD· το χρησιμοποιούμε εδώ μόνο για να παρουσιάσουμε τη regression.) Φορτώνουμε το dataset, πραγματοποιούμε preprocessing (κωδικοποιούμε τα categorical features), εκπαιδεύουμε ένα linear regression model και αξιολογούμε το Mean Squared Error (MSE) και το R² score σε ένα test set.
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
Σε αυτό το παράδειγμα, το μοντέλο γραμμικής παλινδρόμησης προσπαθεί να προβλέψει το `duration` της σύνδεσης από άλλα χαρακτηριστικά του δικτύου. Μετράμε την απόδοση με το Mean Squared Error (MSE) και το R². Ένα R² κοντά στο 1.0 θα έδειχνε ότι το μοντέλο εξηγεί το μεγαλύτερο μέρος της διακύμανσης στο `duration`, ενώ ένα χαμηλό ή αρνητικό R² υποδεικνύει κακή προσαρμογή. (Μην εκπλαγείτε αν το R² είναι χαμηλό εδώ -- η πρόβλεψη του `duration` μπορεί να είναι δύσκολη με βάση τα διαθέσιμα χαρακτηριστικά και η γραμμική παλινδρόμηση μπορεί να μην αποτυπώνει τα μοτίβα, αν αυτά είναι σύνθετα.)
</details>

### Λογιστική παλινδρόμηση

Η λογιστική παλινδρόμηση είναι ένας αλγόριθμος **classification** που μοντελοποιεί την πιθανότητα ένα στιγμιότυπο να ανήκει σε μια συγκεκριμένη κλάση (συνήθως στην "positive" κλάση). Παρά το όνομά της, η *λογιστική* παλινδρόμηση χρησιμοποιείται για διακριτά αποτελέσματα (σε αντίθεση με τη γραμμική παλινδρόμηση, η οποία χρησιμοποιείται για συνεχή αποτελέσματα). Χρησιμοποιείται κυρίως για **binary classification** (δύο κλάσεις, π.χ. malicious έναντι benign), αλλά μπορεί να επεκταθεί σε προβλήματα multi-class (με τη χρήση προσεγγίσεων softmax ή one-vs-rest).<sup>[[3]](#references)</sup>

Η λογιστική παλινδρόμηση χρησιμοποιεί τη logistic function (γνωστή και ως sigmoid function) για να αντιστοιχίσει τις προβλεπόμενες τιμές σε πιθανότητες. Σημειώστε ότι η sigmoid function είναι μια συνάρτηση με τιμές μεταξύ 0 και 1, η οποία αυξάνεται σύμφωνα με μια καμπύλη σχήματος S, ανάλογα με τις ανάγκες του classification, κάτι που είναι χρήσιμο για εργασίες binary classification. Επομένως, κάθε feature κάθε εισόδου πολλαπλασιάζεται με το αντίστοιχο weight και το αποτέλεσμα περνά από τη sigmoid function για την παραγωγή μιας πιθανότητας:
```plaintext
p(y=1|x) = 1 / (1 + e^(-z))
```
Όπου:

- `p(y=1|x)` είναι η πιθανότητα η έξοδος `y` να είναι 1 δεδομένης της εισόδου `x`
- `e` είναι η βάση του φυσικού λογαρίθμου
- `z` είναι ένας γραμμικός συνδυασμός των χαρακτηριστικών εισόδου, που συνήθως αναπαρίσταται ως `z = w1*x1 + w2*x2 + ... + wn*xn + b`. Παρατηρήστε ότι και πάλι, στην απλούστερη μορφή του, είναι μια ευθεία γραμμή, αλλά σε πιο σύνθετες περιπτώσεις γίνεται ένα hyperplane με πολλές διαστάσεις (μία ανά χαρακτηριστικό).

> [!TIP]
> *Use cases in cybersecurity:* Επειδή πολλά προβλήματα ασφάλειας είναι ουσιαστικά αποφάσεις ναι/όχι, το Logistic Regression χρησιμοποιείται ευρέως. Για παράδειγμα, ένα σύστημα intrusion detection μπορεί να χρησιμοποιήσει Logistic Regression για να αποφασίσει αν μια σύνδεση δικτύου αποτελεί επίθεση, με βάση τα χαρακτηριστικά αυτής της σύνδεσης. Στο phishing detection, το Logistic Regression μπορεί να συνδυάσει χαρακτηριστικά ενός website (μήκος URL, παρουσία του συμβόλου "@", κ.λπ.) σε μια πιθανότητα το website να είναι phishing. Έχει χρησιμοποιηθεί σε φίλτρα spam πρώτης γενιάς και παραμένει ένα ισχυρό baseline για πολλές εργασίες classification.

#### Logistic Regression για classification με περισσότερες από δύο κατηγορίες

Το Logistic Regression έχει σχεδιαστεί για binary classification, αλλά μπορεί να επεκταθεί ώστε να χειρίζεται multi-class προβλήματα, με τη χρήση τεχνικών όπως το **one-vs-rest** (OvR) ή το **softmax regression**. Στο OvR, εκπαιδεύεται ένα ξεχωριστό μοντέλο Logistic Regression για κάθε class, αντιμετωπίζοντάς την ως positive class έναντι όλων των άλλων. Η class με την υψηλότερη προβλεπόμενη πιθανότητα επιλέγεται ως τελική πρόβλεψη. Το Softmax regression γενικεύει το Logistic Regression σε πολλαπλές classes, εφαρμόζοντας τη συνάρτηση softmax στο output layer και παράγοντας μια κατανομή πιθανότητας για όλες τις classes.

#### **Βασικά χαρακτηριστικά του Logistic Regression:**

-   **Τύπος προβλήματος:** Classification (συνήθως binary). Προβλέπει την πιθανότητα της positive class.

-   **Ερμηνευσιμότητα:** Υψηλή -- όπως και στο linear regression, οι συντελεστές των χαρακτηριστικών μπορούν να δείξουν πώς κάθε χαρακτηριστικό επηρεάζει τα log-odds του αποτελέσματος. Αυτή η διαφάνεια εκτιμάται συχνά στην ασφάλεια, για την κατανόηση των παραγόντων που συμβάλλουν σε ένα alert.

-   **Πλεονεκτήματα:** Απλό και γρήγορο στην εκπαίδευση· λειτουργεί καλά όταν η σχέση μεταξύ των χαρακτηριστικών και των log-odds του αποτελέσματος είναι γραμμική. Παράγει πιθανότητες, επιτρέποντας risk scoring. Με την κατάλληλη regularization, γενικεύεται καλά και μπορεί να χειριστεί την multicollinearity καλύτερα από το απλό linear regression.

-   **Περιορισμοί:** Υποθέτει γραμμικό decision boundary στον χώρο των χαρακτηριστικών (αποτυγχάνει αν το πραγματικό boundary είναι σύνθετο/μη γραμμικό). Μπορεί να έχει χαμηλότερη απόδοση σε προβλήματα όπου οι αλληλεπιδράσεις ή οι μη γραμμικές επιδράσεις είναι κρίσιμες, εκτός αν προσθέσετε χειροκίνητα polynomial ή interaction features. Επίσης, το Logistic Regression είναι λιγότερο αποτελεσματικό όταν οι classes δεν μπορούν να διαχωριστούν εύκολα μέσω ενός γραμμικού συνδυασμού χαρακτηριστικών.


<details>
<summary>Παράδειγμα -- Phishing Website Detection με Logistic Regression:</summary>

Θα χρησιμοποιήσουμε ένα **Phishing Websites Dataset** (από το UCI repository), το οποίο περιέχει εξαγόμενα χαρακτηριστικά websites (όπως το αν το URL περιέχει IP address, την ηλικία του domain, την παρουσία ύποπτων στοιχείων σε HTML κ.λπ.) και μια ετικέτα που υποδεικνύει αν το site είναι phishing ή legitimate.<sup>[[4]](#references)</sup> Εκπαιδεύουμε ένα μοντέλο Logistic Regression για να ταξινομήσουμε websites και στη συνέχεια αξιολογούμε τα accuracy, precision, recall, F1-score και ROC AUC σε ένα test split.
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
Σε αυτό το παράδειγμα ανίχνευσης phishing, η logistic regression παράγει μια πιθανότητα για κάθε website ως προς το αν είναι phishing. Αξιολογώντας τα accuracy, precision, recall και F1, αποκτούμε μια εικόνα για την απόδοση του model. Για παράδειγμα, υψηλό recall σημαίνει ότι εντοπίζει τα περισσότερα phishing sites (σημαντικό για την ασφάλεια, ώστε να ελαχιστοποιούνται οι επιθέσεις που δεν εντοπίζονται), ενώ υψηλό precision σημαίνει ότι παράγει λίγους false alarms (σημαντικό για την αποφυγή κόπωσης των analysts). Το ROC AUC (Area Under the ROC Curve) παρέχει ένα measure απόδοσης ανεξάρτητο από το threshold (το 1.0 είναι ιδανικό, ενώ το 0.5 δεν είναι καλύτερο από την τυχαία πρόβλεψη). Η logistic regression συχνά αποδίδει καλά σε τέτοιες εργασίες, αλλά αν το decision boundary μεταξύ phishing και legitimate sites είναι σύνθετο, μπορεί να χρειάζονται ισχυρότερα non-linear models.

</details>

### Decision Trees

Ένα decision tree είναι ένας ευέλικτος **supervised learning algorithm** που μπορεί να χρησιμοποιηθεί τόσο για εργασίες classification όσο και regression. Μαθαίνει ένα ιεραρχικό μοντέλο αποφάσεων με μορφή δέντρου, βασισμένο στα features των δεδομένων. Κάθε internal node του δέντρου αντιπροσωπεύει έναν έλεγχο σε ένα συγκεκριμένο feature, κάθε branch αντιπροσωπεύει ένα αποτέλεσμα αυτού του ελέγχου και κάθε leaf node αντιπροσωπεύει μια predicted class (για classification) ή value (για regression).<sup>[[5]](#references)</sup>

Για την κατασκευή ενός δέντρου, algorithms όπως το CART (Classification and Regression Tree) χρησιμοποιούν measures όπως το **Gini impurity** ή το **information gain (entropy)**, ώστε να επιλέξουν το καλύτερο feature και threshold για τον διαχωρισμό των δεδομένων σε κάθε βήμα. Ο στόχος σε κάθε split είναι η κατάτμηση των δεδομένων με τρόπο που αυξάνει την ομοιογένεια της target variable στα resulting subsets (στο classification, κάθε node πρέπει να είναι όσο το δυνατόν πιο pure, περιέχοντας κυρίως μία μόνο class).

Τα decision trees είναι **highly interpretable** -- μπορεί κανείς να ακολουθήσει τη διαδρομή από το root έως το leaf, ώστε να κατανοήσει τη λογική πίσω από μια πρόβλεψη (π.χ., *"IF `service = telnet` AND `src_bytes > 1000` AND `failed_logins > 3` THEN classify as attack"*). Αυτό είναι πολύτιμο στο cybersecurity για την εξήγηση του λόγου για τον οποίο δημιουργήθηκε ένα συγκεκριμένο alert. Τα trees μπορούν φυσικά να χειριστούν τόσο numerical όσο και categorical data και απαιτούν ελάχιστο preprocessing (π.χ. δεν χρειάζεται feature scaling).

Ωστόσο, ένα μεμονωμένο decision tree μπορεί εύκολα να κάνει overfit στα training data, ειδικά αν αναπτυχθεί σε μεγάλο βάθος (με πολλά splits). Τεχνικές όπως το pruning (περιορισμός του tree depth ή απαίτηση ενός ελάχιστου αριθμού samples ανά leaf) χρησιμοποιούνται συχνά για την αποφυγή του overfitting.

Υπάρχουν 3 βασικά components ενός decision tree:
- **Root Node**: Ο κορυφαίος node του tree, που αντιπροσωπεύει ολόκληρο το dataset.
- **Internal Nodes**: Nodes που αντιπροσωπεύουν features και αποφάσεις βασισμένες σε αυτά τα features.
- **Leaf Nodes**: Nodes που αντιπροσωπεύουν το τελικό outcome ή την prediction.

Ένα tree μπορεί τελικά να μοιάζει κάπως έτσι:
```plaintext
[Root Node]
/   \
[Node A]  [Node B]
/   \      /   \
[Leaf 1] [Leaf 2] [Leaf 3] [Leaf 4]
```
> [!TIP]
> *Περιπτώσεις χρήσης στην κυβερνοασφάλεια:* Τα δέντρα αποφάσεων έχουν χρησιμοποιηθεί σε συστήματα ανίχνευσης εισβολών για την εξαγωγή **κανόνων** αναγνώρισης επιθέσεων. Για παράδειγμα, τα πρώιμα IDS που βασίζονταν στα ID3/C4.5 παρήγαγαν ευανάγνωστους κανόνες για να διακρίνουν την κανονική από την κακόβουλη κίνηση. Χρησιμοποιούνται επίσης στην ανάλυση malware για να αποφασιστεί αν ένα αρχείο είναι κακόβουλο, με βάση τα χαρακτηριστικά του (μέγεθος αρχείου, εντροπία section, κλήσεις API κ.λπ.). Η σαφήνεια των δέντρων αποφάσεων τα καθιστά χρήσιμα όταν απαιτείται διαφάνεια -- ένας analyst μπορεί να εξετάσει το δέντρο για να επικυρώσει τη λογική ανίχνευσης.

#### **Βασικά χαρακτηριστικά των Decision Trees:**

-   **Τύπος προβλήματος:** Τόσο classification όσο και regression. Χρησιμοποιούνται συνήθως για την ταξινόμηση επιθέσεων έναντι κανονικής κίνησης κ.λπ.

-   **Ερμηνευσιμότητα:** Πολύ υψηλή -- οι αποφάσεις του model μπορούν να οπτικοποιηθούν και να γίνουν κατανοητές ως ένα σύνολο κανόνων if-then. Αυτό αποτελεί σημαντικό πλεονέκτημα στην ασφάλεια, για την εμπιστοσύνη και την επαλήθευση της συμπεριφοράς του model.

-   **Πλεονεκτήματα:** Μπορούν να αποτυπώσουν μη γραμμικές σχέσεις και αλληλεπιδράσεις μεταξύ features (κάθε διαχωρισμός μπορεί να θεωρηθεί ως αλληλεπίδραση). Δεν χρειάζεται να γίνει scaling των features ή one-hot encode των categorical variables -- τα trees τα διαχειρίζονται εγγενώς. Γρήγορο inference (η πρόβλεψη είναι απλώς η ακολούθηση μιας διαδρομής στο tree).

-   **Περιορισμοί:** Είναι επιρρεπή σε overfitting αν δεν ελεγχθούν (ένα βαθύ tree μπορεί να απομνημονεύσει το training set). Μπορεί να είναι ασταθή -- μικρές αλλαγές στα δεδομένα ενδέχεται να οδηγήσουν σε διαφορετική δομή tree. Ως μεμονωμένα models, η ακρίβειά τους μπορεί να μην ανταγωνίζεται πιο προηγμένες μεθόδους (τα ensembles όπως τα Random Forests συνήθως αποδίδουν καλύτερα, μειώνοντας το variance).

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

- **Information Gain**: Η μείωση της entropy ή της Gini impurity μετά από ένα split. Όσο υψηλότερο είναι το information gain, τόσο καλύτερο είναι το split. Υπολογίζεται ως εξής:

```plaintext
Information Gain = Entropy(parent) - (Weighted Average of Entropy(children))
```

Επιπλέον, ένα tree τερματίζεται όταν:
- Όλα τα instances σε ένα node ανήκουν στην ίδια κλάση. Αυτό μπορεί να οδηγήσει σε overfitting.
- Επιτευχθεί το μέγιστο βάθος (hardcoded) του tree. Αυτός είναι ένας τρόπος αποτροπής του overfitting.
- Ο αριθμός των instances σε ένα node είναι μικρότερος από ένα συγκεκριμένο threshold. Αυτός είναι επίσης ένας τρόπος αποτροπής του overfitting.
- Το information gain από περαιτέρω splits είναι μικρότερο από ένα συγκεκριμένο threshold. Αυτός είναι επίσης ένας τρόπος αποτροπής του overfitting.

<details>
<summary>Παράδειγμα -- Decision Tree για Ανίχνευση Εισβολών:</summary>
Θα εκπαιδεύσουμε ένα decision tree στο dataset NSL-KDD για να ταξινομήσουμε τις network connections ως *normal* ή *attack*. Το NSL-KDD είναι μια βελτιωμένη έκδοση του κλασικού dataset KDD Cup 1999, με features όπως protocol type, service, duration, number of failed logins κ.λπ., καθώς και ένα label που υποδεικνύει τον τύπο της επίθεσης ή την ένδειξη "normal". Θα αντιστοιχίσουμε όλους τους τύπους επιθέσεων στην κλάση "anomaly" (binary classification: normal έναντι anomaly). Μετά την εκπαίδευση, θα αξιολογήσουμε την απόδοση του tree στο test set.
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
Σε αυτό το παράδειγμα decision tree, περιορίσαμε το βάθος του δέντρου στο 10 για να αποφύγουμε το ακραίο overfitting (την παράμετρο `max_depth=10`). Τα metrics δείχνουν πόσο καλά το δέντρο διακρίνει την κανονική από την traffic επίθεσης. Το υψηλό recall σημαίνει ότι εντοπίζει τις περισσότερες επιθέσεις (κάτι σημαντικό για ένα IDS), ενώ το υψηλό precision σημαίνει λίγους false συναγερμούς. Τα decision trees συχνά επιτυγχάνουν αξιοπρεπή accuracy σε structured data, αλλά ένα μεμονωμένο tree μπορεί να μην πετύχει την καλύτερη δυνατή απόδοση. Παρ' όλα αυτά, η *ερμηνευσιμότητα* του μοντέλου αποτελεί σημαντικό πλεονέκτημα -- θα μπορούσαμε να εξετάσουμε τα splits του tree για να δούμε, για παράδειγμα, ποια features (π.χ. `service`, `src_bytes` κ.λπ.) επηρεάζουν περισσότερο την επισήμανση μιας σύνδεσης ως malicious.

</details>

### Random Forests

Το Random Forest είναι μια μέθοδος **ensemble learning** που βασίζεται στα decision trees για τη βελτίωση της απόδοσης. Ένα random forest εκπαιδεύει πολλά decision trees (εξ ου και το "forest") και συνδυάζει τα outputs τους για να πραγματοποιήσει μια τελική πρόβλεψη (για classification, συνήθως με majority vote). Οι δύο βασικές ιδέες σε ένα random forest είναι το **bagging** (bootstrap aggregating) και το **feature randomness**:

-   **Bagging:** Κάθε tree εκπαιδεύεται σε ένα τυχαίο bootstrap sample των training data (με sampling με replacement). Αυτό εισάγει diversity μεταξύ των trees.

-   **Feature Randomness:** Σε κάθε split ενός tree, εξετάζεται ένα τυχαίο υποσύνολο features για το split (αντί για όλα τα features). Αυτό αποσυσχετίζει περαιτέρω τα trees.

Με τον υπολογισμό του μέσου όρου των αποτελεσμάτων πολλών trees, το random forest μειώνει το variance που μπορεί να έχει ένα μεμονωμένο decision tree. Με απλά λόγια, μεμονωμένα trees μπορεί να κάνουν overfit ή να είναι θορυβώδη, αλλά ένας μεγάλος αριθμός διαφορετικών trees που ψηφίζουν μαζί εξομαλύνει αυτά τα σφάλματα. Το αποτέλεσμα είναι συχνά ένα μοντέλο με **υψηλότερο accuracy** και καλύτερο generalization από ένα μεμονωμένο decision tree. Επιπλέον, τα random forests μπορούν να παρέχουν μια εκτίμηση του feature importance (εξετάζοντας πόσο κάθε feature split μειώνει κατά μέσο όρο το impurity).

Τα random forests έχουν γίνει ένα **workhorse στο cybersecurity** για εργασίες όπως intrusion detection, malware classification και spam detection. Συχνά αποδίδουν καλά out-of-the-box με ελάχιστο tuning και μπορούν να διαχειριστούν μεγάλα feature sets. Για παράδειγμα, στο intrusion detection, ένα random forest μπορεί να ξεπεράσει ένα μεμονωμένο decision tree εντοπίζοντας πιο subtle patterns επιθέσεων με λιγότερα false positives. Έρευνες έχουν δείξει ότι τα random forests αποδίδουν ευνοϊκά σε σύγκριση με άλλους αλγορίθμους στην ταξινόμηση επιθέσεων σε datasets όπως τα NSL-KDD και UNSW-NB15.<sup>[[6]](#references)[[7]](#references)</sup>

#### **Βασικά χαρακτηριστικά των Random Forests:**

-   **Τύπος προβλήματος:** Κυρίως classification (χρησιμοποιείται επίσης για regression). Ιδιαίτερα κατάλληλο για high-dimensional structured data, που είναι συνηθισμένα στα security logs.

-   **Ερμηνευσιμότητα:** Χαμηλότερη από ενός μεμονωμένου decision tree -- δεν μπορείτε εύκολα να οπτικοποιήσετε ή να εξηγήσετε εκατοντάδες trees ταυτόχρονα. Ωστόσο, τα feature importance scores παρέχουν κάποια εικόνα για το ποια attributes επηρεάζουν περισσότερο το αποτέλεσμα.

-   **Πλεονεκτήματα:** Γενικά υψηλότερο accuracy από μοντέλα με ένα μόνο tree, χάρη στο ensemble effect. Ανθεκτικό στο overfitting -- ακόμη και αν μεμονωμένα trees κάνουν overfit, το ensemble κάνει καλύτερο generalization. Διαχειρίζεται τόσο numerical όσο και categorical features και μπορεί να χειριστεί missing data σε κάποιο βαθμό. Είναι επίσης σχετικά ανθεκτικό στα outliers.

-   **Περιορισμοί:** Το μέγεθος του model μπορεί να είναι μεγάλο (πολλά trees, καθένα από τα οποία μπορεί να είναι deep). Οι predictions είναι πιο αργές από ενός μεμονωμένου tree (καθώς πρέπει να γίνει aggregation σε πολλά trees). Έχει μικρότερη ερμηνευσιμότητα -- ενώ γνωρίζετε τα σημαντικά features, η ακριβής λογική δεν μπορεί εύκολα να trace-αριστεί όπως ένας απλός κανόνας. Αν το dataset είναι εξαιρετικά high-dimensional και sparse, η εκπαίδευση ενός πολύ μεγάλου forest μπορεί να είναι computationally heavy.

-   **Διαδικασία εκπαίδευσης:**
1. **Bootstrap Sampling**: Κάντε τυχαίο sampling των training data με replacement για να δημιουργήσετε πολλά υποσύνολα (bootstrap samples).
2. **Tree Construction**: Για κάθε bootstrap sample, δημιουργήστε ένα decision tree χρησιμοποιώντας ένα τυχαίο υποσύνολο features σε κάθε split. Αυτό εισάγει diversity μεταξύ των trees.
3. **Aggregation**: Για classification tasks, η τελική prediction πραγματοποιείται με majority vote μεταξύ των predictions όλων των trees. Για regression tasks, η τελική prediction είναι ο μέσος όρος των predictions όλων των trees.

<details>
<summary>Παράδειγμα -- Random Forest για Intrusion Detection (NSL-KDD):</summary>
Θα χρησιμοποιήσουμε το ίδιο NSL-KDD dataset (με binary labels ως normal έναντι anomaly) και θα εκπαιδεύσουμε έναν Random Forest classifier. Αναμένουμε ότι το random forest θα αποδώσει εξίσου καλά ή καλύτερα από το μεμονωμένο decision tree, χάρη στο ensemble averaging που μειώνει το variance. Θα το αξιολογήσουμε με τα ίδια metrics.
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
Το Random Forest συνήθως επιτυγχάνει ισχυρά αποτελέσματα σε αυτή την εργασία intrusion detection. Μπορεί να παρατηρήσουμε βελτίωση σε metrics όπως το F1 ή το AUC σε σύγκριση με το μεμονωμένο decision tree, ειδικά στο recall ή το precision, ανάλογα με τα δεδομένα. Αυτό συμφωνεί με την άποψη ότι το *"Random Forest (RF) is an ensemble classifier and performs well compared to other traditional classifiers for effective classification of attacks."*.<sup>[[6]](#references)</sup> Σε ένα security operations περιβάλλον, ένα μοντέλο random forest μπορεί να εντοπίζει τις επιθέσεις πιο αξιόπιστα, μειώνοντας παράλληλα τους false alarms, χάρη στον συνδυασμό πολλών decision rules. Η feature importance από το forest μπορεί να μας δείξει ποια network features είναι οι πιο ενδεικτικές επιθέσεων (π.χ. συγκεκριμένα network services ή ασυνήθιστοι αριθμοί packets).

</details>

### Support Vector Machines (SVM)

Τα Support Vector Machines είναι ισχυρά supervised learning models που χρησιμοποιούνται κυρίως για classification (και επίσης για regression ως SVR). Ένα SVM προσπαθεί να βρει το **optimal separating hyperplane** που μεγιστοποιεί το margin μεταξύ δύο classes. Μόνο ένα υποσύνολο των training points (τα "support vectors" που βρίσκονται πιο κοντά στο boundary) καθορίζει τη θέση αυτού του hyperplane. Με τη μεγιστοποίηση του margin (της απόστασης μεταξύ των support vectors και του hyperplane), τα SVMs τείνουν να επιτυγχάνουν καλή γενίκευση.<sup>[[8]](#references)</sup>

Κλειδί για την ισχύ των SVMs είναι η δυνατότητα χρήσης **kernel functions** για τον χειρισμό μη γραμμικών σχέσεων. Τα δεδομένα μπορούν να μετασχηματιστούν έμμεσα σε έναν feature space υψηλότερης διάστασης, όπου μπορεί να υπάρχει ένας linear separator. Τα συνηθισμένα kernels περιλαμβάνουν τα polynomial, radial basis function (RBF) και sigmoid. Για παράδειγμα, αν οι classes του network traffic δεν είναι linearly separable στον αρχικό feature space, ένα RBF kernel μπορεί να τις αντιστοιχίσει σε υψηλότερη διάσταση, όπου το SVM βρίσκει έναν linear διαχωρισμό (ο οποίος αντιστοιχεί σε ένα non-linear boundary στον αρχικό space). Η ευελιξία επιλογής kernels επιτρέπει στα SVMs να αντιμετωπίζουν διάφορα προβλήματα.

Τα SVMs είναι γνωστό ότι αποδίδουν καλά σε περιπτώσεις με high-dimensional feature spaces (όπως text data ή malware opcode sequences) και σε περιπτώσεις όπου ο αριθμός των features είναι μεγάλος σε σχέση με τον αριθμό των samples. Ήταν δημοφιλή σε πολλές πρώιμες εφαρμογές cybersecurity, όπως malware classification και anomaly-based intrusion detection, κατά τη δεκαετία του 2000, συχνά παρουσιάζοντας υψηλή accuracy.

Ωστόσο, τα SVMs δεν κλιμακώνονται εύκολα σε πολύ μεγάλα datasets (η training complexity είναι super-linear ως προς τον αριθμό των samples και η memory usage μπορεί να είναι υψηλή, καθώς ενδέχεται να χρειάζεται να αποθηκεύουν πολλά support vectors). Στην πράξη, για εργασίες όπως το network intrusion detection με εκατομμύρια records, ένα SVM μπορεί να είναι πολύ αργό χωρίς προσεκτικό subsampling ή τη χρήση approximate methods.

#### **Βασικά χαρακτηριστικά του SVM:**

-   **Τύπος προβλήματος:** Classification (binary ή multiclass μέσω one-vs-one/one-vs-rest) και regression variants. Χρησιμοποιείται συχνά σε binary classification με σαφή margin separation.

-   **Interpretability:** Medium -- τα SVMs δεν είναι τόσο interpretable όσο τα decision trees ή το logistic regression. Παρότι μπορείτε να εντοπίσετε ποια data points είναι support vectors και να αποκτήσετε κάποια εικόνα για το ποια features μπορεί να είναι influential (μέσω των weights στην περίπτωση του linear kernel), στην πράξη τα SVMs (ιδίως με non-linear kernels) αντιμετωπίζονται ως black-box classifiers.

-   **Πλεονεκτήματα:** Αποτελεσματικά σε high-dimensional spaces· μπορούν να μοντελοποιήσουν complex decision boundaries με το kernel trick· είναι ανθεκτικά στο overfitting όταν μεγιστοποιείται το margin (ιδίως με κατάλληλη παράμετρο regularization C)· αποδίδουν καλά ακόμη και όταν οι classes δεν διαχωρίζονται με μεγάλη απόσταση (βρίσκουν το βέλτιστο compromise boundary).

-   **Περιορισμοί:** **Computationally intensive** για μεγάλα datasets (τόσο το training όσο και το prediction κλιμακώνονται ανεπαρκώς καθώς αυξάνονται τα δεδομένα). Απαιτείται προσεκτικό tuning των kernel και regularization parameters (C, kernel type, gamma για RBF κ.λπ.). Δεν παρέχουν άμεσα probabilistic outputs (αν και μπορεί να χρησιμοποιηθεί Platt scaling για την εξαγωγή probabilities). Επίσης, τα SVMs μπορεί να είναι ευαίσθητα στην επιλογή kernel parameters --- μια κακή επιλογή μπορεί να οδηγήσει σε underfit ή overfit.

*Use cases in cybersecurity:* Τα SVMs έχουν χρησιμοποιηθεί σε **malware detection** (π.χ. για την ταξινόμηση αρχείων βάσει extracted features ή opcode sequences), **network anomaly detection** (ταξινόμηση του traffic ως normal ή malicious) και **phishing detection** (με χρήση features των URLs). Για παράδειγμα, ένα SVM μπορεί να λάβει features ενός email (counts συγκεκριμένων keywords, sender reputation scores κ.λπ.) και να το ταξινομήσει ως phishing ή legitimate. Έχουν επίσης εφαρμοστεί σε **intrusion detection** σε feature sets όπως το KDD, επιτυγχάνοντας συχνά υψηλή accuracy με κόστος σε computation.

<details>
<summary>Παράδειγμα -- SVM για Malware Classification:</summary>
Θα χρησιμοποιήσουμε ξανά το phishing website dataset, αυτή τη φορά με ένα SVM. Επειδή τα SVMs μπορεί να είναι αργά, θα χρησιμοποιήσουμε ένα subset των δεδομένων για το training, αν χρειαστεί (το dataset περιλαμβάνει περίπου 11k instances, τα οποία ένα SVM μπορεί να διαχειριστεί σχετικά εύκολα). Θα χρησιμοποιήσουμε ένα RBF kernel, το οποίο αποτελεί συνηθισμένη επιλογή για non-linear data, και θα ενεργοποιήσουμε τα probability estimates για να υπολογίσουμε το ROC AUC.
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
Το μοντέλο SVM θα επιστρέψει μετρικές τις οποίες μπορούμε να συγκρίνουμε με τη logistic regression για την ίδια εργασία. Ενδέχεται να διαπιστώσουμε ότι το SVM επιτυγχάνει υψηλή ακρίβεια και AUC, εάν τα δεδομένα διαχωρίζονται καλά από τα features. Από την άλλη πλευρά, εάν το dataset περιείχε πολύ θόρυβο ή επικαλυπτόμενες κλάσεις, το SVM μπορεί να μην υπερέχει σημαντικά της logistic regression. Στην πράξη, τα SVM μπορούν να προσφέρουν βελτίωση όταν υπάρχουν σύνθετες, μη γραμμικές σχέσεις μεταξύ των features και της κλάσης -- ο πυρήνας RBF μπορεί να αποτυπώσει καμπύλα όρια απόφασης που θα έχανε η logistic regression. Όπως συμβαίνει με όλα τα μοντέλα, απαιτείται προσεκτική ρύθμιση του `C` (regularization) και των παραμέτρων του kernel (όπως το `gamma` για το RBF), ώστε να επιτευχθεί ισορροπία μεταξύ bias και variance.

</details>

#### Διαφορά Logistic Rergessions & SVM

| Aspect | **Logistic Regression** | **Support Vector Machines** |
|---|---|---|
| **Objective function** | Ελαχιστοποιεί το **log-loss** (cross-entropy). | Μεγιστοποιεί το **margin**, ενώ ελαχιστοποιεί το **hinge-loss**. |
| **Decision boundary** | Βρίσκει το **hyperplane βέλτιστης προσαρμογής** που μοντελοποιεί το _P(y\|x)_. | Βρίσκει το **hyperplane μέγιστου margin** (το μεγαλύτερο κενό από τα κοντινότερα σημεία). |
| **Output** | **Πιθανοτικό** – παρέχει calibrated class probabilities μέσω του σ(w·x + b). | **Ντετερμινιστικό** – επιστρέφει class labels· οι probabilities απαιτούν πρόσθετη επεξεργασία (π.χ. Platt scaling). |
| **Regularisation** | L2 (προεπιλογή) ή L1, εξισορροπεί άμεσα το underfitting και το overfitting. | Η παράμετρος C αποτελεί συμβιβασμό μεταξύ του πλάτους του margin και των mis-classifications· οι παράμετροι του kernel προσθέτουν πολυπλοκότητα. |
| **Kernels / Non‑linear** | Η εγγενής μορφή είναι **γραμμική**· η μη γραμμικότητα προστίθεται μέσω feature engineering. | Το ενσωματωμένο **kernel trick** (RBF, poly κ.λπ.) του επιτρέπει να μοντελοποιεί σύνθετα όρια σε χώρο υψηλής διάστασης. |
| **Scalability** | Επιλύει μια convex optimisation σε **O(nd)**· διαχειρίζεται καλά πολύ μεγάλα n. | Η εκπαίδευση μπορεί να απαιτεί **O(n²–n³)** σε memory/time χωρίς specialised solvers· είναι λιγότερο κατάλληλη για τεράστιες τιμές του n. |
| **Interpretability** | **Υψηλή** – τα weights δείχνουν την επιρροή των features· το odds ratio είναι εύκολα κατανοητό. | **Χαμηλή** για μη γραμμικούς kernels· τα support vectors είναι sparse, αλλά δεν εξηγούνται εύκολα. |
| **Sensitivity to outliers** | Χρησιμοποιεί ομαλό log-loss → είναι λιγότερο ευαίσθητη. | Το hinge-loss με hard margin μπορεί να είναι **ευαίσθητο**· το soft-margin (C) μετριάζει το πρόβλημα. |
| **Typical use cases** | Credit scoring, medical risk, A/B testing – όπου έχουν σημασία οι **probabilities και η explainability**. | Image/text classification, bio-informatics – όπου έχουν σημασία τα **σύνθετα όρια** και τα **high-dimensional data**. |

* **Εάν χρειάζεστε calibrated probabilities, interpretability ή λειτουργία σε τεράστια datasets — επιλέξτε Logistic Regression.**
* **Εάν χρειάζεστε ένα ευέλικτο μοντέλο που μπορεί να αποτυπώσει μη γραμμικές σχέσεις χωρίς χειροκίνητο feature engineering — επιλέξτε SVM (με kernels).**
* Και τα δύο βελτιστοποιούν convex objectives, επομένως **τα global minima είναι εγγυημένα**, αλλά οι kernels του SVM προσθέτουν hyper-parameters και υπολογιστικό κόστος.

### Naive Bayes

Το Naive Bayes είναι μια οικογένεια **probabilistic classifiers** που βασίζεται στην εφαρμογή του Bayes' Theorem, με την ισχυρή υπόθεση ανεξαρτησίας μεταξύ των features. Παρά αυτή τη «naive» υπόθεση, το Naive Bayes συχνά λειτουργεί εκπληκτικά καλά σε ορισμένες εφαρμογές, ειδικά σε εκείνες που περιλαμβάνουν text ή categorical data, όπως η ανίχνευση spam.<sup>[[9]](#references)</sup>


#### Θεώρημα του Bayes

Το θεώρημα του Bayes αποτελεί τη βάση των Naive Bayes classifiers. Συσχετίζει τις conditional και marginal probabilities τυχαίων γεγονότων. Ο τύπος είναι ο εξής:
```plaintext
P(A|B) = (P(B|A) * P(A)) / P(B)
```
Πού:
- `P(A|B)` είναι η εκ των υστέρων πιθανότητα της κλάσης `A` δεδομένου του χαρακτηριστικού `B`.
- `P(B|A)` είναι η πιθανοφάνεια του χαρακτηριστικού `B` δεδομένης της κλάσης `A`.
- `P(A)` είναι η εκ των προτέρων πιθανότητα της κλάσης `A`.
- `P(B)` είναι η εκ των προτέρων πιθανότητα του χαρακτηριστικού `B`.

Για παράδειγμα, αν θέλουμε να ταξινομήσουμε αν ένα κείμενο έχει γραφτεί από παιδί ή ενήλικα, μπορούμε να χρησιμοποιήσουμε τις λέξεις του κειμένου ως χαρακτηριστικά. Με βάση κάποια αρχικά δεδομένα, ο Naive Bayes classifier θα υπολογίσει εκ των προτέρων τις πιθανότητες κάθε λέξης να ανήκει σε κάθε πιθανή κλάση (παιδί ή ενήλικας). Όταν δοθεί ένα νέο κείμενο, θα υπολογίσει την πιθανότητα κάθε πιθανής κλάσης δεδομένων των λέξεων του κειμένου και θα επιλέξει την κλάση με την υψηλότερη πιθανότητα.

Όπως μπορείτε να δείτε σε αυτό το παράδειγμα, ο Naive Bayes classifier είναι πολύ απλός και γρήγορος, αλλά υποθέτει ότι τα χαρακτηριστικά είναι ανεξάρτητα, κάτι που δεν ισχύει πάντα σε δεδομένα του πραγματικού κόσμου.


#### Τύποι Naive Bayes Classifiers

Υπάρχουν αρκετοί τύποι Naive Bayes classifiers, ανάλογα με τον τύπο των δεδομένων και την κατανομή των χαρακτηριστικών:
- **Gaussian Naive Bayes**: Υποθέτει ότι τα χαρακτηριστικά ακολουθούν Gaussian (κανονική) κατανομή. Είναι κατάλληλος για συνεχή δεδομένα.
- **Multinomial Naive Bayes**: Υποθέτει ότι τα χαρακτηριστικά ακολουθούν multinomial κατανομή. Είναι κατάλληλος για διακριτά δεδομένα, όπως οι μετρήσεις λέξεων στην ταξινόμηση κειμένου.
- **Bernoulli Naive Bayes**: Υποθέτει ότι τα χαρακτηριστικά είναι δυαδικά (0 ή 1). Είναι κατάλληλος για δυαδικά δεδομένα, όπως η παρουσία ή η απουσία λέξεων στην ταξινόμηση κειμένου.
- **Categorical Naive Bayes**: Υποθέτει ότι τα χαρακτηριστικά είναι categorical μεταβλητές. Είναι κατάλληλος για categorical δεδομένα, όπως η ταξινόμηση φρούτων με βάση το χρώμα και το σχήμα τους.


#### **Βασικά χαρακτηριστικά του Naive Bayes:**

-   **Τύπος προβλήματος:** Classification (binary ή multi-class). Χρησιμοποιείται συχνά για εργασίες text classification στην κυβερνοασφάλεια (spam, phishing κ.λπ.).

-   **Ερμηνευσιμότητα:** Μέτρια -- δεν είναι τόσο άμεσα ερμηνεύσιμος όσο ένα decision tree, αλλά μπορεί κανείς να εξετάσει τις μαθημένες πιθανότητες (π.χ. ποιες λέξεις είναι πιθανότερο να εμφανίζονται σε spam σε σχέση με ham emails). Η μορφή του μοντέλου (πιθανότητες για κάθε χαρακτηριστικό δεδομένης της κλάσης) μπορεί να γίνει κατανοητή, αν χρειαστεί.

-   **Πλεονεκτήματα:** **Πολύ γρήγορη** εκπαίδευση και πρόβλεψη, ακόμη και σε μεγάλα datasets (γραμμική ως προς τον αριθμό των instances * τον αριθμό των features). Απαιτεί σχετικά μικρή ποσότητα δεδομένων για την αξιόπιστη εκτίμηση των πιθανοτήτων, ειδικά με τη σωστή χρήση smoothing. Συχνά είναι εκπληκτικά ακριβής ως baseline, ιδιαίτερα όταν τα χαρακτηριστικά συνεισφέρουν ανεξάρτητα στοιχεία στην κλάση. Λειτουργεί καλά με high-dimensional δεδομένα (π.χ. χιλιάδες features από κείμενο). Δεν απαιτεί σύνθετο tuning, πέρα από τον ορισμό μιας smoothing παραμέτρου.

-   **Περιορισμοί:** Η υπόθεση ανεξαρτησίας μπορεί να περιορίσει την ακρίβεια όταν τα χαρακτηριστικά έχουν υψηλή συσχέτιση. Για παράδειγμα, σε network δεδομένα, χαρακτηριστικά όπως τα `src_bytes` και `dst_bytes` μπορεί να συσχετίζονται· ο Naive Bayes δεν θα καταγράψει αυτή την αλληλεπίδραση. Καθώς το μέγεθος των δεδομένων αυξάνεται σημαντικά, πιο εκφραστικά μοντέλα (όπως ensembles ή neural nets) μπορούν να ξεπεράσουν το NB, μαθαίνοντας τις εξαρτήσεις μεταξύ των χαρακτηριστικών. Επίσης, αν απαιτείται ένας συγκεκριμένος συνδυασμός χαρακτηριστικών για την αναγνώριση μιας επίθεσης (και όχι μόνο μεμονωμένα χαρακτηριστικά ανεξάρτητα), το NB θα δυσκολευτεί.

> [!TIP]
> *Use cases in cybersecurity:* Η κλασική χρήση είναι η **ανίχνευση spam** -- ο Naive Bayes αποτέλεσε τον πυρήνα των πρώτων spam filters, χρησιμοποιώντας τις συχνότητες συγκεκριμένων tokens (λέξεις, φράσεις, IP addresses) για να υπολογίσει την πιθανότητα ένα email να είναι spam. Χρησιμοποιείται επίσης στην **ανίχνευση phishing emails** και στην **ταξινόμηση URLs**, όπου η παρουσία συγκεκριμένων keywords ή χαρακτηριστικών (όπως το "login.php" σε ένα URL ή το `@` σε ένα URL path) συνεισφέρει στην πιθανότητα phishing. Στην ανάλυση malware, θα μπορούσε κανείς να φανταστεί έναν Naive Bayes classifier που χρησιμοποιεί την παρουσία συγκεκριμένων API calls ή permissions σε software, για να προβλέψει αν πρόκειται για malware. Παρόλο που οι πιο προηγμένοι αλγόριθμοι συχνά αποδίδουν καλύτερα, ο Naive Bayes παραμένει ένα καλό baseline λόγω της ταχύτητας και της απλότητάς του.

<details>
<summary>Παράδειγμα -- Naive Bayes για ανίχνευση phishing:</summary>
Για να παρουσιάσουμε τον Naive Bayes, θα χρησιμοποιήσουμε Gaussian Naive Bayes στο NSL-KDD intrusion dataset (με binary labels). Το Gaussian NB θα θεωρήσει ότι κάθε feature ακολουθεί κανονική κατανομή ανά κλάση. Αυτή είναι μια πρόχειρη επιλογή, καθώς πολλά network features είναι διακριτά ή έχουν έντονη ασυμμετρία, αλλά δείχνει πώς θα εφαρμόζαμε το NB σε δεδομένα με continuous features. Θα μπορούσαμε επίσης να επιλέξουμε Bernoulli NB σε ένα dataset με binary features (όπως ένα σύνολο από triggered alerts), αλλά εδώ θα παραμείνουμε στο NSL-KDD για λόγους συνέχειας.
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
Αυτός ο κώδικας εκπαιδεύει έναν classifier Naive Bayes για την ανίχνευση επιθέσεων. Ο Naive Bayes θα υπολογίσει τιμές όπως `P(service=http | Attack)` και `P(Service=http | Normal)` με βάση τα training data, υποθέτοντας ανεξαρτησία μεταξύ των features. Στη συνέχεια, θα χρησιμοποιήσει αυτές τις πιθανότητες για να ταξινομήσει νέες συνδέσεις ως normal ή attack, με βάση τα features που παρατηρούνται. Η απόδοση του NB στο NSL-KDD μπορεί να μην είναι τόσο υψηλή όσο εκείνη πιο προηγμένων μοντέλων (επειδή παραβιάζεται η ανεξαρτησία των features), αλλά συχνά είναι αξιοπρεπής και προσφέρει το πλεονέκτημα της εξαιρετικά υψηλής ταχύτητας. Σε σενάρια όπως το real-time email filtering ή το αρχικό triage URLs, ένα μοντέλο Naive Bayes μπορεί να επισημάνει γρήγορα τις προφανώς κακόβουλες περιπτώσεις με χαμηλή κατανάλωση πόρων.

</details>

### k-Nearest Neighbors (k-NN)

Το k-Nearest Neighbors είναι ένας από τους απλούστερους αλγορίθμους machine learning. Είναι μια **non-parametric, instance-based** μέθοδος που πραγματοποιεί προβλέψεις με βάση την ομοιότητα με παραδείγματα του training set. Η ιδέα για την ταξινόμηση είναι η εξής: για να ταξινομηθεί ένα νέο data point, βρίσκουμε τα **k** κοντινότερα points στα training data (τους «nearest neighbors») και του εκχωρούμε την πλειοψηφική class μεταξύ αυτών των neighbors. Η «εγγύτητα» ορίζεται από ένα distance metric, συνήθως την Euclidean distance για αριθμητικά data (μπορούν να χρησιμοποιηθούν και άλλες αποστάσεις για διαφορετικούς τύπους features ή προβλημάτων).<sup>[[10]](#references)</sup>

Το K-NN δεν απαιτεί *explicit training* -- η φάση του «training» consiste απλώς στην αποθήκευση του dataset. Όλη η εργασία πραγματοποιείται κατά το query (prediction): ο αλγόριθμος πρέπει να υπολογίσει τις αποστάσεις από το query point προς όλα τα training points, ώστε να βρει τα κοντινότερα. Αυτό καθιστά τον χρόνο prediction **γραμμικό ως προς τον αριθμό των training samples**, κάτι που μπορεί να είναι δαπανηρό για μεγάλα datasets. Για τον λόγο αυτό, το k-NN είναι καταλληλότερο για μικρότερα datasets ή σενάρια όπου μπορείτε να ανταλλάξετε memory και speed με απλότητα.

Παρά την απλότητά του, το k-NN μπορεί να μοντελοποιήσει πολύ σύνθετα decision boundaries (καθώς, στην πράξη, το decision boundary μπορεί να έχει οποιοδήποτε σχήμα, το οποίο καθορίζεται από την κατανομή των παραδειγμάτων). Τείνει να αποδίδει καλά όταν το decision boundary είναι πολύ irregular και υπάρχει μεγάλος όγκος data -- ουσιαστικά αφήνοντας τα data να «μιλήσουν από μόνα τους». Ωστόσο, σε υψηλές διαστάσεις, τα distance metrics μπορεί να γίνουν λιγότερο meaningful (curse of dimensionality) και η μέθοδος μπορεί να δυσκολευτεί, εκτός αν διαθέτετε τεράστιο αριθμό samples.

*Use cases στο cybersecurity:* Το k-NN έχει εφαρμοστεί σε anomaly detection -- για παράδειγμα, ένα intrusion detection system μπορεί να χαρακτηρίσει ένα network event ως malicious αν οι περισσότεροι από τους nearest neighbors του (προηγούμενα events) ήταν malicious. Αν το normal traffic σχηματίζει clusters και οι επιθέσεις είναι outliers, μια προσέγγιση K-NN (με k=1 ή μικρό k) αποτελεί ουσιαστικά ένα **nearest-neighbor anomaly detection**. Το K-NN έχει επίσης χρησιμοποιηθεί για την ταξινόμηση malware families μέσω binary feature vectors: ένα νέο file μπορεί να ταξινομηθεί ως μέλος μιας συγκεκριμένης malware family αν βρίσκεται πολύ κοντά (στο feature space) σε γνωστά instances αυτής της family. Στην πράξη, το k-NN δεν είναι τόσο συνηθισμένο όσο πιο scalable algorithms, αλλά είναι conceptually straightforward και χρησιμοποιείται μερικές φορές ως baseline ή για small-scale problems.

#### **Key characteristics of k-NN:**

-   **Type of Problem:** Classification (και υπάρχουν variants για regression). Είναι μια μέθοδος *lazy learning* -- δεν πραγματοποιείται explicit model fitting.

-   **Interpretability:** Low έως medium -- δεν υπάρχει global model ή concise explanation, αλλά τα αποτελέσματα μπορούν να ερμηνευτούν εξετάζοντας τους nearest neighbors που επηρέασαν μια απόφαση (π.χ. «αυτό το network flow ταξινομήθηκε ως malicious επειδή είναι παρόμοιο με αυτά τα 3 γνωστά malicious flows»). Επομένως, οι explanations μπορούν να βασίζονται σε examples.

-   **Advantages:** Πολύ απλή στην υλοποίηση και την κατανόηση. Δεν κάνει assumptions σχετικά με την κατανομή των data (non-parametric). Μπορεί να διαχειριστεί φυσικά multi-class problems. Είναι **adaptive**, με την έννοια ότι τα decision boundaries μπορούν να είναι πολύ σύνθετα και να διαμορφώνονται από την κατανομή των data.

-   **Limitations:** Το prediction μπορεί να είναι αργό για μεγάλα datasets (πρέπει να υπολογιστούν πολλές αποστάσεις). Απαιτεί πολλή memory -- αποθηκεύει όλα τα training data. Η απόδοση μειώνεται σε high-dimensional feature spaces, επειδή όλα τα points τείνουν να γίνουν σχεδόν ισαπέχοντα (καθιστώντας την έννοια του «nearest» λιγότερο meaningful). Απαιτείται σωστή επιλογή του *k* (αριθμός των neighbors) -- ένα πολύ μικρό k μπορεί να οδηγήσει σε noisy αποτελέσματα, ενώ ένα πολύ μεγάλο k μπορεί να περιλαμβάνει irrelevant points από άλλες classes. Επίσης, τα features πρέπει να γίνουν κατάλληλα scaled, επειδή οι υπολογισμοί αποστάσεων είναι ευαίσθητοι στο scale.

<details>
<summary>Example -- k-NN for Phishing Detection:</summary>

Θα χρησιμοποιήσουμε ξανά το NSL-KDD (binary classification). Επειδή το k-NN είναι computationally heavy, θα χρησιμοποιήσουμε ένα subset των training data, ώστε το demonstration να παραμείνει tractable. Θα επιλέξουμε, για παράδειγμα, 20.000 training samples από τα συνολικά 125k και θα χρησιμοποιήσουμε k=5 neighbors. Μετά το training (στην πραγματικότητα, απλώς την αποθήκευση των data), θα αξιολογήσουμε το μοντέλο στο test set. Θα κάνουμε επίσης scale στα features για τον υπολογισμό των αποστάσεων, ώστε κανένα μεμονωμένο feature να μην κυριαρχεί εξαιτίας του scale.
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
Το μοντέλο k-NN θα ταξινομήσει μια σύνδεση εξετάζοντας τις 5 πλησιέστερες συνδέσεις στο υποσύνολο του training set. Αν, για παράδειγμα, 4 από αυτούς τους γείτονες είναι attacks (anomalies) και 1 είναι normal, η νέα σύνδεση θα ταξινομηθεί ως attack. Η απόδοση μπορεί να είναι ικανοποιητική, αν και συχνά όχι τόσο υψηλή όσο ενός καλά ρυθμισμένου Random Forest ή SVM στα ίδια δεδομένα. Ωστόσο, το k-NN μπορεί μερικές φορές να ξεχωρίσει όταν οι κατανομές των κλάσεων είναι πολύ ακανόνιστες και σύνθετες -- χρησιμοποιώντας ουσιαστικά μια memory-based lookup. Στην cybersecurity, το k-NN (με k=1 ή μικρό k) θα μπορούσε να χρησιμοποιηθεί για την ανίχνευση γνωστών attack patterns μέσω παραδειγμάτων ή ως στοιχείο σε πιο σύνθετα συστήματα (π.χ. για clustering και στη συνέχεια ταξινόμηση με βάση το cluster membership).
</details>

### Gradient Boosting Machines (π.χ. XGBoost)

Τα Gradient Boosting Machines συγκαταλέγονται στους ισχυρότερους αλγορίθμους για structured data. Το **gradient boosting** αναφέρεται στην τεχνική δημιουργίας ενός ensemble από weak learners (συχνά decision trees) με sequential τρόπο, όπου κάθε νέο model διορθώνει τα errors του προηγούμενου ensemble. Σε αντίθεση με το bagging (Random Forests), το οποίο δημιουργεί trees παράλληλα και υπολογίζει τον μέσο όρο τους, το boosting δημιουργεί trees *ένα-ένα*, εστιάζοντας περισσότερο στα instances που τα προηγούμενα trees ταξινόμησαν λανθασμένα.<sup>[[11]](#references)</sup>

Οι δημοφιλέστερες implementations τα τελευταία χρόνια είναι οι **XGBoost**, **LightGBM** και **CatBoost**, οι οποίες είναι libraries για gradient boosting decision trees (GBDT). Έχουν σημειώσει εξαιρετική επιτυχία σε machine learning competitions και εφαρμογές, συχνά **επιτυγχάνοντας state-of-the-art performance σε tabular datasets**. Στην cybersecurity, researchers και practitioners έχουν χρησιμοποιήσει gradient boosted trees για tasks όπως **malware detection** (χρησιμοποιώντας features που εξάγονται από files ή runtime behavior) και **network intrusion detection**. Για παράδειγμα, ένα gradient boosting model μπορεί να συνδυάσει πολλούς weak rules (trees), όπως "αν υπάρχουν πολλά SYN packets και ασυνήθιστο port -> πιθανό scan", σε έναν ισχυρό composite detector που λαμβάνει υπόψη πολλά λεπτά patterns.

Γιατί είναι τόσο αποτελεσματικά τα boosted trees; Κάθε tree στη sequence εκπαιδεύεται πάνω στα *residual errors* (gradients) των predictions του τρέχοντος ensemble. Με αυτόν τον τρόπο, το model σταδιακά **"ενισχύει"** τις περιοχές στις οποίες είναι αδύναμο. Η χρήση decision trees ως base learners σημαίνει ότι το τελικό model μπορεί να καταγράψει σύνθετες interactions και non-linear relations. Επίσης, το boosting διαθέτει εγγενώς μια μορφή ενσωματωμένου regularization: προσθέτοντας πολλά μικρά trees (και χρησιμοποιώντας learning rate για την κλιμάκωση της συνεισφοράς τους), συχνά γενικεύεται καλά χωρίς έντονο overfitting, εφόσον επιλεγούν οι κατάλληλες parameters.

#### **Βασικά χαρακτηριστικά του Gradient Boosting:**

-   **Τύπος προβλήματος:** Κυρίως classification και regression. Στην ασφάλεια, συνήθως classification (π.χ. binary classification μιας σύνδεσης ή ενός file). Υποστηρίζει binary, multi-class (με το κατάλληλο loss), ακόμη και ranking problems.

-   **Ερμηνευσιμότητα:** Χαμηλή έως μέτρια. Ενώ ένα μεμονωμένο boosted tree είναι μικρό, ένα πλήρες model μπορεί να έχει εκατοντάδες trees, επομένως δεν είναι human-interpretable ως σύνολο. Ωστόσο, όπως το Random Forest, μπορεί να παρέχει feature importance scores, ενώ tools όπως το SHAP (SHapley Additive exPlanations) μπορούν να χρησιμοποιηθούν για την ερμηνεία individual predictions σε κάποιο βαθμό.

-   **Πλεονεκτήματα:** Συχνά είναι ο **αλγόριθμος με την καλύτερη απόδοση** για structured/tabular data. Μπορεί να ανιχνεύσει σύνθετα patterns και interactions. Διαθέτει πολλές tuning knobs (αριθμός trees, depth των trees, learning rate, regularization terms) για την προσαρμογή της πολυπλοκότητας του model και την αποφυγή overfitting. Οι σύγχρονες implementations είναι βελτιστοποιημένες για speed (π.χ. το XGBoost χρησιμοποιεί second-order gradient info και efficient data structures). Τείνει να διαχειρίζεται imbalanced data καλύτερα όταν συνδυάζεται με κατάλληλες loss functions ή με προσαρμογή των sample weights.

-   **Περιορισμοί:** Είναι πιο σύνθετο στη ρύθμιση από τα απλούστερα models· το training μπορεί να είναι αργό αν τα trees είναι deep ή ο αριθμός των trees μεγάλος (αν και συνήθως παραμένει ταχύτερο από το training ενός συγκρίσιμου deep neural network στα ίδια δεδομένα). Το model μπορεί να υποστεί overfit αν δεν ρυθμιστεί σωστά (π.χ. υπερβολικά πολλά deep trees με ανεπαρκές regularization). Λόγω των πολλών hyperparameters, η αποτελεσματική χρήση του gradient boosting μπορεί να απαιτεί περισσότερη expertise ή experimentation. Επίσης, όπως οι tree-based μέθοδοι, δεν διαχειρίζεται εγγενώς τόσο αποτελεσματικά πολύ sparse high-dimensional data όσο τα linear models ή το Naive Bayes (αν και μπορεί να εφαρμοστεί, π.χ. σε text classification, αλλά ίσως να μην είναι η πρώτη επιλογή χωρίς feature engineering).

> [!TIP]
> *Use cases στην cybersecurity:* Σχεδόν οπουδήποτε θα μπορούσε να χρησιμοποιηθεί ένα decision tree ή random forest, ένα gradient boosting model μπορεί να επιτύχει καλύτερη ακρίβεια. Για παράδειγμα, οι διαγωνισμοί **Microsoft's malware detection** έχουν κάνει εκτεταμένη χρήση του XGBoost σε engineered features από binary files. Η έρευνα για **network intrusion detection** συχνά αναφέρει κορυφαία results με GBDTs (π.χ. XGBoost στα CIC-IDS2017 ή UNSW-NB15 datasets). Αυτά τα models μπορούν να λάβουν ένα ευρύ φάσμα features (protocol types, frequency συγκεκριμένων events, statistical features της κίνησης κ.λπ.) και να τα συνδυάσουν για την ανίχνευση threats. Στο phishing detection, το gradient boosting μπορεί να συνδυάσει lexical features των URLs, domain reputation features και page content features για να επιτύχει πολύ υψηλή ακρίβεια. Η ensemble προσέγγιση βοηθά στην κάλυψη πολλών corner cases και λεπτομερειών στα δεδομένα.

<details>
<summary>Παράδειγμα -- XGBoost για Phishing Detection:</summary>
Θα χρησιμοποιήσουμε έναν gradient boosting classifier στο phishing dataset. Για να διατηρήσουμε τα πράγματα απλά και self-contained, θα χρησιμοποιήσουμε το `sklearn.ensemble.GradientBoostingClassifier` (το οποίο είναι μια πιο αργή αλλά straightforward implementation). Κανονικά, θα μπορούσε κανείς να χρησιμοποιήσει τις libraries `xgboost` ή `lightgbm` για καλύτερη performance και επιπλέον features. Θα εκπαιδεύσουμε το model και θα το αξιολογήσουμε με παρόμοιο τρόπο όπως προηγουμένως.
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
Το μοντέλο gradient boosting πιθανότατα θα πετύχει πολύ υψηλή ακρίβεια και AUC σε αυτό το phishing dataset (συχνά αυτά τα μοντέλα μπορούν να ξεπεράσουν το 95% ακρίβειας με σωστό tuning σε τέτοια δεδομένα, όπως έχει παρατηρηθεί στη σχετική βιβλιογραφία. Αυτό δείχνει γιατί τα GBDTs θεωρούνται *«το state-of-the-art μοντέλο για tabular datasets»* -- συχνά υπερτερούν έναντι απλούστερων αλγορίθμων, καθώς εντοπίζουν σύνθετα μοτίβα.<sup>[[11]](#references)</sup> Σε ένα πλαίσιο κυβερνοασφάλειας, αυτό θα μπορούσε να σημαίνει τον εντοπισμό περισσότερων phishing sites ή επιθέσεων με λιγότερες αστοχίες. Φυσικά, πρέπει να είμαστε προσεκτικοί με το overfitting -- συνήθως θα χρησιμοποιούσαμε τεχνικές όπως cross-validation και θα παρακολουθούσαμε την απόδοση σε ένα validation set κατά την ανάπτυξη ενός τέτοιου μοντέλου για deployment.

</details>

### Συνδυασμός Μοντέλων: Ensemble Learning και Stacking

Το ensemble learning είναι μια στρατηγική **συνδυασμού πολλαπλών μοντέλων** για τη βελτίωση της συνολικής απόδοσης. Έχουμε ήδη δει συγκεκριμένες ensemble μεθόδους: Random Forest (ένα ensemble από δέντρα μέσω bagging) και Gradient Boosting (ένα ensemble από δέντρα μέσω sequential boosting). Ωστόσο, ensembles μπορούν να δημιουργηθούν και με άλλους τρόπους, όπως **voting ensembles** ή **stacked generalization (stacking)**. Η βασική ιδέα είναι ότι διαφορετικά μοντέλα μπορεί να εντοπίζουν διαφορετικά μοτίβα ή να έχουν διαφορετικές αδυναμίες· συνδυάζοντάς τα, μπορούμε να **αντισταθμίσουμε τα σφάλματα κάθε μοντέλου με τα δυνατά σημεία κάποιου άλλου**.<sup>[[12]](#references)</sup>

-   **Voting Ensemble:** Σε έναν απλό voting classifier, εκπαιδεύουμε πολλαπλά διαφορετικά μοντέλα (για παράδειγμα, ένα logistic regression, ένα decision tree και ένα SVM) και τα βάζουμε να ψηφίσουν για την τελική πρόβλεψη (πλειοψηφική ψήφος για classification). Αν σταθμίσουμε τις ψήφους (π.χ. δώσουμε μεγαλύτερο βάρος στα πιο ακριβή μοντέλα), έχουμε ένα weighted voting scheme. Αυτό συνήθως βελτιώνει την απόδοση όταν τα μεμονωμένα μοντέλα είναι αρκετά καλά και ανεξάρτητα -- το ensemble μειώνει τον κίνδυνο ενός λάθους από ένα μεμονωμένο μοντέλο, καθώς τα υπόλοιπα μπορεί να το διορθώσουν. Είναι σαν να έχουμε μια ομάδα ειδικών αντί για μία μόνο άποψη.

-   **Stacking (Stacked Ensemble):** Το stacking προχωρά ένα βήμα παραπέρα. Αντί για μια απλή ψηφοφορία, εκπαιδεύει ένα **meta-model** ώστε να **μάθει πώς να συνδυάζει καλύτερα τις προβλέψεις** των base models. Για παράδειγμα, εκπαιδεύεις 3 διαφορετικούς classifiers (base learners) και στη συνέχεια τροφοδοτείς τις εξόδους τους (ή τις πιθανότητές τους) ως features σε έναν meta-classifier (συχνά ένα απλό μοντέλο, όπως το logistic regression), ο οποίος μαθαίνει τον βέλτιστο τρόπο συνδυασμού τους. Το meta-model εκπαιδεύεται σε ένα validation set ή μέσω cross-validation, ώστε να αποφεύγεται το overfitting. Το stacking συχνά μπορεί να ξεπεράσει το απλό voting, μαθαίνοντας *ποια μοντέλα να εμπιστεύεται περισσότερο σε κάθε περίσταση*. Στην κυβερνοασφάλεια, ένα μοντέλο μπορεί να είναι καλύτερο στον εντοπισμό network scans, ενώ ένα άλλο στον εντοπισμό malware beaconing· ένα stacking model θα μπορούσε να μάθει να βασίζεται κατάλληλα στο καθένα.

Τα ensembles, είτε μέσω voting είτε μέσω stacking, τείνουν να **βελτιώνουν την ακρίβεια** και την ανθεκτικότητα. Το μειονέκτημα είναι η αυξημένη πολυπλοκότητα και, μερικές φορές, η μειωμένη interpretability (αν και ορισμένες ensemble προσεγγίσεις, όπως ο μέσος όρος από decision trees, μπορούν να προσφέρουν κάποια insight, π.χ. feature importance). Στην πράξη, αν οι operational περιορισμοί το επιτρέπουν, η χρήση ενός ensemble μπορεί να οδηγήσει σε υψηλότερα detection rates. Πολλές νικητήριες λύσεις σε cybersecurity challenges (και γενικότερα σε Kaggle competitions) χρησιμοποιούν ensemble τεχνικές για να αποσπάσουν και το τελευταίο μέρος της διαθέσιμης απόδοσης.

<details>
<summary>Παράδειγμα -- Voting Ensemble για Phishing Detection:</summary>
Για να παρουσιάσουμε το model stacking, ας συνδυάσουμε μερικά από τα μοντέλα που συζητήσαμε στο phishing dataset. Θα χρησιμοποιήσουμε ένα logistic regression, ένα decision tree και ένα k-NN ως base learners, και ένα Random Forest ως meta-learner για τη συγκέντρωση των προβλέψεών τους. Το meta-learner θα εκπαιδευτεί στις εξόδους των base learners (με χρήση cross-validation στο training set). Περιμένουμε το stacked model να έχει απόδοση ίδια ή ελαφρώς καλύτερη από εκείνη των μεμονωμένων μοντέλων.
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
Το stacked ensemble αξιοποιεί τα συμπληρωματικά πλεονεκτήματα των base models. Για παράδειγμα, η logistic regression μπορεί να χειρίζεται τις γραμμικές πτυχές των δεδομένων, το decision tree μπορεί να εντοπίζει συγκεκριμένες αλληλεπιδράσεις που μοιάζουν με κανόνες και το k-NN μπορεί να αποδίδει εξαιρετικά σε τοπικές γειτονιές του χώρου χαρακτηριστικών. Το meta-model (ένα random forest εδώ) μπορεί να μάθει πώς να σταθμίζει αυτές τις εισόδους. Οι resulting metrics συχνά δείχνουν βελτίωση (έστω και μικρή) σε σχέση με τις metrics οποιουδήποτε μεμονωμένου model. Στο παράδειγμα phishing, αν το logistic μόνο του είχε F1, για παράδειγμα, 0.95 και το tree 0.94, το stack μπορεί να πετύχει 0.96, αξιοποιώντας τα σημεία στα οποία κάθε model κάνει λάθη.

Μέθοδοι ensemble όπως αυτή καταδεικνύουν την αρχή ότι *"ο συνδυασμός πολλαπλών models συνήθως οδηγεί σε καλύτερο generalization"*.<sup>[[12]](#references)</sup> Στην κυβερνοασφάλεια, αυτό μπορεί να υλοποιηθεί με πολλαπλές detection engines (μία μπορεί να βασίζεται σε rules, μία σε machine learning και μία σε anomaly detection) και, στη συνέχεια, με ένα layer που συγκεντρώνει τα alerts τους -- ουσιαστικά μια μορφή ensemble -- ώστε να λαμβάνει τελική απόφαση με υψηλότερη confidence. Κατά την ανάπτυξη τέτοιων συστημάτων, πρέπει να λαμβάνεται υπόψη η πρόσθετη πολυπλοκότητα και να διασφαλίζεται ότι το ensemble δεν θα γίνει υπερβολικά δύσκολο στη διαχείριση ή την επεξήγηση. Ωστόσο, από άποψη accuracy, τα ensembles και το stacking είναι ισχυρά εργαλεία για τη βελτίωση της απόδοσης των models.

</details>

## Αναφορές

- [1] [AI and Machine Learning in Cybersecurity - zvelo](https://zvelo.com/ai-and-machine-learning-in-cybersecurity/)
- [2] [Linear Regression, Explained - Medium](https://medium.com/@chaandram/linear-regression-explained-28d5bf1934ae)
- [3] [Logistic Regression - Medium](https://madhuramiah.medium.com/logistic-regression-6e55553cc003)
- [4] [Sohail Ahmed Khan, Wasiq Khan, Abir Hussain - "Phishing Attacks and Websites Classification Using Machine Learning and Multiple Datasets (A Comparative Analysis)"](https://arxiv.org/pdf/2101.02552)
- [5] [Decision Tree - GeeksforGeeks](https://www.geeksforgeeks.org/decision-tree-introduction-example/)
- [6] [Reena Singh Rajput, Sanjay Agrawal - "Denial of Services Attack Detection using Random Forest Classifier with Information Gain"](https://rjwave.org/ijedr/viewpaperforall.php?paper=IJEDR1703132)
- [7] [Raisa Abedin Disha, Sajjad Waheed - "Performance analysis of machine learning models for intrusion detection system using Gini Impurity-based Weighted Random Forest (GIWRF) feature selection technique"](https://cybersecurity.springeropen.com/articles/10.1186/s42400-021-00103-8)
- [8] [What is a Support Vector Machine? - IBM](https://www.ibm.com/think/topics/support-vector-machine)
- [9] [Naive Bayes spam filtering - Wikipedia](https://en.m.wikipedia.org/wiki/Naive_Bayes_spam_filtering)
- [10] [What is k-Nearest Neighbors (KNN)? - IBM](https://www.ibm.com/think/topics/knn)
- [11] [GBDT Demystified: How LightGBM, XGBoost and CatBoost Work - Medium](https://medium.com/@rupalipatelkvc/gbdt-demystified-how-lightgbm-xgboost-and-catboost-work-9479b7262644)
- [12] [Ensemble Learning: Boosting Model Performance by Combining Strengths - Medium](https://medium.com/@sarahzouinina/ensemble-learning-boosting-model-performance-by-combining-strengths-02e56165b901)
- [13] [How Deep Learning Enhances Intrusion Detection Systems](https://cybersecurity-magazine.com/how-deep-learning-enhances-intrusion-detection-systems/)

{{#include ../banners/hacktricks-training.md}}
