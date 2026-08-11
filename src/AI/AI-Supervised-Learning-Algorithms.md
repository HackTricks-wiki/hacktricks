# Αλγόριθμοι Supervised Learning

{{#include ../banners/hacktricks-training.md}}

## Βασικές πληροφορίες

Το Supervised Learning χρησιμοποιεί δεδομένα με labels για την εκπαίδευση μοντέλων που μπορούν να κάνουν προβλέψεις σε νέα, μη εμφανισμένα inputs. Στην κυβερνοασφάλεια, το Supervised Machine Learning εφαρμόζεται ευρέως σε εργασίες όπως η ανίχνευση εισβολών (ταξινόμηση της κίνησης δικτύου ως *normal* ή *attack*), η ανίχνευση malware (διάκριση κακόβουλου λογισμικού από benign), η ανίχνευση phishing (εντοπισμός πλαστών websites ή emails) και το spam filtering, μεταξύ άλλων.<sup>[[1]](#references)</sup> Κάθε algorithm έχει τα δικά του πλεονεκτήματα και είναι κατάλληλος για διαφορετικούς τύπους προβλημάτων (classification ή regression). Παρακάτω εξετάζουμε βασικούς supervised learning algorithms, εξηγούμε πώς λειτουργούν και παρουσιάζουμε τη χρήση τους σε πραγματικά cybersecurity datasets. Εξετάζουμε επίσης πώς ο συνδυασμός μοντέλων (ensemble learning) μπορεί συχνά να βελτιώσει την predictive performance.

## Algorithms

-   **Linear Regression:** Ένας θεμελιώδης regression algorithm για την πρόβλεψη αριθμητικών αποτελεσμάτων μέσω προσαρμογής μιας γραμμικής εξίσωσης στα δεδομένα.

-   **Logistic Regression:** Ένας classification algorithm (παρά το όνομά του) που χρησιμοποιεί logistic function για τη μοντελοποίηση της πιθανότητας ενός binary αποτελέσματος.

-   **Decision Trees:** Μοντέλα με δενδροειδή δομή που χωρίζουν τα δεδομένα με βάση τα features για να κάνουν προβλέψεις· χρησιμοποιούνται συχνά λόγω της interpretability τους.

-   **Random Forests:** Ένα ensemble από decision trees (μέσω bagging) που βελτιώνει την accuracy και μειώνει το overfitting.

-   **Support Vector Machines (SVM):** Max-margin classifiers που βρίσκουν το βέλτιστο separating hyperplane· μπορούν να χρησιμοποιούν kernels για non-linear δεδομένα.

-   **Naive Bayes:** Ένας probabilistic classifier που βασίζεται στο θεώρημα του Bayes και στην υπόθεση ανεξαρτησίας των features, ο οποίος χρησιμοποιείται ευρέως στο spam filtering.

-   **k-Nearest Neighbors (k-NN):** Ένας απλός "instance-based" classifier που αντιστοιχίζει ένα sample στην class που πλειοψηφεί μεταξύ των κοντινότερων neighbors του.

-   **Gradient Boosting Machines:** Ensemble models (π.χ. XGBoost, LightGBM) που δημιουργούν έναν ισχυρό predictor προσθέτοντας διαδοχικά weaker learners (συνήθως decision trees).

Κάθε ενότητα παρακάτω παρέχει μια βελτιωμένη περιγραφή του algorithm και ένα **Python code example** χρησιμοποιώντας libraries όπως `pandas` και `scikit-learn` (και `PyTorch` στο παράδειγμα neural network). Τα παραδείγματα χρησιμοποιούν δημόσια διαθέσιμα cybersecurity datasets (όπως το NSL-KDD για intrusion detection και ένα Phishing Websites dataset) και ακολουθούν μια συνεπή δομή:

1.  **Φόρτωση του dataset** (download μέσω URL, εφόσον είναι διαθέσιμο).

2.  **Preprocess των δεδομένων** (π.χ. encode των categorical features, scale των values, διαχωρισμός σε train/test sets).

3.  **Εκπαίδευση του model** στα training data.

4.  **Evaluation** σε test set με χρήση metrics: accuracy, precision, recall, F1-score και ROC AUC για classification (και mean squared error για regression).

Ας εξετάσουμε κάθε algorithm:

### Linear Regression

Η Linear Regression είναι ένας **regression** algorithm που χρησιμοποιείται για την πρόβλεψη συνεχών αριθμητικών values. Υποθέτει μια γραμμική σχέση μεταξύ των input features (independent variables) και του output (dependent variable). Το model προσπαθεί να προσαρμόσει μια ευθεία γραμμή (ή hyperplane σε υψηλότερες διαστάσεις) που περιγράφει καλύτερα τη σχέση μεταξύ των features και του target. Αυτό γίνεται συνήθως μέσω ελαχιστοποίησης του αθροίσματος των squared errors μεταξύ των predicted και actual values (μέθοδος Ordinary Least Squares).<sup>[[2]](#references)</sup>

Ο απλούστερος τρόπος αναπαράστασης της linear regression είναι με μια γραμμή:
```plaintext
y = mx + b
```
Όπου:

- `y` είναι η προβλεπόμενη τιμή (output)
- `m` είναι η κλίση της γραμμής (coefficient)
- `x` είναι το input feature
- `b` είναι το y-intercept

Ο στόχος του linear regression είναι να βρει τη γραμμή που ταιριάζει καλύτερα και ελαχιστοποιεί τη διαφορά μεταξύ των προβλεπόμενων και των πραγματικών τιμών στο dataset. Φυσικά, αυτό είναι πολύ απλό: θα ήταν μια ευθεία γραμμή που διαχωρίζει 2 κατηγορίες, αλλά αν προστεθούν περισσότερες διαστάσεις, η γραμμή γίνεται πιο σύνθετη:
```plaintext
y = w1*x1 + w2*x2 + ... + wn*xn + b
```
> [!TIP]
> *Περιπτώσεις χρήσης στην κυβερνοασφάλεια:* Η γραμμική παλινδρόμηση από μόνη της είναι λιγότερο συνηθισμένη για βασικές εργασίες ασφάλειας (οι οποίες συχνά είναι classification), αλλά μπορεί να χρησιμοποιηθεί για την πρόβλεψη αριθμητικών αποτελεσμάτων. Για παράδειγμα, θα μπορούσε να χρησιμοποιηθεί για **την πρόβλεψη του όγκου της κίνησης δικτύου** ή **την εκτίμηση του αριθμού των επιθέσεων σε μια χρονική περίοδο**, με βάση ιστορικά δεδομένα. Θα μπορούσε επίσης να προβλέψει έναν βαθμό κινδύνου ή τον αναμενόμενο χρόνο μέχρι τον εντοπισμό μιας επίθεσης, δεδομένων συγκεκριμένων μετρικών του συστήματος. Στην πράξη, οι αλγόριθμοι classification (όπως η logistic regression ή τα δέντρα) χρησιμοποιούνται συχνότερα για τον εντοπισμό εισβολών ή malware, αλλά η γραμμική παλινδρόμηση αποτελεί θεμέλιο και είναι χρήσιμη για αναλύσεις που βασίζονται σε regression.

#### **Βασικά χαρακτηριστικά της γραμμικής παλινδρόμησης:**

-   **Τύπος προβλήματος:** Regression (πρόβλεψη συνεχών τιμών). Δεν είναι κατάλληλη για άμεσο classification, εκτός αν εφαρμοστεί ένα threshold στην έξοδο.

-   **Ερμηνευσιμότητα:** Υψηλή -- οι συντελεστές είναι εύκολο να ερμηνευτούν, δείχνοντας τη γραμμική επίδραση κάθε feature.

-   **Πλεονεκτήματα:** Απλή και γρήγορη· αποτελεί καλή baseline επιλογή για εργασίες regression· λειτουργεί καλά όταν η πραγματική σχέση είναι περίπου γραμμική.

-   **Περιορισμοί:** Δεν μπορεί να αποτυπώσει σύνθετες ή μη γραμμικές σχέσεις (χωρίς χειροκίνητο feature engineering)· είναι επιρρεπής σε underfitting όταν οι σχέσεις είναι μη γραμμικές· είναι ευαίσθητη σε outliers, οι οποίοι μπορούν να στρεβλώσουν τα αποτελέσματα.

-   **Εύρεση της καλύτερης προσαρμογής:** Για να βρούμε τη γραμμή βέλτιστης προσαρμογής που διαχωρίζει τις πιθανές κατηγορίες, χρησιμοποιούμε μια μέθοδο που ονομάζεται **Ordinary Least Squares (OLS)**. Αυτή η μέθοδος ελαχιστοποιεί το άθροισμα των τετραγώνων των διαφορών μεταξύ των παρατηρούμενων τιμών και των τιμών που προβλέπονται από το γραμμικό μοντέλο.

<details>
<summary>Παράδειγμα -- Πρόβλεψη διάρκειας σύνδεσης (Regression) σε Dataset εισβολών
</summary>
Παρακάτω παρουσιάζουμε τη γραμμική παλινδρόμηση χρησιμοποιώντας το dataset κυβερνοασφάλειας NSL-KDD. Θα το αντιμετωπίσουμε ως πρόβλημα regression, προβλέποντας το `duration` των συνδέσεων δικτύου με βάση άλλα features. (Στην πραγματικότητα, το `duration` είναι ένα feature του NSL-KDD· το χρησιμοποιούμε εδώ απλώς για να παρουσιάσουμε τη regression.) Φορτώνουμε το dataset, εκτελούμε preprocessing (κωδικοποιούμε τα categorical features), εκπαιδεύουμε ένα μοντέλο γραμμικής παλινδρόμησης και αξιολογούμε το Mean Squared Error (MSE) και το R² score σε ένα test set.
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
Σε αυτό το παράδειγμα, το μοντέλο linear regression προσπαθεί να προβλέψει το `duration` της σύνδεσης από άλλα χαρακτηριστικά του δικτύου. Μετράμε την απόδοση με τα Mean Squared Error (MSE) και R². Ένα R² κοντά στο 1.0 θα έδειχνε ότι το μοντέλο εξηγεί το μεγαλύτερο μέρος της διακύμανσης του `duration`, ενώ ένα χαμηλό ή αρνητικό R² υποδεικνύει κακή προσαρμογή. (Μην εκπλαγείτε αν το R² είναι χαμηλό εδώ -- η πρόβλεψη του `duration` μπορεί να είναι δύσκολη με βάση τα συγκεκριμένα χαρακτηριστικά και η linear regression ενδέχεται να μην αποτυπώνει τα μοτίβα, αν αυτά είναι σύνθετα.)
</details>

### Logistic Regression

Η logistic regression είναι ένας αλγόριθμος **ταξινόμησης** που μοντελοποιεί την πιθανότητα ένα στιγμιότυπο να ανήκει σε μια συγκεκριμένη κλάση (συνήθως την «θετική» κλάση). Παρά το όνομά της, η *logistic* regression χρησιμοποιείται για διακριτά αποτελέσματα (σε αντίθεση με τη linear regression, η οποία χρησιμοποιείται για συνεχή αποτελέσματα). Χρησιμοποιείται κυρίως για **binary classification** (δύο κλάσεις, π.χ. malicious έναντι benign), αλλά μπορεί να επεκταθεί σε προβλήματα πολλών κλάσεων (με χρήση προσεγγίσεων softmax ή one-vs-rest).<sup>[[3]](#references)</sup>

Η logistic regression χρησιμοποιεί τη logistic function (γνωστή και ως sigmoid function) για να αντιστοιχίσει τις προβλεπόμενες τιμές σε πιθανότητες. Σημειώστε ότι η sigmoid function είναι μια συνάρτηση με τιμές μεταξύ 0 και 1, η οποία αυξάνεται σε καμπύλη σχήματος S ανάλογα με τις ανάγκες της ταξινόμησης, κάτι που είναι χρήσιμο για εργασίες binary classification. Επομένως, κάθε feature κάθε εισόδου πολλαπλασιάζεται με το αντίστοιχο weight, και το αποτέλεσμα περνά από τη sigmoid function για να παραχθεί μια πιθανότητα:
```plaintext
p(y=1|x) = 1 / (1 + e^(-z))
```
Όπου:

- `p(y=1|x)` είναι η πιθανότητα η έξοδος `y` να είναι 1 δεδομένης της εισόδου `x`
- `e` είναι η βάση του φυσικού λογαρίθμου
- `z` είναι ένας γραμμικός συνδυασμός των χαρακτηριστικών εισόδου, που συνήθως αναπαρίσταται ως `z = w1*x1 + w2*x2 + ... + wn*xn + b`. Παρατηρήστε ότι και πάλι, στην απλούστερη μορφή του, είναι μια ευθεία γραμμή, αλλά σε πιο σύνθετες περιπτώσεις γίνεται ένα υπερεπίπεδο με πολλές διαστάσεις (μία ανά χαρακτηριστικό).

> [!TIP]
> *Περιπτώσεις χρήσης στην κυβερνοασφάλεια:* Επειδή πολλά security προβλήματα είναι ουσιαστικά αποφάσεις ναι/όχι, το Logistic Regression χρησιμοποιείται ευρέως. Για παράδειγμα, ένα σύστημα intrusion detection μπορεί να χρησιμοποιήσει Logistic Regression για να αποφασίσει αν μια network connection είναι attack, με βάση τα χαρακτηριστικά αυτής της connection. Στο phishing detection, το Logistic Regression μπορεί να συνδυάσει χαρακτηριστικά ενός website (μήκος URL, παρουσία του συμβόλου "@", κ.λπ.) σε μια πιθανότητα το website να είναι phishing. Έχει χρησιμοποιηθεί σε early-generation spam filters και παραμένει ένα ισχυρό baseline για πολλές classification tasks.

#### Logistic Regression για non-binary classification

Το Logistic Regression έχει σχεδιαστεί για binary classification, αλλά μπορεί να επεκταθεί ώστε να χειρίζεται multi-class προβλήματα, χρησιμοποιώντας τεχνικές όπως **one-vs-rest** (OvR) ή **softmax regression**. Στο OvR, εκπαιδεύεται ένα ξεχωριστό μοντέλο Logistic Regression για κάθε class, αντιμετωπίζοντάς την ως positive class έναντι όλων των άλλων. Η class με την υψηλότερη predicted probability επιλέγεται ως τελική πρόβλεψη. Το Softmax regression γενικεύει το Logistic Regression σε πολλαπλές classes, εφαρμόζοντας τη συνάρτηση softmax στο output layer και παράγοντας μια probability distribution για όλες τις classes.

#### **Βασικά χαρακτηριστικά του Logistic Regression:**

-   **Τύπος προβλήματος:** Classification (συνήθως binary). Προβλέπει την probability της positive class.

-   **Ερμηνευσιμότητα:** Υψηλή -- όπως και στο linear regression, οι coefficients των χαρακτηριστικών μπορούν να υποδείξουν πώς κάθε χαρακτηριστικό επηρεάζει τα log-odds του αποτελέσματος. Αυτή η διαφάνεια εκτιμάται συχνά στη security, για την κατανόηση των παραγόντων που συμβάλλουν σε ένα alert.

-   **Πλεονεκτήματα:** Απλό και γρήγορο στην εκπαίδευση· λειτουργεί καλά όταν η σχέση μεταξύ των χαρακτηριστικών και των log-odds του αποτελέσματος είναι γραμμική. Παράγει probabilities, επιτρέποντας risk scoring. Με την κατάλληλη regularization, γενικεύεται καλά και μπορεί να χειριστεί την multicollinearity καλύτερα από το απλό linear regression.

-   **Περιορισμοί:** Υποθέτει ένα γραμμικό decision boundary στον χώρο των χαρακτηριστικών (αποτυγχάνει όταν το πραγματικό boundary είναι σύνθετο/μη γραμμικό). Μπορεί να έχει χαμηλότερη απόδοση σε προβλήματα όπου οι αλληλεπιδράσεις ή οι μη γραμμικές επιδράσεις είναι κρίσιμες, εκτός αν προσθέσετε χειροκίνητα polynomial ή interaction features. Επίσης, το Logistic Regression είναι λιγότερο αποτελεσματικό όταν οι classes δεν μπορούν να διαχωριστούν εύκολα μέσω ενός γραμμικού συνδυασμού χαρακτηριστικών.


<details>
<summary>Παράδειγμα -- Phishing Website Detection με Logistic Regression:</summary>

Θα χρησιμοποιήσουμε ένα **Phishing Websites Dataset** (από το UCI repository), το οποίο περιέχει extracted features websites (όπως αν το URL έχει IP address, την ηλικία του domain, την παρουσία ύποπτων στοιχείων στο HTML κ.λπ.) και ένα label που υποδεικνύει αν το site είναι phishing ή legitimate.<sup>[[4]](#references)</sup> Εκπαιδεύουμε ένα μοντέλο Logistic Regression για την ταξινόμηση websites και στη συνέχεια αξιολογούμε την accuracy, το precision, το recall, το F1-score και το ROC AUC σε ένα test split.
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
Σε αυτό το παράδειγμα ανίχνευσης phishing, η logistic regression παράγει μια πιθανότητα για κάθε website να είναι phishing. Αξιολογώντας τα accuracy, precision, recall και F1, αποκτούμε μια εικόνα για την απόδοση του μοντέλου. Για παράδειγμα, υψηλό recall σημαίνει ότι εντοπίζει τα περισσότερα phishing sites (σημαντικό για την ασφάλεια, ώστε να ελαχιστοποιούνται οι επιθέσεις που δεν εντοπίζονται), ενώ υψηλό precision σημαίνει ότι έχει λίγους false alarms (σημαντικό για την αποφυγή κόπωσης των analysts). Το ROC AUC (Area Under the ROC Curve) παρέχει ένα μέτρο απόδοσης ανεξάρτητο από το threshold (το 1.0 είναι ιδανικό, ενώ το 0.5 δεν είναι καλύτερο από την τυχαιότητα). Η logistic regression συχνά αποδίδει καλά σε τέτοιες εργασίες, αλλά αν το decision boundary μεταξύ phishing και legitimate sites είναι σύνθετο, μπορεί να χρειάζονται ισχυρότερα μη γραμμικά μοντέλα.

</details>

### Δέντρα Απόφασης

Ένα decision tree είναι ένας ευέλικτος **αλγόριθμος επιβλεπόμενης μάθησης** που μπορεί να χρησιμοποιηθεί τόσο για εργασίες classification όσο και regression. Μαθαίνει ένα ιεραρχικό μοντέλο αποφάσεων σε μορφή δέντρου, βασισμένο στα features των δεδομένων. Κάθε internal node του δέντρου αντιπροσωπεύει έναν έλεγχο σε ένα συγκεκριμένο feature, κάθε branch αντιπροσωπεύει ένα αποτέλεσμα αυτού του ελέγχου και κάθε leaf node αντιπροσωπεύει μια προβλεπόμενη κλάση (για classification) ή τιμή (για regression).<sup>[[5]](#references)</sup>

Για την κατασκευή ενός δέντρου, algorithms όπως το CART (Classification and Regression Tree) χρησιμοποιούν μέτρα όπως το **Gini impurity** ή το **information gain (entropy)** για να επιλέξουν το καλύτερο feature και threshold με τα οποία θα χωρίσουν τα δεδομένα σε κάθε βήμα. Ο στόχος σε κάθε split είναι η κατάτμηση των δεδομένων, ώστε να αυξηθεί η ομοιογένεια της target variable στα resulting subsets (για classification, κάθε node επιδιώκεται να είναι όσο το δυνατόν πιο pure, περιέχοντας κυρίως μία μόνο κλάση).

Τα decision trees είναι **ιδιαίτερα εύκολα στην ερμηνεία** -- μπορεί κανείς να ακολουθήσει τη διαδρομή από το root έως το leaf, ώστε να κατανοήσει τη λογική πίσω από μια πρόβλεψη (π.χ., *"IF `service = telnet` AND `src_bytes > 1000` AND `failed_logins > 3` THEN classify as attack"*). Αυτό είναι πολύτιμο στην κυβερνοασφάλεια για την εξήγηση του λόγου για τον οποίο δημιουργήθηκε ένα συγκεκριμένο alert. Τα trees μπορούν να χειριστούν φυσικά τόσο numerical όσο και categorical data και απαιτούν ελάχιστο preprocessing (π.χ. δεν χρειάζεται feature scaling).

Ωστόσο, ένα μεμονωμένο decision tree μπορεί εύκολα να κάνει overfit στα training data, ειδικά αν αναπτυχθεί σε μεγάλο βάθος (πολλά splits). Τεχνικές όπως το pruning (περιορισμός του tree depth ή απαίτηση ελάχιστου αριθμού samples ανά leaf) χρησιμοποιούνται συχνά για την αποτροπή του overfitting.

Υπάρχουν 3 κύρια components ενός decision tree:
- **Root Node**: Ο ανώτατος node του tree, που αντιπροσωπεύει ολόκληρο το dataset.
- **Internal Nodes**: Nodes που αντιπροσωπεύουν features και αποφάσεις βασισμένες σε αυτά τα features.
- **Leaf Nodes**: Nodes που αντιπροσωπεύουν το τελικό αποτέλεσμα ή την πρόβλεψη.

Ένα tree μπορεί τελικά να μοιάζει κάπως έτσι:
```plaintext
[Root Node]
/   \
[Node A]  [Node B]
/   \      /   \
[Leaf 1] [Leaf 2] [Leaf 3] [Leaf 4]
```
> [!TIP]
> *Περιπτώσεις χρήσης στην cybersecurity:* Τα Decision Trees έχουν χρησιμοποιηθεί σε intrusion detection systems για την εξαγωγή **κανόνων** που αναγνωρίζουν επιθέσεις. Για παράδειγμα, πρώιμα IDS που βασίζονταν στα ID3/C4.5 δημιουργούσαν κανόνες αναγνώσιμους από ανθρώπους, για να διακρίνουν τη φυσιολογική από την κακόβουλη κίνηση. Χρησιμοποιούνται επίσης στην ανάλυση malware, για να αποφασιστεί αν ένα αρχείο είναι κακόβουλο με βάση τα χαρακτηριστικά του (μέγεθος αρχείου, entropy τμημάτων, κλήσεις API κ.λπ.). Η σαφήνεια των Decision Trees τα καθιστά χρήσιμα όταν απαιτείται διαφάνεια -- ένας analyst μπορεί να εξετάσει το tree για να επικυρώσει τη λογική ανίχνευσης.

#### **Βασικά χαρακτηριστικά των Decision Trees:**

-   **Τύπος προβλήματος:** Τόσο classification όσο και regression. Χρησιμοποιούνται συχνά για classification επιθέσεων έναντι φυσιολογικής κίνησης κ.λπ.

-   **Ερμηνευσιμότητα:** Πολύ υψηλή -- οι αποφάσεις του model μπορούν να οπτικοποιηθούν και να γίνουν κατανοητές ως ένα σύνολο κανόνων if-then. Αυτό αποτελεί σημαντικό πλεονέκτημα στην ασφάλεια, για την εμπιστοσύνη και την επαλήθευση της συμπεριφοράς του model.

-   **Πλεονεκτήματα:** Μπορούν να αποτυπώσουν μη γραμμικές σχέσεις και αλληλεπιδράσεις μεταξύ features (κάθε διαχωρισμός μπορεί να θεωρηθεί αλληλεπίδραση). Δεν χρειάζεται scaling των features ή one-hot encoding των categorical variables -- τα trees τα διαχειρίζονται εγγενώς. Γρήγορο inference (η πρόβλεψη είναι απλώς η παρακολούθηση μιας διαδρομής στο tree).

-   **Περιορισμοί:** Είναι επιρρεπή σε overfitting αν δεν ελεγχθούν (ένα βαθύ tree μπορεί να απομνημονεύσει το training set). Μπορεί να είναι ασταθή -- μικρές αλλαγές στα δεδομένα ενδέχεται να οδηγήσουν σε διαφορετική δομή tree. Ως μεμονωμένα models, η ακρίβειά τους μπορεί να μην ανταγωνίζεται πιο προηγμένες μεθόδους (ensembles όπως τα Random Forests συνήθως αποδίδουν καλύτερα, μειώνοντας το variance).

-   **Εύρεση του καλύτερου split:**
- **Gini Impurity**: Μετρά την impurity ενός node. Μικρότερη Gini impurity υποδεικνύει καλύτερο split. Ο τύπος είναι:

```plaintext
Gini = 1 - Σ(p_i^2)
```

Όπου το `p_i` είναι η αναλογία των instances της κλάσης `i`.

- **Entropy**: Μετρά την αβεβαιότητα στο dataset. Μικρότερη entropy υποδεικνύει καλύτερο split. Ο τύπος είναι:

```plaintext
Entropy = -Σ(p_i * log2(p_i))
```

Όπου το `p_i` είναι η αναλογία των instances της κλάσης `i`.

- **Information Gain**: Η μείωση της entropy ή της Gini impurity μετά από ένα split. Όσο μεγαλύτερο είναι το information gain, τόσο καλύτερο είναι το split. Υπολογίζεται ως εξής:

```plaintext
Information Gain = Entropy(parent) - (Weighted Average of Entropy(children))
```

Επιπλέον, ένα tree τερματίζεται όταν:
- Όλα τα instances ενός node ανήκουν στην ίδια κλάση. Αυτό μπορεί να οδηγήσει σε overfitting.
- Επιτευχθεί το μέγιστο βάθος (hardcoded) του tree. Αυτό αποτελεί τρόπο αποτροπής του overfitting.
- Ο αριθμός των instances σε ένα node είναι μικρότερος από ένα συγκεκριμένο όριο. Αυτό αποτελεί επίσης τρόπο αποτροπής του overfitting.
- Το information gain από περαιτέρω splits είναι μικρότερο από ένα συγκεκριμένο όριο. Αυτό αποτελεί επίσης τρόπο αποτροπής του overfitting.

<details>
<summary>Παράδειγμα -- Decision Tree για Intrusion Detection:</summary>
Θα εκπαιδεύσουμε ένα decision tree στο dataset NSL-KDD, για να ταξινομήσουμε τις network connections είτε ως *normal* είτε ως *attack*. Το NSL-KDD είναι μια βελτιωμένη έκδοση του κλασικού dataset KDD Cup 1999, με features όπως protocol type, service, duration, number of failed logins κ.λπ., και μια label που υποδεικνύει τον τύπο της επίθεσης ή την ένδειξη "normal". Θα αντιστοιχίσουμε όλους τους τύπους επιθέσεων στην κλάση "anomaly" (binary classification: normal έναντι anomaly). Μετά την εκπαίδευση, θα αξιολογήσουμε την απόδοση του tree στο test set.
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
Σε αυτό το παράδειγμα decision tree, περιορίσαμε το βάθος του δέντρου στο 10 για να αποφύγουμε το ακραίο overfitting (η παράμετρος `max_depth=10`). Τα metrics δείχνουν πόσο καλά το δέντρο διακρίνει την κανονική από την attack traffic. Ένα υψηλό recall σημαίνει ότι εντοπίζει τις περισσότερες attacks (κάτι σημαντικό για ένα IDS), ενώ το υψηλό precision σημαίνει λίγους false alarms. Τα decision trees συχνά επιτυγχάνουν ικανοποιητική accuracy σε structured data, όμως ένα μεμονωμένο δέντρο μπορεί να μην πετύχει την καλύτερη δυνατή performance. Παρ' όλα αυτά, η *interpretability* του model είναι ένα σημαντικό πλεονέκτημα -- θα μπορούσαμε να εξετάσουμε τα splits του δέντρου για να δούμε, για παράδειγμα, ποια features (π.χ. `service`, `src_bytes` κ.λπ.) επηρεάζουν περισσότερο την επισήμανση μιας σύνδεσης ως malicious.

</details>

### Random Forests

Το Random Forest είναι μια μέθοδος **ensemble learning** που βασίζεται στα decision trees για τη βελτίωση της performance. Ένα random forest εκπαιδεύει πολλά decision trees (εξ ου και το "forest") και συνδυάζει τα outputs τους για να δημιουργήσει μια τελική πρόβλεψη (για classification, συνήθως μέσω majority vote). Οι δύο βασικές ιδέες σε ένα random forest είναι το **bagging** (bootstrap aggregating) και η **feature randomness**:

-   **Bagging:** Κάθε tree εκπαιδεύεται σε ένα τυχαίο bootstrap sample των training data (δειγματοληψία με replacement). Αυτό εισάγει diversity μεταξύ των trees.

-   **Feature Randomness:** Σε κάθε split ενός tree, εξετάζεται ένα τυχαίο subset των features για το splitting (αντί για όλα τα features). Αυτό μειώνει περαιτέρω τη συσχέτιση μεταξύ των trees.

Με τον υπολογισμό του average των αποτελεσμάτων πολλών trees, το random forest μειώνει το variance που μπορεί να έχει ένα μεμονωμένο decision tree. Με απλά λόγια, μεμονωμένα trees μπορεί να κάνουν overfit ή να είναι noisy, όμως ένας μεγάλος αριθμός διαφορετικών trees που ψηφίζουν μαζί εξομαλύνει αυτά τα errors. Το αποτέλεσμα είναι συχνά ένα model με **υψηλότερη accuracy** και καλύτερο generalization από ένα μεμονωμένο decision tree. Επιπλέον, τα random forests μπορούν να παρέχουν μια εκτίμηση του feature importance (εξετάζοντας κατά πόσο κάθε feature split μειώνει κατά μέσο όρο το impurity).

Τα random forests έχουν γίνει ένα **workhorse στην cybersecurity** για tasks όπως intrusion detection, malware classification και spam detection. Συχνά έχουν καλή performance out-of-the-box με ελάχιστο tuning και μπορούν να διαχειριστούν μεγάλα feature sets. Για παράδειγμα, στο intrusion detection, ένα random forest μπορεί να ξεπεράσει ένα μεμονωμένο decision tree, εντοπίζοντας πιο subtle patterns των attacks με λιγότερα false positives. Έρευνες έχουν δείξει ότι τα random forests έχουν ευνοϊκή performance σε σύγκριση με άλλους algorithms στην ταξινόμηση attacks σε datasets όπως τα NSL-KDD και UNSW-NB15.<sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

#### **Βασικά χαρακτηριστικά των Random Forests:**

-   **Τύπος προβλήματος:** Κυρίως classification (χρησιμοποιείται επίσης για regression). Είναι ιδιαίτερα κατάλληλο για high-dimensional structured data, όπως αυτά που συναντώνται συνήθως στα security logs.

-   **Interpretability:** Μικρότερη από αυτήν ενός μεμονωμένου decision tree -- δεν μπορείτε εύκολα να visualise ή να εξηγήσετε εκατοντάδες trees ταυτόχρονα. Ωστόσο, τα feature importance scores παρέχουν κάποια εικόνα για το ποια attributes επηρεάζουν περισσότερο.

-   **Πλεονεκτήματα:** Γενικά υψηλότερη accuracy από τα single-tree models χάρη στο ensemble effect. Είναι robust απέναντι στο overfitting -- ακόμη και αν μεμονωμένα trees κάνουν overfit, το ensemble γενικεύει καλύτερα. Διαχειρίζεται numerical και categorical features και μπορεί, σε κάποιο βαθμό, να διαχειριστεί missing data. Είναι επίσης σχετικά robust απέναντι σε outliers.

-   **Περιορισμοί:** Το μέγεθος του model μπορεί να είναι μεγάλο (πολλά trees, καθένα από τα οποία μπορεί να είναι deep). Οι predictions είναι πιο αργές από αυτές ενός single tree (καθώς πρέπει να γίνει aggregation σε πολλά trees). Έχει μικρότερη interpretability -- ενώ γνωρίζετε τα σημαντικά features, η ακριβής λογική δεν είναι εύκολο να trace-αριστεί όπως ένας απλός κανόνας. Αν το dataset είναι εξαιρετικά high-dimensional και sparse, η εκπαίδευση ενός πολύ μεγάλου forest μπορεί να απαιτεί σημαντικούς computational resources.

-   **Διαδικασία εκπαίδευσης:**
1. **Bootstrap Sampling**: Κάντε τυχαία δειγματοληψία των training data με replacement για να δημιουργήσετε πολλά subsets (bootstrap samples).
2. **Tree Construction**: Για κάθε bootstrap sample, δημιουργήστε ένα decision tree χρησιμοποιώντας ένα τυχαίο subset των features σε κάθε split. Αυτό εισάγει diversity μεταξύ των trees.
3. **Aggregation**: Για classification tasks, η τελική prediction προκύπτει από majority vote μεταξύ των predictions όλων των trees. Για regression tasks, η τελική prediction είναι ο average των predictions όλων των trees.

<details>
<summary>Παράδειγμα -- Random Forest για Intrusion Detection (NSL-KDD):</summary>
Θα χρησιμοποιήσουμε το ίδιο NSL-KDD dataset (με binary labels ως normal ή anomaly) και θα εκπαιδεύσουμε έναν Random Forest classifier. Περιμένουμε το random forest να έχει performance ίση ή καλύτερη από το μεμονωμένο decision tree, χάρη στο ensemble averaging που μειώνει το variance. Θα το αξιολογήσουμε με τα ίδια metrics.
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
Το random forest συνήθως επιτυγχάνει ισχυρά αποτελέσματα σε αυτή την εργασία intrusion detection. Ενδέχεται να παρατηρήσουμε βελτίωση σε metrics όπως το F1 ή το AUC σε σύγκριση με το single decision tree, ειδικά στο recall ή το precision, ανάλογα με τα δεδομένα. Αυτό συμφωνεί με την άποψη ότι *"Random Forest (RF) is an ensemble classifier and performs well compared to other traditional classifiers for effective classification of attacks."*.<sup>[[6]](#references)</sup> Σε ένα πλαίσιο security operations, ένα μοντέλο random forest μπορεί να εντοπίζει επιθέσεις με μεγαλύτερη αξιοπιστία, μειώνοντας παράλληλα τα false alarms, χάρη στον μέσο όρο πολλών decision rules. Η feature importance από το forest μπορεί να μας δείξει ποια network features είναι πιο ενδεικτικά επιθέσεων (π.χ. συγκεκριμένα network services ή ασυνήθιστες μετρήσεις πακέτων).

</details>

### Support Vector Machines (SVM)

Τα Support Vector Machines είναι ισχυρά supervised learning models που χρησιμοποιούνται κυρίως για classification (και επίσης για regression ως SVR). Ένα SVM προσπαθεί να βρει το **optimal separating hyperplane** που μεγιστοποιεί το margin μεταξύ δύο classes. Μόνο ένα υποσύνολο των training points (τα "support vectors" που βρίσκονται πιο κοντά στο boundary) καθορίζει τη θέση αυτού του hyperplane. Μεγιστοποιώντας το margin (την απόσταση μεταξύ των support vectors και του hyperplane), τα SVM τείνουν να επιτυγχάνουν καλή generalization.<sup>[[8]](#references)</sup>

Κλειδί για την ισχύ των SVM είναι η δυνατότητα χρήσης **kernel functions** για τη διαχείριση μη γραμμικών σχέσεων. Τα δεδομένα μπορούν να μετασχηματιστούν έμμεσα σε έναν feature space υψηλότερης διάστασης, όπου μπορεί να υπάρχει ένας linear separator. Τα συνηθισμένα kernels περιλαμβάνουν τα polynomial, radial basis function (RBF) και sigmoid. Για παράδειγμα, αν οι classes του network traffic δεν είναι linearly separable στον αρχικό feature space, ένα RBF kernel μπορεί να τις αντιστοιχίσει σε υψηλότερη διάσταση, όπου το SVM βρίσκει ένα linear split (το οποίο αντιστοιχεί σε non-linear boundary στον αρχικό χώρο). Η ευελιξία επιλογής kernels επιτρέπει στα SVM να αντιμετωπίζουν ποικίλα προβλήματα.

Τα SVM είναι γνωστά για την καλή απόδοσή τους σε περιπτώσεις με high-dimensional feature spaces (όπως text data ή malware opcode sequences) και σε περιπτώσεις όπου ο αριθμός των features είναι μεγάλος σε σχέση με τον αριθμό των samples. Ήταν δημοφιλή σε πολλές πρώιμες εφαρμογές cybersecurity, όπως malware classification και anomaly-based intrusion detection, κατά τη δεκαετία του 2000, παρουσιάζοντας συχνά υψηλό accuracy.

Ωστόσο, τα SVM δεν κλιμακώνονται εύκολα σε πολύ μεγάλα datasets (η πολυπλοκότητα του training είναι super-linear ως προς τον αριθμό των samples και η χρήση μνήμης μπορεί να είναι υψηλή, καθώς ενδέχεται να χρειάζεται να αποθηκεύσουν πολλά support vectors). Στην πράξη, για εργασίες όπως network intrusion detection με εκατομμύρια records, ένα SVM μπορεί να είναι πολύ αργό χωρίς προσεκτικό subsampling ή χρήση approximate methods.

#### **Βασικά χαρακτηριστικά του SVM:**

-   **Τύπος προβλήματος:** Classification (binary ή multiclass μέσω one-vs-one/one-vs-rest) και regression variants. Χρησιμοποιείται συχνά σε binary classification με σαφή margin separation.

-   **Interpretability:** Μέτρια -- τα SVM δεν είναι τόσο interpretable όσο τα decision trees ή το logistic regression. Παρότι μπορείτε να αναγνωρίσετε ποια data points είναι support vectors και να αποκτήσετε κάποια εικόνα για το ποια features μπορεί να επηρεάζουν (μέσω των weights στην περίπτωση του linear kernel), στην πράξη τα SVM (ιδίως με non-linear kernels) αντιμετωπίζονται ως black-box classifiers.

-   **Πλεονεκτήματα:** Αποτελεσματικά σε high-dimensional spaces· μπορούν να μοντελοποιούν complex decision boundaries με το kernel trick· ανθεκτικά στο overfitting όταν μεγιστοποιείται το margin (ιδίως με κατάλληλη παράμετρο regularization C)· λειτουργούν καλά ακόμη και όταν οι classes δεν διαχωρίζονται με μεγάλη απόσταση (βρίσκουν το καλύτερο compromise boundary).

-   **Περιορισμοί:** **Computationally intensive** για μεγάλα datasets (τόσο το training όσο και το prediction κλιμακώνονται ανεπαρκώς καθώς αυξάνονται τα δεδομένα). Απαιτούν προσεκτικό tuning των kernel και regularization parameters (C, kernel type, gamma για RBF κ.λπ.). Δεν παρέχουν άμεσα probabilistic outputs (αν και μπορείτε να χρησιμοποιήσετε Platt scaling για να λάβετε probabilities). Επίσης, τα SVM μπορεί να είναι ευαίσθητα στην επιλογή των kernel parameters --- μια κακή επιλογή μπορεί να οδηγήσει σε underfit ή overfit.

*Use cases στο cybersecurity:* Τα SVM έχουν χρησιμοποιηθεί σε **malware detection** (π.χ. για την ταξινόμηση αρχείων βάσει extracted features ή opcode sequences), **network anomaly detection** (ταξινόμηση traffic ως normal ή malicious) και **phishing detection** (με χρήση features των URLs). Για παράδειγμα, ένα SVM θα μπορούσε να λάβει features ενός email (μετρήσεις συγκεκριμένων keywords, sender reputation scores κ.λπ.) και να το ταξινομήσει ως phishing ή legitimate. Έχουν επίσης εφαρμοστεί σε **intrusion detection** σε feature sets όπως το KDD, επιτυγχάνοντας συχνά υψηλό accuracy με κόστος σε computation.

<details>
<summary>Παράδειγμα -- SVM για Malware Classification:</summary>
Θα χρησιμοποιήσουμε ξανά το phishing website dataset, αυτή τη φορά με ένα SVM. Επειδή τα SVM μπορεί να είναι αργά, θα χρησιμοποιήσουμε ένα subset των δεδομένων για training αν χρειαστεί (το dataset περιλαμβάνει περίπου 11k instances, τα οποία ένα SVM μπορεί να διαχειριστεί σχετικά εύκολα). Θα χρησιμοποιήσουμε ένα RBF kernel, το οποίο αποτελεί συνηθισμένη επιλογή για non-linear data, και θα ενεργοποιήσουμε τα probability estimates για τον υπολογισμό του ROC AUC.
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
Το μοντέλο SVM θα εξάγει metrics που μπορούμε να συγκρίνουμε με τη λογιστική παλινδρόμηση στην ίδια εργασία. Μπορεί να διαπιστώσουμε ότι το SVM επιτυγχάνει υψηλό accuracy και AUC, αν τα δεδομένα διαχωρίζονται καλά από τα features. Από την άλλη πλευρά, αν το dataset περιείχε πολύ θόρυβο ή επικαλυπτόμενες κλάσεις, το SVM μπορεί να μην υπερέχει σημαντικά της λογιστικής παλινδρόμησης. Στην πράξη, τα SVM μπορούν να προσφέρουν βελτίωση όταν υπάρχουν σύνθετες, μη γραμμικές σχέσεις μεταξύ των features και της κλάσης -- ο RBF kernel μπορεί να αποτυπώσει καμπύλα όρια απόφασης που θα έχανε η λογιστική παλινδρόμηση. Όπως συμβαίνει με όλα τα μοντέλα, απαιτείται προσεκτικό tuning των παραμέτρων `C` (regularization) και των παραμέτρων του kernel (όπως το `gamma` για τον RBF), ώστε να επιτευχθεί ισορροπία μεταξύ bias και variance.

</details>

#### Διαφορές μεταξύ Λογιστικής Παλινδρόμησης και SVM

| Aspect | **Λογιστική Παλινδρόμηση** | **Support Vector Machines** |
|---|---|---|
| **Objective function** | Ελαχιστοποιεί το **log‑loss** (cross‑entropy). | Μεγιστοποιεί το **margin**, ενώ ελαχιστοποιεί το **hinge‑loss**. |
| **Decision boundary** | Βρίσκει το **best‑fit hyperplane** που μοντελοποιεί το _P(y\|x)_. | Βρίσκει το **maximum‑margin hyperplane** (το μεγαλύτερο κενό από τα κοντινότερα σημεία). |
| **Output** | **Πιθανοτικό** – παρέχει calibrated class probabilities μέσω του σ(w·x + b). | **Ντετερμινιστικό** – επιστρέφει class labels· οι probabilities απαιτούν επιπλέον επεξεργασία (π.χ. Platt scaling). |
| **Regularisation** | L2 (default) ή L1, εξισορροπεί άμεσα το under/over‑fitting. | Η παράμετρος C αντισταθμίζει το πλάτος του margin έναντι των mis‑classifications· οι παράμετροι του kernel προσθέτουν πολυπλοκότητα. |
| **Kernels / Non‑linear** | Η native μορφή είναι **linear**· η μη γραμμικότητα προστίθεται μέσω feature engineering. | Το ενσωματωμένο **kernel trick** (RBF, poly κ.λπ.) του επιτρέπει να μοντελοποιεί σύνθετα όρια σε high‑dim. χώρο. |
| **Scalability** | Επιλύει convex optimisation σε **O(nd)**· διαχειρίζεται καλά πολύ μεγάλα n. | Το training μπορεί να απαιτεί **O(n²–n³)** σε memory/time χωρίς specialised solvers· είναι λιγότερο κατάλληλο για τεράστια n. |
| **Interpretability** | **Υψηλή** – τα weights δείχνουν την επιρροή των features· το odds ratio είναι διαισθητικό. | **Χαμηλή** για non‑linear kernels· τα support vectors είναι sparse, αλλά δεν εξηγούνται εύκολα. |
| **Sensitivity to outliers** | Χρησιμοποιεί smooth log‑loss → είναι λιγότερο ευαίσθητη. | Το hinge‑loss με hard margin μπορεί να είναι **ευαίσθητο**· το soft‑margin (C) το μετριάζει. |
| **Typical use cases** | Credit scoring, medical risk, A/B testing – όπου έχουν σημασία οι **probabilities και η explainability**. | Image/text classification, bio‑informatics – όπου έχουν σημασία τα **σύνθετα όρια** και τα **high‑dimensional data**. |

* **Αν χρειάζεστε calibrated probabilities, interpretability ή λειτουργείτε σε τεράστια datasets — επιλέξτε Logistic Regression.**
* **Αν χρειάζεστε ένα ευέλικτο μοντέλο που μπορεί να αποτυπώσει μη γραμμικές σχέσεις χωρίς manual feature engineering — επιλέξτε SVM (με kernels).**
* Και τα δύο βελτιστοποιούν convex objectives, επομένως τα **global minima είναι εγγυημένα**, αλλά τα kernels του SVM προσθέτουν hyper‑parameters και computational cost.

### Naive Bayes

Το Naive Bayes είναι μια οικογένεια **probabilistic classifiers** που βασίζεται στην εφαρμογή του Bayes' Theorem, με μια ισχυρή υπόθεση ανεξαρτησίας μεταξύ των features. Παρά αυτή την "naive" υπόθεση, το Naive Bayes συχνά λειτουργεί εκπληκτικά καλά σε ορισμένες εφαρμογές, ειδικά σε εφαρμογές που περιλαμβάνουν text ή categorical data, όπως το spam detection.<sup>[[9]](#references)</sup>


#### Bayes' Theorem

Το Bayes' theorem αποτελεί τη βάση των Naive Bayes classifiers. Συνδέει τις conditional και marginal probabilities τυχαίων γεγονότων. Ο τύπος είναι:
```plaintext
P(A|B) = (P(B|A) * P(A)) / P(B)
```
Όπου:
- `P(A|B)` είναι η εκ των υστέρων πιθανότητα της κλάσης `A` δεδομένου του χαρακτηριστικού `B`.
- `P(B|A)` είναι η πιθανοφάνεια του χαρακτηριστικού `B` δεδομένης της κλάσης `A`.
- `P(A)` είναι η εκ των προτέρων πιθανότητα της κλάσης `A`.
- `P(B)` είναι η εκ των προτέρων πιθανότητα του χαρακτηριστικού `B`.

Για παράδειγμα, αν θέλουμε να ταξινομήσουμε αν ένα κείμενο έχει γραφτεί από παιδί ή ενήλικα, μπορούμε να χρησιμοποιήσουμε τις λέξεις του κειμένου ως χαρακτηριστικά. Με βάση κάποια αρχικά δεδομένα, ο Naive Bayes classifier θα υπολογίσει εκ των προτέρων τις πιθανότητες κάθε λέξης να ανήκει σε κάθε πιθανή κλάση (παιδί ή ενήλικας). Όταν δοθεί ένα νέο κείμενο, θα υπολογίσει την πιθανότητα κάθε πιθανής κλάσης δεδομένων των λέξεων του κειμένου και θα επιλέξει την κλάση με τη μεγαλύτερη πιθανότητα.

Όπως μπορείτε να δείτε σε αυτό το παράδειγμα, ο Naive Bayes classifier είναι πολύ απλός και γρήγορος, αλλά υποθέτει ότι τα χαρακτηριστικά είναι ανεξάρτητα, κάτι που δεν ισχύει πάντα σε δεδομένα του πραγματικού κόσμου.


#### Τύποι Naive Bayes Classifiers

Υπάρχουν διάφοροι τύποι Naive Bayes classifiers, ανάλογα με τον τύπο των δεδομένων και την κατανομή των χαρακτηριστικών:
- **Gaussian Naive Bayes**: Υποθέτει ότι τα χαρακτηριστικά ακολουθούν Gaussian (κανονική) κατανομή. Είναι κατάλληλος για συνεχή δεδομένα.
- **Multinomial Naive Bayes**: Υποθέτει ότι τα χαρακτηριστικά ακολουθούν multinomial κατανομή. Είναι κατάλληλος για διακριτά δεδομένα, όπως οι μετρήσεις λέξεων σε text classification.
- **Bernoulli Naive Bayes**: Υποθέτει ότι τα χαρακτηριστικά είναι δυαδικά (0 ή 1). Είναι κατάλληλος για δυαδικά δεδομένα, όπως η παρουσία ή η απουσία λέξεων σε text classification.
- **Categorical Naive Bayes**: Υποθέτει ότι τα χαρακτηριστικά είναι categorical variables. Είναι κατάλληλος για categorical data, όπως η ταξινόμηση φρούτων με βάση το χρώμα και το σχήμα τους.


#### **Βασικά χαρακτηριστικά του Naive Bayes:**

-   **Τύπος προβλήματος:** Classification (binary ή multi-class). Χρησιμοποιείται συνήθως για text classification tasks στο cybersecurity (spam, phishing κ.λπ.).

-   **Ερμηνευσιμότητα:** Μέτρια -- δεν είναι τόσο άμεσα ερμηνεύσιμος όσο ένα decision tree, αλλά μπορεί κανείς να εξετάσει τις μαθημένες πιθανότητες (π.χ. ποιες λέξεις είναι πιθανότερο να εμφανίζονται σε spam σε σύγκριση με ham emails). Η μορφή του model (πιθανότητες για κάθε χαρακτηριστικό δεδομένης της κλάσης) μπορεί να γίνει κατανοητή, αν χρειαστεί.

-   **Πλεονεκτήματα:** **Πολύ γρήγορη** εκπαίδευση και πρόβλεψη, ακόμη και σε μεγάλα datasets (γραμμική ως προς τον αριθμό των instances * τον αριθμό των features). Απαιτεί σχετικά μικρή ποσότητα δεδομένων για την αξιόπιστη εκτίμηση πιθανοτήτων, ειδικά με κατάλληλο smoothing. Συχνά είναι απροσδόκητα ακριβής ως baseline, ιδιαίτερα όταν τα χαρακτηριστικά συνεισφέρουν ανεξάρτητα στοιχεία στην κλάση. Λειτουργεί καλά με high-dimensional data (π.χ. χιλιάδες features από κείμενο). Δεν απαιτεί complex tuning πέρα από τον καθορισμό μιας smoothing parameter.

-   **Περιορισμοί:** Η υπόθεση ανεξαρτησίας μπορεί να περιορίσει την ακρίβεια, αν τα χαρακτηριστικά συσχετίζονται έντονα. Για παράδειγμα, σε network data, χαρακτηριστικά όπως `src_bytes` και `dst_bytes` μπορεί να συσχετίζονται· ο Naive Bayes δεν θα καταγράψει αυτή την αλληλεπίδραση. Καθώς το μέγεθος των δεδομένων αυξάνεται σημαντικά, πιο expressive models (όπως ensembles ή neural nets) μπορούν να ξεπεράσουν το NB, μαθαίνοντας τις εξαρτήσεις μεταξύ των χαρακτηριστικών. Επίσης, αν απαιτείται ένας συγκεκριμένος συνδυασμός χαρακτηριστικών για την αναγνώριση μιας επίθεσης (και όχι απλώς μεμονωμένα χαρακτηριστικά ανεξάρτητα), το NB θα δυσκολευτεί.

> [!TIP]
> *Use cases στο cybersecurity:* Η κλασική χρήση είναι το **spam detection** -- ο Naive Bayes αποτέλεσε τον πυρήνα των πρώτων spam filters, χρησιμοποιώντας τις συχνότητες συγκεκριμένων tokens (λέξεις, φράσεις, IP addresses) για να υπολογίσει την πιθανότητα ένα email να είναι spam. Χρησιμοποιείται επίσης σε **phishing email detection** και **URL classification**, όπου η παρουσία συγκεκριμένων keywords ή χαρακτηριστικών (όπως το "login.php" σε ένα URL ή το `@` σε ένα URL path) συνεισφέρει στην πιθανότητα phishing. Στο malware analysis, θα μπορούσε κανείς να φανταστεί έναν Naive Bayes classifier που χρησιμοποιεί την παρουσία συγκεκριμένων API calls ή permissions σε software, για να προβλέψει αν πρόκειται για malware. Παρότι οι πιο advanced algorithms συχνά αποδίδουν καλύτερα, ο Naive Bayes παραμένει ένα καλό baseline λόγω της ταχύτητας και της απλότητάς του.

<details>
<summary>Παράδειγμα -- Naive Bayes για Phishing Detection:</summary>
Για να παρουσιάσουμε τον Naive Bayes, θα χρησιμοποιήσουμε Gaussian Naive Bayes στο NSL-KDD intrusion dataset (με binary labels). Το Gaussian NB θα θεωρήσει ότι κάθε feature ακολουθεί normal distribution ανά class. Αυτή είναι μια πρόχειρη επιλογή, καθώς πολλά network features είναι discrete ή highly skewed, αλλά δείχνει πώς θα εφαρμοζόταν το NB σε continuous feature data. Θα μπορούσαμε επίσης να επιλέξουμε Bernoulli NB σε ένα dataset από binary features (όπως ένα σύνολο από triggered alerts), αλλά εδώ θα παραμείνουμε στο NSL-KDD για λόγους συνέχειας.
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
Αυτός ο κώδικας εκπαιδεύει έναν classifier Naive Bayes για την ανίχνευση attacks. Το Naive Bayes υπολογίζει πράγματα όπως `P(service=http | Attack)` και `P(Service=http | Normal)` με βάση τα training data, θεωρώντας ότι υπάρχει ανεξαρτησία μεταξύ των features. Στη συνέχεια χρησιμοποιεί αυτές τις πιθανότητες για να ταξινομήσει νέες συνδέσεις ως normal ή attack, με βάση τα features που παρατηρούνται. Η απόδοση του NB στο NSL-KDD μπορεί να μην είναι τόσο υψηλή όσο αυτή πιο advanced μοντέλων (καθώς παραβιάζεται η ανεξαρτησία των features), αλλά συχνά είναι ικανοποιητική και προσφέρει το πλεονέκτημα της εξαιρετικά υψηλής ταχύτητας. Σε σενάρια όπως το real-time email filtering ή το αρχικό triage URLs, ένα μοντέλο Naive Bayes μπορεί να επισημαίνει γρήγορα τις προφανώς malicious περιπτώσεις με χαμηλή χρήση πόρων.

</details>

### k-Nearest Neighbors (k-NN)

Το k-Nearest Neighbors είναι ένας από τους απλούστερους machine learning algorithms. Είναι μια **non-parametric, instance-based** μέθοδος που κάνει predictions με βάση την ομοιότητα με παραδείγματα από το training set. Η ιδέα για classification είναι η εξής: για να ταξινομηθεί ένα νέο data point, βρίσκουμε τα **k** κοντινότερα points στα training data (τους «nearest neighbors») και αντιστοιχίζουμε την majority class μεταξύ αυτών των neighbors. Η «κοντινότητα» ορίζεται από ένα distance metric, συνήθως την Euclidean distance για numeric data (μπορούν να χρησιμοποιηθούν και άλλες distances για διαφορετικούς τύπους features ή προβλημάτων).<sup>[[10]](#references)</sup>

Το K-NN δεν απαιτεί *explicit training* -- η φάση του «training» συνίσταται απλώς στην αποθήκευση του dataset. Όλη η εργασία πραγματοποιείται κατά το query (prediction): ο algorithm πρέπει να υπολογίσει τις distances από το query point προς όλα τα training points, ώστε να βρει τα κοντινότερα. Αυτό κάνει τον χρόνο prediction **γραμμικό ως προς τον αριθμό των training samples**, κάτι που μπορεί να είναι δαπανηρό για μεγάλα datasets. Εξαιτίας αυτού, το k-NN ταιριάζει καλύτερα σε μικρότερα datasets ή σε σενάρια όπου μπορείτε να ανταλλάξετε memory και speed με απλότητα.

Παρά την απλότητά του, το k-NN μπορεί να μοντελοποιήσει πολύ σύνθετα decision boundaries (καθώς, ουσιαστικά, το decision boundary μπορεί να έχει οποιοδήποτε σχήμα υπαγορεύεται από την κατανομή των examples). Τείνει να αποδίδει καλά όταν το decision boundary είναι πολύ irregular και υπάρχει μεγάλη ποσότητα data -- ουσιαστικά αφήνοντας τα data να «μιλήσουν από μόνα τους». Ωστόσο, σε υψηλές διαστάσεις, τα distance metrics μπορεί να γίνουν λιγότερο meaningful (curse of dimensionality), και η μέθοδος μπορεί να δυσκολευτεί, εκτός αν διαθέτετε έναν τεράστιο αριθμό samples.

*Use cases in cybersecurity:* Το k-NN έχει εφαρμοστεί σε anomaly detection -- για παράδειγμα, ένα intrusion detection system μπορεί να χαρακτηρίσει ένα network event ως malicious αν οι περισσότεροι από τους nearest neighbors του (προηγούμενα events) ήταν malicious. Αν η normal traffic σχηματίζει clusters και τα attacks είναι outliers, μια προσέγγιση K-NN (με k=1 ή μικρό k) αποτελεί ουσιαστικά **nearest-neighbor anomaly detection**. Το K-NN έχει επίσης χρησιμοποιηθεί για την ταξινόμηση malware families μέσω binary feature vectors: ένα νέο file μπορεί να ταξινομηθεί ως μέλος μιας συγκεκριμένης malware family αν είναι πολύ κοντά (στο feature space) σε γνωστά instances αυτής της family. Στην πράξη, το k-NN δεν είναι τόσο συνηθισμένο όσο πιο scalable algorithms, αλλά είναι conceptually straightforward και χρησιμοποιείται μερικές φορές ως baseline ή για small-scale problems.

#### **Βασικά χαρακτηριστικά του k-NN:**

-   **Τύπος προβλήματος:** Classification (και υπάρχουν variants για regression). Είναι μια μέθοδος *lazy learning* -- δεν πραγματοποιείται explicit model fitting.

-   **Interpretability:** Χαμηλή έως μέτρια -- δεν υπάρχει global model ή concise explanation, αλλά τα αποτελέσματα μπορούν να ερμηνευτούν εξετάζοντας τους nearest neighbors που επηρέασαν μια απόφαση (π.χ. «αυτό το network flow ταξινομήθηκε ως malicious επειδή είναι παρόμοιο με αυτά τα 3 γνωστά malicious flows»). Επομένως, οι explanations μπορούν να βασίζονται σε examples.

-   **Πλεονεκτήματα:** Πολύ απλό στην υλοποίηση και την κατανόηση. Δεν κάνει assumptions σχετικά με την κατανομή των data (non-parametric). Μπορεί να χειριστεί φυσικά multi-class problems. Είναι **adaptive**, με την έννοια ότι τα decision boundaries μπορούν να είναι πολύ σύνθετα και να διαμορφώνονται από την κατανομή των data.

-   **Περιορισμοί:** Το prediction μπορεί να είναι αργό για μεγάλα datasets (πρέπει να υπολογιστούν πολλές distances). Απαιτεί αρκετή memory -- αποθηκεύει όλα τα training data. Η απόδοση υποβαθμίζεται σε high-dimensional feature spaces, επειδή όλα τα points τείνουν να γίνονται σχεδόν ισαπέχοντα (κάνοντας την έννοια του «nearest» λιγότερο meaningful). Πρέπει να επιλεγεί σωστά το *k* (ο αριθμός των neighbors) -- ένα υπερβολικά μικρό k μπορεί να είναι noisy, ενώ ένα υπερβολικά μεγάλο k μπορεί να συμπεριλάβει irrelevant points από άλλες classes. Επίσης, τα features πρέπει να γίνονται appropriately scaled, επειδή οι distance calculations είναι ευαίσθητοι στο scale.

<details>
<summary>Παράδειγμα -- k-NN για Phishing Detection:</summary>

Θα χρησιμοποιήσουμε ξανά το NSL-KDD (binary classification). Επειδή το k-NN είναι computationally heavy, θα χρησιμοποιήσουμε ένα subset των training data, ώστε η διαδικασία να παραμείνει tractable σε αυτή την επίδειξη. Θα επιλέξουμε, για παράδειγμα, 20.000 training samples από τα συνολικά 125k και θα χρησιμοποιήσουμε k=5 neighbors. Μετά το training (που στην πραγματικότητα συνίσταται απλώς στην αποθήκευση των data), θα αξιολογήσουμε το μοντέλο στο test set. Θα κάνουμε επίσης scale στα features για το distance calculation, ώστε κανένα feature να μην κυριαρχεί εξαιτίας του scale.
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
Το μοντέλο k-NN θα ταξινομήσει μια σύνδεση εξετάζοντας τις 5 πλησιέστερες συνδέσεις στο υποσύνολο του training set. Αν, για παράδειγμα, 4 από αυτούς τους γείτονες είναι επιθέσεις (anomalies) και 1 είναι φυσιολογική, η νέα σύνδεση θα ταξινομηθεί ως επίθεση. Η απόδοση μπορεί να είναι ικανοποιητική, αν και συχνά όχι τόσο υψηλή όσο μιας καλά ρυθμισμένης Random Forest ή ενός SVM στα ίδια δεδομένα. Ωστόσο, το k-NN μπορεί μερικές φορές να υπερέχει όταν οι κατανομές των κλάσεων είναι πολύ ακανόνιστες και σύνθετες -- λειτουργώντας ουσιαστικά ως αναζήτηση βασισμένη στη μνήμη. Στην cybersecurity, το k-NN (με k=1 ή μικρό k) θα μπορούσε να χρησιμοποιηθεί για την ανίχνευση γνωστών attack patterns μέσω παραδειγμάτων ή ως συστατικό πιο σύνθετων συστημάτων (π.χ., για clustering και στη συνέχεια ταξινόμηση με βάση την ένταξη σε cluster).
</details>

### Gradient Boosting Machines (π.χ., XGBoost)

Οι Gradient Boosting Machines συγκαταλέγονται στους ισχυρότερους αλγόριθμους για structured data. Το **gradient boosting** αναφέρεται στην τεχνική δημιουργίας ενός ensemble από weak learners (συχνά decision trees) με διαδοχικό τρόπο, όπου κάθε νέο μοντέλο διορθώνει τα σφάλματα του προηγούμενου ensemble. Σε αντίθεση με το bagging (Random Forests), το οποίο δημιουργεί τα trees παράλληλα και υπολογίζει τον μέσο όρο τους, το boosting δημιουργεί τα trees *ένα-ένα*, εστιάζοντας περισσότερο στις περιπτώσεις που τα προηγούμενα trees ταξινόμησαν λανθασμένα.<sup>[[11]](#references)</sup>

Οι δημοφιλέστερες υλοποιήσεις τα τελευταία χρόνια είναι οι **XGBoost**, **LightGBM** και **CatBoost**, οι οποίες είναι όλες βιβλιοθήκες gradient boosting decision tree (GBDT). Έχουν σημειώσει εξαιρετική επιτυχία σε διαγωνισμούς και εφαρμογές machine learning, συχνά **επιτυγχάνοντας state-of-the-art απόδοση σε tabular datasets**. Στην cybersecurity, ερευνητές και επαγγελματίες έχουν χρησιμοποιήσει gradient boosted trees για εργασίες όπως η **ανίχνευση malware** (με χρήση features που εξάγονται από αρχεία ή από συμπεριφορά κατά το runtime) και η **ανίχνευση network intrusion**. Για παράδειγμα, ένα μοντέλο gradient boosting μπορεί να συνδυάσει πολλούς weak rules (trees), όπως «αν υπάρχουν πολλά SYN packets και ασυνήθιστο port -> πιθανό scan», σε έναν ισχυρό σύνθετο detector που λαμβάνει υπόψη πολλά λεπτά patterns.

Γιατί είναι τόσο αποτελεσματικά τα boosted trees; Κάθε tree στη σειρά εκπαιδεύεται πάνω στα *residual errors* (gradients) των προβλέψεων του τρέχοντος ensemble. Με αυτόν τον τρόπο, το μοντέλο **«ενισχύει»** σταδιακά τις περιοχές στις οποίες είναι αδύναμο. Η χρήση decision trees ως base learners επιτρέπει στο τελικό μοντέλο να αποτυπώνει σύνθετες αλληλεπιδράσεις και μη γραμμικές σχέσεις. Επιπλέον, το boosting διαθέτει εγγενώς μια μορφή ενσωματωμένης regularization: με την προσθήκη πολλών μικρών trees (και τη χρήση learning rate για την κλιμάκωση της συνεισφοράς τους), συχνά γενικεύει καλά χωρίς έντονο overfitting, εφόσον επιλεγούν οι κατάλληλες παράμετροι.

#### **Βασικά χαρακτηριστικά του Gradient Boosting:**

-   **Τύπος προβλήματος:** Κυρίως classification και regression. Στην ασφάλεια, συνήθως classification (π.χ., binary classification μιας σύνδεσης ή ενός αρχείου). Υποστηρίζει binary, multi-class (με την κατάλληλη loss) και ακόμη και ranking problems.

-   **Ερμηνευσιμότητα:** Χαμηλή έως μέτρια. Παρότι ένα μεμονωμένο boosted tree είναι μικρό, ένα πλήρες μοντέλο μπορεί να διαθέτει εκατοντάδες trees, επομένως δεν είναι ερμηνεύσιμο από άνθρωπο ως σύνολο. Ωστόσο, όπως και η Random Forest, μπορεί να παρέχει scores σημαντικότητας των features, ενώ εργαλεία όπως το SHAP (SHapley Additive exPlanations) μπορούν να χρησιμοποιηθούν για την ερμηνεία μεμονωμένων προβλέψεων σε κάποιο βαθμό.

-   **Πλεονεκτήματα:** Συχνά είναι ο **αλγόριθμος με την καλύτερη απόδοση** για structured/tabular data. Μπορεί να ανιχνεύσει σύνθετα patterns και αλληλεπιδράσεις. Διαθέτει πολλές παραμέτρους ρύθμισης (αριθμός trees, βάθος trees, learning rate, όροι regularization) για την προσαρμογή της πολυπλοκότητας του μοντέλου και την αποτροπή του overfitting. Οι σύγχρονες υλοποιήσεις είναι βελτιστοποιημένες για ταχύτητα (π.χ., το XGBoost χρησιμοποιεί second-order gradient information και αποδοτικές δομές δεδομένων). Τείνει να χειρίζεται καλύτερα imbalanced data όταν συνδυάζεται με κατάλληλες loss functions ή με προσαρμογή των sample weights.

-   **Περιορισμοί:** Είναι πιο σύνθετο στη ρύθμιση από απλούστερα μοντέλα· η εκπαίδευση μπορεί να είναι αργή αν τα trees είναι βαθιά ή ο αριθμός των trees μεγάλος (αν και συνήθως παραμένει ταχύτερη από την εκπαίδευση ενός αντίστοιχου deep neural network στα ίδια δεδομένα). Το μοντέλο μπορεί να υποστεί overfitting αν δεν ρυθμιστεί σωστά (π.χ., πάρα πολλά βαθιά trees με ανεπαρκή regularization). Επειδή διαθέτει πολλές hyperparameters, η αποτελεσματική χρήση του gradient boosting μπορεί να απαιτεί περισσότερη τεχνογνωσία ή πειραματισμό. Επίσης, όπως και οι tree-based μέθοδοι, δεν χειρίζεται εγγενώς τόσο αποδοτικά πολύ sparse high-dimensional data όσο τα linear models ή το Naive Bayes (αν και μπορεί να εφαρμοστεί, π.χ., σε text classification, όμως ίσως να μην είναι η πρώτη επιλογή χωρίς feature engineering).

> [!TIP]
> *Use cases στην cybersecurity:* Σχεδόν οπουδήποτε θα μπορούσε να χρησιμοποιηθεί ένα decision tree ή μια random forest, ένα μοντέλο gradient boosting μπορεί να επιτύχει μεγαλύτερη ακρίβεια. Για παράδειγμα, οι διαγωνισμοί **ανίχνευσης malware της Microsoft** έχουν αξιοποιήσει εκτενώς το XGBoost σε engineered features από binary files. Η έρευνα για **network intrusion detection** συχνά αναφέρει κορυφαία αποτελέσματα με GBDTs (π.χ., XGBoost στα datasets CIC-IDS2017 ή UNSW-NB15). Αυτά τα μοντέλα μπορούν να λάβουν ένα ευρύ φάσμα features (τύπους πρωτοκόλλων, συχνότητα συγκεκριμένων events, statistical features της κίνησης κ.λπ.) και να τα συνδυάσουν για την ανίχνευση threats. Στην ανίχνευση phishing, το gradient boosting μπορεί να συνδυάσει lexical features των URLs, features reputation των domains και features από το περιεχόμενο των σελίδων, επιτυγχάνοντας πολύ υψηλή ακρίβεια. Η ensemble προσέγγιση βοηθά στην κάλυψη πολλών corner cases και λεπτομερειών στα δεδομένα.

<details>
<summary>Παράδειγμα -- XGBoost για ανίχνευση phishing:</summary>
Θα χρησιμοποιήσουμε έναν gradient boosting classifier στο phishing dataset. Για να διατηρήσουμε τα πράγματα απλά και self-contained, θα χρησιμοποιήσουμε το `sklearn.ensemble.GradientBoostingClassifier` (το οποίο είναι μια πιο αργή αλλά απλή υλοποίηση). Κανονικά, θα μπορούσε να χρησιμοποιηθεί η βιβλιοθήκη `xgboost` ή `lightgbm` για καλύτερη απόδοση και πρόσθετες δυνατότητες. Θα εκπαιδεύσουμε το μοντέλο και θα αξιολογήσουμε την απόδοσή του με παρόμοιο τρόπο όπως προηγουμένως.
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
Το μοντέλο gradient boosting πιθανότατα θα επιτύχει πολύ υψηλή ακρίβεια και AUC σε αυτό το phishing dataset (συχνά αυτά τα μοντέλα μπορούν να ξεπεράσουν το 95% ακρίβειας με σωστό tuning σε τέτοια δεδομένα, όπως φαίνεται στη βιβλιογραφία. Αυτό δείχνει γιατί τα GBDTs θεωρούνται *"the state of the art model for tabular dataset"* -- συχνά ξεπερνούν απλούστερους αλγορίθμους, εντοπίζοντας σύνθετα μοτίβα.<sup>[[11]](#references)</sup> Σε ένα πλαίσιο κυβερνοασφάλειας, αυτό θα μπορούσε να σημαίνει τον εντοπισμό περισσότερων phishing sites ή επιθέσεων με λιγότερες αστοχίες. Φυσικά, πρέπει να είμαστε προσεκτικοί με το overfitting -- συνήθως θα χρησιμοποιούσαμε τεχνικές όπως το cross-validation και θα παρακολουθούσαμε την απόδοση σε ένα validation set κατά την ανάπτυξη ενός τέτοιου μοντέλου για deployment.

</details>

### Συνδυασμός Μοντέλων: Ensemble Learning και Stacking

Το ensemble learning είναι μια στρατηγική **συνδυασμού πολλαπλών μοντέλων** για τη βελτίωση της συνολικής απόδοσης. Έχουμε ήδη δει συγκεκριμένες ensemble μεθόδους: Random Forest (ένα ensemble δέντρων μέσω bagging) και Gradient Boosting (ένα ensemble δέντρων μέσω sequential boosting). Ωστόσο, ensembles μπορούν να δημιουργηθούν και με άλλους τρόπους, όπως **voting ensembles** ή **stacked generalization (stacking)**. Η βασική ιδέα είναι ότι διαφορετικά μοντέλα μπορεί να εντοπίζουν διαφορετικά μοτίβα ή να έχουν διαφορετικές αδυναμίες· συνδυάζοντάς τα, μπορούμε να **αντισταθμίσουμε τα σφάλματα κάθε μοντέλου με τα ισχυρά σημεία κάποιου άλλου**.<sup>[[12]](#references)</sup>

-   **Voting Ensemble:** Σε έναν απλό voting classifier, εκπαιδεύουμε πολλά διαφορετικά μοντέλα (για παράδειγμα, ένα logistic regression, ένα decision tree και ένα SVM) και τα αφήνουμε να ψηφίσουν για την τελική πρόβλεψη (πλειοψηφική ψήφος για classification). Αν σταθμίσουμε τις ψήφους (π.χ. δώσουμε μεγαλύτερο βάρος στα ακριβέστερα μοντέλα), έχουμε ένα weighted voting scheme. Αυτό συνήθως βελτιώνει την απόδοση όταν τα μεμονωμένα μοντέλα είναι αρκετά καλά και ανεξάρτητα -- το ensemble μειώνει τον κίνδυνο ενός λάθους από κάποιο μεμονωμένο μοντέλο, καθώς τα υπόλοιπα μπορεί να το διορθώσουν. Είναι σαν να έχουμε μια ομάδα ειδικών αντί για μία μόνο άποψη.

-   **Stacking (Stacked Ensemble):** Το stacking προχωρά ένα βήμα παραπέρα. Αντί για μια απλή ψήφο, εκπαιδεύει ένα **meta-model** ώστε να **μαθαίνει πώς να συνδυάζει καλύτερα τις προβλέψεις** των base models. Για παράδειγμα, εκπαιδεύουμε 3 διαφορετικούς classifiers (base learners) και στη συνέχεια τροφοδοτούμε τις εξόδους τους (ή τις πιθανότητές τους) ως features σε έναν meta-classifier (συχνά ένα απλό μοντέλο, όπως logistic regression), ο οποίος μαθαίνει τον βέλτιστο τρόπο συνδυασμού τους. Το meta-model εκπαιδεύεται σε ένα validation set ή μέσω cross-validation, ώστε να αποφεύγεται το overfitting. Το stacking συχνά μπορεί να ξεπεράσει το απλό voting, μαθαίνοντας *ποια μοντέλα πρέπει να εμπιστεύεται περισσότερο σε κάθε περίσταση*. Στην κυβερνοασφάλεια, ένα μοντέλο μπορεί να είναι καλύτερο στον εντοπισμό network scans, ενώ ένα άλλο στον εντοπισμό malware beaconing· ένα stacking model θα μπορούσε να μάθει να βασίζεται στο καθένα με τον κατάλληλο τρόπο.

Τα ensembles, είτε μέσω voting είτε μέσω stacking, τείνουν να **αυξάνουν την ακρίβεια** και την ανθεκτικότητα. Το μειονέκτημα είναι η αυξημένη πολυπλοκότητα και, ορισμένες φορές, η μειωμένη ερμηνευσιμότητα (αν και ορισμένες ensemble προσεγγίσεις, όπως ο μέσος όρος των decision trees, μπορούν να παρέχουν κάποια εικόνα, π.χ. feature importance). Στην πράξη, εφόσον το επιτρέπουν οι operational περιορισμοί, η χρήση ενός ensemble μπορεί να οδηγήσει σε υψηλότερα detection rates. Πολλές νικητήριες λύσεις σε cybersecurity challenges (και γενικά σε Kaggle competitions) χρησιμοποιούν ensemble τεχνικές για να αποσπάσουν και το τελευταίο μέρος της απόδοσης.

<details>
<summary>Παράδειγμα -- Voting Ensemble για Phishing Detection:</summary>
Για να παρουσιάσουμε το model stacking, ας συνδυάσουμε μερικά από τα μοντέλα που συζητήσαμε στο phishing dataset. Θα χρησιμοποιήσουμε ένα logistic regression, ένα decision tree και ένα k-NN ως base learners, και ένα Random Forest ως meta-learner για τη συγκέντρωση των προβλέψεών τους. Το meta-learner θα εκπαιδευτεί στις εξόδους των base learners (χρησιμοποιώντας cross-validation στο training set). Αναμένουμε το stacked model να έχει εξίσου καλή ή ελαφρώς καλύτερη απόδοση από τα μεμονωμένα μοντέλα.
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
Το stacked ensemble αξιοποιεί τα συμπληρωματικά πλεονεκτήματα των base models. Για παράδειγμα, η logistic regression μπορεί να χειρίζεται τις γραμμικές πτυχές των δεδομένων, το decision tree μπορεί να εντοπίζει συγκεκριμένες αλληλεπιδράσεις που μοιάζουν με κανόνες και το k-NN μπορεί να αποδίδει εξαιρετικά σε τοπικές γειτονιές του feature space. Το meta-model (random forest εδώ) μπορεί να μάθει πώς να σταθμίζει αυτές τις εισόδους. Οι resulting metrics συχνά παρουσιάζουν βελτίωση (έστω και μικρή) σε σχέση με τα metrics οποιουδήποτε μεμονωμένου model. Στο παράδειγμα phishing, αν η logistic regression μόνη της είχε F1, για παράδειγμα, 0.95 και το tree 0.94, το stack θα μπορούσε να επιτύχει 0.96, αξιοποιώντας τα σημεία στα οποία κάθε model κάνει λάθος.

Οι ensemble methods όπως αυτή καταδεικνύουν την αρχή ότι *«ο συνδυασμός πολλαπλών models συνήθως οδηγεί σε καλύτερη γενίκευση»*.<sup>[[12]](#references)</sup> Στην κυβερνοασφάλεια, αυτό μπορεί να υλοποιηθεί με τη χρήση πολλαπλών detection engines (μία μπορεί να βασίζεται σε rules, μία σε machine learning και μία σε anomaly detection) και, στη συνέχεια, ενός layer που συγκεντρώνει τα alerts τους -- ουσιαστικά μια μορφή ensemble -- για τη λήψη τελικής απόφασης με υψηλότερη confidence. Κατά την ανάπτυξη τέτοιων συστημάτων, πρέπει να λαμβάνεται υπόψη η πρόσθετη πολυπλοκότητα και να διασφαλίζεται ότι το ensemble δεν θα γίνει υπερβολικά δύσκολο στη διαχείριση ή την επεξήγηση. Ωστόσο, από άποψη accuracy, τα ensembles και το stacking είναι ισχυρά εργαλεία για τη βελτίωση της απόδοσης των models.

</details>

Οι προσεγγίσεις neural-network που περιγράφονται στη [σελίδα deep-learning](AI-Deep-Learning.md) μπορούν να συμπληρώσουν αυτά τα κλασικά models για intrusion detection, όταν το dataset και το compute budget δικαιολογούν την πρόσθετη πολυπλοκότητα.<sup>[[13]](#references)</sup>

## References

- [1] [AI και Machine Learning στην Κυβερνοασφάλεια - zvelo](https://zvelo.com/ai-and-machine-learning-in-cybersecurity/)
- [2] [Linear Regression, Επεξήγηση - Medium](https://medium.com/@chaandram/linear-regression-explained-28d5bf1934ae)
- [3] [Logistic Regression - Medium](https://madhuramiah.medium.com/logistic-regression-6e55553cc003)
- [4] [Sohail Ahmed Khan, Wasiq Khan, Abir Hussain - "Ταξινόμηση Phishing Attacks και Websites με χρήση Machine Learning και πολλαπλών Datasets (Συγκριτική Ανάλυση)"](https://arxiv.org/pdf/2101.02552)
- [5] [Decision Tree - GeeksforGeeks](https://www.geeksforgeeks.org/decision-tree-introduction-example/)
- [6] [Reena Singh Rajput, Sanjay Agrawal - "Ανίχνευση Denial of Services Attack με χρήση Random Forest Classifier και Information Gain"](https://rjwave.org/ijedr/viewpaperforall.php?paper=IJEDR1703132)
- [7] [Raisa Abedin Disha, Sajjad Waheed - "Ανάλυση απόδοσης μοντέλων machine learning για intrusion detection system με χρήση της τεχνικής επιλογής χαρακτηριστικών Gini Impurity-based Weighted Random Forest (GIWRF)"](https://cybersecurity.springeropen.com/articles/10.1186/s42400-021-00103-8)
- [8] [Τι είναι ένα Support Vector Machine; - IBM](https://www.ibm.com/think/topics/support-vector-machine)
- [9] [Naive Bayes spam filtering - Wikipedia](https://en.m.wikipedia.org/wiki/Naive_Bayes_spam_filtering)
- [10] [Τι είναι το k-Nearest Neighbors (KNN); - IBM](https://www.ibm.com/think/topics/knn)
- [11] [GBDT χωρίς μυστήρια: Πώς λειτουργούν τα LightGBM, XGBoost και CatBoost - Medium](https://medium.com/@rupalipatelkvc/gbdt-demystified-how-lightgbm-xgboost-and-catboost-work-9479b7262644)
- [12] [Ensemble Learning: Βελτίωση της απόδοσης των models μέσω συνδυασμού των πλεονεκτημάτων τους - Medium](https://medium.com/@sarahzouinina/ensemble-learning-boosting-model-performance-by-combining-strengths-02e56165b901)
- [13] [Πώς το Deep Learning βελτιώνει τα Intrusion Detection Systems](https://cybersecurity-magazine.com/how-deep-learning-enhances-intrusion-detection-systems/)
{{#include ../banners/hacktricks-training.md}}
