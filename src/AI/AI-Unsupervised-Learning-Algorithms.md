# Αλγόριθμοι Μη Επιβλεπόμενης Μάθησης

{{#include ../banners/hacktricks-training.md}}

## Μη Επιβλεπόμενη Μάθηση

Η μη επιβλεπόμενη μάθηση είναι ένας τύπος machine learning όπου το μοντέλο εκπαιδεύεται σε δεδομένα χωρίς επισημασμένες αποκρίσεις. Ο στόχος είναι να εντοπιστούν μοτίβα, δομές ή σχέσεις μέσα στα δεδομένα. Σε αντίθεση με την επιβλεπόμενη μάθηση, όπου το μοντέλο μαθαίνει από επισημασμένα παραδείγματα, οι αλγόριθμοι μη επιβλεπόμενης μάθησης λειτουργούν με μη επισημασμένα δεδομένα.
Η μη επιβλεπόμενη μάθηση χρησιμοποιείται συχνά για εργασίες όπως clustering, μείωση διαστατικότητας και ανίχνευση ανωμαλιών. Μπορεί να βοηθήσει στην ανακάλυψη κρυφών μοτίβων στα δεδομένα, στην ομαδοποίηση παρόμοιων στοιχείων ή στη μείωση της πολυπλοκότητας των δεδομένων, διατηρώντας παράλληλα τα βασικά χαρακτηριστικά τους.


### K-Means Clustering

Το K-Means είναι ένας αλγόριθμος clustering βασισμένος σε κεντροειδή, ο οποίος διαχωρίζει τα δεδομένα σε K clusters, αντιστοιχίζοντας κάθε σημείο στον πλησιέστερο μέσο όρο cluster. Ο αλγόριθμος λειτουργεί ως εξής:
1. **Αρχικοποίηση**: Επιλέγονται K αρχικά κέντρα cluster (κεντροειδή), συχνά τυχαία ή μέσω πιο έξυπνων μεθόδων όπως το k-means++
2. **Ανάθεση**: Κάθε σημείο δεδομένων αντιστοιχίζεται στο πλησιέστερο κεντροειδές με βάση ένα metric απόστασης (π.χ. Ευκλείδεια απόσταση).
3. **Ενημέρωση**: Τα κεντροειδή υπολογίζονται ξανά, λαμβάνοντας τον μέσο όρο όλων των σημείων δεδομένων που έχουν αντιστοιχιστεί σε κάθε cluster.
4. **Επανάληψη**: Τα βήματα 2–3 επαναλαμβάνονται μέχρι να σταθεροποιηθούν οι αναθέσεις των clusters (τα κεντροειδή να μην μετακινούνται σημαντικά).

> [!TIP]
> *Περιπτώσεις χρήσης στο cybersecurity:* Το K-Means χρησιμοποιείται για intrusion detection μέσω clustering συμβάντων δικτύου. Για παράδειγμα, ερευνητές εφάρμοσαν το K-Means στο dataset εισβολών KDD Cup 99 και διαπίστωσαν ότι διαχώρισε αποτελεσματικά την κίνηση σε clusters φυσιολογικής κίνησης και επιθέσεων. Στην πράξη, οι security analysts μπορούν να ομαδοποιούν καταχωρίσεις logs ή δεδομένα συμπεριφοράς χρηστών, ώστε να εντοπίζουν ομάδες παρόμοιας δραστηριότητας. Σημεία που δεν ανήκουν σε ένα καλά σχηματισμένο cluster μπορεί να υποδεικνύουν ανωμαλίες (π.χ. μια νέα παραλλαγή malware που σχηματίζει το δικό της μικρό cluster). Το K-Means μπορεί επίσης να βοηθήσει στην ταξινόμηση οικογενειών malware, ομαδοποιώντας binaries με βάση προφίλ συμπεριφοράς ή feature vectors.

#### Επιλογή του K
Ο αριθμός των clusters (K) είναι μια hyperparameter που πρέπει να οριστεί πριν από την εκτέλεση του αλγορίθμου. Τεχνικές όπως η Elbow Method ή το Silhouette Score μπορούν να βοηθήσουν στον προσδιορισμό μιας κατάλληλης τιμής για το K, αξιολογώντας την απόδοση του clustering:

- **Elbow Method**: Σχεδιάστε το άθροισμα των τετραγώνων των αποστάσεων από κάθε σημείο προς το κεντροειδές του cluster στο οποίο έχει ανατεθεί, ως συνάρτηση του K. Αναζητήστε ένα σημείο "αγκώνα", όπου ο ρυθμός μείωσης αλλάζει απότομα, υποδεικνύοντας έναν κατάλληλο αριθμό clusters.
- **Silhouette Score**: Υπολογίστε το silhouette score για διαφορετικές τιμές του K. Ένα υψηλότερο silhouette score υποδεικνύει καλύτερα ορισμένα clusters.

#### Παραδοχές και Περιορισμοί

Το K-Means υποθέτει ότι τα **clusters είναι σφαιρικά και ίσου μεγέθους**, κάτι που μπορεί να μην ισχύει για όλα τα datasets. Είναι ευαίσθητο στην αρχική τοποθέτηση των κεντροειδών και μπορεί να συγκλίνει σε τοπικά ελάχιστα. Επιπλέον, το K-Means δεν είναι κατάλληλο για datasets με διαφορετικές πυκνότητες ή μη σφαιρικά σχήματα και features με διαφορετικές κλίμακες. Μπορεί να είναι απαραίτητα βήματα preprocessing, όπως normalization ή standardization, ώστε όλα τα features να συνεισφέρουν εξίσου στους υπολογισμούς αποστάσεων.

<details>
<summary>Παράδειγμα -- Clustering Συμβάντων Δικτύου
</summary>
Παρακάτω προσομοιώνουμε δεδομένα κίνησης δικτύου και χρησιμοποιούμε το K-Means για να τα ομαδοποιήσουμε. Ας υποθέσουμε ότι έχουμε συμβάντα με features όπως η διάρκεια σύνδεσης και ο αριθμός bytes. Δημιουργούμε 3 clusters "φυσιολογικής" κίνησης και 1 μικρό cluster που αντιπροσωπεύει ένα μοτίβο επίθεσης. Στη συνέχεια εκτελούμε το K-Means για να δούμε αν τα διαχωρίζει.
```python
import numpy as np
from sklearn.cluster import KMeans

# Simulate synthetic network traffic data (e.g., [duration, bytes]).
# Three normal clusters and one small attack cluster.
rng = np.random.RandomState(42)
normal1 = rng.normal(loc=[50, 500], scale=[10, 100], size=(500, 2))   # Cluster 1
normal2 = rng.normal(loc=[60, 1500], scale=[8, 200], size=(500, 2))   # Cluster 2
normal3 = rng.normal(loc=[70, 3000], scale=[5, 300], size=(500, 2))   # Cluster 3
attack = rng.normal(loc=[200, 800], scale=[5, 50], size=(50, 2))      # Small attack cluster

X = np.vstack([normal1, normal2, normal3, attack])
# Run K-Means clustering into 4 clusters (we expect it to find the 4 groups)
kmeans = KMeans(n_clusters=4, random_state=0, n_init=10)
labels = kmeans.fit_predict(X)

# Analyze resulting clusters
clusters, counts = np.unique(labels, return_counts=True)
print(f"Cluster labels: {clusters}")
print(f"Cluster sizes: {counts}")
print("Cluster centers (duration, bytes):")
for idx, center in enumerate(kmeans.cluster_centers_):
print(f"  Cluster {idx}: {center}")
```
Σε αυτό το παράδειγμα, το K-Means θα πρέπει να εντοπίσει 4 συστάδες. Η μικρή συστάδα επιθέσεων (με ασυνήθιστα μεγάλη διάρκεια ~200) ιδανικά θα σχηματίσει τη δική της συστάδα, δεδομένης της απόστασής της από τις κανονικές συστάδες. Εκτυπώνουμε τα μεγέθη και τα κέντρα των συστάδων για να ερμηνεύσουμε τα αποτελέσματα. Σε ένα πραγματικό σενάριο, θα μπορούσε κανείς να επισημάνει τη συστάδα με λίγα σημεία ως πιθανές ανωμαλίες ή να εξετάσει τα μέλη της για κακόβουλη δραστηριότητα.
</details>

### Ιεραρχική Συσταδοποίηση

Η ιεραρχική συσταδοποίηση δημιουργεί μια ιεραρχία συστάδων χρησιμοποιώντας είτε μια προσέγγιση από κάτω προς τα πάνω (συσσωρευτική) είτε μια προσέγγιση από πάνω προς τα κάτω (διαιρετική):

1. **Συσσωρευτική (Από Κάτω προς τα Πάνω)**: Ξεκινά με κάθε σημείο δεδομένων ως ξεχωριστή συστάδα και συγχωνεύει επαναληπτικά τις πλησιέστερες συστάδες, μέχρι να απομείνει μία ενιαία συστάδα ή να επιτευχθεί ένα κριτήριο τερματισμού.
2. **Διαιρετική (Από Πάνω προς τα Κάτω)**: Ξεκινά με όλα τα σημεία δεδομένων σε μία ενιαία συστάδα και διαχωρίζει επαναληπτικά τις συστάδες, μέχρι κάθε σημείο δεδομένων να αποτελεί τη δική του συστάδα ή να επιτευχθεί ένα κριτήριο τερματισμού.

Η συσσωρευτική συσταδοποίηση απαιτεί έναν ορισμό της απόστασης μεταξύ συστάδων και ένα κριτήριο σύνδεσης για να αποφασιστεί ποιες συστάδες θα συγχωνευθούν. Οι συνήθεις μέθοδοι σύνδεσης περιλαμβάνουν τη μονή σύνδεση (απόσταση των πλησιέστερων σημείων μεταξύ δύο συστάδων), την πλήρη σύνδεση (απόσταση των πιο απομακρυσμένων σημείων), τη μέση σύνδεση κ.ά., ενώ η μετρική απόστασης είναι συχνά η Ευκλείδεια. Η επιλογή σύνδεσης επηρεάζει το σχήμα των συστάδων που παράγονται. Δεν χρειάζεται να προκαθοριστεί ο αριθμός των συστάδων K· μπορείτε να «κόψετε» το δενδρόγραμμα σε ένα επιλεγμένο επίπεδο για να λάβετε τον επιθυμητό αριθμό συστάδων.

Η ιεραρχική συσταδοποίηση παράγει ένα δενδρόγραμμα, μια δομή που μοιάζει με δέντρο και παρουσιάζει τις σχέσεις μεταξύ των συστάδων σε διαφορετικά επίπεδα λεπτομέρειας. Το δενδρόγραμμα μπορεί να κοπεί στο επιθυμητό επίπεδο για να ληφθεί ένας συγκεκριμένος αριθμός συστάδων.

> [!TIP]
> *Περιπτώσεις χρήσης στην κυβερνοασφάλεια:* Η ιεραρχική συσταδοποίηση μπορεί να οργανώσει συμβάντα ή οντότητες σε ένα δέντρο, ώστε να εντοπίζονται σχέσεις. Για παράδειγμα, στην ανάλυση malware, η συσσωρευτική συσταδοποίηση θα μπορούσε να ομαδοποιήσει δείγματα βάσει ομοιότητας συμπεριφοράς, αποκαλύπτοντας μια ιεραρχία οικογενειών και παραλλαγών malware. Στην ασφάλεια δικτύων, θα μπορούσε κανείς να συσταδοποιήσει ροές IP traffic και να χρησιμοποιήσει το δενδρόγραμμα για να δει υποομαδοποιήσεις της κίνησης (π.χ. ανά protocol και στη συνέχεια ανά συμπεριφορά). Επειδή δεν χρειάζεται να επιλέξετε εκ των προτέρων το K, είναι χρήσιμη κατά την εξερεύνηση νέων δεδομένων, όταν ο αριθμός των κατηγοριών επιθέσεων είναι άγνωστος.

#### Παραδοχές και Περιορισμοί

Η ιεραρχική συσταδοποίηση δεν προϋποθέτει συγκεκριμένο σχήμα συστάδας και μπορεί να εντοπίσει ένθετες συστάδες. Είναι χρήσιμη για την ανακάλυψη ταξινομίας ή σχέσεων μεταξύ ομάδων (π.χ. για την ομαδοποίηση malware σε υποομάδες οικογενειών). Είναι ντετερμινιστική (χωρίς προβλήματα τυχαίας αρχικοποίησης). Ένα βασικό πλεονέκτημα είναι το δενδρόγραμμα, το οποίο παρέχει εικόνα της δομής συσταδοποίησης των δεδομένων σε όλες τις κλίμακες – οι security analysts μπορούν να αποφασίσουν ένα κατάλληλο cutoff για να εντοπίσουν ουσιαστικές συστάδες. Ωστόσο, είναι υπολογιστικά δαπανηρή (συνήθως χρόνος $O(n^2)$ ή χειρότερα για naive implementations) και δεν είναι εφικτή για πολύ μεγάλα datasets. Είναι επίσης μια greedy διαδικασία – μόλις πραγματοποιηθεί μια συγχώνευση ή ένας διαχωρισμός, δεν μπορεί να αναιρεθεί, γεγονός που μπορεί να οδηγήσει σε μη βέλτιστες συστάδες αν γίνει κάποιο λάθος νωρίς. Τα outliers μπορούν επίσης να επηρεάσουν ορισμένες στρατηγικές σύνδεσης (η μονή σύνδεση μπορεί να προκαλέσει το φαινόμενο «αλυσίδας», όπου οι συστάδες συνδέονται μέσω outliers).

<details>
<summary>Παράδειγμα -- Συσσωρευτική Συσταδοποίηση Συμβάντων
</summary>

Θα επαναχρησιμοποιήσουμε τα συνθετικά δεδομένα από το παράδειγμα K-Means (3 κανονικές συστάδες + 1 συστάδα επιθέσεων) και θα εφαρμόσουμε συσσωρευτική συσταδοποίηση. Στη συνέχεια, θα παρουσιάσουμε πώς λαμβάνονται ένα δενδρόγραμμα και οι ετικέτες των συστάδων.
```python
from sklearn.cluster import AgglomerativeClustering
from scipy.cluster.hierarchy import linkage, dendrogram

# Perform agglomerative clustering (bottom-up) on the data
agg = AgglomerativeClustering(n_clusters=None, distance_threshold=0, linkage='ward')
# distance_threshold=0 gives the full tree without cutting (we can cut manually)
agg.fit(X)

print(f"Number of merge steps: {agg.n_clusters_ - 1}")  # should equal number of points - 1
# Create a dendrogram using SciPy for visualization (optional)
Z = linkage(X, method='ward')
# Normally, you would plot the dendrogram. Here we'll just compute cluster labels for a chosen cut:
clusters_3 = AgglomerativeClustering(n_clusters=3, linkage='ward').fit_predict(X)
print(f"Labels with 3 clusters: {np.unique(clusters_3)}")
print(f"Cluster sizes for 3 clusters: {np.bincount(clusters_3)}")
```
</details>

### DBSCAN (Density-Based Spatial Clustering of Applications with Noise)

Το DBSCAN είναι ένας αλγόριθμος clustering βασισμένος στην πυκνότητα, ο οποίος ομαδοποιεί σημεία που βρίσκονται σε κοντινή απόσταση μεταξύ τους, ενώ επισημαίνει τα σημεία σε περιοχές χαμηλής πυκνότητας ως outliers. Είναι ιδιαίτερα χρήσιμος για datasets με μεταβαλλόμενες πυκνότητες και μη σφαιρικά σχήματα.

Το DBSCAN λειτουργεί ορίζοντας δύο παραμέτρους:
- **Epsilon (ε)**: Η μέγιστη απόσταση μεταξύ δύο σημείων ώστε να θεωρούνται μέρος του ίδιου cluster.
- **MinPts**: Ο ελάχιστος αριθμός σημείων που απαιτείται για τον σχηματισμό μιας πυκνής περιοχής (core point).

Το DBSCAN αναγνωρίζει core points, border points και noise points:
- **Core Point**: Ένα σημείο με τουλάχιστον MinPts γείτονες σε απόσταση ε.
- **Border Point**: Ένα σημείο που βρίσκεται σε απόσταση ε από ένα core point, αλλά έχει λιγότερους από MinPts γείτονες.
- **Noise Point**: Ένα σημείο που δεν είναι ούτε core point ούτε border point.

Το clustering ξεκινά επιλέγοντας ένα μη επισκέψιμο core point, επισημαίνοντάς το ως νέο cluster και στη συνέχεια προσθέτοντας αναδρομικά όλα τα σημεία που είναι density-reachable από αυτό (core points και οι γείτονές τους κ.λπ.). Τα border points προστίθενται στο cluster ενός κοντινού core point. Αφού επεκταθούν όλα τα προσβάσιμα σημεία, το DBSCAN μετακινείται σε ένα άλλο μη επισκέψιμο core point για να ξεκινήσει νέο cluster. Τα σημεία που δεν προσεγγίζονται από κανένα core point παραμένουν επισημασμένα ως noise.

> [!TIP]
> *Use cases in cybersecurity:* Το DBSCAN είναι χρήσιμο για anomaly detection στην κίνηση δικτύου. Για παράδειγμα, η φυσιολογική δραστηριότητα των χρηστών μπορεί να σχηματίζει ένα ή περισσότερα πυκνά clusters στον χώρο χαρακτηριστικών, ενώ νέες συμπεριφορές επιθέσεων εμφανίζονται ως διάσπαρτα σημεία, τα οποία το DBSCAN θα επισημάνει ως noise (outliers). Έχει χρησιμοποιηθεί για clustering εγγραφών network flow, όπου μπορεί να ανιχνεύσει port scans ή κίνηση denial-of-service ως αραιές περιοχές σημείων. Μια άλλη εφαρμογή είναι η ομαδοποίηση παραλλαγών malware: αν τα περισσότερα δείγματα ομαδοποιούνται ανά οικογένεια, αλλά μερικά δεν ταιριάζουν πουθενά, αυτά τα λίγα θα μπορούσαν να είναι zero-day malware. Η δυνατότητα επισήμανσης του noise επιτρέπει στις ομάδες ασφάλειας να επικεντρωθούν στη διερεύνηση αυτών των outliers.

#### Assumptions and Limitations

**Assumptions & Strengths:**: Το DBSCAN δεν υποθέτει σφαιρικά clusters – μπορεί να εντοπίσει clusters αυθαίρετου σχήματος (ακόμη και σε μορφή αλυσίδας ή γειτονικά clusters). Καθορίζει αυτόματα τον αριθμό των clusters με βάση την πυκνότητα των δεδομένων και μπορεί να αναγνωρίσει αποτελεσματικά τα outliers ως noise. Αυτό το καθιστά ισχυρό για δεδομένα πραγματικού κόσμου με ακανόνιστα σχήματα και noise. Είναι ανθεκτικό στα outliers (σε αντίθεση με το K-Means, το οποίο τα αναγκάζει να ενταχθούν σε clusters). Λειτουργεί καλά όταν τα clusters έχουν περίπου ομοιόμορφη πυκνότητα.

**Limitations**: Η απόδοση του DBSCAN εξαρτάται από την επιλογή κατάλληλων τιμών για τα ε και MinPts. Μπορεί να δυσκολευτεί με δεδομένα που έχουν μεταβαλλόμενες πυκνότητες – ένα μόνο ε δεν μπορεί να προσαρμοστεί ταυτόχρονα σε πυκνά και αραιά clusters. Αν το ε είναι πολύ μικρό, επισημαίνει τα περισσότερα σημεία ως noise· αν είναι πολύ μεγάλο, τα clusters μπορεί να συγχωνευθούν εσφαλμένα. Επίσης, το DBSCAN μπορεί να είναι αναποτελεσματικό σε πολύ μεγάλα datasets (naively $O(n^2)$, αν και το spatial indexing μπορεί να βοηθήσει). Σε χώρους χαρακτηριστικών υψηλής διάστασης, η έννοια της «απόστασης εντός ε» μπορεί να είναι λιγότερο ουσιαστική (curse of dimensionality), και το DBSCAN μπορεί να χρειάζεται προσεκτική ρύθμιση παραμέτρων ή να αποτυγχάνει να εντοπίσει διαισθητικά clusters. Παρά τους περιορισμούς αυτούς, επεκτάσεις όπως το HDBSCAN αντιμετωπίζουν ορισμένα ζητήματα (όπως τη μεταβαλλόμενη πυκνότητα).

<details>
<summary>Example -- Clustering with Noise
</summary>
```python
from sklearn.cluster import DBSCAN

# Generate synthetic data: 2 normal clusters and 5 outlier points
cluster1 = rng.normal(loc=[100, 1000], scale=[5, 100], size=(100, 2))
cluster2 = rng.normal(loc=[120, 2000], scale=[5, 100], size=(100, 2))
outliers = rng.uniform(low=[50, 50], high=[180, 3000], size=(5, 2))  # scattered anomalies
data = np.vstack([cluster1, cluster2, outliers])

# Run DBSCAN with chosen eps and MinPts
eps = 15.0   # radius for neighborhood
min_pts = 5  # minimum neighbors to form a dense region
db = DBSCAN(eps=eps, min_samples=min_pts).fit(data)
labels = db.labels_  # cluster labels (-1 for noise)

# Analyze clusters and noise
num_clusters = len(set(labels) - {-1})
num_noise = np.sum(labels == -1)
print(f"DBSCAN found {num_clusters} clusters and {num_noise} noise points")
print("Cluster labels for first 10 points:", labels[:10])
```
Σε αυτό το snippet, προσαρμόσαμε τα `eps` και `min_samples` ώστε να ταιριάζουν στην κλίμακα των δεδομένων μας (15.0 σε μονάδες χαρακτηριστικών και απαίτηση 5 σημείων για τον σχηματισμό cluster). Το DBSCAN θα πρέπει να εντοπίσει 2 clusters (τα clusters κανονικής κίνησης) και να επισημάνει τα 5 injected outliers ως noise. Εμφανίζουμε τον αριθμό των clusters σε σχέση με τα noise points για να το επαληθεύσουμε. Σε ένα πραγματικό περιβάλλον, θα μπορούσε κανείς να επαναλάβει τη διαδικασία για διαφορετικές τιμές των ε (χρησιμοποιώντας ένα k-distance graph heuristic για την επιλογή του ε) και του MinPts (συχνά ορίζεται περίπου ίσο με τη διαστατικότητα των δεδομένων + 1, ως εμπειρικός κανόνας), ώστε να εντοπίσει σταθερά αποτελέσματα clustering. Η δυνατότητα ρητής επισήμανσης του noise βοηθά στον διαχωρισμό πιθανών attack data για περαιτέρω ανάλυση.

</details>

### Principal Component Analysis (PCA)

Το PCA είναι μια τεχνική **μείωσης διαστατικότητας** που βρίσκει ένα νέο σύνολο ορθογώνιων αξόνων (principal components), οι οποίοι αποτυπώνουν τη μέγιστη διακύμανση των δεδομένων. Με απλά λόγια, το PCA περιστρέφει και προβάλλει τα δεδομένα σε ένα νέο σύστημα συντεταγμένων, έτσι ώστε το πρώτο principal component (PC1) να εξηγεί τη μεγαλύτερη δυνατή διακύμανση, το δεύτερο PC (PC2) να εξηγεί τη μεγαλύτερη διακύμανση που είναι ορθογώνια προς το PC1 και ούτω καθεξής. Μαθηματικά, το PCA υπολογίζει τα eigenvectors του covariance matrix των δεδομένων - αυτά τα eigenvectors είναι οι κατευθύνσεις των principal components, ενώ τα αντίστοιχα eigenvalues υποδεικνύουν το ποσοστό διακύμανσης που εξηγεί το καθένα. Χρησιμοποιείται συχνά για feature extraction, visualization και noise reduction.

Σημειώστε ότι αυτό είναι χρήσιμο όταν οι διαστάσεις του dataset περιέχουν **σημαντικές γραμμικές εξαρτήσεις ή συσχετίσεις**.

Το PCA λειτουργεί εντοπίζοντας τα principal components των δεδομένων, τα οποία είναι οι κατευθύνσεις μέγιστης διακύμανσης. Τα βήματα του PCA είναι:
1. **Standardization**: Κεντράρουμε τα δεδομένα αφαιρώντας τον μέσο όρο και κλιμακώνοντάς τα σε μοναδιαία διακύμανση.
2. **Covariance Matrix**: Υπολογίζουμε το covariance matrix των standardized δεδομένων, ώστε να κατανοήσουμε τις σχέσεις μεταξύ των χαρακτηριστικών.
3. **Eigenvalue Decomposition**: Εκτελούμε eigenvalue decomposition στο covariance matrix για να λάβουμε τα eigenvalues και τα eigenvectors.
4. **Select Principal Components**: Ταξινομούμε τα eigenvalues σε φθίνουσα σειρά και επιλέγουμε τα κορυφαία K eigenvectors που αντιστοιχούν στα μεγαλύτερα eigenvalues. Αυτά τα eigenvectors σχηματίζουν τον νέο χώρο χαρακτηριστικών.
5. **Transform Data**: Προβάλλουμε τα αρχικά δεδομένα στον νέο χώρο χαρακτηριστικών χρησιμοποιώντας τα επιλεγμένα principal components.
Το PCA χρησιμοποιείται ευρέως για data visualization, noise reduction και ως βήμα preprocessing για άλλους machine learning algorithms. Βοηθά στη μείωση της διαστατικότητας των δεδομένων, διατηρώντας παράλληλα την ουσιώδη δομή τους.

#### Eigenvalues και Eigenvectors

Ένα eigenvalue είναι ένας scalar που υποδεικνύει το ποσοστό διακύμανσης που αποτυπώνει το αντίστοιχο eigenvector. Ένα eigenvector αναπαριστά μια κατεύθυνση στον χώρο χαρακτηριστικών, κατά μήκος της οποίας τα δεδομένα μεταβάλλονται περισσότερο.

Φανταστείτε ότι το A είναι ένας square matrix και το v είναι ένα μη μηδενικό vector, έτσι ώστε: `A * v = λ * v`
όπου:
- Το A είναι ένας square matrix, όπως ο [ [1, 2], [2, 1]] (π.χ., covariance matrix)
- Το v είναι ένα eigenvector (π.χ., [1, 1])

Τότε, `A * v = [ [1, 2], [2, 1]] * [1, 1] = [3, 3]`, το οποίο θα είναι το eigenvalue λ πολλαπλασιασμένο με το eigenvector v, άρα το eigenvalue λ = 3.

#### Eigenvalues και Eigenvectors στο PCA

Ας το εξηγήσουμε με ένα παράδειγμα. Φανταστείτε ότι έχετε ένα dataset με πολλές grey scale εικόνες προσώπων διαστάσεων 100x100 pixels. Κάθε pixel μπορεί να θεωρηθεί feature, επομένως έχετε 10.000 features ανά εικόνα (ή ένα vector 10000 components ανά εικόνα). Αν θέλετε να μειώσετε τη διαστατικότητα αυτού του dataset χρησιμοποιώντας PCA, θα ακολουθούσατε τα εξής βήματα:

1. **Standardization**: Κεντράρουμε τα δεδομένα αφαιρώντας από το dataset τον μέσο όρο κάθε feature (pixel).
2. **Covariance Matrix**: Υπολογίζουμε το covariance matrix των standardized δεδομένων, το οποίο αποτυπώνει τον τρόπο με τον οποίο τα features (pixels) μεταβάλλονται από κοινού.
- Σημειώστε ότι η covariance μεταξύ δύο μεταβλητών (στη συγκεκριμένη περίπτωση, pixels) υποδεικνύει σε ποιον βαθμό μεταβάλλονται μαζί. Επομένως, η ιδέα εδώ είναι να εντοπίσουμε ποια pixels τείνουν να αυξάνονται ή να μειώνονται μαζί με γραμμική σχέση.
- Για παράδειγμα, αν το pixel 1 και το pixel 2 τείνουν να αυξάνονται μαζί, η covariance μεταξύ τους θα είναι θετική.
- Το covariance matrix θα είναι ένας πίνακας 10,000x10,000, όπου κάθε entry αναπαριστά την covariance μεταξύ δύο pixels.
3. **Solve the The eigenvalue equation**: Η eigenvalue equation που πρέπει να επιλυθεί είναι `C * v = λ * v`, όπου το C είναι το covariance matrix, το v είναι το eigenvector και το λ είναι το eigenvalue. Μπορεί να επιλυθεί χρησιμοποιώντας μεθόδους όπως:
- **Eigenvalue Decomposition**: Εκτελούμε eigenvalue decomposition στο covariance matrix για να λάβουμε τα eigenvalues και τα eigenvectors.
- **Singular Value Decomposition (SVD)**: Εναλλακτικά, μπορείτε να χρησιμοποιήσετε το SVD για να αποσυνθέσετε το data matrix σε singular values και vectors, τα οποία μπορούν επίσης να αποδώσουν τα principal components.
4. **Select Principal Components**: Ταξινομούμε τα eigenvalues σε φθίνουσα σειρά και επιλέγουμε τα κορυφαία K eigenvectors που αντιστοιχούν στα μεγαλύτερα eigenvalues. Αυτά τα eigenvectors αναπαριστούν τις κατευθύνσεις μέγιστης διακύμανσης στα δεδομένα.

> [!TIP]
> *Use cases in cybersecurity:* Μια συνηθισμένη χρήση του PCA στην ασφάλεια είναι η μείωση χαρακτηριστικών για anomaly detection. Για παράδειγμα, ένα intrusion detection system με περισσότερα από 40 network metrics (όπως τα NSL-KDD features) μπορεί να χρησιμοποιήσει PCA για να μειώσει τα δεδομένα σε λίγα components, συνοψίζοντάς τα για visualization ή για τροφοδότηση clustering algorithms. Οι analysts μπορούν να σχεδιάσουν την network traffic στον χώρο των δύο πρώτων principal components, ώστε να δουν αν τα attacks διαχωρίζονται από την κανονική κίνηση. Το PCA μπορεί επίσης να βοηθήσει στην εξάλειψη redundant features (όπως bytes sent και bytes received, αν συσχετίζονται), ώστε οι detection algorithms να γίνουν πιο robust και faster.

#### Assumptions και Limitations

Το PCA υποθέτει ότι οι **principal axes της διακύμανσης είναι meaningful** - είναι μια linear method, επομένως αποτυπώνει linear correlations στα δεδομένα. Είναι unsupervised, καθώς χρησιμοποιεί μόνο το feature covariance. Τα πλεονεκτήματα του PCA περιλαμβάνουν noise reduction (τα components μικρής διακύμανσης συχνά αντιστοιχούν σε noise) και decorrelation των features. Είναι computationally efficient για moderately high dimensions και συχνά αποτελεί χρήσιμο preprocessing step για άλλους algorithms (για τον περιορισμό του curse of dimensionality). Ένας περιορισμός είναι ότι το PCA περιορίζεται σε linear relationships - δεν αποτυπώνει complex nonlinear structure (ενώ τα autoencoders ή το t-SNE ενδέχεται να το κάνουν). Επίσης, τα PCA components μπορεί να είναι δύσκολο να ερμηνευθούν σε σχέση με τα original features (είναι συνδυασμοί των original features). Στην cybersecurity, απαιτείται προσοχή: ένα attack που προκαλεί μόνο μια subtle αλλαγή σε ένα low-variance feature μπορεί να μην εμφανιστεί στα top PCs (καθώς το PCA δίνει προτεραιότητα στη διακύμανση και όχι απαραίτητα στο “interestingness”).

<details>
<summary>Example -- Reducing Dimensions of Network Data
</summary>

Ας υποθέσουμε ότι έχουμε network connection logs με πολλά features (π.χ. durations, bytes, counts). Θα δημιουργήσουμε ένα synthetic 4-dimensional dataset (με κάποια συσχέτιση μεταξύ των features) και θα χρησιμοποιήσουμε PCA για να το μειώσουμε σε 2 dimensions για visualization ή περαιτέρω ανάλυση.
```python
from sklearn.decomposition import PCA

# Create synthetic 4D data (3 clusters similar to before, but add correlated features)
# Base features: duration, bytes (as before)
base_data = np.vstack([normal1, normal2, normal3])  # 1500 points from earlier normal clusters
# Add two more features correlated with existing ones, e.g. packets = bytes/50 + noise, errors = duration/10 + noise
packets = base_data[:, 1] / 50 + rng.normal(scale=0.5, size=len(base_data))
errors = base_data[:, 0] / 10 + rng.normal(scale=0.5, size=len(base_data))
data_4d = np.column_stack([base_data[:, 0], base_data[:, 1], packets, errors])

# Apply PCA to reduce 4D data to 2D
pca = PCA(n_components=2)
data_2d = pca.fit_transform(data_4d)
print("Explained variance ratio of 2 components:", pca.explained_variance_ratio_)
print("Original shape:", data_4d.shape, "Reduced shape:", data_2d.shape)
# We can examine a few transformed points
print("First 5 data points in PCA space:\n", data_2d[:5])
```
Εδώ πήραμε τα προηγούμενα clusters κανονικής κίνησης και επεκτείναμε κάθε data point με δύο επιπλέον features (packets και errors) που συσχετίζονται με τα bytes και τη duration. Στη συνέχεια χρησιμοποιείται PCA για τη συμπίεση των 4 features σε 2 principal components. Εκτυπώνουμε το explained variance ratio, το οποίο μπορεί να δείξει ότι, για παράδειγμα, >95% της διακύμανσης αποτυπώνεται από τα 2 components (άρα υπάρχει μικρή απώλεια πληροφοριών). Το output δείχνει επίσης ότι το σχήμα των δεδομένων μειώνεται από (1500, 4) σε (1500, 2). Τα πρώτα σημεία στον χώρο του PCA δίνονται ως παράδειγμα. Στην πράξη, θα μπορούσε κανείς να σχεδιάσει το data_2d για να ελέγξει οπτικά αν τα clusters διακρίνονται. Αν υπήρχε anomaly, μπορεί να εμφανιζόταν ως ένα σημείο που βρίσκεται μακριά από το κύριο cluster στον χώρο του PCA. Επομένως, το PCA βοηθά στη συμπύκνωση σύνθετων δεδομένων σε μια διαχειρίσιμη μορφή για ανθρώπινη ερμηνεία ή ως input σε άλλους αλγορίθμους.

</details>


### Gaussian Mixture Models (GMM)

Ένα Gaussian Mixture Model θεωρεί ότι τα δεδομένα παράγονται από ένα μείγμα **πολλών Gaussian (normal) distributions με άγνωστες παραμέτρους**. Στην ουσία, είναι ένα probabilistic clustering model: προσπαθεί να αντιστοιχίσει soft κάθε σημείο σε ένα από τα K Gaussian components. Κάθε Gaussian component k διαθέτει ένα mean vector (μ_k), ένα covariance matrix (Σ_k) και ένα mixing weight (π_k), το οποίο αντιπροσωπεύει το πόσο συχνά εμφανίζεται το συγκεκριμένο cluster. Σε αντίθεση με το K-Means, το οποίο πραγματοποιεί “hard” assignments, το GMM δίνει σε κάθε σημείο μια πιθανότητα να ανήκει σε κάθε cluster.

Το fitting ενός GMM πραγματοποιείται συνήθως μέσω του αλγορίθμου Expectation-Maximization (EM):

- **Initialization**: Ξεκινάμε με αρχικές εκτιμήσεις για τα means, τα covariances και τους mixing coefficients (ή χρησιμοποιούμε τα αποτελέσματα του K-Means ως starting point).

- **E-step (Expectation)**: Με δεδομένες τις τρέχουσες παραμέτρους, υπολογίζουμε την ευθύνη κάθε cluster για κάθε σημείο: ουσιαστικά `r_nk = P(z_k | x_n)`, όπου το z_k είναι η latent variable που υποδεικνύει τη συμμετοχή σε cluster για το σημείο x_n. Αυτό πραγματοποιείται με χρήση του Bayes' theorem, όπου υπολογίζουμε την posterior probability κάθε σημείου να ανήκει σε κάθε cluster, με βάση τις τρέχουσες παραμέτρους. Οι responsibilities υπολογίζονται ως:
```math
r_{nk} = \frac{\pi_k \mathcal{N}(x_n | \mu_k, \Sigma_k)}{\sum_{j=1}^{K} \pi_j \mathcal{N}(x_n | \mu_j, \Sigma_j)}
```
όπου:
- \( \pi_k \) είναι ο mixing coefficient για το cluster k (prior probability του cluster k),
- \( \mathcal{N}(x_n | \mu_k, \Sigma_k) \) είναι η Gaussian probability density function για το σημείο \( x_n \), δεδομένων του mean \( \mu_k \) και του covariance \( \Sigma_k \).

- **M-step (Maximization)**: Ενημερώνουμε τις παραμέτρους χρησιμοποιώντας τις responsibilities που υπολογίστηκαν στο E-step:
- Ενημερώνουμε κάθε mean μ_k ως τον weighted average των σημείων, όπου τα weights είναι οι responsibilities.
- Ενημερώνουμε κάθε covariance Σ_k ως το weighted covariance των σημείων που αντιστοιχίστηκαν στο cluster k.
- Ενημερώνουμε τους mixing coefficients π_k ως τη μέση responsibility για το cluster k.

- **Iterate** τα E και M steps μέχρι τη σύγκλιση (οι παράμετροι σταθεροποιούνται ή η βελτίωση του likelihood βρίσκεται κάτω από ένα threshold).

Το αποτέλεσμα είναι ένα σύνολο Gaussian distributions που μοντελοποιούν συλλογικά τη συνολική distribution των δεδομένων. Μπορούμε να χρησιμοποιήσουμε το fitted GMM για clustering, αντιστοιχίζοντας κάθε σημείο στο Gaussian με την υψηλότερη πιθανότητα, ή να διατηρήσουμε τις πιθανότητες για uncertainty. Μπορούμε επίσης να αξιολογήσουμε το likelihood νέων σημείων, ώστε να ελέγξουμε αν ταιριάζουν στο model (κάτι χρήσιμο για anomaly detection).

> [!TIP]
> *Use cases in cybersecurity:* Το GMM μπορεί να χρησιμοποιηθεί για anomaly detection, μοντελοποιώντας τη distribution των normal δεδομένων: οποιοδήποτε σημείο έχει πολύ χαμηλή πιθανότητα υπό το learned mixture επισημαίνεται ως anomaly. Για παράδειγμα, θα μπορούσατε να εκπαιδεύσετε ένα GMM σε legitimate network traffic features· ένα attack connection που δεν μοιάζει με κανένα learned cluster θα είχε χαμηλό likelihood. Τα GMMs χρησιμοποιούνται επίσης για το clustering activities όπου τα clusters μπορεί να έχουν διαφορετικά shapes – για παράδειγμα, για grouping χρηστών με βάση behavior profiles, όπου τα features κάθε profile μπορεί να είναι Gaussian-like αλλά με τη δική τους variance structure. Ένα ακόμη σενάριο είναι το phishing detection: τα legitimate email features μπορεί να σχηματίζουν ένα Gaussian cluster, τα γνωστά phishing emails ένα άλλο και οι νέες phishing campaigns μπορεί να εμφανίζονται είτε ως ξεχωριστό Gaussian είτε ως σημεία με χαμηλό likelihood σε σχέση με το υπάρχον mixture.

#### Assumptions and Limitations

Το GMM είναι μια generalization του K-Means που ενσωματώνει covariance, επομένως τα clusters μπορούν να είναι ellipsoidal (όχι μόνο spherical). Διαχειρίζεται clusters διαφορετικών sizes και shapes, όταν το covariance είναι full. Το soft clustering αποτελεί πλεονέκτημα όταν τα cluster boundaries είναι ασαφή – για παράδειγμα, στο cybersecurity, ένα event μπορεί να έχει traits από πολλαπλούς attack types· το GMM μπορεί να αποτυπώσει αυτή την uncertainty μέσω probabilities. Το GMM παρέχει επίσης probabilistic density estimation των δεδομένων, κάτι χρήσιμο για τον εντοπισμό outliers (σημεία με χαμηλό likelihood υπό όλα τα mixture components).

Από την άλλη πλευρά, το GMM απαιτεί τον καθορισμό του αριθμού των components K (αν και μπορούν να χρησιμοποιηθούν criteria όπως τα BIC/AIC για την επιλογή του). Το EM μπορεί μερικές φορές να συγκλίνει αργά ή σε local optimum, επομένως το initialization είναι σημαντικό (συχνά εκτελείται το EM πολλές φορές). Αν τα δεδομένα δεν ακολουθούν πραγματικά ένα mixture από Gaussians, το model μπορεί να αποτελεί poor fit. Υπάρχει επίσης ο κίνδυνος ένα Gaussian να συρρικνωθεί ώστε να καλύπτει μόνο ένα outlier (αν και το regularization ή τα minimum covariance bounds μπορούν να περιορίσουν αυτό το πρόβλημα).


<details>
<summary>Παράδειγμα -- Soft Clustering & Anomaly Scores
</summary>
```python
from sklearn.mixture import GaussianMixture

# Fit a GMM with 3 components to the normal traffic data
gmm = GaussianMixture(n_components=3, covariance_type='full', random_state=0)
gmm.fit(base_data)  # using the 1500 normal data points from PCA example

# Print the learned Gaussian parameters
print("GMM means:\n", gmm.means_)
print("GMM covariance matrices:\n", gmm.covariances_)

# Take a sample attack-like point and evaluate it
sample_attack = np.array([[200, 800]])  # an outlier similar to earlier attack cluster
probs = gmm.predict_proba(sample_attack)
log_likelihood = gmm.score_samples(sample_attack)
print("Cluster membership probabilities for sample attack:", probs)
print("Log-likelihood of sample attack under GMM:", log_likelihood)
```
Σε αυτόν τον κώδικα, εκπαιδεύουμε ένα GMM με 3 Gaussian distributions στην κανονική κίνηση (υποθέτοντας ότι γνωρίζουμε 3 profiles νόμιμης κίνησης). Οι μέσες τιμές και οι συνδιακυμάνσεις που εμφανίζονται περιγράφουν αυτά τα clusters (για παράδειγμα, ένας μέσος όρος μπορεί να είναι περίπου [50,500], αντιστοιχώντας στο κέντρο ενός cluster κ.λπ.). Στη συνέχεια, ελέγχουμε μια ύποπτη σύνδεση [duration=200, bytes=800]. Η `predict_proba` δίνει την πιθανότητα αυτό το σημείο να ανήκει σε καθένα από τα 3 clusters – θα περιμέναμε αυτές οι πιθανότητες να είναι πολύ χαμηλές ή έντονα skewed, καθώς το [200,800] απέχει πολύ από τα normal clusters. Εμφανίζεται το συνολικό `score_samples` (log-likelihood). Μια πολύ χαμηλή τιμή υποδεικνύει ότι το σημείο δεν ταιριάζει καλά στο model, επισημαίνοντάς το ως anomaly. Στην πράξη, θα μπορούσε να οριστεί ένα threshold στο log-likelihood (ή στο max probability), ώστε να αποφασίζεται αν ένα σημείο είναι αρκετά απίθανο για να θεωρηθεί malicious. Επομένως, το GMM παρέχει έναν principled τρόπο για anomaly detection και παράλληλα παράγει soft clusters που λαμβάνουν υπόψη την αβεβαιότητα.
</details>

### Isolation Forest

Το **Isolation Forest** είναι ένας ensemble algorithm για anomaly detection, βασισμένος στην ιδέα της τυχαίας απομόνωσης σημείων. Η αρχή είναι ότι τα anomalies είναι λίγα και διαφορετικά, επομένως απομονώνονται ευκολότερα από τα normal points. Ένα Isolation Forest δημιουργεί πολλά binary isolation trees (random decision trees), τα οποία διαχωρίζουν τα δεδομένα τυχαία. Σε κάθε node ενός tree, επιλέγεται ένα random feature και μια random τιμή split μεταξύ του min και του max αυτού του feature για τα δεδομένα του συγκεκριμένου node. Αυτό το split χωρίζει τα δεδομένα σε δύο branches. Το tree αναπτύσσεται μέχρι κάθε point να απομονωθεί στο δικό του leaf ή να επιτευχθεί το μέγιστο ύψος του tree.

Η anomaly detection πραγματοποιείται παρατηρώντας το path length κάθε point σε αυτά τα random trees – δηλαδή, τον αριθμό των splits που απαιτούνται για την απομόνωση του point. Διαισθητικά, τα anomalies (outliers) τείνουν να απομονώνονται γρηγορότερα, επειδή ένα random split είναι πιθανότερο να διαχωρίσει ένα outlier (το οποίο βρίσκεται σε sparse region) απ' ό,τι ένα normal point σε ένα dense cluster. Το Isolation Forest υπολογίζει ένα anomaly score από το average path length σε όλα τα trees: μικρότερο average path → περισσότερο anomalous. Τα scores συνήθως κανονικοποιούνται στο [0,1], όπου το 1 σημαίνει πολύ πιθανό anomaly.

> [!TIP]
> *Use cases in cybersecurity:* Τα Isolation Forests έχουν χρησιμοποιηθεί επιτυχώς σε intrusion detection και fraud detection. Για παράδειγμα, εκπαιδεύστε ένα Isolation Forest σε network traffic logs που περιέχουν κυρίως normal behavior· το forest θα παράγει σύντομα paths για ασυνήθιστη κίνηση (όπως ένα IP που χρησιμοποιεί ένα unheard-of port ή ένα ασυνήθιστο packet size pattern), επισημαίνοντάς την για έλεγχο. Επειδή δεν απαιτεί labeled attacks, είναι κατάλληλο για την ανίχνευση άγνωστων τύπων attacks. Μπορεί επίσης να αναπτυχθεί σε user login data για την ανίχνευση account takeovers (οι anomalous ώρες ή τοποθεσίες σύνδεσης απομονώνονται γρήγορα). Σε ένα use-case, ένα Isolation Forest θα μπορούσε να προστατεύει μια enterprise παρακολουθώντας system metrics και δημιουργώντας alert όταν ένας συνδυασμός metrics (CPU, network, file changes) φαίνεται πολύ διαφορετικός (short isolation paths) από τα historical patterns.

#### Assumptions and Limitations

**Advantages**: Το Isolation Forest δεν απαιτεί assumption σχετικά με distribution· στοχεύει άμεσα στην απομόνωση. Είναι αποδοτικό σε high-dimensional data και large datasets (linear complexity $O(n\log n)$ για τη δημιουργία του forest), καθώς κάθε tree απομονώνει points χρησιμοποιώντας μόνο ένα subset των features και των splits. Τείνει να χειρίζεται καλά τα numerical features και μπορεί να είναι ταχύτερο από distance-based methods, οι οποίες μπορεί να έχουν complexity $O(n^2)$. Παρέχει επίσης αυτόματα ένα anomaly score, επομένως μπορείτε να ορίσετε ένα threshold για alerts (ή να χρησιμοποιήσετε μια παράμετρο contamination, ώστε να αποφασίζεται αυτόματα ένα cutoff με βάση το αναμενόμενο ποσοστό anomalies).

**Limitations**: Λόγω της random φύσης του, τα αποτελέσματα μπορεί να διαφέρουν ελαφρώς μεταξύ των runs (αν και, με αρκετά trees, αυτή η διαφορά είναι μικρή). Αν τα δεδομένα περιέχουν πολλά irrelevant features ή αν τα anomalies δεν διαφοροποιούνται έντονα σε κάποιο feature, η απομόνωση μπορεί να μην είναι αποτελεσματική (τα random splits μπορεί να απομονώσουν normal points κατά τύχη – ωστόσο, το averaging πολλών trees μετριάζει αυτό το πρόβλημα). Επιπλέον, το Isolation Forest γενικά υποθέτει ότι τα anomalies αποτελούν μια μικρή μειοψηφία (κάτι που συνήθως ισχύει σε cybersecurity scenarios).

<details>
<summary>Example -- Detecting Outliers in Network Logs
</summary>

Θα χρησιμοποιήσουμε το προηγούμενο test dataset (το οποίο περιέχει normal και ορισμένα attack points) και θα εκτελέσουμε ένα Isolation Forest, για να δούμε αν μπορεί να διαχωρίσει τα attacks. Θα υποθέσουμε ότι περιμένουμε περίπου το 15% των δεδομένων να είναι anomalous (για σκοπούς επίδειξης).
```python
from sklearn.ensemble import IsolationForest

# Combine normal and attack test data from autoencoder example
X_test_if = test_data  # (120 x 2 array with 100 normal and 20 attack points)
# Train Isolation Forest (unsupervised) on the test set itself for demo (in practice train on known normal)
iso_forest = IsolationForest(n_estimators=100, contamination=0.15, random_state=0)
iso_forest.fit(X_test_if)
# Predict anomalies (-1 for anomaly, 1 for normal)
preds = iso_forest.predict(X_test_if)
anomaly_scores = iso_forest.decision_function(X_test_if)  # the higher, the more normal
print("Isolation Forest predicted labels (first 20):", preds[:20])
print("Number of anomalies detected:", np.sum(preds == -1))
print("Example anomaly scores (lower means more anomalous):", anomaly_scores[:5])
```
Σε αυτόν τον κώδικα, δημιουργούμε ένα instance του `IsolationForest` με 100 δέντρα και ορίζουμε `contamination=0.15` (δηλαδή αναμένουμε περίπου 15% anomalies· το model θα ορίσει το κατώφλι του score έτσι ώστε περίπου το 15% των σημείων να επισημαίνονται). Το εκπαιδεύουμε στο `X_test_if`, το οποίο περιέχει έναν συνδυασμό από normal και attack points (σημείωση: κανονικά θα το εκπαιδεύαμε σε training data και στη συνέχεια θα χρησιμοποιούσαμε το predict σε νέα data, αλλά εδώ, για λόγους επίδειξης, εκπαιδεύουμε και κάνουμε predict στο ίδιο set ώστε να παρατηρήσουμε άμεσα τα αποτελέσματα).

Η έξοδος εμφανίζει τα predicted labels για τα πρώτα 20 points (όπου το -1 υποδεικνύει anomaly). Επίσης, εκτυπώνουμε πόσα anomalies εντοπίστηκαν συνολικά και μερικά παραδείγματα anomaly scores. Θα αναμέναμε περίπου 18 από τα 120 points να έχουν label -1 (καθώς το contamination ήταν 15%). Αν τα 20 attack samples είναι πράγματι τα πιο ακραία, τα περισσότερα από αυτά θα πρέπει να εμφανίζονται σε εκείνα τα -1 predictions. Το anomaly score (η decision function του Isolation Forest) είναι υψηλότερο για τα normal points και χαμηλότερο (πιο αρνητικό) για τα anomalies – εκτυπώνουμε μερικές τιμές για να δούμε τον διαχωρισμό. Στην πράξη, θα μπορούσε κανείς να ταξινομήσει τα data σύμφωνα με το score, ώστε να δει τα κορυφαία outliers και να τα διερευνήσει. Επομένως, το Isolation Forest παρέχει έναν αποδοτικό τρόπο για το φιλτράρισμα μεγάλων unlabeled security data και την επιλογή των πιο μη κανονικών instances για human analysis ή περαιτέρω automated scrutiny.
</details>


### t-SNE (t-Distributed Stochastic Neighbor Embedding)

Το **t-SNE** είναι μια nonlinear dimensionality reduction technique, σχεδιασμένη ειδικά για την οπτικοποίηση high-dimensional data σε 2 ή 3 dimensions. Μετατρέπει τις ομοιότητες μεταξύ των data points σε joint probability distributions και προσπαθεί να διατηρήσει τη δομή των local neighborhoods στην projection χαμηλότερης διάστασης. Με απλούστερους όρους, το t-SNE τοποθετεί τα points σε (για παράδειγμα) 2D, έτσι ώστε τα παρόμοια points (στο original space) να καταλήγουν κοντά μεταξύ τους και τα διαφορετικά points να καταλήγουν μακριά το ένα από το άλλο με υψηλή πιθανότητα.

Ο αλγόριθμος έχει τρία βασικά στάδια:

1. **Compute pairwise affinities in high-dimensional space:** Για κάθε ζεύγος points, το t-SNE υπολογίζει την πιθανότητα να επιλεγεί το συγκεκριμένο ζεύγος ως neighbors (αυτό γίνεται με το centering μιας Gaussian distribution σε κάθε point και τη μέτρηση αποστάσεων – η παράμετρος perplexity επηρεάζει τον effective αριθμό των neighbors που λαμβάνονται υπόψη).
2. **Compute pairwise affinities in low-dimensional (e.g. 2D) space:** Αρχικά, τα points τοποθετούνται τυχαία σε 2D. Το t-SNE ορίζει μια παρόμοια probability για τις αποστάσεις σε αυτόν τον χάρτη (χρησιμοποιώντας ένα Student t-distribution kernel, το οποίο έχει heavier tails από το Gaussian, ώστε να επιτρέπει στα απομακρυσμένα points μεγαλύτερη ελευθερία).
3. **Gradient Descent:** Στη συνέχεια, το t-SNE μετακινεί επαναληπτικά τα points σε 2D, ώστε να ελαχιστοποιήσει την απόκλιση Kullback–Leibler (KL) μεταξύ της high-D affinity distribution και της low-D. Αυτό έχει ως αποτέλεσμα η διάταξη 2D να αντικατοπτρίζει όσο το δυνατόν περισσότερο τη high-D δομή – τα points που βρίσκονταν κοντά στο original space έλκονται μεταξύ τους, ενώ εκείνα που βρίσκονταν μακριά απωθούνται, μέχρι να επιτευχθεί ισορροπία.

Το αποτέλεσμα είναι συχνά ένα visually meaningful scatter plot, στο οποίο γίνονται εμφανή τα clusters των data.

> [!TIP]
> *Use cases in cybersecurity:* Το t-SNE χρησιμοποιείται συχνά για **την οπτικοποίηση high-dimensional security data για human analysis**. Για παράδειγμα, σε ένα security operations center, οι analysts θα μπορούσαν να πάρουν ένα event dataset με δεκάδες features (αριθμούς ports, συχνότητες, byte counts κ.λπ.) και να χρησιμοποιήσουν το t-SNE για να δημιουργήσουν ένα 2D plot. Τα attacks μπορεί να σχηματίζουν τα δικά τους clusters ή να διαχωρίζονται από τα normal data σε αυτό το plot, καθιστώντας τα ευκολότερα στον εντοπισμό. Έχει εφαρμοστεί σε malware datasets για την ανάδειξη ομαδοποιήσεων malware families ή σε network intrusion data, όπου διαφορετικοί τύποι attacks σχηματίζουν σαφώς διακριτά clusters, καθοδηγώντας την περαιτέρω investigation. Ουσιαστικά, το t-SNE παρέχει έναν τρόπο να δούμε τη δομή σε cyber data, η οποία διαφορετικά θα ήταν δυσνόητη.

#### Assumptions and Limitations

Το t-SNE είναι εξαιρετικό για visual discovery patterns. Μπορεί να αποκαλύψει clusters, subclusters και outliers που άλλες linear methods (όπως το PCA) ενδέχεται να μην εντοπίζουν. Έχει χρησιμοποιηθεί σε cybersecurity research για την οπτικοποίηση σύνθετων data, όπως malware behavior profiles ή network traffic patterns. Επειδή διατηρεί την local structure, είναι κατάλληλο για την ανάδειξη natural groupings.

Ωστόσο, το t-SNE είναι computationally heavier (περίπου $O(n^2)$), επομένως μπορεί να απαιτεί sampling για πολύ μεγάλα datasets. Διαθέτει επίσης hyperparameters (perplexity, learning rate, iterations), τα οποία μπορούν να επηρεάσουν την έξοδο – για παράδειγμα, διαφορετικές τιμές perplexity μπορεί να αποκαλύψουν clusters σε διαφορετικές scales. Τα t-SNE plots μπορεί μερικές φορές να παρερμηνευτούν – οι αποστάσεις στον χάρτη δεν έχουν άμεση globally meaningful ερμηνεία (εστιάζει στο local neighborhood, και ορισμένες φορές τα clusters μπορεί να εμφανίζονται τεχνητά καλά διαχωρισμένα). Επίσης, το t-SNE προορίζεται κυρίως για visualization· δεν παρέχει έναν straightforward τρόπο προβολής νέων data points χωρίς επανυπολογισμό και δεν προορίζεται να χρησιμοποιείται ως preprocessing για predictive modeling (το UMAP είναι μια alternative που αντιμετωπίζει ορισμένα από αυτά τα ζητήματα με μεγαλύτερη ταχύτητα).

<details>
<summary>Example -- Visualizing Network Connections
</summary>

Θα χρησιμοποιήσουμε το t-SNE για να μειώσουμε ένα multi-feature dataset σε 2D. Για λόγους επίδειξης, ας πάρουμε τα προηγούμενα 4D data (τα οποία περιείχαν 3 natural clusters από normal traffic) και ας προσθέσουμε μερικά anomaly points. Στη συνέχεια, θα εκτελέσουμε το t-SNE και θα οπτικοποιήσουμε τα αποτελέσματα (σε εννοιολογικό επίπεδο).
```python
# 1 ─────────────────────────────────────────────────────────────────────
#    Create synthetic 4-D dataset
#      • Three clusters of “normal” traffic (duration, bytes)
#      • Two correlated features: packets & errors
#      • Five outlier points to simulate suspicious traffic
# ──────────────────────────────────────────────────────────────────────
import numpy as np
import matplotlib.pyplot as plt
from sklearn.manifold import TSNE
from sklearn.preprocessing import StandardScaler

rng = np.random.RandomState(42)

# Base (duration, bytes) clusters
normal1 = rng.normal(loc=[50, 500],  scale=[10, 100], size=(500, 2))
normal2 = rng.normal(loc=[60, 1500], scale=[8,  200], size=(500, 2))
normal3 = rng.normal(loc=[70, 3000], scale=[5,  300], size=(500, 2))

base_data = np.vstack([normal1, normal2, normal3])       # (1500, 2)

# Correlated features
packets = base_data[:, 1] / 50 + rng.normal(scale=0.5, size=len(base_data))
errors  = base_data[:, 0] / 10 + rng.normal(scale=0.5, size=len(base_data))

data_4d = np.column_stack([base_data, packets, errors])  # (1500, 4)

# Outlier / attack points
outliers_4d = np.column_stack([
rng.normal(250, 1, size=5),     # extreme duration
rng.normal(1000, 1, size=5),    # moderate bytes
rng.normal(5, 1, size=5),       # very low packets
rng.normal(25, 1, size=5)       # high errors
])

data_viz = np.vstack([data_4d, outliers_4d])             # (1505, 4)

# 2 ─────────────────────────────────────────────────────────────────────
#    Standardize features (recommended for t-SNE)
# ──────────────────────────────────────────────────────────────────────
scaler = StandardScaler()
data_scaled = scaler.fit_transform(data_viz)

# 3 ─────────────────────────────────────────────────────────────────────
#    Run t-SNE to project 4-D → 2-D
# ──────────────────────────────────────────────────────────────────────
tsne = TSNE(
n_components=2,
perplexity=30,
learning_rate='auto',
init='pca',
random_state=0
)
data_2d = tsne.fit_transform(data_scaled)
print("t-SNE output shape:", data_2d.shape)  # (1505, 2)

# 4 ─────────────────────────────────────────────────────────────────────
#    Visualize: normal traffic vs. outliers
# ──────────────────────────────────────────────────────────────────────
plt.figure(figsize=(8, 6))
plt.scatter(
data_2d[:-5, 0], data_2d[:-5, 1],
label="Normal traffic",
alpha=0.6,
s=10
)
plt.scatter(
data_2d[-5:, 0], data_2d[-5:, 1],
label="Outliers / attacks",
alpha=0.9,
s=40,
marker="X",
edgecolor='k'
)

plt.title("t-SNE Projection of Synthetic Network Traffic")
plt.xlabel("t-SNE component 1")
plt.ylabel("t-SNE component 2")
plt.legend()
plt.tight_layout()
plt.show()
```
Εδώ συνδυάσαμε το προηγούμενο 4D normal dataset με μερικά extreme outliers (τα outliers έχουν ένα feature («duration») ορισμένο σε πολύ υψηλή τιμή κ.λπ., ώστε να προσομοιώσουμε ένα ασυνήθιστο μοτίβο). Εκτελούμε t-SNE με μια τυπική τιμή perplexity ίση με 30. Το output data_2d έχει shape (1505, 2). Δεν θα δημιουργήσουμε πραγματικά plot σε αυτό το κείμενο, αλλά αν το κάναμε, θα περιμέναμε να δούμε ίσως τρία συμπαγή clusters που αντιστοιχούν στα 3 normal clusters, ενώ τα 5 outliers θα εμφανίζονταν ως isolated points μακριά από αυτά τα clusters. Σε ένα interactive workflow, θα μπορούσαμε να χρωματίσουμε τα points σύμφωνα με το label τους (normal ή το cluster στο οποίο ανήκουν, έναντι anomaly), για να επαληθεύσουμε αυτή τη δομή. Ακόμη και χωρίς labels, ένας analyst θα μπορούσε να παρατηρήσει αυτά τα 5 points να βρίσκονται σε κενό χώρο στο 2D plot και να τα επισημάνει. Αυτό δείχνει πώς το t-SNE μπορεί να αποτελέσει ισχυρό βοήθημα για visual anomaly detection και cluster inspection σε cybersecurity data, συμπληρώνοντας τους automated algorithms παραπάνω.

</details>


### HDBSCAN (Hierarchical Density-Based Spatial Clustering of Applications with Noise)

Το **HDBSCAN** είναι μια επέκταση του DBSCAN που εξαλείφει την ανάγκη επιλογής μίας μοναδικής global τιμής `eps` και μπορεί να ανακτήσει clusters με **διαφορετική πυκνότητα**, δημιουργώντας μια ιεραρχία density-connected components και στη συνέχεια συμπυκνώνοντάς την. Σε σύγκριση με το vanilla DBSCAN, συνήθως

* εξάγει πιο intuitive clusters όταν ορισμένα clusters είναι dense και άλλα sparse,
* έχει μόνο μία πραγματική hyper-parameter (`min_cluster_size`) και ένα sensible default,
* παρέχει σε κάθε point μια *probability* συμμετοχής σε cluster και ένα **outlier score** (`outlier_scores_`), κάτι εξαιρετικά χρήσιμο για threat-hunting dashboards.<sup>[[1]](#references)</sup>

> [!TIP]
> *Use cases στο cybersecurity:* Το HDBSCAN είναι ιδιαίτερα δημοφιλές στα σύγχρονα threat-hunting pipelines – συχνά θα το δείτε μέσα σε notebook-based hunting playbooks που παρέχονται με commercial XDR suites. Μια πρακτική συνταγή είναι το clustering HTTP beaconing traffic κατά τη διάρκεια IR: το user-agent, το interval και το URI length συχνά σχηματίζουν αρκετά συμπαγή groups νόμιμων software updaters, ενώ τα C2 beacons παραμένουν ως tiny low-density clusters ή ως pure noise.

<details>
<summary>Example – Finding beaconing C2 channels</summary>
```python
import pandas as pd
from hdbscan import HDBSCAN
from sklearn.preprocessing import StandardScaler

# df has features extracted from proxy logs
features = [
"avg_interval",      # seconds between requests
"uri_length_mean",   # average URI length
"user_agent_entropy" # Shannon entropy of UA string
]
X = StandardScaler().fit_transform(df[features])

hdb = HDBSCAN(min_cluster_size=15,  # at least 15 similar beacons to be a group
metric="euclidean",
prediction_data=True)
labels = hdb.fit_predict(X)

df["cluster"] = labels
# Anything with label == -1 is noise → inspect as potential C2
suspects = df[df["cluster"] == -1]
print("Suspect beacon count:", len(suspects))
```
</details>

---

### Ζητήματα Robustness και Security – Poisoning & Adversarial Attacks (2023-2025)

Πρόσφατες μελέτες έδειξαν ότι οι **unsupervised learners *δεν* είναι άτρωτοι σε active attackers**:

* **Data-poisoning εναντίον anomaly detectors.** Οι Chen *et al.* (IEEE S&P 2024) απέδειξαν ότι η προσθήκη μόλις 3 % ειδικά διαμορφωμένου traffic μπορεί να μετατοπίσει το decision boundary των Isolation Forest και ECOD, έτσι ώστε τα πραγματικά attacks να φαίνονται φυσιολογικά. Οι συγγραφείς δημοσίευσαν ένα open-source PoC (`udo-poison`) που συνθέτει αυτόματα poison points.<sup>[[2]](#references)</sup>
* **Backdooring clustering models.** Η τεχνική *BadCME* (BlackHat EU 2023) εισάγει ένα μικρό trigger pattern· κάθε φορά που εμφανίζεται αυτό το trigger, ένας detector βασισμένος σε K-Means τοποθετεί αθόρυβα το event μέσα σε ένα “benign” cluster.
* **Evasion των DBSCAN/HDBSCAN.** Ένα ακαδημαϊκό pre-print του 2025 από το KU Leuven έδειξε ότι ένας attacker μπορεί να δημιουργήσει beaconing patterns που σκόπιμα πέφτουν σε density gaps, κρυμμένα ουσιαστικά μέσα σε labels *noise*.

Mitigations που κερδίζουν έδαφος:

1. **Model sanitisation / TRIM.** Πριν από κάθε retraining epoch, απορρίπτονται τα 1–2 % των points με το υψηλότερο loss (trimmed maximum likelihood), ώστε το poisoning να γίνεται σημαντικά δυσκολότερο.
2. **Consensus ensembling.** Συνδυάζονται αρκετοί heterogeneous detectors (π.χ. Isolation Forest + GMM + ECOD) και δημιουργείται alert αν οποιοδήποτε model επισημάνει ένα point. Η έρευνα δείχνει ότι αυτό αυξάνει το κόστος του attacker κατά >10×.
3. **Distance-based defence για clustering.** Επανυπολογίζονται τα clusters με `k` διαφορετικά random seeds και αγνοούνται τα points που μετακινούνται συνεχώς μεταξύ clusters.

---

### Modern Open-Source Tooling (2024-2025)

* Το **PyOD 2.x** (κυκλοφόρησε τον Μάιο του 2024) πρόσθεσε τους *ECOD*, *COPOD* και GPU-accelerated *AutoFormer* detectors. Πλέον περιλαμβάνει ένα `benchmark` sub-command που σας επιτρέπει να συγκρίνετε περισσότερους από 30 algorithms στο dataset σας με **μία γραμμή κώδικα**:
```bash
pyod benchmark --input logs.csv --label attack --n_jobs 8
```
* Το **Anomalib v1.5** (Φεβρουάριος 2025) εστιάζει στο vision, αλλά περιέχει επίσης μια generic υλοποίηση του **PatchCore** – χρήσιμη για screenshot-based phishing page detection.
* Το **scikit-learn 1.5** (Νοέμβριος 2024) εκθέτει επιτέλους το `score_samples` για το *HDBSCAN* μέσω του νέου `cluster.HDBSCAN` wrapper, επομένως δεν χρειάζεστε το external contrib package όταν χρησιμοποιείτε Python 3.12.

<details>
<summary>Γρήγορο παράδειγμα PyOD – ensemble ECOD + Isolation Forest</summary>
```python
from pyod.models import ECOD, IForest
from pyod.utils.data import generate_data, evaluate_print
from pyod.utils.example import visualize

X_train, y_train, X_test, y_test = generate_data(
n_train=5000, n_test=1000, n_features=16,
contamination=0.02, random_state=42)

models = [ECOD(), IForest()]

# majority vote – flag if any model thinks it is anomalous
anomaly_scores = sum(m.fit(X_train).decision_function(X_test) for m in models) / len(models)

evaluate_print("Ensemble", y_test, anomaly_scores)
```
</details>

## Αναφορές

- [1] [HDBSCAN – Ιεραρχική ομαδοποίηση βάσει πυκνότητας](https://github.com/scikit-learn-contrib/hdbscan)
- [2] Chen, X. *et al.* «Η ευπάθεια του Unsupervised Anomaly Detection σε Data Poisoning». *IEEE Symposium on Security and Privacy*, 2024.



{{#include ../banners/hacktricks-training.md}}
