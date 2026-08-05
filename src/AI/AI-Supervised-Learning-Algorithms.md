# Supervised Learning Algorithms

{{#include ../banners/hacktricks-training.md}}

## Basic Information

Supervised learning, yeni ve daha önce görülmemiş girdiler hakkında tahminler yapabilen modelleri eğitmek için etiketli verileri kullanır. Cybersecurity alanında supervised machine learning; izinsiz giriş tespiti (ağ trafiğini *normal* veya *attack* olarak sınıflandırma), malware detection (kötü amaçlı yazılımları benign yazılımlardan ayırma), phishing detection (sahte web sitelerini veya e-postaları tespit etme) ve spam filtering gibi görevlerde yaygın olarak kullanılır. Her algorithm farklı güçlü yönlere sahiptir ve farklı problem türlerine (classification veya regression) uygundur. Aşağıda temel supervised learning algorithms konularını inceliyor, nasıl çalıştıklarını açıklıyor ve gerçek cybersecurity datasets üzerinde kullanımlarını gösteriyoruz. Ayrıca modellerin birleştirilmesinin (ensemble learning) tahmin performansını çoğu zaman nasıl artırabileceğini de ele alıyoruz.

## Algorithms

-   **Linear Regression:** Verilere bir doğrusal denklem uydurarak sayısal sonuçları tahmin etmek için kullanılan temel bir regression algorithm.

-   **Logistic Regression:** İkili bir sonucun olasılığını modellemek için logistic function kullanan bir classification algorithm (adına rağmen).

-   **Decision Trees:** Tahmin yapmak için verileri feature'lara göre bölen, ağaç yapısındaki modeller; genellikle yorumlanabilirlikleri nedeniyle kullanılır.

-   **Random Forests:** Doğruluğu artıran ve overfitting'i azaltan, decision trees topluluğu (bagging yoluyla).

-   **Support Vector Machines (SVM):** En uygun ayırıcı hyperplane'i bulan, maksimum marjlı classifier'lar; non-linear veriler için kernel'lar kullanabilir.

-   **Naive Bayes:** Feature'ların bağımsız olduğu varsayımıyla Bayes' theorem'e dayanan ve spam filtering'de yaygın olarak kullanılan olasılıksal bir classifier.

-   **k-Nearest Neighbors (k-NN):** Bir sample'ı en yakın komşularının çoğunluk sınıfına göre etiketleyen basit, "instance-based" bir classifier.

-   **Gradient Boosting Machines:** Daha zayıf learner'ları (genellikle decision trees) art arda ekleyerek güçlü bir predictor oluşturan ensemble modelleri (ör. XGBoost, LightGBM).

Aşağıdaki her bölüm algorithm hakkında geliştirilmiş bir açıklama ve `pandas` ile `scikit-learn` gibi kütüphaneleri (ve neural network örneği için `PyTorch`) kullanan bir **Python code example** sunar. Örnekler, herkese açık cybersecurity datasets'lerini (izinsiz giriş tespiti için NSL-KDD ve bir Phishing Websites dataset'i gibi) kullanır ve tutarlı bir yapı izler:

1.  **Load the dataset** (varsa URL üzerinden indirme).

2.  **Preprocess the data** (ör. categorical features'ları encode etme, değerleri scale etme, train/test set'lerine ayırma).

3.  **Train the model** training data üzerinde.

4.  Classification için accuracy, precision, recall, F1-score ve ROC AUC; regression için ise mean squared error metric'lerini kullanarak bir test seti üzerinde **Evaluate** etme.

Her algorithm'a göz atalım:

### Linear Regression

Linear regression, sürekli sayısal değerleri tahmin etmek için kullanılan bir **regression** algorithm'dir. Girdi feature'ları (independent variables) ile çıktı (dependent variable) arasında doğrusal bir ilişki olduğunu varsayar. Model, feature'lar ile target arasındaki ilişkiyi en iyi şekilde açıklayan düz bir çizgi (veya daha yüksek boyutlarda hyperplane) uydurmaya çalışır. Bu işlem genellikle tahmin edilen ve gerçek değerler arasındaki squared errors toplamının minimize edilmesiyle gerçekleştirilir (Ordinary Least Squares method).<sup>[[8]](#references)</sup>

Linear regression'ı temsil etmenin en basit biçimi bir doğrudur:
```plaintext
y = mx + b
```
Nerede:

- `y` tahmin edilen değerdir (çıktı)
- `m` doğrunun eğimidir (katsayı)
- `x` girdi özelliğidir
- `b` y-kesişimidir

Linear regression'ın amacı, veri kümesindeki tahmin edilen değerlerle gerçek değerler arasındaki farkı en aza indiren en uygun doğruyu bulmaktır. Elbette bu çok basittir; iki kategoriyi ayıran düz bir doğru olur. Ancak daha fazla boyut eklenirse doğru daha karmaşık hale gelir:
```plaintext
y = w1*x1 + w2*x2 + ... + wn*xn + b
```
> [!TIP]
> *Siber güvenlikte kullanım alanları:* Linear regression, temel güvenlik görevlerinde (bunlar çoğunlukla classification görevleridir) daha az yaygındır, ancak sayısal sonuçları tahmin etmek için uygulanabilir. Örneğin, geçmiş verilere dayanarak **network traffic hacmini tahmin etmek** veya **belirli bir zaman aralığındaki saldırı sayısını tahmin etmek** için linear regression kullanılabilir. Ayrıca belirli sistem metrikleri verildiğinde bir risk skorunu veya bir saldırının tespit edilmesine kadar geçmesi beklenen süreyi tahmin edebilir. Uygulamada, izinsiz girişleri veya malware'i tespit etmek için classification algorithms (logistic regression veya trees gibi) daha sık kullanılır; ancak linear regression, regression odaklı analizler için bir temel oluşturur ve kullanışlıdır.

#### **Linear Regression'ın temel özellikleri:**

-   **Problem türü:** Regression (sürekli değerleri tahmin etme). Çıktıya bir eşik uygulanmadığı sürece doğrudan classification için uygun değildir.

-   **Yorumlanabilirlik:** Yüksek -- katsayıların yorumlanması kolaydır ve her feature'ın doğrusal etkisini gösterir.

-   **Avantajlar:** Basit ve hızlıdır; regression görevleri için iyi bir başlangıç noktasıdır; gerçek ilişki yaklaşık olarak doğrusal olduğunda iyi çalışır.

-   **Sınırlamalar:** Manuel feature engineering yapılmadığında karmaşık veya doğrusal olmayan ilişkileri yakalayamaz; ilişkiler doğrusal olmadığında underfitting'e yatkındır; sonuçları çarpıtabilecek outlier'lara karşı hassastır.

-   **En iyi uyumu bulma:** Olası kategorileri ayıran en iyi uyum doğrusunu bulmak için **Ordinary Least Squares (OLS)** adı verilen bir yöntem kullanırız. Bu yöntem, gözlemlenen değerler ile linear model tarafından tahmin edilen değerler arasındaki farkların kareleri toplamını minimize eder.

<details>
<summary>Örnek -- Bir Intrusion Dataset'inde Connection Duration Tahmini (Regression)
</summary>
Aşağıda NSL-KDD cybersecurity dataset'ini kullanarak linear regression'ı gösteriyoruz. Diğer feature'lara dayanarak network connection'ların `duration` değerini tahmin ederek bunu bir regression problemi olarak ele alacağız. (Gerçekte `duration`, NSL-KDD'nin feature'larından biridir; burada yalnızca regression'ı göstermek amacıyla kullanıyoruz.) Dataset'i yüklüyor, preprocess ediyor (categorical feature'ları encode ediyor), bir linear regression modelini eğitiyor ve bir test seti üzerinde Mean Squared Error (MSE) ile R² skorunu değerlendiriyoruz.
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
Bu örnekte, linear regression modeli diğer ağ özelliklerinden bağlantı `duration` değerini tahmin etmeye çalışır. Performansı Mean Squared Error (MSE) ve R² ile ölçeriz. 1.0'a yakın bir R², modelin `duration` değerindeki varyansın çoğunu açıkladığını gösterirken düşük veya negatif bir R², uyumun zayıf olduğunu gösterir. (Burada R² düşük çıkarsa şaşırmayın -- `duration` değerini verilen özelliklerden tahmin etmek zor olabilir ve linear regression, örüntüler karmaşıksa bunları yakalayamayabilir.)
</details>

### Logistic Regression

Logistic regression, bir örneğin belirli bir sınıfa (genellikle "pozitif" sınıfa) ait olma olasılığını modelleyen bir **classification** algoritmasıdır. Adına rağmen *logistic* regression, discrete sonuçlar için kullanılır (continuous sonuçlar için kullanılan linear regression'ın aksine). Özellikle **binary classification** (iki sınıf; örneğin malicious ve benign) için kullanılır, ancak multi-class problemlerine de (softmax veya one-vs-rest yaklaşımları kullanılarak) genişletilebilir.<sup>[[1]](#references)</sup>

Logistic regression, tahmin edilen değerleri olasılıklara dönüştürmek için logistic function'ı (sigmoid function olarak da bilinir) kullanır. Sigmoid function'ın, classification gereksinimlerine göre S şeklinde bir eğri boyunca büyüyen ve 0 ile 1 arasında değerler alan bir function olduğunu unutmayın; bu, binary classification görevleri için kullanışlıdır. Bu nedenle, her input'un her feature'ı kendisine atanmış weight ile çarpılır ve sonuç, bir olasılık üretmek üzere sigmoid function'dan geçirilir:
```plaintext
p(y=1|x) = 1 / (1 + e^(-z))
```
Where:

- `p(y=1|x)`, `x` girdisi verildiğinde çıktının `y` değerinin 1 olma olasılığıdır
- `e`, doğal logaritmanın tabanıdır
- `z`, girdi özelliklerinin doğrusal birleşimidir ve genellikle `z = w1*x1 + w2*x2 + ... + wn*xn + b` şeklinde gösterilir. En basit hâlinde bunun yine düz bir çizgi olduğuna, ancak daha karmaşık durumlarda birkaç boyuta sahip (her özellik için bir tane) bir hyperplane'a dönüştüğüne dikkat edin.

> [!TIP]
> *Siber güvenlikte kullanım alanları:* Birçok güvenlik problemi esasen evet/hayır kararları olduğundan logistic regression yaygın olarak kullanılır. Örneğin bir intrusion detection system, bir network connection'ın özelliklerine dayanarak bu bağlantının bir attack olup olmadığına karar vermek için logistic regression kullanabilir. Phishing detection işleminde logistic regression, bir web sitesinin özelliklerini (URL uzunluğu, `"@"` sembolünün bulunması vb.) phishing olma olasılığına dönüştürebilir. Erken nesil spam filtrelerinde kullanılmıştır ve birçok classification görevi için hâlâ güçlü bir baseline olma özelliğini korumaktadır.

#### Binary olmayan classification için Logistic Regression

Logistic regression binary classification için tasarlanmıştır, ancak **one-vs-rest** (OvR) veya **softmax regression** gibi teknikler kullanılarak multi-class problemleri ele alacak şekilde genişletilebilir. OvR'de her class için ayrı bir logistic regression modeli eğitilir ve ilgili class, diğer tüm class'lara karşı positive class olarak değerlendirilir. En yüksek tahmin edilen olasılığa sahip class, nihai tahmin olarak seçilir. Softmax regression, çıktı katmanına softmax fonksiyonunu uygulayarak ve tüm class'lar üzerinde bir olasılık dağılımı üreterek logistic regression'ı birden fazla class'ı destekleyecek şekilde genelleştirir.

#### **Logistic Regression'ın temel özellikleri:**

-   **Problem türü:** Classification (genellikle binary). Positive class'ın olasılığını tahmin eder.

-   **Yorumlanabilirlik:** Yüksek -- linear regression'da olduğu gibi feature coefficient'ları, her özelliğin sonucun log-odds değerini nasıl etkilediğini gösterebilir. Bu şeffaflık, bir alert'e hangi faktörlerin katkıda bulunduğunu anlamak açısından security alanında genellikle değerlidir.

-   **Avantajları:** Eğitilmesi basit ve hızlıdır; feature'lar ile sonucun log-odds değeri arasındaki ilişki linear olduğunda iyi çalışır. Risk scoring yapılmasını sağlayan olasılıklar üretir. Uygun regularization ile iyi genelleme yapar ve multicollinearity durumunu plain linear regression'a göre daha iyi ele alabilir.

-   **Sınırlamaları:** Feature space içinde linear bir decision boundary olduğunu varsayar (gerçek boundary karmaşık/non-linear ise başarısız olur). Etkileşimlerin veya non-linear etkilerin kritik olduğu problemlerde, polynomial veya interaction feature'larını manuel olarak eklemediğiniz sürece düşük performans gösterebilir. Ayrıca class'lar feature'ların linear bir birleşimiyle kolayca ayrılamıyorsa logistic regression daha az etkili olur.


<details>
<summary>Örnek -- Logistic Regression ile Phishing Website Detection:</summary>

UCI repository'den alınan ve web sitelerinin çıkarılmış feature'larını (URL'nin bir IP address içerip içermediği, domain'in yaşı, HTML'de şüpheli öğelerin bulunup bulunmadığı vb.) ve sitenin phishing veya legitimate olduğunu belirten bir label'ı içeren bir **Phishing Websites Dataset** kullanacağız. Web sitelerini sınıflandırmak için bir logistic regression modeli eğitecek ve ardından bir test split'i üzerinde accuracy, precision, recall, F1-score ve ROC AUC değerlerini değerlendireceğiz.
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
Bu phishing detection örneğinde logistic regression, her web sitesinin phishing olma olasılığını üretir. Accuracy, precision, recall ve F1 değerlerini değerlendirerek modelin performansı hakkında fikir ediniriz. Örneğin, yüksek recall değeri çoğu phishing sitesini yakaladığı anlamına gelir (kaçırılan saldırıları en aza indirmek için güvenlik açısından önemlidir); yüksek precision değeri ise az sayıda false alarm ürettiği anlamına gelir (analist yorgunluğunu önlemek için önemlidir). ROC AUC (ROC Eğrisi Altındaki Alan), threshold'dan bağımsız bir performans ölçümü sağlar (1.0 ideal, 0.5 ise şanstan daha iyi değil anlamına gelir). Logistic regression bu tür görevlerde genellikle iyi performans gösterir; ancak phishing ve legitimate siteler arasındaki decision boundary karmaşıksa daha güçlü non-linear modellere ihtiyaç duyulabilir.

</details>

### Karar Ağaçları

Bir decision tree, hem classification hem de regression görevleri için kullanılabilen çok yönlü bir **supervised learning algorithm**'dir. Verilerin feature'larına dayalı, hiyerarşik ve ağaç benzeri bir karar modeli öğrenir. Ağacın her internal node'u belirli bir feature üzerinde yapılan bir testi, her branch bu testin bir sonucunu ve her leaf node classification için tahmin edilen class'ı veya regression için değeri temsil eder.<sup>[[2]](#references)</sup>

Bir ağaç oluşturmak için CART (Classification and Regression Tree) gibi algoritmalar, verileri her adımda bölmek üzere en iyi feature'ı ve threshold'u seçmek amacıyla **Gini impurity** veya **information gain (entropy)** gibi ölçümler kullanır. Her split işlemindeki amaç, ortaya çıkan alt kümelerde target variable'ın homojenliğini artıracak şekilde verileri partition etmektir (classification için her node, ağırlıklı olarak tek bir class içerecek şekilde mümkün olduğunca pure olmayı hedefler).

Decision tree'ler **son derece açıklanabilirdir** -- bir prediction'ın mantığını anlamak için root'tan leaf'e kadar olan yol takip edilebilir (ör. *"`service = telnet` AND `src_bytes > 1000` AND `failed_logins > 3` İSE attack olarak classify et"*). Bu, belirli bir alert'in neden üretildiğini açıklamak açısından cybersecurity'de değerlidir. Ağaçlar hem numerical hem de categorical data'yı doğal olarak işleyebilir ve çok az preprocessing gerektirir (ör. feature scaling gerekli değildir).

Bununla birlikte, özellikle derin oluşturulduklarında (çok sayıda split), tek bir decision tree training data'ya kolayca overfit olabilir. Overfitting'i önlemek için pruning (tree depth'i sınırlandırmak veya leaf başına minimum sample sayısı belirlemek) gibi teknikler sıklıkla kullanılır.

Bir decision tree'nin 3 ana bileşeni vardır:
- **Root Node**: Tüm dataset'i temsil eden ağacın en üst node'u.
- **Internal Nodes**: Feature'ları ve bu feature'lara dayalı kararları temsil eden node'lar.
- **Leaf Nodes**: Nihai sonucu veya prediction'ı temsil eden node'lar.

Bir ağaç aşağıdaki gibi görünebilir:
```plaintext
[Root Node]
/   \
[Node A]  [Node B]
/   \      /   \
[Leaf 1] [Leaf 2] [Leaf 3] [Leaf 4]
```
> [!TIP]
> *Siber güvenlikte kullanım alanları:* Karar ağaçları, saldırıları tanımlamaya yönelik **kurallar** türetmek için intrusion detection sistemlerinde kullanılmıştır. Örneğin, ID3/C4.5 tabanlı erken dönem IDS'ler, normal ve kötü amaçlı trafiği birbirinden ayırmak için insanlar tarafından okunabilir kurallar üretirdi. Ayrıca bir dosyanın özniteliklerine (dosya boyutu, section entropy, API çağrıları vb.) dayanarak kötü amaçlı olup olmadığına karar vermek için malware analysis süreçlerinde de kullanılırlar. Karar ağaçlarının açıklığı, şeffaflığın gerekli olduğu durumlarda onları kullanışlı kılar -- bir analyst, detection mantığını doğrulamak için ağacı inceleyebilir.

#### **Karar Ağaçlarının temel özellikleri:**

-   **Problem Türü:** Hem classification hem de regression. Saldırılar ile normal trafiğin sınıflandırılmasında vb. yaygın olarak kullanılır.

-   **Yorumlanabilirlik:** Çok yüksek -- modelin kararları görselleştirilebilir ve if-then kuralları kümesi olarak anlaşılabilir. Bu, model davranışına duyulan güven ve doğrulama açısından security alanında önemli bir avantajdır.

-   **Avantajlar:** Öznitelikler arasındaki doğrusal olmayan ilişkileri ve etkileşimleri yakalayabilir (her split bir etkileşim olarak görülebilir). Öznitelikleri ölçeklendirmeye veya kategorik değişkenleri one-hot encode etmeye gerek yoktur -- ağaçlar bunları yerel olarak işler. Hızlı inference (prediction yalnızca ağaçta bir yol izlemektir).

-   **Sınırlamalar:** Kontrol edilmezse overfitting'e eğilimlidir (derin bir ağaç training set'ini ezberleyebilir). Kararsız olabilirler -- verilerdeki küçük değişiklikler farklı bir ağaç yapısına yol açabilir. Tekil modeller olarak doğrulukları daha gelişmiş yöntemlerle aynı seviyeye ulaşmayabilir (Random Forests gibi ensemble'lar variance'ı azaltarak genellikle daha iyi performans gösterir).

-   **En İyi Split'i Bulma:**
- **Gini Impurity**: Bir node'un impurity'sini ölçer. Daha düşük bir Gini impurity, daha iyi bir split olduğunu gösterir. Formül:

```plaintext
Gini = 1 - Σ(p_i^2)
```

Burada `p_i`, `i` sınıfındaki örneklerin oranıdır.

- **Entropy**: Dataset'teki belirsizliği ölçer. Daha düşük entropy, daha iyi bir split olduğunu gösterir. Formül:

```plaintext
Entropy = -Σ(p_i * log2(p_i))
```

Burada `p_i`, `i` sınıfındaki örneklerin oranıdır.

- **Information Gain**: Bir split sonrasında entropy veya Gini impurity'deki azalmadır. Information gain ne kadar yüksekse split o kadar iyidir. Şu şekilde hesaplanır:

```plaintext
Information Gain = Entropy(parent) - (Weighted Average of Entropy(children))
```

Ayrıca bir ağaç şu durumlarda sonlandırılır:
- Bir node'daki tüm örnekler aynı sınıfa aittir. Bu, overfitting'e yol açabilir.
- Ağacın maksimum derinliğine (hardcoded) ulaşılmıştır. Bu, overfitting'i önlemenin bir yoludur.
- Bir node'daki örnek sayısı belirli bir threshold'un altındadır. Bu da overfitting'i önlemenin bir yoludur.
- İleri split'lerden elde edilen information gain belirli bir threshold'un altındadır. Bu da overfitting'i önlemenin bir yoludur.

<details>
<summary>Örnek -- Intrusion Detection için Karar Ağacı:</summary>
Ağ bağlantılarını *normal* veya *attack* olarak sınıflandırmak için NSL-KDD dataset'i üzerinde bir karar ağacı eğiteceğiz. NSL-KDD, protokol türü, service, duration, başarısız login sayısı vb. özniteliklere ve saldırı türünü veya "normal" değerini belirten bir label'a sahip klasik KDD Cup 1999 dataset'inin geliştirilmiş bir sürümüdür. Tüm saldırı türlerini "anomaly" sınıfına eşleyeceğiz (binary classification: normal ve anomaly). Eğitimden sonra ağacın test setindeki performansını değerlendireceğiz.
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
Bu karar ağacı örneğinde, aşırı overfitting'i önlemek için ağaç derinliğini 10 ile sınırladık (`max_depth=10` parametresi). Metrikler, ağacın normal ve saldırı trafiğini ne kadar iyi ayırt ettiğini gösterir. Yüksek recall, saldırıların çoğunu yakaladığı anlamına gelir (bir IDS için önemlidir); yüksek precision ise az sayıda yanlış alarm olduğu anlamına gelir. Karar ağaçları yapılandırılmış verilerde genellikle makul bir doğruluk elde eder, ancak tek bir ağaç mümkün olan en iyi performansa ulaşamayabilir. Bununla birlikte, modelin *yorumlanabilirliği* büyük bir avantajdır -- ağacın bölünmelerini inceleyerek hangi özelliklerin (ör. `service`, `src_bytes` vb.) bir bağlantının kötü amaçlı olarak işaretlenmesinde en etkili olduğunu görebiliriz.

</details>

### Random Forests

Random Forest, performansı iyileştirmek için karar ağaçlarını temel alan bir **ensemble learning** yöntemidir. Bir random forest birden fazla karar ağacı eğitir (bu nedenle "forest") ve nihai bir tahmin yapmak için bu ağaçların çıktılarını birleştirir (classification için genellikle çoğunluk oyu kullanılır). Bir random forest'taki iki temel fikir **bagging** (bootstrap aggregating) ve **feature randomness**'tır:

-   **Bagging:** Her ağaç, eğitim verilerinin rastgele bir bootstrap örneği üzerinde eğitilir (örnekler yerine koymalı olarak seçilir). Bu, ağaçlar arasında çeşitlilik oluşturur.

-   **Feature Randomness:** Bir ağaçtaki her bölünmede, bölme işlemi için rastgele bir özellik alt kümesi değerlendirilir (tüm özellikler yerine). Bu, ağaçların korelasyonunu daha da azaltır.

Random forest, birçok ağacın sonuçlarının ortalamasını alarak tek bir karar ağacının sahip olabileceği varyansı azaltır. Basitçe ifade etmek gerekirse, tek tek ağaçlar overfit olabilir veya gürültülü sonuçlar üretebilir; ancak birlikte oy kullanan çok sayıda çeşitli ağaç bu hataları dengeler. Sonuç genellikle tek bir karar ağacına kıyasla **daha yüksek doğruluk** ve daha iyi genelleme sağlayan bir modeldir. Ayrıca random forests, her özellik bölünmesinin impurity'yi ortalama olarak ne kadar azalttığına bakarak feature importance için bir tahmin sağlayabilir.

Random forests; intrusion detection, malware classification ve spam detection gibi görevlerde **siber güvenlikte temel araçlardan biri** haline gelmiştir. Genellikle çok az ayarlamayla kullanıma hazır şekilde iyi performans gösterir ve büyük özellik kümelerini işleyebilir. Örneğin intrusion detection'da bir random forest, daha az false positive ile daha ince saldırı örüntülerini yakalayarak tek bir karar ağacından daha iyi performans gösterebilir. Araştırmalar, random forests'ın NSL-KDD ve UNSW-NB15 gibi veri kümelerinde saldırıları sınıflandırırken diğer algoritmalara kıyasla başarılı sonuçlar verdiğini göstermiştir.<sup>[[3]](#references)[[9]](#references)</sup>

#### **Key characteristics of Random Forests:**

-   **Type of Problem:** Öncelikle classification (regression için de kullanılır). Güvenlik loglarında yaygın olan yüksek boyutlu yapılandırılmış veriler için çok uygundur.

-   **Interpretability:** Tek bir karar ağacına kıyasla daha düşüktür -- yüzlerce ağacı aynı anda kolayca görselleştiremez veya açıklayamazsınız. Bununla birlikte, feature importance skorları hangi özniteliklerin en etkili olduğuna dair bir miktar fikir sağlar.

-   **Advantages:** Ensemble etkisi sayesinde genellikle tek ağaçlı modellere kıyasla daha yüksek doğruluk sağlar. Overfitting'e karşı dayanıklıdır -- tek tek ağaçlar overfit olsa bile ensemble daha iyi genelleme yapar. Hem numerical hem de categorical özellikleri işler ve missing data'yı bir ölçüde yönetebilir. Ayrıca outlier'lara karşı da görece dayanıklıdır.

-   **Limitations:** Model boyutu büyük olabilir (çok sayıda ağaç ve her biri potansiyel olarak derin). Tahminler tek bir ağaca göre daha yavaştır (çünkü birçok ağaç üzerinden aggregation yapmanız gerekir). Daha az yorumlanabilirdir -- önemli özellikleri bilseniz de kesin mantık, basit bir kural gibi kolayca izlenemez. Veri kümesi son derece yüksek boyutlu ve sparse ise çok büyük bir forest'ı eğitmek computational açıdan ağır olabilir.

-   **Training Process:**
1. **Bootstrap Sampling**: Birden fazla alt küme (bootstrap samples) oluşturmak için eğitim verilerini replacement ile rastgele örnekleyin.
2. **Tree Construction**: Her bootstrap sample için, her bölünmede rastgele bir özellik alt kümesi kullanarak bir karar ağacı oluşturun. Bu, ağaçlar arasında çeşitlilik sağlar.
3. **Aggregation**: Classification görevlerinde nihai tahmin, tüm ağaçların tahminleri arasındaki çoğunluk oyu alınarak yapılır. Regression görevlerinde nihai tahmin, tüm ağaçların tahminlerinin ortalamasıdır.

<details>
<summary>Example -- Random Forest for Intrusion Detection (NSL-KDD):</summary>
Aynı NSL-KDD veri kümesini (normal ve anomaly olarak binary etiketlenmiş) kullanacak ve bir Random Forest classifier eğiteceğiz. Ensemble averaging varyansı azalttığı için random forest'ın tek karar ağacı kadar iyi veya ondan daha iyi performans göstermesini bekliyoruz. Modeli aynı metriklerle değerlendireceğiz.
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
Random forest genellikle bu intrusion detection görevinde güçlü sonuçlar elde eder. Verilere bağlı olarak, tek bir decision tree ile karşılaştırıldığında özellikle recall veya precision değerlerinde F1 ya da AUC gibi metriklerde iyileşme gözlemleyebiliriz. Bu durum, *"Random Forest (RF) is an ensemble classifier and performs well compared to other traditional classifiers for effective classification of attacks."* anlayışıyla örtüşür. Bir security operations bağlamında random forest modeli, çok sayıda decision rule'un ortalamasını aldığı için false alarm'ları azaltırken saldırıları daha güvenilir şekilde işaretleyebilir. Forest'tan elde edilen feature importance değerleri, hangi network feature'larının saldırıların en belirgin göstergeleri olduğunu (örneğin belirli network services veya olağandışı packet sayıları) gösterebilir.

</details>

### Support Vector Machines (SVM)

Support Vector Machines, öncelikli olarak classification (ve ayrıca SVR olarak regression) için kullanılan güçlü supervised learning modelleridir. Bir SVM, iki class arasındaki margin'i maksimize eden **optimal separating hyperplane**'ı bulmaya çalışır. Yalnızca training point'lerinin bir alt kümesi (sınıra en yakın olan "support vectors") bu hyperplane'ın konumunu belirler. Margin'i (support vectors ile hyperplane arasındaki mesafeyi) maksimize ederek SVM'ler iyi bir generalization elde etme eğilimindedir.<sup>[[4]](#references)</sup>

SVM'nin gücünün temelinde, non-linear ilişkileri ele almak için **kernel functions** kullanabilmesi vardır. Data, linear bir separator'ın bulunabileceği daha yüksek boyutlu bir feature space'e örtük olarak dönüştürülebilir. Yaygın kernel'lar arasında polynomial, radial basis function (RBF) ve sigmoid bulunur. Örneğin, network traffic class'ları raw feature space'te linearly separable değilse, bir RBF kernel bunları daha yüksek bir boyuta map edebilir; burada SVM, linear bir split bulur (bu, original space'te non-linear bir boundary'ye karşılık gelir). Kernel seçme esnekliği, SVM'lerin çeşitli problemlerle başa çıkmasını sağlar.

SVM'lerin, yüksek boyutlu feature space'lerde (text data veya malware opcode sequences gibi) ve feature sayısının sample sayısına kıyasla fazla olduğu durumlarda iyi performans gösterdiği bilinir. 2000'lerde malware classification ve anomaly-based intrusion detection gibi birçok erken dönem cybersecurity uygulamasında popülerdiler ve çoğu zaman yüksek accuracy gösterdiler.

Ancak SVM'ler çok büyük dataset'lere kolayca ölçeklenemez (training complexity, sample sayısına göre super-linear'dır ve çok sayıda support vector saklaması gerekebileceğinden memory kullanımı yüksek olabilir). Uygulamada, milyonlarca record içeren network intrusion detection görevlerinde SVM, dikkatli subsampling yapılmadan veya approximate methods kullanılmadan çok yavaş olabilir.

#### **Key characteristics of SVM:**

-   **Type of Problem:** Classification (one-vs-one/one-vs-rest aracılığıyla binary veya multiclass) ve regression varyantları. Genellikle clear margin separation bulunan binary classification için kullanılır.

-   **Interpretability:** Medium -- SVM'ler decision trees veya logistic regression kadar interpretable değildir. Hangi data point'lerinin support vector olduğunu belirleyebilir ve hangi feature'ların etkili olabileceği hakkında (linear kernel durumunda weights aracılığıyla) fikir edinebilirsiniz; ancak pratikte SVM'ler (özellikle non-linear kernel'larla) black-box classifier olarak değerlendirilir.

-   **Advantages:** High-dimensional space'lerde etkilidir; kernel trick ile complex decision boundaries modelleyebilir; margin maksimize edilirse overfitting'e karşı dayanıklıdır (özellikle uygun bir regularization parameter C ile); class'lar büyük bir mesafeyle ayrılmamış olsa bile iyi çalışır (en iyi compromise boundary'yi bulur).

-   **Limitations:** Büyük dataset'ler için **computationally intensive**'dır (data büyüdükçe hem training hem de prediction kötü ölçeklenir). Kernel ve regularization parameter'larının (C, kernel type, RBF için gamma vb.) dikkatle ayarlanmasını gerektirir. Doğrudan probabilistic output sağlamaz (ancak probability elde etmek için Platt scaling kullanılabilir). Ayrıca SVM'ler kernel parameter'larının seçimine duyarlı olabilir --- kötü bir seçim underfit veya overfit'e yol açabilir.

*Use cases in cybersecurity:* SVM'ler **malware detection** (örneğin extracted feature'lara veya opcode sequences'a göre file'ları sınıflandırma), **network anomaly detection** (traffic'i normal veya malicious olarak sınıflandırma) ve **phishing detection** (URL feature'larını kullanarak) için kullanılmıştır. Örneğin bir SVM, bir email'in feature'larını (belirli keyword'lerin sayıları, sender reputation score'ları vb.) alıp bunu phishing veya legitimate olarak sınıflandırabilir. Ayrıca KDD gibi feature set'leri üzerinde **intrusion detection** için de uygulanmış ve computation maliyeti karşılığında çoğu zaman yüksek accuracy elde edilmiştir.

<details>
<summary>Example -- Malware Classification için SVM:</summary>
Bu kez bir SVM kullanarak phishing website dataset'ini yeniden kullanacağız. SVM'ler yavaş olabileceğinden, gerekirse training için data'nın bir alt kümesini kullanacağız (dataset yaklaşık 11k instance içeriyor; bu miktar SVM'nin makul şekilde işleyebileceği bir miktardır). Non-linear data için yaygın bir seçim olan RBF kernel'ı kullanacağız ve ROC AUC'yi hesaplamak için probability estimates'i etkinleştireceğiz.
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
SVM modeli, aynı görevdeki logistic regression ile karşılaştırabileceğimiz metrikler üretecektir. Veriler özellikler tarafından iyi bir şekilde ayrıştırılmışsa SVM'nin yüksek accuracy ve AUC değerlerine ulaştığını görebiliriz. Öte yandan dataset çok fazla gürültüye veya örtüşen sınıflara sahipse SVM, logistic regression'dan anlamlı ölçüde daha iyi performans göstermeyebilir. Uygulamada SVM'ler, özellikler ile sınıf arasında karmaşık ve doğrusal olmayan ilişkiler olduğunda performansı artırabilir -- RBF kernel, logistic regression'ın yakalayamayacağı eğri karar sınırlarını yakalayabilir. Tüm modellerde olduğu gibi, bias ve variance arasında denge kurmak için `C` (regularization) ve kernel parametrelerinin (RBF için `gamma` gibi) dikkatli bir şekilde ayarlanması gerekir.

</details>

#### Logistic Regression ve SVM Arasındaki Fark

| Aspect | **Logistic Regression** | **Support Vector Machines** |
|---|---|---|
| **Objective function** | **log-loss** (cross-entropy) değerini minimize eder. | **margin** değerini maksimize ederken **hinge-loss** değerini minimize eder. |
| **Decision boundary** | _P(y\|x)_ değerini modelleyen **en iyi uyumlu hyperplane**'i bulur. | **Maximum-margin hyperplane**'i (en yakın noktalara olan en büyük aralığı) bulur. |
| **Output** | **Probabilistic** – σ(w·x + b) aracılığıyla kalibre edilmiş sınıf olasılıkları verir. | **Deterministic** – sınıf etiketleri döndürür; olasılıklar için ek işlem gerekir (ör. Platt scaling). |
| **Regularisation** | L2 (varsayılan) veya L1, underfitting/overfitting dengesini doğrudan sağlar. | C parametresi, margin genişliği ile yanlış sınıflandırmalar arasında denge kurar; kernel parametreleri karmaşıklık ekler. |
| **Kernels / Non-linear** | Yerleşik biçimi **linear**'dır; non-linearity feature engineering ile eklenir. | Yerleşik **kernel trick** (RBF, poly vb.), yüksek boyutlu uzayda karmaşık sınırları modellemesini sağlar. |
| **Scalability** | **O(nd)** karmaşıklığında convex optimisation gerçekleştirir; çok büyük n değerlerini iyi işler. | Özel solver'lar olmadan eğitim bellek/zaman açısından **O(n²–n³)** olabilir; çok büyük n değerleri için daha az uygundur. |
| **Interpretability** | **Yüksek** – ağırlıklar feature etkisini gösterir; odds ratio sezgiseldir. | Non-linear kernel'lar için **düşük**; support vector'ler seyrektir ancak açıklanmaları kolay değildir. |
| **Sensitivity to outliers** | Smooth log-loss kullandığı için daha az hassastır. | Hard margin kullanan hinge-loss **hassas** olabilir; soft-margin (C) bunu azaltır. |
| **Typical use cases** | **Olasılıkların ve açıklanabilirliğin** önemli olduğu kredi skorlama, tıbbi risk ve A/B testing. | **Karmaşık sınırların** ve **yüksek boyutlu verilerin** önemli olduğu image/text classification ve bio-informatics. |

* **Kalibre edilmiş olasılıklara, açıklanabilirliğe ihtiyacınız varsa veya çok büyük dataset'ler üzerinde çalışıyorsanız — Logistic Regression'ı seçin.**
* **Manuel feature engineering yapmadan doğrusal olmayan ilişkileri yakalayabilen esnek bir modele ihtiyacınız varsa — SVM'yi (kernel'lar ile) seçin.**
* Her ikisi de convex objective'ları optimize eder; bu nedenle **global minimum'lar garanti edilir**, ancak SVM'nin kernel'ları hyper-parameter'lar ve computational cost ekler.

### Naive Bayes

Naive Bayes, feature'lar arasında güçlü bir bağımsızlık varsayımıyla Bayes' Theorem'ın uygulanmasına dayanan bir **probabilistic classifier** ailesidir. Bu "naive" varsayıma rağmen Naive Bayes, özellikle spam detection gibi text veya categorical data içeren belirli uygulamalarda çoğu zaman şaşırtıcı derecede iyi çalışır.<sup>[[5]](#references)</sup>


#### Bayes' Theorem

Bayes' theorem, Naive Bayes classifier'larının temelidir. Rastgele olayların koşullu ve marjinal olasılıkları arasındaki ilişkiyi kurar. Formül şöyledir:
```plaintext
P(A|B) = (P(B|A) * P(A)) / P(B)
```
Nerede:
- `P(A|B)`, `B` özelliği verildiğinde `A` sınıfının posterior olasılığıdır.
- `P(B|A)`, `A` sınıfı verildiğinde `B` özelliğinin likelihood değeridir.
- `P(A)`, `A` sınıfının prior olasılığıdır.
- `P(B)`, `B` özelliğinin prior olasılığıdır.

Örneğin, bir metnin çocuk mu yoksa yetişkin tarafından mı yazıldığını sınıflandırmak istiyorsak metindeki kelimeleri özellik olarak kullanabiliriz. Bazı başlangıç verilerine dayanarak Naive Bayes classifier, her kelimenin olası sınıfların (çocuk veya yetişkin) her birinde bulunma olasılığını önceden hesaplar. Yeni bir metin verildiğinde, metindeki kelimeler verildiğinde her olası sınıfın olasılığını hesaplar ve olasılığı en yüksek olan sınıfı seçer.

Bu örnekte görebileceğiniz gibi Naive Bayes classifier oldukça basit ve hızlıdır; ancak özelliklerin bağımsız olduğunu varsayar. Gerçek dünya verilerinde bu her zaman geçerli değildir.


#### Naive Bayes Classifier Türleri

Veri türüne ve özelliklerin dağılımına bağlı olarak birkaç Naive Bayes classifier türü vardır:
- **Gaussian Naive Bayes**: Özelliklerin Gaussian (normal) dağılımını izlediğini varsayar. Sürekli veriler için uygundur.
- **Multinomial Naive Bayes**: Özelliklerin multinomial dağılımını izlediğini varsayar. Metin classification işlemindeki kelime sayımları gibi ayrık veriler için uygundur.
- **Bernoulli Naive Bayes**: Özelliklerin binary (0 veya 1) olduğunu varsayar. Metin classification işleminde kelimelerin bulunması veya bulunmaması gibi binary veriler için uygundur.
- **Categorical Naive Bayes**: Özelliklerin categorical değişkenler olduğunu varsayar. Meyveleri renk ve şekillerine göre sınıflandırmak gibi categorical veriler için uygundur.


#### **Naive Bayes'in temel özellikleri:**

-   **Problem Türü:** Classification (binary veya multi-class). Cybersecurity alanında text classification görevlerinde (spam, phishing vb.) yaygın olarak kullanılır.

-   **Yorumlanabilirlik:** Orta -- bir decision tree kadar doğrudan yorumlanabilir değildir; ancak öğrenilen olasılıklar incelenebilir (örneğin spam ve ham e-postalarda hangi kelimelerin görülme olasılığının en yüksek olduğu). Modelin yapısı (sınıf verildiğinde her özellik için olasılıklar), gerektiğinde anlaşılabilir.

-   **Avantajlar:** Büyük dataset'lerde bile **çok hızlı** training ve prediction (instance sayısı * feature sayısı ile doğrusal). Özellikle uygun smoothing kullanıldığında, olasılıkları güvenilir şekilde tahmin etmek için nispeten az miktarda veri gerektirir. Özelliklerin sınıfa bağımsız şekilde kanıt sağlaması durumunda, özellikle bir baseline olarak çoğu zaman şaşırtıcı derecede doğrudur. High-dimensional verilerle (örneğin text'ten elde edilen binlerce feature) iyi çalışır. Bir smoothing parameter ayarlamanın ötesinde karmaşık tuning gerektirmez.

-   **Sınırlamalar:** Özellikler yüksek oranda correlated olduğunda independence assumption doğruluğu sınırlayabilir. Örneğin network verilerinde `src_bytes` ve `dst_bytes` gibi özellikler correlated olabilir; Naive Bayes bu etkileşimi yakalayamaz. Veri boyutu çok büyüdüğünde, feature dependency'lerini öğrenebilen daha expressive modeller (ensemble'lar veya neural net'ler gibi) NB'yi geçebilir. Ayrıca bir attack'ı belirlemek için özelliklerin tek tek bağımsız olmasından ziyade belirli bir feature kombinasyonu gerekiyorsa NB zorlanır.

> [!TIP]
> *Cybersecurity'deki kullanım alanları:* Klasik kullanım alanı **spam detection**'dır -- Naive Bayes, belirli token'ların (kelimeler, ifadeler, IP adresleri) frekanslarını kullanarak bir e-postanın spam olma olasılığını hesaplayan ilk spam filter'larının temelini oluşturuyordu. Ayrıca belirli keyword'lerin veya karakteristiklerin (bir URL'de `"login.php"` ya da bir URL path'inde `@` bulunması gibi) phishing olasılığına katkıda bulunduğu **phishing email detection** ve **URL classification** işlemlerinde de kullanılır. Malware analysis alanında, bir yazılımın malware olup olmadığını tahmin etmek için belirli API çağrılarının veya permission'ların varlığını kullanan bir Naive Bayes classifier düşünülebilir. Daha gelişmiş algorithm'ler çoğu zaman daha iyi performans gösterse de Naive Bayes, hızı ve basitliği sayesinde iyi bir baseline olmaya devam eder.

<details>
<summary>Örnek -- Phishing Detection için Naive Bayes:</summary>
Naive Bayes'i göstermek için NSL-KDD intrusion dataset'i üzerinde (binary label'lar ile) Gaussian Naive Bayes kullanacağız. Gaussian NB, her feature'ın sınıf başına normal bir dağılım izlediğini varsayar. Birçok network feature'ı ayrık veya highly skewed olduğundan bu, yaklaşık bir seçimdir; ancak NB'nin continuous feature verilerine nasıl uygulanacağını gösterir. Ayrıca binary feature'lardan (örneğin tetiklenen alert'lerden oluşan bir set) oluşan bir dataset üzerinde Bernoulli NB seçebilirdik; ancak burada continuity sağlamak için NSL-KDD ile devam edeceğiz.
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
Bu kod, saldırıları tespit etmek için bir Naive Bayes classifier eğitir. Naive Bayes, feature'lar arasındaki bağımsızlığı varsayarak training data temelinde `P(service=http | Attack)` ve `P(Service=http | Normal)` gibi olasılıkları hesaplar. Ardından gözlemlenen feature'lara göre yeni bağlantıları normal veya attack olarak sınıflandırmak için bu olasılıkları kullanır. NB'nin NSL-KDD üzerindeki performansı, feature bağımsızlığı ihlal edildiği için daha gelişmiş modeller kadar yüksek olmayabilir; ancak genellikle yeterli sonuç verir ve son derece yüksek hız avantajına sahiptir. Gerçek zamanlı email filtering veya URL'lerin ilk triage'ı gibi senaryolarda, bir Naive Bayes modeli düşük kaynak kullanımıyla bariz şekilde malicious durumları hızlıca işaretleyebilir.

</details>

### k-Nearest Neighbors (k-NN)

k-Nearest Neighbors, en basit machine learning algoritmalarından biridir. Training set'teki örneklere benzerliğe göre tahmin yapan **non-parametric, instance-based** bir yöntemdir. Classification için temel fikir şudur: yeni bir data point'i sınıflandırmak üzere training data içindeki en yakın **k** point'i (yani "nearest neighbors") bulmak ve bu komşular arasındaki çoğunluk class'ını atamak. "Yakınlık", bir distance metric ile tanımlanır; numeric data için genellikle Euclidean distance kullanılır (farklı feature veya problem türleri için başka distance'lar da kullanılabilir).<sup>[[10]](#references)</sup>

K-NN, *explicit training* gerektirmez -- "training" aşaması yalnızca dataset'i saklamaktan ibarettir. Tüm işlem query (prediction) sırasında gerçekleşir: algoritma, en yakın point'leri bulmak için query point ile tüm training point'leri arasındaki distance'ları hesaplamalıdır. Bu nedenle prediction time, **training sample sayısıyla lineer** olarak artar ve büyük dataset'lerde maliyetli olabilir. Bu yüzden k-NN, daha küçük dataset'ler veya basitlik karşılığında memory ve speed'den ödün verebileceğiniz senaryolar için en uygunudur.

Basitliğine rağmen k-NN, çok karmaşık decision boundary'leri modelleyebilir (çünkü decision boundary, örneklerin dağılımının belirlediği herhangi bir şekle sahip olabilir). Decision boundary çok düzensiz olduğunda ve elinizde çok fazla data bulunduğunda genellikle iyi sonuç verir -- esas olarak data'nın "kendi adına konuşmasına" izin verir. Ancak yüksek dimension'larda distance metric'leri daha az anlamlı hale gelebilir (curse of dimensionality) ve çok büyük sayıda sample olmadığında yöntem zorlanabilir.

*Use cases in cybersecurity:* k-NN, anomaly detection için kullanılmıştır -- örneğin bir intrusion detection system, nearest neighbor'larının (önceki event'lerin) çoğu malicious ise bir network event'ini malicious olarak işaretleyebilir. Normal traffic cluster'lar oluşturuyor ve attack'ler outlier durumundaysa, bir K-NN yaklaşımı (k=1 veya küçük bir k ile) temelde bir **nearest-neighbor anomaly detection** yöntemi olur. K-NN, malware family'lerini binary feature vector'lar aracılığıyla sınıflandırmak için de kullanılmıştır: yeni bir file, feature space'te belirli bir malware family'sinin bilinen instance'larına çok yakınsa o family'ye ait olarak sınıflandırılabilir. Uygulamada k-NN, daha scalable algoritmalar kadar yaygın değildir; ancak kavramsal olarak basittir ve bazen baseline olarak veya küçük ölçekli problemler için kullanılır.

#### **Key characteristics of k-NN:**

-   **Type of Problem:** Classification (regression variant'ları da vardır). Bu, *lazy learning* yöntemidir -- explicit model fitting yapılmaz.

-   **Interpretability:** Düşük ile orta arasıdır -- global bir model veya kısa ve öz bir açıklama yoktur; ancak bir kararı etkileyen nearest neighbor'lara bakılarak sonuçlar yorumlanabilir (örneğin, "bu network flow, şu 3 bilinen malicious flow'a benzediği için malicious olarak sınıflandırıldı"). Bu nedenle açıklamalar example-based olabilir.

-   **Advantages:** Uygulaması ve anlaşılması çok basittir. Data distribution hakkında herhangi bir varsayımda bulunmaz (non-parametric). Multi-class problemlerini doğal olarak ele alabilir. Decision boundary'lerin data distribution tarafından şekillendirilen çok karmaşık yapılara sahip olabilmesi nedeniyle **adaptive**'dir.

-   **Limitations:** Büyük dataset'lerde prediction yavaş olabilir (çok sayıda distance hesaplanmalıdır). Memory-intensive'dır -- tüm training data'yı saklar. Tüm point'ler neredeyse eşit uzaklıkta hale gelme eğiliminde olduğundan, high-dimensional feature space'lerde performans düşer (bu da "nearest" kavramını daha az anlamlı hale getirir). *k* (neighbor sayısı) uygun şekilde seçilmelidir -- çok küçük bir k gürültülü sonuçlara, çok büyük bir k ise diğer class'lara ait ilgisiz point'lerin dahil edilmesine yol açabilir. Ayrıca distance hesaplamaları scale'e duyarlı olduğundan feature'lar uygun şekilde scaled edilmelidir.

<details>
<summary>Example -- Phishing Detection için k-NN:</summary>

Yine NSL-KDD'yi (binary classification) kullanacağız. k-NN computationally heavy olduğu için bu demonstration'da yönetilebilir tutmak amacıyla training data'nın bir subset'ini kullanacağız. Full 125k içinden, örneğin 20.000 training sample seçecek ve k=5 neighbor kullanacağız. Training'den sonra (aslında yalnızca data'yı sakladıktan sonra) test seti üzerinde evaluation yapacağız. Ayrıca distance calculation için feature'ları scale edeceğiz; böylece scale nedeniyle hiçbir tek feature'ın baskın hale gelmemesini sağlayacağız.
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
k-NN modeli, eğitim kümesi alt kümesindeki en yakın 5 bağlantıya bakarak bir bağlantıyı sınıflandırır. Örneğin, bu komşuların 4'ü attack (anomaly) ve 1'i normal ise yeni bağlantı attack olarak sınıflandırılır. Performans makul olabilir, ancak çoğu zaman aynı veriler üzerinde iyi ayarlanmış bir Random Forest veya SVM kadar yüksek değildir. Bununla birlikte, sınıf dağılımları çok düzensiz ve karmaşık olduğunda k-NN bazen öne çıkabilir; bu durumda model, etkili bir şekilde memory-based lookup kullanır. Cybersecurity alanında k-NN (k=1 veya küçük k değerleriyle), bilinen attack pattern'lerini örnekler üzerinden tespit etmek ya da daha karmaşık sistemlerde (ör. clustering ve ardından cluster üyeliğine göre classification yapmak) bir bileşen olarak kullanılabilir.
</details>

### Gradient Boosting Machines (ör. XGBoost)

Gradient Boosting Machines, structured data için en güçlü algoritmalar arasındadır. **Gradient boosting**, weak learner'lardan (çoğunlukla decision tree'lerden) oluşan bir ensemble'ı, her yeni model önceki ensemble'ın hatalarını düzeltecek şekilde ardışık olarak oluşturma tekniğini ifade eder. Ağaçları paralel olarak oluşturan ve ortalamalarını alan bagging'in (Random Forests) aksine boosting, ağaçları *tek tek* oluşturur ve her ağaç, önceki ağaçların yanlış tahmin ettiği örneklere daha fazla odaklanır.

Son yıllarda en popüler implementasyonlar **XGBoost**, **LightGBM** ve **CatBoost** olmuştur; bunların tümü gradient boosting decision tree (GBDT) kütüphaneleridir. Machine learning yarışmalarında ve uygulamalarında son derece başarılı olmuş, çoğu zaman **tabular dataset'lerde state-of-the-art performans** elde etmişlerdir. Cybersecurity alanında araştırmacılar ve uygulayıcılar, **malware detection** (dosyalardan veya runtime davranışından çıkarılan feature'ları kullanarak) ve **network intrusion detection** gibi görevlerde gradient boosted tree'ler kullanmıştır. Örneğin bir gradient boosting modeli, "çok sayıda SYN paketi ve olağandışı port -> muhtemel scan" gibi birçok weak rule'u (tree'leri) bir araya getirerek, çok sayıda ince pattern'i hesaba katan güçlü bir composite detector oluşturabilir.<sup>[[6]](#references)</sup>

Boosted tree'ler neden bu kadar etkilidir? Sequence içindeki her tree, mevcut ensemble'ın tahminlerindeki *residual error'lar* (gradient'ler) üzerinde eğitilir. Böylece model, zayıf olduğu alanları kademeli olarak **"boost"** eder. Base learner olarak decision tree'lerin kullanılması, final modelin karmaşık etkileşimleri ve non-linear ilişkileri yakalamasını sağlar. Ayrıca boosting, yerleşik bir regularization biçimine sahiptir: çok sayıda küçük tree ekleyerek (ve katkılarını ölçeklendirmek için learning rate kullanarak), uygun parametreler seçildiğinde aşırı overfitting olmadan çoğu zaman iyi genelleme yapar.

#### **Gradient Boosting'in temel özellikleri:**

-   **Problem Türü:** Öncelikle classification ve regression. Security alanında genellikle classification (ör. bir bağlantıyı veya dosyayı binary olarak sınıflandırmak) kullanılır. Uygun loss ile binary, multi-class ve hatta ranking problemlerini ele alabilir.

-   **Yorumlanabilirlik:** Düşük ila orta düzey. Tek bir boosted tree küçük olsa da tam bir model yüzlerce tree içerebilir ve bir bütün olarak insan tarafından yorumlanabilir değildir. Ancak Random Forest gibi feature importance skorları sağlayabilir; SHAP (SHapley Additive exPlanations) gibi araçlar da bireysel tahminleri belirli ölçüde yorumlamak için kullanılabilir.

-   **Avantajlar:** Structured/tabular data için çoğu zaman **en iyi performans gösteren** algoritmadır. Karmaşık pattern'leri ve etkileşimleri tespit edebilir. Model karmaşıklığını özelleştirmek ve overfitting'i önlemek için çok sayıda ayar seçeneğine (tree sayısı, tree derinliği, learning rate, regularization terimleri) sahiptir. Modern implementasyonlar hız için optimize edilmiştir (ör. XGBoost, second-order gradient bilgisi ve verimli data structure'lar kullanır). Uygun loss function'larla birleştirildiğinde veya sample weight'ler ayarlandığında imbalanced data'yı daha iyi ele alma eğilimindedir.

-   **Sınırlamalar:** Daha basit modellere göre ayarlanması daha zordur; tree'ler derinse veya tree sayısı fazlaysa training yavaş olabilir (ancak aynı veriler üzerinde karşılaştırılabilir bir deep neural network eğitmekten genellikle hâlâ daha hızlıdır). Model uygun şekilde ayarlanmazsa overfit olabilir (ör. yeterli regularization olmadan çok fazla sayıda derin tree kullanılması). Çok sayıda hyperparameter nedeniyle gradient boosting'i etkili şekilde kullanmak daha fazla uzmanlık veya deneme gerektirebilir. Ayrıca tree-based method'lar gibi, çok sparse ve high-dimensional data'yı linear model'ler veya Naive Bayes kadar verimli şekilde doğal olarak ele almaz (yine de text classification gibi alanlarda uygulanabilir; ancak feature engineering olmadan ilk tercih olmayabilir).

> [!TIP]
> *Cybersecurity'de kullanım alanları:* Bir decision tree veya random forest'ın kullanılabileceği hemen her yerde, bir gradient boosting modeli daha iyi doğruluk elde edebilir. Örneğin **Microsoft'un malware detection** yarışmalarında, binary dosyalardan çıkarılan ve işlenmiş feature'lar üzerinde XGBoost yoğun olarak kullanılmıştır. **Network intrusion detection** araştırmalarında GBDT'lerle (ör. CIC-IDS2017 veya UNSW-NB15 dataset'leri üzerinde XGBoost) en iyi sonuçların elde edildiği sıkça raporlanır. Bu modeller çok çeşitli feature'ları (protocol türleri, belirli event'lerin sıklığı, traffic'in statistical feature'ları vb.) alıp threat'leri tespit etmek üzere birleştirebilir. Phishing detection'da gradient boosting; URL'lerin lexical feature'larını, domain reputation feature'larını ve page content feature'larını birleştirerek çok yüksek doğruluk elde edebilir. Ensemble yaklaşımı, data'daki birçok corner case'i ve ince ayrıntıyı kapsama konusunda yardımcı olur.

<details>
<summary>Örnek -- XGBoost ile Phishing Detection:</summary>
Phishing dataset'i üzerinde bir gradient boosting classifier kullanacağız. İşleri basit ve self-contained tutmak için `sklearn.ensemble.GradientBoostingClassifier` kullanacağız (bu, daha yavaş ancak anlaşılır bir implementasyondur). Normalde daha iyi performans ve ek özellikler için `xgboost` veya `lightgbm` kütüphaneleri kullanılabilir. Modeli eğitecek ve daha önce olduğu gibi değerlendireceğiz.
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
Gradient boosting modeli, bu phishing veri setinde muhtemelen çok yüksek doğruluk ve AUC elde edecektir (literatürde görüldüğü üzere, uygun ayarlamayla bu tür verilerde bu modeller sıklıkla %95'in üzerinde doğruluğa ulaşabilir. Bu, GBDT'lerin neden *"the state of the art model for tabular dataset"* olarak kabul edildiğini gösterir -- karmaşık örüntüleri yakalayarak genellikle daha basit algoritmalardan daha iyi performans gösterirler. Siber güvenlik bağlamında bu, daha az hatalı tespit ile daha fazla phishing sitesinin veya saldırının yakalanması anlamına gelebilir. Elbette overfitting konusunda dikkatli olunmalıdır -- böyle bir modeli deployment için geliştirirken genellikle cross-validation gibi teknikler kullanır ve bir validation seti üzerindeki performansı izleriz.

</details>

### Modelleri Birleştirme: Ensemble Learning ve Stacking

Ensemble learning, genel performansı artırmak için **birden fazla modeli birleştirme** stratejisidir. Daha önce belirli ensemble yöntemlerini gördük: Random Forest (bagging aracılığıyla ağaçlardan oluşan bir ensemble) ve Gradient Boosting (ardışık boosting aracılığıyla ağaçlardan oluşan bir ensemble). Ancak ensemble'lar **voting ensemble** veya **stacked generalization (stacking)** gibi başka yöntemlerle de oluşturulabilir. Temel fikir, farklı modellerin farklı örüntüleri yakalayabilmesi veya farklı zayıflıklara sahip olmasıdır; bu modelleri birleştirerek **her modelin hatalarını diğerinin güçlü yönleriyle telafi edebiliriz**.<sup>[[13]](#references)</sup>

-   **Voting Ensemble:** Basit bir voting classifier'da birden fazla farklı model (örneğin logistic regression, decision tree ve SVM) eğitir ve son tahmin için bunların oylarını kullanırız (classification için çoğunluk oyu). Oyları ağırlıklandırırsak (örneğin daha doğru modellere daha yüksek ağırlık verirsek), bu weighted voting yöntemi olur. Bireysel modeller makul ölçüde iyi ve bağımsız olduğunda bu yöntem genellikle performansı artırır -- diğer modeller hatayı düzeltebileceğinden ensemble, tek bir modelin hata yapma riskini azaltır. Bu, tek bir görüş yerine bir uzmanlar paneline sahip olmaya benzer.

-   **Stacking (Stacked Ensemble):** Stacking bir adım daha ileri gider. Basit bir oylama yerine, base modellerin tahminlerini **en iyi şekilde nasıl birleştireceğini öğrenen** bir **meta-model** eğitir. Örneğin 3 farklı classifier (base learner) eğitir, ardından bunların çıktılarını (veya olasılıklarını) özellik olarak bir meta-classifier'a (genellikle logistic regression gibi basit bir modele) vererek bunları en uygun şekilde birleştirmeyi öğrenmesini sağlarsınız. Overfitting'i önlemek için meta-model bir validation seti üzerinde veya cross-validation aracılığıyla eğitilir. Stacking, *hangi koşullarda hangi modellere daha fazla güvenilmesi gerektiğini* öğrenerek basit voting yönteminden daha iyi performans gösterebilir. Siber güvenlikte bir model network scan'lerini yakalamada daha iyi olabilirken başka bir model malware beaconing'i yakalamada daha başarılı olabilir; bir stacking modeli her birine uygun şekilde güvenmeyi öğrenebilir.

Voting veya stacking yoluyla oluşturulan ensemble'lar genellikle **doğruluğu** ve dayanıklılığı artırır. Dezavantajı, karmaşıklığın artması ve bazen yorumlanabilirliğin azalmasıdır (ancak decision tree'lerin ortalamasını alan ensemble gibi bazı ensemble yaklaşımları, örneğin feature importance aracılığıyla, yine de belirli düzeyde içgörü sağlayabilir). Uygulama kısıtları izin veriyorsa bir ensemble kullanmak pratikte daha yüksek detection oranları sağlayabilir. Siber güvenlik yarışmalarındaki (ve genel olarak Kaggle yarışmalarındaki) birçok başarılı çözüm, performanstan geriye kalan son küçük kazanımları elde etmek için ensemble tekniklerini kullanır.

<details>
<summary>Örnek -- Phishing Detection için Voting Ensemble:</summary>
Model stacking'i açıklamak için ele aldığımız modellerden birkaçını phishing veri seti üzerinde birleştirelim. Base learner olarak bir logistic regression, bir decision tree ve bir k-NN kullanacak; tahminlerini birleştirmek için de meta-learner olarak bir Random Forest kullanacağız. Meta-learner, base learner'ların çıktıları üzerinde (training seti için cross-validation kullanılarak) eğitilecektir. Stacked modelin, bireysel modeller kadar iyi veya onlardan biraz daha iyi performans göstermesini bekliyoruz.
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
Stacked ensemble, temel modellerin birbirini tamamlayan güçlü yönlerinden yararlanır. Örneğin logistic regression verilerin doğrusal yönlerini ele alabilir, decision tree belirli kural benzeri etkileşimleri yakalayabilir ve k-NN özellik uzayındaki yerel komşuluklarda başarılı olabilir. Meta-model (burada random forest), bu girdilerin nasıl ağırlıklandırılacağını öğrenebilir. Ortaya çıkan metrikler genellikle herhangi bir tek modelin metriklerine kıyasla (küçük de olsa) bir iyileşme gösterir. Phishing örneğimizde logistic tek başına 0.95, tree ise 0.94 F1 değerine sahipse stack, her modelin hata yaptığı noktaları telafi ederek 0.96 değerine ulaşabilir.

Bunun gibi ensemble yöntemleri, *"birden fazla modeli birleştirmek genellikle daha iyi genelleme sağlar"* ilkesini gösterir. Cybersecurity alanında bu, birden fazla detection engine kullanılarak uygulanabilir (bunlardan biri rule-based, biri machine learning, biri anomaly-based olabilir) ve ardından uyarıları toplayan bir katman -- etkin biçimde bir ensemble biçimi -- daha yüksek güvenle nihai bir karar verebilir. Bu tür sistemleri dağıtırken ek karmaşıklık göz önünde bulundurulmalı ve ensemble'ın yönetilmesinin veya açıklanmasının fazla zorlaşmadığından emin olunmalıdır. Ancak doğruluk açısından ensemble ve stacking, model performansını iyileştirmek için güçlü araçlardır.

</details>


## References

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
