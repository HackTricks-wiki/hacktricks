# Supervised Learning Algorithms

{{#include ../banners/hacktricks-training.md}}

## Temel Bilgiler

Supervised learning, yeni ve daha önce görülmemiş girdiler hakkında tahminler yapabilen modelleri eğitmek için etiketlenmiş verileri kullanır. Cybersecurity alanında supervised machine learning; saldırı tespiti (ağ trafiğini *normal* veya *attack* olarak sınıflandırma), malware tespiti (kötü amaçlı yazılımları zararsız yazılımlardan ayırt etme), phishing tespiti (sahte web sitelerini veya e-postaları belirleme) ve spam filtreleme gibi görevlerde yaygın olarak kullanılır.<sup>[[1]](#references)</sup> Her algoritmanın kendine özgü güçlü yönleri vardır ve farklı problem türleri (classification veya regression) için uygundur. Aşağıda temel supervised learning algoritmalarını inceleyecek, nasıl çalıştıklarını açıklayacak ve gerçek cybersecurity dataset'leri üzerinde kullanımlarını göstereceğiz. Ayrıca modellerin birleştirilmesinin (ensemble learning) tahmin performansını çoğu zaman nasıl iyileştirebildiğini de ele alacağız.

## Algorithms

-   **Linear Regression:** Verilere bir linear equation uydurarak sayısal sonuçları tahmin eden temel bir regression algoritmasıdır.

-   **Logistic Regression:** Adına rağmen, binary bir sonucun olasılığını modellemek için logistic function kullanan bir classification algoritmasıdır.

-   **Decision Trees:** Tahmin yapmak için verileri özelliklere göre bölen tree-structured modellerdir; genellikle yorumlanabilirlikleri nedeniyle kullanılırlar.

-   **Random Forests:** Doğruluğu artıran ve overfitting'i azaltan, decision tree'lerden oluşan (bagging yoluyla) bir ensemble modelidir.

-   **Support Vector Machines (SVM):** En iyi ayıran hyperplane'i bulan max-margin classifier'lardır; non-linear veriler için kernel'ler kullanabilirler.

-   **Naive Bayes:** Feature independence varsayımına sahip, Bayes' theorem temelinde çalışan ve spam filtrelemede yaygın olarak kullanılan probabilistic bir classifier'dır.

-   **k-Nearest Neighbors (k-NN):** Bir sample'ı, en yakın komşularının çoğunluk class'ına göre etiketleyen basit bir "instance-based" classifier'dır.

-   **Gradient Boosting Machines:** Daha zayıf learner'ları (genellikle decision tree'leri) sıralı olarak ekleyerek güçlü bir predictor oluşturan ensemble modellerdir (ör. XGBoost, LightGBM).

Aşağıdaki her bölüm, algoritmanın geliştirilmiş bir açıklamasını ve `pandas` ile `scikit-learn` gibi kütüphaneleri (neural network örneği için `PyTorch`) kullanan bir **Python code example** sağlar. Örnekler, herkese açık cybersecurity dataset'lerini (intrusion detection için NSL-KDD ve Phishing Websites dataset'i gibi) kullanır ve tutarlı bir yapı izler:

1.  **Dataset'i yükleyin** (varsa URL üzerinden indirin).

2.  **Verileri preprocess edin** (ör. categorical feature'ları encode edin, değerleri scale edin, train/test set'lerine ayırın).

3.  **Modeli** training data üzerinde **train edin**.

4.  Classification için accuracy, precision, recall, F1-score ve ROC AUC; regression için ise mean squared error metriklerini kullanarak bir test seti üzerinde **evaluate edin**.

Her algoritmaya daha yakından bakalım:

### Linear Regression

Linear regression, sürekli sayısal değerleri tahmin etmek için kullanılan bir **regression** algoritmasıdır. Girdi feature'ları (independent variable'lar) ile çıktı (dependent variable) arasında linear bir ilişki olduğunu varsayar. Model, feature'lar ile target arasındaki ilişkiyi en iyi şekilde açıklayan düz bir çizgi (veya daha yüksek boyutlarda hyperplane) uydurmaya çalışır. Bu işlem genellikle tahmin edilen ve gerçek değerler arasındaki squared error'ların toplamı minimize edilerek gerçekleştirilir (Ordinary Least Squares method).<sup>[[2]](#references)</sup>

Linear regression'ı temsil etmenin en basit yolu bir çizgidir:
```plaintext
y = mx + b
```
Burada:

- `y` tahmin edilen değerdir (çıktı)
- `m` doğrunun eğimidir (katsayı)
- `x` girdi özelliğidir
- `b` y-kesişimidir

Linear regression'ın amacı, tahmin edilen değerlerle veri kümesindeki gerçek değerler arasındaki farkı en aza indiren en uygun doğruyu bulmaktır. Elbette bu çok basittir; 2 kategoriyi ayıran düz bir doğru olurdu, ancak daha fazla boyut eklenirse doğru daha karmaşık hale gelir:
```plaintext
y = w1*x1 + w2*x2 + ... + wn*xn + b
```
> [!TIP]
> *Siber güvenlikte kullanım alanları:* Linear regression, temel security görevlerinde (genellikle classification kullanılır) daha az yaygındır, ancak sayısal sonuçları tahmin etmek için uygulanabilir. Örneğin, geçmiş verilere dayanarak **network traffic hacmini tahmin etmek** veya **bir zaman aralığındaki attack sayısını tahmin etmek** için linear regression kullanılabilir. Ayrıca belirli system metrikleri verildiğinde bir risk skorunu ya da bir attack'ın tespit edilmesine kadar beklenen süreyi tahmin edebilir. Uygulamada, intrusion veya malware tespiti için classification algorithms (logistic regression veya trees gibi) daha sık kullanılır; ancak linear regression bir temel oluşturur ve regression odaklı analizler için kullanışlıdır.

#### **Linear Regression'ın temel özellikleri:**

-   **Problem türü:** Regression (sürekli değerleri tahmin etme). Çıktıya bir threshold uygulanmadığı sürece doğrudan classification için uygun değildir.

-   **Yorumlanabilirlik:** Yüksek -- coefficient'ların yorumlanması kolaydır ve her feature'ın linear etkisini gösterir.

-   **Avantajlar:** Basit ve hızlıdır; regression görevleri için iyi bir baseline'dır; gerçek ilişki yaklaşık olarak linear olduğunda iyi çalışır.

-   **Sınırlamalar:** Manuel feature engineering yapılmadığı sürece karmaşık veya non-linear ilişkileri yakalayamaz; ilişkiler non-linear olduğunda underfitting yapmaya yatkındır; sonuçları çarpıtabilecek outlier'lara karşı hassastır.

-   **En iyi uyumu bulma:** Olası kategorileri birbirinden ayıran en iyi uyum çizgisini bulmak için **Ordinary Least Squares (OLS)** adı verilen bir yöntem kullanırız. Bu yöntem, gözlemlenen değerler ile linear model tarafından tahmin edilen değerler arasındaki farkların kareleri toplamını minimize eder.

<details>
<summary>Örnek -- Bir Intrusion Dataset'inde Connection Duration'ı Tahmin Etme (Regression)
</summary>
Aşağıda NSL-KDD cybersecurity dataset'ini kullanarak linear regression'ı gösteriyoruz. Diğer feature'lara dayanarak network connection'ların `duration` değerini tahmin ederek bunu bir regression problemi olarak ele alacağız. (Gerçekte `duration`, NSL-KDD'nin feature'larından biridir; burada yalnızca regression'ı açıklamak için kullanıyoruz.) Dataset'i yüklüyor, preprocess ediyor (categorical feature'ları encode ediyor), bir linear regression model'i eğitiyor ve test seti üzerindeki Mean Squared Error (MSE) ile R² score değerlerini değerlendiriyoruz.
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
Bu örnekte linear regression modeli, diğer network özelliklerinden bağlantı `duration` değerini tahmin etmeye çalışır. Performansı Mean Squared Error (MSE) ve R² ile ölçeriz. 1.0'a yakın bir R², modelin `duration` değerindeki varyansın çoğunu açıkladığını gösterirken düşük veya negatif bir R², uyumun zayıf olduğunu gösterir. (R² düşük çıkarsa şaşırmayın -- verilen özelliklerden `duration` değerini tahmin etmek zor olabilir ve linear regression, desenler karmaşıksa bunları yakalayamayabilir.)
</details>

### Logistic Regression

Logistic regression, bir örneğin belirli bir sınıfa (genellikle "positive" sınıfına) ait olma olasılığını modelleyen bir **classification** algoritmasıdır. Adına rağmen *logistic* regression, linear regression'ın aksine sürekli sonuçlar için değil, ayrık sonuçlar için kullanılır. Özellikle **binary classification** (iki sınıf; örneğin malicious ve benign) için kullanılır, ancak multi-class problemlerine de (softmax veya one-vs-rest yaklaşımları kullanılarak) genişletilebilir.<sup>[[3]](#references)</sup>

Logistic regression, tahmin edilen değerleri olasılıklara dönüştürmek için logistic function'ı (sigmoid function olarak da bilinir) kullanır. Sigmoid function'ın, classification gereksinimlerine göre S şeklinde bir eğriyle büyüyen ve 0 ile 1 arasında değerler alan bir function olduğunu unutmayın; bu, binary classification görevleri için kullanışlıdır. Bu nedenle her input'un her feature'ı kendisine atanmış weight ile çarpılır ve sonuç, bir olasılık üretmek için sigmoid function'dan geçirilir:
```plaintext
p(y=1|x) = 1 / (1 + e^(-z))
```
Where:

- `p(y=1|x)`, `x` girdisi verildiğinde çıktının `y` değerinin 1 olma olasılığıdır
- `e`, doğal logaritmanın tabanıdır
- `z`, girdi özelliklerinin doğrusal birleşimidir ve genellikle `z = w1*x1 + w2*x2 + ... + wn*xn + b` şeklinde gösterilir. En basit hâliyle yine düz bir çizgi olduğunu, ancak daha karmaşık durumlarda birkaç boyutlu (her özellik için bir boyut) bir hiper düzleme dönüştüğünü unutmayın.

> [!TIP]
> *Siber güvenlikte kullanım alanları:* Birçok güvenlik sorunu temel olarak evet/hayır kararları olduğundan, lojistik regresyon yaygın olarak kullanılır. Örneğin bir intrusion detection system, bir network connection'ın özelliklerine dayanarak bu bağlantının bir saldırı olup olmadığına karar vermek için lojistik regresyon kullanabilir. Phishing detection işleminde lojistik regresyon, bir web sitesinin özelliklerini (URL uzunluğu, `"@"` sembolünün bulunması vb.) phishing olma olasılığına dönüştürebilir. Erken nesil spam filtrelerinde kullanılmıştır ve birçok classification görevi için hâlâ güçlü bir baseline olmaya devam etmektedir.

#### Binary olmayan classification için Lojistik Regresyon

Lojistik regresyon binary classification için tasarlanmıştır, ancak **one-vs-rest** (OvR) veya **softmax regression** gibi teknikler kullanılarak multi-class problemleriyle çalışacak şekilde genişletilebilir. OvR'de her class için ayrı bir lojistik regresyon modeli eğitilir ve ilgili class positive class, diğer tüm class'lar ise karşılaştırma grubu olarak ele alınır. En yüksek tahmin edilen olasılığa sahip class, nihai tahmin olarak seçilir. Softmax regression, çıktı katmanına softmax function uygulayarak lojistik regresyonu birden fazla class'a geneller ve tüm class'lar üzerinde bir olasılık dağılımı üretir.

#### **Lojistik Regresyonun temel özellikleri:**

-   **Problem türü:** Classification (genellikle binary). Positive class olasılığını tahmin eder.

-   **Yorumlanabilirlik:** Yüksek -- linear regression'da olduğu gibi, feature coefficient değerleri her özelliğin sonucun log-odds değerini nasıl etkilediğini gösterebilir. Bu şeffaflık, bir alert'e hangi faktörlerin katkıda bulunduğunu anlamak açısından security alanında sıklıkla takdir edilir.

-   **Avantajları:** Eğitimi basit ve hızlıdır; özelliklerle sonucun log-odds değerleri arasındaki ilişkinin doğrusal olduğu durumlarda iyi çalışır. Risk scoring olanağı sağlayacak şekilde olasılıklar üretir. Uygun regularization ile iyi genelleme yapar ve plain linear regression'a kıyasla multicollinearity ile daha iyi başa çıkabilir.

-   **Sınırlamaları:** Feature space'te linear bir decision boundary olduğunu varsayar (gerçek boundary karmaşık/non-linear ise başarısız olur). Etkileşimlerin veya non-linear etkilerin kritik olduğu problemlerde, polynomial veya interaction feature'larını manuel olarak eklemediğiniz sürece düşük performans gösterebilir. Ayrıca class'lar feature'ların linear combination'ı ile kolayca ayrıştırılamıyorsa lojistik regresyon daha az etkilidir.


<details>
<summary>Örnek -- Lojistik Regresyon ile Phishing Website Detection:</summary>

Web sitelerinden çıkarılmış özellikleri (URL'nin bir IP address içerip içermediği, domain'in yaşı, HTML'de şüpheli öğelerin bulunup bulunmadığı vb.) ve sitenin phishing veya legitimate olduğunu belirten bir label'ı içeren **Phishing Websites Dataset**'i (UCI repository'den) kullanacağız.<sup>[[4]](#references)</sup> Web sitelerini sınıflandırmak için bir lojistik regresyon modeli eğitecek, ardından bir test split'i üzerindeki accuracy, precision, recall, F1-score ve ROC AUC değerlerini değerlendireceğiz.
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
Bu phishing detection örneğinde logistic regression, her web sitesinin phishing olup olmadığına dair bir olasılık üretir. Accuracy, precision, recall ve F1 değerlerini değerlendirerek modelin performansı hakkında fikir ediniriz. Örneğin, yüksek recall değerine sahip olması çoğu phishing sitesini yakaladığı anlamına gelir (kaçırılan saldırıları en aza indirmek güvenlik açısından önemlidir); yüksek precision ise az sayıda false alarm ürettiği anlamına gelir (analist yorgunluğunu önlemek açısından önemlidir). ROC AUC (Area Under the ROC Curve), threshold'dan bağımsız bir performans ölçümü sağlar (1.0 ideal, 0.5 ise şanstan daha iyi değildir). Logistic regression bu tür görevlerde çoğu zaman iyi performans gösterir; ancak phishing ve meşru siteler arasındaki decision boundary karmaşıksa daha güçlü non-linear modellere ihtiyaç duyulabilir.

</details>

### Karar Ağaçları

Bir decision tree, hem classification hem de regression görevleri için kullanılabilen çok yönlü bir **supervised learning algorithm**'dir. Verilerin feature'larına dayalı, hiyerarşik ve ağaç benzeri bir karar modeli öğrenir. Ağacın her internal node'u belirli bir feature üzerinde yapılan bir testi, her branch bu testin bir sonucunu ve her leaf node ise tahmin edilen class'ı (classification için) veya değeri (regression için) temsil eder.<sup>[[5]](#references)</sup>

Bir ağaç oluşturmak için CART (Classification and Regression Tree) gibi algorithm'ler, verileri her adımda bölmek üzere en iyi feature ve threshold'u seçmek için **Gini impurity** veya **information gain (entropy)** gibi ölçümler kullanır. Her split'teki amaç, ortaya çıkan alt kümelerde target variable'ın homojenliğini artıracak şekilde verileri partition etmektir (classification için her node, ağırlıklı olarak tek bir class içerecek şekilde mümkün olduğunca pure olmayı hedefler).

Decision tree'ler **highly interpretable**'dır -- bir prediction'ın arkasındaki mantığı anlamak için root'tan leaf'e kadar olan yol takip edilebilir (ör. *"`service = telnet` VE `src_bytes > 1000` VE `failed_logins > 3` İSE attack olarak sınıflandır"*). Bu, belirli bir alert'in neden oluşturulduğunu açıklamak açısından cybersecurity'de değerlidir. Tree'ler hem numerical hem de categorical data'yı doğal olarak işleyebilir ve çok az preprocessing gerektirir (ör. feature scaling gerekli değildir).

Bununla birlikte, özellikle derin büyütüldüğünde (çok sayıda split), tek bir decision tree training data'ya kolayca overfit olabilir. Overfitting'i önlemek için pruning (tree depth'i sınırlamak veya leaf başına minimum sample sayısı şartı koymak) gibi teknikler sıklıkla kullanılır.

Bir decision tree'nin 3 ana bileşeni vardır:
- **Root Node**: Ağacın tamamını temsil eden en üst node.
- **Internal Nodes**: Feature'ları ve bu feature'lara dayalı kararları temsil eden node'lar.
- **Leaf Nodes**: Nihai sonucu veya prediction'ı temsil eden node'lar.

Bir ağaç şu şekilde görünebilir:
```plaintext
[Root Node]
/   \
[Node A]  [Node B]
/   \      /   \
[Leaf 1] [Leaf 2] [Leaf 3] [Leaf 4]
```
> [!TIP]
> *Siber güvenlikte kullanım alanları:* Decision trees, saldırıları tanımlamak için **kurallar** türetmek amacıyla intrusion detection systems içinde kullanılmıştır. Örneğin ID3/C4.5 tabanlı ilk IDS'ler, normal ve kötü amaçlı trafiği ayırt etmek için insanların okuyabileceği kurallar üretirdi. Ayrıca bir dosyanın özniteliklerine (dosya boyutu, section entropy, API çağrıları vb.) göre kötü amaçlı olup olmadığına karar vermek için malware analysis alanında da kullanılırlar. Decision trees'in açıklığı, şeffaflığın gerektiği durumlarda onları kullanışlı kılar -- bir analyst, detection logic'i doğrulamak için ağacı inceleyebilir.

#### **Decision Trees'in temel özellikleri:**

-   **Problem Türü:** Hem classification hem de regression. Saldırılar ile normal trafik gibi durumların classification'ında yaygın olarak kullanılır.

-   **Yorumlanabilirlik:** Çok yüksek -- modelin kararları görselleştirilebilir ve if-then rules kümesi olarak anlaşılabilir. Bu, model davranışına duyulan güven ve doğrulama açısından security alanında önemli bir avantajdır.

-   **Avantajlar:** Öznitelikler arasındaki non-linear relationships ve interactions'ları yakalayabilir (her split bir interaction olarak görülebilir). Öznitelikleri scale etmeye veya categorical variables'ı one-hot encode etmeye gerek yoktur -- trees bunları doğal olarak işler. Fast inference (prediction yalnızca tree'de bir path takip edilerek yapılır).

-   **Sınırlamalar:** Kontrol edilmezse overfitting'e yatkındır (derin bir tree training set'i ezberleyebilir). Unstable olabilirler -- data'daki küçük değişiklikler farklı bir tree structure'a yol açabilir. Tekil modeller olarak accuracy'leri daha gelişmiş yöntemlerle eşleşmeyebilir (Random Forests gibi ensembles, variance'ı azaltarak genellikle daha iyi performans gösterir).

-   **En İyi Split'i Bulma:**
- **Gini Impurity**: Bir node'un impurity'sini ölçer. Daha düşük bir Gini impurity, daha iyi bir split olduğunu gösterir. Formül:

```plaintext
Gini = 1 - Σ(p_i^2)
```

Burada `p_i`, `i` sınıfındaki örneklerin oranıdır.

- **Entropy**: Dataset'teki uncertainty'yi ölçer. Daha düşük entropy, daha iyi bir split olduğunu gösterir. Formül:

```plaintext
Entropy = -Σ(p_i * log2(p_i))
```

Burada `p_i`, `i` sınıfındaki örneklerin oranıdır.

- **Information Gain**: Bir split sonrasında entropy veya Gini impurity'deki azalmadır. Information gain ne kadar yüksekse split o kadar iyidir. Şu şekilde hesaplanır:

```plaintext
Information Gain = Entropy(parent) - (Weighted Average of Entropy(children))
```

Ayrıca bir tree şu durumlarda sona erdirilir:
- Bir node'daki tüm örnekler aynı sınıfa aittir. Bu, overfitting'e yol açabilir.
- Tree'nin maksimum depth'i (hardcoded) erreicht. Bu, overfitting'i önlemenin bir yoludur.
- Bir node'daki örnek sayısı belirli bir threshold'un altındadır. Bu da overfitting'i önlemenin bir yoludur.
- Daha ileri split'lerden elde edilen information gain belirli bir threshold'un altındadır. Bu da overfitting'i önlemenin bir yoludur.

<details>
<summary>Örnek -- Intrusion Detection için Decision Tree:</summary>
NSL-KDD dataset'i üzerinde bir decision tree eğiterek network connections'ları *normal* veya *attack* olarak sınıflandıracağız. NSL-KDD, protocol type, service, duration, failed logins sayısı vb. özniteliklere ve attack type'ı veya "normal" değerini belirten bir label'a sahip olan klasik KDD Cup 1999 dataset'inin geliştirilmiş bir sürümüdür. Tüm attack type'larını "anomaly" sınıfına eşleyeceğiz (binary classification: normal ve anomaly). Training sonrasında tree'nin test set'indeki performance'ını değerlendireceğiz.
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
Bu decision tree örneğinde, aşırı overfitting'i önlemek için ağaç derinliğini 10 ile sınırladık (`max_depth=10` parametresi). Metrikler, ağacın normal ve attack trafiğini ne kadar iyi ayırt ettiğini gösterir. Yüksek recall, saldırıların çoğunu yakaladığı anlamına gelir (bir IDS için önemlidir); yüksek precision ise az sayıda false alarm anlamına gelir. Decision tree'ler yapılandırılmış verilerde genellikle makul bir doğruluk elde eder, ancak tek bir ağaç mümkün olan en iyi performansa ulaşamayabilir. Bununla birlikte, modelin *yorumlanabilirliği* büyük bir avantajdır -- ağacın split'lerini inceleyerek örneğin hangi feature'ların (`service`, `src_bytes` vb.) bir bağlantının malicious olarak işaretlenmesinde en etkili olduğunu görebiliriz.

</details>

### Random Forests

Random Forest, performansı artırmak için decision tree'lerden yararlanan bir **ensemble learning** yöntemidir. Bir random forest birden fazla decision tree eğitir (bu nedenle "forest" adı kullanılır) ve nihai bir prediction yapmak için bunların çıktılarını birleştirir (classification için genellikle majority vote kullanılır). Bir random forest'taki iki temel fikir **bagging** (bootstrap aggregating) ve **feature randomness**'tir:

-   **Bagging:** Her tree, training data'nın rastgele bir bootstrap sample'ı üzerinde eğitilir (replacement ile örneklenir). Bu, tree'ler arasında çeşitlilik oluşturur.

-   **Feature Randomness:** Bir tree'deki her split'te, split işlemi için feature'ların rastgele bir alt kümesi değerlendirilir (tüm feature'lar yerine). Bu, tree'lerin korelasyonunu daha da azaltır.

Random forest, birçok tree'nin sonuçlarının ortalamasını alarak tek bir decision tree'nin sahip olabileceği variance'ı azaltır. Basitçe ifade etmek gerekirse, bireysel tree'ler overfit olabilir veya gürültülü sonuçlar üretebilir; ancak birlikte oy kullanan çok sayıda farklı tree bu hataları dengeler. Sonuç genellikle tek bir decision tree'ye kıyasla **daha yüksek accuracy** ve daha iyi generalization sağlayan bir modeldir. Ayrıca random forest'lar, her feature split'inin impurity'yi ortalama olarak ne kadar azalttığına bakarak feature importance için bir tahmin sunabilir.

Random forest'lar intrusion detection, malware classification ve spam detection gibi görevlerde **siber güvenlik alanında temel araçlardan biri** haline gelmiştir. Genellikle minimum tuning ile kutudan çıktığı haliyle iyi performans gösterir ve büyük feature set'lerini işleyebilir. Örneğin intrusion detection'da bir random forest, daha az false positive ile saldırıların daha incelikli pattern'lerini yakalayarak tek bir decision tree'den daha iyi performans gösterebilir. Araştırmalar, random forest'ların NSL-KDD ve UNSW-NB15 gibi dataset'lerde attack classification için diğer algorithm'lere kıyasla başarılı sonuçlar verdiğini göstermiştir.<sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

#### **Random Forests'ın temel özellikleri:**

-   **Problem Türü:** Öncelikli olarak classification (regression için de kullanılır). Security log'larında yaygın olan high-dimensional structured data için oldukça uygundur.

-   **Yorumlanabilirlik:** Tek bir decision tree'ye kıyasla daha düşüktür -- yüzlerce tree'yi aynı anda kolayca görselleştiremez veya açıklayamazsınız. Bununla birlikte feature importance skorları, hangi attribute'ların en etkili olduğu konusunda bazı içgörüler sağlar.

-   **Avantajlar:** Ensemble etkisi sayesinde genellikle single-tree modellerden daha yüksek accuracy sağlar. Overfitting'e karşı dayanıklıdır -- bireysel tree'ler overfit olsa bile ensemble daha iyi generalization sağlar. Hem numerical hem de categorical feature'ları işleyebilir ve missing data'yı belirli ölçüde yönetebilir. Ayrıca outlier'lara karşı da görece dayanıklıdır.

-   **Sınırlamalar:** Model boyutu büyük olabilir (çok sayıda tree ve her biri potansiyel olarak derin). Prediction işlemi tek bir tree'ye göre daha yavaştır (çünkü birçok tree'nin sonucunu birleştirmeniz gerekir). Daha az yorumlanabilirdir -- önemli feature'ları bilseniz de kesin mantık, basit bir rule olarak kolayca izlenemez. Dataset son derece high-dimensional ve sparse ise çok büyük bir forest'ı eğitmek computational açıdan ağır olabilir.

-   **Training Süreci:**
1. **Bootstrap Sampling**: Birden fazla subset (bootstrap sample) oluşturmak için training data'yı replacement ile rastgele örnekleyin.
2. **Tree Construction**: Her bootstrap sample için, her split'te feature'ların rastgele bir alt kümesini kullanarak bir decision tree oluşturun. Bu, tree'ler arasında çeşitlilik sağlar.
3. **Aggregation**: Classification görevlerinde nihai prediction, tüm tree'lerin prediction'ları arasında majority vote alınarak yapılır. Regression görevlerinde nihai prediction, tüm tree'lerin prediction'larının ortalamasıdır.

<details>
<summary>Örnek -- Intrusion Detection için Random Forest (NSL-KDD):</summary>
Aynı NSL-KDD dataset'ini (normal ve anomaly olarak binary labeled) kullanacak ve bir Random Forest classifier eğiteceğiz. Ensemble averaging'in variance'ı azaltması sayesinde random forest'ın single decision tree kadar iyi veya ondan daha iyi performans göstermesini bekliyoruz. Aynı metriklerle değerlendirme yapacağız.
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
Random forest, bu intrusion detection görevinde genellikle güçlü sonuçlar elde eder. Verilere bağlı olarak, özellikle recall veya precision değerlerinde, tek bir decision tree ile karşılaştırıldığında F1 veya AUC gibi metriklerde iyileşme gözlemleyebiliriz. Bu, *"Random Forest (RF) bir ensemble classifier'dır ve saldırıların etkili sınıflandırılması için diğer geleneksel classifier'lara kıyasla iyi performans gösterir."* anlayışıyla uyumludur.<sup>[[6]](#references)</sup> Bir security operations bağlamında random forest modeli, çok sayıda decision rule'un ortalamasını aldığı için false alarm'ları azaltırken saldırıları daha güvenilir şekilde işaretleyebilir. Forest'tan elde edilen feature importance, hangi network feature'larının saldırıların en güçlü göstergeleri olduğunu (ör. belirli network service'leri veya olağandışı packet sayıları) gösterebilir.

</details>

### Support Vector Machines (SVM)

Support Vector Machines, öncelikle classification (ayrıca SVR olarak regression) için kullanılan güçlü supervised learning modelleridir. Bir SVM, iki class arasındaki margin'i maksimize eden **optimal separating hyperplane**'ı bulmaya çalışır. Yalnızca training point'lerinin bir alt kümesi ("boundary'ye en yakın support vector'lar") bu hyperplane'ın konumunu belirler. Margin'i (support vector'lar ile hyperplane arasındaki mesafeyi) maksimize ederek SVM'ler iyi bir generalization elde etme eğilimindedir.<sup>[[8]](#references)</sup>

SVM'nin gücünün temelinde, non-linear ilişkileri ele almak için **kernel function**'ları kullanabilmesi vardır. Data, linear bir separator'ın bulunabileceği daha yüksek boyutlu bir feature space'e örtük olarak dönüştürülebilir. Yaygın kernel'lar arasında polynomial, radial basis function (RBF) ve sigmoid bulunur. Örneğin network traffic class'ları ham feature space'te linear olarak ayrılabilir değilse, bir RBF kernel bunları daha yüksek bir boyuta map edebilir; burada SVM linear bir split bulur (bu split, original space'te non-linear bir boundary'ye karşılık gelir). Kernel seçme esnekliği, SVM'lerin çeşitli problemleri ele almasını sağlar.

SVM'lerin, yüksek boyutlu feature space'lere sahip durumlarda (text data veya malware opcode sequence'leri gibi) ve feature sayısının sample sayısına göre büyük olduğu durumlarda iyi performans gösterdiği bilinir. SVM'ler, 2000'lerde malware classification ve anomaly-based intrusion detection gibi birçok erken dönem cybersecurity uygulamasında popülerdi ve çoğu zaman yüksek accuracy gösteriyordu.

Bununla birlikte SVM'ler çok büyük dataset'lere kolayca ölçeklenemez (training complexity, sample sayısına göre super-linear'dır ve çok sayıda support vector depolaması gerekebileceğinden memory kullanımı yüksek olabilir). Pratikte, milyonlarca record içeren network intrusion detection görevlerinde SVM, dikkatli subsampling veya approximate method'lar kullanılmadan çok yavaş kalabilir.

#### **SVM'nin temel özellikleri:**

-   **Problem türü:** Classification (one-vs-one/one-vs-rest aracılığıyla binary veya multiclass) ve regression varyantları. Genellikle margin separation'ın net olduğu binary classification'da kullanılır.

-   **Yorumlanabilirlik:** Orta -- SVM'ler decision tree veya logistic regression kadar yorumlanabilir değildir. Hangi data point'lerinin support vector olduğunu belirleyebilir ve hangi feature'ların etkili olabileceği hakkında (linear kernel durumunda weight'ler aracılığıyla) fikir edinebilirsiniz; ancak pratikte SVM'ler (özellikle non-linear kernel'larla) black-box classifier olarak değerlendirilir.

-   **Avantajlar:** High-dimensional space'lerde etkilidir; kernel trick ile complex decision boundary'leri modelleyebilir; margin maksimize edilirse overfitting'e karşı dayanıklıdır (özellikle uygun bir regularization parameter'ı olan C ile); class'lar büyük bir mesafe ile ayrılmadığında bile iyi çalışır (en iyi compromise boundary'yi bulur).

-   **Sınırlamalar:** Büyük dataset'ler için **computationally intensive**'dır (data büyüdükçe hem training hem de prediction iyi ölçeklenmez). Kernel ve regularization parameter'larının (C, kernel type, RBF için gamma vb.) dikkatli şekilde ayarlanmasını gerektirir. Doğrudan probabilistic output sağlamaz (ancak probability elde etmek için Platt scaling kullanılabilir). Ayrıca SVM'ler kernel parameter'larının seçimine duyarlı olabilir --- kötü bir seçim underfit veya overfit'e yol açabilir.

*Cybersecurity'deki kullanım alanları:* SVM'ler **malware detection** (ör. dosyaları çıkarılan feature'lara veya opcode sequence'lerine göre sınıflandırma), **network anomaly detection** (traffic'i normal veya malicious olarak sınıflandırma) ve **phishing detection** (URL feature'larını kullanma) için kullanılmıştır. Örneğin bir SVM, bir email'in feature'larını (belirli keyword'lerin sayıları, sender reputation score'ları vb.) alıp bunu phishing veya legitimate olarak sınıflandırabilir. Ayrıca KDD gibi feature set'leri üzerinde **intrusion detection** için de uygulanmış ve computation maliyeti karşılığında çoğu zaman yüksek accuracy elde edilmiştir.

<details>
<summary>Örnek -- Malware Classification için SVM:</summary>
Bu kez phishing website dataset'ini bir SVM ile tekrar kullanacağız. SVM'ler yavaş olabileceğinden, gerekirse training için data'nın bir alt kümesini kullanacağız (dataset yaklaşık 11k instance içeriyor ve SVM bunu makul şekilde işleyebilir). Non-linear data için yaygın bir seçim olan RBF kernel'ı kullanacağız ve ROC AUC hesaplamak için probability estimate'lerini etkinleştireceğiz.
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
SVM modeli, aynı görevde lojistik regresyonla karşılaştırabileceğimiz metrikler üretecektir. Veriler özellikler tarafından iyi şekilde ayrılıyorsa SVM'nin yüksek doğruluk ve AUC değerine ulaştığını görebiliriz. Öte yandan veri kümesinde çok fazla gürültü veya örtüşen sınıflar varsa SVM, lojistik regresyondan önemli ölçüde daha iyi performans göstermeyebilir. Uygulamada SVM'ler, özellikler ile sınıf arasında karmaşık, doğrusal olmayan ilişkiler olduğunda avantaj sağlayabilir -- RBF kernel'i, lojistik regresyonun yakalayamayacağı eğri karar sınırlarını modelleyebilir. Tüm modellerde olduğu gibi, bias ve variance dengesini sağlamak için `C` (regularization) ve kernel parametrelerinin (RBF için `gamma` gibi) dikkatli şekilde ayarlanması gerekir.

</details>

#### Lojistik Regresyon ve SVM Arasındaki Farklar

| Aspect | **Lojistik Regresyon** | **Support Vector Machines** |
|---|---|---|
| **Objective function** | **log-loss** (cross-entropy) değerini minimize eder. | **hinge-loss** değerini minimize ederken **margin** değerini maksimize eder. |
| **Decision boundary** | _P(y\|x)_ değerini modelleyen **en iyi uyumlu hyperplane**'i bulur. | **Maksimum-margin hyperplane**'i (en yakın noktalara en büyük uzaklığa sahip hyperplane'i) bulur. |
| **Output** | **Olasılıksal** – σ(w·x + b) aracılığıyla kalibre edilmiş sınıf olasılıkları sağlar. | **Deterministik** – sınıf etiketleri döndürür; olasılıklar için ek işlem gerekir (ör. Platt scaling). |
| **Regularisation** | L2 (varsayılan) veya L1, underfitting/overfitting dengesini doğrudan sağlar. | C parametresi, margin genişliği ile yanlış sınıflandırmalar arasında denge kurar; kernel parametreleri karmaşıklık ekler. |
| **Kernels / Non-linear** | Yerel biçimi **lineer**dir; non-linearity feature engineering ile eklenir. | Yerleşik **kernel trick** (RBF, poly vb.), yüksek boyutlu uzayda karmaşık sınırları modellemesini sağlar. |
| **Scalability** | **O(nd)** karmaşıklığında convex optimisation gerçekleştirir; çok büyük n değerlerini iyi işler. | Özel solver'lar olmadan eğitim, bellek/zaman açısından **O(n²–n³)** olabilir; çok büyük n değerleri için daha elverişsizdir. |
| **Interpretability** | **Yüksek** – ağırlıklar feature etkisini gösterir; odds ratio sezgiseldir. | Non-linear kernel'ler için **düşük**; support vector'ler sparse olsa da açıklanmaları kolay değildir. |
| **Sensitivity to outliers** | Smooth log-loss kullanır → daha az hassastır. | Hard margin kullanan hinge-loss **hassas** olabilir; soft-margin (C) bunu azaltır. |
| **Typical use cases** | **Olasılıkların ve açıklanabilirliğin** önemli olduğu kredi puanlama, tıbbi risk ve A/B testing. | **Karmaşık sınırların** ve **yüksek boyutlu verilerin** önemli olduğu image/text classification ve bio-informatics. |

* **Kalibre edilmiş olasılıklara, açıklanabilirliğe ihtiyacınız varsa veya çok büyük veri kümeleriyle çalışıyorsanız — Lojistik Regresyon'u seçin.**
* **Manuel feature engineering yapmadan doğrusal olmayan ilişkileri yakalayabilen esnek bir modele ihtiyacınız varsa — SVM'yi (kernel'lerle) seçin.**
* Her ikisi de convex objective'ları optimize eder; bu nedenle **global minimum'lar garanti edilir**, ancak SVM'nin kernel'leri hyper-parameter'lar ve hesaplama maliyeti ekler.

### Naive Bayes

Naive Bayes, özellikler arasında güçlü bir bağımsızlık varsayımıyla Bayes Teoremi'nin uygulanmasına dayanan bir **olasılıksal classifier** ailesidir. Bu "naive" varsayıma rağmen Naive Bayes, özellikle spam detection gibi text veya categorical data içeren belirli uygulamalarda çoğu zaman şaşırtıcı derecede iyi çalışır.<sup>[[9]](#references)</sup>


#### Bayes' Teoremi

Bayes teoremi, Naive Bayes classifier'larının temelidir. Rastgele olayların koşullu ve marjinal olasılıklarını ilişkilendirir. Formül şöyledir:
```plaintext
P(A|B) = (P(B|A) * P(A)) / P(B)
```
Where:
- `P(A|B)`, `B` özelliği verildiğinde `A` sınıfının posterior olasılığıdır.
- `P(B|A)`, `A` sınıfı verildiğinde `B` özelliğinin olabilirliğidir.
- `P(A)`, `A` sınıfının önsel olasılığıdır.
- `P(B)`, `B` özelliğinin önsel olasılığıdır.

Örneğin, bir metnin çocuk mu yoksa yetişkin tarafından mı yazıldığını sınıflandırmak istiyorsak metindeki kelimeleri özellik olarak kullanabiliriz. Bazı başlangıç verilerine dayanarak Naive Bayes classifier, her kelimenin olası sınıfların her birinde (çocuk veya yetişkin) bulunma olasılıklarını önceden hesaplar. Yeni bir metin verildiğinde, metindeki kelimeler verildiğinde her olası sınıfın olasılığını hesaplar ve en yüksek olasılığa sahip sınıfı seçer.

Bu örnekte görebileceğiniz gibi Naive Bayes classifier çok basit ve hızlıdır; ancak özelliklerin birbirinden bağımsız olduğunu varsayar. Gerçek dünya verilerinde bu durum her zaman geçerli değildir.


#### Naive Bayes Classifier Türleri

Veri türüne ve özelliklerin dağılımına bağlı olarak çeşitli Naive Bayes classifier türleri vardır:
- **Gaussian Naive Bayes**: Özelliklerin Gaussian (normal) dağılımı izlediğini varsayar. Sürekli veriler için uygundur.
- **Multinomial Naive Bayes**: Özelliklerin multinomial dağılım izlediğini varsayar. Metin classification'daki kelime sayımları gibi ayrık veriler için uygundur.
- **Bernoulli Naive Bayes**: Özelliklerin binary (0 veya 1) olduğunu varsayar. Metin classification'da kelimelerin bulunması veya bulunmaması gibi binary veriler için uygundur.
- **Categorical Naive Bayes**: Özelliklerin categorical değişkenler olduğunu varsayar. Meyveleri renk ve şekillerine göre sınıflandırmak gibi categorical veriler için uygundur.


#### **Naive Bayes'in temel özellikleri:**

-   **Problem Türü:** Classification (binary veya multi-class). Siber güvenlikteki text classification görevlerinde (spam, phishing vb.) yaygın olarak kullanılır.

-   **Yorumlanabilirlik:** Orta düzeydedir -- decision tree kadar doğrudan yorumlanabilir değildir; ancak öğrenilen olasılıklar incelenebilir (örneğin spam ve ham e-postalarda hangi kelimelerin bulunma olasılığının en yüksek olduğu). Modelin biçimi (sınıf verildiğinde her özellik için olasılıklar), gerektiğinde anlaşılabilir.

-   **Avantajlar:** Büyük dataset'lerde bile **çok hızlı** training ve prediction (instance sayısı * feature sayısı ile lineer). Özellikle uygun smoothing ile olasılıkları güvenilir biçimde tahmin etmek için görece az miktarda veri gerektirir. Özelliklerin sınıfa bağımsız olarak kanıt sağladığı durumlarda, baseline olarak çoğu zaman şaşırtıcı derecede doğrudur. High-dimensional verilerle (örneğin text'ten elde edilen binlerce feature) iyi çalışır. Bir smoothing parametresi ayarlamak dışında karmaşık tuning gerektirmez.

-   **Sınırlamalar:** Özellikler yüksek oranda correlated olduğunda bağımsızlık varsayımı doğruluğu sınırlayabilir. Örneğin network verilerinde `src_bytes` ve `dst_bytes` gibi özellikler correlated olabilir; Naive Bayes bu etkileşimi yakalayamaz. Veri boyutu çok büyüdükçe, feature dependencies öğrenebilen daha expressive modeller (ensemble'lar veya neural net'ler gibi) NB'yi geçebilir. Ayrıca bir saldırıyı tanımlamak için belirli bir feature kombinasyonu gerekiyorsa (özelliklerin yalnızca tek başına bağımsız olarak değerlendirilmesi yeterli değilse), NB zorlanır.

> [!TIP]
> *Siber güvenlikte kullanım alanları:* Klasik kullanım alanı **spam detection**'dır -- Naive Bayes, belirli token'ların (kelimeler, ifadeler, IP adresleri) sıklığını kullanarak bir e-postanın spam olma olasılığını hesaplayan erken dönem spam filter'larının temeliydi. Ayrıca **phishing email detection** ve **URL classification** için de kullanılır; burada belirli keyword'lerin veya karakteristiklerin bulunması (bir URL'de "login.php" olması veya URL path'inde `@` bulunması gibi) phishing olasılığına katkıda bulunur. Malware analysis'de, bir yazılımda belirli API çağrılarının veya permission'ların bulunmasını kullanarak bunun malware olup olmadığını tahmin eden bir Naive Bayes classifier düşünülebilir. Daha gelişmiş algorithm'ler çoğu zaman daha iyi performans gösterse de Naive Bayes, hızı ve basitliği sayesinde iyi bir baseline olmaya devam eder.

<details>
<summary>Örnek -- Phishing Detection için Naive Bayes:</summary>
Naive Bayes'i göstermek için binary label'lara sahip NSL-KDD intrusion dataset üzerinde Gaussian Naive Bayes kullanacağız. Gaussian NB, her feature'ın sınıfa göre normal dağılım izlediğini kabul eder. Network feature'larının çoğu discrete veya highly skewed olduğundan bu kaba bir seçimdir; ancak NB'nin continuous feature verilerine nasıl uygulanacağını gösterir. Binary feature'lardan oluşan bir dataset üzerinde (örneğin tetiklenen alert'lerden oluşan bir set) Bernoulli NB'yi de seçebilirdik; ancak burada süreklilik açısından NSL-KDD ile devam edeceğiz.
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
Bu kod, saldırıları tespit etmek için bir Naive Bayes classifier eğitir. Naive Bayes, özellikler arasında bağımsızlık olduğunu varsayarak eğitim verilerine dayanarak `P(service=http | Attack)` ve `P(Service=http | Normal)` gibi olasılıkları hesaplar. Ardından gözlemlenen özelliklere göre yeni bağlantıları normal veya saldırı olarak sınıflandırmak için bu olasılıkları kullanır. Özellik bağımsızlığı ihlal edildiğinden NB'nin NSL-KDD üzerindeki performansı daha gelişmiş modeller kadar yüksek olmayabilir; ancak genellikle yeterli sonuç verir ve son derece hızlı olması gibi bir avantaj sunar. Gerçek zamanlı e-posta filtreleme veya URL'lerin ilk triage işlemi gibi senaryolarda Naive Bayes modeli, düşük kaynak kullanımıyla açıkça malicious durumları hızlıca işaretleyebilir.

</details>

### k-Nearest Neighbors (k-NN)

k-Nearest Neighbors, en basit machine learning algoritmalarından biridir. Eğitim kümesindeki örneklere olan benzerliğe göre tahmin yapan **non-parametric, instance-based** bir yöntemdir. Classification için temel fikir şudur: yeni bir data point'i sınıflandırmak için eğitim verilerindeki en yakın **k** noktayı (yani "nearest neighbors") bulmak ve bu komşular arasındaki çoğunluk sınıfını atamak. "Yakınlık", bir distance metric ile tanımlanır; numeric data için genellikle Euclidean distance kullanılır (farklı feature veya problem türleri için başka distance ölçümleri de kullanılabilir).<sup>[[10]](#references)</sup>

K-NN, *açık bir training işlemi gerektirmez* -- "training" aşaması yalnızca dataset'in saklanmasından ibarettir. Tüm işlem query (prediction) sırasında gerçekleşir: algoritma, en yakın noktaları bulmak için query point ile tüm training point'leri arasındaki distance değerlerini hesaplamalıdır. Bu durum, prediction süresini **training sample sayısıyla doğrusal** hale getirir ve büyük dataset'lerde maliyetli olabilir. Bu nedenle k-NN, daha küçük dataset'ler veya basitlik karşılığında memory ve speed kullanımını artırabileceğiniz senaryolar için daha uygundur.

Basit olmasına rağmen k-NN, oldukça karmaşık decision boundary'leri modelleyebilir (çünkü decision boundary, örneklerin dağılımının belirlediği herhangi bir şekli alabilir). Decision boundary çok düzensiz olduğunda ve elinizde çok miktarda data bulunduğunda genellikle iyi performans gösterir -- temel olarak data'nın "kendi adına konuşmasına" izin verir. Ancak yüksek boyutlarda distance metric'leri anlamlılığını yitirebilir (curse of dimensionality) ve çok fazla sample bulunmadığı sürece yöntem zorlanabilir.

*Cybersecurity kullanım alanları:* k-NN, anomaly detection için kullanılmıştır -- örneğin bir intrusion detection system, nearest neighbor'larının (önceki event'lerin) çoğu malicious ise bir network event'ini malicious olarak etiketleyebilir. Normal traffic kümeler oluşturuyor ve saldırılar outlier durumundaysa, k-NN yaklaşımı (k=1 veya küçük bir k ile) temel olarak bir **nearest-neighbor anomaly detection** yöntemi haline gelir. K-NN, binary feature vector'leri kullanarak malware family'lerini sınıflandırmak için de kullanılmıştır: yeni bir file, feature space'te belirli bir malware family'sinin bilinen instance'larına çok yakınsa bu family'ye ait olarak sınıflandırılabilir. Uygulamada k-NN, daha iyi ölçeklenebilen algoritmalar kadar yaygın değildir; ancak kavramsal olarak anlaşılması kolaydır ve bazen baseline olarak veya küçük ölçekli problemler için kullanılır.

#### **k-NN'nin temel özellikleri:**

-   **Problem Türü:** Classification (regression varyantları da bulunur). Bu, *lazy learning* yöntemidir -- açık bir model fitting işlemi yoktur.

-   **Yorumlanabilirlik:** Düşük ila orta -- global bir model veya kısa ve öz bir açıklama yoktur; ancak bir karar üzerinde etkili olan nearest neighbor'lara bakılarak sonuçlar yorumlanabilir (örneğin, "bu network flow, şu 3 bilinen malicious flow'a benzediği için malicious olarak sınıflandırıldı"). Bu nedenle açıklamalar example-based olabilir.

-   **Avantajlar:** Uygulaması ve anlaşılması çok basittir. Data dağılımı hakkında herhangi bir varsayımda bulunmaz (non-parametric). Multi-class problemlerini doğal olarak ele alabilir. Decision boundary'lerin data dağılımı tarafından şekillendirilen çok karmaşık biçimler alabilmesi nedeniyle **adaptive** bir yöntemdir.

-   **Sınırlamalar:** Büyük dataset'lerde prediction yavaş olabilir (çok sayıda distance hesaplanmalıdır). Memory açısından yoğundur -- tüm training data'sını saklar. Tüm noktalar neredeyse eşit uzaklıktaymış gibi olma eğiliminde olduğundan, yüksek boyutlu feature space'lerde performans düşer (bu da "nearest" kavramını daha az anlamlı hale getirir). *k* (neighbor sayısı) uygun şekilde seçilmelidir -- çok küçük bir k gürültülü sonuçlara, çok büyük bir k ise diğer sınıflardan ilgisiz noktaların dahil edilmesine neden olabilir. Ayrıca distance hesaplamaları scale'e duyarlı olduğundan feature'lar uygun şekilde scale edilmelidir.

<details>
<summary>Örnek -- Phishing Detection için k-NN:</summary>

Yine NSL-KDD kullanacağız (binary classification). k-NN computational açıdan ağır olduğundan, bu demonstration'ı uygulanabilir tutmak için training data'nın bir alt kümesini kullanacağız. Full 125k içinden örneğin 20.000 training sample seçecek ve k=5 neighbor kullanacağız. Training işleminden sonra (aslında yalnızca data saklanmış olacak), test seti üzerinde değerlendirme yapacağız. Ayrıca distance hesaplaması için feature'ları scale edeceğiz; böylece scale nedeniyle tek bir feature'ın baskın hale gelmesini önleyeceğiz.
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
k-NN modeli, training set alt kümesindeki en yakın 5 bağlantıya bakarak bir bağlantıyı sınıflandırır. Örneğin, bu komşuların 4'ü attack (anomaly) ve 1'i normal ise yeni bağlantı attack olarak sınıflandırılır. Performans makul olabilir; ancak genellikle aynı veriler üzerinde iyi ayarlanmış bir Random Forest veya SVM kadar yüksek değildir. Bununla birlikte k-NN, class dağılımları oldukça düzensiz ve karmaşık olduğunda, effectively memory-based lookup kullanarak bazen öne çıkabilir. Cybersecurity alanında k-NN (k=1 veya küçük bir k değeriyle), bilinen attack pattern'lerini örnekler üzerinden tespit etmek ya da daha karmaşık sistemlerde (örneğin clustering ve ardından cluster membership'e göre classification yapmak için) bir bileşen olarak kullanılabilir.
</details>

### Gradient Boosting Machines (e.g., XGBoost)

Gradient Boosting Machines, structured data için en güçlü algorithm'ler arasındadır. **Gradient boosting**, weak learner'lardan (çoğunlukla decision tree'lerden) oluşan bir ensemble'ı sıralı biçimde oluşturma tekniğini ifade eder; burada her yeni model, önceki ensemble'ın hatalarını düzeltir. Tree'leri paralel olarak oluşturarak ortalamalarını alan bagging'in (Random Forests) aksine boosting, tree'leri *one by one* oluşturur ve her biri önceki tree'lerin yanlış tahmin ettiği instance'lara daha fazla odaklanır.<sup>[[11]](#references)</sup>

Son yıllardaki en popüler implementation'lar **XGBoost**, **LightGBM** ve **CatBoost**'tur; bunların tümü gradient boosting decision tree (GBDT) library'leridir. Machine learning competitions ve uygulamalarında son derece başarılı olmuş, çoğu zaman **tabular dataset'lerde state-of-the-art performance elde etmişlerdir**. Cybersecurity alanında researchers ve practitioners, gradient boosted tree'leri **malware detection** (file'lardan veya runtime behavior'dan çıkarılan feature'ları kullanarak) ve **network intrusion detection** gibi görevlerde kullanmıştır. Örneğin, bir gradient boosting modeli "çok sayıda SYN packet'i ve unusual port varsa -> muhtemelen scan" gibi birçok weak rule'u (tree) birleştirerek, çok sayıda ince pattern'i hesaba katan güçlü bir composite detector oluşturabilir.

Boosted tree'ler neden bu kadar etkilidir? Sequence içindeki her tree, mevcut ensemble'ın prediction'larındaki *residual errors* (gradient'ler) üzerinde eğitilir. Bu şekilde model, zayıf olduğu alanları kademeli olarak **"boost" eder**. Base learner olarak decision tree'lerin kullanılması, final modelin karmaşık interaction'ları ve non-linear relation'ları yakalamasını sağlar. Ayrıca boosting, yerleşik bir regularization biçimine sahiptir: çok sayıda küçük tree ekleyerek (ve katkılarını ölçeklendirmek için learning rate kullanarak), uygun parametreler seçildiğinde genellikle aşırı overfitting olmadan iyi generalize olur.

#### **Key characteristics of Gradient Boosting:**

-   **Type of Problem:** Öncelikle classification ve regression. Security alanında genellikle classification (örneğin, bir connection'ı veya file'ı binary olarak classify etmek) kullanılır. Binary, multi-class (uygun loss ile) ve hatta ranking problem'lerini ele alabilir.

-   **Interpretability:** Düşük ila orta. Tek bir boosted tree küçük olsa da full model yüzlerce tree içerebilir ve bir bütün olarak human-interpretable değildir. Bununla birlikte Random Forest gibi feature importance score'ları sağlayabilir; SHAP (SHapley Additive exPlanations) gibi tool'lar da individual prediction'ları bir ölçüde yorumlamak için kullanılabilir.

-   **Advantages:** Structured/tabular data için çoğu zaman **en yüksek performansı gösteren** algorithm'dir. Karmaşık pattern'leri ve interaction'ları tespit edebilir. Model complexity'yi özelleştirmek ve overfitting'i önlemek için çok sayıda tuning seçeneğine (tree sayısı, tree depth'i, learning rate, regularization term'leri) sahiptir. Modern implementation'lar speed için optimize edilmiştir (örneğin XGBoost, second-order gradient bilgisi ve efficient data structure'lar kullanır). Uygun loss function'larla birleştirildiğinde veya sample weight'leri ayarlandığında imbalanced data'yı daha iyi ele alma eğilimindedir.

-   **Limitations:** Daha basit model'lere göre tune edilmesi daha zordur; tree'ler deep olduğunda veya tree sayısı fazla olduğunda training yavaşlayabilir (yine de aynı data üzerinde comparable bir deep neural network train etmekten genellikle daha hızlıdır). Tune edilmezse model overfit olabilir (örneğin, yeterli regularization olmadan çok fazla deep tree kullanıldığında). Çok sayıda hyperparameter nedeniyle gradient boosting'i etkili biçimde kullanmak daha fazla expertise veya experimentation gerektirebilir. Ayrıca tree-based method'lar gibi, çok sparse high-dimensional data'yı linear model'ler veya Naive Bayes kadar verimli biçimde inherently ele almaz (text classification'da olduğu gibi yine de uygulanabilir; ancak feature engineering olmadan ilk tercih olmayabilir).

> [!TIP]
> *Cybersecurity'de kullanım alanları:* Bir decision tree veya random forest'ın kullanılabileceği neredeyse her yerde, bir gradient boosting modeli daha iyi accuracy sağlayabilir. Örneğin, **Microsoft'un malware detection** competition'larında binary file'lardan elde edilen engineered feature'lar üzerinde XGBoost yoğun biçimde kullanılmıştır. **Network intrusion detection** araştırmaları çoğu zaman GBDT'lerle (örneğin CIC-IDS2017 veya UNSW-NB15 dataset'lerinde XGBoost kullanarak) en iyi sonuçları bildirir. Bu modeller, threat'leri tespit etmek için geniş bir feature yelpazesini (protocol type'ları, belirli event'lerin frequency'si, traffic'in statistical feature'ları vb.) alıp birleştirebilir. Phishing detection'da gradient boosting; URL'lerin lexical feature'larını, domain reputation feature'larını ve page content feature'larını birleştirerek çok yüksek accuracy elde edebilir. Ensemble yaklaşımı, data'daki birçok corner case'i ve inceliği kapsanmaya yardımcı olur.

<details>
<summary>Example -- XGBoost for Phishing Detection:</summary>
Phishing dataset'i üzerinde bir gradient boosting classifier kullanacağız. İşleri basit ve self-contained tutmak için `sklearn.ensemble.GradientBoostingClassifier` kullanacağız (bu, daha yavaş ancak anlaşılır bir implementation'dır). Normalde daha iyi performance ve ek feature'lar için `xgboost` veya `lightgbm` library'lerinden biri kullanılabilir. Model'i train edecek ve daha önce olduğu gibi evaluate edeceğiz.
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
Gradient boosting modeli muhtemelen bu phishing veri setinde çok yüksek doğruluk ve AUC değerine ulaşacaktır (literatürde görüldüğü üzere, bu tür verilerde uygun ayarlamalarla bu modeller genellikle %95'in üzerinde doğruluk sağlayabilir. Bu durum, GBDT'lerin neden *"tabular dataset için son teknoloji model"* olarak kabul edildiğini gösterir -- karmaşık örüntüleri yakalayarak genellikle daha basit algoritmalardan daha iyi performans gösterirler.<sup>[[11]](#references)</sup> Siber güvenlik bağlamında bu, daha az hatalı tespit ile daha fazla phishing sitesi veya saldırısının yakalanması anlamına gelebilir. Elbette overfitting konusunda dikkatli olunmalıdır -- böyle bir modeli deployment için geliştirirken genellikle cross-validation gibi teknikleri kullanır ve bir validation seti üzerindeki performansı izleriz.

</details>

### Modelleri Birleştirme: Ensemble Learning ve Stacking

Ensemble learning, genel performansı iyileştirmek için **birden fazla modeli birleştirme** stratejisidir. Belirli ensemble yöntemlerini zaten gördük: Random Forest (bagging aracılığıyla ağaçlardan oluşan bir ensemble) ve Gradient Boosting (sıralı boosting aracılığıyla ağaçlardan oluşan bir ensemble). Ancak ensemble'lar **voting ensemble** veya **stacked generalization (stacking)** gibi başka yöntemlerle de oluşturulabilir. Temel fikir, farklı modellerin farklı örüntüleri yakalayabilmesi veya farklı zayıflıklara sahip olabilmesidir; bunları birleştirerek **her modelin hatalarını diğerinin güçlü yönleriyle telafi edebiliriz**.<sup>[[12]](#references)</sup>

-   **Voting Ensemble:** Basit bir voting classifier'da birden fazla çeşitli model (örneğin bir logistic regression, bir decision tree ve bir SVM) eğitir ve nihai tahmin için bunların oy kullanmasını sağlarız (classification için çoğunluk oyu). Oyları ağırlıklandırırsak (örneğin daha doğru modellere daha yüksek ağırlık verirsek), weighted voting yöntemi elde edilir. Bu yöntem, bireysel modeller yeterince iyi ve bağımsız olduğunda genellikle performansı artırır -- ensemble, bir modelin hata yapma riskini azaltır; çünkü diğer modeller bu hatayı düzeltebilir. Bu, tek bir görüş yerine bir uzmanlar paneline sahip olmak gibidir.

-   **Stacking (Stacked Ensemble):** Stacking bir adım daha ileri gider. Basit bir oylama yerine, temel modellerin tahminlerini **en iyi şekilde nasıl birleştireceğini öğrenmek** için bir **meta-model** eğitir. Örneğin, 3 farklı classifier (base learner) eğitir, ardından bunların çıktılarını (veya olasılıklarını) bir meta-classifier'a (genellikle logistic regression gibi basit bir model) feature olarak aktarırız; meta-classifier bunları birleştirmenin en uygun yolunu öğrenir. Overfitting'i önlemek için meta-model bir validation seti üzerinde veya cross-validation aracılığıyla eğitilir. Stacking, *hangi koşullarda hangi modellere daha fazla güvenilmesi gerektiğini* öğrenerek basit voting yönteminden çoğu zaman daha iyi performans gösterebilir. Siber güvenlikte bir model network scan'lerini yakalamada daha iyi olurken başka bir model malware beaconing'i yakalamada daha iyi olabilir; stacking modeli her birine uygun şekilde güvenmeyi öğrenebilir.

Voting veya stacking yoluyla oluşturulan ensemble'lar genellikle **doğruluğu** ve dayanıklılığı artırır. Dezavantajı ise artan karmaşıklık ve bazen azalan yorumlanabilirliktir (ancak decision tree'lerin ortalaması gibi bazı ensemble yaklaşımları, örneğin feature importance sağlayarak, yine de bir miktar içgörü sunabilir). Uygulamadaki kısıtlamalar izin veriyorsa ensemble kullanmak daha yüksek detection rate sağlayabilir. Siber güvenlik challenge'larında (ve genel olarak Kaggle yarışmalarında) birçok başarılı çözüm, performansın son kısmını da elde etmek için ensemble tekniklerini kullanır.

<details>
<summary>Örnek -- Phishing Detection için Voting Ensemble:</summary>
Model stacking'i açıklamak için phishing veri setinde ele aldığımız modellerden birkaçını birleştirelim. Base learner olarak bir logistic regression, bir decision tree ve bir k-NN kullanacak; tahminlerini birleştirmek için meta-learner olarak bir Random Forest kullanacağız. Meta-learner, base learner'ların çıktıları üzerinde (training seti ile cross-validation kullanılarak) eğitilecektir. Stacked modelin, bireysel modeller kadar iyi veya onlardan biraz daha iyi performans göstermesini bekliyoruz.
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
Stacked ensemble, temel modellerin birbirini tamamlayan güçlü yönlerinden yararlanır. Örneğin logistic regression verilerin doğrusal yönlerini ele alabilir, decision tree belirli kural benzeri etkileşimleri yakalayabilir ve k-NN özellik uzayının yerel bölgelerinde başarılı olabilir. Meta-model (burada random forest), bu girdilerin nasıl ağırlıklandırılacağını öğrenebilir. Ortaya çıkan metrikler çoğu zaman (küçük de olsa) herhangi bir tek modelin metriklerine kıyasla iyileşme gösterir. Phishing örneğimizde logistic modelinin tek başına F1 değeri örneğin 0.95 ve tree modelinin değeri 0.94 ise stack, her modelin hata yaptığı noktaları telafi ederek 0.96 değerine ulaşabilir.

Bunun gibi ensemble yöntemleri, *"birden fazla modelin birleştirilmesi genellikle daha iyi genelleme sağlar"* ilkesini gösterir.<sup>[[12]](#references)</sup> Cybersecurity alanında bu, birden fazla detection engine kullanılarak (biri rule-based, biri machine learning, biri anomaly-based olabilir) ve ardından uyarıları toplayan bir katmanla -- esasen bir ensemble biçimiyle -- daha yüksek güvenle nihai karar verilerek uygulanabilir. Bu tür sistemleri dağıtırken, eklenen karmaşıklık göz önünde bulundurulmalı ve ensemble'ın yönetilmesi veya açıklanmasının aşırı zor hale gelmemesi sağlanmalıdır. Ancak doğruluk açısından ensemble ve stacking, model performansını iyileştirmek için güçlü araçlardır.

</details>

[deep-learning page](AI-Deep-Learning.md) içinde açıklanan neural-network yaklaşımları, dataset ve compute budget ek karmaşıklığı haklı çıkardığında intrusion detection için bu klasik modelleri tamamlayabilir.<sup>[[13]](#references)</sup>

## References

- [1] [Cybersecurity'de AI ve Machine Learning - zvelo](https://zvelo.com/ai-and-machine-learning-in-cybersecurity/)
- [2] [Linear Regression Açıklaması - Medium](https://medium.com/@chaandram/linear-regression-explained-28d5bf1934ae)
- [3] [Logistic Regression - Medium](https://madhuramiah.medium.com/logistic-regression-6e55553cc003)
- [4] [Sohail Ahmed Khan, Wasiq Khan, Abir Hussain - "Machine Learning ve Birden Fazla Dataset Kullanılarak Phishing Attack ve Website Sınıflandırması (Karşılaştırmalı Bir Analiz)"](https://arxiv.org/pdf/2101.02552)
- [5] [Decision Tree - GeeksforGeeks](https://www.geeksforgeeks.org/decision-tree-introduction-example/)
- [6] [Reena Singh Rajput, Sanjay Agrawal - "Information Gain ile Random Forest Classifier Kullanarak Denial of Services Attack Detection"](https://rjwave.org/ijedr/viewpaperforall.php?paper=IJEDR1703132)
- [7] [Raisa Abedin Disha, Sajjad Waheed - "Gini Impurity tabanlı Weighted Random Forest (GIWRF) feature selection tekniği kullanılarak intrusion detection system için machine learning modellerinin performans analizi"](https://cybersecurity.springeropen.com/articles/10.1186/s42400-021-00103-8)
- [8] [Support Vector Machine nedir? - IBM](https://www.ibm.com/think/topics/support-vector-machine)
- [9] [Naive Bayes spam filtering - Wikipedia](https://en.m.wikipedia.org/wiki/Naive_Bayes_spam_filtering)
- [10] [k-Nearest Neighbors (KNN) nedir? - IBM](https://www.ibm.com/think/topics/knn)
- [11] [GBDT Açıklaması: LightGBM, XGBoost ve CatBoost Nasıl Çalışır? - Medium](https://medium.com/@rupalipatelkvc/gbdt-demystified-how-lightgbm-xgboost-and-catboost-work-9479b7262644)
- [12] [Ensemble Learning: Güçlü Yönleri Birleştirerek Model Performansını Artırma - Medium](https://medium.com/@sarahzouinina/ensemble-learning-boosting-model-performance-by-combining-strengths-02e56165b901)
- [13] [Deep Learning Intrusion Detection System'lerini Nasıl Geliştirir?](https://cybersecurity-magazine.com/how-deep-learning-enhances-intrusion-detection-systems/)
{{#include ../banners/hacktricks-training.md}}
