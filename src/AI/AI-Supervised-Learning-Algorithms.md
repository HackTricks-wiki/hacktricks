# Denetimli Öğrenme Algoritmaları

{{#include ../banners/hacktricks-training.md}}

## Temel Bilgiler

Denetimli öğrenme, yeni ve daha önce görülmemiş girdiler üzerinde tahminler yapabilen modelleri eğitmek için etiketlenmiş verileri kullanır. Cybersecurity alanında denetimli machine learning; izinsiz giriş tespiti (ağ trafiğini *normal* veya *attack* olarak sınıflandırma), malware detection (kötü amaçlı yazılımları zararsız yazılımlardan ayırma), phishing detection (sahte web sitelerini veya e-postaları belirleme) ve spam filtering gibi görevlerde yaygın olarak uygulanır.<sup>[[1]](#references)</sup> Her algoritmanın kendine özgü güçlü yönleri vardır ve farklı problem türlerine (classification veya regression) uygundur. Aşağıda temel denetimli öğrenme algoritmalarını inceleyecek, nasıl çalıştıklarını açıklayacak ve gerçek cybersecurity veri kümeleri üzerinde kullanımlarını göstereceğiz. Ayrıca modelleri birleştirmenin (ensemble learning) tahmin performansını çoğu zaman nasıl iyileştirebildiğini de ele alacağız.

## Algoritmalar

-   **Linear Regression:** Verilere doğrusal bir denklem uydurarak sayısal sonuçları tahmin eden temel bir regression algoritmasıdır.

-   **Logistic Regression:** Adına rağmen, ikili bir sonucun olasılığını modellemek için logistic function kullanan bir classification algoritmasıdır.

-   **Decision Trees:** Tahmin yapmak için verileri özelliklere göre bölen, ağaç yapısındaki modellerdir; genellikle yorumlanabilirlikleri nedeniyle kullanılırlar.

-   **Random Forests:** Doğruluğu artıran ve overfitting'i azaltan, decision tree'lerden oluşan bir ensemble modelidir (bagging yoluyla).

-   **Support Vector Machines (SVM):** En uygun ayırıcı hyperplane'i bulan, maximum-margin classifier'lardır; doğrusal olmayan veriler için kernel'lar kullanabilirler.

-   **Naive Bayes:** Özelliklerin bağımsız olduğu varsayımıyla Bayes theorem'e dayanan ve spam filtering'de kullanılmasıyla tanınan olasılıksal bir classifier'dır.

-   **k-Nearest Neighbors (k-NN):** Bir sample'ı en yakın komşularının çoğunluk sınıfına göre etiketleyen basit, "instance-based" bir classifier'dır.

-   **Gradient Boosting Machines:** Daha zayıf learner'ları (genellikle decision tree'leri) sıralı olarak ekleyerek güçlü bir predictor oluşturan ensemble modellerdir (ör. XGBoost, LightGBM).

Aşağıdaki her bölüm, algoritmanın geliştirilmiş bir açıklamasını ve `pandas` ile `scikit-learn` gibi kütüphaneleri (neural network örneği için `PyTorch`) kullanan bir **Python code example** sunar. Örnekler, herkese açık cybersecurity veri kümelerini (izinsiz giriş tespiti için NSL-KDD ve bir Phishing Websites veri kümesi gibi) kullanır ve tutarlı bir yapı izler:

1.  **Veri kümesini yükleyin** (varsa URL üzerinden indirin).

2.  **Verileri preprocess edin** (ör. categorical feature'ları encode edin, değerleri scale edin, train/test set'lerine ayırın).

3.  **Modeli train verileri** üzerinde eğitin.

4.  Classification için accuracy, precision, recall, F1-score ve ROC AUC; regression için ise mean squared error metriklerini kullanarak bir test seti üzerinde **değerlendirin**.

Her algoritmayı inceleyelim:

### Linear Regression

Linear regression, sürekli sayısal değerleri tahmin etmek için kullanılan bir **regression** algoritmasıdır. Girdi feature'ları (independent variable'lar) ile çıktı (dependent variable) arasında doğrusal bir ilişki olduğunu varsayar. Model, feature'lar ile target arasındaki ilişkiyi en iyi şekilde açıklayan düz bir çizgiye (daha yüksek boyutlarda hyperplane) uymaya çalışır. Bu işlem genellikle tahmin edilen ve gerçek değerler arasındaki kareli hataların toplamının en aza indirilmesiyle gerçekleştirilir (Ordinary Least Squares yöntemi).<sup>[[2]](#references)</sup>

Linear regression'ı temsil etmenin en basit biçimi bir çizgidir:
```plaintext
y = mx + b
```
Burada:

- `y` tahmin edilen değerdir (çıktı)
- `m` doğrunun eğimidir (katsayı)
- `x` girdi özelliğidir
- `b` y-kesişimidir

Linear regression'ın amacı, veri kümesindeki tahmin edilen değerlerle gerçek değerler arasındaki farkı en aza indiren en iyi uyumlu doğruyu bulmaktır. Elbette bu çok basittir; 2 kategoriyi ayıran düz bir doğru olacaktır, ancak daha fazla boyut eklendiğinde doğru daha karmaşık hale gelir:
```plaintext
y = w1*x1 + w2*x2 + ... + wn*xn + b
```
> [!TIP]
> *Siber güvenlikte kullanım alanları:* Linear regression, temel güvenlik görevlerinde (genellikle classification kullanılır) daha az yaygındır; ancak sayısal sonuçları tahmin etmek için uygulanabilir. Örneğin, geçmiş verilere dayanarak **ağ trafiği hacmini tahmin etmek** veya **belirli bir zaman aralığındaki saldırı sayısını tahmin etmek** için linear regression kullanılabilir. Ayrıca belirli sistem metrikleri verildiğinde bir risk puanını veya bir saldırının tespit edilmesine kadar geçmesi beklenen süreyi de tahmin edebilir. Uygulamada, izinsiz girişleri veya malware'i tespit etmek için classification algorithms (logistic regression veya trees gibi) daha sık kullanılır; ancak linear regression, regression odaklı analizler için bir temel oluşturur ve kullanışlıdır.

#### **Linear Regression'ın temel özellikleri:**

-   **Problem türü:** Regression (sürekli değerleri tahmin etme). Çıktıya bir eşik uygulanmadığı sürece doğrudan classification için uygun değildir.

-   **Yorumlanabilirlik:** Yüksek -- coefficients kolayca yorumlanabilir ve her feature'ın doğrusal etkisini gösterir.

-   **Avantajlar:** Basit ve hızlıdır; regression görevleri için iyi bir baseline'dır; gerçek ilişki yaklaşık olarak doğrusal olduğunda iyi çalışır.

-   **Sınırlamalar:** Manuel feature engineering olmadan karmaşık veya doğrusal olmayan ilişkileri yakalayamaz; ilişkiler doğrusal olmadığında underfitting'e yatkındır; sonuçları çarpıtabilecek outlier'lara karşı hassastır.

-   **En iyi uyumu bulma:** Olası kategorileri birbirinden ayıran en iyi uyum doğrusunu bulmak için **Ordinary Least Squares (OLS)** adı verilen bir yöntem kullanırız. Bu yöntem, gözlemlenen değerler ile linear model tarafından tahmin edilen değerler arasındaki farkların kareleri toplamını minimize eder.

<details>
<summary>Örnek -- Bir Intrusion Dataset'inde Connection Duration'ı Tahmin Etme (Regression)
</summary>
Aşağıda NSL-KDD cybersecurity dataset'ini kullanarak linear regression'ı gösteriyoruz. Diğer feature'lara dayanarak network connection'ların `duration` değerini tahmin ederek bunu bir regression problemi olarak ele alacağız. (Gerçekte `duration`, NSL-KDD'nin bir feature'ıdır; burada yalnızca regression'ı açıklamak için kullanıyoruz.) Dataset'i yüklüyor, ön işliyor (categorical feature'ları encode ediyor), bir linear regression model'i eğitiyor ve bir test seti üzerindeki Mean Squared Error (MSE) ile R² score'u değerlendiriyoruz.
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
Bu örnekte linear regression modeli, diğer ağ özelliklerinden bağlantı `duration` değerini tahmin etmeye çalışır. Performansı Mean Squared Error (MSE) ve R² ile ölçeriz. 1.0'a yakın bir R², modelin `duration` değerindeki varyansın çoğunu açıkladığını gösterirken düşük veya negatif bir R², uyumun zayıf olduğunu gösterir. (Burada R² düşük çıkarsa şaşırmayın -- `duration` değerini verilen özelliklerden tahmin etmek zor olabilir ve linear regression, örüntüler karmaşıksa bunları yakalayamayabilir.)
</details>

### Lojistik Regresyon

Lojistik regresyon, bir örneğin belirli bir sınıfa (genellikle "pozitif" sınıfa) ait olma olasılığını modelleyen bir **classification** algoritmasıdır. Adına rağmen *lojistik* regresyon, linear regression'ın aksine sürekli sonuçlar için değil, ayrık sonuçlar için kullanılır. Özellikle **binary classification** (iki sınıf, ör. malicious ve benign) için kullanılır; ancak multi-class problemlerine de (softmax veya one-vs-rest yaklaşımları kullanılarak) genişletilebilir.<sup>[[3]](#references)</sup>

Lojistik regresyon, tahmin edilen değerleri olasılıklara dönüştürmek için logistic function (sigmoid function olarak da bilinir) kullanır. Sigmoid function'ın 0 ile 1 arasında değerlere sahip ve classification gereksinimlerine göre S şeklinde bir eğri boyunca büyüyen bir function olduğunu unutmayın; bu, binary classification görevleri için kullanışlıdır. Bu nedenle, her girdinin her feature'ı kendisine atanmış weight ile çarpılır ve sonuç, bir olasılık üretmek için sigmoid function'dan geçirilir:
```plaintext
p(y=1|x) = 1 / (1 + e^(-z))
```
Burada:

- `p(y=1|x)`, `x` girdisi verildiğinde çıktının `y` değerinin 1 olma olasılığıdır
- `e`, doğal logaritmanın tabanıdır
- `z`, girdi özelliklerinin doğrusal birleşimidir ve genellikle `z = w1*x1 + w2*x2 + ... + wn*xn + b` şeklinde gösterilir. En basit hâlinde bunun yine düz bir doğru olduğuna, ancak daha karmaşık durumlarda birkaç boyutlu bir hiper düzleme dönüştüğüne (her özellik için bir boyut) dikkat edin.

> [!TIP]
> *Siber güvenlikte kullanım alanları:* Birçok güvenlik problemi temelde evet/hayır kararları olduğundan, lojistik regresyon yaygın olarak kullanılır. Örneğin bir intrusion detection system, bir network bağlantısının özelliklerine dayanarak bu bağlantının bir saldırı olup olmadığına karar vermek için lojistik regresyon kullanabilir. Phishing detection işleminde lojistik regresyon, bir web sitesinin özelliklerini (URL uzunluğu, `"@"` sembolünün bulunması vb.) bir phishing olasılığına dönüştürebilir. İlk nesil spam filtrelerinde kullanılmıştır ve birçok classification görevi için hâlâ güçlü bir temel yöntemdir.

#### Binary olmayan classification için Logistic Regression

Logistic regression, binary classification için tasarlanmıştır; ancak **one-vs-rest** (OvR) veya **softmax regression** gibi tekniklerle multi-class problemleri ele alacak şekilde genişletilebilir. OvR'de her sınıf için ayrı bir logistic regression modeli eğitilir ve ilgili sınıf, diğer tüm sınıflara karşı pozitif sınıf olarak ele alınır. En yüksek tahmin edilen olasılığa sahip sınıf, nihai tahmin olarak seçilir. Softmax regression, çıktı katmanına softmax fonksiyonunu uygulayarak ve tüm sınıflar üzerinde bir olasılık dağılımı üreterek logistic regression'ı birden fazla sınıfa geneller.

#### **Logistic Regression'ın temel özellikleri:**

-   **Problem türü:** Classification (genellikle binary). Pozitif sınıfın olasılığını tahmin eder.

-   **Yorumlanabilirlik:** Yüksek -- linear regression'da olduğu gibi, özellik katsayıları her özelliğin sonucun log-odds değerini nasıl etkilediğini gösterebilir. Bu şeffaflık, hangi faktörlerin bir alert'e katkıda bulunduğunu anlamak açısından security alanında sıklıkla önemsenir.

-   **Avantajlar:** Eğitilmesi basit ve hızlıdır; özellikler ile sonucun log-odds değeri arasındaki ilişki doğrusal olduğunda iyi çalışır. Olasılık çıktısı üreterek risk scoring yapılmasını sağlar. Uygun regularization ile iyi genelleme yapar ve plain linear regression'a kıyasla multicollinearity sorununu daha iyi ele alabilir.

-   **Sınırlamalar:** Feature space içinde doğrusal bir decision boundary olduğunu varsayar (gerçek sınır karmaşık/doğrusal olmayan bir yapıdaysa başarısız olur). Polynomial veya interaction özelliklerini elle eklemediğiniz sürece, etkileşimlerin veya doğrusal olmayan etkilerin kritik olduğu problemlerde düşük performans gösterebilir. Ayrıca sınıflar, özelliklerin doğrusal bir birleşimiyle kolayca ayrılabilir değilse logistic regression daha az etkili olur.


<details>
<summary>Örnek -- Logistic Regression ile Phishing Website Detection:</summary>

Web sitelerinden çıkarılmış özellikleri (URL'nin bir IP adresi içerip içermediği, domain yaşı, HTML'de şüpheli öğelerin bulunması vb.) ve sitenin phishing veya legitimate olduğunu belirten bir label içeren **Phishing Websites Dataset**'i (UCI repository'den) kullanacağız.<sup>[[4]](#references)</sup> Web sitelerini sınıflandırmak için bir logistic regression modeli eğitecek, ardından test split'i üzerinde accuracy, precision, recall, F1-score ve ROC AUC değerlerini değerlendireceğiz.
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
Bu phishing detection örneğinde logistic regression, her web sitesinin phishing olma olasılığını üretir. Accuracy, precision, recall ve F1 değerlerini değerlendirerek modelin performansı hakkında fikir ediniriz. Örneğin, yüksek bir recall değeri, çoğu phishing sitesini yakaladığı anlamına gelir (kaçırılan saldırıları en aza indirmek güvenlik açısından önemlidir); yüksek precision ise az sayıda yanlış alarm ürettiği anlamına gelir (analist yorgunluğunu önlemek açısından önemlidir). ROC AUC (ROC Eğrisi Altındaki Alan), threshold'dan bağımsız bir performans ölçümü sağlar (1.0 ideal, 0.5 ise şanstan daha iyi olmayan performanstır). Logistic regression bu tür görevlerde çoğunlukla iyi performans gösterir; ancak phishing ve legitimate siteler arasındaki decision boundary karmaşıksa daha güçlü non-linear modellere ihtiyaç duyulabilir.

</details>

### Decision Trees

Bir decision tree, hem classification hem de regression görevlerinde kullanılabilen çok yönlü bir **supervised learning algorithm**'dir. Verilerin özelliklerine dayalı, hiyerarşik ve ağaç benzeri bir karar modeli öğrenir. Ağacın her internal node'u belirli bir özellik üzerinde yapılan bir testi, her branch bu testin bir sonucunu, her leaf node ise tahmin edilen class'ı (classification için) veya değeri (regression için) temsil eder.<sup>[[5]](#references)</sup>

Bir ağaç oluşturmak için CART (Classification and Regression Tree) gibi algorithm'ler, verileri her adımda bölmek üzere en iyi özellik ve threshold'u seçmek amacıyla **Gini impurity** veya **information gain (entropy)** gibi ölçümler kullanır. Her split işlemindeki amaç, ortaya çıkan alt kümelerde target variable'ın homojenliğini artıracak şekilde verileri partition etmektir (classification için her node, ağırlıklı olarak tek bir class içerecek şekilde mümkün olduğunca pure olmayı hedefler).

Decision tree'ler **yüksek düzeyde yorumlanabilirdir** -- bir prediction'ın ardındaki mantığı anlamak için root'tan leaf'e kadar olan yol takip edilebilir (ör. *"IF `service = telnet` AND `src_bytes > 1000` AND `failed_logins > 3` THEN classify as attack"*). Bu, belirli bir alert'in neden oluşturulduğunu açıklamak açısından cybersecurity alanında değerlidir. Tree'ler hem numerical hem de categorical data'yı doğal olarak işleyebilir ve çok az preprocessing gerektirir (ör. feature scaling gerekmez).

Ancak tek bir decision tree, özellikle derin büyütüldüğünde (çok sayıda split), training data'ya kolayca overfit olabilir. Overfitting'i önlemek için pruning (tree depth'i sınırlamak veya leaf başına minimum sample sayısı belirlemek) gibi teknikler sıklıkla kullanılır.

Bir decision tree'nin 3 ana bileşeni vardır:
- **Root Node**: Ağacın tamamını temsil eden, ağacın en üst node'udur.
- **Internal Nodes**: Özellikleri ve bu özelliklere dayalı kararları temsil eden node'lardır.
- **Leaf Nodes**: Nihai sonucu veya prediction'ı temsil eden node'lardır.

Bir tree şu şekilde görünebilir:
```plaintext
[Root Node]
/   \
[Node A]  [Node B]
/   \      /   \
[Leaf 1] [Leaf 2] [Leaf 3] [Leaf 4]
```
> [!TIP]
> *Siber güvenlikte kullanım alanları:* Karar ağaçları, saldırıları tanımlamak için **kurallar** türetmek amacıyla intrusion detection systems içinde kullanılmıştır. Örneğin, ID3/C4.5 tabanlı eski IDS'ler normal ve kötü amaçlı trafiği ayırt etmek için insan tarafından okunabilir kurallar oluştururdu. Ayrıca bir dosyanın özniteliklerine (dosya boyutu, section entropy, API calls vb.) göre kötü amaçlı olup olmadığına karar vermek için malware analysis alanında da kullanılırlar. Karar ağaçlarının açıklığı, şeffaflığın gerekli olduğu durumlarda onları kullanışlı kılar -- bir analyst, detection logic'i doğrulamak için ağacı inceleyebilir.

#### **Karar Ağaçlarının temel özellikleri:**

-   **Problem Türü:** Hem classification hem de regression. Saldırıları normal trafikten ayırma gibi classification işlemlerinde yaygın olarak kullanılır.

-   **Yorumlanabilirlik:** Çok yüksek -- modelin kararları görselleştirilebilir ve bir dizi if-then kuralı olarak anlaşılabilir. Bu, model davranışına duyulan güven ve doğrulama açısından security alanında önemli bir avantajdır.

-   **Avantajlar:** Öznitelikler arasındaki non-linear ilişkileri ve etkileşimleri yakalayabilir (her split bir etkileşim olarak görülebilir). Öznitelikleri scale etmeye veya categorical variables için one-hot encode kullanmaya gerek yoktur -- ağaçlar bunları native olarak işler. Inference hızlıdır (prediction yalnızca ağaçta bir yol izlemekten ibarettir).

-   **Sınırlamalar:** Kontrol edilmezse overfitting'e yatkındır (derin bir ağaç training set'i ezberleyebilir). Stabil olmayabilirler -- verilerdeki küçük değişiklikler farklı bir ağaç yapısına yol açabilir. Tekil modeller olarak accuracy'leri daha gelişmiş yöntemlerle eşleşmeyebilir (Random Forests gibi ensembles, variance'ı azaltarak genellikle daha iyi performans gösterir).

-   **En İyi Split'i Bulma:**
- **Gini Impurity**: Bir node'un impurity'sini ölçer. Daha düşük Gini impurity, daha iyi bir split olduğunu gösterir. Formül:

```plaintext
Gini = 1 - Σ(p_i^2)
```

Burada `p_i`, `i` class'ındaki instance'ların oranıdır.

- **Entropy**: Dataset'teki belirsizliği ölçer. Daha düşük entropy, daha iyi bir split olduğunu gösterir. Formül:

```plaintext
Entropy = -Σ(p_i * log2(p_i))
```

Burada `p_i`, `i` class'ındaki instance'ların oranıdır.

- **Information Gain**: Bir split sonrasında entropy veya Gini impurity'deki azalmadır. Information gain ne kadar yüksekse split o kadar iyidir. Şu şekilde hesaplanır:

```plaintext
Information Gain = Entropy(parent) - (Weighted Average of Entropy(children))
```

Ayrıca bir tree şu durumlarda sonlandırılır:
- Bir node'daki tüm instance'lar aynı class'a aittir. Bu, overfitting'e yol açabilir.
- Tree'nin maximum depth (hardcoded) değerine ulaşılır. Bu, overfitting'i önlemenin bir yoludur.
- Bir node'daki instance sayısı belirli bir threshold'un altındadır. Bu da overfitting'i önlemenin bir yoludur.
- Daha ileri split'lerden elde edilen information gain belirli bir threshold'un altındadır. Bu da overfitting'i önlemenin bir yoludur.

<details>
<summary>Örnek -- Intrusion Detection için Karar Tree'si:</summary>
Network connection'ları *normal* veya *attack* olarak sınıflandırmak için NSL-KDD dataset'i üzerinde bir decision tree eğiteceğiz. NSL-KDD, protocol type, service, duration, failed login sayısı vb. özniteliklere ve attack type'ı veya "normal" değerini belirten bir label'a sahip klasik KDD Cup 1999 dataset'inin geliştirilmiş bir sürümüdür. Tüm attack type'ları "anomaly" class'ına eşleyeceğiz (binary classification: normal ve anomaly). Training sonrasında tree'nin test set'indeki performance'ını değerlendireceğiz.
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
Bu karar ağacı örneğinde, aşırı overfitting'i önlemek için ağaç derinliğini 10 ile sınırladık (`max_depth=10` parametresi). Metrikler, ağacın normal ve attack trafiğini ne kadar iyi ayırt ettiğini gösterir. Yüksek recall, çoğu attack'i yakaladığı anlamına gelir (bir IDS için önemlidir); yüksek precision ise az sayıda false alarm anlamına gelir. Karar ağaçları, yapılandırılmış verilerde genellikle makul bir accuracy elde eder, ancak tek bir ağaç mümkün olan en iyi performansa ulaşamayabilir. Bununla birlikte, modelin *yorumlanabilirliği* büyük bir avantajdır -- ağacın bölme noktalarını inceleyerek örneğin hangi feature'ların (`service`, `src_bytes` vb.) bir bağlantıyı malicious olarak işaretlemede en etkili olduğunu görebiliriz.

</details>

### Random Forests

Random Forest, performansı iyileştirmek için karar ağaçlarını temel alan bir **ensemble learning** yöntemidir. Bir random forest birden fazla karar ağacı eğitir (bu nedenle "forest" denir) ve nihai bir prediction yapmak için çıktılarını birleştirir (classification için genellikle majority vote kullanılır). Bir random forest'taki iki temel fikir **bagging** (bootstrap aggregating) ve **feature randomness**'tir:

-   **Bagging:** Her ağaç, training data'nın rastgele bir bootstrap sample'ı üzerinde eğitilir (replacement ile örneklenir). Bu, ağaçlar arasında diversity oluşturur.

-   **Feature Randomness:** Bir ağaçtaki her split sırasında, splitting için feature'ların rastgele bir alt kümesi değerlendirilir (tüm feature'lar yerine). Bu, ağaçlar arasındaki korelasyonu daha da azaltır.

Birçok ağacın sonuçlarının ortalamasını alarak random forest, tek bir karar ağacında oluşabilecek variance'ı azaltır. Basitçe ifade etmek gerekirse, tek tek ağaçlar overfit olabilir veya noisy olabilir; ancak birlikte oy kullanan çok sayıda diverse ağaç bu hataları yumuşatır. Sonuç genellikle tek bir karar ağacına kıyasla **daha yüksek accuracy** ve daha iyi generalization sağlayan bir modeldir. Ayrıca random forest'lar, her feature split'inin impurity'yi ortalama olarak ne kadar azalttığına bakarak feature importance tahmini sağlayabilir.

Random forest'lar intrusion detection, malware classification ve spam detection gibi görevlerde **cybersecurity alanında bir workhorse** haline gelmiştir. Genellikle minimum tuning ile out-of-the-box iyi performans gösterir ve büyük feature set'lerini işleyebilir. Örneğin intrusion detection'da bir random forest, daha subtle attack pattern'lerini daha az false positive ile yakalayarak tek bir karar ağacından daha iyi performans gösterebilir. Araştırmalar, NSL-KDD ve UNSW-NB15 gibi dataset'lerde attack'leri classification konusunda random forest'ların diğer algorithm'lere kıyasla olumlu performans gösterdiğini ortaya koymuştur.<sup>[[6]](#references)[[7]](#references)</sup>

#### **Random Forests'ın temel özellikleri:**

-   **Problem Türü:** Öncelikli olarak classification (regression için de kullanılır). Security log'larında yaygın olan high-dimensional structured data için çok uygundur.

-   **Yorumlanabilirlik:** Tek bir karar ağacına kıyasla daha düşüktür -- yüzlerce ağacı aynı anda kolayca visualize veya explain edemezsiniz. Bununla birlikte, feature importance score'ları hangi attribute'ların en etkili olduğu hakkında bir miktar insight sağlar.

-   **Avantajlar:** Ensemble effect sayesinde genellikle single-tree model'lerden daha yüksek accuracy. Overfitting'e karşı dayanıklıdır -- tek tek ağaçlar overfit olsa bile ensemble daha iyi generalize olur. Hem numerical hem de categorical feature'ları işler ve missing data'yı belirli ölçüde yönetebilir. Ayrıca outlier'lara karşı da nispeten dayanıklıdır.

-   **Sınırlamalar:** Model size büyük olabilir (çok sayıda ağaç ve her biri potansiyel olarak derin). Prediction'lar tek bir ağaçtan daha yavaştır (çok sayıda ağaç üzerinden aggregation yapmanız gerekir). Daha az yorumlanabilirdir -- önemli feature'ları bilseniz de exact logic, basit bir rule gibi kolayca izlenemez. Dataset son derece high-dimensional ve sparse ise çok büyük bir forest'ı eğitmek computational açıdan ağır olabilir.

-   **Training Process:**
1. **Bootstrap Sampling**: Birden fazla subset (bootstrap sample) oluşturmak için training data'yı replacement ile rastgele örnekleyin.
2. **Tree Construction**: Her bootstrap sample için, her split'te feature'ların rastgele bir subset'ini kullanarak bir karar ağacı oluşturun. Bu, ağaçlar arasında diversity oluşturur.
3. **Aggregation**: Classification görevlerinde nihai prediction, tüm ağaçların prediction'ları arasındaki majority vote alınarak yapılır. Regression görevlerinde nihai prediction, tüm ağaçların prediction'larının average'ıdır.

<details>
<summary>Example -- Intrusion Detection için Random Forest (NSL-KDD):</summary>
Aynı NSL-KDD dataset'ini (normal ve anomaly olarak binary labeled) kullanacak ve bir Random Forest classifier eğiteceğiz. Ensemble averaging'in variance'ı azaltması sayesinde random forest'ın tek bir karar ağacı kadar iyi veya ondan daha iyi performans göstermesini bekliyoruz. Aynı metrics ile değerlendireceğiz.
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
Random forest, bu intrusion detection görevinde genellikle güçlü sonuçlar elde eder. Verilere bağlı olarak, özellikle recall veya precision değerlerinde, tek bir decision tree ile karşılaştırıldığında F1 veya AUC gibi metriklerde iyileşme gözlemleyebiliriz. Bu durum, *"Random Forest (RF) is an ensemble classifier and performs well compared to other traditional classifiers for effective classification of attacks."* anlayışıyla örtüşür.<sup>[[6]](#references)</sup> Bir security operations bağlamında random forest modeli, çok sayıda decision rule'un ortalamasını aldığı için false alarm'ları azaltırken saldırıları daha güvenilir şekilde işaretleyebilir. Forest'tan elde edilen feature importance, hangi network feature'larının saldırıların en güçlü göstergeleri olduğunu (ör. belirli network service'leri veya olağandışı packet sayıları) ortaya çıkarabilir.

</details>

### Support Vector Machines (SVM)

Support Vector Machines, öncelikle classification (ve ayrıca SVR olarak regression) için kullanılan güçlü supervised learning modelleridir. Bir SVM, iki class arasındaki margin'i maksimize eden **optimal separating hyperplane**'ı bulmaya çalışır. Yalnızca training point'lerinin bir alt kümesi (sınıra en yakın olan "support vector"lar) bu hyperplane'in konumunu belirler. Margin'i (support vector'lar ile hyperplane arasındaki mesafeyi) maksimize ederek SVM'ler iyi bir generalization elde etme eğilimindedir.<sup>[[8]](#references)</sup>

SVM'nin gücünün temelinde, non-linear ilişkileri ele almak için **kernel function**'ları kullanabilmesi vardır. Data, linear separator'ın bulunabileceği daha yüksek boyutlu bir feature space'e örtük olarak dönüştürülebilir. Yaygın kernel'lar arasında polynomial, radial basis function (RBF) ve sigmoid bulunur. Örneğin, network traffic class'ları ham feature space'te linearly separable değilse, bir RBF kernel bunları daha yüksek bir boyuta map edebilir; burada SVM, linear bir ayrım bulur (bu ayrım original space'te non-linear bir sınıra karşılık gelir). Kernel seçme esnekliği, SVM'lerin çeşitli problemleri ele almasını sağlar.

SVM'lerin, high-dimensional feature space içeren durumlarda (text data veya malware opcode sequence'leri gibi) ve feature sayısının sample sayısına göre fazla olduğu durumlarda iyi performans gösterdiği bilinir. SVM'ler, 2000'lerde malware classification ve anomaly-based intrusion detection gibi birçok erken dönem cybersecurity uygulamasında popülerdi ve çoğu zaman yüksek accuracy gösteriyordu.

Bununla birlikte SVM'ler çok büyük dataset'lere kolayca ölçeklenemez (training complexity, sample sayısına göre super-linear'dır ve çok sayıda support vector saklaması gerekebileceğinden memory kullanımı yüksek olabilir). Pratikte, milyonlarca record içeren network intrusion detection gibi görevlerde, dikkatli subsampling yapılmadan veya approximate method'lar kullanılmadan SVM çok yavaş kalabilir.

#### **Key characteristics of SVM:**

-   **Type of Problem:** Classification (one-vs-one/one-vs-rest aracılığıyla binary veya multiclass) ve regression variant'ları. Genellikle margin separation'ın net olduğu binary classification'da kullanılır.

-   **Interpretability:** Medium -- SVM'ler decision tree veya logistic regression kadar yorumlanabilir değildir. Hangi data point'lerinin support vector olduğunu belirleyebilir ve hangi feature'ların etkili olabileceği konusunda (linear kernel durumunda weight'ler aracılığıyla) bir fikir edinebilirsiniz; ancak pratikte SVM'ler (özellikle non-linear kernel'lar ile) black-box classifier olarak değerlendirilir.

-   **Advantages:** High-dimensional space'lerde etkilidir; kernel trick ile complex decision boundary'leri modelleyebilir; margin maksimize edilirse overfitting'e karşı dayanıklıdır (özellikle uygun bir regularization parameter C ile); class'lar büyük bir mesafeyle ayrılmadığında bile iyi çalışır (en iyi compromise boundary'yi bulur).

-   **Limitations:** Büyük dataset'ler için **computationally intensive**'dır (data büyüdükçe hem training hem de prediction kötü ölçeklenir). Kernel ve regularization parameter'larının (C, kernel type, RBF için gamma vb.) dikkatle ayarlanmasını gerektirir. Doğrudan probabilistic output sağlamaz (ancak probability elde etmek için Platt scaling kullanılabilir). Ayrıca SVM'ler kernel parameter seçimine duyarlı olabilir --- kötü bir seçim underfit veya overfit'e yol açabilir.

*Use cases in cybersecurity:* SVM'ler **malware detection** (ör. dosyaları extracted feature'lara veya opcode sequence'lerine göre sınıflandırma), **network anomaly detection** (traffic'i normal veya malicious olarak sınıflandırma) ve **phishing detection** (URL feature'larını kullanarak) için kullanılmıştır. Örneğin bir SVM, bir email'in feature'larını (belirli keyword'lerin sayıları, sender reputation score'ları vb.) alıp bunu phishing veya legitimate olarak sınıflandırabilir. Ayrıca KDD gibi feature set'leri üzerinde **intrusion detection** için de uygulanmış ve computation maliyeti karşılığında çoğu zaman yüksek accuracy elde edilmiştir.

<details>
<summary>Example -- SVM for Malware Classification:</summary>
Bu kez phishing website dataset'ini bir SVM ile kullanacağız. SVM'ler yavaş olabileceğinden, gerekirse training için data'nın bir alt kümesini kullanacağız (dataset yaklaşık 11k instance içeriyor; bu miktar SVM'nin makul şekilde işleyebileceği bir miktardır). Non-linear data için yaygın bir seçim olan RBF kernel'ı kullanacağız ve ROC AUC hesaplamak için probability estimate'lerini etkinleştireceğiz.
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
SVM modeli, aynı görevde logistic regression ile karşılaştırabileceğimiz metrikler üretir. Veriler özellikler tarafından iyi şekilde ayrılıyorsa SVM'nin yüksek accuracy ve AUC değerlerine ulaştığını görebiliriz. Öte yandan, veri kümesinde çok fazla gürültü veya örtüşen sınıflar varsa SVM, logistic regression'dan önemli ölçüde daha iyi performans göstermeyebilir. Uygulamada SVM'ler, özellikler ile sınıf arasında karmaşık ve doğrusal olmayan ilişkiler olduğunda performansı artırabilir -- RBF kernel, logistic regression'ın gözden kaçıracağı eğrisel karar sınırlarını yakalayabilir. Tüm modellerde olduğu gibi, bias ve variance arasında denge kurmak için `C` (regularization) ve kernel parametrelerinin (RBF için `gamma` gibi) dikkatli şekilde ayarlanması gerekir.

</details>

#### Logistic Rergessions ve SVM Arasındaki Fark

| Aspect | **Logistic Regression** | **Support Vector Machines** |
|---|---|---|
| **Objective function** | **log-loss** (cross-entropy) değerini minimize eder. | **hinge-loss** değerini minimize ederken **margin** değerini maksimize eder. |
| **Decision boundary** | _P(y\|x)_ modelleyen **best-fit hyperplane**'ı bulur. | **Maximum-margin hyperplane**'ı (en yakın noktalara en büyük uzaklığa sahip düzlem) bulur. |
| **Output** | **Probabilistic** – σ(w·x + b) aracılığıyla kalibre edilmiş sınıf olasılıkları sağlar. | **Deterministic** – sınıf etiketleri döndürür; olasılıklar için ek işlem gerekir (ör. Platt scaling). |
| **Regularisation** | L2 (varsayılan) veya L1, under/over-fitting dengesini doğrudan sağlar. | C parametresi, margin genişliği ile yanlış sınıflandırmalar arasında denge kurar; kernel parametreleri karmaşıklık ekler. |
| **Kernels / Non-linear** | Yerel formu **linear**'dır; non-linearity feature engineering ile eklenir. | Yerleşik **kernel trick** (RBF, poly vb.), yüksek boyutlu uzayda karmaşık sınırları modellemesini sağlar. |
| **Scalability** | **O(nd)** içinde convex optimisation çözer; çok büyük n değerlerini iyi şekilde işler. | Özel solver'lar olmadan eğitim bellek/zaman açısından **O(n²–n³)** olabilir; çok büyük n değerleri için daha az uygundur. |
| **Interpretability** | **High** – weight değerleri feature etkisini gösterir; odds ratio sezgiseldir. | Doğrusal olmayan kernel'lar için **Low**; support vector'ler seyrektir ancak açıklanmaları kolay değildir. |
| **Sensitivity to outliers** | Smooth log-loss kullanır → daha az hassastır. | Hard margin içeren hinge-loss **hassas** olabilir; soft-margin (C) bunu azaltır. |
| **Typical use cases** | **Olasılıkların ve açıklanabilirliğin** önemli olduğu credit scoring, medical risk ve A/B testing. | **Karmaşık sınırların** ve **yüksek boyutlu verilerin** önemli olduğu image/text classification ve bio-informatics. |

* Kalibre edilmiş olasılıklara, interpretability'ye veya çok büyük veri kümelerinde çalışmaya ihtiyacınız varsa — **Logistic Regression** seçin.
* Manuel feature engineering yapmadan non-linear ilişkileri yakalayabilen esnek bir modele ihtiyacınız varsa — **SVM (kernel'lar ile)** seçin.
* Her ikisi de convex objective'ları optimize eder; bu nedenle **global minimum'lar garanti edilir**, ancak SVM kernel'ları hyper-parameter'lar ve computational cost ekler.

### Naive Bayes

Naive Bayes, feature'lar arasında güçlü bir bağımsızlık varsayımı uygulayarak Bayes' Theorem'e dayanan bir **probabilistic classifier** ailesidir. Bu "naive" varsayıma rağmen Naive Bayes, özellikle spam detection gibi text veya categorical data içeren belirli uygulamalarda çoğu zaman şaşırtıcı derecede iyi çalışır.<sup>[[9]](#references)</sup>


#### Bayes' Theorem

Bayes' theorem, Naive Bayes classifier'larının temelidir. Random event'lerin conditional ve marginal probability değerleri arasındaki ilişkiyi açıklar. Formül şu şekildedir:
```plaintext
P(A|B) = (P(B|A) * P(A)) / P(B)
```
Nerede:
- `P(A|B)`, `B` özelliği verildiğinde `A` sınıfının posterior olasılığıdır.
- `P(B|A)`, `A` sınıfı verildiğinde `B` özelliğinin likelihood değeridir.
- `P(A)`, `A` sınıfının prior olasılığıdır.
- `P(B)`, `B` özelliğinin prior olasılığıdır.

Örneğin, bir metnin çocuk veya yetişkin tarafından yazılıp yazılmadığını sınıflandırmak istiyorsak metindeki kelimeleri özellik olarak kullanabiliriz. Bazı başlangıç verilerine dayanarak Naive Bayes classifier, her kelimenin potansiyel sınıfların her birinde (çocuk veya yetişkin) bulunma olasılıklarını önceden hesaplar. Yeni bir metin verildiğinde, metindeki kelimeler göz önüne alındığında her potansiyel sınıfın olasılığını hesaplar ve en yüksek olasılığa sahip sınıfı seçer.

Bu örnekte görebileceğiniz gibi Naive Bayes classifier oldukça basit ve hızlıdır; ancak özelliklerin bağımsız olduğunu varsayar. Bu durum gerçek dünya verilerinde her zaman geçerli değildir.


#### Naive Bayes Classifiers Türleri

Veri türüne ve özelliklerin dağılımına bağlı olarak çeşitli Naive Bayes classifier türleri vardır:
- **Gaussian Naive Bayes**: Özelliklerin Gaussian (normal) dağılımı izlediğini varsayar. Sürekli veriler için uygundur.
- **Multinomial Naive Bayes**: Özelliklerin multinomial dağılım izlediğini varsayar. Metin sınıflandırmasındaki kelime sayımları gibi ayrık veriler için uygundur.
- **Bernoulli Naive Bayes**: Özelliklerin binary (0 veya 1) olduğunu varsayar. Metin sınıflandırmasında kelimelerin mevcut olması veya bulunmaması gibi binary veriler için uygundur.
- **Categorical Naive Bayes**: Özelliklerin categorical değişkenler olduğunu varsayar. Meyveleri renk ve şekillerine göre sınıflandırmak gibi categorical veriler için uygundur.


#### **Naive Bayes'in temel özellikleri:**

-   **Problem Türü:** Sınıflandırma (binary veya multi-class). Siber güvenlikte text classification görevlerinde (spam, phishing vb.) yaygın olarak kullanılır.

-   **Yorumlanabilirlik:** Orta -- decision tree kadar doğrudan yorumlanabilir değildir; ancak öğrenilen olasılıklar (ör. spam ve ham e-postalarda hangi kelimelerin daha olası olduğu) incelenebilir. Modelin yapısı (sınıfa göre her özellik için olasılıklar), gerektiğinde anlaşılabilir.

-   **Avantajlar:** Büyük veri kümelerinde bile **çok hızlı** training ve prediction (instance sayısı * feature sayısı ile doğrusal). Özellikle uygun smoothing ile olasılıkları güvenilir şekilde tahmin etmek için görece az miktarda veri gerektirir. Özelliklerin sınıfa bağımsız şekilde kanıt sağlaması durumunda, baseline olarak sıklıkla şaşırtıcı derecede doğrudur. High-dimensional verilerle (ör. text verilerinden elde edilen binlerce feature) iyi çalışır. Bir smoothing parameter ayarlamanın ötesinde karmaşık bir tuning gerektirmez.

-   **Sınırlamalar:** Özellikler yüksek oranda korelasyonluysa independence assumption doğruluğu sınırlayabilir. Örneğin network verilerinde `src_bytes` ve `dst_bytes` gibi özellikler korelasyonlu olabilir; Naive Bayes bu etkileşimi yakalayamaz. Veri boyutu çok büyüdüğünde, feature dependencies öğrenerek daha ifade gücü yüksek modeller (ensembles veya neural nets gibi) NB'yi geride bırakabilir. Ayrıca bir saldırıyı tanımlamak için özelliklerin tek tek bağımsız olmasından ziyade belirli bir feature kombinasyonu gerekiyorsa NB zorlanır.

> [!TIP]
> *Siber güvenlikte kullanım alanları:* Klasik kullanım alanı **spam detection**'dır -- Naive Bayes, belirli token'ların (kelimeler, ifadeler, IP adresleri) frekanslarını kullanarak bir e-postanın spam olma olasılığını hesaplayan ilk spam filtrelerinin temeliydi. Ayrıca belirli anahtar kelimelerin veya özelliklerin (bir URL'deki "login.php" ya da URL path'indeki `@` gibi) bulunmasının phishing olasılığına katkıda bulunduğu **phishing email detection** ve **URL classification** alanlarında da kullanılır. Malware analysis alanında, yazılımdaki belirli API çağrılarının veya permission'ların varlığını kullanarak yazılımın malware olup olmadığını tahmin eden bir Naive Bayes classifier düşünülebilir. Daha gelişmiş algorithm'ler sıklıkla daha iyi performans gösterse de Naive Bayes, hızı ve basitliği nedeniyle hâlâ iyi bir baseline olmaya devam eder.

<details>
<summary>Örnek -- Phishing Detection için Naive Bayes:</summary>
Naive Bayes'i göstermek için binary label'lara sahip NSL-KDD intrusion dataset üzerinde Gaussian Naive Bayes kullanacağız. Gaussian NB, her özelliği sınıf başına normal dağılım izliyormuş gibi ele alır. Birçok network özelliği ayrık veya yüksek ölçüde çarpık olduğundan bu, kabaca seçilmiş bir yöntemdir; ancak NB'nin continuous feature verilerine nasıl uygulanacağını gösterir. Binary feature'lara (ör. tetiklenen alert'lerden oluşan bir küme) sahip bir dataset üzerinde Bernoulli NB de seçebilirdik; ancak burada NSL-KDD ile devam edeceğiz.
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
Bu kod, saldırıları tespit etmek için bir Naive Bayes classifier eğitir. Naive Bayes, özellikler arasındaki bağımsızlığı varsayarak eğitim verilerine dayanarak `P(service=http | Attack)` ve `P(Service=http | Normal)` gibi olasılıkları hesaplar. Ardından gözlemlenen özelliklere dayanarak yeni bağlantıları normal veya saldırı olarak sınıflandırmak için bu olasılıkları kullanır. NB'nin NSL-KDD üzerindeki performansı daha gelişmiş modeller kadar yüksek olmayabilir (çünkü özellik bağımsızlığı ihlal edilir), ancak genellikle yeterli sonuç verir ve olağanüstü hız avantajına sahiptir. Gerçek zamanlı email filtering veya URL'lerin ilk triage işlemi gibi senaryolarda bir Naive Bayes modeli, kaynak kullanımını düşük tutarak açıkça kötü amaçlı durumları hızlıca işaretleyebilir.

</details>

### k-Nearest Neighbors (k-NN)

k-Nearest Neighbors, en basit machine learning algoritmalarından biridir. Eğitim setindeki örneklere benzerliğe dayanarak tahminler yapan **non-parametric, instance-based** bir yöntemdir. Classification için fikir şudur: yeni bir data point'i sınıflandırmak üzere eğitim verilerindeki en yakın **k** noktayı (yani "nearest neighbors") bulun ve bu komşular arasındaki çoğunluk sınıfını atayın. "Yakınlık", bir distance metric ile tanımlanır; numeric data için genellikle Euclidean distance kullanılır (farklı feature veya problem türleri için başka distance metric'ler de kullanılabilir).<sup>[[10]](#references)</sup>

K-NN *explicit training* gerektirmez -- "training" aşaması yalnızca dataset'i depolamaktan ibarettir. Tüm işlem query (prediction) sırasında gerçekleşir: algoritma, en yakın noktaları bulmak için query point ile tüm training point'leri arasındaki mesafeleri hesaplamalıdır. Bu durum prediction süresini **training sample sayısıyla doğrusal** hale getirir ve büyük dataset'lerde maliyetli olabilir. Bu nedenle k-NN, daha küçük dataset'ler veya basitlik karşılığında memory ve speed'den ödün verebileceğiniz senaryolar için en uygunudur.

Basitliğine rağmen k-NN, çok karmaşık decision boundary'leri modelleyebilir (çünkü decision boundary, örneklerin dağılımı tarafından belirlenen herhangi bir şekle sahip olabilir). Decision boundary'nin oldukça düzensiz olduğu ve çok fazla data bulunduğu durumlarda başarılı olma eğilimindedir -- temel olarak datanın "kendi adına konuşmasına" izin verir. Ancak yüksek boyutlarda distance metric'ler anlamını yitirebilir (curse of dimensionality) ve çok fazla sample bulunmadığı sürece yöntem zorlanabilir.

*Cybersecurity kullanım alanları:* k-NN, anomaly detection için uygulanmıştır -- örneğin bir intrusion detection system, nearest neighbor'larının (önceki event'lerin) çoğu malicious ise bir network event'i malicious olarak etiketleyebilir. Normal traffic kümeler oluşturuyor ve saldırılar outlier olarak kalıyorsa, bir K-NN yaklaşımı (k=1 veya küçük bir k ile) temel olarak **nearest-neighbor anomaly detection** gerçekleştirir. K-NN, binary feature vector'leri kullanılarak malware family'lerini sınıflandırmak için de kullanılmıştır: yeni bir file, feature space'te belirli bir malware family'sinin bilinen örneklerine çok yakınsa o family'ye ait olarak sınıflandırılabilir. Uygulamada k-NN, daha ölçeklenebilir algoritmalar kadar yaygın değildir; ancak kavramsal olarak basittir ve bazen baseline olarak veya küçük ölçekli problemler için kullanılır.

#### **k-NN'nin temel özellikleri:**

-   **Problem Türü:** Classification (regression varyantları da mevcuttur). *Lazy learning* yöntemidir -- explicit model fitting gerçekleştirilmez.

-   **Yorumlanabilirlik:** Düşük ila orta -- global bir model veya kısa ve öz bir açıklama yoktur; ancak bir karar üzerinde etkili olan nearest neighbor'lara bakılarak sonuçlar yorumlanabilir (örneğin, "bu network flow, bilinen şu 3 malicious flow'a benzediği için malicious olarak sınıflandırıldı"). Dolayısıyla açıklamalar example-based olabilir.

-   **Avantajlar:** Uygulaması ve anlaşılması çok basittir. Data distribution hakkında herhangi bir varsayımda bulunmaz (non-parametric). Multi-class problemleri doğal olarak ele alabilir. Decision boundary'lerin data distribution tarafından şekillendirilerek çok karmaşık olabilmesi anlamında **adaptive** bir yöntemdir.

-   **Sınırlamalar:** Büyük dataset'lerde prediction yavaş olabilir (çok sayıda distance hesaplanmalıdır). Memory-intensive bir yöntemdir -- tüm training data'sını depolar. Yüksek boyutlu feature space'lerde performans düşer; çünkü tüm noktalar neredeyse eşit uzaklıktaymış gibi olur (bu da "nearest" kavramını daha az anlamlı hale getirir). *k* (neighbor sayısı) uygun şekilde seçilmelidir -- çok küçük bir k gürültülü sonuçlara, çok büyük bir k ise diğer class'lara ait ilgisiz noktaların dahil edilmesine neden olabilir. Ayrıca distance hesaplamaları scale'e duyarlı olduğundan feature'lar uygun şekilde scale edilmelidir.

<details>
<summary>Örnek -- Phishing Detection için k-NN:</summary>

Yine NSL-KDD'yi kullanacağız (binary classification). k-NN computationally heavy olduğundan, bu demonstration'ı uygulanabilir tutmak için training data'sının bir subset'ini kullanacağız. Tam 125k içinden örneğin 20.000 training sample seçecek ve k=5 neighbor kullanacağız. Training'den sonra (aslında yalnızca data'yı depoladıktan sonra) test seti üzerinde evaluation gerçekleştireceğiz. Ayrıca distance calculation için feature'ları scale edeceğiz; böylece scale nedeniyle tek bir feature'ın baskın hale gelmesini önleyeceğiz.
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
k-NN modeli, training set alt kümesindeki en yakın 5 bağlantıya bakarak bir bağlantıyı sınıflandırır. Örneğin, bu komşuların 4'ü attack (anomaly) ve 1'i normal ise yeni bağlantı attack olarak sınıflandırılır. Performansı makul olabilir; ancak çoğu zaman aynı veriler üzerinde iyi ayarlanmış bir Random Forest veya SVM kadar yüksek değildir. Bununla birlikte k-NN, class distribution'ların oldukça düzensiz ve karmaşık olduğu durumlarda bazen öne çıkabilir; çünkü temelde memory-based lookup kullanır. Cybersecurity alanında k-NN (k=1 veya küçük bir k değeriyle), bilinen attack pattern'lerini örnekler üzerinden tespit etmek ya da daha karmaşık sistemlerde bir bileşen olarak (örneğin clustering işlemi yapıp ardından cluster membership'e göre sınıflandırmak için) kullanılabilir.
</details>

### Gradient Boosting Machines (ör. XGBoost)

Gradient Boosting Machines, structured data için en güçlü algoritmalar arasındadır. **Gradient boosting**, zayıf learner'lardan (çoğunlukla decision tree'lerden) oluşan bir ensemble'ı sırayla oluşturma tekniğini ifade eder; burada her yeni model, önceki ensemble'ın hatalarını düzeltir. Ağaçları paralel olarak oluşturan ve sonuçlarının ortalamasını alan bagging (Random Forests) yaklaşımının aksine boosting, ağaçları *tek tek* oluşturur ve her ağaç, önceki ağaçların yanlış tahmin ettiği örneklere daha fazla odaklanır.<sup>[[11]](#references)</sup>

Son yıllardaki en popüler implementasyonlar **XGBoost**, **LightGBM** ve **CatBoost**'tur; bunların tümü gradient boosting decision tree (GBDT) kütüphaneleridir. Machine learning yarışmalarında ve uygulamalarında son derece başarılı olmuşlar ve çoğu zaman **tabular dataset'lerde state-of-the-art performans** elde etmişlerdir. Cybersecurity alanında araştırmacılar ve uygulayıcılar, **malware detection** (dosyalardan veya runtime behavior'dan çıkarılan feature'ları kullanarak) ve **network intrusion detection** gibi görevlerde gradient boosted tree'leri kullanmıştır. Örneğin bir gradient boosting modeli, "çok sayıda SYN packet'i ve alışılmadık bir port varsa -> muhtemelen scan" gibi birçok zayıf kuralı (tree'yi), çok sayıda ince pattern'i hesaba katan güçlü bir composite detector'da birleştirebilir.

Boosted tree'ler neden bu kadar etkilidir? Sequence içindeki her tree, mevcut ensemble'ın prediction'larındaki *residual error'lar* (gradient'ler) üzerinde eğitilir. Bu şekilde model, zayıf olduğu alanları kademeli olarak **"boost"** eder. Base learner olarak decision tree'lerin kullanılması, final modelin karmaşık etkileşimleri ve non-linear ilişkileri yakalamasını sağlar. Ayrıca boosting, yerleşik bir regularization biçimine sahiptir: çok sayıda küçük tree ekleyerek (ve katkılarını ölçeklendirmek için bir learning rate kullanarak), uygun parametreler seçildiğinde aşırı overfitting olmadan çoğu zaman iyi bir şekilde generalize olur.

#### **Gradient Boosting'in temel özellikleri:**

-   **Problem türü:** Öncelikle classification ve regression. Security alanında genellikle classification (örneğin bir bağlantıyı veya dosyayı binary olarak sınıflandırma) kullanılır. Binary, multi-class (uygun loss ile) ve hatta ranking problemlerini işleyebilir.

-   **Yorumlanabilirlik:** Düşük ile orta düzeyde. Tek bir boosted tree küçük olsa da tam model yüzlerce tree içerebilir ve bütünüyle insan tarafından yorumlanabilir değildir. Ancak Random Forest gibi feature importance skorları sağlayabilir; SHAP (SHapley Additive exPlanations) gibi araçlar da bireysel prediction'ları bir ölçüde yorumlamak için kullanılabilir.

-   **Avantajları:** Structured/tabular data için çoğu zaman **en yüksek performansı sağlayan** algoritmadır. Karmaşık pattern'leri ve etkileşimleri tespit edebilir. Model karmaşıklığını özelleştirmek ve overfitting'i önlemek için çok sayıda tuning seçeneğine (tree sayısı, tree derinliği, learning rate, regularization terimleri) sahiptir. Modern implementasyonlar hız için optimize edilmiştir (örneğin XGBoost, second-order gradient bilgisi ve verimli data structure'lar kullanır). Uygun loss function'larla birleştirildiğinde veya sample weight'leri ayarlandığında imbalanced data'yı daha iyi işleme eğilimindedir.

-   **Sınırlamaları:** Daha basit modellere kıyasla ayarlanması daha karmaşıktır; tree'ler derin olduğunda veya tree sayısı fazla olduğunda training yavaşlayabilir (ancak genellikle aynı veriler üzerinde karşılaştırılabilir bir deep neural network eğitmekten yine de daha hızlıdır). Model ayarlanmazsa overfit olabilir (örneğin yeterli regularization olmadan çok fazla sayıda derin tree kullanılması). Çok sayıda hyperparameter bulunduğundan gradient boosting'i etkili şekilde kullanmak daha fazla uzmanlık veya deneme gerektirebilir. Ayrıca tree-based method'lar gibi, çok sparse ve high-dimensional data'yı linear model'ler veya Naive Bayes kadar verimli şekilde doğal olarak işleyemez (text classification'da olduğu gibi yine de uygulanabilir; ancak feature engineering yapılmadan ilk tercih olmayabilir).

> [!TIP]
> *Cybersecurity'deki kullanım alanları:* Bir decision tree veya random forest'ın kullanılabileceği hemen her yerde bir gradient boosting modeli daha yüksek accuracy sağlayabilir. Örneğin **Microsoft'un malware detection** yarışmalarında, binary file'lardan çıkarılan engineered feature'lar üzerinde XGBoost yoğun şekilde kullanılmıştır. **Network intrusion detection** araştırmalarında GBDT'lerle (örneğin CIC-IDS2017 veya UNSW-NB15 dataset'leri üzerinde XGBoost kullanarak) en iyi sonuçların alındığı sıkça raporlanır. Bu modeller çok çeşitli feature'ları (protocol type'ları, belirli event'lerin frequency değerleri, traffic'in statistical feature'ları vb.) alıp threat'leri tespit etmek üzere birleştirebilir. Phishing detection'da gradient boosting; URL'lerin lexical feature'larını, domain reputation feature'larını ve page content feature'larını birleştirerek çok yüksek accuracy elde edebilir. Ensemble yaklaşımı, data içindeki çok sayıda corner case'i ve ince ayrıntıyı kapsamaya yardımcı olur.

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
Gradient boosting modeli muhtemelen bu phishing veri kümesinde çok yüksek doğruluk ve AUC elde edecektir (literatürde görüldüğü üzere, uygun ayarlamalarla bu tür verilerde bu modeller çoğu zaman %95'in üzerinde doğruluğa ulaşabilir. Bu durum, GBDT'lerin neden *"tabular dataset için son teknoloji model"* olarak kabul edildiğini gösterir -- karmaşık örüntüleri yakalayarak genellikle daha basit algoritmalardan daha iyi performans gösterirler.<sup>[[11]](#references)</sup> Sibersecurity bağlamında bu, daha az hatalı sonuçla daha fazla phishing sitesi veya saldırısının yakalanması anlamına gelebilir. Elbette overfitting konusunda dikkatli olunmalıdır -- böyle bir modeli deployment için geliştirirken genellikle cross-validation gibi teknikleri kullanır ve bir validation seti üzerindeki performansı izleriz.

</details>

### Modelleri Birleştirme: Ensemble Learning ve Stacking

Ensemble learning, genel performansı iyileştirmek için **birden fazla modeli birleştirme** stratejisidir. Belirli ensemble yöntemlerini zaten gördük: Random Forest (bagging aracılığıyla ağaçlardan oluşan bir ensemble) ve Gradient Boosting (ardışık boosting aracılığıyla ağaçlardan oluşan bir ensemble). Ancak ensemble'lar **voting ensemble** veya **stacked generalization (stacking)** gibi başka yollarla da oluşturulabilir. Temel fikir, farklı modellerin farklı örüntüleri yakalayabilmesi veya farklı zayıflıklara sahip olabilmesidir; bunları birleştirerek **her modelin hatalarını diğerinin güçlü yönleriyle telafi edebiliriz**.<sup>[[12]](#references)</sup>

-   **Voting Ensemble:** Basit bir voting classifier'da birden fazla farklı model (örneğin bir logistic regression, bir decision tree ve bir SVM) eğitir ve nihai tahmin için bunların oy vermesini sağlarız (classification için çoğunluk oyu). Oyları ağırlıklandırırsak (örneğin daha doğru modellere daha yüksek ağırlık verirsek), bu weighted voting şeması olur. Bireysel modeller makul ölçüde iyi ve bağımsız olduğunda bu genellikle performansı iyileştirir -- diğer modeller hatayı düzeltebileceğinden ensemble, tek bir modelin hata yapma riskini azaltır. Bu, tek bir görüş yerine bir uzmanlar paneline sahip olmaya benzer.

-   **Stacking (Stacked Ensemble):** Stacking bunu bir adım ileri taşır. Basit bir oy kullanmak yerine, temel modellerin tahminlerini en iyi şekilde **nasıl birleştireceğini öğrenmek** için bir **meta-model** eğitir. Örneğin, 3 farklı classifier (base learner) eğitir, ardından bunların çıktılarını (veya olasılıklarını), bunları en uygun şekilde harmanlamayı öğrenen bir meta-classifier'a (çoğunlukla logistic regression gibi basit bir model) özellik olarak aktarırız. Meta-model, overfitting'i önlemek için bir validation seti üzerinde veya cross-validation aracılığıyla eğitilir. Stacking, *hangi koşullarda hangi modellere daha fazla güvenileceğini* öğrenerek çoğu zaman basit voting'den daha iyi performans gösterebilir. Sibersecurity alanında bir model network scan'lerini yakalamada daha iyi olurken, başka bir model malware beaconing'i yakalamada daha iyi olabilir; stacking modeli her birine uygun şekilde güvenmeyi öğrenebilir.

Voting veya stacking yoluyla oluşturulan ensemble'lar genellikle **doğruluğu** ve dayanıklılığı artırır. Dezavantajı, artan karmaşıklık ve bazen azalan yorumlanabilirliktir (ancak decision tree'lerin ortalaması gibi bazı ensemble yaklaşımları yine de belirli içgörüler sağlayabilir; örneğin feature importance). Pratikte, operasyonel kısıtlar izin veriyorsa bir ensemble kullanmak daha yüksek detection rate sağlayabilir. Sibersecurity challenge'larındaki (ve genel olarak Kaggle competition'larındaki) birçok kazanan çözüm, performansın son kısmını da elde etmek için ensemble tekniklerini kullanır.

<details>
<summary>Örnek -- Phishing Detection için Voting Ensemble:</summary>
Model stacking'i göstermek için phishing veri kümesinde ele aldığımız modellerden birkaçını birleştirelim. Base learner olarak bir logistic regression, bir decision tree ve bir k-NN kullanacak, tahminlerini birleştirmek için de meta-learner olarak bir Random Forest kullanacağız. Meta-learner, base learner'ların çıktıları üzerinde (training seti üzerinde cross-validation kullanılarak) eğitilecektir. Stacked modelin bireysel modeller kadar iyi veya onlardan biraz daha iyi performans göstermesini bekliyoruz.
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
Stacked ensemble, base modellerin tamamlayıcı güçlü yönlerinden yararlanır. Örneğin logistic regression verilerin doğrusal yönlerini ele alabilir, decision tree belirli kural benzeri etkileşimleri yakalayabilir ve k-NN feature space'in yerel komşuluklarında başarılı olabilir. Meta-model (burada random forest), bu girdileri nasıl ağırlıklandıracağını öğrenebilir. Ortaya çıkan metrikler genellikle herhangi bir tek modelin metriklerine kıyasla (küçük de olsa) bir iyileşme gösterir. Phishing örneğimizde logistic tek başına 0.95, tree ise 0.94 F1 değerine sahipse stack, her modelin hata yaptığı noktaları telafi ederek 0.96 değerine ulaşabilir.

Bunun gibi ensemble yöntemleri, *"birden fazla modelin birleştirilmesinin genellikle daha iyi genelleme sağlaması"* ilkesini gösterir.<sup>[[12]](#references)</sup> Cybersecurity alanında bu, birden fazla detection engine kullanılarak (bunlardan biri rule-based, biri machine learning, biri anomaly-based olabilir) ve ardından uyarıları birleştiren bir katman eklenerek -- yani etkin şekilde bir ensemble oluşturularak -- daha yüksek güvenle nihai bir karar verilmesi şeklinde uygulanabilir. Bu tür sistemleri deploy ederken, eklenen karmaşıklık dikkate alınmalı ve ensemble'ın yönetilmesinin veya açıklanmasının fazla zor hale gelmediğinden emin olunmalıdır. Ancak doğruluk açısından ensembles ve stacking, model performansını iyileştirmek için güçlü araçlardır.

</details>

## References

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
