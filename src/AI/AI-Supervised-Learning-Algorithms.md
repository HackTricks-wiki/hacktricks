# Denetimli Öğrenme Algoritmaları

{{#include ../banners/hacktricks-training.md}}

## Temel Bilgiler

Denetimli öğrenme, yeni, görülmemiş girdiler üzerinde tahminler yapabilen modelleri eğitmek için etiketli veriler kullanır. Siber güvenlikte, denetimli makine öğrenimi, saldırı tespiti (ağ trafiğini *normal* veya *saldırı* olarak sınıflandırma), kötü amaçlı yazılım tespiti (zararlı yazılımları zararsız olanlardan ayırma), kimlik avı tespiti (sahte web siteleri veya e-postaları tanımlama) ve spam filtreleme gibi görevlerde yaygın olarak uygulanmaktadır. Her algoritmanın güçlü yönleri vardır ve farklı problem türlerine (sınıflandırma veya regresyon) uygundur. Aşağıda, ana denetimli öğrenme algoritmalarını gözden geçiriyoruz, nasıl çalıştıklarını açıklıyoruz ve gerçek siber güvenlik veri setlerinde kullanımını gösteriyoruz. Ayrıca, modellerin birleştirilmesinin (ansambl öğrenme) tahmin performansını sıklıkla nasıl artırabileceğini tartışıyoruz.

## Algoritmalar

-   **Doğrusal Regresyon:** Sayısal sonuçları tahmin etmek için verilere doğrusal bir denklem uyduran temel bir regresyon algoritmasıdır.

-   **Lojistik Regresyon:** İki değerli bir sonucun olasılığını modellemek için lojistik bir fonksiyon kullanan bir sınıflandırma algoritmasıdır (adıyla çelişmesine rağmen).

-   **Karar Ağaçları:** Verileri özelliklere göre bölen ağaç yapısındaki modellerdir; genellikle yorumlanabilirlikleri için kullanılır.

-   **Rastgele Ormanlar:** Doğruluk artıran ve aşırı uyumu azaltan karar ağaçlarının (bagging yoluyla) bir ansamblıdır.

-   **Destek Vektör Makineleri (SVM):** Optimal ayırıcı hiper düzlemi bulan maksimum marj sınıflandırıcılarıdır; doğrusal olmayan veriler için çekirdekler kullanabilir.

-   **Naive Bayes:** Özellik bağımsızlığı varsayımı ile Bayes teoremi temelinde bir olasılık sınıflandırıcısıdır; ünlü olarak spam filtrelemede kullanılır.

-   **k-En Yakın Komşu (k-NN):** En yakın komşularının çoğunluk sınıfına dayalı olarak bir örneği etiketleyen basit bir "örnek tabanlı" sınıflandırıcıdır.

-   **Gradient Boosting Makineleri:** Zayıf öğrenicileri (genellikle karar ağaçları) ardışık olarak ekleyerek güçlü bir tahminci oluşturan ansambl modelleridir (örneğin, XGBoost, LightGBM).

Aşağıdaki her bölüm, algoritmanın geliştirilmiş bir tanımını ve `pandas` ve `scikit-learn` (ve sinir ağı örneği için `PyTorch`) gibi kütüphaneleri kullanarak bir **Python kod örneği** sunmaktadır. Örnekler, kamuya açık siber güvenlik veri setlerini (örneğin, saldırı tespiti için NSL-KDD ve bir Kimlik Avı Web Siteleri veri seti) kullanmakta ve tutarlı bir yapı izlemektedir:

1.  **Veri setini yükle** (varsa URL üzerinden indir).

2.  **Verileri ön işleme** (örneğin, kategorik özellikleri kodlama, değerleri ölçeklendirme, eğitim/test setlerine ayırma).

3.  **Modeli eğit** eğitim verileri üzerinde.

4.  **Test setinde değerlendir**: sınıflandırma için doğruluk, hassasiyet, geri çağırma, F1 skoru ve ROC AUC (ve regresyon için ortalama kare hatası) metriklerini kullanarak.

Her bir algoritmaya dalalım:

### Doğrusal Regresyon

Doğrusal regresyon, sürekli sayısal değerleri tahmin etmek için kullanılan bir **regresyon** algoritmasıdır. Girdi özellikleri (bağımsız değişkenler) ile çıktı (bağımlı değişken) arasında doğrusal bir ilişki varsayar. Model, özellikler ile hedef arasındaki ilişkiyi en iyi şekilde tanımlayan bir doğruyu (veya daha yüksek boyutlarda bir hiper düzlemi) uydurmaya çalışır. Bu genellikle tahmin edilen ve gerçek değerler arasındaki kare hataların toplamını minimize ederek yapılır (Ordinary Least Squares yöntemi).

Doğrusal regresyonu temsil etmenin en basit yolu bir doğrudur:
```plaintext
y = mx + b
```
Nerede:

- `y` tahmin edilen değer (çıktı)
- `m` doğrunun eğimi (katsayı)
- `x` girdi özelliği
- `b` y-kesişimi

Doğrusal regresyonun amacı, tahmin edilen değerler ile veri setindeki gerçek değerler arasındaki farkı en aza indiren en iyi uyumlu çizgiyi bulmaktır. Elbette, bu çok basit, iki kategoriyi ayıran düz bir çizgi olur, ancak daha fazla boyut eklendiğinde, çizgi daha karmaşık hale gelir:
```plaintext
y = w1*x1 + w2*x2 + ... + wn*xn + b
```
> [!TIP]
> *Siber güvenlikte kullanım durumları:* Doğrusal regresyon, temel güvenlik görevleri için (genellikle sınıflandırma olan) daha az yaygındır, ancak sayısal sonuçları tahmin etmek için uygulanabilir. Örneğin, doğrusal regresyon kullanılarak **ağ trafiği hacmi tahmin edilebilir** veya belirli bir zaman diliminde **saldırı sayısı tahmin edilebilir** geçmiş verilere dayanarak. Ayrıca, belirli sistem metrikleri göz önüne alındığında, bir risk puanı veya bir saldırının tespit edilmesine kadar beklenen süreyi tahmin edebilir. Pratikte, sınıflandırma algoritmaları (lojistik regresyon veya ağaçlar gibi) ihlalleri veya kötü amaçlı yazılımları tespit etmek için daha sık kullanılır, ancak doğrusal regresyon bir temel olarak hizmet eder ve regresyon odaklı analizler için faydalıdır.

#### **Doğrusal Regresyonun Anahtar Özellikleri:**

-   **Problem Türü:** Regresyon (sürekli değerleri tahmin etme). Çıktıya bir eşik uygulanmadıkça doğrudan sınıflandırma için uygun değildir.

-   **Yorumlanabilirlik:** Yüksek -- katsayılar, her özelliğin doğrusal etkisini göstererek basit bir şekilde yorumlanabilir.

-   **Avantajlar:** Basit ve hızlı; regresyon görevleri için iyi bir temel; gerçek ilişki yaklaşık olarak doğrusal olduğunda iyi çalışır.

-   **Sınırlamalar:** Karmaşık veya doğrusal olmayan ilişkileri yakalayamaz (manuel özellik mühendisliği olmadan); ilişkiler doğrusal değilse aşırı uyum sağlama eğilimindedir; sonuçları çarpıtabilecek aykırı değerlere duyarlıdır.

-   **En İyi Uyumun Bulunması:** Olası kategorileri ayıran en iyi uyum çizgisini bulmak için **Ordinary Least Squares (OLS)** adı verilen bir yöntem kullanıyoruz. Bu yöntem, gözlemlenen değerler ile doğrusal model tarafından tahmin edilen değerler arasındaki kare farkların toplamını minimize eder.

<details>
<summary>Örnek -- Bir İhlal Veri Setinde Bağlantı Süresini Tahmin Etme (Regresyon)
</summary>
Aşağıda, NSL-KDD siber güvenlik veri setini kullanarak doğrusal regresyonu gösteriyoruz. Bunu, diğer özelliklere dayanarak ağ bağlantılarının `süresini` tahmin ederek bir regresyon problemi olarak ele alacağız. (Gerçekte, `süre` NSL-KDD'nin bir özelliğidir; burada regresyonu göstermek için kullanıyoruz.) Veri setini yüklüyoruz, ön işleme tabi tutuyoruz (kategorik özellikleri kodluyoruz), bir doğrusal regresyon modeli eğitiyoruz ve bir test setinde Ortalama Kare Hata (MSE) ve R² puanını değerlendiriyoruz.
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
Bu örnekte, doğrusal regresyon modeli diğer ağ özelliklerinden bağlantı `süresi`ni tahmin etmeye çalışır. Performansı Ortalama Kare Hatası (MSE) ve R² ile ölçüyoruz. R²'nin 1.0'a yakın olması, modelin `süre`deki çoğu varyansı açıkladığını gösterirken, düşük veya negatif bir R² kötü bir uyum olduğunu belirtir. (R²'nin burada düşük olmasına şaşırmayın -- verilen özelliklerden `süre`yi tahmin etmek zor olabilir ve doğrusal regresyon karmaşık desenleri yakalayamayabilir.)

### Lojistik Regresyon

Lojistik regresyon, bir örneğin belirli bir sınıfa (genellikle "pozitif" sınıf) ait olma olasılığını modelleyen bir **sınıflandırma** algoritmasıdır. Adına rağmen, *lojistik* regresyon ayrık sonuçlar için kullanılır (doğrusal regresyonun sürekli sonuçlar için olduğu gibi). Özellikle **ikili sınıflandırma** (iki sınıf, örneğin, kötü niyetli vs. zararsız) için kullanılır, ancak çok sınıflı problemlere (softmax veya bir-vs-diğer yaklaşımlarını kullanarak) genişletilebilir.

Lojistik regresyon, tahmin edilen değerleri olasılıklara eşlemek için lojistik fonksiyonu (aynı zamanda sigmoid fonksiyonu olarak da bilinir) kullanır. Sigmoid fonksiyonunun, sınıflandırmanın ihtiyaçlarına göre S şeklinde bir eğri ile büyüyen, 0 ile 1 arasında değerler alan bir fonksiyon olduğunu unutmayın; bu, ikili sınıflandırma görevleri için faydalıdır. Bu nedenle, her girişin her özelliği, atanan ağırlığı ile çarpılır ve sonuç, bir olasılık üretmek için sigmoid fonksiyonundan geçirilir:
```plaintext
p(y=1|x) = 1 / (1 + e^(-z))
```
Where:

- `p(y=1|x)` çıktının `y` 1 olma olasılığıdır, verilen girdi `x`
- `e` doğal logaritmanın tabanıdır
- `z` girdi özelliklerinin lineer kombinasyonudur, genellikle `z = w1*x1 + w2*x2 + ... + wn*xn + b` olarak temsil edilir. En basit haliyle bir doğru olduğunu, ancak daha karmaşık durumlarda birkaç boyutlu (her özellik için bir) bir hiper düzlem haline geldiğini unutmayın.

> [!TIP]
> *Siber güvenlikte kullanım durumları:* Birçok güvenlik problemi esasen evet/hayır kararları olduğundan, lojistik regresyon yaygın olarak kullanılmaktadır. Örneğin, bir saldırı tespit sistemi, bir ağ bağlantısının o bağlantının özelliklerine dayanarak bir saldırı olup olmadığını belirlemek için lojistik regresyon kullanabilir. Phishing tespitinde, lojistik regresyon bir web sitesinin özelliklerini (URL uzunluğu, "@" sembolünün varlığı vb.) phishing olma olasılığına dönüştürebilir. Erken nesil spam filtrelerinde kullanılmıştır ve birçok sınıflandırma görevi için güçlü bir temel olmaya devam etmektedir.

#### Lojistik Regresyonun ikili olmayan sınıflandırma için

Lojistik regresyon ikili sınıflandırma için tasarlanmıştır, ancak **bir-vs-diğerleri** (OvR) veya **softmax regresyonu** gibi teknikler kullanarak çoklu sınıf problemlerini ele almak için genişletilebilir. OvR'de, her sınıf için ayrı bir lojistik regresyon modeli eğitilir ve bu sınıf diğer tüm sınıflara karşı pozitif sınıf olarak ele alınır. En yüksek tahmin edilen olasılığa sahip sınıf, nihai tahmin olarak seçilir. Softmax regresyonu, çıktı katmanına softmax fonksiyonu uygulayarak lojistik regresyonu birden fazla sınıfa genelleştirir ve tüm sınıflar üzerinde bir olasılık dağılımı üretir.

#### **Lojistik Regresyonun Ana Özellikleri:**

-   **Problem Türü:** Sınıflandırma (genellikle ikili). Pozitif sınıfın olasılığını tahmin eder.

-   **Yorumlanabilirlik:** Yüksek -- lineer regresyon gibi, özellik katsayıları her bir özelliğin sonucun log-odds'unu nasıl etkilediğini gösterebilir. Bu şeffaflık, bir uyarıya hangi faktörlerin katkıda bulunduğunu anlamak için güvenlikte genellikle takdir edilmektedir.

-   **Avantajlar:** Eğitimi basit ve hızlıdır; özellikler ile sonucun log-odds'u arasındaki ilişki lineer olduğunda iyi çalışır. Olasılıkları çıktılar, risk puanlamasına olanak tanır. Uygun düzenleme ile iyi genelleme yapar ve çoklu doğrusal bağıntıları düz lineer regresyondan daha iyi ele alabilir.

-   **Sınırlamalar:** Özellik alanında lineer bir karar sınırı varsayar (gerçek sınır karmaşık/lineer değilse başarısız olur). Etkileşimlerin veya lineer olmayan etkilerin kritik olduğu problemler üzerinde düşük performans gösterebilir, aksi takdirde polinom veya etkileşim özelliklerini manuel olarak eklemeniz gerekir. Ayrıca, sınıflar özelliklerin lineer kombinasyonu ile kolayca ayrılabilir değilse, lojistik regresyon daha az etkili olur.

<details>
<summary>Örnek -- Lojistik Regresyon ile Phishing Web Sitesi Tespiti:</summary>

Bir **Phishing Web Siteleri Veri Seti** (UCI deposundan) kullanacağız; bu veri seti, web sitelerinin çıkarılmış özelliklerini (URL'nin bir IP adresi olup olmadığı, alan adının yaşı, HTML'deki şüpheli unsurların varlığı vb.) ve sitenin phishing veya meşru olup olmadığını belirten bir etiketi içerir. Web sitelerini sınıflandırmak için bir lojistik regresyon modeli eğitiyoruz ve ardından test bölümü üzerinde doğruluğunu, kesinliğini, hatırlama oranını, F1-skorunu ve ROC AUC'yi değerlendiriyoruz.
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
Bu phishing tespiti örneğinde, lojistik regresyon her web sitesinin phishing olma olasılığını üretir. Doğruluk, kesinlik, hatırlama ve F1 değerlendirerek modelin performansını anlarız. Örneğin, yüksek bir hatırlama, çoğu phishing sitesini yakaladığı anlamına gelir (kaçırılan saldırıları en aza indirmek için güvenlik açısından önemlidir), yüksek kesinlik ise az sayıda yanlış alarm olduğu anlamına gelir (analist yorgunluğunu önlemek için önemlidir). ROC AUC (ROC Eğrisi Altındaki Alan), performansın eşik bağımsız bir ölçüsünü verir (1.0 ideal, 0.5 şansa eşit). Lojistik regresyon genellikle bu tür görevlerde iyi performans gösterir, ancak phishing ve meşru siteler arasındaki karar sınırı karmaşık ise, daha güçlü doğrusal olmayan modellere ihtiyaç duyulabilir.

</details>

### Karar Ağaçları

Karar ağacı, hem sınıflandırma hem de regresyon görevleri için kullanılabilen çok yönlü bir **denetimli öğrenme algoritması**dır. Verilerin özelliklerine dayalı olarak kararların hiyerarşik ağaç benzeri bir modelini öğrenir. Ağacın her iç düğümü belirli bir özellik üzerinde bir testi temsil eder, her dal o testin bir sonucunu temsil eder ve her yaprak düğümü bir tahmin edilen sınıfı (sınıflandırma için) veya değeri (regresyon için) temsil eder.

Bir ağaç inşa etmek için CART (Sınıflandırma ve Regresyon Ağacı) gibi algoritmalar, her adımda verileri bölmek için en iyi özelliği ve eşiği seçmek üzere **Gini saflığı** veya **bilgi kazancı (entropi)** gibi ölçüleri kullanır. Her bölünmedeki hedef, sonuçta oluşan alt kümelerde hedef değişkenin homojenliğini artırmak için verileri bölmektir (sınıflandırma için, her düğüm mümkün olduğunca saf olmaya çalışır ve ağırlıklı olarak tek bir sınıf içerir).

Karar ağaçları **yüksek derecede yorumlanabilir** -- bir tahminin arkasındaki mantığı anlamak için kökten yaprağa kadar olan yolu takip edebilirsiniz (örneğin, *"EĞER `service = telnet` VE `src_bytes > 1000` VE `failed_logins > 3` O ZAMAN saldırı olarak sınıflandır"*). Bu, belirli bir uyarının neden yükseltildiğini açıklamak için siber güvenlikte değerlidir. Ağaçlar hem sayısal hem de kategorik verileri doğal olarak işleyebilir ve az miktarda ön işleme gerektirir (örneğin, özellik ölçeklendirmeye ihtiyaç yoktur).

Ancak, tek bir karar ağacı eğitim verilerine kolayca aşırı uyum sağlayabilir, özellikle derin büyütüldüğünde (birçok bölme). Aşırı uyumu önlemek için genellikle budama (ağaç derinliğini sınırlama veya her yaprak için minimum örnek sayısı gerektirme) gibi teknikler kullanılır.

Bir karar ağacının 3 ana bileşeni vardır:
- **Kök Düğüm**: Ağacın en üst düğümü, tüm veri kümesini temsil eder.
- **İç Düğümler**: Özellikleri ve bu özelliklere dayalı kararları temsil eden düğümler.
- **Yaprak Düğümler**: Nihai sonucu veya tahmini temsil eden düğümler.

Bir ağaç şu şekilde görünebilir:
```plaintext
[Root Node]
/   \
[Node A]  [Node B]
/   \      /   \
[Leaf 1] [Leaf 2] [Leaf 3] [Leaf 4]
```
> [!TIP]
> *Siber güvenlikte kullanım durumları:* Karar ağaçları, saldırıları tanımlamak için **kurallar** türetmek amacıyla saldırı tespit sistemlerinde kullanılmıştır. Örneğin, ID3/C4.5 tabanlı erken IDS'ler, normal ve kötü niyetli trafiği ayırt etmek için insan tarafından okunabilir kurallar oluştururdu. Ayrıca, bir dosyanın kötü niyetli olup olmadığını belirlemek için dosya boyutu, bölüm entropisi, API çağrıları gibi özelliklerine dayanarak kötü amaçlı yazılım analizinde de kullanılırlar. Karar ağaçlarının netliği, şeffaflığın gerektiği durumlarda faydalı olmasını sağlar -- bir analist, tespiti doğrulamak için ağacı inceleyebilir.

#### **Karar Ağaçlarının Temel Özellikleri:**

-   **Problem Türü:** Hem sınıflandırma hem de regresyon. Saldırıların normal trafikten ayırt edilmesi gibi sınıflandırma için yaygın olarak kullanılır.

-   **Yorumlanabilirlik:** Çok yüksek -- modelin kararları, bir dizi if-then kuralı olarak görselleştirilebilir ve anlaşılabilir. Bu, güvenlikte model davranışının güvenilirliği ve doğrulanması için büyük bir avantajdır.

-   **Avantajlar:** Doğrusal olmayan ilişkileri ve özellikler arasındaki etkileşimleri yakalayabilir (her bir bölme bir etkileşim olarak görülebilir). Özellikleri ölçeklendirmeye veya kategorik değişkenleri one-hot kodlamaya gerek yoktur -- ağaçlar bunları yerel olarak işler. Hızlı çıkarım (tahmin, ağaçta bir yolu takip etmekten ibarettir).

-   **Sınırlamalar:** Kontrol edilmediğinde aşırı uyum sağlama eğilimindedir (derin bir ağaç eğitim setini ezberleyebilir). Dengesiz olabilirler -- verilerdeki küçük değişiklikler farklı bir ağaç yapısına yol açabilir. Tek modeller olarak, doğrulukları daha gelişmiş yöntemlerle (Random Forests gibi topluluklar genellikle varyansı azaltarak daha iyi performans gösterir) eşleşmeyebilir.

-   **En İyi Bölmeyi Bulma:**
- **Gini Safsızlığı**: Bir düğümün safsızlığını ölçer. Daha düşük Gini safsızlığı, daha iyi bir bölmeyi gösterir. Formül:

```plaintext
Gini = 1 - Σ(p_i^2)
```

Burada `p_i`, `i` sınıfındaki örneklerin oranını temsil eder.

- **Entropi**: Veri setindeki belirsizliği ölçer. Daha düşük entropi, daha iyi bir bölmeyi gösterir. Formül:

```plaintext
Entropy = -Σ(p_i * log2(p_i))
```

Burada `p_i`, `i` sınıfındaki örneklerin oranını temsil eder.

- **Bilgi Kazancı**: Bir bölmeden sonra entropi veya Gini safsızlığındaki azalma. Bilgi kazancı ne kadar yüksekse, bölme o kadar iyidir. Hesaplama:

```plaintext
Information Gain = Entropy(parent) - (Weighted Average of Entropy(children))
```

Ayrıca, bir ağaç şu durumlarda sonlanır:
- Bir düğümdeki tüm örnekler aynı sınıfa aittir. Bu aşırı uyuma yol açabilir.
- Ağacın maksimum derinliği (sabit kodlanmış) ulaşılmıştır. Bu, aşırı uyumu önlemenin bir yoludur.
- Bir düğümdeki örnek sayısı belirli bir eşik değerinin altındadır. Bu da aşırı uyumu önlemenin bir yoludur.
- Daha fazla bölmeden elde edilen bilgi kazancı belirli bir eşik değerinin altındadır. Bu da aşırı uyumu önlemenin bir yoludur.

<details>
<summary>Örnek -- Saldırı Tespiti için Karar Ağacı:</summary>
Ağ bağlantılarını *normal* veya *saldırı* olarak sınıflandırmak için NSL-KDD veri setinde bir karar ağacı eğiteceğiz. NSL-KDD, protokol türü, hizmet, süre, başarısız girişim sayısı gibi özelliklere sahip klasik KDD Cup 1999 veri setinin geliştirilmiş bir versiyonudur ve saldırı türünü veya "normal"i belirten bir etiket içerir. Tüm saldırı türlerini "anomalik" sınıfına (ikili sınıflandırma: normal vs anomali) eşleştireceğiz. Eğitimden sonra, ağacın test setindeki performansını değerlendireceğiz.
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
Bu karar ağacı örneğinde, aşırı uyumdan kaçınmak için ağacın derinliğini 10 ile sınırladık (`max_depth=10` parametresi). Metikler, ağacın normal ile saldırı trafiğini ne kadar iyi ayırt ettiğini gösterir. Yüksek bir geri çağırma, çoğu saldırıyı yakaladığı anlamına gelir (IDS için önemlidir), yüksek bir hassasiyet ise az sayıda yanlış alarm demektir. Karar ağaçları genellikle yapılandırılmış verilerde makul bir doğruluk elde eder, ancak tek bir ağaç en iyi performansa ulaşamayabilir. Yine de, modelin *yorumlanabilirliği* büyük bir artıdır -- örneğin, bir bağlantıyı kötü niyetli olarak işaretlemede en etkili olan özelliklerin (örneğin, `service`, `src_bytes` vb.) neler olduğunu görmek için ağacın bölümlerini inceleyebiliriz.

</details>

### Rastgele Ormanlar

Rastgele Orman, performansı artırmak için karar ağaçlarına dayanan bir **toplu öğrenme** yöntemidir. Rastgele orman, birden fazla karar ağacı (bu nedenle "orman") eğitir ve nihai tahmin yapmak için çıktıları birleştirir (sınıflandırma için genellikle çoğunluk oyu ile). Rastgele ormanda iki ana fikir **bagging** (bootstrap toplama) ve **özellik rastgeleliği**dir:

-   **Bagging:** Her ağaç, eğitim verilerinin rastgele bir bootstrap örneği üzerinde eğitilir (yerine koyarak örnekleme). Bu, ağaçlar arasında çeşitlilik sağlar.

-   **Özellik Rastgeleliği:** Bir ağaçtaki her bölmede, bölme için rastgele bir özellik alt kümesi dikkate alınır (tüm özellikler yerine). Bu, ağaçların daha fazla korelasyonunu azaltır.

Birçok ağacın sonuçlarını ortalamasıyla, rastgele orman, tek bir karar ağacının sahip olabileceği varyansı azaltır. Basit terimlerle, bireysel ağaçlar aşırı uyum sağlayabilir veya gürültülü olabilir, ancak çeşitli ağaçların birlikte oy vermesi bu hataları düzeltir. Sonuç genellikle **daha yüksek doğruluk** ve tek bir karar ağacından daha iyi genelleme ile bir modeldir. Ayrıca, rastgele ormanlar, her özelliğin ortalama olarak saflığı ne kadar azalttığını gözlemleyerek özellik öneminin bir tahminini sağlayabilir.

Rastgele ormanlar, sızma tespiti, kötü amaçlı yazılım sınıflandırması ve spam tespiti gibi görevler için siber güvenlikte bir **iş gücü** haline gelmiştir. Genellikle minimal ayarlarla kutudan çıktığı gibi iyi performans gösterir ve büyük özellik setlerini yönetebilir. Örneğin, sızma tespitinde, bir rastgele orman, daha az yanlış pozitif ile daha ince saldırı desenlerini yakalayarak bireysel bir karar ağacından daha iyi performans gösterebilir. Araştırmalar, rastgele ormanların NSL-KDD ve UNSW-NB15 gibi veri setlerinde saldırıları sınıflandırmada diğer algoritmalara kıyasla olumlu sonuçlar verdiğini göstermiştir.

#### **Rastgele Ormanların Ana Özellikleri:**

-   **Problem Türü:** Öncelikle sınıflandırma (regresyon için de kullanılır). Güvenlik günlüklerinde yaygın olan yüksek boyutlu yapılandırılmış veriler için çok uygundur.

-   **Yorumlanabilirlik:** Tek bir karar ağacından daha düşük -- yüzlerce ağacı aynı anda kolayca görselleştiremez veya açıklayamazsınız. Ancak, özellik önem puanları, hangi niteliklerin en etkili olduğu hakkında bazı bilgiler sağlar.

-   **Avantajlar:** Genellikle toplu etki nedeniyle tek ağaç modellerinden daha yüksek doğruluk. Aşırı uyuma karşı dayanıklıdır -- bireysel ağaçlar aşırı uyum sağlasa bile, topluluk daha iyi genelleme yapar. Hem sayısal hem de kategorik özellikleri yönetir ve kayıp verileri bir ölçüde idare edebilir. Ayrıca, uç değerlere karşı da nispeten dayanıklıdır.

-   **Sınırlamalar:** Model boyutu büyük olabilir (birçok ağaç, her biri potansiyel olarak derin). Tahminler, birçok ağaç üzerinde toplama yapmanız gerektiğinden tek bir ağaçtan daha yavaştır. Daha az yorumlanabilir -- önemli özellikleri bilseniz de, tam mantık basit bir kural olarak kolayca izlenemez. Veri seti son derece yüksek boyutlu ve seyrekse, çok büyük bir ormanı eğitmek hesaplama açısından ağır olabilir.

-   **Eğitim Süreci:**
1. **Bootstrap Örnekleme**: Eğitim verilerini yerine koyarak rastgele örnekleyerek birden fazla alt küme (bootstrap örnekleri) oluşturun.
2. **Ağaç İnşası**: Her bootstrap örneği için, her bölmede rastgele bir özellik alt kümesi kullanarak bir karar ağacı inşa edin. Bu, ağaçlar arasında çeşitlilik sağlar.
3. **Toplama**: Sınıflandırma görevleri için, nihai tahmin, tüm ağaçların tahminleri arasında çoğunluk oyu alarak yapılır. Regresyon görevleri için, nihai tahmin, tüm ağaçların tahminlerinin ortalamasıdır.

<details>
<summary>Örnek -- Sızma Tespiti için Rastgele Orman (NSL-KDD):</summary>
Aynı NSL-KDD veri setini (normal ile anomali olarak ikili etiketlenmiş) kullanacağız ve bir Rastgele Orman sınıflandırıcısı eğiteceğiz. Rastgele ormanın, varyansı azaltan toplu ortalama sayesinde tek karar ağacından eşit veya daha iyi performans göstermesini bekliyoruz. Aynı metriklerle değerlendireceğiz.
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
Rastgele orman, bu saldırı tespit görevinde genellikle güçlü sonuçlar elde eder. Tek bir karar ağacına kıyasla, özellikle geri çağırma veya hassasiyet açısından, veriye bağlı olarak F1 veya AUC gibi metriklerde bir iyileşme gözlemleyebiliriz. Bu, *"Rastgele Orman (RF), bir topluluk sınıflandırıcısıdır ve saldırıların etkili sınıflandırması için diğer geleneksel sınıflandırıcılara kıyasla iyi performans gösterir."* anlayışıyla uyumludur. Bir güvenlik operasyonları bağlamında, rastgele orman modeli, birçok karar kuralının ortalaması sayesinde saldırıları daha güvenilir bir şekilde işaretleyebilirken yanlış alarmları azaltabilir. Ormandan elde edilen özellik önemi, hangi ağ özelliklerinin saldırıları en iyi şekilde gösterdiğini (örneğin, belirli ağ hizmetleri veya olağandışı paket sayıları) bize söyleyebilir.

</details>

### Destek Vektör Makineleri (SVM)

Destek Vektör Makineleri, öncelikle sınıflandırma (ve ayrıca SVR olarak regresyon) için kullanılan güçlü denetimli öğrenme modelleridir. Bir SVM, iki sınıf arasındaki marjı maksimize eden **optimal ayırıcı hiper düzlemi** bulmaya çalışır. Bu hiper düzlemin konumunu belirleyen tek bir eğitim noktası alt kümesi (sınırın en yakınındaki "destek vektörleri") vardır. Marjı maksimize ederek (destek vektörleri ile hiper düzlem arasındaki mesafe), SVM'ler iyi genelleme sağlama eğilimindedir.

SVM'nin gücünün anahtarı, doğrusal olmayan ilişkileri ele almak için **kernel fonksiyonları** kullanma yeteneğidir. Veriler, doğrusal bir ayırıcı olabilecek daha yüksek boyutlu bir özellik alanına örtük olarak dönüştürülebilir. Yaygın kernel türleri arasında polinom, radyal baz fonksiyonu (RBF) ve sigmoid bulunur. Örneğin, ağ trafiği sınıfları ham özellik alanında doğrusal olarak ayrılamıyorsa, bir RBF kernel, bunları SVM'nin doğrusal bir bölme bulduğu daha yüksek bir boyuta haritalayabilir (bu, orijinal alandaki doğrusal olmayan bir sınırla karşılık gelir). Kernel seçme esnekliği, SVM'lerin çeşitli problemleri ele almasına olanak tanır.

SVM'lerin, yüksek boyutlu özellik alanlarında (metin verisi veya kötü amaçlı yazılım opcode dizileri gibi) ve özellik sayısının örnek sayısına göre büyük olduğu durumlarda iyi performans gösterdiği bilinmektedir. 2000'lerde kötü amaçlı yazılım sınıflandırması ve anomali tabanlı saldırı tespiti gibi birçok erken siber güvenlik uygulamasında popülerdi ve genellikle yüksek doğruluk gösteriyordu.

Ancak, SVM'ler çok büyük veri setlerine kolayca ölçeklenemez (eğitim karmaşıklığı, örnek sayısında süper lineerdir ve bellek kullanımı yüksek olabilir çünkü birçok destek vektörünü saklaması gerekebilir). Pratikte, milyonlarca kayıttan oluşan ağ saldırı tespiti gibi görevler için, dikkatli alt örnekleme veya yaklaşık yöntemler kullanılmadıkça SVM çok yavaş olabilir.

#### **SVM'nin Ana Özellikleri:**

-   **Problem Türü:** Sınıflandırma (ikili veya çok sınıflı bir-vs-bir/bir-vs-kalan) ve regresyon varyantları. Genellikle net marj ayrımı ile ikili sınıflandırmada kullanılır.

-   **Yorumlanabilirlik:** Orta -- SVM'ler, karar ağaçları veya lojistik regresyon kadar yorumlanabilir değildir. Hangi veri noktalarının destek vektörleri olduğunu belirleyebilir ve hangi özelliklerin etkili olabileceği hakkında bir fikir edinebilirsiniz (doğrusal kernel durumundaki ağırlıklar aracılığıyla), pratikte SVM'ler (özellikle doğrusal olmayan kernel'lerle) kara kutu sınıflandırıcılar olarak ele alınır.

-   **Avantajlar:** Yüksek boyutlu alanlarda etkili; kernel hilesi ile karmaşık karar sınırlarını modelleyebilir; marj maksimize edildiğinde aşırı uyuma karşı dayanıklıdır (özellikle uygun bir düzenleme parametresi C ile); sınıflar büyük bir mesafe ile ayrılmadığında bile iyi çalışır (en iyi uzlaşma sınırını bulur).

-   **Sınırlamalar:** **Büyük veri setleri için hesaplama açısından yoğun** (hem eğitim hem de tahmin, veri büyüdükçe kötü ölçeklenir). Kernel ve düzenleme parametrelerinin (C, kernel türü, RBF için gamma vb.) dikkatli bir şekilde ayarlanmasını gerektirir. Doğrudan olasılık çıktıları sağlamaz (ancak olasılıkları elde etmek için Platt ölçeklendirmesi kullanılabilir). Ayrıca, SVM'ler kernel parametrelerinin seçimine karşı hassas olabilir --- kötü bir seçim, aşırı uyum veya yetersiz uyum ile sonuçlanabilir.

*Siber güvenlikteki kullanım durumları:* SVM'ler, **kötü amaçlı yazılım tespiti** (örneğin, çıkarılan özellikler veya opcode dizileri temelinde dosyaları sınıflandırma), **ağ anomali tespiti** (trafiği normal veya kötü niyetli olarak sınıflandırma) ve **oltalama tespiti** (URL'lerin özelliklerini kullanarak) için kullanılmıştır. Örneğin, bir SVM, bir e-postanın özelliklerini (belirli anahtar kelimelerin sayıları, gönderenin itibar puanları vb.) alabilir ve bunu oltalama veya meşru olarak sınıflandırabilir. Ayrıca, KDD gibi özellik setlerinde **saldırı tespiti** için de uygulanmışlardır ve genellikle hesaplama maliyeti pahasına yüksek doğruluk elde etmiştir.

<details>
<summary>Örnek -- Kötü Amaçlı Yazılım Sınıflandırması için SVM:</summary>
Yine oltalama web sitesi veri setini kullanacağız, bu sefer bir SVM ile. SVM'ler yavaş olabileceğinden, gerekirse eğitim için verinin bir alt kümesini kullanacağız (veri seti yaklaşık 11k örnekten oluşuyor, bu da SVM'nin makul bir şekilde başa çıkabileceği bir miktar). Doğrusal olmayan veriler için yaygın bir seçim olan bir RBF kernel kullanacağız ve ROC AUC hesaplamak için olasılık tahminlerini etkinleştireceğiz.
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
SVM modeli, aynı görevde lojistik regresyon ile karşılaştırabileceğimiz metrikler üretecektir. Verilerin özellikler tarafından iyi ayrılmış olması durumunda SVM'nin yüksek bir doğruluk ve AUC elde ettiğini görebiliriz. Öte yandan, veri setinde çok fazla gürültü veya örtüşen sınıflar varsa, SVM lojistik regresyonu önemli ölçüde geçemeyebilir. Pratikte, SVM'ler, özellikler ve sınıf arasında karmaşık, doğrusal olmayan ilişkiler olduğunda bir avantaj sağlayabilir - RBF çekirdeği, lojistik regresyonun kaçıracağı eğrilen karar sınırlarını yakalayabilir. Tüm modellerde olduğu gibi, `C` (düzenleme) ve çekirdek parametrelerinin (RBF için `gamma` gibi) dikkatli bir şekilde ayarlanması, yanlılık ve varyansı dengelemek için gereklidir.

</details>

#### Lojistik Regresyonlar ve SVM Arasındaki Fark

| Aspect | **Lojistik Regresyon** | **Destek Vektör Makineleri** |
|---|---|---|
| **Amaç fonksiyonu** | **log-kayıp** (çapraz-entropi) en aza indirir. | **margini** maksimize ederken **hinge-kayıp** en aza indirir. |
| **Karar sınırı** | _P(y\|x)_ modelleyen **en iyi uyum hiper düzlemi** bulur. | **maksimum-margini hiper düzlemi** (en yakın noktalara en büyük boşluk) bulur. |
| **Çıktı** | **Olasılıksal** – σ(w·x + b) aracılığıyla kalibre edilmiş sınıf olasılıkları verir. | **Belirleyici** – sınıf etiketlerini döndürür; olasılıklar ek çalışma gerektirir (örneğin, Platt ölçeklendirmesi). |
| **Düzenleme** | L2 (varsayılan) veya L1, doğrudan aşırı/az fit etmeyi dengeler. | C parametresi, margin genişliği ile yanlış sınıflandırmalar arasında bir denge kurar; çekirdek parametreleri karmaşıklık ekler. |
| **Çekirdekler / Doğrusal Olmayan** | Yerel formu **doğrusal**; doğrusal olmayanlık özellik mühendisliği ile eklenir. | Yerleşik **çekirdek hilesi** (RBF, polinom vb.) karmaşık sınırları yüksek boyutlu uzayda modellemesine olanak tanır. |
| **Ölçeklenebilirlik** | **O(nd)**'de konveks optimizasyonu çözer; çok büyük n'leri iyi yönetir. | Eğitim, özel çözücüler olmadan **O(n²–n³)** bellek/zaman alabilir; büyük n'lere daha az dostça. |
| **Yorumlanabilirlik** | **Yüksek** – ağırlıklar özellik etkisini gösterir; oran oranı sezgisel. | Doğrusal olmayan çekirdekler için **Düşük**; destek vektörleri seyrek ama açıklaması kolay değildir. |
| **Aykırı değerlere duyarlılık** | Pürüzsüz log-kayıp kullanır → daha az duyarlıdır. | Sert margin ile hinge-kayıp **duyarlı** olabilir; yumuşak margin (C) bunu hafifletir. |
| **Tipik kullanım durumları** | Kredi puanlama, tıbbi risk, A/B testi – **olasılıklar ve açıklanabilirlik** önemli olduğunda. | Görüntü/metin sınıflandırması, biyoinformatik – **karmaşık sınırlar** ve **yüksek boyutlu veriler** önemli olduğunda. |

* **Kalibre edilmiş olasılıklara, yorumlanabilirliğe ihtiyacınız varsa veya büyük veri setlerinde çalışıyorsanız — Lojistik Regresyon'u seçin.**
* **Manuel özellik mühendisliği olmadan doğrusal olmayan ilişkileri yakalayabilen esnek bir modele ihtiyacınız varsa — SVM'yi (çekirdeklerle) seçin.**
* Her ikisi de konveks hedefleri optimize eder, bu nedenle **küresel minimumlar garanti edilir**, ancak SVM'nin çekirdekleri hiper-parametreler ve hesaplama maliyeti ekler.

### Naif Bayes

Naif Bayes, özellikler arasında güçlü bir bağımsızlık varsayımına dayanan **olasılıksal sınıflandırıcılar** ailesidir. Bu "naif" varsayıma rağmen, Naif Bayes belirli uygulamalar için, özellikle metin veya kategorik verilerle ilgili olanlar, spam tespiti gibi, şaşırtıcı derecede iyi çalışır.

#### Bayes Teoremi

Bayes teoremi, Naif Bayes sınıflandırıcılarının temelini oluşturur. Rastgele olayların koşullu ve marjinal olasılıklarını ilişkilendirir. Formül:
```plaintext
P(A|B) = (P(B|A) * P(A)) / P(B)
```
Where:
- `P(A|B)` sınıf `A`'nın özellik `B` verildiğinde posterior olasılığıdır.
- `P(B|A)` sınıf `A` verildiğinde özellik `B`'nin olasılığıdır.
- `P(A)` sınıf `A`'nın öncel olasılığıdır.
- `P(B)` özellik `B`'nin öncel olasılığıdır.

Örneğin, bir metnin bir çocuk veya bir yetişkin tarafından yazılıp yazılmadığını sınıflandırmak istiyorsak, metindeki kelimeleri özellikler olarak kullanabiliriz. Bazı başlangıç verilerine dayanarak, Naive Bayes sınıflandırıcısı her kelimenin her potansiyel sınıfta (çocuk veya yetişkin) olma olasılıklarını önceden hesaplayacaktır. Yeni bir metin verildiğinde, metindeki kelimelere dayanarak her potansiyel sınıfın olasılığını hesaplayacak ve en yüksek olasılığa sahip sınıfı seçecektir.

Bu örnekte görüldüğü gibi, Naive Bayes sınıflandırıcısı çok basit ve hızlıdır, ancak özelliklerin bağımsız olduğunu varsayar; bu, gerçek dünya verilerinde her zaman geçerli değildir.

#### Naive Bayes Sınıflandırıcılarının Türleri

Veri türüne ve özelliklerin dağılımına bağlı olarak birkaç tür Naive Bayes sınıflandırıcısı vardır:
- **Gaussian Naive Bayes**: Özelliklerin Gaussian (normal) dağılımı izlediğini varsayar. Sürekli veriler için uygundur.
- **Multinomial Naive Bayes**: Özelliklerin multinomial dağılımı izlediğini varsayar. Metin sınıflandırmasında kelime sayıları gibi ayrık veriler için uygundur.
- **Bernoulli Naive Bayes**: Özelliklerin ikili (0 veya 1) olduğunu varsayar. Metin sınıflandırmasında kelimelerin varlığı veya yokluğu gibi ikili veriler için uygundur.
- **Categorical Naive Bayes**: Özelliklerin kategorik değişkenler olduğunu varsayar. Renk ve şekil gibi kategorik veriler için uygundur.

#### **Naive Bayes'in Ana Özellikleri:**

-   **Problem Türü:** Sınıflandırma (ikili veya çoklu sınıf). Siber güvenlikte metin sınıflandırma görevleri için yaygın olarak kullanılır (spam, phishing, vb.).

-   **Yorumlanabilirlik:** Orta -- karar ağaçları kadar doğrudan yorumlanabilir değildir, ancak öğrenilen olasılıkları incelemek mümkündür (örneğin, spam ve ham e-postalarda hangi kelimelerin en olası olduğu). Modelin formu (sınıfa göre her özellik için olasılıklar) gerektiğinde anlaşılabilir.

-   **Avantajlar:** **Çok hızlı** eğitim ve tahmin, büyük veri setlerinde bile (örnek sayısı * özellik sayısı açısından lineer). Olasılıkları güvenilir bir şekilde tahmin etmek için nispeten az veri gerektirir, özellikle uygun düzeltme ile. Özellikler bağımsız olarak sınıfa kanıt sunduğunda genellikle şaşırtıcı derecede doğru bir temel sağlar. Yüksek boyutlu verilerle (örneğin, metinden gelen binlerce özellik) iyi çalışır. Düzeltme parametresi ayarlamaktan başka karmaşık ayarlamalar gerektirmez.

-   **Sınırlamalar:** Bağımsızlık varsayımı, özellikler yüksek oranda korelasyona sahipse doğruluğu sınırlayabilir. Örneğin, ağ verilerinde `src_bytes` ve `dst_bytes` gibi özellikler birbirleriyle ilişkili olabilir; Naive Bayes bu etkileşimi yakalayamaz. Veri boyutu çok büyük hale geldikçe, daha ifade edici modeller (örneğin, topluluklar veya sinir ağları) özellik bağımlılıklarını öğrenerek NB'yi geçebilir. Ayrıca, bir saldırıyı tanımlamak için belirli bir özellik kombinasyonu gerekiyorsa (sadece bireysel özellikler bağımsız olarak değil), NB zorlanacaktır.

> [!TIP]
> *Siber güvenlikte kullanım durumları:* Klasik kullanım **spam tespiti**dir -- Naive Bayes, belirli token'ların (kelimeler, ifadeler, IP adresleri) sıklıklarını kullanarak bir e-postanın spam olma olasılığını hesaplayan erken spam filtrelerinin temelini oluşturuyordu. Ayrıca **phishing e-posta tespiti** ve **URL sınıflandırması** için de kullanılır; belirli anahtar kelimelerin veya özelliklerin (örneğin, bir URL'de "login.php" veya bir URL yolunda `@` varlığı) phishing olasılığına katkıda bulunur. Kötü amaçlı yazılım analizinde, belirli API çağrılarının veya yazılımdaki izinlerin varlığını kullanarak bunun kötü amaçlı yazılım olup olmadığını tahmin eden bir Naive Bayes sınıflandırıcısı hayal edilebilir. Daha gelişmiş algoritmalar genellikle daha iyi performans gösterse de, Naive Bayes hızı ve sadeliği nedeniyle iyi bir temel olarak kalır.

<details>
<summary>Örnek -- Phishing Tespiti için Naive Bayes:</summary>
Naive Bayes'i göstermek için, NSL-KDD saldırı veri setinde (ikili etiketlerle) Gaussian Naive Bayes kullanacağız. Gaussian NB, her özelliği sınıfa göre normal dağılım izliyormuş gibi ele alacaktır. Bu, birçok ağ özelliği ayrık veya yüksek oranda çarpık olduğu için kaba bir seçimdir, ancak NB'nin sürekli özellik verilerine nasıl uygulanacağını gösterir. Ayrıca, ikili özellikler (tetiklenmiş uyarılar gibi) içeren bir veri setinde Bernoulli NB'yi de seçebiliriz, ancak burada süreklilik için NSL-KDD ile devam edeceğiz.
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
Bu kod, saldırıları tespit etmek için bir Naive Bayes sınıflandırıcısını eğitir. Naive Bayes, özellikler arasında bağımsızlık varsayarak, eğitim verilerine dayanarak `P(service=http | Attack)` ve `P(Service=http | Normal)` gibi şeyleri hesaplayacaktır. Ardından, gözlemlenen özelliklere dayanarak yeni bağlantıları normal veya saldırı olarak sınıflandırmak için bu olasılıkları kullanacaktır. NB'nin NSL-KDD üzerindeki performansı, daha gelişmiş modeller kadar yüksek olmayabilir (çünkü özellik bağımsızlığı ihlal edilmiştir), ancak genellikle makuldür ve aşırı hız avantajıyla birlikte gelir. Gerçek zamanlı e-posta filtreleme veya URL'lerin ilk önceliklendirilmesi gibi senaryolarda, bir Naive Bayes modeli, belirgin şekilde kötü niyetli durumları hızlı bir şekilde işaretleyebilir ve düşük kaynak kullanımı ile çalışır.

</details>

### k-En Yakın Komşular (k-NN)

k-En Yakın Komşular, en basit makine öğrenimi algoritmalarından biridir. Bu, eğitim setindeki örneklere benzerliğe dayalı tahminler yapan **parametre içermeyen, örnek bazlı** bir yöntemdir. Sınıflandırma fikri şudur: yeni bir veri noktasını sınıflandırmak için, eğitim verilerindeki **k** en yakın noktaları (en "yakın komşularını") bulmak ve bu komşular arasında çoğunluk sınıfını atamaktır. "Yakınlık", genellikle sayısal veriler için Öklid mesafesi olan bir mesafe metriği ile tanımlanır (farklı türde özellikler veya problemler için diğer mesafeler kullanılabilir).

K-NN, *açık bir eğitim gerektirmez* -- "eğitim" aşaması sadece veri kümesini depolamaktır. Tüm çalışma sorgu (tahmin) sırasında gerçekleşir: algoritma, en yakın noktaları bulmak için sorgu noktasından tüm eğitim noktalarına mesafeleri hesaplamak zorundadır. Bu, tahmin süresini **eğitim örneklerinin sayısına göre lineer** hale getirir, bu da büyük veri setleri için maliyetli olabilir. Bu nedenle, k-NN, daha küçük veri setleri veya bellek ve hızı basitlik için takas edebileceğiniz senaryolar için en uygun olanıdır.

Basitliğine rağmen, k-NN çok karmaşık karar sınırlarını modelleyebilir (çünkü etkili bir şekilde karar sınırı, örneklerin dağılımı tarafından belirlenen herhangi bir şekil olabilir). Karar sınırı çok düzensiz olduğunda ve çok fazla veriniz olduğunda iyi sonuçlar verir -- esasen verilerin "kendi kendine konuşmasına" izin verir. Ancak, yüksek boyutlarda, mesafe metrikleri daha az anlamlı hale gelebilir (boyut laneti) ve yöntem, büyük sayıda örneğiniz yoksa zorlanabilir.

*Siber güvenlikteki kullanım durumları:* k-NN, anomali tespiti için uygulanmıştır -- örneğin, bir saldırı tespit sistemi, en yakın komşularının (önceki olaylar) çoğu kötü niyetli ise bir ağ olayını kötü niyetli olarak etiketleyebilir. Normal trafik kümeler oluşturursa ve saldırılar aykırı değerlerse, k-NN yaklaşımı (k=1 veya küçük k ile) esasen **en yakın komşu anomali tespiti** yapar. K-NN, ikili özellik vektörleri ile kötü amaçlı yazılım ailelerini sınıflandırmak için de kullanılmıştır: yeni bir dosya, o ailenin bilinen örneklerine çok yakınsa belirli bir kötü amaçlı yazılım ailesi olarak sınıflandırılabilir. Pratikte, k-NN, daha ölçeklenebilir algoritmalar kadar yaygın değildir, ancak kavramsal olarak basittir ve bazen bir temel veya küçük ölçekli problemler için kullanılır.

#### **k-NN'nin Ana Özellikleri:**

-   **Problem Türü:** Sınıflandırma (ve regresyon varyantları mevcuttur). Bu, *tembel öğrenme* yöntemidir -- açık bir model uyumu yoktur.

-   **Yorumlanabilirlik:** Düşük ila orta -- global bir model veya özlü bir açıklama yoktur, ancak bir kararın etkilediği en yakın komşulara bakarak sonuçlar yorumlanabilir (örneğin, "bu ağ akışı, bu 3 bilinen kötü niyetli akışa benzer olduğu için kötü niyetli olarak sınıflandırıldı"). Bu nedenle, açıklamalar örnek bazlı olabilir.

-   **Avantajlar:** Uygulaması ve anlaşılması çok basit. Veri dağılımı hakkında hiçbir varsayımda bulunmaz (parametre içermeyen). Çok sınıflı problemleri doğal olarak ele alabilir. **Uyumlu** bir yapıya sahiptir; karar sınırları çok karmaşık olabilir ve veri dağılımı tarafından şekillendirilir.

-   **Sınırlamalar:** Büyük veri setleri için tahmin yavaş olabilir (birçok mesafe hesaplanması gerekir). Bellek yoğun -- tüm eğitim verilerini depolar. Yüksek boyutlu özellik alanlarında performans düşer çünkü tüm noktalar neredeyse eşit uzaklıkta hale gelir (bu da "en yakın" kavramını daha az anlamlı kılar). *k* (komşu sayısı) uygun bir şekilde seçilmelidir -- çok küçük k gürültülü olabilir, çok büyük k diğer sınıflardan alakasız noktaları içerebilir. Ayrıca, mesafe hesaplamaları ölçeğe duyarlı olduğundan, özelliklerin uygun şekilde ölçeklendirilmesi gerekir.

<details>
<summary>Örnek -- Phishing Tespiti için k-NN:</summary>

Yine NSL-KDD'yi (ikili sınıflandırma) kullanacağız. k-NN hesaplama açısından ağır olduğu için, bu gösterimde yönetilebilir tutmak için eğitim verilerinin bir alt kümesini kullanacağız. Tam 125k'dan 20,000 eğitim örneği seçeceğiz ve k=5 komşu kullanacağız. Eğitimden sonra (gerçekten sadece veriyi depolamak), test setinde değerlendirme yapacağız. Ayrıca, ölçek hesaplaması için özellikleri ölçeklendireceğiz, böylece tek bir özellik ölçek nedeniyle baskın çıkmaz.
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
k-NN modeli, bağlantıyı eğitim seti alt kümesindeki en yakın 5 bağlantıya bakarak sınıflandırır. Örneğin, bu komşulardan 4'ü saldırı (anomaliler) ve 1'i normal ise, yeni bağlantı bir saldırı olarak sınıflandırılacaktır. Performans makul olabilir, ancak genellikle aynı verilerde iyi ayarlanmış bir Random Forest veya SVM kadar yüksek değildir. Ancak, k-NN bazen sınıf dağılımları çok düzensiz ve karmaşık olduğunda parlayabilir - etkili bir şekilde bellek tabanlı bir arama kullanarak. Siber güvenlikte, k-NN (k=1 veya küçük k ile) bilinen saldırı desenlerinin tespiti için örnek olarak veya daha karmaşık sistemlerde (örneğin, kümeleme ve ardından küme üyeliğine göre sınıflandırma için) bir bileşen olarak kullanılabilir.

### Gradient Boosting Machines (örneğin, XGBoost)

Gradient Boosting Machines, yapılandırılmış veriler için en güçlü algoritmalardan biridir. **Gradient boosting**, zayıf öğrenicilerin (genellikle karar ağaçları) ardışık bir şekilde bir topluluk oluşturma tekniğini ifade eder; burada her yeni model, önceki topluluğun hatalarını düzeltir. Ağaçları paralel olarak inşa eden ve ortalayan bagging (Random Forests) ile karşılaştırıldığında, boosting ağaçları *birer birer* inşa eder ve her biri önceki ağaçların yanlış tahmin ettiği örneklere daha fazla odaklanır.

Son yıllarda en popüler uygulamalar **XGBoost**, **LightGBM** ve **CatBoost**'tur; bunların hepsi gradient boosting karar ağaçları (GBDT) kütüphaneleridir. Makine öğrenimi yarışmalarında ve uygulamalarında son derece başarılı olmuşlardır ve genellikle **tablo verilerinde en son teknoloji performansı elde etmektedirler**. Siber güvenlikte, araştırmacılar ve uygulayıcılar, **kötü amaçlı yazılım tespiti** (dosyalardan veya çalışma zamanı davranışından çıkarılan özellikler kullanarak) ve **ağ saldırı tespiti** gibi görevler için gradient boosted ağaçlar kullanmışlardır. Örneğin, bir gradient boosting modeli, "birçok SYN paketi ve alışılmadık port -> muhtemel tarama" gibi birçok zayıf kuralı (ağaçları) güçlü bir bileşik dedektöre dönüştürebilir ve birçok ince deseni dikkate alır.

Neden artırılmış ağaçlar bu kadar etkilidir? Sıralamadaki her ağaç, mevcut topluluğun tahminlerinin *artık hataları* (gradyanlar) üzerinde eğitilir. Bu şekilde, model zayıf olduğu alanları yavaş yavaş **"artırır"**. Karar ağaçlarının temel öğreniciler olarak kullanılması, nihai modelin karmaşık etkileşimleri ve doğrusal olmayan ilişkileri yakalayabilmesini sağlar. Ayrıca, boosting, yerleşik bir düzenleme biçimine sahiptir: birçok küçük ağaç ekleyerek (ve katkılarını ölçeklendirmek için bir öğrenme oranı kullanarak), genellikle uygun parametreler seçildiğinde büyük aşırı uyum olmadan iyi genelleme yapar.

#### **Gradient Boosting'in Ana Özellikleri:**

-   **Problem Türü:** Öncelikle sınıflandırma ve regresyon. Güvenlikte genellikle sınıflandırma (örneğin, bir bağlantıyı veya dosyayı ikili olarak sınıflandırma). İkili, çok sınıflı (uygun kayıpla) ve hatta sıralama problemlerini ele alır.

-   **Yorumlanabilirlik:** Düşük ila orta. Tek bir artırılmış ağaç küçük olsa da, tam bir model yüzlerce ağaç içerebilir, bu da bütünüyle insan tarafından yorumlanamaz. Ancak, Random Forest gibi, özellik önem puanları sağlayabilir ve SHAP (SHapley Additive exPlanations) gibi araçlar, bireysel tahminleri bir ölçüde yorumlamak için kullanılabilir.

-   **Avantajlar:** Genellikle yapılandırılmış/tablo verileri için **en iyi performans gösteren** algoritmadır. Karmaşık desenleri ve etkileşimleri tespit edebilir. Model karmaşıklığını özelleştirmek ve aşırı uyumu önlemek için birçok ayar düğmesine (ağaç sayısı, ağaç derinliği, öğrenme oranı, düzenleme terimleri) sahiptir. Modern uygulamalar hız için optimize edilmiştir (örneğin, XGBoost ikinci dereceden gradyan bilgisi ve verimli veri yapıları kullanır). Uygun kayıp fonksiyonları ile veya örnek ağırlıklarını ayarlayarak dengesiz verileri daha iyi işleme eğilimindedir.

-   **Sınırlamalar:** Daha basit modellere göre ayarlaması daha karmaşıktır; ağaçlar derin veya ağaç sayısı büyükse eğitim yavaş olabilir (ancak yine de genellikle aynı verilerde karşılaştırılabilir bir derin sinir ağını eğitmekten daha hızlıdır). Model ayarlanmadan aşırı uyum sağlayabilir (örneğin, yetersiz düzenleme ile çok fazla derin ağaç). Birçok hiperparametre nedeniyle, gradient boosting'i etkili bir şekilde kullanmak daha fazla uzmanlık veya deney yapmayı gerektirebilir. Ayrıca, ağaç tabanlı yöntemler gibi, çok seyrek yüksek boyutlu verileri doğrusal modeller veya Naive Bayes kadar verimli bir şekilde ele almaz (ancak yine de uygulanabilir, örneğin metin sınıflandırmasında, ancak özellik mühendisliği olmadan ilk tercih olmayabilir).

> [!TIP]
> *Siber güvenlikte kullanım alanları:* Bir karar ağacı veya rastgele orman kullanılabilecek hemen her yerde, bir gradient boosting modeli daha iyi doğruluk elde edebilir. Örneğin, **Microsoft'un kötü amaçlı yazılım tespiti** yarışmalarında, ikili dosyalardan mühendislik özellikleri üzerinde XGBoost'un yoğun kullanımı görülmüştür. **Ağ saldırı tespiti** araştırmaları genellikle GBDT'lerle en iyi sonuçları rapor etmektedir (örneğin, XGBoost'un CIC-IDS2017 veya UNSW-NB15 veri setlerinde). Bu modeller, tehditleri tespit etmek için geniş bir özellik yelpazesini (protokol türleri, belirli olayların sıklığı, trafik istatistiksel özellikleri vb.) alabilir ve bunları birleştirebilir. Phishing tespitinde, gradient boosting, URL'lerin sözcüksel özelliklerini, alan adı itibar özelliklerini ve sayfa içerik özelliklerini birleştirerek çok yüksek doğruluk elde edebilir. Topluluk yaklaşımı, verilerdeki birçok köşe durumu ve inceliği kapsamaya yardımcı olur.

<details>
<summary>Örnek -- Phishing Tespiti için XGBoost:</summary>
Phishing veri setinde bir gradient boosting sınıflandırıcısı kullanacağız. İşleri basit ve kendi kendine yeterli tutmak için, `sklearn.ensemble.GradientBoostingClassifier` (bu daha yavaş ama basit bir uygulamadır) kullanacağız. Normalde, daha iyi performans ve ek özellikler için `xgboost` veya `lightgbm` kütüphaneleri kullanılabilir. Modeli eğiteceğiz ve daha önceki gibi değerlendireceğiz.
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
Gradient boosting modeli, bu phishing veri setinde çok yüksek doğruluk ve AUC elde etme olasılığı taşımaktadır (genellikle bu modeller, bu tür verilerde uygun ayarlamalarla %95'ten fazla doğruluk elde edebilir, literatürde görüldüğü gibi. Bu, GBDT'lerin *"tablo veri setleri için en iyi model" olarak neden kabul edildiğini gösterir* -- karmaşık desenleri yakalayarak genellikle daha basit algoritmalardan daha iyi performans gösterirler. Siber güvenlik bağlamında, bu daha fazla phishing sitesi veya saldırısını daha az hata ile yakalamak anlamına gelebilir. Elbette, aşırı uyum konusunda dikkatli olunmalıdır -- böyle bir modeli dağıtım için geliştirirken genellikle çapraz doğrulama gibi teknikler kullanır ve bir doğrulama setinde performansı izleriz.

</details>

### Modelleri Birleştirme: Ensemble Öğrenme ve Stacking

Ensemble öğrenme, genel performansı artırmak için **birden fazla modeli birleştirme** stratejisidir. Daha önce belirli ensemble yöntemlerini gördük: Random Forest (bagging ile ağaçların bir ensemble'ı) ve Gradient Boosting (sıralı boosting ile ağaçların bir ensemble'ı). Ancak, ensemble'lar **oylama ensemble'ları** veya **stacked generalization (stacking)** gibi diğer yollarla da oluşturulabilir. Ana fikir, farklı modellerin farklı desenleri yakalayabileceği veya farklı zayıflıkları olabileceğidir; bunları birleştirerek, **her modelin hatalarını diğerinin güçlü yönleriyle telafi edebiliriz**.

-   **Oylama Ensemble:** Basit bir oylama sınıflandırıcısında, birden fazla çeşitli modeli (örneğin, bir lojistik regresyon, bir karar ağacı ve bir SVM) eğitiyoruz ve bunların son tahmin üzerinde oy kullanmalarını sağlıyoruz (sınıflandırma için çoğunluk oyu). Oylara ağırlık verirsek (örneğin, daha doğru modellere daha yüksek ağırlık), bu ağırlıklı bir oylama şemasına dönüşür. Bu genellikle bireysel modeller makul derecede iyi ve bağımsız olduğunda performansı artırır -- ensemble, bireysel bir modelin hatasının riskini azaltır çünkü diğerleri bunu düzeltebilir. Bu, tek bir görüş yerine bir uzman paneline sahip olmak gibidir.

-   **Stacking (Stacked Ensemble):** Stacking bir adım daha ileri gider. Basit bir oy yerine, bir **meta-model** eğiterek **temel modellerin tahminlerini en iyi şekilde nasıl birleştireceğini öğrenir**. Örneğin, 3 farklı sınıflandırıcı (temel öğreniciler) eğitirsiniz, ardından çıktıları (veya olasılıkları) bir meta-sınıflandırıcıya (genellikle lojistik regresyon gibi basit bir model) özellik olarak beslersiniz; bu model, bunları harmanlamanın en iyi yolunu öğrenir. Meta-model, aşırı uyumu önlemek için bir doğrulama setinde veya çapraz doğrulama ile eğitilir. Stacking, *hangi modellerin hangi durumlarda daha fazla güvenilir olduğunu öğrenerek* basit oylamadan genellikle daha iyi performans gösterebilir. Siber güvenlikte, bir model ağ taramalarını yakalamada daha iyi olabilirken, diğeri kötü amaçlı yazılım sinyallerini yakalamada daha iyi olabilir; bir stacking modeli her birine uygun şekilde güvenmeyi öğrenebilir.

Oylama veya stacking ile olsun, ensemble'lar genellikle **doğruluğu** ve sağlamlığı artırma eğilimindedir. Dezavantajı, artan karmaşıklık ve bazen azalan yorumlanabilirliktir (ancak karar ağaçlarının ortalaması gibi bazı ensemble yaklaşımları yine de bazı içgörüler sağlayabilir, örneğin, özellik önemi). Pratikte, operasyonel kısıtlamalar izin veriyorsa, bir ensemble kullanmak daha yüksek tespit oranlarına yol açabilir. Siber güvenlik zorluklarında (ve genel olarak Kaggle yarışmalarında) birçok kazanan çözüm, son performans parçasını elde etmek için ensemble tekniklerini kullanmaktadır.

<details>
<summary>Örnek -- Phishing Tespiti için Oylama Ensemble:</summary>
Model stacking'i göstermek için, phishing veri setinde tartıştığımız birkaç modeli birleştirelim. Temel öğreniciler olarak bir lojistik regresyon, bir karar ağacı ve bir k-NN kullanacağız ve tahminlerini toplamak için bir Random Forest'ı meta-öğrenici olarak kullanacağız. Meta-öğrenici, temel öğrenicilerin çıktıları üzerinde (eğitim setinde çapraz doğrulama kullanarak) eğitilecektir. Stacked modelin, bireysel modeller kadar iyi veya biraz daha iyi performans göstermesini bekliyoruz.
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
Yığın topluluğu, temel modellerin tamamlayıcı güçlerinden yararlanır. Örneğin, lojistik regresyon verilerin doğrusal yönlerini ele alabilir, karar ağaçları belirli kural benzeri etkileşimleri yakalayabilir ve k-NN, özellik alanındaki yerel komşuluklarda başarılı olabilir. Meta-model (burada bir rastgele orman) bu girdileri nasıl ağırlayacağını öğrenebilir. Ortaya çıkan metrikler genellikle herhangi bir tek modelin metriklerine göre bir iyileşme (hatta az da olsa) gösterir. Phishing örneğimizde, eğer lojistik tek başına 0.95 F1 değerine ve ağaç 0.94'e sahipse, yığın her modelin hata yaptığı yerleri alarak 0.96'ya ulaşabilir.

Bu tür topluluk yöntemleri, *"birden fazla modelin birleştirilmesinin genellikle daha iyi genelleme sağladığı"*. Siber güvenlikte, bu, birden fazla tespit motoru (birinin kural tabanlı, birinin makine öğrenimi, birinin anomali tabanlı olabileceği) bulundurularak ve ardından uyarılarını toplayan bir katman eklenerek uygulanabilir -- etkili bir topluluk biçimi -- daha yüksek güvenle nihai bir karar vermek için. Bu tür sistemler dağıtılırken, ek karmaşıklığı göz önünde bulundurmak ve topluluğun yönetilmesi veya açıklanması zor hale gelmediğinden emin olmak gerekir. Ancak doğruluk açısından, topluluklar ve yığınlama model performansını artırmak için güçlü araçlardır.

</details>


## Referanslar

- [https://madhuramiah.medium.com/logistic-regression-6e55553cc003](https://madhuramiah.medium.com/logistic-regression-6e55553cc003)
- [https://www.geeksforgeeks.org/decision-tree-introduction-example/](https://www.geeksforgeeks.org/decision-tree-introduction-example/)
- [https://rjwave.org/ijedr/viewpaperforall.php?paper=IJEDR1703132](https://rjwave.org/ijedr/viewpaperforall.php?paper=IJEDR1703132)
- [https://www.ibm.com/think/topics/support-vector-machine](https://www.ibm.com/think/topics/support-vector-machine)
- [https://en.m.wikipedia.org/wiki/Naive_Bayes_spam_filtering](https://en.m.wikipedia.org/wiki/Naive_Bayes_spam_filtering)
- [https://medium.com/@rupalipatelkvc/gbdt-demystified-how-lightgbm-xgboost-and-catboost-work-9479b7262644](https://medium.com/@rupalipatelkvc/gbdt-demystified-how-lightgbm-xgboost-and-catboost-work-9479b7262644)
- [https://zvelo.com/ai-and-machine-learning-in-cybersecurity/](https://zvelo.com/ai-and-machine-learning-in-cybersecurity/)
- [https://medium.com/@chaandram/linear-regression-explained-28d5bf1934ae](https://medium.com/@chaandram/linear-regression-explained-28d5bf1934ae)
- [https://cybersecurity.springeropen.com/articles/10.1186/s42400-021-00103-8](https://cybersecurity.springeropen.com/articles/10.1186/s42400-021-00103-8)
- [https://www.ibm.com/think/topics/knn](https://www.ibm.com/think/topics/knn)
- [https://www.ibm.com/think/topics/knn](https://www.ibm.com/think/topics/knn)
- [https://arxiv.org/pdf/2101.02552](https://arxiv.org/pdf/2101.02552)
- [https://cybersecurity-magazine.com/how-deep-learning-enhances-intrusion-detection-systems/](https://cybersecurity-magazine.com/how-deep-learning-enhances-intrusion-detection-systems/)
- [https://cybersecurity-magazine.com/how-deep-learning-enhances-intrusion-detection-systems/](https://cybersecurity-magazine.com/how-deep-learning-enhances-intrusion-detection-systems/)
- [https://medium.com/@sarahzouinina/ensemble-learning-boosting-model-performance-by-combining-strengths-02e56165b901](https://medium.com/@sarahzouinina/ensemble-learning-boosting-model-performance-by-combining-strengths-02e56165b901)
- [https://medium.com/@sarahzouinina/ensemble-learning-boosting-model-performance-by-combining-strengths-02e56165b901](https://medium.com/@sarahzouinina/ensemble-learning-boosting-model-performance-by-combining-strengths-02e56165b901)

{{#include ../banners/hacktricks-training.md}}
