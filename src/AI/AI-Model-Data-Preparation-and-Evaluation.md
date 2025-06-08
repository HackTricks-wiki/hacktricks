# Model Data Preparation & Evaluation

{{#include ../banners/hacktricks-training.md}}

Model veri hazırlığı, makine öğrenimi sürecinde kritik bir adımdır, çünkü ham verileri makine öğrenimi modellerinin eğitimi için uygun bir formata dönüştürmeyi içerir. Bu süreç birkaç ana adımı içerir:

1. **Veri Toplama**: Verileri çeşitli kaynaklardan toplamak, örneğin veritabanları, API'ler veya dosyalar. Veriler yapılandırılmış (örneğin, tablolar) veya yapılandırılmamış (örneğin, metin, resimler) olabilir.
2. **Veri Temizleme**: Hatalı, eksik veya alakasız veri noktalarını kaldırmak veya düzeltmek. Bu adım, eksik değerlerle başa çıkmayı, yinelenenleri kaldırmayı ve aykırı değerleri filtrelemeyi içerebilir.
3. **Veri Dönüştürme**: Verileri modelleme için uygun bir formata dönüştürmek. Bu, normalleştirme, ölçeklendirme, kategorik değişkenleri kodlama ve özellik mühendisliği gibi tekniklerle yeni özellikler oluşturmayı içerebilir.
4. **Veri Bölme**: Veri setini eğitim, doğrulama ve test setlerine ayırmak, böylece modelin görülmemiş verilere iyi genelleme yapabilmesini sağlamak.

## Veri Toplama

Veri toplama, verileri çeşitli kaynaklardan toplama sürecini içerir, bunlar arasında:
- **Veritabanları**: İlişkisel veritabanlarından (örneğin, SQL veritabanları) veya NoSQL veritabanlarından (örneğin, MongoDB) veri çıkarmak.
- **API'ler**: Web API'lerinden veri almak, bu API'ler gerçek zamanlı veya tarihsel veri sağlayabilir.
- **Dosyalar**: CSV, JSON veya XML gibi formatlarda dosyalardan veri okumak.
- **Web Kazıma**: Web kazıma teknikleri kullanarak web sitelerinden veri toplamak.

Makine öğrenimi projesinin amacına bağlı olarak, veriler ilgili kaynaklardan çıkarılacak ve toplanacaktır, böylece problem alanını temsil etmesi sağlanacaktır.

## Veri Temizleme

Veri temizleme, veri setindeki hataları veya tutarsızlıkları tanımlama ve düzeltme sürecidir. Bu adım, makine öğrenimi modellerinin eğitimi için kullanılan verilerin kalitesini sağlamak için gereklidir. Veri temizlemedeki ana görevler şunlardır:
- **Eksik Değerlerle Baş Etme**: Eksik veri noktalarını tanımlama ve ele alma. Yaygın stratejiler şunlardır:
- Eksik değerleri olan satır veya sütunları kaldırmak.
- Eksik değerleri ortalama, medyan veya mod imputasyonu gibi tekniklerle doldurmak.
- K-en yakın komşular (KNN) imputasyonu veya regresyon imputasyonu gibi ileri yöntemler kullanmak.
- **Yinelenenleri Kaldırma**: Her veri noktasının benzersiz olmasını sağlamak için yinelenen kayıtları tanımlama ve kaldırma.
- **Aykırı Değerleri Filtreleme**: Modelin performansını etkileyebilecek aykırı değerleri tespit etme ve kaldırma. Aykırı değerleri tanımlamak için Z-skoru, IQR (Çeyrekler Arası Aralık) veya görselleştirmeler (örneğin, kutu grafikleri) gibi teknikler kullanılabilir.

### Veri temizleme örneği
```python
import pandas as pd
# Load the dataset
data = pd.read_csv('data.csv')

# Finding invalid values based on a specific function
def is_valid_possitive_int(num):
try:
num = int(num)
return 1 <= num <= 31
except ValueError:
return False

invalid_days = data[~data['days'].astype(str).apply(is_valid_positive_int)]

## Dropping rows with invalid days
data = data.drop(invalid_days.index, errors='ignore')



# Set "NaN" values to a specific value
## For example, setting NaN values in the 'days' column to 0
data['days'] = pd.to_numeric(data['days'], errors='coerce')

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
data.fillna(data.mean(), inplace=True)

# Removing duplicates
data.drop_duplicates(inplace=True)
# Filtering outliers using Z-score
from scipy import stats
z_scores = stats.zscore(data.select_dtypes(include=['float64', 'int64']))
data = data[(z_scores < 3).all(axis=1)]
```
## Veri Dönüşümü

Veri dönüşümü, verileri modelleme için uygun bir formata dönüştürmeyi içerir. Bu adım şunları içerebilir:
- **Normalizasyon ve Standartlaştırma**: Sayısal özellikleri genellikle [0, 1] veya [-1, 1] gibi ortak bir aralığa ölçeklendirme. Bu, optimizasyon algoritmalarının yakınsamasını iyileştirmeye yardımcı olur.
- **Min-Max Ölçekleme**: Özellikleri genellikle [0, 1] gibi sabit bir aralığa yeniden ölçeklendirme. Bu, şu formül kullanılarak yapılır: `X' = (X - X_{min}) / (X_{max} - X_{min})`
- **Z-Skoru Normalizasyonu**: Özellikleri ortalamadan çıkararak ve standart sapmaya bölerek standartlaştırma, sonuçta ortalaması 0 ve standart sapması 1 olan bir dağılım elde edilir. Bu, şu formül kullanılarak yapılır: `X' = (X - μ) / σ`, burada μ ortalama ve σ standart sapmadır.
- **Çarpıklık ve Kütle**: Özelliklerin dağılımını çarpıklığı (asimetrik) ve kütleyi (zirvelilik) azaltacak şekilde ayarlama. Bu, logaritmik, karekök veya Box-Cox dönüşümleri gibi dönüşümler kullanılarak yapılabilir. Örneğin, bir özelliğin çarpık bir dağılımı varsa, logaritmik dönüşüm uygulamak normalleştirmeye yardımcı olabilir.
- **Dize Normalizasyonu**: Dizeleri tutarlı bir formata dönüştürme, örneğin:
  - Küçük harfe çevirme
  - Özel karakterleri kaldırma (ilgili olanları koruyarak)
  - Durdurma kelimelerini kaldırma (anlama katkıda bulunmayan yaygın kelimeler, örneğin "the", "is", "and")
  - Çok sık ve çok nadir kelimeleri kaldırma (örneğin, belgelerin %90'ından fazlasında görünen veya korpus içinde 5'ten az görünen kelimeler)
  - Boşlukları kesme
  - Kökleme/Lemmatizasyon: Kelimeleri temel veya kök formuna indirme (örneğin, "running" kelimesini "run" olarak).

- **Kategorik Değişkenlerin Kodlanması**: Kategorik değişkenleri sayısal temsillere dönüştürme. Yaygın teknikler şunlardır:
  - **One-Hot Kodlama**: Her kategori için ikili sütunlar oluşturma.
  - Örneğin, bir özelliğin "kırmızı", "yeşil" ve "mavi" kategorileri varsa, bu üç ikili sütuna dönüştürülecektir: `is_red`(100), `is_green`(010) ve `is_blue`(001).
  - **Etiket Kodlama**: Her kategoriye benzersiz bir tamsayı atama.
  - Örneğin, "kırmızı" = 0, "yeşil" = 1, "mavi" = 2.
  - **Sıralı Kodlama**: Kategorilerin sırasına göre tamsayılar atama.
  - Örneğin, kategoriler "düşük", "orta" ve "yüksek" ise, sırasıyla 0, 1 ve 2 olarak kodlanabilirler.
  - **Hashing Kodlama**: Kategorileri sabit boyutlu vektörlere dönüştürmek için bir hash fonksiyonu kullanma, bu yüksek kardinaliteli kategorik değişkenler için yararlı olabilir.
  - Örneğin, bir özelliğin birçok benzersiz kategorisi varsa, hashing boyutları azaltabilirken kategoriler hakkında bazı bilgileri koruyabilir.
  - **Kelime Torbası (BoW)**: Metin verilerini kelime sayıları veya frekansları matris olarak temsil etme, burada her satır bir belgeyi ve her sütun korpus içindeki benzersiz bir kelimeyi temsil eder.
  - Örneğin, korpus "kedi", "köpek" ve "balık" kelimelerini içeriyorsa, "kedi" ve "köpek" içeren bir belge [1, 1, 0] olarak temsil edilecektir. Bu özel temsil "unigram" olarak adlandırılır ve kelimelerin sırasını yakalamaz, bu nedenle anlamsal bilgiyi kaybeder.
  - **Bigram/Trigram**: BoW'yi kelime dizilerini (bigramlar veya trigramlar) yakalamak için genişletme, böylece bazı bağlamları koruma. Örneğin, "kedi ve köpek" bir bigram olarak [1, 1] olarak temsil edilecektir. Bu durumda daha fazla anlamsal bilgi toplanır (temsilin boyutunu artırır) ancak yalnızca 2 veya 3 kelime için.
  - **TF-IDF (Terim Frekansı-Ters Belge Frekansı)**: Bir kelimenin bir belgede, belgeler (korpus) koleksiyonu ile olan önemini değerlendiren istatistiksel bir ölçü. Terim frekansını (bir kelimenin bir belgede ne sıklıkla göründüğünü) ve ters belge frekansını (bir kelimenin tüm belgelerde ne kadar nadir olduğunu) birleştirir.
  - Örneğin, "kedi" kelimesi bir belgede sıkça görünüyorsa ancak tüm korpus içinde nadir ise, yüksek bir TF-IDF puanına sahip olacaktır, bu da o belgede önemini gösterir.

- **Özellik Mühendisliği**: Mevcut özelliklerden yeni özellikler oluşturma, modelin tahmin gücünü artırmak için. Bu, özellikleri birleştirmeyi, tarih/saat bileşenlerini çıkarmayı veya alan spesifik dönüşümler uygulamayı içerebilir.

## Veri Bölme

Veri bölme, veri kümesini eğitim, doğrulama ve test için ayrı alt kümelere ayırmayı içerir. Bu, modelin görünmeyen veriler üzerindeki performansını değerlendirmek ve aşırı uyumdan kaçınmak için gereklidir. Yaygın stratejiler şunlardır:
- **Eğitim-Test Bölmesi**: Veri kümesini bir eğitim setine (genellikle verilerin %60-80'i), hiperparametreleri ayarlamak için bir doğrulama setine (%10-15) ve bir test setine (%10-15) ayırma. Model, eğitim setinde eğitilir ve test setinde değerlendirilir.
- Örneğin, 1000 örnekten oluşan bir veri kümeniz varsa, 700 örneği eğitim için, 150'yi doğrulama için ve 150'yi test için kullanabilirsiniz.
- **Tabakalı Örnekleme**: Eğitim ve test setlerindeki sınıfların dağılımının genel veri kümesine benzer olmasını sağlama. Bu, bazı sınıfların diğerlerinden önemli ölçüde daha az örneğe sahip olabileceği dengesiz veri kümeleri için özellikle önemlidir.
- **Zaman Serisi Bölmesi**: Zaman serisi verileri için, veri kümesi zaman temelinde bölünür, böylece eğitim seti daha önceki zaman dilimlerinden veriler içerirken test seti daha sonraki dönemlerden veriler içerir. Bu, modelin gelecekteki veriler üzerindeki performansını değerlendirmeye yardımcı olur.
- **K-Katlı Çapraz Doğrulama**: Veri kümesini K alt kümeye (katlar) ayırma ve modeli K kez eğitme, her seferinde farklı bir katı test seti olarak ve kalan katları eğitim seti olarak kullanma. Bu, modelin farklı veri alt kümeleri üzerinde değerlendirilmesini sağlar ve performansının daha sağlam bir tahminini sunar.

## Model Değerlendirmesi

Model değerlendirmesi, bir makine öğrenimi modelinin görünmeyen veriler üzerindeki performansını değerlendirme sürecidir. Modelin yeni verilere ne kadar iyi genelleştiğini nicel olarak ölçmek için çeşitli metrikler kullanmayı içerir. Yaygın değerlendirme metrikleri şunlardır:

### Doğruluk

Doğruluk, toplam örnekler içindeki doğru tahmin edilen örneklerin oranıdır. Şu şekilde hesaplanır:
```plaintext
Accuracy = (Number of Correct Predictions) / (Total Number of Predictions)
```
> [!TIP]
> Doğruluk, basit ve sezgisel bir metriktir, ancak bir sınıfın diğerlerini domine ettiği dengesiz veri setleri için uygun olmayabilir, çünkü model performansı hakkında yanıltıcı bir izlenim verebilir. Örneğin, verilerin %90'ı A sınıfına aitse ve model tüm örnekleri A sınıfı olarak tahmin ederse, %90 doğruluk elde eder, ancak B sınıfını tahmin etmekte faydalı olmayacaktır.

### Precision

Precision, model tarafından yapılan tüm pozitif tahminler içindeki gerçek pozitif tahminlerin oranıdır. Aşağıdaki gibi hesaplanır:
```plaintext
Precision = (True Positives) / (True Positives + False Positives)
```
> [!TIP]
> Kesinlik, yanlış pozitiflerin maliyetli veya istenmeyen olduğu senaryolarda özellikle önemlidir, örneğin tıbbi tanılar veya dolandırıcılık tespiti gibi. Örneğin, bir model 100 durumu pozitif olarak tahmin ederse, ancak bunlardan yalnızca 80'i gerçekten pozitifse, kesinlik 0.8 (yüzde 80) olacaktır.

### Recall (Duyarlılık)

Recall, duyarlılık veya gerçek pozitif oranı olarak da bilinir, tüm gerçek pozitif durumlar içindeki gerçek pozitif tahminlerin oranıdır. Aşağıdaki gibi hesaplanır:
```plaintext
Recall = (True Positives) / (True Positives + False Negatives)
```
> [!TIP]
> Hatırlama, yanlış negatiflerin maliyetli veya istenmeyen olduğu senaryolarda kritik öneme sahiptir, örneğin hastalık tespiti veya spam filtrelemede. Örneğin, bir model 100 gerçek pozitif örnekten 80'ini tanımlıyorsa, hatırlama 0.8 (yüzde 80) olacaktır.

### F1 Skoru

F1 skoru, hassasiyet ve hatırlamanın harmonik ortalamasıdır ve iki metrik arasında bir denge sağlar. Aşağıdaki gibi hesaplanır:
```plaintext
F1 Score = 2 * (Precision * Recall) / (Precision + Recall)
```
> [!TIP]
> F1 skoru, dengesiz veri setleriyle çalışırken özellikle yararlıdır, çünkü hem yanlış pozitifleri hem de yanlış negatifleri dikkate alır. Kesinlik ve hatırlama arasındaki dengeyi yakalayan tek bir metrik sağlar. Örneğin, bir modelin kesinliği 0.8 ve hatırlaması 0.6 ise, F1 skoru yaklaşık 0.69 olacaktır.

### ROC-AUC (Alıcı İşletim Karakteristiği - Eğri Altındaki Alan)

ROC-AUC metriği, modelin sınıfları ayırt etme yeteneğini, doğru pozitif oranını (duyarlılık) çeşitli eşik ayarlarında yanlış pozitif oranı ile grafik üzerinde göstererek değerlendirir. ROC eğrisi altındaki alan (AUC), modelin performansını nicelendirir; 1 değeri mükemmel sınıflandırmayı, 0.5 değeri ise rastgele tahmini gösterir.

> [!TIP]
> ROC-AUC, ikili sınıflandırma problemleri için özellikle yararlıdır ve modelin farklı eşikler üzerindeki performansına kapsamlı bir bakış sağlar. Doğruluğa kıyasla sınıf dengesizliğine daha az duyarlıdır. Örneğin, AUC'si 0.9 olan bir model, pozitif ve negatif örnekleri ayırt etme yeteneğinin yüksek olduğunu gösterir.

### Özgüllük

Özgüllük, doğru negatif oranı olarak da bilinir, tüm gerçek negatif örnekler içindeki doğru negatif tahminlerin oranıdır. Aşağıdaki gibi hesaplanır:
```plaintext
Specificity = (True Negatives) / (True Negatives + False Positives)
```
> [!TIP]
> Spesifiklik, yanlış pozitiflerin maliyetli veya istenmeyen olduğu senaryolarda önemlidir, örneğin tıbbi testler veya dolandırıcılık tespiti gibi. Modelin negatif örnekleri ne kadar iyi tanımladığını değerlendirmeye yardımcı olur. Örneğin, bir model 100 gerçek negatif örnekten 90'ını doğru bir şekilde tanımlıyorsa, spesifiklik 0.9 (yüzde 90) olacaktır.

### Matthews Korelasyon Katsayısı (MCC)
Matthews Korelasyon Katsayısı (MCC), ikili sınıflandırmaların kalitesinin bir ölçüsüdür. Doğru ve yanlış pozitifler ile negatifleri dikkate alarak, modelin performansına dengeli bir bakış sağlar. MCC şu şekilde hesaplanır:
```plaintext
MCC = (TP * TN - FP * FN) / sqrt((TP + FP) * (TP + FN) * (TN + FP) * (TN + FN))
```
where:
- **TP**: Doğru Pozitifler
- **TN**: Doğru Negatifler
- **FP**: Yanlış Pozitifler
- **FN**: Yanlış Negatifler

> [!TIP]
> MCC, -1 ile 1 arasında değişir; burada 1 mükemmel sınıflandırmayı, 0 rastgele tahmini ve -1 tahmin ile gözlem arasında tam bir anlaşmazlığı gösterir. Dört karışıklık matris bileşenini dikkate aldığı için dengesiz veri setleri için özellikle yararlıdır.

### Ortalama Mutlak Hata (MAE)
Ortalama Mutlak Hata (MAE), tahmin edilen ve gerçek değerler arasındaki ortalama mutlak farkı ölçen bir regresyon metriğidir. Aşağıdaki gibi hesaplanır:
```plaintext
MAE = (1/n) * Σ|y_i - ŷ_i|
```
nerede:
- **n**: Örnek sayısı
- **y_i**: i. örnek için gerçek değer
- **ŷ_i**: i. örnek için tahmin edilen değer

> [!TIP]
> MAE, tahminlerdeki ortalama hatanın basit bir yorumunu sağlar, bu da anlamayı kolaylaştırır. Ortalama Kare Hata (MSE) gibi diğer metriklere kıyasla aykırı değerlere karşı daha az hassastır. Örneğin, bir modelin MAE'si 5 ise, bu, modelin tahminlerinin ortalama olarak gerçek değerlerden 5 birim saptığı anlamına gelir.

### Karışıklık Matrisi

Karışıklık matrisi, bir sınıflandırma modelinin performansını, doğru pozitif, doğru negatif, yanlış pozitif ve yanlış negatif tahminlerin sayısını göstererek özetleyen bir tablodur. Modelin her sınıfta ne kadar iyi performans gösterdiğine dair ayrıntılı bir görünüm sağlar.

|               | Tahmin Edilen Pozitif | Tahmin Edilen Negatif |
|---------------|------------------------|------------------------|
| Gerçek Pozitif| Doğru Pozitif (TP)     | Yanlış Negatif (FN)    |
| Gerçek Negatif| Yanlış Pozitif (FP)    | Doğru Negatif (TN)     |

- **Doğru Pozitif (TP)**: Model pozitif sınıfı doğru tahmin etti.
- **Doğru Negatif (TN)**: Model negatif sınıfı doğru tahmin etti.
- **Yanlış Pozitif (FP)**: Model pozitif sınıfı yanlış tahmin etti (Tip I hatası).
- **Yanlış Negatif (FN)**: Model negatif sınıfı yanlış tahmin etti (Tip II hatası).

Karışıklık matrisi, doğruluk, kesinlik, hatırlama ve F1 skoru gibi çeşitli değerlendirme metriklerini hesaplamak için kullanılabilir.

{{#include ../banners/hacktricks-training.md}}
