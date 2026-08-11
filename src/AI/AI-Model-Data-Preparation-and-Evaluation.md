# Model Verisi Hazırlama ve Değerlendirme

{{#include ../banners/hacktricks-training.md}}

Model verilerinin hazırlanması, ham verilerin machine learning modellerini eğitmeye uygun bir biçime dönüştürülmesini içerdiğinden, machine learning pipeline'ındaki kritik bir adımdır. Bu süreç birkaç temel adımı kapsar:

1. **Veri Toplama**: Veritabanları, API'ler veya dosyalar gibi çeşitli kaynaklardan veri toplama. Veriler yapılandırılmış (ör. tablolar) veya yapılandırılmamış (ör. metin, görseller) olabilir.
2. **Veri Temizleme**: Hatalı, eksik veya ilgisiz veri noktalarını kaldırma ya da düzeltme. Bu adım eksik değerlerin işlenmesini, tekrarların kaldırılmasını ve aykırı değerlerin filtrelenmesini içerebilir.
3. **Veri Dönüştürme**: Verileri modellemeye uygun bir biçime dönüştürme. Bu işlem normalizasyonu, ölçeklendirmeyi, kategorik değişkenlerin kodlanmasını ve feature engineering gibi tekniklerle yeni özellikler oluşturulmasını içerebilir.
4. **Veri Bölme**: Modelin görülmemiş verilere iyi şekilde genelleme yapabilmesini sağlamak için veri kümesini training, validation ve test kümelerine ayırma.

## Veri Toplama

Veri toplama, aşağıdakiler dahil olmak üzere çeşitli kaynaklardan veri toplamayı içerir:
- **Veritabanları**: İlişkisel veritabanlarından (ör. SQL veritabanları) veya NoSQL veritabanlarından (ör. MongoDB) veri çıkarma.
- **API'ler**: Gerçek zamanlı veya geçmiş veriler sağlayabilen web API'lerinden veri alma.
- **Dosyalar**: CSV, JSON veya XML gibi biçimlerdeki dosyalardan veri okuma.
- **Web Scraping**: Web scraping tekniklerini kullanarak web sitelerinden veri toplama.

Machine learning projesinin amacına bağlı olarak veriler, problem alanını temsil ettiğinden emin olmak için ilgili kaynaklardan çıkarılıp toplanır.

## Veri Temizleme <sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

Veri temizleme, veri kümesindeki hataların veya tutarsızlıkların belirlenip düzeltilmesi sürecidir. Bu adım, machine learning modellerini eğitmek için kullanılan verilerin kalitesini güvence altına almak açısından gereklidir. Veri temizlemedeki temel görevler şunlardır:
- **Eksik Değerlerin İşlenmesi**: Eksik veri noktalarını belirleme ve ele alma. Yaygın stratejiler şunları içerir:
- Eksik değer içeren satırları veya sütunları kaldırma.
- Mean, median veya mode imputation gibi teknikleri kullanarak eksik değerleri doldurma.
- K-nearest neighbors (KNN) imputation veya regression imputation gibi gelişmiş yöntemleri kullanma.
- **Tekrarların Kaldırılması**: Her veri noktasının benzersiz olmasını sağlamak için tekrar eden kayıtları belirleyip kaldırma.
- **Aykırı Değerlerin Filtrelenmesi**: Modelin performansını çarpıtabilecek aykırı değerleri tespit edip kaldırma. Aykırı değerleri belirlemek için Z-score, IQR (Interquartile Range) veya görselleştirmeler (ör. box plot'lar) gibi teknikler kullanılabilir.

### Veri temizleme örneği
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
## Veri Dönüşümü <sup>[[1]](#references)</sup>

Veri dönüşümü, verilerin modellemeye uygun bir formata dönüştürülmesini içerir. Bu adım şunları içerebilir:
- **Normalization ve standardization**: Sayısal özelliklerin genellikle [0, 1] veya [-1, 1] olmak üzere ortak bir aralığa ölçeklendirilmesi. Bu, optimization algoritmalarının yakınsamasını iyileştirebilir.
- **Min-Max Scaling**: Özelliklerin sabit bir aralığa, genellikle [0, 1] aralığına yeniden ölçeklendirilmesi. Bu işlem şu formül kullanılarak gerçekleştirilir: `X' = (X - X_{min}) / (X_{max} - X_{min})`
- **Z-Score Normalization**: Ortalamanın çıkarılması ve standard deviation değerine bölünmesi yoluyla özelliklerin standardize edilmesi; bunun sonucunda ortalaması 0 ve standard deviation değeri 1 olan bir dağılım elde edilir. Bu işlem şu formül kullanılarak gerçekleştirilir: `X' = (X - μ) / σ`; burada μ ortalama, σ ise standard deviation değeridir.
- **Skewness ve kurtosis**: Logaritma, karekök veya Box-Cox gibi dönüşümlerle özellik dağılımlarının ayarlanması. Örneğin, logaritmik bir dönüşüm pozitif skew değerini azaltabilir.
- **String Normalization**: String'lerin aşağıdaki gibi tutarlı bir formata dönüştürülmesi:
- Küçük harfe dönüştürme
- Özel karakterlerin kaldırılması (ilgili olanlar korunarak)
- Stop word'lerin kaldırılması ("the", "is" ve "and" gibi anlama katkıda bulunmayan yaygın kelimeler)
- Çok sık ve çok nadir kelimelerin kaldırılması (örneğin, belgelerin %90'ından fazlasında veya corpus içinde 5 kereden az görünen kelimeler)
- Boşlukların kırpılması
- Stemming/Lemmatization: Kelimelerin temel veya kök biçimlerine indirgenmesi (örneğin, "running" kelimesinin "run" biçimine dönüştürülmesi).

- **Categorical Variables Encoding**: Kategorik değişkenlerin sayısal gösterimlere dönüştürülmesi. Yaygın teknikler şunlardır:
- **One-Hot Encoding**: Her kategori için binary sütunlar oluşturulması.
- Örneğin, bir özellik "red", "green" ve "blue" kategorilerine sahipse üç binary sütuna dönüştürülür: `is_red`(100), `is_green`(010) ve `is_blue`(001).
- **Label Encoding**: Her kategoriye benzersiz bir integer atanması.
- Örneğin, "red" = 0, "green" = 1, "blue" = 2.
- **Ordinal Encoding**: Kategorilerin sırasına göre integer değerler atanması.
- Örneğin, kategoriler "low", "medium" ve "high" ise bunlar sırasıyla 0, 1 ve 2 olarak encode edilebilir.
- **Hashing Encoding**: Kategorileri sabit boyutlu vektörlere dönüştürmek için bir hash function kullanılması; bu, yüksek cardinality değerine sahip kategorik değişkenler için yararlı olabilir.
- Örneğin, bir özellik çok sayıda benzersiz kategoriye sahipse hashing, kategoriler hakkındaki bazı bilgileri korurken boyutluluğu azaltabilir.
- **Bag of Words (BoW)**: Metin verilerinin, her satırın bir belgeye ve her sütunun corpus içindeki benzersiz bir kelimeye karşılık geldiği, kelime sayılarını veya frekanslarını içeren bir matrix olarak gösterilmesi.
- Örneğin, corpus "cat", "dog" ve "fish" kelimelerini içeriyorsa, "cat" ve "dog" içeren bir belge [1, 1, 0] olarak gösterilir. Bu özel gösterime "unigram" adı verilir ve kelimelerin sırasını yakalamadığı için semantic bilgiyi kaybeder.
- **Bigram/Trigram**: Bağlamın bir kısmını korumak için kelime dizilerini (bigram veya trigram) yakalayacak şekilde BoW'un genişletilmesi. Örneğin, "cat and dog", "cat and" için [1, 1] ve "and dog" için [1, 1] biçiminde bir bigram olarak gösterilir. Bu durumda daha fazla semantic bilgi elde edilir (gösterimin boyutluluğu artar), ancak bu yalnızca aynı anda 2 veya 3 kelime için geçerlidir.
- **TF-IDF (Term Frequency-Inverse Document Frequency)**: Bir kelimenin bir belgedeki önemini belge koleksiyonuna (corpus) göre değerlendiren istatistiksel ölçü. Term frequency (bir kelimenin bir belgede ne sıklıkta göründüğü) ile inverse document frequency (bir kelimenin tüm belgeler arasındaki nadirliği) değerlerini birleştirir.
- Örneğin, "cat" kelimesi bir belgede sıkça görülüyor ancak corpus genelinde nadirse, yüksek bir TF-IDF score değerine sahip olur ve bu da ilgili belgedeki önemini gösterir.

- **Feature Engineering**: Modelin predictive power değerini artırmak için mevcut özelliklerden yeni özellikler oluşturulması. Bu işlem özelliklerin birleştirilmesini, tarih/saat bileşenlerinin çıkarılmasını veya domain-specific dönüşümlerin uygulanmasını içerebilir.

## Veri Bölme <sup>[[3]](#references)</sup>

Veri bölme, dataset'in training, validation ve testing için ayrı alt kümelere ayrılmasını içerir. Bu işlem, modelin görülmemiş verilerdeki performansını değerlendirmek ve overfitting'i önlemek için gereklidir. Yaygın stratejiler şunlardır:
- **Train-Test Split**: Dataset'in bir training set'e (genellikle verilerin %60-80'i), hyperparameter'ları ayarlamak için bir validation set'e (verilerin %10-15'i) ve bir test set'e (verilerin %10-15'i) bölünmesi. Model training set üzerinde eğitilir ve test set üzerinde değerlendirilir.
- Örneğin, 1000 sample içeren bir dataset'iniz varsa training için 700, validation için 150 ve testing için 150 sample kullanabilirsiniz.
- **Stratified Sampling**: Training ve test set'lerindeki class dağılımının genel dataset'e benzer olmasının sağlanması. Bu, bazı class'ların diğerlerine göre önemli ölçüde daha az sample'a sahip olabileceği imbalanced dataset'ler için özellikle önemlidir.
- **Time Series Split**: Time series verileri için dataset'in zamana göre bölünmesi; training set'in daha erken zaman aralıklarına ait verileri, test set'in ise daha sonraki zaman aralıklarına ait verileri içermesinin sağlanması. Bu, modelin gelecekteki verilerdeki performansının değerlendirilmesine yardımcı olur.
- **K-Fold Cross-Validation**: Dataset'in K alt kümeye (fold) bölünmesi ve modelin K kez eğitilmesi; her seferinde farklı bir fold test set olarak, kalan fold'lar ise training set olarak kullanılır. Bu, modelin farklı veri alt kümelerinde değerlendirilmesini sağlayarak performansına ilişkin daha güvenilir bir tahmin elde edilmesine yardımcı olur.

## Model Değerlendirmesi <sup>[[4]](#references)</sup>

Model değerlendirmesi, bir machine learning modelinin görülmemiş verilerdeki performansını ölçme sürecidir. Modelin yeni verilere ne kadar iyi genelleştiğini nicel olarak ifade etmek için çeşitli metriklerin kullanılmasını içerir. Yaygın değerlendirme metrikleri şunlardır:

### Accuracy

Accuracy, doğru tahmin edilen örneklerin toplam örnek sayısına oranıdır. Şu şekilde hesaplanır:
```plaintext
Accuracy = (Number of Correct Predictions) / (Total Number of Predictions)
```
> [!TIP]
> Doğruluk basit ve sezgisel bir metriktir, ancak bir sınıfın diğerlerine baskın olduğu dengesiz veri kümeleri için uygun olmayabilir; çünkü model performansı hakkında yanıltıcı bir izlenim verebilir. Örneğin, verilerin %90'ı A sınıfına aitse ve model tüm örnekleri A sınıfı olarak tahmin ederse %90 doğruluk elde eder, ancak B sınıfını tahmin etmede kullanışlı olmaz.

### Precision

Precision, model tarafından yapılan tüm pozitif tahminler arasındaki doğru pozitif tahminlerin oranıdır. Şu şekilde hesaplanır:
```plaintext
Precision = (True Positives) / (True Positives + False Positives)
```
> [!TIP]
> Yanlış pozitiflerin maliyetli veya istenmeyen olduğu tıbbi teşhis ya da fraud detection gibi senaryolarda precision özellikle önemlidir. Örneğin bir model 100 örneği pozitif olarak tahmin ediyor, ancak bunların yalnızca 80'i gerçekten pozitifse precision 0,8 (80%) olur.

### Recall (Sensitivity)

Sensitivity veya true positive rate olarak da bilinen recall, tüm gerçek pozitif örnekler içindeki doğru pozitif tahminlerin oranıdır. Şu şekilde hesaplanır:
```plaintext
Recall = (True Positives) / (True Positives + False Negatives)
```
> [!TIP]
> Recall, hastalık tespiti veya spam filtering gibi yanlış negatiflerin maliyetli ya da istenmeyen olduğu senaryolarda kritik öneme sahiptir. Örneğin bir model, gerçek pozitif 100 örneğin 80'ini tespit ederse recall değeri 0,8 (%80) olur.

### F1 Score

F1 score, precision ve recall değerlerinin harmonik ortalamasıdır ve bu iki metrik arasında denge sağlar. Şu şekilde hesaplanır:
```plaintext
F1 Score = 2 * (Precision * Recall) / (Precision + Recall)
```
> [!TIP]
> F1 skoru, hem false positive hem de false negative değerlerini dikkate aldığı için özellikle dengesiz veri kümeleriyle çalışırken kullanışlıdır. Precision ve recall arasındaki dengeyi yakalayan tek bir metrik sağlar. Örneğin, bir modelin precision değeri 0.8 ve recall değeri 0.6 ise F1 skoru yaklaşık 0.69 olur.

### ROC-AUC (Receiver Operating Characteristic - Area Under the Curve)

ROC-AUC metriği, çeşitli threshold ayarlarında true positive rate (sensitivity) değerini false positive rate karşısında çizerek modelin sınıflar arasındaki ayrımı yapabilme yeteneğini değerlendirir. ROC eğrisinin altındaki alan (AUC), modelin performansını nicelendirir; 1 değeri kusursuz sınıflandırmayı, 0.5 değeri ise rastgele tahmini gösterir.

> [!TIP]
> ROC-AUC, özellikle binary classification problemleri için kullanışlıdır ve modelin farklı threshold değerlerindeki performansına kapsamlı bir bakış sağlar. Class imbalance durumundan accuracy metriğine kıyasla daha az etkilenir. Örneğin, AUC değeri 0.9 olan bir model, pozitif ve negatif örnekleri ayırt etme konusunda yüksek bir yeteneğe sahip olduğunu gösterir.

### Specificity

Specificity, true negative rate olarak da bilinir ve tüm gerçek negatif örnekler arasındaki true negative tahminlerin oranıdır. Şu şekilde hesaplanır:
```plaintext
Specificity = (True Negatives) / (True Negatives + False Positives)
```
> [!TIP]
> Yanlış pozitiflerin maliyetli veya istenmeyen olduğu tıbbi testler ya da fraud detection gibi senaryolarda özgüllük önemlidir. Modelin negatif örnekleri ne kadar iyi tanımladığını değerlendirmeye yardımcı olur. Örneğin bir model, gerçek 100 negatif örnekten 90'ını doğru şekilde tanımlıyorsa özgüllük 0,9 (%90) olur.

### Matthews Correlation Coefficient (MCC)
Matthews Correlation Coefficient (MCC), binary classifications kalitesinin bir ölçüsüdür. True ve false positive ile negative değerlerini dikkate alarak modelin performansına dengeli bir bakış sunar. MCC şu şekilde hesaplanır:
```plaintext
MCC = (TP * TN - FP * FN) / sqrt((TP + FP) * (TP + FN) * (TN + FP) * (TN + FN))
```
burada:
- **TP**: Doğru Pozitifler
- **TN**: Doğru Negatifler
- **FP**: Yanlış Pozitifler
- **FN**: Yanlış Negatifler

> [!TIP]
> MCC, -1 ile 1 arasında değişir; 1 mükemmel sınıflandırmayı, 0 rastgele tahmini ve -1 tahmin ile gözlem arasında tamamen uyuşmazlık olduğunu gösterir. Dengesiz veri kümeleri için özellikle kullanışlıdır; çünkü karmaşıklık matrisinin dört bileşenini de dikkate alır.

### Ortalama Mutlak Hata (MAE)
Ortalama Mutlak Hata (MAE), tahmin edilen ve gerçek değerler arasındaki mutlak farkın ortalamasını ölçen bir regresyon metriğidir. Şu şekilde hesaplanır:
```plaintext
MAE = (1/n) * Σ|y_i - ŷ_i|
```
burada:
- **n**: Örnek sayısı
- **y_i**: i örneği için gerçek değer
- **ŷ_i**: i örneği için tahmin edilen değer

> [!TIP]
> MAE, tahminlerdeki ortalama hatanın kolay anlaşılır bir yorumunu sunar. Mean Squared Error (MSE) gibi diğer metriklere kıyasla outlier değerlerden daha az etkilenir. Örneğin, bir modelin MAE değeri 5 ise bu, modelin tahminlerinin gerçek değerlerden ortalama 5 birim saptığı anlamına gelir.

### Confusion Matrix

Confusion matrix, doğru pozitif, doğru negatif, yanlış pozitif ve yanlış negatif tahminlerin sayılarını göstererek bir classification modelinin performansını özetleyen bir tablodur. Modelin her class üzerinde ne kadar iyi performans gösterdiğine dair ayrıntılı bir görünüm sağlar.

|               | Tahmin Pozitif | Tahmin Negatif |
|---------------|---------------------|---------------------|
| Gerçek Pozitif| Doğru Pozitif (TP)  | Yanlış Negatif (FN)  |
| Gerçek Negatif| Yanlış Pozitif (FP) | Doğru Negatif (TN)   |

- **True Positive (TP)**: Model, pozitif class'ı doğru şekilde tahmin etti.
- **True Negative (TN)**: Model, negatif class'ı doğru şekilde tahmin etti.
- **False Positive (FP)**: Model, pozitif class'ı yanlış şekilde tahmin etti (Type I error).
- **False Negative (FN)**: Model, negatif class'ı yanlış şekilde tahmin etti (Type II error).

Confusion matrix; accuracy, precision, recall ve F1 score gibi evaluation metriklerini hesaplamak için kullanılabilir.

## References

- [1] [scikit-learn - Verilerin preprocessing işlemi](https://scikit-learn.org/stable/modules/preprocessing.html)
- [2] [scikit-learn - Eksik değerlerin imputation işlemi](https://scikit-learn.org/stable/modules/impute.html)
- [3] [scikit-learn - Cross-validation: estimator performansının değerlendirilmesi](https://scikit-learn.org/stable/modules/cross_validation.html)
- [4] [scikit-learn - Metrikler ve scoring](https://scikit-learn.org/stable/modules/model_evaluation.html)
{{#include ../banners/hacktricks-training.md}}
