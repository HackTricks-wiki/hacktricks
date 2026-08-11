# Maandalizi na Tathmini ya Data ya Modeli

{{#include ../banners/hacktricks-training.md}}

Maandalizi ya data ya modeli ni hatua muhimu katika mchakato wa machine learning, kwa kuwa inahusisha kubadilisha data ghafi kuwa muundo unaofaa kwa kufundisha machine learning models. Mchakato huu unajumuisha hatua kadhaa muhimu:

1. **Ukusanyaji wa Data**: Kukusanya data kutoka vyanzo mbalimbali, kama vile databases, APIs, au files. Data inaweza kuwa structured (kwa mfano, tables) au unstructured (kwa mfano, text, images).
2. **Usafishaji wa Data**: Kuondoa au kurekebisha data yenye makosa, isiyokamilika, au isiyohusika. Hatua hii inaweza kujumuisha kushughulikia missing values, kuondoa duplicates, na kuchuja outliers.
3. **Ubadilishaji wa Data**: Kubadilisha data kuwa muundo unaofaa kwa modeling. Hii inaweza kujumuisha normalization, scaling, encoding categorical variables, na kuunda features mpya kupitia techniques kama feature engineering.
4. **Ugawaji wa Data**: Kugawa dataset kuwa training, validation, na test sets ili kuhakikisha model inaweza kufanya generalization vizuri kwenye data ambayo haijawahi kuonekana.

## Ukusanyaji wa Data

Ukusanyaji wa data unahusisha kukusanya data kutoka vyanzo mbalimbali, ambavyo vinaweza kujumuisha:
- **Databases**: Kutoa data kutoka relational databases (kwa mfano, SQL databases) au NoSQL databases (kwa mfano, MongoDB).
- **APIs**: Kupata data kutoka web APIs, ambazo zinaweza kutoa data ya wakati halisi au ya kihistoria.
- **Files**: Kusoma data kutoka files zenye formats kama CSV, JSON, au XML.
- **Web Scraping**: Kukusanya data kutoka websites kwa kutumia web scraping techniques.

Kulingana na lengo la machine learning project, data itatolewa na kukusanywa kutoka vyanzo vinavyohusika ili kuhakikisha inawakilisha problem domain.

## Usafishaji wa Data <sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

Usafishaji wa data ni mchakato wa kutambua na kurekebisha makosa au kutokulingana ndani ya dataset. Hatua hii ni muhimu ili kuhakikisha ubora wa data inayotumika kufundisha machine learning models. Kazi muhimu katika usafishaji wa data ni pamoja na:
- **Kushughulikia Missing Values**: Kutambua na kushughulikia data points zilizokosekana. Mikakati ya kawaida ni pamoja na:
- Kuondoa rows au columns zenye missing values.
- Kujaza missing values kwa kutumia techniques kama mean, median, au mode imputation.
- Kutumia methods za hali ya juu kama K-nearest neighbors (KNN) imputation au regression imputation.
- **Kuondoa Duplicates**: Kutambua na kuondoa records zilizorudiwa ili kuhakikisha kila data point ni ya kipekee.
- **Kuchuja Outliers**: Kugundua na kuondoa outliers ambazo zinaweza kupotosha utendaji wa model. Techniques kama Z-score, IQR (Interquartile Range), au visualizations (kwa mfano, box plots) zinaweza kutumika kutambua outliers.

### Mfano wa usafishaji wa data
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
## Data Transformation <sup>[[1]](#references)</sup>

Data transformation inahusisha kubadilisha data kuwa muundo unaofaa kwa modeling. Hatua hii inaweza kujumuisha:
- **Normalization and standardization**: Kupanua vipengele vya nambari hadi kwenye range ya pamoja, kwa kawaida [0, 1] au [-1, 1]. Hii inaweza kuboresha convergence ya optimization algorithms.
- **Min-Max Scaling**: Kubadilisha vipengele kwa scale ya kudumu, kwa kawaida [0, 1]. Hii hufanywa kwa kutumia formula: `X' = (X - X_{min}) / (X_{max} - X_{min})`
- **Z-Score Normalization**: Kuweka vipengele kwenye kiwango sanifu kwa kutoa mean na kugawanya kwa standard deviation, hivyo kupata distribution yenye mean ya 0 na standard deviation ya 1. Hii hufanywa kwa kutumia formula: `X' = (X - μ) / σ`, ambapo μ ni mean na σ ni standard deviation.
- **Skewness and kurtosis**: Kurekebisha distributions za vipengele kwa transformations kama logarithm, square root, au Box-Cox. Kwa mfano, logarithmic transformation inaweza kupunguza positive skew.
- **String Normalization**: Kubadilisha strings kuwa format inayofanana, kama vile:
- Kuweka herufi zote kuwa lowercase
- Kuondoa special characters (kuhifadhi zinazohusika)
- Kuondoa stop words (maneno ya kawaida yasiyochangia maana, kama vile "the", "is", na "and")
- Kuondoa maneno yanayotokea mara nyingi sana na yanayotokea mara chache sana (kwa mfano, maneno yanayoonekana katika zaidi ya 90% ya documents au chini ya mara 5 kwenye corpus)
- Kuondoa whitespace ya ziada
- Stemming/Lemmatization: Kupunguza maneno hadi kwenye umbo lake la msingi au mzizi (kwa mfano, "running" kuwa "run").

- **Encoding Categorical Variables**: Kubadilisha categorical variables kuwa representations za nambari. Techniques za kawaida zinajumuisha:
- **One-Hot Encoding**: Kuunda binary columns kwa kila category.
- Kwa mfano, ikiwa feature ina categories "red", "green", na "blue", itabadilishwa kuwa binary columns tatu: `is_red`(100), `is_green`(010), na `is_blue`(001).
- **Label Encoding**: Kuweka integer ya kipekee kwa kila category.
- Kwa mfano, "red" = 0, "green" = 1, "blue" = 2.
- **Ordinal Encoding**: Kuweka integers kulingana na mpangilio wa categories.
- Kwa mfano, ikiwa categories ni "low", "medium", na "high", zinaweza ku-encodeiwa kama 0, 1, na 2, kwa mtiririko huo.
- **Hashing Encoding**: Kutumia hash function kubadilisha categories kuwa vectors zenye size maalum, jambo linaloweza kuwa muhimu kwa categorical variables zenye cardinality kubwa.
- Kwa mfano, ikiwa feature ina categories nyingi za kipekee, hashing inaweza kupunguza dimensionality huku ikihifadhi baadhi ya taarifa kuhusu categories.
- **Bag of Words (BoW)**: Kuwakilisha text data kama matrix ya counts au frequencies za words, ambapo kila row inawakilisha document na kila column inawakilisha word ya kipekee kwenye corpus.
- Kwa mfano, ikiwa corpus ina words "cat", "dog", na "fish", document iliyo na "cat" na "dog" ingewakilishwa kama [1, 1, 0]. Representation hii maalum huitwa "unigram" na haikamatili mpangilio wa words, hivyo hupoteza semantic information.
- **Bigram/Trigram**: Kupanua BoW ili kukamata sequences za words (bigrams au trigrams) na kuhifadhi baadhi ya context. Kwa mfano, "cat and dog" ingewakilishwa kama bigram [1, 1] kwa "cat and" na [1, 1] kwa "and dog". Katika hali hizi semantic information zaidi hukusanywa (na kuongeza dimensionality ya representation), lakini kwa words 2 au 3 pekee kwa wakati mmoja.
- **TF-IDF (Term Frequency-Inverse Document Frequency)**: Kipimo cha kitakwimu kinachotathmini umuhimu wa word katika document ikilinganishwa na mkusanyiko wa documents (corpus). Huchanganya term frequency (mara ambazo word huonekana katika document) na inverse document frequency (jinsi word ilivyo nadra katika documents zote).
- Kwa mfano, ikiwa word "cat" inaonekana mara nyingi katika document lakini ni nadra katika corpus nzima, itakuwa na TF-IDF score ya juu, ikionyesha umuhimu wake katika document hiyo.

- **Feature Engineering**: Kuunda features mpya kutoka kwa zilizopo ili kuongeza uwezo wa model wa kufanya predictions. Hii inaweza kuhusisha kuchanganya features, kutoa vipengele vya tarehe/muda, au kutumia transformations maalum za domain.

## Data Splitting <sup>[[3]](#references)</sup>

Data splitting inahusisha kugawanya dataset kuwa subsets tofauti za training, validation, na testing. Hii ni muhimu kwa kutathmini performance ya model kwenye data ambayo haijaonekana na kuzuia overfitting. Strategies za kawaida zinajumuisha:
- **Train-Test Split**: Kugawanya dataset kuwa training set (kwa kawaida 60-80% ya data), validation set (10-15% ya data) kwa ajili ya kurekebisha hyperparameters, na test set (10-15% ya data). Model hufunzwa kwa training set na kutathminiwa kwa test set.
- Kwa mfano, ikiwa una dataset yenye samples 1000, unaweza kutumia samples 700 kwa training, 150 kwa validation, na 150 kwa testing.
- **Stratified Sampling**: Kuhakikisha kuwa distribution ya classes katika training na test sets inafanana na dataset nzima. Hii ni muhimu hasa kwa imbalanced datasets, ambapo baadhi ya classes zinaweza kuwa na samples chache kwa kiasi kikubwa kuliko nyingine.
- **Time Series Split**: Kwa time series data, dataset hugawanywa kulingana na muda, huku ikihakikisha kuwa training set ina data kutoka vipindi vya awali na test set ina data kutoka vipindi vya baadaye. Hii husaidia kutathmini performance ya model kwenye data ya baadaye.
- **K-Fold Cross-Validation**: Kugawanya dataset kuwa subsets K (folds) na kufundisha model mara K, ambapo kila mara fold tofauti hutumika kama test set na folds zilizobaki hutumika kama training set. Hii husaidia kuhakikisha kuwa model inatathminiwa kwenye subsets tofauti za data, na kutoa makadirio thabiti zaidi ya performance yake.

## Model Evaluation <sup>[[4]](#references)</sup>

Model evaluation ni mchakato wa kutathmini performance ya machine learning model kwenye data ambayo haijaonekana. Unahusisha kutumia metrics mbalimbali kupima jinsi model inavyoweza ku-generalize kwenye data mpya. Metrics za kawaida za evaluation zinajumuisha:

### Accuracy

Accuracy ni uwiano wa instances zilizotabiriwa kwa usahihi dhidi ya instances zote. Hukokotolewa kama:
```plaintext
Accuracy = (Number of Correct Predictions) / (Total Number of Predictions)
```
> [!TIP]
> Usahihi ni kipimo rahisi na angavu, lakini huenda kisifae kwa datasets zisizosawazika ambapo class moja inatawala nyingine, kwa sababu kinaweza kutoa taswira potofu ya utendaji wa model. Kwa mfano, ikiwa 90% ya data ni ya class A na model inatabiri matukio yote kuwa class A, itafikia usahihi wa 90%, lakini haitakuwa na manufaa katika kutabiri class B.

### Precision

Precision ni uwiano wa utabiri chanya wa kweli kati ya utabiri wote chanya uliofanywa na model. Huhesabiwa hivi:
```plaintext
Precision = (True Positives) / (True Positives + False Positives)
```
> [!TIP]
> Precision ni muhimu hasa katika hali ambapo false positives ni za gharama kubwa au hazitakiwi, kama vile katika utambuzi wa magonjwa au detection ya fraud. Kwa mfano, ikiwa model inatabiri matukio 100 kuwa positive, lakini ni 80 tu kati yao ambayo kwa kweli ni positive, precision itakuwa 0.8 (80%).

### Recall (Sensitivity)

Recall, inayojulikana pia kama sensitivity au true positive rate, ni uwiano wa true positive predictions ikilinganishwa na matukio yote halisi yaliyo positive. Inahesabiwa kama:
```plaintext
Recall = (True Positives) / (True Positives + False Negatives)
```
> [!TIP]
> Recall ni muhimu katika hali ambapo false negatives ni ghali au hazitakiwi, kama vile katika utambuzi wa magonjwa au uchujaji wa spam. Kwa mfano, ikiwa model itatambua matukio 80 kati ya 100 halisi yenye matokeo chanya, recall itakuwa 0.8 (80%).

### F1 Score

F1 score ni harmonic mean ya precision na recall, ikitoa uwiano kati ya vipimo hivyo viwili. Hukokotolewa kama ifuatavyo:
```plaintext
F1 Score = 2 * (Precision * Recall) / (Precision + Recall)
```
> [!TIP]
> Alama ya F1 ni muhimu hasa unaposhughulikia datasets zisizosawazika, kwa kuwa inazingatia false positives na false negatives. Inatoa metric moja inayowakilisha uwiano kati ya precision na recall. Kwa mfano, ikiwa model ina precision ya 0.8 na recall ya 0.6, alama ya F1 itakuwa takribani 0.69.

### ROC-AUC (Receiver Operating Characteristic - Area Under the Curve)

Metric ya ROC-AUC hutathmini uwezo wa model kutofautisha kati ya classes kwa kuchora kiwango cha true positives (sensitivity) dhidi ya kiwango cha false positives katika mipangilio mbalimbali ya threshold. Eneo lililo chini ya curve ya ROC (AUC) hupima utendaji wa model, ambapo thamani ya 1 inaonyesha classification kamili na thamani ya 0.5 inaonyesha kubahatisha bila mpangilio.

> [!TIP]
> ROC-AUC ni muhimu hasa kwa matatizo ya binary classification na hutoa mtazamo mpana wa utendaji wa model katika thresholds tofauti. Haiathiriwi sana na kutosawazika kwa classes ikilinganishwa na accuracy. Kwa mfano, model yenye AUC ya 0.9 inaonyesha kuwa ina uwezo mkubwa wa kutofautisha instances chanya na hasi.

### Specificity

Specificity, inayojulikana pia kama true negative rate, ni uwiano wa predictions hasi za kweli kati ya instances zote hasi halisi. Huhesabiwa kama:
```plaintext
Specificity = (True Negatives) / (True Negatives + False Positives)
```
> [!TIP]
> Specificity ni muhimu katika hali ambapo false positives ni za gharama kubwa au hazitakiwi, kama vile katika upimaji wa kimatibabu au utambuzi wa ulaghai. Husaidia kutathmini jinsi model inavyotambua matukio hasi. Kwa mfano, ikiwa model inatambua kwa usahihi matukio 90 kati ya 100 halisi hasi, specificity itakuwa 0.9 (90%).

### Matthews Correlation Coefficient (MCC)
Matthews Correlation Coefficient (MCC) ni kipimo cha ubora wa binary classifications. Huzingatia true positives, false positives, true negatives na false negatives, na kutoa mtazamo uliosawazika wa utendaji wa model. MCC huhesabiwa kama:
```plaintext
MCC = (TP * TN - FP * FN) / sqrt((TP + FP) * (TP + FN) * (TN + FP) * (TN + FN))
```
ambapo:
- **TP**: Chanya za Kweli
- **TN**: Hasi za Kweli
- **FP**: Chanya za Uongo
- **FN**: Hasi za Uongo

> [!TIP]
> MCC huanzia -1 hadi 1, ambapo 1 huashiria uainishaji kamili, 0 huashiria kubahatisha kwa nasibu, na -1 huashiria kutokubaliana kabisa kati ya utabiri na uchunguzi. Ni muhimu hasa kwa datasets zisizo na uwiano, kwa kuwa huzingatia vipengele vyote vinne vya matrix ya mkanganyiko.

### Kosa la Wastani la Thamani Kamili (MAE)
Kosa la Wastani la Thamani Kamili (MAE) ni kipimo cha regression kinachopima tofauti ya wastani ya thamani kamili kati ya thamani zilizotabiriwa na thamani halisi. Hukokotolewa kama ifuatavyo:
```plaintext
MAE = (1/n) * Σ|y_i - ŷ_i|
```
ambapo:
- **n**: Idadi ya instances
- **y_i**: Thamani halisi ya instance i
- **ŷ_i**: Thamani iliyotabiriwa ya instance i

> [!TIP]
> MAE hutoa tafsiri rahisi ya kosa la wastani katika utabiri, hivyo kuifanya iwe rahisi kueleweka. Haisikii sana outliers ikilinganishwa na metrics nyingine kama Mean Squared Error (MSE). Kwa mfano, ikiwa model ina MAE ya 5, inamaanisha kuwa, kwa wastani, utabiri wa model unatofautiana na thamani halisi kwa units 5.

### Matrix ya Mkanganyiko

Matrix ya mkanganyiko ni jedwali linalofupisha utendaji wa classification model kwa kuonyesha hesabu za utabiri wa true positive, true negative, false positive, na false negative. Hutoa mtazamo wa kina wa jinsi model inavyofanya kazi kwenye kila class.

|               | Predicted Positive | Predicted Negative |
|---------------|---------------------|---------------------|
| Actual Positive| True Positive (TP)  | False Negative (FN)  |
| Actual Negative| False Positive (FP) | True Negative (TN)   |

- **True Positive (TP)**: Model ilitabiri kwa usahihi class chanya.
- **True Negative (TN)**: Model ilitabiri kwa usahihi class hasi.
- **False Positive (FP)**: Model ilitabiri kimakosa class chanya (kosa la Aina ya I).
- **False Negative (FN)**: Model ilitabiri kimakosa class hasi (kosa la Aina ya II).

Matrix ya mkanganyiko inaweza kutumika kukokotoa evaluation metrics kama vile accuracy, precision, recall, na F1 score.

## References

- [1] [scikit-learn - Kuchakata data](https://scikit-learn.org/stable/modules/preprocessing.html)
- [2] [scikit-learn - Imputation ya thamani zilizokosekana](https://scikit-learn.org/stable/modules/impute.html)
- [3] [scikit-learn - Cross-validation: kutathmini utendaji wa estimator](https://scikit-learn.org/stable/modules/cross_validation.html)
- [4] [scikit-learn - Metrics na scoring](https://scikit-learn.org/stable/modules/model_evaluation.html)
{{#include ../banners/hacktricks-training.md}}
