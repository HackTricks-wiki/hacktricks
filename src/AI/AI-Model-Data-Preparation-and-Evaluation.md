# Model Data Preparation & Evaluation

{{#include ../banners/hacktricks-training.md}}

Kuandaa data ya modeli ni hatua muhimu katika mchakato wa kujifunza mashine, kwani inahusisha kubadilisha data ghafi kuwa muundo unaofaa kwa mafunzo ya modeli za kujifunza mashine. Mchakato huu unajumuisha hatua kadhaa muhimu:

1. **Data Collection**: Kukusanya data kutoka vyanzo mbalimbali, kama vile hifadhidata, APIs, au faili. Data inaweza kuwa na muundo (mfano, meza) au isiyo na muundo (mfano, maandiko, picha).
2. **Data Cleaning**: Kuondoa au kurekebisha alama za data zisizo sahihi, zisizokamilika, au zisizohusiana. Hatua hii inaweza kujumuisha kushughulikia thamani zinazokosekana, kuondoa nakala, na kuchuja alama za nje.
3. **Data Transformation**: Kubadilisha data kuwa muundo unaofaa kwa mfano. Hii inaweza kujumuisha urekebishaji, kupima, kuandika mabadiliko ya kategoria, na kuunda vipengele vipya kupitia mbinu kama vile uhandisi wa vipengele.
4. **Data Splitting**: Kugawa dataset katika seti za mafunzo, uthibitisho, na mtihani ili kuhakikisha modeli inaweza kujumlisha vizuri kwa data isiyoonekana.

## Data Collection

Kukusanya data kunahusisha kukusanya data kutoka vyanzo mbalimbali, ambavyo vinaweza kujumuisha:
- **Databases**: Kutolewa kwa data kutoka hifadhidata za uhusiano (mfano, hifadhidata za SQL) au hifadhidata za NoSQL (mfano, MongoDB).
- **APIs**: Kupata data kutoka kwa APIs za wavuti, ambazo zinaweza kutoa data ya wakati halisi au ya kihistoria.
- **Files**: Kusoma data kutoka kwa faili katika muundo kama CSV, JSON, au XML.
- **Web Scraping**: Kukusanya data kutoka tovuti kwa kutumia mbinu za kuchambua wavuti.

Kulingana na lengo la mradi wa kujifunza mashine, data itachukuliwa na kukusanywa kutoka vyanzo husika ili kuhakikisha inawakilisha eneo la tatizo.

## Data Cleaning

Kuondoa data ni mchakato wa kubaini na kurekebisha makosa au kutokuelewana katika dataset. Hatua hii ni muhimu ili kuhakikisha ubora wa data inayotumika kwa mafunzo ya modeli za kujifunza mashine. Kazi kuu katika kuondoa data ni pamoja na:
- **Handling Missing Values**: Kubaini na kushughulikia alama za data zinazokosekana. Mikakati ya kawaida ni pamoja na:
- Kuondoa safu au nguzo zenye thamani zinazokosekana.
- Kuweka thamani zinazokosekana kwa kutumia mbinu kama vile wastani, median, au uhamasishaji wa kawaida.
- Kutumia mbinu za kisasa kama vile uhamasishaji wa K-nearest neighbors (KNN) au uhamasishaji wa regression.
- **Removing Duplicates**: Kubaini na kuondoa rekodi za nakala ili kuhakikisha kila alama ya data ni ya kipekee.
- **Filtering Outliers**: Kugundua na kuondoa alama za nje ambazo zinaweza kuathiri utendaji wa mfano. Mbinu kama Z-score, IQR (Interquartile Range), au picha (mfano, sanduku la michoro) zinaweza kutumika kubaini alama za nje.

### Example of data cleaning
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
## Data Transformation

Data transformation inahusisha kubadilisha data kuwa katika muundo unaofaa kwa ajili ya uundaji wa mifano. Hatua hii inaweza kujumuisha:
- **Normalization & Standarization**: Kupanua vipengele vya nambari hadi kiwango cha kawaida, kwa kawaida [0, 1] au [-1, 1]. Hii husaidia kuboresha mchakato wa kukaribia wa algorithimu za optimization.
- **Min-Max Scaling**: Kupanua vipengele hadi kiwango kilichowekwa, kwa kawaida [0, 1]. Hii inafanywa kwa kutumia formula: `X' = (X - X_{min}) / (X_{max} - X_{min})`
- **Z-Score Normalization**: Kuweka viwango vya vipengele kwa kupunguza wastani na kugawanya kwa kiwango cha kawaida, na kusababisha usambazaji wenye wastani wa 0 na kiwango cha kawaida cha 1. Hii inafanywa kwa kutumia formula: `X' = (X - μ) / σ`, ambapo μ ni wastani na σ ni kiwango cha kawaida.
- **Skeyewness and Kurtosis**: Kurekebisha usambazaji wa vipengele ili kupunguza skewness (asymmetry) na kurtosis (peakedness). Hii inaweza kufanywa kwa kutumia mabadiliko kama vile logarithmic, square root, au Box-Cox transformations. Kwa mfano, ikiwa kipengele kina usambazaji ulio skewed, kutumia mabadiliko ya logarithmic kunaweza kusaidia kuifanya iwe ya kawaida.
- **String Normalization**: Kubadilisha nyuzi kuwa muundo wa kawaida, kama vile:
- Lowercasing
- Kuondoa wahusika maalum (kuhifadhi wale muhimu)
- Kuondoa maneno ya kusimamisha (maneno ya kawaida ambayo hayachangii maana, kama "the", "is", "and")
- Kuondoa maneno yanayojirudia sana na maneno nadra sana (kwa mfano, maneno yanayoonekana katika zaidi ya 90% ya hati au chini ya mara 5 katika corpus)
- Kukata nafasi za wazi
- Stemming/Lemmatization: Kupunguza maneno kuwa katika mfumo wao wa msingi au mzizi (kwa mfano, "running" kuwa "run").

- **Encoding Categorical Variables**: Kubadilisha variables za kategoria kuwa uwakilishi wa nambari. Mbinu za kawaida ni pamoja na:
- **One-Hot Encoding**: Kuunda safu za binary kwa kila kategoria.
- Kwa mfano, ikiwa kipengele kina kategoria "red", "green", na "blue", kitabadilishwa kuwa safu tatu za binary: `is_red`(100), `is_green`(010), na `is_blue`(001).
- **Label Encoding**: Kuweka nambari ya kipekee kwa kila kategoria.
- Kwa mfano, "red" = 0, "green" = 1, "blue" = 2.
- **Ordinal Encoding**: Kuweka nambari kulingana na mpangilio wa kategoria.
- Kwa mfano, ikiwa kategoria ni "low", "medium", na "high", zinaweza kuwekwa kama 0, 1, na 2, mtawalia.
- **Hashing Encoding**: Kutumia kazi ya hash kubadilisha kategoria kuwa vectors za ukubwa wa kudumu, ambayo inaweza kuwa muhimu kwa variables za kategoria zenye kadi nyingi.
- Kwa mfano, ikiwa kipengele kina kategoria nyingi za kipekee, hashing inaweza kupunguza ukubwa wa dimensionality huku ikihifadhi baadhi ya taarifa kuhusu kategoria.
- **Bag of Words (BoW)**: Kuonyesha data ya maandiko kama matrix ya hesabu za maneno au mara kwa mara, ambapo kila safu inahusiana na hati na kila safu inahusiana na neno la kipekee katika corpus.
- Kwa mfano, ikiwa corpus ina maneno "cat", "dog", na "fish", hati inayojumuisha "cat" na "dog" itawakilishwa kama [1, 1, 0]. Uwakilishi huu maalum unaitwa "unigram" na hauwezi kukamata mpangilio wa maneno, hivyo hupoteza taarifa ya maana.
- **Bigram/Trigram**: Kupanua BoW ili kukamata mfuatano wa maneno (bigrams au trigrams) ili kuhifadhi muktadha fulani. Kwa mfano, "cat and dog" itawakilishwa kama bigram [1, 1] kwa "cat and" na [1, 1] kwa "and dog". Katika kesi hizi, taarifa zaidi ya maana inakusanywa (kuongeza ukubwa wa uwakilishi) lakini kwa maneno 2 au 3 kwa wakati mmoja.
- **TF-IDF (Term Frequency-Inverse Document Frequency)**: Kipimo cha takwimu kinachopima umuhimu wa neno katika hati kulingana na mkusanyiko wa hati (corpus). Kinachanganya mara ya neno (jinsi neno linavyoonekana katika hati) na mara ya kinyume ya hati (jinsi neno lilivyo nadra katika hati zote).
- Kwa mfano, ikiwa neno "cat" linaonekana mara nyingi katika hati lakini ni nadra katika corpus nzima, litakuwa na alama ya juu ya TF-IDF, ikionyesha umuhimu wake katika hati hiyo.

- **Feature Engineering**: Kuunda vipengele vipya kutoka kwa vile vilivyopo ili kuboresha uwezo wa mfano wa kutabiri. Hii inaweza kujumuisha kuunganisha vipengele, kutoa vipengele vya tarehe/nyakati, au kutumia mabadiliko maalum ya eneo.

## Data Splitting

Data splitting inahusisha kugawanya dataset katika sehemu tofauti kwa ajili ya mafunzo, uthibitisho, na upimaji. Hii ni muhimu ili kutathmini utendaji wa mfano kwenye data isiyoonekana na kuzuia overfitting. Mbinu za kawaida ni pamoja na:
- **Train-Test Split**: Kugawanya dataset katika seti ya mafunzo (kwa kawaida 60-80% ya data), seti ya uthibitisho (10-15% ya data) ili kurekebisha hyperparameters, na seti ya upimaji (10-15% ya data). Mfano unafundishwa kwenye seti ya mafunzo na kutathminiwa kwenye seti ya upimaji.
- Kwa mfano, ikiwa una dataset ya sampuli 1000, unaweza kutumia sampuli 700 kwa mafunzo, 150 kwa uthibitisho, na 150 kwa upimaji.
- **Stratified Sampling**: Kuhakikisha kuwa usambazaji wa madaraja katika seti za mafunzo na upimaji ni sawa na dataset nzima. Hii ni muhimu hasa kwa datasets zisizo sawa, ambapo baadhi ya madaraja yanaweza kuwa na sampuli chache sana kuliko mengine.
- **Time Series Split**: Kwa data ya mfululizo wa wakati, dataset inagawanywa kulingana na wakati, kuhakikisha kuwa seti ya mafunzo ina data kutoka nyakati za awali na seti ya upimaji ina data kutoka nyakati za baadaye. Hii husaidia kutathmini utendaji wa mfano kwenye data ya baadaye.
- **K-Fold Cross-Validation**: Kugawanya dataset katika K sehemu (folds) na kufundisha mfano mara K, kila wakati ukitumia fold tofauti kama seti ya upimaji na folds zilizobaki kama seti ya mafunzo. Hii husaidia kuhakikisha kuwa mfano unathminiwa kwenye sehemu tofauti za data, ikitoa makadirio thabiti zaidi ya utendaji wake.

## Model Evaluation

Model evaluation ni mchakato wa kutathmini utendaji wa mfano wa kujifunza mashine kwenye data isiyoonekana. Inahusisha kutumia vipimo mbalimbali kupima jinsi mfano unavyoweza kuhamasisha kwenye data mpya. Vipimo vya kawaida vya tathmini ni pamoja na:

### Accuracy

Accuracy ni sehemu ya matukio yaliyotabiriwa kwa usahihi kati ya jumla ya matukio. Inakokotolewa kama:
```plaintext
Accuracy = (Number of Correct Predictions) / (Total Number of Predictions)
```
> [!TIP]
> Usahihi ni kipimo rahisi na cha kueleweka, lakini huenda usifae kwa seti za data zisizo na uwiano ambapo darasa moja linatawala mengine kwani linaweza kutoa picha isiyo sahihi ya utendaji wa mfano. Kwa mfano, ikiwa 90% ya data inahusiana na darasa A na mfano un预测所有实例为类A, itapata usahihi wa 90%, lakini haitakuwa na manufaa katika kutabiri darasa B.

### Usahihi

Usahihi ni sehemu ya utabiri sahihi wa chanya kutoka kwa utabiri wote chanya uliofanywa na mfano. Inakokotolewa kama:
```plaintext
Precision = (True Positives) / (True Positives + False Positives)
```
> [!TIP]
> Usahihi ni muhimu hasa katika hali ambapo matokeo ya uwongo yana gharama kubwa au hayapendekezwi, kama katika uchunguzi wa matibabu au kugundua udanganyifu. Kwa mfano, ikiwa mfano un预测 100 matukio kama chanya, lakini tu 80 kati yao ni kweli chanya, usahihi utakuwa 0.8 (80%).

### Kumbukumbu (Sensitivity)

Kumbukumbu, pia inajulikana kama sensitivity au kiwango cha kweli chanya, ni sehemu ya utabiri wa kweli chanya kati ya matukio yote halisi chanya. Inakokotwa kama:
```plaintext
Recall = (True Positives) / (True Positives + False Negatives)
```
> [!TIP]
> Kumbuka ni muhimu katika hali ambapo hasi za uwongo ni za gharama kubwa au zisizohitajika, kama katika ugunduzi wa magonjwa au kuchuja barua taka. Kwa mfano, ikiwa mfano unapata 80 kati ya 100 ya matukio halisi chanya, kumbukumbu itakuwa 0.8 (80%).

### F1 Score

F1 score ni wastani wa harmonic wa usahihi na kumbukumbu, ikitoa uwiano kati ya vipimo viwili. Inakokotolewa kama:
```plaintext
F1 Score = 2 * (Precision * Recall) / (Precision + Recall)
```
> [!TIP]
> Alama ya F1 ni muhimu hasa unaposhughulika na seti za data zisizo sawa, kwani inazingatia both false positives na false negatives. Inatoa kipimo kimoja kinachoshughulikia uwiano kati ya usahihi na ukumbusho. Kwa mfano, ikiwa mfano una usahihi wa 0.8 na ukumbusho wa 0.6, alama ya F1 itakuwa takriban 0.69.

### ROC-AUC (Receiver Operating Characteristic - Eneo Chini ya Curve)

Kipimo cha ROC-AUC kinatathmini uwezo wa mfano kutofautisha kati ya madaraja kwa kuchora kiwango halisi chanya (sensitivity) dhidi ya kiwango cha uwongo chanya katika mipangilio mbalimbali ya kigezo. Eneo chini ya curve ya ROC (AUC) kinakadiria utendaji wa mfano, ambapo thamani ya 1 inaashiria uainishaji kamili na thamani ya 0.5 inaashiria kubahatisha kwa nasibu.

> [!TIP]
> ROC-AUC ni muhimu hasa kwa matatizo ya uainishaji wa binary na inatoa mtazamo mpana wa utendaji wa mfano katika mipangilio tofauti. Ni nyeti kidogo kwa kutokuwepo kwa uwiano wa madaraja ikilinganishwa na usahihi. Kwa mfano, mfano wenye AUC ya 0.9 inaashiria kuwa una uwezo mkubwa wa kutofautisha kati ya matukio chanya na hasi.

### Specificity

Specificity, pia inajulikana kama kiwango halisi hasi, ni sehemu ya utabiri halisi hasi kati ya matukio yote halisi hasi. Inakadiriawa kama:
```plaintext
Specificity = (True Negatives) / (True Negatives + False Positives)
```
> [!TIP]
> Upeo ni muhimu katika hali ambapo matokeo ya uwongo yana gharama kubwa au si ya kutakikana, kama katika upimaji wa matibabu au kugundua udanganyifu. Inasaidia kutathmini jinsi vizuri mfano unavyotambua matukio mabaya. Kwa mfano, ikiwa mfano unapata kwa usahihi 90 kati ya 100 ya matukio halisi mabaya, upeo utakuwa 0.9 (90%).

### Matthews Correlation Coefficient (MCC)
Matthews Correlation Coefficient (MCC) ni kipimo cha ubora wa uainishaji wa binary. Inachukua katika akaunti ya kweli na uwongo chanya na hasi, ikitoa mtazamo wa usawa wa utendaji wa mfano. MCC inakokotolewa kama:
```plaintext
MCC = (TP * TN - FP * FN) / sqrt((TP + FP) * (TP + FN) * (TN + FP) * (TN + FN))
```
where:
- **TP**: True Positives
- **TN**: True Negatives
- **FP**: False Positives
- **FN**: False Negatives

> [!TIP]
> MCC inashughulikia kutoka -1 hadi 1, ambapo 1 inaashiria uainishaji kamili, 0 inaashiria kubahatisha kwa nasibu, na -1 inaashiria kutokubaliana kabisa kati ya utabiri na uchunguzi. Ni muhimu hasa kwa seti za data zisizo sawa, kwani inazingatia vipengele vyote vinne vya matrix ya kuchanganya.

### Mean Absolute Error (MAE)
Mean Absolute Error (MAE) ni kipimo cha urudufu kinachopima tofauti ya wastani ya absolute kati ya thamani zilizotabiriwa na halisi. Inakokotolewa kama:
```plaintext
MAE = (1/n) * Σ|y_i - ŷ_i|
```
where:
- **n**: Idadi ya mifano
- **y_i**: Thamani halisi ya mfano i
- **ŷ_i**: Thamani iliy预测wa kwa mfano i

> [!TIP]
> MAE inatoa tafsiri rahisi ya makosa ya wastani katika utabiri, na kufanya iwe rahisi kueleweka. Ni nyeti kidogo kwa viashiria vya nje ikilinganishwa na vipimo vingine kama Mean Squared Error (MSE). Kwa mfano, ikiwa mfano una MAE ya 5, inamaanisha kwamba, kwa wastani, utabiri wa mfano unachukua mbali na thamani halisi kwa vitengo 5.

### Confusion Matrix

Confusion matrix ni jedwali linaloelezea utendaji wa mfano wa uainishaji kwa kuonyesha hesabu za utabiri sahihi wa chanya, sahihi wa hasi, utabiri wa chanya wa uwongo, na utabiri wa hasi wa uwongo. Inatoa mtazamo wa kina wa jinsi mfano unavyofanya kazi katika kila daraja.

|               | Predicted Positive | Predicted Negative |
|---------------|---------------------|---------------------|
| Actual Positive| True Positive (TP)  | False Negative (FN)  |
| Actual Negative| False Positive (FP) | True Negative (TN)   |

- **True Positive (TP)**: Mfano ulitabiri kwa usahihi daraja chanya.
- **True Negative (TN)**: Mfano ulitabiri kwa usahihi daraja hasi.
- **False Positive (FP)**: Mfano ulitabiri kwa makosa daraja chanya (Kosa Aina I).
- **False Negative (FN)**: Mfano ulitabiri kwa makosa daraja hasi (Kosa Aina II).

Confusion matrix inaweza kutumika kuhesabu vipimo mbalimbali vya tathmini, kama usahihi, usahihi, kukumbuka, na alama ya F1.


{{#include ../banners/hacktricks-training.md}}
