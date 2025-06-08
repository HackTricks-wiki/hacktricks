# Supervised Learning Algorithms

{{#include ../banners/hacktricks-training.md}}

## Basic Information

Kujifunza kwa kusimamiwa hutumia data iliyo na lebo kufundisha mifano inayoweza kufanya makadirio juu ya ingizo jipya, lisilojulikana. Katika usalama wa mtandao, kujifunza kwa mashine kwa kusimamiwa kunatumika sana katika kazi kama vile kugundua uvamizi (kuainisha trafiki ya mtandao kama *ya kawaida* au *shambulio*), kugundua programu hasidi (kutofautisha programu mbaya na zisizo na madhara), kugundua ulaghai (kutambua tovuti au barua pepe za ulaghai), na kuchuja barua taka, miongoni mwa zingine. Kila algorithimu ina nguvu zake na inafaa kwa aina tofauti za matatizo (kuainisha au kurudi). Hapa chini tunakagua algorithimu muhimu za kujifunza kwa kusimamiwa, kuelezea jinsi zinavyofanya kazi, na kuonyesha matumizi yao kwenye seti halisi za data za usalama wa mtandao. Tunajadili pia jinsi ya kuunganisha mifano (kujifunza kwa pamoja) kunaweza kuboresha utendaji wa makadirio mara nyingi.

## Algorithms

-   **Linear Regression:** Algorithimu ya msingi ya kurudi kwa kutabiri matokeo ya nambari kwa kufananisha sawa la moja kwa moja na data.

-   **Logistic Regression:** Algorithimu ya kuainisha (licha ya jina lake) inayotumia kazi ya logistic kuunda mfano wa uwezekano wa matokeo ya binary.

-   **Decision Trees:** Mifano iliyo na muundo wa mti inayogawanya data kwa vipengele ili kufanya makadirio; mara nyingi hutumiwa kwa sababu ya ueleweka wao.

-   **Random Forests:** Kikundi cha miti za maamuzi (kupitia bagging) kinachoboresha usahihi na kupunguza overfitting.

-   **Support Vector Machines (SVM):** Wapangaji wa max-margin wanaopata hyperplane bora ya kutenganisha; wanaweza kutumia kernels kwa data isiyo ya laini.

-   **Naive Bayes:** Mwapangaji wa uwezekano kulingana na nadharia ya Bayes na dhana ya uhuru wa vipengele, maarufu katika kuchuja barua taka.

-   **k-Nearest Neighbors (k-NN):** Mwapangaji rahisi wa "kigezo-kilichotegemea" anayepatia lebo sampuli kulingana na darasa la wingi la majirani zake wa karibu.

-   **Gradient Boosting Machines:** Mifano ya pamoja (mfano, XGBoost, LightGBM) zinazojenga mpangaji mwenye nguvu kwa kuongeza wanafunzi dhaifu kwa mpangilio (kawaida miti za maamuzi).

Kila sehemu hapa chini inatoa maelezo yaliyoboreshwa ya algorithimu na **mfano wa msimbo wa Python** ukitumia maktaba kama `pandas` na `scikit-learn` (na `PyTorch` kwa mfano wa mtandao wa neva). Mifano inatumia seti za data za usalama wa mtandao zinazopatikana kwa umma (kama NSL-KDD kwa kugundua uvamizi na seti ya Tovuti za Ulaghai) na inafuata muundo thabiti:

1.  **Pakia seti ya data** (shusha kupitia URL ikiwa inapatikana).

2.  **Tayarisha data** (mfano, encode vipengele vya kategoria, pima thamani, gawanya katika seti za mafunzo/test).

3.  **Fundisha mfano** kwenye data ya mafunzo.

4.  **Tathmini** kwenye seti ya mtihani ukitumia vipimo: usahihi, usahihi, kumbukumbu, F1-score, na ROC AUC kwa kuainisha (na makosa ya wastani ya mraba kwa kurudi).

Hebu tuingie kwenye kila algorithimu:

### Linear Regression

Linear regression ni algorithimu ya **kurudi** inayotumika kutabiri thamani za nambari zisizobadilika. Inadhani uhusiano wa moja kwa moja kati ya vipengele vya ingizo (vigezo huru) na matokeo (kigezo kinachotegemea). Mfano unajaribu kufananisha mstari wa moja kwa moja (au hyperplane katika vipimo vya juu) ambao unafafanua bora uhusiano kati ya vipengele na lengo. Hii kawaida hufanywa kwa kupunguza jumla ya makosa ya mraba kati ya thamani zilizotabiriwa na halisi (mbinu ya Ordinary Least Squares).

Njia rahisi ya kuwakilisha linear regression ni kwa mstari:
```plaintext
y = mx + b
```
Wapi:

- `y` ni thamani inayotabiriwa (matokeo)
- `m` ni mteremko wa laini (kiwango)
- `x` ni kipengele cha ingizo
- `b` ni kukatiza kwa y

Lengo la regression ya mstari ni kupata laini inayofaa zaidi ambayo inapunguza tofauti kati ya thamani zinazotabiriwa na thamani halisi katika seti ya data. Bila shaka, hii ni rahisi sana, itakuwa laini moja inayotenganisha makundi 2, lakini ikiwa vipimo zaidi vitajumuishwa, laini inakuwa ngumu zaidi:
```plaintext
y = w1*x1 + w2*x2 + ... + wn*xn + b
```
> [!TIP]
> *Matumizi katika usalama wa mtandao:* Linear regression yenyewe si ya kawaida kwa kazi za msingi za usalama (ambazo mara nyingi ni uainishaji), lakini inaweza kutumika kutabiri matokeo ya nambari. Kwa mfano, mtu anaweza kutumia linear regression ili **kutabiri kiasi cha trafiki ya mtandao** au **kukadiria idadi ya mashambulizi katika kipindi fulani** kulingana na data za kihistoria. Pia inaweza kutabiri alama ya hatari au muda unaotarajiwa hadi kugundua shambulizi, ikizingatia vipimo fulani vya mfumo. Katika mazoezi, algorithimu za uainishaji (kama logistic regression au miti) hutumiwa mara nyingi zaidi kwa kugundua uvamizi au malware, lakini linear regression inatumika kama msingi na ni muhimu kwa uchambuzi unaolenga regression.

#### **Sifa kuu za Linear Regression:**

-   **Aina ya Tatizo:** Regression (kutabiri thamani za endelevu). Haifai kwa uainishaji wa moja kwa moja isipokuwa kigezo kitatumika kwa matokeo.

-   **Ufafanuzi:** Juu -- coefficients ni rahisi kueleweka, zinaonyesha athari ya moja kwa moja ya kila kipengele.

-   **Faida:** Rahisi na haraka; msingi mzuri kwa kazi za regression; inafanya kazi vizuri wakati uhusiano halisi ni wa karibu lineari.

-   **Mipaka:** Haiwezi kukamata uhusiano tata au usio wa lineari (bila uhandisi wa kipengele wa mikono); inakabiliwa na underfitting ikiwa uhusiano ni usio wa lineari; nyeti kwa outliers ambazo zinaweza kupotosha matokeo.

-   **Kupata Mstari Bora:** Ili kupata mstari bora unaotenganisha makundi yanayowezekana, tunatumia mbinu inayoitwa **Ordinary Least Squares (OLS)**. Mbinu hii inapunguza jumla ya tofauti zilizokadiriwa kati ya thamani zilizoshuhudiwa na thamani zinazokadiriwa na mfano wa lineari.

<details>
<summary>Mfano -- Kutabiri Muda wa Muunganisho (Regression) katika Dataset ya Uvamizi
</summary>
Hapa chini tunaonyesha linear regression kwa kutumia dataset ya usalama wa mtandao ya NSL-KDD. Tutachukulia hii kama tatizo la regression kwa kutabiri `muda` wa muunganisho wa mtandao kulingana na vipengele vingine. (Katika hali halisi, `muda` ni kipengele kimoja cha NSL-KDD; tunakitumia hapa tu kuonyesha regression.) Tunapakia dataset, tunaiandaa (kuandika vipengele vya kategoria), tunafundisha mfano wa linear regression, na kutathmini Makosa ya Kiwango cha Mkataba (MSE) na alama ya R² kwenye seti ya mtihani.
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
Katika mfano huu, mfano wa linear regression unajaribu kutabiri `duration` ya muunganisho kutoka kwa vipengele vingine vya mtandao. Tunapima utendaji kwa kutumia Mean Squared Error (MSE) na R². R² inayokaribia 1.0 ingekuwa inaonyesha kwamba mfano unaelezea tofauti nyingi katika `duration`, wakati R² ya chini au hasi inaonyesha ulinganifu mbaya. (Usishangae ikiwa R² ni ya chini hapa -- kutabiri `duration` kunaweza kuwa ngumu kutokana na vipengele vilivyotolewa, na linear regression inaweza isishike mifumo ikiwa ni ngumu.)

### Logistic Regression

Logistic regression ni **classification** algorithm inayomodeli uwezekano kwamba mfano unahusiana na darasa fulani (kawaida darasa "chanya"). Licha ya jina lake, *logistic* regression inatumika kwa matokeo ya kutenganishwa (kinyume na linear regression ambayo ni kwa matokeo ya kuendelea). Inatumika hasa kwa **binary classification** (darasa mbili, mfano, mbaya dhidi ya nzuri), lakini inaweza kupanuliwa kwa matatizo ya darasa nyingi (kwa kutumia softmax au mbinu moja dhidi ya nyingine).

Logistic regression inatumia kazi ya logistic (pia inajulikana kama kazi ya sigmoid) kubadilisha thamani zinazotabiriwa kuwa uwezekano. Kumbuka kwamba kazi ya sigmoid ni kazi yenye thamani kati ya 0 na 1 inayokua katika curve ya S kulingana na mahitaji ya uainishaji, ambayo ni muhimu kwa kazi za uainishaji wa binary. Hivyo, kila kipengele cha kila ingizo kinazidishwa na uzito wake uliotolewa, na matokeo yanapitishwa kupitia kazi ya sigmoid ili kutoa uwezekano:
```plaintext
p(y=1|x) = 1 / (1 + e^(-z))
```
Where:

- `p(y=1|x)` ni uwezekano kwamba matokeo `y` ni 1 kutokana na ingizo `x`
- `e` ni msingi wa logarithm ya asili
- `z` ni mchanganyiko wa moja kwa moja wa vipengele vya ingizo, kawaida inawakilishwa kama `z = w1*x1 + w2*x2 + ... + wn*xn + b`. Angalia jinsi tena katika mfumo wake rahisi ni mstari wa moja kwa moja, lakini katika kesi ngumu zaidi inakuwa hyperplane yenye vipimo vingi (moja kwa kila kipengele).

> [!TIP]
> *Matumizi katika usalama wa mtandao:* Kwa sababu matatizo mengi ya usalama kimsingi ni maamuzi ya ndiyo/hapana, regression ya logistic inatumika sana. Kwa mfano, mfumo wa kugundua uvamizi unaweza kutumia regression ya logistic kuamua ikiwa muunganisho wa mtandao ni shambulio kulingana na vipengele vya muunganisho huo. Katika kugundua phishing, regression ya logistic inaweza kuunganisha vipengele vya tovuti (urefu wa URL, uwepo wa alama ya "@" n.k.) katika uwezekano wa kuwa phishing. Imetumika katika filters za spam za kizazi cha awali na inabaki kuwa msingi mzuri kwa kazi nyingi za uainishaji.

#### Regression ya Logistic kwa uainishaji usio wa binary

Regression ya logistic imeundwa kwa ajili ya uainishaji wa binary, lakini inaweza kupanuliwa kushughulikia matatizo ya madarasa mengi kwa kutumia mbinu kama **moja dhidi ya wengine** (OvR) au **softmax regression**. Katika OvR, mfano tofauti wa regression ya logistic unafundishwa kwa kila darasa, ukitreat kama darasa chanya dhidi ya mengine yote. Darasa lenye uwezekano wa juu zaidi linachaguliwa kama utabiri wa mwisho. Softmax regression inapanua regression ya logistic kwa madarasa mengi kwa kutumia kazi ya softmax kwenye safu ya matokeo, ikitoa usambazaji wa uwezekano juu ya madarasa yote.

#### **Sifa kuu za Regression ya Logistic:**

-   **Aina ya Tatizo:** Uainishaji (kawaida wa binary). Inatabiri uwezekano wa darasa chanya.

-   **Ufafanuzi:** Juu -- kama regression ya moja kwa moja, coefficients za vipengele zinaweza kuonyesha jinsi kila kipengele kinavyoathiri log-odds ya matokeo. Uwazi huu mara nyingi unathaminiwa katika usalama kwa kuelewa ni vigezo gani vinavyosababisha tahadhari.

-   **Faida:** Rahisi na haraka kufundisha; inafanya kazi vizuri wakati uhusiano kati ya vipengele na log-odds ya matokeo ni wa moja kwa moja. Inatoa uwezekano, ikiruhusu upimaji wa hatari. Kwa udhibiti sahihi, inapanua vizuri na inaweza kushughulikia multicollinearity bora zaidi kuliko regression ya moja kwa moja ya kawaida.

-   **Mapungufu:** Inadhani mipaka ya maamuzi ya moja kwa moja katika nafasi ya vipengele (inaweza kushindwa ikiwa mipaka halisi ni ngumu/siyo ya moja kwa moja). Inaweza kufanya vibaya kwenye matatizo ambapo mwingiliano au athari zisizo za moja kwa moja ni muhimu, isipokuwa uongeze vipengele vya polynomial au mwingiliano kwa mikono. Pia, regression ya logistic ni dhaifu ikiwa madarasa hayawezi kutenganishwa kwa urahisi na mchanganyiko wa moja kwa moja wa vipengele.

<details>
<summary>Mfano -- Kugundua Tovuti za Phishing kwa Regression ya Logistic:</summary>

Tutatumia **Seti ya Takwimu za Tovuti za Phishing** (kutoka kwenye hazina ya UCI) ambayo ina vipengele vilivyotolewa vya tovuti (kama vile ikiwa URL ina anwani ya IP, umri wa kikoa, uwepo wa vipengele vya kutatanisha katika HTML, n.k.) na lebo inayonyesha ikiwa tovuti ni phishing au halali. Tunafundisha mfano wa regression ya logistic ili kuainisha tovuti na kisha kutathmini usahihi wake, usahihi, kukumbuka, alama ya F1, na ROC AUC kwenye mgawanyiko wa mtihani.
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
Katika mfano huu wa kugundua phishing, regression ya logistic inatoa uwezekano wa kila tovuti kuwa phishing. Kwa kutathmini usahihi, usahihi wa kweli, kurudi, na F1, tunapata hisia ya utendaji wa mfano. Kwa mfano, kurudi kwa juu kutamaanisha inakamata tovuti nyingi za phishing (muhimu kwa usalama ili kupunguza mashambulizi yaliyokosa), wakati usahihi wa juu unamaanisha ina alama chache za uwongo (muhimu ili kuepuka uchovu wa mchambuzi). ROC AUC (Eneo Chini ya Mchoro wa ROC) inatoa kipimo kisichotegemea kigezo cha utendaji (1.0 ni bora, 0.5 si bora zaidi kuliko bahati nasibu). Regression ya logistic mara nyingi inafanya vizuri katika kazi kama hizo, lakini ikiwa mpaka wa uamuzi kati ya tovuti za phishing na halali ni ngumu, mifano isiyo ya kawaida yenye nguvu zaidi inaweza kuhitajika.

</details>

### Miti ya Uamuzi

Mti wa uamuzi ni **algorithms ya kujifunza kwa usimamizi** inayoweza kutumika kwa kazi za uainishaji na regression. Inajifunza mfano wa mti wa maamuzi wa kihierarkia kulingana na vipengele vya data. Kila nodi ya ndani ya mti inawakilisha mtihani juu ya kipengele fulani, kila tawi linawakilisha matokeo ya mtihani huo, na kila nodi ya majani inawakilisha daraja lililotabiriwa (kwa uainishaji) au thamani (kwa regression).

Ili kujenga mti, algorithms kama CART (Mti wa Uainishaji na Regression) hutumia vipimo kama **uchafu wa Gini** au **faida ya taarifa (entropi)** kuchagua kipengele bora na kigezo cha kugawanya data katika kila hatua. Lengo katika kila mgawanyiko ni kugawanya data ili kuongeza umoja wa variable lengwa katika sehemu zinazotokana (kwa uainishaji, kila nodi inalenga kuwa safi kadri inavyowezekana, ikijumuisha daraja moja tu).

Miti ya uamuzi ni **rahisi kueleweka** -- mtu anaweza kufuata njia kutoka mzizi hadi jani ili kuelewa mantiki nyuma ya utabiri (kwa mfano, *"IKIWA `service = telnet` NA `src_bytes > 1000` NA `failed_logins > 3` BASI ainishe kama shambulio"*). Hii ni muhimu katika usalama wa mtandao kwa kuelezea kwa nini arifa fulani ilitolewa. Miti inaweza kushughulikia data za nambari na za kategoria kwa urahisi na inahitaji maandalizi madogo (kwa mfano, upimaji wa kipengele hauhitajiki).

Hata hivyo, mti mmoja wa uamuzi unaweza kwa urahisi kujiweka kwenye data ya mafunzo, hasa ikiwa umejengwa kwa kina (mgawanyiko mingi). Mbinu kama pruning (kudhibiti kina cha mti au kuhitaji idadi ya chini ya sampuli kwa kila jani) mara nyingi hutumiwa kuzuia kujiweka.

Kuna vipengele 3 vikuu vya mti wa uamuzi:
- **Nodi ya Mzizi**: Nodi ya juu ya mti, inawakilisha dataset nzima.
- **Nodi za Ndani**: Nodi zinazowakilisha vipengele na maamuzi kulingana na vipengele hivyo.
- **Nodi za Majani**: Nodi zinazowakilisha matokeo ya mwisho au utabiri.

Mti unaweza kuishia kuonekana kama hii:
```plaintext
[Root Node]
/   \
[Node A]  [Node B]
/   \      /   \
[Leaf 1] [Leaf 2] [Leaf 3] [Leaf 4]
```
> [!TIP]
> *Matumizi katika usalama wa mtandao:* Miti ya maamuzi imekuwa ikitumika katika mifumo ya kugundua uvamizi ili kupata **kanuni** za kutambua mashambulizi. Kwa mfano, mifumo ya awali ya IDS kama vile inayotegemea ID3/C4.5 ingezalisha kanuni zinazoweza kusomeka na binadamu ili kutofautisha trafiki ya kawaida na ya uhalifu. Pia zinatumika katika uchambuzi wa malware ili kuamua kama faili ni ya uhalifu kulingana na sifa zake (ukubwa wa faili, entropy ya sehemu, wito wa API, n.k.). Uwazi wa miti ya maamuzi unazifanya kuwa muhimu wakati uwazi unahitajika -- mchambuzi anaweza kuchunguza mti ili kuthibitisha mantiki ya kugundua.

#### **Sifa kuu za Miti ya Maamuzi:**

-   **Aina ya Tatizo:** Uainishaji na urejeleaji. Inatumika sana kwa uainishaji wa mashambulizi dhidi ya trafiki ya kawaida, n.k.

-   **Ufafanuzi:** Juu sana -- maamuzi ya mfano yanaweza kuonyeshwa na kueleweka kama seti ya kanuni za kama-kisha. Hii ni faida kubwa katika usalama kwa kuaminika na uthibitisho wa tabia ya mfano.

-   **Faida:** Inaweza kushika uhusiano usio wa moja kwa moja na mwingiliano kati ya vipengele (kila mgawanyiko unaweza kuonekana kama mwingiliano). Hakuna haja ya kupima vipengele au kuandika moja kwa moja mabadiliko ya kategoria -- miti inashughulikia hayo kiasili. Utabiri wa haraka (utabiri ni kufuata tu njia katika mti).

-   **Mapungufu:** Inaweza kuwa na hatari ya kupita kiasi ikiwa haitadhibitiwa (mti mrefu unaweza kukumbuka seti ya mafunzo). Inaweza kuwa isiyo thabiti -- mabadiliko madogo katika data yanaweza kusababisha muundo tofauti wa mti. Kama mifano ya pekee, usahihi wao unaweza kutofautiana na mbinu za juu zaidi (mchanganyiko kama Random Forests kwa kawaida hufanya vizuri zaidi kwa kupunguza tofauti).

-   **Kupata Mgawanyiko Bora:**
- **Gini Impurity**: Inapima uchafuzi wa nodi. Uchafuzi wa chini wa Gini unaonyesha mgawanyiko bora. Formula ni:

```plaintext
Gini = 1 - Σ(p_i^2)
```

Ambapo `p_i` ni sehemu ya matukio katika darasa `i`.

- **Entropy**: Inapima kutokuwa na uhakika katika seti ya data. Entropy ya chini inaonyesha mgawanyiko bora. Formula ni:

```plaintext
Entropy = -Σ(p_i * log2(p_i))
```

Ambapo `p_i` ni sehemu ya matukio katika darasa `i`.

- **Information Gain**: Kupungua kwa entropy au uchafuzi wa Gini baada ya mgawanyiko. Kadri faida ya taarifa inavyokuwa kubwa, ndivyo mgawanyiko unavyokuwa bora. Inakokotwa kama:

```plaintext
Information Gain = Entropy(parent) - (Weighted Average of Entropy(children))
```

Zaidi ya hayo, mti unamalizika wakati:
- Matukio yote katika nodi yanategemea darasa moja. Hii inaweza kusababisha kupita kiasi.
- Kina cha juu zaidi (kilichowekwa kwa nguvu) cha mti kimefikiwa. Hii ni njia ya kuzuia kupita kiasi.
- Idadi ya matukio katika nodi iko chini ya kigezo fulani. Hii pia ni njia ya kuzuia kupita kiasi.
- Faida ya taarifa kutoka kwa mgawanyiko zaidi iko chini ya kigezo fulani. Hii pia ni njia ya kuzuia kupita kiasi.

<details>
<summary>Mfano -- Mti wa Maamuzi kwa Kugundua Uvamizi:</summary>
Tutafundisha mti wa maamuzi kwenye seti ya data ya NSL-KDD ili kuainisha muunganisho wa mtandao kama *kawaida* au *shambulizi*. NSL-KDD ni toleo lililoboreshwa la seti ya data ya KDD Cup 1999, ikiwa na vipengele kama aina ya protokali, huduma, muda, idadi ya kuingia kwa mafanikio, n.k., na lebo inayonyesha aina ya shambulizi au "kawaida". Tutapanga aina zote za mashambulizi kwenye darasa la "anomaly" (uainishaji wa binary: kawaida dhidi ya anomaly). Baada ya mafunzo, tutakadiria utendaji wa mti kwenye seti ya mtihani.
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
Katika mfano huu wa mti wa maamuzi, tulipunguza kina cha mti kuwa 10 ili kuepuka kupita kiasi kwa kuzingatia (parameter ya `max_depth=10`). Vipimo vinaonyesha jinsi mti unavyotofautisha trafiki ya kawaida dhidi ya shambulio. Kumbukumbu ya juu itamaanisha inakamata mashambulizi mengi (muhimu kwa IDS), wakati usahihi wa juu unamaanisha alama chache za uwongo. Miti ya maamuzi mara nyingi inapata usahihi mzuri kwenye data iliyopangwa, lakini mti mmoja huenda usifikie utendaji bora zaidi unaowezekana. Hata hivyo, *ufahamu* wa mfano ni faida kubwa -- tunaweza kuchunguza mgawanyiko wa mti kuona, kwa mfano, ni vipengele vipi (k.m., `service`, `src_bytes`, n.k.) vina ushawishi mkubwa katika kuashiria muunganisho kama mbaya.

</details>

### Misitu ya Nasibu

Misitu ya Nasibu ni mbinu ya **ujifunzaji wa pamoja** inayojenga juu ya miti ya maamuzi ili kuboresha utendaji. Misitu ya nasibu inafundisha miti mingi ya maamuzi (hivyo "msitu") na kuunganisha matokeo yao ili kufanya utabiri wa mwisho (kwa uainishaji, kawaida kwa kura ya wingi). Mawazo mawili makuu katika msitu wa nasibu ni **bagging** (kuunganisha bootstrapping) na **uhusiano wa vipengele**:

-   **Bagging:** Kila mti unafundishwa kwenye sampuli ya bootstrapping ya nasibu ya data ya mafunzo (iliyochukuliwa kwa kubadilishana). Hii inaingiza utofauti kati ya miti.

-   **Uhusiano wa Vipengele:** Kila wakati wa mgawanyiko katika mti, subset ya nasibu ya vipengele inazingatiwa kwa ajili ya mgawanyiko (badala ya vipengele vyote). Hii inafanya miti kuwa na uhusiano mdogo zaidi.

Kwa kuhesabu matokeo ya miti mingi, msitu wa nasibu hupunguza tofauti ambayo mti mmoja wa maamuzi unaweza kuwa nayo. Kwa maneno rahisi, miti binafsi inaweza kupita kiasi au kuwa na kelele, lakini idadi kubwa ya miti tofauti ikipiga kura pamoja inasafisha makosa hayo. Matokeo mara nyingi ni mfano wenye **usahihi wa juu** na ujanibishaji bora kuliko mti mmoja wa maamuzi. Aidha, misitu ya nasibu inaweza kutoa makadirio ya umuhimu wa vipengele (kwa kuangalia ni kiasi gani kila mgawanyiko wa kipengele hupunguza uchafu kwa wastani).

Misitu ya nasibu yamekuwa **kazi kubwa katika usalama wa mtandao** kwa kazi kama vile kugundua uvamizi, uainishaji wa malware, na kugundua barua taka. Mara nyingi hufanya vizuri bila marekebisho makubwa na zinaweza kushughulikia seti kubwa za vipengele. Kwa mfano, katika kugundua uvamizi, msitu wa nasibu unaweza kufanya vizuri zaidi kuliko mti mmoja wa maamuzi kwa kukamata mifumo ya mashambulizi ya siri zaidi kwa alama chache za uwongo. Utafiti umeonyesha misitu ya nasibu ikifanya vizuri ikilinganishwa na algorithimu nyingine katika kuainisha mashambulizi katika seti za data kama NSL-KDD na UNSW-NB15.

#### **Sifa kuu za Misitu ya Nasibu:**

-   **Aina ya Tatizo:** Kimsingi uainishaji (pia hutumiwa kwa urejeleaji). Inafaa sana kwa data iliyopangwa ya kiwango cha juu inayopatikana katika kumbukumbu za usalama.

-   **Ufafanuzi:** Chini kuliko mti mmoja wa maamuzi -- huwezi kuona kwa urahisi au kuelezea miti mia kwa wakati mmoja. Hata hivyo, alama za umuhimu wa vipengele zinatoa ufahamu fulani kuhusu ni sifa zipi zenye ushawishi mkubwa.

-   **Faida:** Kwa ujumla usahihi wa juu zaidi kuliko mifano ya miti moja kutokana na athari ya pamoja. Imara dhidi ya kupita kiasi -- hata kama miti binafsi inapita kiasi, pamoja inajitenga vizuri zaidi. Inashughulikia vipengele vya nambari na vya kategoria na inaweza kudhibiti data iliyokosekana kwa kiwango fulani. Pia ni imara dhidi ya vitu vya nje.

-   **Vikwazo:** Ukubwa wa mfano unaweza kuwa mkubwa (miti mingi, kila moja inaweza kuwa na kina). Utabiri ni polepole kuliko mti mmoja (kwa kuwa lazima uunganishe juu ya miti mingi). Ni ngumu kueleweka -- ingawa unajua vipengele muhimu, mantiki halisi si rahisi kufuatilia kama sheria rahisi. Ikiwa seti ya data ni kubwa sana na yenye upungufu, kufundisha msitu mkubwa sana kunaweza kuwa na uzito wa hesabu.

-   **Mchakato wa Mafunzo:**
1. **Sampuli ya Bootstrapping**: Chukua sampuli ya nasibu ya data ya mafunzo kwa kubadilishana ili kuunda subsets nyingi (sampuli za bootstrapping).
2. **Ujenzi wa Mti**: Kwa kila sampuli ya bootstrapping, jenga mti wa maamuzi ukitumia subset ya nasibu ya vipengele katika kila mgawanyiko. Hii inaingiza utofauti kati ya miti.
3. **Kuunganisha**: Kwa kazi za uainishaji, utabiri wa mwisho unafanywa kwa kuchukua kura ya wingi kati ya utabiri wa miti yote. Kwa kazi za urejeleaji, utabiri wa mwisho ni wastani wa utabiri kutoka kwa miti yote.

<details>
<summary>Mfano -- Misitu ya Nasibu kwa Kugundua Uvamizi (NSL-KDD):</summary>
Tutatumia seti ile ile ya data ya NSL-KDD (iliyowekwa alama kama ya kawaida dhidi ya anomali) na kufundisha mchanganuzi wa Misitu ya Nasibu. Tunatarajia msitu wa nasibu kufanya vizuri kama au bora kuliko mti mmoja wa maamuzi, shukrani kwa kuunganisha wastani kupunguza tofauti. Tutakagua kwa vipimo vile vile.
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
Miti ya nasibu kwa kawaida inapata matokeo mazuri katika kazi hii ya kugundua uvamizi. Tunaweza kuona uboreshaji katika vipimo kama F1 au AUC ikilinganishwa na mti mmoja wa maamuzi, hasa katika kukumbuka au usahihi, kulingana na data. Hii inakubaliana na ufahamu kwamba *"Random Forest (RF) ni mchanganyiko wa wakala na inafanya vizuri ikilinganishwa na wakala wengine wa jadi kwa ajili ya uainishaji mzuri wa mashambulizi."*. Katika muktadha wa operesheni za usalama, mfano wa random forest unaweza kuashiria mashambulizi kwa uaminifu zaidi huku ukipunguza alama za uwongo, kutokana na wastani wa sheria nyingi za maamuzi. Umuhimu wa vipengele kutoka kwa msitu unaweza kutuambia ni vipengele gani vya mtandao vinavyodhihirisha mashambulizi zaidi (kwa mfano, huduma fulani za mtandao au idadi isiyo ya kawaida ya pakiti).

</details>

### Mashine za Vektori za Msaada (SVM)

Mashine za Vektori za Msaada ni mifano yenye nguvu ya kujifunza kwa usimamizi inayotumika hasa kwa ajili ya uainishaji (na pia urejeleaji kama SVR). SVM inajaribu kupata **hyperplane ya kutenganisha bora** inayoongeza mipaka kati ya makundi mawili. Ni subset tu ya alama za mafunzo (vektori za msaada "zinazo karibu na mpaka") inayotengeneza nafasi ya hyperplane hii. Kwa kuongeza mipaka (kiasi kati ya vektori za msaada na hyperplane), SVM hujenga ujanibishaji mzuri.

Muhimu kwa nguvu ya SVM ni uwezo wa kutumia **kazi za kernel** kushughulikia uhusiano usio wa mstari. Data inaweza kubadilishwa kwa siri kuwa katika nafasi ya vipengele yenye dimbwi kubwa ambapo mtenganishi wa mstari unaweza kuwepo. Kerneli za kawaida ni pamoja na polynomial, kazi ya msingi ya radial (RBF), na sigmoid. Kwa mfano, ikiwa makundi ya trafiki ya mtandao hayawezi kutenganishwa kwa mstari katika nafasi ya vipengele ghafi, kernel ya RBF inaweza kuyachora katika dimbwi kubwa ambapo SVM inapata mgawanyiko wa mstari (ambao unalingana na mpaka usio wa mstari katika nafasi ya asili). Uwezo wa kuchagua kerneli unaruhusu SVM kushughulikia matatizo mbalimbali.

SVM zinajulikana kufanya vizuri katika hali zenye nafasi za vipengele zenye dimbwi kubwa (kama data ya maandiko au mfuatano wa opcode za malware) na katika kesi ambapo idadi ya vipengele ni kubwa ikilinganishwa na idadi ya sampuli. Zilikuwa maarufu katika matumizi mengi ya awali ya usalama wa mtandao kama vile uainishaji wa malware na kugundua uvamizi kulingana na anomali katika miaka ya 2000, mara nyingi zikionyesha usahihi wa juu.

Hata hivyo, SVM hazipatikani kwa urahisi kwa seti kubwa za data (ugumu wa mafunzo ni juu ya mstari katika idadi ya sampuli, na matumizi ya kumbukumbu yanaweza kuwa juu kwani inaweza kuhitaji kuhifadhi vektori vingi vya msaada). Katika mazoezi, kwa kazi kama kugundua uvamizi wa mtandao na rekodi milioni, SVM inaweza kuwa polepole bila kuchambua kwa makini au kutumia mbinu za takriban.

#### **Sifa kuu za SVM:**

-   **Aina ya Tatizo:** Uainishaji (wa binary au multiclass kupitia moja dhidi ya moja/moja dhidi ya wengine) na toleo la urejeleaji. Mara nyingi hutumiwa katika uainishaji wa binary na kutenganisha mipaka wazi.

-   **Ufafanuzi:** Kati -- SVM hazieleweki kama miti ya maamuzi au urejeleaji wa logistic. Ingawa unaweza kubaini ni alama zipi ni vektori za msaada na kupata hisia fulani ya ni vipengele vipi vinaweza kuwa na ushawishi (kupitia uzito katika kesi ya kernel ya mstari), katika mazoezi SVM (hasa na kerneli zisizo za mstari) hut treated kama wakala wa sanduku jeusi.

-   **Faida:** Inafanya kazi vizuri katika nafasi zenye dimbwi kubwa; inaweza kuunda mipaka ngumu ya maamuzi kwa kutumia hila ya kernel; ni thabiti dhidi ya kupita kiasi ikiwa mipaka imeongezwa (hasa na parameter sahihi ya kawaida C); inafanya kazi vizuri hata wakati makundi hayajatenganishwa kwa umbali mkubwa (inapata mpaka bora wa makubaliano).

-   **Vikwazo:** **Inahitaji nguvu ya kompyuta** kwa seti kubwa za data (mafunzo na utabiri vinakua vibaya kadri data inavyokua). Inahitaji urekebishaji wa makini wa kernel na vigezo vya kawaida (C, aina ya kernel, gamma kwa RBF, nk). Haipati moja kwa moja matokeo ya uwezekano (ingawa mtu anaweza kutumia Platt scaling kupata uwezekano). Pia, SVM zinaweza kuwa nyeti kwa uchaguzi wa vigezo vya kernel --- uchaguzi mbaya unaweza kusababisha chini ya kufaa au kupita kiasi.

*Matumizi katika usalama wa mtandao:* SVM zimekuwa zikitumika katika **gundua malware** (kwa mfano, kuainisha faili kulingana na vipengele vilivyotolewa au mfuatano wa opcode), **gundua anomali za mtandao** (kuainisha trafiki kama ya kawaida dhidi ya hatari), na **gundua phishing** (kutumia vipengele vya URLs). Kwa mfano, SVM inaweza kuchukua vipengele vya barua pepe (idadi ya maneno fulani, alama za sifa za mtumaji, nk.) na kuainisha kama phishing au halali. Pia zimekuwa zikitumika katika **gundua uvamizi** kwenye seti za vipengele kama KDD, mara nyingi zikipata usahihi wa juu kwa gharama ya kompyuta.

<details>
<summary>Mfano -- SVM kwa Uainishaji wa Malware:</summary>
Tutatumia seti ya data ya tovuti za phishing tena, wakati huu na SVM. Kwa sababu SVM zinaweza kuwa polepole, tutatumia subset ya data kwa mafunzo ikiwa inahitajika (seti ya data ina takriban matukio 11k, ambayo SVM inaweza kushughulikia kwa kiasi). Tutatumia kernel ya RBF ambayo ni chaguo la kawaida kwa data zisizo za mstari, na tutaruhusu makadirio ya uwezekano ili kuhesabu ROC AUC.
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
SVM modeli itatoa metriki ambazo tunaweza kulinganisha na regression ya logistic kwenye kazi hiyo hiyo. Tunaweza kupata kwamba SVM inapata usahihi wa juu na AUC ikiwa data imegawanywa vizuri na vipengele. Kwa upande mwingine, ikiwa dataset ilikuwa na kelele nyingi au madarasa yanayoshirikiana, SVM inaweza isifanye vizuri zaidi kuliko regression ya logistic. Katika mazoezi, SVM zinaweza kutoa ongezeko wakati kuna uhusiano mgumu, usio wa moja kwa moja kati ya vipengele na darasa -- kernel ya RBF inaweza kukamata mipaka ya maamuzi iliyopinda ambayo regression ya logistic ingepuuzia. Kama ilivyo kwa mifano yote, tuning ya makini ya `C` (regularization) na vigezo vya kernel (kama `gamma` kwa RBF) inahitajika ili kulinganisha bias na variance.

</details>

#### Tofauti kati ya Regression ya Logistic na SVM

| Kipengele | **Regression ya Logistic** | **Mashine za Vektori za Msaada** |
|---|---|---|
| **Kazi ya lengo** | Inapunguza **log‑loss** (cross‑entropy). | Inapanua **margin** wakati inapunguza **hinge‑loss**. |
| **Mipaka ya maamuzi** | Inapata **hyperplane bora** inayomodeli _P(y\|x)_. | Inapata **hyperplane yenye margin kubwa** (pengo kubwa kwa pointi za karibu). |
| **Matokeo** | **Kihesabu** – inatoa uwezekano wa darasa ulio sahihi kupitia σ(w·x + b). | **Kihakika** – inarudisha lebo za darasa; uwezekano unahitaji kazi ya ziada (mfano: Platt scaling). |
| **Regularization** | L2 (default) au L1, moja kwa moja inalinganisha under/over‑fitting. | Kigezo cha C kinabadilisha upana wa margin dhidi ya makosa ya uainishaji; vigezo vya kernel vinaongeza ugumu. |
| **Kernels / Usio wa moja kwa moja** | Fomu asilia ni **mwelekeo**; usio wa moja kwa moja umeongezwa na uhandisi wa vipengele. | **Kernel trick** iliyojengwa (RBF, poly, nk.) inaruhusu kuunda mipaka ngumu katika nafasi ya dimu kubwa. |
| **Uwezo wa kupanuka** | Inatatua optimization convex katika **O(nd)**; inashughulikia n kubwa sana vizuri. | Mafunzo yanaweza kuwa **O(n²–n³)** kumbukumbu/muda bila wasaidizi maalum; si rafiki kwa n kubwa. |
| **Ufafanuzi** | **Juu** – uzito unaonyesha ushawishi wa kipengele; uwiano wa nafasi ni wa kueleweka. | **Chini** kwa kernels zisizo za moja kwa moja; vektori za msaada ni chache lakini si rahisi kuelezea. |
| **Hassira kwa outliers** | Inatumia log‑loss laini → si nyeti sana. | Hinge‑loss yenye margin ngumu inaweza kuwa **nyeti**; soft‑margin (C) inapunguza. |
| **Matumizi ya kawaida** | Uthibitishaji wa mkopo, hatari ya matibabu, A/B testing – ambapo **uwezekano na ufafanuzi** ni muhimu. | Uainishaji wa picha/maandishi, bio‑informatics – ambapo **mipaka ngumu** na **data ya dimu kubwa** ni muhimu. |

* **Ikiwa unahitaji uwezekano ulio sahihi, ufafanuzi, au unafanya kazi kwenye datasets kubwa — chagua Regression ya Logistic.**
* **Ikiwa unahitaji mfano rahisi ambao unaweza kukamata uhusiano usio wa moja kwa moja bila uhandisi wa vipengele wa mikono — chagua SVM (pamoja na kernels).**
* Zote zinaongeza malengo convex, hivyo **minima za kimataifa zinahakikishwa**, lakini kernels za SVM zinaongeza vigezo vya hyper na gharama za kompyuta.

### Naive Bayes

Naive Bayes ni familia ya **wajumuishaji wa kihesabu** inayotokana na kutumia Theorem ya Bayes na dhana ya uhuru mkubwa kati ya vipengele. Licha ya dhana hii "ya kijinga", Naive Bayes mara nyingi inafanya kazi vizuri kwa maombi fulani, hasa yale yanayohusisha maandiko au data ya kategoria, kama vile kugundua spam.


#### Theorem ya Bayes

Theorem ya Bayes ni msingi wa wajumuishaji wa Naive Bayes. Inahusisha uwezekano wa masharti na uwezekano wa mipaka ya matukio ya nasibu. Formula ni:
```plaintext
P(A|B) = (P(B|A) * P(A)) / P(B)
```
Where:
- `P(A|B)` ni uwezekano wa baada ya darasa `A` kutokana na kipengele `B`.
- `P(B|A)` ni uwezekano wa kipengele `B` kutokana na darasa `A`.
- `P(A)` ni uwezekano wa awali wa darasa `A`.
- `P(B)` ni uwezekano wa awali wa kipengele `B`.

Kwa mfano, ikiwa tunataka kuainisha kama maandiko yameandikwa na mtoto au mtu mzima, tunaweza kutumia maneno katika maandiko kama vipengele. Kulingana na data fulani ya awali, mchanganuzi wa Naive Bayes utahesabu awali uwezekano wa kila neno kuwa katika kila darasa linalowezekana (mtoto au mtu mzima). Wakati maandiko mapya yanapopewa, utahesabu uwezekano wa kila darasa linalowezekana kulingana na maneno katika maandiko na kuchagua darasa lenye uwezekano mkubwa zaidi.

Kama unavyoona katika mfano huu, mchanganuzi wa Naive Bayes ni rahisi sana na haraka, lakini unadhani kwamba vipengele ni huru, ambayo si kila wakati hali halisi katika data za ulimwengu halisi.

#### Aina za Mchanganuzi wa Naive Bayes

Kuna aina kadhaa za mchanganuzi wa Naive Bayes, kulingana na aina ya data na usambazaji wa vipengele:
- **Gaussian Naive Bayes**: Unadhani kwamba vipengele vinafuata usambazaji wa Gaussian (wa kawaida). Inafaa kwa data ya kuendelea.
- **Multinomial Naive Bayes**: Unadhani kwamba vipengele vinafuata usambazaji wa multinomial. Inafaa kwa data ya kutenganisha, kama vile hesabu za maneno katika uainishaji wa maandiko.
- **Bernoulli Naive Bayes**: Unadhani kwamba vipengele ni vya binary (0 au 1). Inafaa kwa data ya binary, kama vile uwepo au kutokuwepo kwa maneno katika uainishaji wa maandiko.
- **Categorical Naive Bayes**: Unadhani kwamba vipengele ni vigezo vya kategoria. Inafaa kwa data ya kategoria, kama vile kuainisha matunda kulingana na rangi na umbo lao.

#### **Sifa kuu za Naive Bayes:**

-   **Aina ya Tatizo:** Uainishaji (binary au multi-class). Inatumika sana kwa kazi za uainishaji wa maandiko katika usalama wa mtandao (spam, phishing, nk.).

-   **Ufafanuzi:** Kati -- si rahisi kueleweka kama mti wa maamuzi, lakini mtu anaweza kuchunguza uwezekano uliojifunza (kwa mfano, maneno yapi yana uwezekano mkubwa katika barua pepe za spam dhidi ya ham). Fomu ya mfano (uwezekano kwa kila kipengele kulingana na darasa) inaweza kueleweka ikiwa inahitajika.

-   **Faida:** **Haraka sana** katika mafunzo na utabiri, hata kwenye seti kubwa za data (mwelekeo katika idadi ya mifano * idadi ya vipengele). Inahitaji kiasi kidogo cha data ili kukadiria uwezekano kwa usahihi, hasa kwa kutumia ulinganifu mzuri. Mara nyingi ni sahihi sana kama msingi, hasa wakati vipengele vinachangia ushahidi kwa uhuru kwa darasa. Inafanya kazi vizuri na data yenye vipimo vingi (kwa mfano, maelfu ya vipengele kutoka kwa maandiko). Hakuna urekebishaji mgumu unaohitajika zaidi ya kuweka kipimo cha ulinganifu.

-   **Vikwazo:** Dhana ya uhuru inaweza kupunguza usahihi ikiwa vipengele vina uhusiano mkubwa. Kwa mfano, katika data ya mtandao, vipengele kama `src_bytes` na `dst_bytes` vinaweza kuwa na uhusiano; Naive Bayes haitachukua mwingiliano huo. Kadri ukubwa wa data unavyokua kuwa mkubwa, mifano yenye kueleweka zaidi (kama vile makundi au mitandao ya neva) inaweza kuzidi NB kwa kujifunza utegemezi wa vipengele. Pia, ikiwa mchanganyiko fulani wa vipengele unahitajika ili kubaini shambulio (sio tu vipengele vya kibinafsi kwa uhuru), NB itakumbana na changamoto.

> [!TIP]
> *Matumizi katika usalama wa mtandao:* Matumizi ya kawaida ni **ugunduzi wa spam** -- Naive Bayes ilikuwa msingi wa filters za spam za awali, ikitumia mara kwa mara ya alama fulani (maneno, misemo, anwani za IP) kukadiria uwezekano wa barua pepe kuwa spam. Pia inatumika katika **ugunduzi wa barua pepe za phishing** na **uainishaji wa URL**, ambapo uwepo wa maneno muhimu au sifa fulani (kama "login.php" katika URL, au `@` katika njia ya URL) unachangia uwezekano wa phishing. Katika uchambuzi wa malware, mtu anaweza kufikiria mchanganuzi wa Naive Bayes anayeweza kutumia uwepo wa wito fulani wa API au ruhusa katika programu kutabiri ikiwa ni malware. Ingawa algorithimu za kisasa mara nyingi zinafanya vizuri zaidi, Naive Bayes inabaki kuwa msingi mzuri kutokana na kasi yake na urahisi.

<details>
<summary>Mfano -- Naive Bayes kwa Ugunduzi wa Phishing:</summary>
Ili kuonyesha Naive Bayes, tutatumia Gaussian Naive Bayes kwenye seti ya data ya uvamizi ya NSL-KDD (ikiwa na lebo za binary). Gaussian NB itachukulia kila kipengele kama ikifuata usambazaji wa kawaida kwa kila darasa. Hii ni chaguo la jumla kwani vipengele vingi vya mtandao ni vya kutenganisha au vina mwelekeo mkubwa, lakini inaonyesha jinsi mtu anavyoweza kutumia NB kwa data ya kipengele cha kuendelea. Tunaweza pia kuchagua Bernoulli NB kwenye seti ya data ya vipengele vya binary (kama vile seti ya tahadhari zilizochochewa), lakini tutabaki na NSL-KDD hapa kwa ajili ya uendelevu.
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
Hii code inafundisha mchekeshaji wa Naive Bayes kugundua mashambulizi. Naive Bayes itahesabu mambo kama `P(service=http | Attack)` na `P(Service=http | Normal)` kulingana na data ya mafunzo, ikidhania uhuru kati ya vipengele. Kisha itatumia uwezekano huu kuainisha muunganisho mpya kama wa kawaida au mashambulizi kulingana na vipengele vilivyoonekana. Utendaji wa NB kwenye NSL-KDD huenda usiwe wa juu kama mifano ya hali ya juu (kwa sababu uhuru wa vipengele unakiukwa), lakini mara nyingi ni mzuri na inakuja na faida ya kasi kubwa. Katika hali kama vile kuchuja barua pepe kwa wakati halisi au uchambuzi wa awali wa URLs, mfano wa Naive Bayes unaweza haraka kuashiria kesi zenye uharibifu wazi kwa matumizi madogo ya rasilimali.

</details>

### k-Nearest Neighbors (k-NN)

k-Nearest Neighbors ni moja ya algorithms rahisi za kujifunza mashine. Ni **mbinu isiyo na vigezo, inayotegemea mifano** ambayo inafanya makadirio kulingana na ufanano na mifano katika seti ya mafunzo. Wazo la kuainisha ni: ili kuainisha kipengele kipya cha data, pata **k** vipengele vya karibu zaidi katika data ya mafunzo (majirani zake "wa karibu zaidi"), na panga darasa la wingi kati ya majirani hao. "Ukakaribu" unafafanuliwa na kipimo cha umbali, kawaida umbali wa Euclidean kwa data za nambari (umbali mwingine unaweza kutumika kwa aina tofauti za vipengele au matatizo).

K-NN inahitaji *hakuna mafunzo maalum* -- awamu ya "mafunzo" ni kuhifadhi dataset. Kazi yote inafanyika wakati wa swali (makadirio): algorithm inapaswa kuhesabu umbali kutoka kwa kipengele cha swali hadi vipengele vyote vya mafunzo ili kupata vya karibu zaidi. Hii inafanya wakati wa makadirio **kuwa sawa na idadi ya sampuli za mafunzo**, ambayo inaweza kuwa ghali kwa datasets kubwa. Kwa sababu hii, k-NN inafaa zaidi kwa datasets ndogo au hali ambapo unaweza kubadilishana kumbukumbu na kasi kwa urahisi.

Licha ya urahisi wake, k-NN inaweza kuunda mipaka ya maamuzi ngumu sana (kwa sababu kimsingi mipaka ya maamuzi inaweza kuwa na umbo lolote linaloamuliwa na usambazaji wa mifano). Inafanya vizuri wakati mipaka ya maamuzi ni isiyo ya kawaida sana na una data nyingi -- kimsingi inaruhusu data "kuzungumza yenyewe". Hata hivyo, katika dimensions za juu, vipimo vya umbali vinaweza kuwa na maana kidogo (laana ya dimensionality), na mbinu inaweza kuwa na shida isipokuwa una idadi kubwa ya sampuli.

*Matumizi katika usalama wa mtandao:* k-NN imekuwa ikitumika katika kugundua anomali -- kwa mfano, mfumo wa kugundua uvamizi unaweza kutaja tukio la mtandao kama la uharibifu ikiwa wengi wa majirani zake wa karibu (matukio ya awali) walikuwa na uharibifu. Ikiwa trafiki ya kawaida inaunda makundi na mashambulizi ni nje ya makundi, mbinu ya K-NN (ikiwa na k=1 au k ndogo) kimsingi inafanya **gundua anomali za jirani wa karibu**. K-NN pia imetumika kwa kuainisha familia za malware kwa kutumia vektori vya vipengele vya binary: faili mpya inaweza kuainishwa kama familia fulani ya malware ikiwa iko karibu sana (katika nafasi ya vipengele) na mifano inayojulikana ya familia hiyo. Katika mazoezi, k-NN si maarufu kama algorithms zinazoweza kupanuka zaidi, lakini ni rahisi kwa dhana na wakati mwingine hutumiwa kama msingi au kwa matatizo madogo.

#### **Sifa kuu za k-NN:**

-   **Aina ya Tatizo:** Uainishaji (na toleo za kurudi zipo). Ni mbinu ya *ujifunzaji mvivu* -- hakuna ulinganifu wa mfano maalum.

-   **Ufafanuzi:** Chini hadi kati -- hakuna mfano wa kimataifa au maelezo mafupi, lakini mtu anaweza kufafanua matokeo kwa kuangalia majirani wa karibu ambao walihusisha uamuzi (kwa mfano, "mtiririko huu wa mtandao ulitambuliwa kama wa uharibifu kwa sababu unafanana na mtiririko huu 3 wa uharibifu uliojulikana"). Hivyo, maelezo yanaweza kuwa ya msingi wa mifano.

-   **Faida:** Ni rahisi sana kutekeleza na kuelewa. Haina dhana kuhusu usambazaji wa data (isiyo na vigezo). Inaweza kushughulikia matatizo ya darasa nyingi kwa asili. Ni **inayoweza kubadilika** kwa maana kwamba mipaka ya maamuzi inaweza kuwa ngumu sana, ikishapingwa na usambazaji wa data.

-   **Vikwazo:** Makadirio yanaweza kuwa polepole kwa datasets kubwa (lazima kuhesabu umbali mwingi). Inahitaji kumbukumbu nyingi -- inahifadhi data zote za mafunzo. Utendaji unashuka katika nafasi za vipengele zenye dimensions za juu kwa sababu kila pointi inakuwa karibu sawa (hii inafanya dhana ya "karibu zaidi" kuwa na maana kidogo). Inahitaji kuchagua *k* (idadi ya majirani) kwa usahihi -- k ndogo sana inaweza kuwa na kelele, k kubwa sana inaweza kujumuisha pointi zisizo na maana kutoka kwa madarasa mengine. Pia, vipengele vinapaswa kupimwa ipasavyo kwa sababu hesabu za umbali zinahusiana na kiwango. 

<details>
<summary>Mfano -- k-NN kwa Kugundua Phishing:</summary>

Tutatumia tena NSL-KDD (uainishaji wa binary). Kwa sababu k-NN ni nzito kwa hesabu, tutatumia sehemu ya data ya mafunzo ili kuifanya iwe rahisi katika onyesho hili. Tutachagua, sema, sampuli 20,000 za mafunzo kutoka kwa jumla ya 125k, na kutumia k=5 majirani. Baada ya mafunzo (kwa kweli ni kuhifadhi data), tutafanya tathmini kwenye seti ya mtihani. Tutapunguza pia vipengele kwa hesabu ya umbali ili kuhakikisha hakuna kipengele kimoja kinatawala kutokana na kiwango.
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
The k-NN model itafanya uainishaji wa muunganisho kwa kuangalia muunganisho 5 wa karibu zaidi katika seti ya mafunzo. Ikiwa, kwa mfano, 4 ya majirani hao ni mashambulizi (anomalies) na 1 ni ya kawaida, muunganisho mpya utaainishwa kama shambulizi. Utendaji unaweza kuwa wa kuridhisha, ingawa mara nyingi si wa juu kama Random Forest au SVM iliyosawazishwa vizuri kwenye data hiyo hiyo. Hata hivyo, k-NN inaweza kung'ara wakati usambazaji wa darasa ni wa kawaida na mgumu -- kwa ufanisi ikitumia utafutaji wa msingi wa kumbukumbu. Katika usalama wa mtandao, k-NN (ikiwa na k=1 au k ndogo) inaweza kutumika kwa kugundua mifumo ya mashambulizi inayojulikana kwa mfano, au kama sehemu katika mifumo tata zaidi (kwa mfano, kwa kuunganisha na kisha kuainisha kulingana na uanachama wa kundi).

### Mashine za Gradient Boosting (mfano, XGBoost)

Mashine za Gradient Boosting ni miongoni mwa algorithimu zenye nguvu zaidi kwa data iliyopangwa. **Gradient boosting** inahusisha mbinu ya kujenga kundi la wanafunzi dhaifu (mara nyingi miti ya maamuzi) kwa njia ya mfululizo, ambapo kila mfano mpya unarekebisha makosa ya kundi la awali. Tofauti na bagging (Random Forests) ambayo inajenga miti kwa pamoja na kuzipatia wastani, boosting inajenga miti *moja kwa moja*, kila moja ikilenga zaidi kwenye matukio ambayo miti ya awali ilikosea kutabiri.

Mifano maarufu zaidi katika miaka ya hivi karibuni ni **XGBoost**, **LightGBM**, na **CatBoost**, ambazo zote ni maktaba za miti ya maamuzi ya gradient boosting (GBDT). Zimefanikiwa sana katika mashindano na matumizi ya kujifunza mashine, mara nyingi **zikipata utendaji wa hali ya juu kwenye seti za data za jedwali**. Katika usalama wa mtandao, watafiti na wataalamu wamezitumia miti za gradient boosted kwa kazi kama **gundua malware** (wakitumia vipengele vilivyotolewa kutoka kwa faili au tabia za wakati wa utekelezaji) na **gundua uvamizi wa mtandao**. Kwa mfano, mfano wa gradient boosting unaweza kuunganisha sheria nyingi dhaifu (miti) kama "ikiwa pakiti nyingi za SYN na bandari zisizo za kawaida -> huenda ni skana" kuwa gundua yenye nguvu inayozingatia mifumo mingi ya nyembamba.

Kwa nini miti iliyoimarishwa ni yenye ufanisi sana? Kila mti katika mfululizo unafundishwa kwenye *makosa ya mabaki* (gradients) ya utabiri wa kundi la sasa. Kwa njia hii, mfano huongeza polepole **"kuimarisha"** maeneo ambapo ni dhaifu. Matumizi ya miti ya maamuzi kama wanafunzi wa msingi yana maana kwamba mfano wa mwisho unaweza kushughulikia mwingiliano mgumu na uhusiano usio wa moja kwa moja. Pia, boosting kwa asili ina aina ya udhibiti wa ndani: kwa kuongeza miti ndogo nyingi (na kutumia kiwango cha kujifunza kubadilisha michango yao), mara nyingi inajitenga vizuri bila kuingiliwa sana, ikiwa vigezo sahihi vinachaguliwa.

#### **Sifa kuu za Gradient Boosting:**

-   **Aina ya Tatizo:** Kimsingi uainishaji na urejeleaji. Katika usalama, kawaida uainishaji (mfano, uainishe muunganisho au faili kwa njia ya binary). Inashughulikia matatizo ya binary, ya darasa nyingi (ikiwa na hasara inayofaa), na hata matatizo ya uorodheshaji.

-   **Ufafanuzi:** Chini hadi kati. Ingawa mti mmoja ulioimarishwa ni mdogo, mfano kamili unaweza kuwa na mamia ya miti, ambayo si rahisi kueleweka na binadamu kwa ujumla. Hata hivyo, kama Random Forest, inaweza kutoa alama za umuhimu wa kipengele, na zana kama SHAP (SHapley Additive exPlanations) zinaweza kutumika kufafanua utabiri wa mtu binafsi kwa kiwango fulani.

-   **Faida:** Mara nyingi ni **algorithimu inayofanya vizuri zaidi** kwa data iliyopangwa/jedwali. Inaweza kugundua mifumo na mwingiliano mgumu. Ina vidhibiti vingi vya kurekebisha (idadi ya miti, kina cha miti, kiwango cha kujifunza, masharti ya udhibiti) ili kubinafsisha ugumu wa mfano na kuzuia kuingiliwa. Mifano ya kisasa imeboreshwa kwa kasi (mfano, XGBoost inatumia taarifa za gradient za kiwango cha pili na muundo wa data mzuri). Inashughulikia data isiyo sawa vizuri zaidi inapounganishwa na kazi za hasara zinazofaa au kwa kubadilisha uzito wa sampuli.

-   **Vikwazo:** Ni ngumu zaidi kurekebisha kuliko mifano rahisi; mafunzo yanaweza kuwa polepole ikiwa miti ni mirefu au idadi ya miti ni kubwa (ingawa bado huwa haraka zaidi kuliko mafunzo ya mtandao wa neva wa kina unaofanana kwenye data hiyo hiyo). Mfano unaweza kuingiliwa ikiwa haujarekebishwa (mfano, miti mingi mirefu bila udhibiti wa kutosha). Kwa sababu ya vigezo vingi, kutumia gradient boosting kwa ufanisi kunaweza kuhitaji utaalamu zaidi au majaribio. Pia, kama mbinu za msingi za miti, haiwezi kushughulikia data ya juu isiyo na wingi kwa ufanisi kama mifano ya moja kwa moja au Naive Bayes (ingawa bado inaweza kutumika, mfano, katika uainishaji wa maandiko, lakini huenda isiwe chaguo la kwanza bila uhandisi wa kipengele).

> [!TIP]
> *Matumizi katika usalama wa mtandao:* Karibu kila mahali ambapo mti wa maamuzi au msitu wa nasibu unaweza kutumika, mfano wa gradient boosting unaweza kufikia usahihi bora. Kwa mfano, mashindano ya **gundua malware ya Microsoft** yameona matumizi makubwa ya XGBoost kwenye vipengele vilivyoundwa kutoka kwa faili za binary. Utafiti wa **gundua uvamizi wa mtandao** mara nyingi unaripoti matokeo bora na GBDTs (mfano, XGBoost kwenye seti za data za CIC-IDS2017 au UNSW-NB15). Mifano hii inaweza kuchukua anuwai kubwa ya vipengele (aina za itifaki, mara kwa mara ya matukio fulani, vipengele vya takwimu vya trafiki, nk) na kuviunganisha kugundua vitisho. Katika kugundua phishing, gradient boosting inaweza kuunganisha vipengele vya leksikali vya URLs, vipengele vya sifa za jina la kikoa, na vipengele vya maudhui ya ukurasa ili kufikia usahihi wa juu sana. Mbinu ya kundi husaidia kufunika kesi nyingi za pembe na nyembamba katika data.

<details>
<summary>Mfano -- XGBoost kwa Kugundua Phishing:</summary>
Tutatumia mfanow wa gradient boosting kwenye seti ya data ya phishing. Ili kuweka mambo kuwa rahisi na ya kujitegemea, tutatumia `sklearn.ensemble.GradientBoostingClassifier` (ambayo ni utekelezaji wa polepole lakini rahisi). Kawaida, mtu anaweza kutumia maktaba za `xgboost` au `lightgbm` kwa utendaji bora na vipengele vya ziada. Tutafundisha mfano na kuutathmini kwa njia sawa na hapo awali.
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
The gradient boosting model itakuwa na uwezekano wa kufikia usahihi wa juu sana na AUC kwenye dataset hii ya phishing (mara nyingi mifano hii inaweza kuzidi 95% usahihi kwa tuning sahihi kwenye data kama hii, kama inavyoonekana katika fasihi. Hii inaonyesha kwa nini GBDTs zinachukuliwa *"mfano wa hali ya juu kwa dataset za tabular"* -- mara nyingi zinapita algorithms rahisi kwa kushika mifumo tata. Katika muktadha wa usalama wa mtandao, hii inaweza kumaanisha kukamata tovuti zaidi za phishing au mashambulizi kwa makosa machache. Bila shaka, mtu lazima awe makini kuhusu overfitting -- kwa kawaida tungetumia mbinu kama cross-validation na kufuatilia utendaji kwenye seti ya uthibitisho tunapounda mfano kama huu kwa ajili ya kutekeleza.

</details>

### Kuunganisha Mifano: Kujifunza kwa Kundi na Stacking

Kujifunza kwa kundi ni mkakati wa **kuunganisha mifano mingi** ili kuboresha utendaji wa jumla. Tayari tumeona mbinu maalum za kundi: Random Forest (kundi la miti kupitia bagging) na Gradient Boosting (kundi la miti kupitia boosting ya mfululizo). Lakini makundi yanaweza kuundwa kwa njia nyingine pia, kama **kundi la kupiga kura** au **stacked generalization (stacking)**. Wazo kuu ni kwamba mifano tofauti inaweza kushika mifumo tofauti au kuwa na udhaifu tofauti; kwa kuunganisha, tunaweza **kurekebisha makosa ya kila mfano kwa nguvu za mwingine**.

-   **Kundi la Kupiga Kura:** Katika mcheza kura rahisi, tunafundisha mifano mingi tofauti (kama vile, regression ya logistic, mti wa maamuzi, na SVM) na kuwafanya wapige kura kwenye utabiri wa mwisho (kura nyingi kwa ajili ya uainishaji). Ikiwa tutapima kura (kwa mfano, uzito mkubwa kwa mifano sahihi zaidi), ni mpango wa kupiga kura wenye uzito. Hii kwa kawaida huongeza utendaji wakati mifano binafsi ni nzuri na huru -- kundi hupunguza hatari ya makosa ya mfano mmoja kwani wengine wanaweza kuyarekebisha. Ni kama kuwa na jopo la wataalam badala ya maoni moja.

-   **Stacking (Kundi la Stacking):** Stacking inaenda hatua zaidi. Badala ya kura rahisi, inafundisha **meta-model** ili **kujifunza jinsi ya kuunganisha bora utabiri** wa mifano ya msingi. Kwa mfano, unafundisha waainishaji 3 tofauti (wajifunzaji wa msingi), kisha unawapa matokeo yao (au uwezekano) kama vipengele kwenye meta-classifier (mara nyingi mfano rahisi kama regression ya logistic) ambayo inajifunza njia bora ya kuyachanganya. Meta-model inafundishwa kwenye seti ya uthibitisho au kupitia cross-validation ili kuepuka overfitting. Stacking mara nyingi inaweza kupita kupiga kura rahisi kwa kujifunza *mifano ipi ya kuamini zaidi katika hali zipi*. Katika usalama wa mtandao, mfano mmoja unaweza kuwa bora katika kukamata skana za mtandao wakati mwingine ni bora katika kukamata beaconing ya malware; mfano wa stacking unaweza kujifunza kutegemea kila mmoja ipasavyo.

Makundi, iwe kwa kupiga kura au stacking, huwa **yanaboresha usahihi** na uimara. Hasara ni kuongezeka kwa ugumu na wakati mwingine kupungua kwa ueleweka (ingawa baadhi ya mbinu za kundi kama wastani wa miti ya maamuzi bado zinaweza kutoa ufahamu fulani, kwa mfano, umuhimu wa kipengele). Katika mazoezi, ikiwa vikwazo vya uendeshaji vinaruhusu, kutumia kundi kunaweza kuleta viwango vya juu vya kugundua. Suluhisho nyingi za kushinda katika changamoto za usalama wa mtandao (na mashindano ya Kaggle kwa ujumla) hutumia mbinu za kundi ili kupata sehemu ya mwisho ya utendaji.

<details>
<summary>Mfano -- Kundi la Kupiga Kura kwa Kugundua Phishing:</summary>
Ili kuonyesha stacking ya mfano, hebu tuunganishe mifano kadhaa tuliyozungumzia kwenye dataset ya phishing. Tutatumia regression ya logistic, mti wa maamuzi, na k-NN kama wajifunzaji wa msingi, na kutumia Random Forest kama meta-learner ili kuunganisha utabiri wao. Meta-learner itafundishwa kwenye matokeo ya wajifunzaji wa msingi (kwa kutumia cross-validation kwenye seti ya mafunzo). Tunatarajia mfano wa stacking utendaji sawa au kidogo bora kuliko mifano binafsi.
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
The stacked ensemble inachukua faida ya nguvu za nyongeza za mifano ya msingi. Kwa mfano, regression ya logistic inaweza kushughulikia vipengele vya laini vya data, mti wa maamuzi unaweza kunasa mwingiliano maalum kama sheria, na k-NN inaweza kuwa bora katika maeneo ya ndani ya nafasi ya kipengele. Meta-modeli (msitu wa nasibu hapa) inaweza kujifunza jinsi ya kupima hizi ingizo. Vipimo vinavyotokana mara nyingi vinaonyesha kuboreshwa (hata kama ni kidogo) juu ya vipimo vya mfano mmoja. Katika mfano wetu wa phishing, ikiwa logistic pekee ilikuwa na F1 ya kusema 0.95 na mti 0.94, stack inaweza kufikia 0.96 kwa kuchukua pale ambapo kila mfano unakosea.

Mbinu za ensemble kama hizi zinaonyesha kanuni kwamba *"kuunganisha mifano mingi kawaida huleta jumla bora"*. Katika usalama wa mtandao, hii inaweza kutekelezwa kwa kuwa na injini nyingi za kugundua (moja inaweza kuwa ya msingi wa sheria, moja ya kujifunza mashine, moja ya msingi wa anomali) na kisha safu inayokusanya arifa zao -- kwa ufanisi aina ya ensemble -- kufanya uamuzi wa mwisho kwa kujiamini zaidi. Wakati wa kupeleka mifumo kama hii, lazima kuzingatia ugumu ulioongezeka na kuhakikisha kwamba ensemble haifanyi kuwa ngumu sana kudhibiti au kuelezea. Lakini kutoka kwa mtazamo wa usahihi, ensembles na stacking ni zana zenye nguvu za kuboresha utendaji wa mfano.

</details>


## References

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
