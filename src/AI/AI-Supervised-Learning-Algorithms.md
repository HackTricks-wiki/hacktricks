# Алгоритми навчання з учителем

{{#include ../banners/hacktricks-training.md}}

## Основна інформація

Навчання з учителем використовує марковані дані для навчання моделей, здатних робити передбачення на нових, раніше не бачених вхідних даних. У кібербезпеці supervised machine learning широко застосовується для таких завдань, як виявлення вторгнень (класифікація мережевого трафіку як *нормального* або *атаки*), виявлення malware (розрізнення шкідливого та безпечного програмного забезпечення), виявлення phishing (ідентифікація шахрайських вебсайтів або електронних листів) і фільтрація спаму. Кожен алгоритм має свої переваги та підходить для різних типів задач (класифікація або регресія). Нижче ми розглянемо основні алгоритми навчання з учителем, пояснимо принцип їхньої роботи та продемонструємо їх використання на реальних наборах даних із кібербезпеки. Також ми обговоримо, як поєднання моделей (ensemble learning) часто може підвищити ефективність передбачень.

## Алгоритми

-   **Linear Regression:** Фундаментальний алгоритм регресії для передбачення числових результатів шляхом підбору лінійного рівняння до даних.

-   **Logistic Regression:** Алгоритм класифікації (попри свою назву), який використовує логістичну функцію для моделювання ймовірності бінарного результату.

-   **Decision Trees:** Моделі з деревоподібною структурою, які розділяють дані за ознаками для виконання передбачень; часто використовуються завдяки своїй інтерпретованості.

-   **Random Forests:** Ансамбль decision trees (за допомогою bagging), який підвищує точність і зменшує перенавчання.

-   **Support Vector Machines (SVM):** Класифікатори з максимальним зазором, які знаходять оптимальну роздільну гіперплощину; можуть використовувати kernels для нелінійних даних.

-   **Naive Bayes:** Імовірнісний класифікатор, заснований на теоремі Bayes, із припущенням про незалежність ознак; відомий використанням у фільтрації спаму.

-   **k-Nearest Neighbors (k-NN):** Простий класифікатор на основі екземплярів, який визначає мітку зразка на основі переважного класу його найближчих сусідів.

-   **Gradient Boosting Machines:** Ансамблеві моделі (наприклад, XGBoost, LightGBM), які створюють сильний предиктор шляхом послідовного додавання слабших learner'ів (зазвичай decision trees).

Кожен наведений нижче розділ містить покращений опис алгоритму та **приклад коду Python** з використанням бібліотек на кшталт `pandas` і `scikit-learn` (а також `PyTorch` для прикладу нейронної мережі). У прикладах використовуються загальнодоступні набори даних із кібербезпеки (наприклад, NSL-KDD для виявлення вторгнень і набір даних Phishing Websites), а також дотримується узгоджена структура:

1.  **Завантажити набір даних** (завантажити через URL, якщо доступний).

2.  **Попередньо обробити дані** (наприклад, закодувати категоріальні ознаки, масштабувати значення, розділити дані на навчальний і тестовий набори).

3.  **Навчити модель** на навчальних даних.

4.  **Оцінити** на тестовому наборі за допомогою метрик: accuracy, precision, recall, F1-score і ROC AUC для класифікації (а також mean squared error для регресії).

Розгляньмо кожен алгоритм:

### Linear Regression

Linear Regression — це алгоритм **регресії**, який використовується для передбачення неперервних числових значень. Він припускає наявність лінійного зв’язку між вхідними ознаками (незалежними змінними) і вихідними даними (залежною змінною). Модель намагається підібрати пряму лінію (або гіперплощину у просторах більшої розмірності), яка найкраще описує зв’язок між ознаками та цільовим значенням. Зазвичай це виконується шляхом мінімізації суми квадратів помилок між передбаченими та фактичними значеннями (метод Ordinary Least Squares).<sup>[[8]](#references)</sup>

Найпростіше представити Linear Regression у вигляді прямої:
```plaintext
y = mx + b
```
Де:

- `y` — прогнозоване значення (вихід)
- `m` — нахил лінії (коефіцієнт)
- `x` — вхідна ознака
- `b` — y-перетин

Мета лінійної регресії — знайти найкращу лінію, яка мінімізує різницю між прогнозованими та фактичними значеннями в наборі даних. Звичайно, це дуже просто: це була б пряма лінія, що розділяє 2 категорії, але якщо додати більше вимірів, лінія стає складнішою:
```plaintext
y = w1*x1 + w2*x2 + ... + wn*xn + b
```
> [!TIP]
> *Випадки використання в cybersecurity:* сама Linear regression рідше використовується для основних завдань безпеки (які часто є задачами classification), але її можна застосовувати для прогнозування числових результатів. Наприклад, за допомогою linear regression можна **прогнозувати обсяг мережевого трафіку** або **оцінювати кількість атак за певний період** на основі історичних даних. Вона також може прогнозувати оцінку ризику або очікуваний час до виявлення атаки з огляду на певні системні метрики. На практиці алгоритми classification (наприклад, logistic regression або дерева) частіше використовуються для виявлення вторгнень чи malware, але linear regression є базовим підходом і корисна для аналізу, орієнтованого на regression.

#### **Ключові характеристики Linear Regression:**

-   **Тип задачі:** Regression (прогнозування неперервних значень). Не підходить для прямої classification, якщо до результату не застосувати порогове значення.

-   **Інтерпретованість:** Висока -- коефіцієнти легко інтерпретувати, оскільки вони показують лінійний вплив кожної ознаки.

-   **Переваги:** Простота та швидкість; хороший базовий підхід для regression-задач; добре працює, коли фактичний взаємозв'язок є приблизно лінійним.

-   **Обмеження:** Не може охопити складні або нелінійні взаємозв'язки (без ручного engineering ознак); схильна до underfitting, якщо взаємозв'язки є нелінійними; чутлива до викидів, які можуть спотворювати результати.

-   **Пошук найкращого наближення:** Щоб знайти лінію найкращого наближення, яка розділяє можливі категорії, ми використовуємо метод під назвою **Ordinary Least Squares (OLS)**. Цей метод мінімізує суму квадратів різниць між спостережуваними значеннями та значеннями, спрогнозованими лінійною моделлю.

<details>
<summary>Приклад -- прогнозування тривалості з'єднання (Regression) у наборі даних про intrusion
</summary>
Нижче ми демонструємо linear regression, використовуючи cybersecurity dataset NSL-KDD. Ми розглянемо це як regression-задачу, прогнозуючи `duration` мережевих з'єднань на основі інших ознак. (Насправді `duration` є однією з ознак NSL-KDD; тут ми використовуємо її лише для ілюстрації regression.) Ми завантажимо dataset, виконаємо його попередню обробку (закодуємо categorical features), навчимо модель linear regression і оцінимо Mean Squared Error (MSE) та показник R² на test set.
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
У цьому прикладі модель лінійної регресії намагається передбачити `duration` з'єднання на основі інших мережевих характеристик. Ми оцінюємо продуктивність за допомогою Mean Squared Error (MSE) і R². Значення R², близьке до 1.0, означало б, що модель пояснює більшу частину варіації `duration`, тоді як низьке або від'ємне значення R² вказує на погану відповідність. (Не дивуйтеся, якщо тут R² буде низьким — передбачити `duration` на основі наведених характеристик може бути складно, а лінійна регресія може не враховувати складні закономірності.)
</details>

### Logistic Regression

Logistic regression — це алгоритм **класифікації**, який моделює ймовірність належності екземпляра до певного класу (зазвичай до «позитивного» класу). Попри свою назву, *logistic* regression використовується для дискретних результатів (на відміну від лінійної регресії, яка застосовується для неперервних результатів). Вона особливо часто використовується для **бінарної класифікації** (двох класів, наприклад malicious і benign), але може бути розширена для задач із кількома класами (за допомогою softmax або підходів one-vs-rest).<sup>[[1]](#references)</sup>

Logistic regression використовує логістичну функцію (також відому як сигмоїдна функція), щоб перетворювати передбачені значення на ймовірності. Зауважте, що сигмоїдна функція має значення від 0 до 1 і зростає за S-подібною кривою відповідно до потреб класифікації, що робить її корисною для задач бінарної класифікації. Таким чином, кожна характеристика кожного вхідного об'єкта множиться на призначену їй вагу, а результат передається через сигмоїдну функцію для отримання ймовірності:
```plaintext
p(y=1|x) = 1 / (1 + e^(-z))
```
Де:

- `p(y=1|x)` — це ймовірність того, що вихід `y` дорівнює 1 за заданого входу `x`
- `e` — основа натурального логарифма
- `z` — лінійна комбінація вхідних ознак, зазвичай представлена як `z = w1*x1 + w2*x2 + ... + wn*xn + b`. Зверніть увагу, що навіть у найпростішій формі це пряма лінія, але у складніших випадках вона стає гіперплощиною з кількома вимірами (по одному на кожну ознаку).

> [!TIP]
> *Випадки використання у кібербезпеці:* Оскільки багато проблем безпеки по суті є рішеннями «так/ні», логістична регресія широко використовується. Наприклад, система виявлення вторгнень може використовувати логістичну регресію, щоб визначити, чи є мережеве з'єднання атакою, на основі його ознак. Для виявлення phishing логістична регресія може об'єднати ознаки вебсайту (довжину URL, наявність символу "@", тощо) у ймовірність того, що він є phishing. Вона використовувалася у фільтрах спаму ранніх поколінь і залишається надійним базовим методом для багатьох завдань класифікації.

#### Логістична регресія для небінарної класифікації

Логістична регресія призначена для бінарної класифікації, але її можна розширити для роботи з багатокласовими задачами за допомогою таких методів, як **one-vs-rest** (OvR) або **softmax regression**. У OvR для кожного класу навчається окрема модель логістичної регресії, яка розглядає цей клас як позитивний, а всі інші — як негативні. Як остаточний прогноз обирається клас із найвищою передбаченою ймовірністю. Softmax regression узагальнює логістичну регресію для кількох класів, застосовуючи функцію softmax до вихідного шару та формуючи розподіл імовірностей для всіх класів.

#### **Ключові характеристики логістичної регресії:**

-   **Тип задачі:** Класифікація (зазвичай бінарна). Передбачає ймовірність позитивного класу.

-   **Інтерпретованість:** Висока — як і в лінійній регресії, коефіцієнти ознак можуть показати, як кожна ознака впливає на логарифм відношення шансів результату. Ця прозорість часто цінується у сфері безпеки для розуміння того, які фактори сприяють спрацюванню.

-   **Переваги:** Простота та висока швидкість навчання; добре працює, коли зв'язок між ознаками та логарифмом відношення шансів результату є лінійним. Видає ймовірності, що дає змогу оцінювати ризик. За належної регуляризації добре узагальнюється та краще працює з мультиколінеарністю, ніж звичайна лінійна регресія.

-   **Обмеження:** Припускає наявність лінійної межі рішень у просторі ознак (не працює, якщо справжня межа є складною або нелінійною). Може показувати гірші результати в задачах, де взаємодії або нелінійні ефекти є критично важливими, якщо вручну не додати поліноміальні ознаки або ознаки взаємодії. Крім того, логістична регресія менш ефективна, якщо класи не можна легко розділити лінійною комбінацією ознак.


<details>
<summary>Приклад -- Виявлення phishing-вебсайтів за допомогою логістичної регресії:</summary>

Ми використаємо **Phishing Websites Dataset** (із репозиторію UCI), який містить виділені ознаки вебсайтів (наприклад, чи містить URL IP-адресу, вік домену, наявність підозрілих елементів у HTML тощо) і мітку, що вказує, чи є сайт phishing або легітимним. Ми навчимо модель логістичної регресії класифікувати вебсайти, а потім оцінимо її accuracy, precision, recall, F1-score і ROC AUC на тестовій вибірці.
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
У цьому прикладі виявлення phishing logistic regression генерує ймовірність того, що кожен вебсайт є phishing. Оцінюючи accuracy, precision, recall і F1, ми отримуємо уявлення про продуктивність моделі. Наприклад, високий recall означає, що вона виявляє більшість phishing-сайтів (це важливо для безпеки, щоб мінімізувати кількість пропущених атак), тоді як висока precision означає малу кількість false alarms (це важливо, щоб уникнути втоми аналітиків). ROC AUC (Area Under the ROC Curve) дає незалежну від порогу оцінку продуктивності (1.0 — ідеальний результат, 0.5 — не краще за випадкове вгадування). Logistic regression часто добре працює в таких завданнях, але якщо межа рішень між phishing- і легітимними сайтами є складною, можуть знадобитися потужніші нелінійні моделі.

</details>

### Дерева рішень

Дерево рішень — це універсальний **алгоритм навчання з учителем**, який можна використовувати як для завдань класифікації, так і для завдань регресії. Воно навчає ієрархічну деревоподібну модель рішень на основі ознак даних. Кожен внутрішній вузол дерева представляє перевірку певної ознаки, кожна гілка представляє результат цієї перевірки, а кожен листовий вузол представляє передбачений клас (для класифікації) або значення (для регресії).<sup>[[2]](#references)</sup>

Для побудови дерева алгоритми на кшталт CART (Classification and Regression Tree) використовують такі показники, як **нечистота Gini** або **інформаційний приріст (ентропія)**, щоб на кожному кроці обрати найкращу ознаку та поріг для розділення даних. Мета кожного розділення — розподілити дані так, щоб підвищити однорідність цільової змінної в отриманих підмножинах (для класифікації кожен вузол має бути якомога чистішим і переважно містити один клас).

Дерева рішень є **дуже інтерпретованими** -- можна пройти шлях від кореня до листа, щоб зрозуміти логіку передбачення (наприклад, *"IF `service = telnet` AND `src_bytes > 1000` AND `failed_logins > 3` THEN classify as attack"*). Це цінно в кібербезпеці для пояснення того, чому було створено певне сповіщення. Дерева можуть природно працювати як із числовими, так і з категоріальними даними та потребують мінімальної попередньої обробки (наприклад, масштабування ознак не потрібне).

Однак окреме дерево рішень може легко перенавчитися на навчальних даних, особливо якщо воно має велику глибину (багато розділень). Для запобігання перенавчанню часто використовують такі методи, як pruning (обмеження глибини дерева або встановлення мінімальної кількості зразків у листі).

Існує 3 основні компоненти дерева рішень:
- **Кореневий вузол**: верхній вузол дерева, що представляє весь набір даних.
- **Внутрішні вузли**: вузли, що представляють ознаки та рішення на основі цих ознак.
- **Листові вузли**: вузли, що представляють кінцевий результат або передбачення.

Дерево може зрештою виглядати так:
```plaintext
[Root Node]
/   \
[Node A]  [Node B]
/   \      /   \
[Leaf 1] [Leaf 2] [Leaf 3] [Leaf 4]
```
> [!TIP]
> *Варіанти використання в кібербезпеці:* Дерева рішень використовувалися в системах виявлення вторгнень для виведення **правил** ідентифікації атак. Наприклад, ранні IDS на основі ID3/C4.5 генерували зрозумілі для людини правила для розрізнення нормального та шкідливого трафіку. Їх також використовують під час аналізу malware, щоб визначити, чи є файл шкідливим, на основі його атрибутів (розмір файлу, entropy секцій, API-виклики тощо). Зрозумілість дерев рішень робить їх корисними, коли потрібна прозорість -- аналітик може перевірити дерево, щоб підтвердити логіку виявлення.

#### **Ключові характеристики дерев рішень:**

-   **Тип задачі:** Класифікація та регресія. Часто використовуються для класифікації атак і нормального трафіку тощо.

-   **Інтерпретованість:** Дуже висока -- рішення моделі можна візуалізувати та зрозуміти як набір правил if-then. Це значна перевага в security для довіри та перевірки поведінки моделі.

-   **Переваги:** Можуть виявляти нелінійні залежності та взаємодії між ознаками (кожне розгалуження можна розглядати як взаємодію). Немає потреби масштабувати ознаки або виконувати one-hot encoding категоріальних змінних -- дерева обробляють їх нативно. Швидкий inference (для prediction достатньо пройти шляхом дерева).

-   **Обмеження:** Схильні до overfitting, якщо їх не контролювати (глибоке дерево може запам’ятати training set). Вони можуть бути нестабільними -- невеликі зміни в даних можуть призвести до іншої структури дерева. Як окремі моделі вони можуть мати нижчу точність порівняно з сучаснішими методами (ансамблі на кшталт Random Forests зазвичай працюють краще, зменшуючи variance).

-   **Пошук найкращого розгалуження:**
- **Gini Impurity**: Вимірює неоднорідність вузла. Нижче значення Gini impurity означає краще розгалуження. Формула:

```plaintext
Gini = 1 - Σ(p_i^2)
```

Де `p_i` -- частка екземплярів, що належать до класу `i`.

- **Entropy**: Вимірює невизначеність у наборі даних. Нижче значення entropy означає краще розгалуження. Формула:

```plaintext
Entropy = -Σ(p_i * log2(p_i))
```

Де `p_i` -- частка екземплярів, що належать до класу `i`.

- **Information Gain**: Зменшення entropy або Gini impurity після розгалуження. Що вищий information gain, то краще розгалуження. Він обчислюється так:

```plaintext
Information Gain = Entropy(parent) - (Weighted Average of Entropy(children))
```

Крім того, побудова дерева завершується, коли:
- Усі екземпляри у вузлі належать до одного класу. Це може призвести до overfitting.
- Досягнуто максимальної (hardcoded) глибини дерева. Це спосіб запобігти overfitting.
- Кількість екземплярів у вузлі нижча за певний поріг. Це також спосіб запобігти overfitting.
- Information gain від подальших розгалужень нижчий за певний поріг. Це також спосіб запобігти overfitting.

<details>
<summary>Приклад -- дерево рішень для виявлення вторгнень:</summary>
Ми навчимо дерево рішень на наборі даних NSL-KDD, щоб класифікувати мережеві з’єднання як *нормальні* або *атаку*. NSL-KDD є покращеною версією класичного набору даних KDD Cup 1999 з такими ознаками, як тип протоколу, service, тривалість, кількість невдалих входів тощо, а також міткою, що вказує на тип атаки або значення "normal". Ми зіставимо всі типи атак із класом "anomaly" (бінарна класифікація: normal проти anomaly). Після навчання ми оцінимо ефективність дерева на test set.
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
У цьому прикладі дерева рішень ми обмежили глибину дерева значенням 10, щоб уникнути надмірного перенавчання (параметр `max_depth=10`). Метрики показують, наскільки добре дерево розрізняє нормальний і атакувальний трафік. Високий recall означає, що воно виявляє більшість атак (що важливо для IDS), тоді як високий precision означає малу кількість хибних спрацьовувань. Дерева рішень часто демонструють достатню точність на структурованих даних, але одне дерево може не забезпечити найкращу можливу продуктивність. Водночас *інтерпретованість* моделі є великою перевагою -- ми можемо дослідити розділення дерева, щоб побачити, наприклад, які ознаки (як-от `service`, `src_bytes` тощо) найбільше впливають на позначення з'єднання як шкідливого.

</details>

### Random Forests

Random Forest -- це метод **ансамблевого навчання**, який використовує дерева рішень для підвищення продуктивності. Random Forest навчає кілька дерев рішень (звідси й назва "ліс") і комбінує їхні результати для отримання фінального прогнозу (для класифікації зазвичай використовується голосування більшості). Дві основні ідеї Random Forest -- це **bagging** (bootstrap aggregating) і **feature randomness**:

-   **Bagging:** Кожне дерево навчається на випадковій bootstrap-вибірці навчальних даних (вибірці з поверненням). Це створює різноманітність між деревами.

-   **Feature Randomness:** Під час кожного розділення дерева для розділення розглядається випадкова підмножина ознак (замість усіх ознак). Це додатково зменшує кореляцію між деревами.

Усереднюючи результати багатьох дерев, Random Forest зменшує дисперсію, яку може мати одне дерево рішень. Простими словами, окремі дерева можуть перенавчатися або бути зашумленими, але велика кількість різноманітних дерев, що голосують разом, згладжує ці помилки. У результаті часто отримуємо модель із **вищою точністю** та кращою здатністю до узагальнення, ніж у одного дерева рішень. Крім того, Random Forest може надавати оцінку важливості ознак (через аналіз того, наскільки кожне розділення за ознакою в середньому зменшує impurity).

Random Forest стали **робочим інструментом у кібербезпеці** для таких завдань, як виявлення вторгнень, класифікація malware і виявлення spam. Вони часто добре працюють одразу, з мінімальним налаштуванням, і можуть обробляти великі набори ознак. Наприклад, у виявленні вторгнень Random Forest може перевершувати окреме дерево рішень, виявляючи більш непомітні шаблони атак із меншою кількістю false positives. Дослідження показали, що Random Forest сприятливо порівнюються з іншими алгоритмами під час класифікації атак у таких наборах даних, як NSL-KDD і UNSW-NB15.<sup>[[3]](#references)[[9]](#references)</sup>

#### **Key characteristics of Random Forests:**

-   **Type of Problem:** Переважно класифікація (також використовується для regression). Дуже добре підходить для багатовимірних структурованих даних, поширених у security logs.

-   **Interpretability:** Нижча, ніж в одного дерева рішень -- неможливо легко візуалізувати або пояснити сотні дерев одночасно. Однак оцінки важливості ознак дають певне уявлення про те, які атрибути мають найбільший вплив.

-   **Advantages:** Як правило, вища точність, ніж у моделей з одним деревом, завдяки ансамблевому ефекту. Стійкість до перенавчання -- навіть якщо окремі дерева перенавчаються, ансамбль краще узагальнює дані. Працює як із числовими, так і з категоріальними ознаками та певною мірою може обробляти відсутні дані. Також відносно стійкий до outliers.

-   **Limitations:** Розмір моделі може бути великим (багато дерев, кожне з яких потенційно може бути глибоким). Прогнози повільніші, ніж в одного дерева (оскільки потрібно агрегувати результати багатьох дерев). Менша інтерпретованість -- хоча важливі ознаки відомі, точну логіку нелегко відстежити у вигляді простого правила. Якщо набір даних надзвичайно багатовимірний і розріджений, навчання дуже великого лісу може бути обчислювально витратним.

-   **Training Process:**
1. **Bootstrap Sampling**: Випадково вибрати навчальні дані з поверненням, щоб створити кілька підмножин (bootstrap-вибірок).
2. **Tree Construction**: Для кожної bootstrap-вибірки побудувати дерево рішень, використовуючи випадкову підмножину ознак під час кожного розділення. Це створює різноманітність між деревами.
3. **Aggregation**: Для завдань класифікації фінальний прогноз отримують голосуванням більшості за прогнозами всіх дерев. Для завдань regression фінальним прогнозом є середнє значення прогнозів усіх дерев.

<details>
<summary>Example -- Random Forest for Intrusion Detection (NSL-KDD):</summary>
Ми використаємо той самий набір даних NSL-KDD (із binary labels: normal проти anomaly) і навчимо classifier Random Forest. Очікуємо, що Random Forest працюватиме не гірше або краще за окреме дерево рішень, оскільки ансамблеве усереднення зменшує дисперсію. Ми оцінимо його за допомогою тих самих метрик.
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
Випадковий ліс зазвичай демонструє високі результати в цьому завданні з виявлення вторгнень. Ми можемо спостерігати покращення таких метрик, як F1 або AUC, порівняно з одним деревом рішень, особливо щодо повноти або точності — залежно від даних. Це узгоджується з розумінням того, що *"Random Forest (RF) is an ensemble classifier and performs well compared to other traditional classifiers for effective classification of attacks."*. У контексті security operations модель випадкового лісу може надійніше виявляти атаки, одночасно зменшуючи кількість хибних спрацювань, завдяки усередненню багатьох правил прийняття рішень. Важливість ознак, отримана з лісу, може показати, які мережеві ознаки найбільше вказують на атаки (наприклад, певні мережеві сервіси або нетипова кількість пакетів).

</details>

### Машини опорних векторів (SVM)

Машини опорних векторів — це потужні моделі supervised learning, що використовуються переважно для класифікації (а також для регресії у варіанті SVR). SVM намагається знайти **оптимальну роздільну гіперплощину**, яка максимізує відступ між двома класами. Лише підмножина навчальних точок (так звані "опорні вектори", найближчі до межі) визначає положення цієї гіперплощини. Максимізація відступу (відстані між опорними векторами та гіперплощиною) зазвичай дає SVM хорошу здатність до узагальнення.<sup>[[4]](#references)</sup>

Ключовою перевагою SVM є можливість використовувати **ядерні функції** для роботи з нелінійними залежностями. Дані можна неявно перетворити у простір ознак вищої розмірності, де може існувати лінійний роздільник. До поширених ядер належать поліноміальне, радіально-базисне (RBF) і сигмоїдальне. Наприклад, якщо класи мережевого трафіку не є лінійно роздільними у вихідному просторі ознак, ядро RBF може відобразити їх у простір вищої розмірності, де SVM знайде лінійний розподіл (який відповідає нелінійній межі у вихідному просторі). Гнучкість вибору ядер дає SVM змогу розв’язувати широкий спектр задач.

Відомо, що SVM добре працюють у ситуаціях із просторами ознак високої розмірності (наприклад, для текстових даних або послідовностей opcode malware), а також у випадках, коли кількість ознак є великою порівняно з кількістю зразків. Вони були популярними в багатьох ранніх застосуваннях у сфері кібербезпеки, таких як класифікація malware та anomaly-based intrusion detection у 2000-х роках, часто демонструючи високу точність.

Однак SVM погано масштабуються до дуже великих наборів даних (складність навчання є надлінійною щодо кількості зразків, а використання пам’яті може бути значним, оскільки може знадобитися зберігати багато опорних векторів). На практиці для таких задач, як network intrusion detection із мільйонами записів, SVM може працювати надто повільно без ретельного subsampling або використання приблизних методів.

#### **Ключові характеристики SVM:**

-   **Тип задачі:** Класифікація (бінарна або multiclass через one-vs-one/one-vs-rest) і варіанти для регресії. Часто використовується у бінарній класифікації з чітким розділенням за відступом.

-   **Інтерпретованість:** Середня -- SVM не такі інтерпретовані, як дерева рішень або logistic regression. Хоча можна визначити, які точки даних є опорними векторами, і отримати певне уявлення про впливовість ознак (через ваги у випадку лінійного ядра), на практиці SVM (особливо з нелінійними ядрами) розглядаються як black-box класифікатори.

-   **Переваги:** Ефективні у просторах високої розмірності; можуть моделювати складні межі прийняття рішень за допомогою kernel trick; стійкі до перенавчання, якщо відступ максимізовано (особливо за правильного параметра регуляризації C); добре працюють навіть тоді, коли класи не розділені великою відстанню (знаходять найкращу компромісну межу).

-   **Обмеження:** **Обчислювально затратні** для великих наборів даних (масштабування як навчання, так і прогнозування є незадовільним зі зростанням обсягу даних). Потребують ретельного налаштування параметрів ядра та регуляризації (C, тип ядра, gamma для RBF тощо). Безпосередньо не надають ймовірнісних результатів (хоча для отримання ймовірностей можна використати Platt scaling). Крім того, SVM можуть бути чутливими до вибору параметрів ядра --- невдалий вибір може призвести до underfit або overfit.

*Застосування в кібербезпеці:* SVM використовувалися для **виявлення malware** (наприклад, класифікації файлів на основі витягнутих ознак або послідовностей opcode), **виявлення мережевих аномалій** (класифікації трафіку як нормального або шкідливого) і **виявлення phishing** (за допомогою ознак URL). Наприклад, SVM може отримати ознаки email (кількість певних ключових слів, оцінки репутації відправника тощо) і класифікувати його як phishing або легітимний. Їх також застосовували для **intrusion detection** на таких наборах ознак, як KDD, часто досягаючи високої точності ціною значних обчислень.

<details>
<summary>Приклад -- SVM для класифікації malware:</summary>
Ми знову використаємо набір даних вебсайтів phishing, цього разу із SVM. Оскільки SVM можуть працювати повільно, за потреби ми використаємо підмножину даних для навчання (набір даних містить близько 11 тисяч екземплярів, із якими SVM може працювати прийнятно). Ми використаємо ядро RBF, яке є поширеним вибором для нелінійних даних, і ввімкнемо оцінювання ймовірностей для розрахунку ROC AUC.
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
Модель SVM виведе метрики, які ми можемо порівняти з логістичною регресією для того самого завдання. Ми можемо виявити, що SVM досягає високих показників accuracy та AUC, якщо дані добре розділяються за ознаками. З іншого боку, якщо набір даних містить багато шуму або класи перекриваються, SVM може не продемонструвати значної переваги над логістичною регресією. На практиці SVM може дати приріст, коли між ознаками та класом існують складні нелінійні залежності — ядро RBF здатне відтворювати вигнуті межі прийняття рішень, які логістична регресія не виявила б. Як і для всіх моделей, необхідне ретельне налаштування параметра `C` (регуляризації) та параметрів ядра (наприклад, `gamma` для RBF), щоб збалансувати зміщення й дисперсію.

</details>

#### Відмінності між Logistic Regression і SVM

| Аспект | **Logistic Regression** | **Support Vector Machines** |
|---|---|---|
| **Цільова функція** | Мінімізує **log-loss** (крос-ентропію). | Максимізує **зазор**, мінімізуючи **hinge-loss**. |
| **Межа прийняття рішень** | Знаходить **найкращу гіперплощину**, яка моделює _P(y\|x)_. | Знаходить **гіперплощину з максимальним зазором** (найбільша відстань до найближчих точок). |
| **Виведення** | **Ймовірнісне** — повертає калібровані ймовірності класів через σ(w·x + b). | **Детерміноване** — повертає мітки класів; для отримання ймовірностей потрібна додаткова обробка (наприклад, Platt scaling). |
| **Регуляризація** | L2 (типово) або L1, безпосередньо врівноважує недонавчання та перенавчання. | Параметр C визначає компроміс між шириною зазору та помилковими класифікаціями; параметри ядра додають складності. |
| **Ядра / Нелінійність** | Вбудована форма є **лінійною**; нелінійність додається через конструювання ознак. | Вбудований **kernel trick** (RBF, poly тощо) дає змогу моделювати складні межі у просторі великої розмірності. |
| **Масштабованість** | Розв'язує опуклу оптимізацію за **O(nd)**; добре працює з дуже великими n. | Навчання може мати складність **O(n²–n³)** за пам'яттю/часом без спеціалізованих solver'ів; гірше підходить для величезних n. |
| **Інтерпретованість** | **Висока** — ваги показують вплив ознак; відношення шансів є інтуїтивно зрозумілим. | **Низька** для нелінійних ядер; support vectors є розрідженими, але їх нелегко пояснити. |
| **Чутливість до викидів** | Використовує плавний log-loss → менш чутлива. | Hinge-loss із жорстким зазором може бути **чутливим**; soft-margin (C) пом'якшує це. |
| **Типові випадки використання** | Кредитний скоринг, медичні ризики, A/B-тестування — коли важливі **ймовірності та зрозумілість**. | Класифікація зображень/тексту, біоінформатика — коли важливі **складні межі** та **дані великої розмірності**. |

* **Якщо вам потрібні калібровані ймовірності, інтерпретованість або робота з величезними наборами даних — обирайте Logistic Regression.**
* **Якщо вам потрібна гнучка модель, здатна виявляти нелінійні залежності без ручного конструювання ознак — обирайте SVM (з ядрами).**
* Обидві моделі оптимізують опуклі цільові функції, тому **глобальні мінімуми гарантовані**, але ядра SVM додають гіперпараметри та обчислювальні витрати.

### Naive Bayes

Naive Bayes — це сімейство **імовірнісних класифікаторів**, заснованих на застосуванні теореми Байєса із сильним припущенням незалежності між ознаками. Попри це «наївне» припущення, Naive Bayes часто демонструє напрочуд добрі результати в певних застосуваннях, особливо під час роботи з текстовими або категоріальними даними, наприклад для виявлення спаму.<sup>[[5]](#references)</sup>


#### Теорема Байєса

Теорема Байєса є основою класифікаторів Naive Bayes. Вона пов'язує умовні та маргінальні ймовірності випадкових подій. Формула має такий вигляд:
```plaintext
P(A|B) = (P(B|A) * P(A)) / P(B)
```
Де:
- `P(A|B)` — апостеріорна ймовірність класу `A` за умови ознаки `B`.
- `P(B|A)` — правдоподібність ознаки `B` за умови класу `A`.
- `P(A)` — апріорна ймовірність класу `A`.
- `P(B)` — апріорна ймовірність ознаки `B`.

Наприклад, якщо ми хочемо класифікувати, чи написаний текст дитиною або дорослим, ми можемо використовувати слова в тексті як ознаки. На основі початкових даних Naive Bayes classifier заздалегідь обчислить імовірності належності кожного слова до кожного потенційного класу (дитина або дорослий). Коли буде отримано новий текст, classifier обчислить імовірність кожного потенційного класу за словами в тексті та вибере клас із найвищою імовірністю.

Як видно з цього прикладу, Naive Bayes classifier дуже простий і швидкий, але він припускає, що ознаки є незалежними, що не завжди відповідає дійсності в реальних даних.


#### Типи Naive Bayes Classifiers

Існує кілька типів Naive Bayes classifiers, залежно від типу даних і розподілу ознак:
- **Gaussian Naive Bayes**: припускає, що ознаки мають Gaussian (normal) distribution. Підходить для неперервних даних.
- **Multinomial Naive Bayes**: припускає, що ознаки мають multinomial distribution. Підходить для дискретних даних, наприклад підрахунку слів у text classification.
- **Bernoulli Naive Bayes**: припускає, що ознаки є binary (0 або 1). Підходить для бінарних даних, наприклад наявності або відсутності слів у text classification.
- **Categorical Naive Bayes**: припускає, що ознаки є categorical variables. Підходить для категоріальних даних, наприклад класифікації фруктів за їхнім кольором і формою.


#### **Ключові характеристики Naive Bayes:**

-   **Тип задачі:** Classification (бінарна або multi-class). Зазвичай використовується для text classification tasks у cybersecurity (spam, phishing тощо).

-   **Інтерпретованість:** Середня -- він не настільки безпосередньо інтерпретований, як decision tree, але можна перевірити вивчені ймовірності (наприклад, які слова найімовірніше трапляються у spam- і ham-листах). За потреби можна зрозуміти форму моделі (ймовірності кожної ознаки за умови класу).

-   **Переваги:** **Дуже швидке** training і prediction навіть на великих датасетах (лінійна залежність від кількості екземплярів * кількості ознак). Для надійного оцінювання ймовірностей потрібно відносно мало даних, особливо за умови правильного smoothing. Часто він напрочуд точний як baseline, особливо коли ознаки незалежно додають докази на користь класу. Добре працює з high-dimensional data (наприклад, тисячами ознак із тексту). Не потребує складного tuning, окрім встановлення smoothing parameter.

-   **Обмеження:** Припущення про незалежність може обмежувати точність, якщо ознаки сильно корелюють. Наприклад, у network data такі ознаки, як `src_bytes` і `dst_bytes`, можуть корелювати; Naive Bayes не врахує цю взаємодію. Коли обсяг даних стає дуже великим, більш виразні моделі (наприклад, ensembles або neural nets) можуть перевершити NB, навчаючись на залежностях між ознаками. Крім того, якщо для ідентифікації атаки потрібне певне поєднання ознак (а не окремі незалежні ознаки), NB матиме труднощі.

> [!TIP]
> *Випадки використання в cybersecurity:* Класичний приклад — **spam detection** -- Naive Bayes був основою перших spam-фільтрів, які використовували частоти певних токенів (слів, фраз, IP-адрес), щоб обчислити ймовірність того, що email є spam. Він також використовується для **phishing email detection** і **URL classification**, де наявність певних ключових слів або характеристик (наприклад, "login.php" в URL або `@` у URL path) впливає на ймовірність phishing. У malware analysis можна уявити Naive Bayes classifier, який використовує наявність певних API calls або permissions у software, щоб передбачити, чи є воно malware. Хоча більш просунуті алгоритми часто показують кращі результати, Naive Bayes залишається хорошим baseline завдяки своїй швидкості та простоті.

<details>
<summary>Приклад -- Naive Bayes для Phishing Detection:</summary>
Щоб продемонструвати Naive Bayes, ми використаємо Gaussian Naive Bayes на intrusion dataset NSL-KDD (із binary labels). Gaussian NB розглядатиме кожну ознаку як таку, що має normal distribution для кожного класу. Це приблизний вибір, оскільки багато network features є дискретними або мають значний перекіс, але він демонструє, як застосувати NB до даних із неперервними ознаками. Ми також могли б обрати Bernoulli NB для датасету з binary features (наприклад, набору triggered alerts), але для узгодженості з попереднім матеріалом використаємо NSL-KDD.
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
Цей код навчає класифікатор Naive Bayes виявляти атаки. Naive Bayes обчислюватиме такі ймовірності, як `P(service=http | Attack)` і `P(Service=http | Normal)`, на основі навчальних даних, припускаючи незалежність між ознаками. Потім він використовуватиме ці ймовірності для класифікації нових з'єднань як нормальних або атак, спираючись на спостережувані ознаки. Продуктивність NB на NSL-KDD може бути не такою високою, як у більш просунутих моделей (оскільки незалежність ознак порушується), але вона часто є достатньою та має перевагу надзвичайно високої швидкості. У таких сценаріях, як фільтрація електронної пошти в реальному часі або первинне сортування URL-адрес, модель Naive Bayes може швидко позначати очевидно шкідливі випадки, використовуючи мало ресурсів.

</details>

### k-Nearest Neighbors (k-NN)

k-Nearest Neighbors — один із найпростіших алгоритмів машинного навчання. Це **непараметричний метод на основі екземплярів**, який робить прогнози на основі схожості з прикладами з навчального набору. Ідея класифікації полягає в тому, щоб для класифікації нової точки даних знайти **k** найближчих точок у навчальних даних (її «найближчих сусідів») і призначити їм клас, що має більшість серед цих сусідів. «Близькість» визначається метрикою відстані, зазвичай евклідовою відстанню для числових даних (для різних типів ознак або задач можна використовувати інші відстані).<sup>[[10]](#references)</sup>

Для k-NN не потрібне *явне навчання* -- фаза «навчання» полягає лише в збереженні набору даних. Уся робота виконується під час запиту (прогнозування): алгоритм має обчислити відстані від точки запиту до всіх навчальних точок, щоб знайти найближчі. Через це час прогнозування **лінійний відносно кількості навчальних прикладів**, що може бути затратним для великих наборів даних. Тому k-NN найкраще підходить для невеликих наборів даних або сценаріїв, де заради простоти можна пожертвувати пам'яттю та швидкістю.

Попри простоту, k-NN може моделювати дуже складні межі рішень (оскільки фактично межа рішення може мати будь-яку форму, визначену розподілом прикладів). Він добре працює, коли межа рішення дуже нерегулярна і є багато даних -- по суті, дозволяючи даним «говорити самим за себе». Однак у просторах високої розмірності метрики відстані можуть ставати менш змістовними (прокляття розмірності), і метод може працювати нестабільно, якщо немає величезної кількості прикладів.

*Випадки використання в кібербезпеці:* k-NN застосовувався для виявлення аномалій -- наприклад, система виявлення вторгнень може позначити мережеву подію як шкідливу, якщо більшість її найближчих сусідів (попередніх подій) були шкідливими. Якщо нормальний трафік формує кластери, а атаки є викидами, підхід K-NN (з k=1 або малим k) фактично реалізує **виявлення аномалій за найближчим сусідом**. K-NN також використовувався для класифікації сімейств malware за бінарними векторами ознак: новий файл може бути класифікований як представник певного сімейства malware, якщо він дуже близький (у просторі ознак) до відомих екземплярів цього сімейства. На практиці k-NN не такий поширений, як алгоритми, що краще масштабуються, але він концептуально простий і іноді використовується як базовий метод або для невеликих задач.

#### **Ключові характеристики k-NN:**

-   **Тип задачі:** Класифікація (також існують варіанти для регресії). Це метод *лінивого навчання* -- явне підлаштування моделі не виконується.

-   **Інтерпретованість:** Від низької до середньої -- глобальної моделі або стислого пояснення немає, але результати можна інтерпретувати, переглянувши найближчих сусідів, які вплинули на рішення (наприклад, «цей мережевий потік класифіковано як шкідливий, оскільки він схожий на ці 3 відомі шкідливі потоки»). Отже, пояснення можуть ґрунтуватися на прикладах.

-   **Переваги:** Дуже простий у реалізації та розумінні. Не робить припущень щодо розподілу даних (непараметричний). Може природно працювати із задачами багатокласової класифікації. Він **адаптивний** у тому сенсі, що межі рішень можуть бути дуже складними та формуватися розподілом даних.

-   **Обмеження:** Прогнозування може бути повільним для великих наборів даних (потрібно обчислювати багато відстаней). Потребує багато пам'яті -- зберігає всі навчальні дані. Продуктивність погіршується у просторах ознак високої розмірності, оскільки всі точки зазвичай стають майже рівновіддаленими (через що поняття «найближчий» стає менш змістовним). Потрібно правильно вибрати *k* (кількість сусідів) -- надто мале k може призвести до шумних результатів, а надто велике k може включати нерелевантні точки з інших класів. Крім того, ознаки потрібно належним чином масштабувати, оскільки обчислення відстані чутливі до масштабу.

<details>
<summary>Приклад -- k-NN для виявлення Phishing:</summary>

Ми знову використаємо NSL-KDD (бінарна класифікація). Оскільки k-NN потребує значних обчислювальних ресурсів, у цій демонстрації ми використаємо підмножину навчальних даних, щоб зберегти прийнятний час виконання. Візьмемо, наприклад, 20 000 навчальних прикладів із повного набору обсягом 125 тис. і використаємо k=5 сусідів. Після навчання (фактично лише збереження даних) ми оцінимо модель на тестовому наборі. Також масштабуємо ознаки для обчислення відстаней, щоб жодна окрема ознака не домінувала через свій масштаб.
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
Модель k-NN класифікуватиме з'єднання, переглядаючи 5 найближчих з'єднань у підмножині навчального набору. Якщо, наприклад, 4 із цих сусідів є атаками (аномаліями), а 1 є нормальним, нове з'єднання буде класифіковано як атаку. Продуктивність може бути прийнятною, хоча часто не такою високою, як у добре налаштованих Random Forest або SVM на тих самих даних. Однак k-NN іноді може добре працювати, коли розподіли класів є дуже нерегулярними та складними, фактично використовуючи пошук у пам'яті. У кібербезпеці k-NN (з k=1 або малим k) можна використовувати для виявлення відомих шаблонів атак за прикладами або як компонент складніших систем (наприклад, для кластеризації, а потім класифікації на основі належності до кластера).
</details>

### Машини градієнтного бустингу (наприклад, XGBoost)

Машини градієнтного бустингу належать до найпотужніших алгоритмів для структурованих даних. **Градієнтний бустинг** — це техніка побудови ансамблю слабких моделей (часто дерев рішень) послідовним способом, коли кожна нова модель виправляє помилки попереднього ансамблю. На відміну від bagging (Random Forest), де дерева будуються паралельно та усереднюються, boosting будує дерева *одне за одним*, і кожне з них більше зосереджується на екземплярах, які попередні дерева класифікували неправильно.

Найпопулярнішими реалізаціями останніх років є **XGBoost**, **LightGBM** і **CatBoost** — усі вони є бібліотеками дерев рішень із градієнтним бустингом (GBDT). Вони були надзвичайно успішними в змаганнях із машинного навчання та прикладних задачах, часто **досягаючи найкращих у галузі результатів на табличних наборах даних**. У кібербезпеці дослідники та практики використовували дерева з градієнтним бустингом для таких задач, як **виявлення malware** (з використанням ознак, отриманих із файлів або поведінки під час виконання) і **виявлення мережевих вторгнень**. Наприклад, модель градієнтного бустингу може об'єднати багато слабких правил (дерев), таких як «якщо є багато SYN-пакетів і незвичний порт -> ймовірно, сканування», у потужний комплексний детектор, який враховує багато непомітних шаблонів.<sup>[[6]](#references)</sup>

Чому дерева з boosting настільки ефективні? Кожне дерево в послідовності навчається на *залишкових помилках* (градієнтах) поточних прогнозів ансамблю. Таким чином, модель поступово **«підсилює»** ділянки, у яких вона є слабкою. Використання дерев рішень як базових моделей дає змогу фінальній моделі виявляти складні взаємодії та нелінійні залежності. Крім того, boosting має вбудовану форму регуляризації: додаючи багато невеликих дерев (і використовуючи швидкість навчання для масштабування їхнього внеску), він часто добре узагальнює дані без значного перенавчання, якщо вибрано належні параметри.

#### **Ключові характеристики Gradient Boosting:**

-   **Тип задачі:** Переважно класифікація та регресія. У сфері безпеки зазвичай використовується класифікація (наприклад, бінарна класифікація з'єднання або файлу). Метод підтримує бінарні, багатокласові задачі (з відповідною функцією втрат) і навіть задачі ранжування.

-   **Інтерпретованість:** Низька або середня. Хоча одне дерево з boosting є невеликим, повна модель може містити сотні дерев, тому її не можна інтерпретувати людиною як єдине ціле. Однак, як і Random Forest, вона може надавати оцінки важливості ознак, а такі інструменти, як SHAP (SHapley Additive exPlanations), можна певною мірою використовувати для інтерпретації окремих прогнозів.

-   **Переваги:** Часто є **найпродуктивнішим** алгоритмом для структурованих/табличних даних. Може виявляти складні шаблони та взаємодії. Має багато параметрів для налаштування (кількість дерев, глибина дерев, швидкість навчання, параметри регуляризації), що дає змогу адаптувати складність моделі та запобігати перенавчанню. Сучасні реалізації оптимізовані для швидкодії (наприклад, XGBoost використовує градієнтну інформацію другого порядку та ефективні структури даних). Як правило, краще працює з незбалансованими даними, якщо його поєднати з відповідними функціями втрат або налаштувати ваги зразків.

-   **Обмеження:** Його складніше налаштовувати, ніж простіші моделі; навчання може бути повільним, якщо дерева глибокі або їхня кількість велика (хоча зазвичай воно все одно швидше за навчання порівнянної глибокої нейронної мережі на тих самих даних). Якщо модель не налаштувати, вона може перенавчитися (наприклад, через надмірну кількість глибоких дерев із недостатньою регуляризацією). Через велику кількість гіперпараметрів ефективне використання градієнтного бустингу може вимагати більше досвіду або експериментів. Крім того, як і методи на основі дерев, він не обробляє дуже розріджені багатовимірні дані так само ефективно, як лінійні моделі або Naive Bayes (хоча його все ще можна застосовувати, наприклад, у класифікації тексту, але без інженерії ознак він може бути не першим вибором).

> [!TIP]
> *Випадки використання в кібербезпеці:* Майже всюди, де можна використовувати дерево рішень або random forest, модель градієнтного бустингу може забезпечити вищу точність. Наприклад, у змаганнях із **виявлення malware від Microsoft** широко використовували XGBoost для інженерно створених ознак із бінарних файлів. Дослідження **виявлення мережевих вторгнень** часто повідомляють про найкращі результати з GBDT (наприклад, XGBoost на наборах даних CIC-IDS2017 або UNSW-NB15). Ці моделі можуть приймати широкий спектр ознак (типи протоколів, частоту певних подій, статистичні характеристики трафіку тощо) та комбінувати їх для виявлення загроз. У виявленні phishing градієнтний бустинг може об'єднувати лексичні ознаки URL, характеристики репутації домену та ознаки вмісту сторінки, щоб досягати дуже високої точності. Ансамблевий підхід допомагає охопити багато крайніх випадків і тонкощів у даних.

<details>
<summary>Приклад -- XGBoost для виявлення phishing:</summary>
Ми використаємо класифікатор градієнтного бустингу на наборі даних про phishing. Щоб зберегти приклад простим і самодостатнім, ми використаємо `sklearn.ensemble.GradientBoostingClassifier` (повільнішу, але зрозумілу реалізацію). Зазвичай можна було б використати бібліотеки `xgboost` або `lightgbm` для кращої продуктивності та додаткових можливостей. Ми навчимо модель і оцінимо її подібно до попереднього прикладу.
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
Модель gradient boosting, імовірно, досягне дуже високих показників accuracy та AUC на цьому phishing dataset (часто такі моделі можуть перевищувати 95% accuracy за належного налаштування на подібних даних, як показано в наукових працях). Це демонструє, чому GBDTs вважаються *"the state of the art model for tabular dataset"* — вони часто перевершують простіші алгоритми, виявляючи складні закономірності. У контексті кібербезпеки це може означати виявлення більшої кількості phishing-сайтів або атак із меншою кількістю пропусків. Звичайно, слід остерігатися overfitting — зазвичай під час розробки такої моделі для розгортання використовують cross-validation і контролюють показники на validation set.

</details>

### Комбінування моделей: Ensemble Learning і Stacking

Ensemble learning — це стратегія **комбінування кількох моделей** для покращення загальної продуктивності. Ми вже розглядали конкретні ensemble-методи: Random Forest (ensemble дерев за допомогою bagging) і Gradient Boosting (ensemble дерев за допомогою послідовного boosting). Але ensembles можна створювати й іншими способами, наприклад за допомогою **voting ensembles** або **stacked generalization (stacking)**. Основна ідея полягає в тому, що різні моделі можуть виявляти різні закономірності або мати різні слабкі сторони; комбінуючи їх, ми можемо **компенсувати помилки кожної моделі перевагами іншої**.<sup>[[13]](#references)</sup>

-   **Voting Ensemble:** У простому voting classifier ми навчаємо кілька різноманітних моделей (наприклад, logistic regression, decision tree і SVM), після чого вони голосують за фінальне передбачення (більшість голосів для classification). Якщо зважити голоси (наприклад, надати вищу вагу точнішим моделям), отримаємо weighted voting scheme. Це зазвичай покращує продуктивність, коли окремі моделі є достатньо якісними та незалежними — ensemble зменшує ризик помилки окремої моделі, оскільки інші можуть її виправити. Це схоже на групу експертів замість однієї думки.

-   **Stacking (Stacked Ensemble):** Stacking іде ще далі. Замість простого голосування він навчає **meta-model**, щоб **навчитися найкращим чином комбінувати передбачення** базових моделей. Наприклад, ви навчаєте 3 різні classifiers (base learners), а потім передаєте їхні результати (або probabilities) як features до meta-classifier (часто це проста модель, наприклад logistic regression), яка навчається оптимальним чином їх поєднувати. Meta-model навчається на validation set або за допомогою cross-validation, щоб уникнути overfitting. Stacking часто може перевершувати просте голосування, навчаючись *яким моделям більше довіряти в різних обставинах*. У кібербезпеці одна модель може краще виявляти network scans, а інша — malware beaconing; stacking model може навчитися належним чином покладатися на кожну з них.

Ensembles — незалежно від того, використовують вони voting чи stacking — зазвичай **підвищують accuracy** і стійкість. Недоліком є підвищена складність і подекуди нижча interpretability (хоча деякі ensemble-підходи, наприклад усереднення decision trees, усе ще можуть надавати певну інформацію, зокрема feature importance). На практиці, якщо операційні обмеження це дозволяють, використання ensemble може забезпечити вищі показники виявлення. Багато найкращих рішень у змаганнях із кібербезпеки (і Kaggle competitions загалом) використовують ensemble-техніки, щоб отримати останній приріст продуктивності.

<details>
<summary>Приклад -- Voting Ensemble для виявлення phishing:</summary>
Щоб проілюструвати model stacking, об'єднаємо кілька моделей, які ми розглядали на phishing dataset. Ми використаємо logistic regression, decision tree і k-NN як base learners, а Random Forest — як meta-learner для агрегування їхніх передбачень. Meta-learner навчатиметься на результатах base learners (із використанням cross-validation на training set). Ми очікуємо, що stacked model працюватиме не гірше або буде дещо кращою за окремі моделі.
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
Стекований ensemble використовує переваги взаємодоповнювальних сильних сторін базових моделей. Наприклад, logistic regression може обробляти лінійні аспекти даних, decision tree — виявляти специфічні взаємозв’язки, подібні до правил, а k-NN — чудово працювати в локальних околицях простору ознак. Meta-model (у цьому випадку random forest) може навчитися визначати вагу цих вхідних даних. Отримані метрики часто демонструють покращення (навіть незначне) порівняно з метриками будь-якої окремої моделі. У нашому прикладі з phishing, якщо F1 для однієї logistic regression становив, наприклад, 0.95, а для tree — 0.94, то stack міг би досягти 0.96, компенсуючи помилки кожної окремої моделі.

Ensemble methods, подібні до цього, демонструють принцип: *«поєднання кількох моделей зазвичай забезпечує краще узагальнення»*. У кібербезпеці це можна реалізувати за допомогою кількох detection engines (один може бути заснований на правилах, інший — на machine learning, третій — на виявленні аномалій), а потім додати рівень, який агрегує їхні alerts -- фактично форму ensemble -- для прийняття остаточного рішення з вищою впевненістю. Під час розгортання таких систем необхідно враховувати додаткову складність і переконатися, що ensemble не стане надто складним для керування або пояснення. Однак з погляду точності ensembles і stacking є потужними інструментами для підвищення продуктивності моделей.

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
