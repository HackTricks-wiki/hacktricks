# Алгоритми навчання з учителем

{{#include ../banners/hacktricks-training.md}}

## Основна інформація

Навчання з учителем використовує дані з мітками для навчання моделей, здатних робити прогнози щодо нових, раніше не бачених вхідних даних. У кібербезпеці supervised machine learning широко застосовується для таких завдань, як виявлення вторгнень (класифікація мережевого трафіку як *нормального* або *атакуючого*), виявлення malware (розрізнення шкідливого та безпечного програмного забезпечення), виявлення phishing (ідентифікація шахрайських вебсайтів або електронних листів) і фільтрація spam тощо.<sup>[[1]](#references)</sup> Кожен алгоритм має свої переваги й підходить для різних типів задач (класифікація або регресія). Нижче ми розглянемо основні алгоритми навчання з учителем, пояснимо принцип їхньої роботи та продемонструємо їх використання на реальних наборах даних із кібербезпеки. Також ми розглянемо, як об'єднання моделей (ensemble learning) часто може підвищити якість прогнозування.

## Алгоритми

-   **Linear Regression:** Фундаментальний алгоритм регресії для прогнозування числових результатів шляхом підбору лінійного рівняння до даних.

-   **Logistic Regression:** Алгоритм класифікації (попри свою назву), який використовує логістичну функцію для моделювання ймовірності бінарного результату.

-   **Decision Trees:** Моделі з деревоподібною структурою, які розділяють дані за ознаками для виконання прогнозів; часто використовуються завдяки своїй інтерпретованості.

-   **Random Forests:** Ансамбль decision trees (за допомогою bagging), який підвищує точність і зменшує overfitting.

-   **Support Vector Machines (SVM):** Класифікатори з максимальним зазором, які знаходять оптимальну роздільну гіперплощину; можуть використовувати kernels для нелінійних даних.

-   **Naive Bayes:** Імовірнісний класифікатор на основі теореми Байєса з припущенням про незалежність ознак, відомий використанням у фільтрації spam.

-   **k-Nearest Neighbors (k-NN):** Простий класифікатор, що працює за принципом "на основі екземплярів" і визначає мітку зразка за класом, який переважає серед його найближчих сусідів.

-   **Gradient Boosting Machines:** Ансамблеві моделі (наприклад, XGBoost, LightGBM), які створюють сильний предиктор шляхом послідовного додавання слабших learner-ів (зазвичай decision trees).

Кожен наведений нижче розділ містить покращений опис алгоритму та **приклад коду Python**, що використовує такі бібліотеки, як `pandas` і `scikit-learn` (а також `PyTorch` для прикладу з neural network). У прикладах використовуються загальнодоступні набори даних із кібербезпеки (наприклад, NSL-KDD для виявлення вторгнень і набір даних Phishing Websites), а також дотримується узгоджена структура:

1.  **Завантажити набір даних** (завантажити через URL, якщо доступно).

2.  **Попередньо обробити дані** (наприклад, закодувати категоріальні ознаки, масштабувати значення, розділити дані на навчальний і тестовий набори).

3.  **Навчити модель** на навчальних даних.

4.  **Оцінити** модель на тестовому наборі за такими метриками: accuracy, precision, recall, F1-score і ROC AUC для класифікації (а також mean squared error для регресії).

Розглянемо кожен алгоритм:

### Linear Regression

Linear regression — це алгоритм **регресії**, який використовується для прогнозування неперервних числових значень. Він припускає наявність лінійного зв'язку між вхідними ознаками (незалежними змінними) та вихідним значенням (залежною змінною). Модель намагається підібрати пряму лінію (або гіперплощину у просторах вищої розмірності), яка найкраще описує зв'язок між ознаками та цільовим значенням. Зазвичай це робиться шляхом мінімізації суми квадратів похибок між прогнозованими та фактичними значеннями (метод Ordinary Least Squares).<sup>[[2]](#references)</sup>

Найпростіший спосіб представити linear regression — це пряма:
```plaintext
y = mx + b
```
Де:

- `y` — передбачене значення (вихід)
- `m` — нахил прямої (коефіцієнт)
- `x` — вхідна ознака
- `b` — перетин із віссю y

Мета лінійної регресії — знайти пряму, яка найкраще відповідає даним і мінімізує різницю між передбаченими та фактичними значеннями в наборі даних. Звичайно, у такому простому випадку це була б пряма лінія, що розділяє 2 категорії, але якщо додати більше вимірів, лінія стає складнішою:
```plaintext
y = w1*x1 + w2*x2 + ... + wn*xn + b
```
> [!TIP]
> *Випадки використання у кібербезпеці:* сама по собі лінійна регресія рідше використовується для основних завдань безпеки (які часто є задачами класифікації), але її можна застосовувати для прогнозування числових результатів. Наприклад, за допомогою лінійної регресії можна **прогнозувати обсяг мережевого трафіку** або **оцінювати кількість атак за певний період** на основі історичних даних. Вона також може прогнозувати оцінку ризику або очікуваний час до виявлення атаки за певних системних метрик. На практиці для виявлення вторгнень або malware частіше використовуються алгоритми класифікації (наприклад, logistic regression або дерева), але лінійна регресія є фундаментальним методом і корисна для аналізу, орієнтованого на регресію.

#### **Ключові характеристики Linear Regression:**

-   **Тип задачі:** Регресія (прогнозування неперервних значень). Не підходить для безпосередньої класифікації, якщо до результату не застосувати порогове значення.

-   **Інтерпретованість:** Висока -- коефіцієнти легко інтерпретувати, оскільки вони показують лінійний вплив кожної ознаки.

-   **Переваги:** Простота й швидкість; хороший базовий метод для задач регресії; добре працює, коли фактичний взаємозв'язок приблизно лінійний.

-   **Обмеження:** Не може відтворювати складні або нелінійні взаємозв'язки (без ручного конструювання ознак); схильна до недонавчання, якщо взаємозв'язки є нелінійними; чутлива до викидів, які можуть спотворювати результати.

-   **Пошук найкращого наближення:** Щоб знайти лінію найкращого наближення, яка розділяє можливі категорії, ми використовуємо метод під назвою **Ordinary Least Squares (OLS)**. Цей метод мінімізує суму квадратів різниць між спостережуваними значеннями та значеннями, спрогнозованими лінійною моделлю.

<details>
<summary>Приклад -- Прогнозування тривалості з'єднання (регресія) у наборі даних про вторгнення
</summary>
Нижче ми демонструємо використання лінійної регресії з набором даних NSL-KDD з кібербезпеки. Ми розглядатимемо це як задачу регресії, прогнозуючи `duration` мережевих з'єднань на основі інших ознак. (Насправді `duration` є однією з ознак NSL-KDD; тут ми використовуємо її лише для ілюстрації регресії.) Ми завантажимо набір даних, попередньо обробимо його (закодуємо категоріальні ознаки), навчимо модель лінійної регресії та оцінимо Mean Squared Error (MSE) і показник R² на тестовій вибірці.
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
У цьому прикладі модель лінійної регресії намагається передбачити `duration` з'єднання на основі інших мережевих ознак. Ми вимірюємо продуктивність за допомогою Mean Squared Error (MSE) і R². Значення R², близьке до 1.0, означало б, що модель пояснює більшу частину дисперсії `duration`, тоді як низьке або від'ємне значення R² вказує на погане наближення. (Не дивуйтеся, якщо R² тут буде низьким — передбачення `duration` може бути складним на основі наведених ознак, а лінійна регресія може не відтворювати закономірності, якщо вони складні.)
</details>

### Logistic Regression

Logistic regression — це алгоритм **класифікації**, який моделює ймовірність належності екземпляра до певного класу (зазвичай до "позитивного" класу). Незважаючи на свою назву, *logistic* regression використовується для дискретних результатів (на відміну від лінійної регресії, яка призначена для неперервних результатів). Вона особливо використовується для **бінарної класифікації** (двох класів, наприклад, шкідливий проти безпечного), але може бути розширена для задач із кількома класами (за допомогою підходів softmax або one-vs-rest).<sup>[[3]](#references)</sup>

Logistic regression використовує logistic function (також відому як sigmoid function), щоб перетворювати передбачені значення на ймовірності. Зверніть увагу, що sigmoid function — це функція зі значеннями від 0 до 1, яка зростає за S-подібною кривою відповідно до потреб класифікації, що робить її корисною для задач бінарної класифікації. Тому кожна ознака кожного вхідного значення множиться на призначену їй вагу, а результат передається через sigmoid function для отримання ймовірності:
```plaintext
p(y=1|x) = 1 / (1 + e^(-z))
```
Де:

- `p(y=1|x)` — це ймовірність того, що вихід `y` дорівнює 1 за заданого входу `x`
- `e` — основа натурального логарифма
- `z` — лінійна комбінація вхідних ознак, зазвичай представлена як `z = w1*x1 + w2*x2 + ... + wn*xn + b`. Зверніть увагу, що навіть у найпростішій формі це пряма лінія, але у складніших випадках вона стає гіперплощиною з кількома вимірами (по одному на кожну ознаку).

> [!TIP]
> *Використання у кібербезпеці:* Оскільки багато проблем безпеки по суті є рішеннями «так/ні», логістична регресія широко використовується. Наприклад, система виявлення вторгнень може використовувати логістичну регресію, щоб визначити, чи є мережеве з'єднання атакою, на основі його ознак. Для виявлення phishing логістична регресія може об'єднати ознаки вебсайту (довжину URL, наявність символу "@» тощо) у ймовірність того, що він є phishing-сайтом. Вона використовувалася у фільтрах спаму ранніх поколінь і досі залишається надійною базовою моделлю для багатьох завдань класифікації.

#### Логістична регресія для не бінарної класифікації

Логістична регресія призначена для бінарної класифікації, але її можна розширити для роботи з багатокласовими проблемами за допомогою таких методів, як **one-vs-rest** (OvR) або **softmax regression**. У OvR для кожного класу навчається окрема модель логістичної регресії, яка розглядає цей клас як позитивний, а всі інші — як негативні. Як остаточний результат обирається клас із найвищою передбаченою ймовірністю. Softmax regression узагальнює логістичну регресію на кілька класів, застосовуючи функцію softmax до вихідного шару та формуючи розподіл ймовірностей між усіма класами.

#### **Ключові характеристики логістичної регресії:**

-   **Тип проблеми:** Класифікація (зазвичай бінарна). Вона передбачає ймовірність позитивного класу.

-   **Інтерпретованість:** Висока — як і в лінійній регресії, коефіцієнти ознак можуть показувати, як кожна ознака впливає на логарифм шансів результату. Така прозорість часто цінується у сфері безпеки для розуміння того, які фактори сприяють появі сповіщення.

-   **Переваги:** Простота та швидкість навчання; добре працює, коли залежність між ознаками та логарифмом шансів результату є лінійною. Видає ймовірності, що дає змогу оцінювати ризик. За належної регуляризації добре узагальнюється та краще обробляє мультиколінеарність, ніж звичайна лінійна регресія.

-   **Обмеження:** Припускає лінійну межу рішення у просторі ознак (не працює, якщо справжня межа є складною/нелінійною). Може показувати гірші результати в задачах, де взаємодії або нелінійні ефекти є критично важливими, якщо вручну не додати поліноміальні ознаки або ознаки взаємодії. Крім того, логістична регресія менш ефективна, якщо класи неможливо легко розділити лінійною комбінацією ознак.


<details>
<summary>Приклад -- Виявлення phishing-сайтів за допомогою логістичної регресії:</summary>

Ми використаємо **набір даних Phishing Websites** (із репозиторію UCI), який містить вилучені ознаки вебсайтів (наприклад, чи містить URL IP-адресу, вік домену, наявність підозрілих елементів у HTML тощо) і мітку, що вказує, чи є сайт phishing-сайтом або легітимним.<sup>[[4]](#references)</sup> Ми навчимо модель логістичної регресії класифікувати вебсайти, а потім оцінимо її accuracy, precision, recall, F1-score і ROC AUC на тестовій вибірці.
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
У цьому прикладі виявлення phishing logistic regression створює ймовірність того, що кожен вебсайт є phishing. Оцінюючи accuracy, precision, recall і F1, ми отримуємо уявлення про продуктивність моделі. Наприклад, високий recall означає, що модель виявляє більшість phishing-сайтів (це важливо для безпеки, щоб мінімізувати кількість пропущених атак), тоді як висока precision означає малу кількість хибних спрацювань (це важливо, щоб уникнути втоми аналітиків). ROC AUC (Area Under the ROC Curve) дає незалежну від порогу оцінку продуктивності (1.0 — ідеальний результат, 0.5 — не краще за випадкове вгадування). Logistic regression часто добре працює в таких завданнях, але якщо межа прийняття рішень між phishing- і легітимними сайтами є складною, можуть знадобитися потужніші нелінійні моделі.

</details>

### Дерева рішень

Дерево рішень — це універсальний **алгоритм навчання з учителем**, який можна використовувати як для задач класифікації, так і для задач регресії. Воно навчає ієрархічну деревоподібну модель прийняття рішень на основі ознак даних. Кожен внутрішній вузол дерева представляє перевірку певної ознаки, кожна гілка — результат цієї перевірки, а кожен листковий вузол — передбачений клас (для класифікації) або значення (для регресії).<sup>[[5]](#references)</sup>

Для побудови дерева такі алгоритми, як CART (Classification and Regression Tree), використовують показники на кшталт **домішки Джині** або **приросту інформації (ентропії)**, щоб на кожному кроці обрати найкращу ознаку й поріг для розділення даних. Мета кожного розділення — розподілити дані так, щоб підвищити однорідність цільової змінної в отриманих підмножинах (для класифікації кожен вузол має бути якомога чистішим і містити переважно один клас).

Дерева рішень є **дуже інтерпретованими** -- можна пройти шлях від кореня до листка, щоб зрозуміти логіку, яка стоїть за передбаченням (наприклад, *"IF `service = telnet` AND `src_bytes > 1000` AND `failed_logins > 3` THEN classify as attack"*). Це цінно в кібербезпеці для пояснення причин спрацювання певного alert. Дерева можуть природно обробляти як числові, так і категоріальні дані та потребують мінімальної попередньої обробки (наприклад, масштабування ознак не потрібне).

Однак одне дерево рішень може легко перенавчитися на навчальних даних, особливо якщо воно має велику глибину (багато розділень). Для запобігання перенавчанню часто використовують такі методи, як обрізання (обмеження глибини дерева або встановлення мінімальної кількості зразків для листка).

Є 3 основні компоненти дерева рішень:
- **Кореневий вузол**: верхній вузол дерева, що представляє весь набір даних.
- **Внутрішні вузли**: вузли, що представляють ознаки та рішення на їхній основі.
- **Листкові вузли**: вузли, що представляють кінцевий результат або передбачення.

Дерево може мати такий вигляд:
```plaintext
[Root Node]
/   \
[Node A]  [Node B]
/   \      /   \
[Leaf 1] [Leaf 2] [Leaf 3] [Leaf 4]
```
> [!TIP]
> *Випадки використання у кібербезпеці:* Дерева рішень використовувалися в системах виявлення вторгнень для виведення **правил** ідентифікації атак. Наприклад, ранні IDS на основі ID3/C4.5 генерували зрозумілі для людини правила для розрізнення нормального та шкідливого трафіку. Їх також використовують під час аналізу malware, щоб визначити, чи є файл шкідливим, на основі його атрибутів (розмір файлу, ентропія секцій, виклики API тощо). Зрозумілість дерев рішень робить їх корисними, коли потрібна прозорість -- аналітик може перевірити дерево, щоб підтвердити логіку виявлення.

#### **Ключові характеристики дерев рішень:**

-   **Тип задачі:** Класифікація та регресія. Зазвичай використовуються для класифікації атак і нормального трафіку тощо.

-   **Інтерпретованість:** Дуже висока -- рішення моделі можна візуалізувати та зрозуміти як набір правил if-then. Це значна перевага у сфері безпеки для забезпечення довіри та перевірки поведінки моделі.

-   **Переваги:** Можуть виявляти нелінійні залежності та взаємодії між ознаками (кожне розділення можна розглядати як взаємодію). Немає потреби масштабувати ознаки або застосовувати one-hot encoding до категоріальних змінних -- дерева обробляють їх нативно. Швидкий inference (для передбачення достатньо пройти шляхом у дереві).

-   **Обмеження:** Схильні до overfitting, якщо їх не контролювати (глибоке дерево може запам'ятати навчальний набір). Вони можуть бути нестабільними -- невеликі зміни в даних можуть призвести до іншої структури дерева. Як окремі моделі вони можуть мати нижчу точність порівняно з більш досконалими методами (ансамблі на кшталт Random Forests зазвичай працюють краще, зменшуючи variance).

-   **Пошук найкращого розділення:**
- **Gini Impurity**: Вимірює неоднорідність вузла. Нижче значення Gini impurity вказує на краще розділення. Формула:

```plaintext
Gini = 1 - Σ(p_i^2)
```

Де `p_i` -- частка екземплярів класу `i`.

- **Entropy**: Вимірює невизначеність у наборі даних. Нижча entropy вказує на краще розділення. Формула:

```plaintext
Entropy = -Σ(p_i * log2(p_i))
```

Де `p_i` -- частка екземплярів класу `i`.

- **Information Gain**: Зменшення entropy або Gini impurity після розділення. Що вищий information gain, то краще розділення. Обчислюється так:

```plaintext
Information Gain = Entropy(parent) - (Weighted Average of Entropy(children))
```

Крім того, дерево завершується, коли:
- Усі екземпляри у вузлі належать до одного класу. Це може призвести до overfitting.
- Досягнуто максимальну (hardcoded) глибину дерева. Це спосіб запобігти overfitting.
- Кількість екземплярів у вузлі нижча за певний поріг. Це також спосіб запобігти overfitting.
- Information gain від подальших розділень нижчий за певний поріг. Це також спосіб запобігти overfitting.

<details>
<summary>Приклад -- Дерево рішень для виявлення вторгнень:</summary>
Ми навчимо дерево рішень на наборі даних NSL-KDD, щоб класифікувати мережеві з'єднання як *нормальні* або *атаку*. NSL-KDD є покращеною версією класичного набору даних KDD Cup 1999 з такими ознаками, як тип протоколу, service, тривалість, кількість невдалих входів тощо, а також міткою, що вказує на тип атаки або значення "normal". Ми зіставимо всі типи атак із класом "anomaly" (бінарна класифікація: normal або anomaly). Після навчання ми оцінимо продуктивність дерева на тестовому наборі.
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
У цьому прикладі дерева рішень ми обмежили глибину дерева значенням 10, щоб уникнути надмірного перенавчання (параметр `max_depth=10`). Метрики показують, наскільки добре дерево розрізняє нормальний і атакувальний трафік. Висока повнота (recall) означає, що воно виявляє більшість атак (що важливо для IDS), тоді як висока точність (precision) означає малу кількість хибних тривог. Дерева рішень часто забезпечують пристойну точність на структурованих даних, але одне дерево може не досягати найкращої можливої продуктивності. Водночас *інтерпретованість* моделі є великою перевагою -- ми можемо дослідити розгалуження дерева, щоб побачити, наприклад, які ознаки (наприклад, `service`, `src_bytes` тощо) найбільше впливають на позначення з'єднання як шкідливого.

</details>

### Random Forests

Random Forest -- це метод **ансамблевого навчання**, який розширює підхід дерев рішень для підвищення продуктивності. Random Forest навчає кілька дерев рішень (звідси й "ліс") і об'єднує їхні результати для отримання остаточного прогнозу (для класифікації зазвичай використовується голосування більшості). Дві основні ідеї Random Forest -- це **bagging** (bootstrap aggregating) і **випадковість ознак**:

-   **Bagging:** Кожне дерево навчається на випадковій bootstrap-вибірці навчальних даних (вибірці з поверненням). Це створює різноманітність між деревами.

-   **Випадковість ознак:** На кожному розгалуженні дерева для розділення розглядається випадкова підмножина ознак (замість усіх ознак). Це додатково зменшує кореляцію між деревами.

Усереднюючи результати багатьох дерев, Random Forest зменшує дисперсію, яку може мати одне дерево рішень. Простими словами, окремі дерева можуть перенавчатися або бути зашумленими, але велика кількість різноманітних дерев, які голосують разом, згладжує ці помилки. У результаті часто отримуємо модель із **вищою точністю** та кращою здатністю до узагальнення, ніж у одного дерева рішень. Крім того, Random Forest може надавати оцінку важливості ознак (визначаючи, наскільки кожне розділення за ознакою в середньому зменшує нечистоту).

Random Forest став **робочим інструментом у кібербезпеці** для таких завдань, як виявлення вторгнень, класифікація шкідливого програмного забезпечення та виявлення спаму. Цей метод часто добре працює одразу після запуску з мінімальним налаштуванням і може обробляти великі набори ознак. Наприклад, у виявленні вторгнень Random Forest може перевершувати окреме дерево рішень, виявляючи більш непомітні шаблони атак із меншою кількістю хибнопозитивних результатів. Дослідження показали, що Random Forest демонструє сприятливі результати порівняно з іншими алгоритмами під час класифікації атак у таких наборах даних, як NSL-KDD і UNSW-NB15.<sup>[[6]](#references)[[7]](#references)</sup>

#### **Ключові характеристики Random Forest:**

-   **Тип задачі:** Переважно класифікація (також використовується для регресії). Дуже добре підходить для багатовимірних структурованих даних, поширених у журналах безпеки.

-   **Інтерпретованість:** Нижча, ніж у одного дерева рішень -- неможливо легко візуалізувати або пояснити сотні дерев одночасно. Однак оцінки важливості ознак дають певне уявлення про те, які атрибути мають найбільший вплив.

-   **Переваги:** Загалом вища точність, ніж у моделей з одним деревом, завдяки ансамблевому ефекту. Стійкість до перенавчання -- навіть якщо окремі дерева перенавчаються, ансамбль краще узагальнює дані. Працює як із числовими, так і з категоріальними ознаками та певною мірою може обробляти пропущені дані. Також відносно стійкий до викидів.

-   **Обмеження:** Розмір моделі може бути великим (багато дерев, кожне з яких може бути глибоким). Прогнози повільніші, ніж у одного дерева (оскільки потрібно агрегувати результати багатьох дерев). Нижча інтерпретованість -- хоча важливі ознаки відомі, точну логіку нелегко відстежити так само, як просте правило. Якщо набір даних є надзвичайно багатовимірним і розрідженим, навчання дуже великого лісу може бути обчислювально витратним.

-   **Процес навчання:**
1. **Bootstrap Sampling**: Випадково вибрати навчальні дані з поверненням, щоб створити кілька підмножин (bootstrap-вибірок).
2. **Tree Construction**: Для кожної bootstrap-вибірки побудувати дерево рішень, використовуючи випадкову підмножину ознак на кожному розгалуженні. Це створює різноманітність між деревами.
3. **Aggregation**: Для задач класифікації остаточний прогноз отримують шляхом голосування більшості між прогнозами всіх дерев. Для задач регресії остаточним прогнозом є середнє значення прогнозів усіх дерев.

<details>
<summary>Приклад -- Random Forest для виявлення вторгнень (NSL-KDD):</summary>
Ми використаємо той самий набір даних NSL-KDD (із двійковими мітками: норма або аномалія) і навчимо класифікатор Random Forest. Очікуємо, що Random Forest працюватиме не гірше або краще за одне дерево рішень, оскільки ансамблеве усереднення зменшує дисперсію. Ми оцінимо його за допомогою тих самих метрик.
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
Random Forest зазвичай демонструє високі результати в цьому завданні з виявлення intrusion. Ми можемо спостерігати покращення таких метрик, як F1 або AUC, порівняно з одним decision tree, особливо щодо recall або precision, залежно від даних. Це узгоджується з розумінням того, що *"Random Forest (RF) is an ensemble classifier and performs well compared to other traditional classifiers for effective classification of attacks."*.<sup>[[6]](#references)</sup> У контексті security operations модель random forest може надійніше виявляти атаки, одночасно зменшуючи кількість false alarms, завдяки усередненню багатьох правил прийняття рішень. Feature importance з forest може показати, які мережеві ознаки найбільше вказують на атаки (наприклад, певні мережеві служби або незвичну кількість пакетів).

</details>

### Support Vector Machines (SVM)

Support Vector Machines — потужні моделі supervised learning, що використовуються переважно для classification (а також для regression як SVR). SVM намагається знайти **оптимальну роздільну гіперплощину**, яка максимізує margin між двома класами. Лише підмножина training points (так звані "support vectors", найближчі до межі) визначає положення цієї гіперплощини. Максимізація margin (відстані між support vectors і гіперплощиною) допомагає SVM досягати хорошої узагальнювальної здатності.<sup>[[8]](#references)</sup>

Ключовою перевагою SVM є можливість використовувати **kernel functions** для обробки нелінійних залежностей. Дані можна неявно перетворити у feature space вищої розмірності, де може існувати лінійний роздільник. Поширені kernels включають polynomial, radial basis function (RBF) і sigmoid. Наприклад, якщо класи мережевого трафіку не є лінійно роздільними в початковому feature space, RBF kernel може відобразити їх у простір вищої розмірності, де SVM знаходить лінійний поділ (який відповідає нелінійній межі в початковому просторі). Гнучкість вибору kernels дає змогу SVM розв'язувати різноманітні завдання.

Відомо, що SVM добре працюють у ситуаціях із feature spaces високої розмірності (наприклад, для текстових даних або послідовностей opcode у malware), а також у випадках, коли кількість features є великою порівняно з кількістю samples. У 2000-х роках вони були популярними в багатьох ранніх cybersecurity-застосунках, таких як malware classification і anomaly-based intrusion detection, часто демонструючи високу accuracy.

Однак SVM погано масштабуються до дуже великих datasets (складність training є super-linear щодо кількості samples, а використання memory може бути значним, оскільки може знадобитися зберігати багато support vectors). На практиці для таких завдань, як network intrusion detection із мільйонами records, SVM може бути надто повільним без ретельного subsampling або використання approximate methods.

#### **Key characteristics of SVM:**

-   **Type of Problem:** Classification (binary або multiclass за допомогою one-vs-one/one-vs-rest) і варіанти regression. Часто використовується для binary classification із чітким розділенням margin.

-   **Interpretability:** Середня -- SVM не такі інтерпретовані, як decision trees або logistic regression. Хоча можна визначити, які data points є support vectors, і отримати певне уявлення про те, які features можуть бути впливовими (через weights у випадку linear kernel), на практиці SVM (особливо з non-linear kernels) розглядаються як black-box classifiers.

-   **Advantages:** Ефективні у feature spaces високої розмірності; можуть моделювати складні decision boundaries за допомогою kernel trick; стійкі до overfitting, якщо margin максимізовано (особливо з належним regularization parameter C); добре працюють навіть тоді, коли класи не розділені великою відстанню (знаходять найкращу компромісну межу).

-   **Limitations:** **Computationally intensive** для великих datasets (і training, і prediction погано масштабуються зі збільшенням обсягу даних). Потребують ретельного налаштування kernel і regularization parameters (C, kernel type, gamma для RBF тощо). Безпосередньо не надають probabilistic outputs (хоча для отримання probabilities можна використовувати Platt scaling). Крім того, SVM можуть бути чутливими до вибору kernel parameters --- невдалий вибір може призвести до underfit або overfit.

*Use cases in cybersecurity:* SVM використовувалися для **malware detection** (наприклад, класифікації files на основі extracted features або opcode sequences), **network anomaly detection** (класифікації traffic як normal або malicious) і **phishing detection** (із використанням features URL). Наприклад, SVM може отримувати features email (кількість певних keywords, sender reputation scores тощо) і класифікувати його як phishing або legitimate. Їх також застосовували для **intrusion detection** на таких feature sets, як KDD, часто досягаючи високої accuracy ціною обчислювальних ресурсів.

<details>
<summary>Example -- SVM for Malware Classification:</summary>
Цього разу ми знову використаємо dataset із phishing websites, але вже з SVM. Оскільки SVM можуть працювати повільно, за потреби ми використаємо підмножину даних для training (dataset містить близько 11k instances, із якими SVM може працювати достатньо ефективно). Ми використаємо RBF kernel, який є поширеним вибором для нелінійних даних, і ввімкнемо probability estimates для обчислення ROC AUC.
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
Модель SVM видасть метрики, які можна порівняти з Logistic Regression для того самого завдання. Ми можемо виявити, що SVM досягає високих показників accuracy та AUC, якщо дані добре розділяються за ознаками. І навпаки, якщо набір даних містить багато шуму або класи перекриваються, SVM може не мати значної переваги над Logistic Regression. На практиці SVM може забезпечити покращення, коли між ознаками та класом існують складні нелінійні залежності — ядро RBF здатне моделювати криволінійні межі рішень, які Logistic Regression не виявить. Як і для всіх моделей, необхідне ретельне налаштування `C` (regularization) і параметрів ядра (наприклад, `gamma` для RBF), щоб збалансувати bias і variance.

</details>

#### Відмінності між Logistic Regression і SVM

| Aspect | **Logistic Regression** | **Support Vector Machines** |
|---|---|---|
| **Цільова функція** | Мінімізує **log-loss** (перехресну ентропію). | Максимізує **margin**, одночасно мінімізуючи **hinge-loss**. |
| **Межа рішень** | Знаходить **гіперплощину найкращого наближення**, яка моделює _P(y\|x)_. | Знаходить **гіперплощину з максимальним margin** (найбільшим проміжком до найближчих точок). |
| **Вивід** | **Ймовірнісний** — надає калібровані ймовірності класів через σ(w·x + b). | **Детермінований** — повертає мітки класів; для отримання ймовірностей потрібна додаткова обробка (наприклад, Platt scaling). |
| **Regularisation** | L2 (за замовчуванням) або L1, безпосередньо врівноважує under/over-fitting. | Параметр C визначає компроміс між шириною margin і помилковими класифікаціями; параметри ядра додають складності. |
| **Kernels / Non-linear** | Вбудована форма є **лінійною**; нелінійність додається за допомогою feature engineering. | Вбудований **kernel trick** (RBF, poly тощо) дає змогу моделювати складні межі у high-dimensional просторі. |
| **Масштабованість** | Розв’язує опуклу оптимізацію за **O(nd)**; добре працює з дуже великими n. | Навчання може мати складність **O(n²–n³)** за пам’яттю/часом без спеціалізованих розв’язувачів; гірше підходить для величезних n. |
| **Інтерпретованість** | **Висока** — ваги показують вплив ознак; odds ratio легко інтерпретувати. | **Низька** для нелінійних ядер; support vectors є розрідженими, але їх нелегко пояснити. |
| **Чутливість до викидів** | Використовує плавний log-loss → менш чутлива. | Hinge-loss із hard margin може бути **чутливим**; soft-margin (C) пом’якшує цей ефект. |
| **Типові випадки використання** | Credit scoring, медичний ризик, A/B testing — коли важливі **ймовірності та пояснюваність**. | Класифікація зображень/тексту, bio-informatics — коли важливі **складні межі** та **high-dimensional data**. |

* **Якщо вам потрібні калібровані ймовірності, інтерпретованість або робота з величезними наборами даних — обирайте Logistic Regression.**
* **Якщо вам потрібна гнучка модель, здатна виявляти нелінійні залежності без ручного feature engineering — обирайте SVM (з ядрами).**
* Обидві моделі оптимізують опуклі цільові функції, тому **глобальні мінімуми гарантовані**, але ядра SVM додають hyper-parameters і обчислювальні витрати.

### Naive Bayes

Naive Bayes — це сімейство **ймовірнісних класифікаторів**, що базуються на застосуванні теореми Байєса із сильним припущенням про незалежність ознак. Попри це «наївне» припущення, Naive Bayes часто працює напрочуд добре для певних застосувань, особливо пов’язаних із текстовими або категоріальними даними, наприклад для виявлення спаму.<sup>[[9]](#references)</sup>


#### Теорема Байєса

Теорема Байєса є основою класифікаторів Naive Bayes. Вона пов’язує умовні та маргінальні ймовірності випадкових подій. Формула має вигляд:
```plaintext
P(A|B) = (P(B|A) * P(A)) / P(B)
```
Де:
- `P(A|B)` — апостеріорна ймовірність класу `A` за умови ознаки `B`.
- `P(B|A)` — правдоподібність ознаки `B` за умови класу `A`.
- `P(A)` — апріорна ймовірність класу `A`.
- `P(B)` — апріорна ймовірність ознаки `B`.

Наприклад, якщо ми хочемо класифікувати, чи написаний текст дитиною або дорослим, ми можемо використовувати слова в тексті як ознаки. На основі початкових даних класифікатор Naive Bayes заздалегідь обчислить імовірності належності кожного слова до кожного потенційного класу (дитина або дорослий). Коли буде отримано новий текст, він обчислить імовірність кожного потенційного класу з урахуванням слів у тексті та вибере клас із найвищою імовірністю.

Як видно з цього прикладу, класифікатор Naive Bayes дуже простий і швидкий, але він припускає, що ознаки є незалежними, що не завжди відповідає дійсності в реальних даних.


#### Типи класифікаторів Naive Bayes

Існує кілька типів класифікаторів Naive Bayes — залежно від типу даних і розподілу ознак:
- **Gaussian Naive Bayes**: Припускає, що ознаки мають Gaussian (нормальний) розподіл. Підходить для неперервних даних.
- **Multinomial Naive Bayes**: Припускає, що ознаки мають мультиноміальний розподіл. Підходить для дискретних даних, таких як кількість слів у класифікації тексту.
- **Bernoulli Naive Bayes**: Припускає, що ознаки є бінарними (0 або 1). Підходить для бінарних даних, таких як наявність або відсутність слів у класифікації тексту.
- **Categorical Naive Bayes**: Припускає, що ознаки є категоріальними змінними. Підходить для категоріальних даних, наприклад для класифікації фруктів за їхнім кольором і формою.


#### **Ключові характеристики Naive Bayes:**

-   **Тип задачі:** Класифікація (бінарна або багатокласова). Часто використовується для задач класифікації тексту в кібербезпеці (spam, phishing тощо).

-   **Інтерпретованість:** Середня -- модель не така безпосередньо зрозуміла, як дерево рішень, але можна перевірити вивчені ймовірності (наприклад, які слова найімовірніше трапляються у spam- і ham-листах). За потреби структуру моделі (імовірності кожної ознаки за умови класу) можна зрозуміти.

-   **Переваги:** **Дуже швидке** навчання та прогнозування навіть на великих наборах даних (лінійне відносно кількості екземплярів * кількості ознак). Для надійного оцінювання ймовірностей потрібно відносно мало даних, особливо за умови правильного згладжування. Часто цей алгоритм напрочуд точний як базова модель, особливо коли ознаки незалежно додають докази на користь класу. Добре працює з багатовимірними даними (наприклад, із тисячами ознак, отриманих із тексту). Не потребує складого налаштування, крім встановлення параметра згладжування.

-   **Обмеження:** Припущення про незалежність може обмежувати точність, якщо ознаки сильно корельовані. Наприклад, у мережевих даних такі ознаки, як `src_bytes` і `dst_bytes`, можуть бути корельованими; Naive Bayes не врахує цю взаємодію. Коли обсяг даних стає дуже великим, більш виразні моделі (наприклад, ансамблі або нейронні мережі) можуть перевершити NB, навчаючись на залежностях між ознаками. Крім того, якщо для ідентифікації атаки потрібне певне поєднання ознак, а не лише незалежний внесок окремих ознак, NB матиме труднощі.

> [!TIP]
> *Випадки використання в кібербезпеці:* Класичний приклад використання — **виявлення spam** -- Naive Bayes був основою перших spam-фільтрів, які використовували частоти певних токенів (слів, фраз, IP-адрес), щоб обчислити ймовірність того, що email є spam. Також він використовується для **виявлення phishing у email** і **класифікації URL**, де наявність певних ключових слів або характеристик (наприклад, "login.php" в URL чи `@` у шляху URL) впливає на ймовірність phishing. У malware analysis можна уявити класифікатор Naive Bayes, який використовує наявність певних API-викликів або дозволів у програмному забезпеченні, щоб спрогнозувати, чи є воно malware. Хоча більш просунуті алгоритми часто працюють краще, Naive Bayes залишається хорошою базовою моделлю завдяки швидкості та простоті.

<details>
<summary>Приклад -- Naive Bayes для виявлення phishing:</summary>
Щоб продемонструвати Naive Bayes, ми використаємо Gaussian Naive Bayes на наборі даних про вторгнення NSL-KDD (із бінарними мітками). Gaussian NB розглядатиме кожну ознаку як таку, що має нормальний розподіл для кожного класу. Це приблизний вибір, оскільки багато мережевих ознак є дискретними або мають сильно асиметричний розподіл, але він показує, як застосувати NB до даних із неперервними ознаками. Ми також могли б вибрати Bernoulli NB для набору даних із бінарними ознаками (наприклад, набору активованих alert), але для узгодженості продовжимо використовувати NSL-KDD.
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
Цей код навчає класифікатор Naive Bayes для виявлення атак. Naive Bayes обчислюватиме такі величини, як `P(service=http | Attack)` і `P(Service=http | Normal)`, на основі навчальних даних, припускаючи незалежність ознак. Потім він використовуватиме ці ймовірності для класифікації нових з'єднань як нормальних або атакувальних на основі спостережуваних ознак. Продуктивність NB на NSL-KDD може бути не такою високою, як у більш просунутих моделей (оскільки припущення про незалежність ознак порушується), але вона часто є достатньою та має перевагу у вигляді надзвичайно високої швидкості. У таких сценаріях, як фільтрація електронної пошти в реальному часі або первинне сортування URL, модель Naive Bayes може швидко позначати явно шкідливі випадки, використовуючи мало ресурсів.

</details>

### k-Nearest Neighbors (k-NN)

k-Nearest Neighbors — один із найпростіших алгоритмів машинного навчання. Це **непараметричний метод на основі екземплярів**, який робить прогнози на основі схожості з прикладами з навчального набору. Ідея класифікації полягає в такому: щоб класифікувати нову точку даних, потрібно знайти **k** найближчих точок у навчальних даних (її «найближчих сусідів») і призначити їй клас, що становить більшість серед цих сусідів. «Близькість» визначається метрикою відстані, зазвичай евклідовою відстанню для числових даних (для різних типів ознак або задач можна використовувати інші відстані).<sup>[[10]](#references)</sup>

K-NN не потребує *явного навчання* — фаза «навчання» полягає лише у збереженні набору даних. Уся робота виконується під час запиту (прогнозування): алгоритм має обчислити відстані від точки запиту до всіх навчальних точок, щоб знайти найближчі. Через це час прогнозування **лінійно залежить від кількості навчальних зразків**, що може бути витратним для великих наборів даних. Тому k-NN найкраще підходить для невеликих наборів даних або сценаріїв, де заради простоти можна обміняти пам'ять і швидкість на простоту.

Попри простоту, k-NN може моделювати дуже складні межі прийняття рішень (оскільки фактично межа прийняття рішень може мати будь-яку форму, визначену розподілом прикладів). Він добре працює, коли межа прийняття рішень дуже нерегулярна і є багато даних — фактично дозволяючи даним «говорити самим за себе». Однак у просторах високої розмірності метрики відстані можуть ставати менш інформативними (прокляття розмірності), і метод може працювати нестабільно, якщо немає величезної кількості зразків.

*Варіанти використання у кібербезпеці:* k-NN застосовували для виявлення аномалій — наприклад, система виявлення вторгнень може позначити мережеву подію як шкідливу, якщо більшість її найближчих сусідів (попередніх подій) були шкідливими. Якщо нормальний трафік формує кластери, а атаки є викидами, підхід K-NN (з k=1 або малим k) фактично виконує **виявлення аномалій за найближчим сусідом**. K-NN також використовували для класифікації сімейств malware за бінарними векторами ознак: новий файл може бути класифікований як представник певного сімейства malware, якщо він дуже близький (у просторі ознак) до відомих екземплярів цього сімейства. На практиці k-NN не такий поширений, як алгоритми, що краще масштабуються, але він концептуально простий і іноді використовується як базовий метод або для задач невеликого масштабу.

#### **Ключові характеристики k-NN:**

-   **Тип задачі:** Класифікація (також існують варіанти для регресії). Це метод *лінивого навчання* — явне підганяння моделі не виконується.

-   **Інтерпретованість:** Низька або середня — немає глобальної моделі чи стислого пояснення, але результати можна інтерпретувати, переглянувши найближчих сусідів, які вплинули на рішення (наприклад, «цей мережевий потік класифіковано як шкідливий, оскільки він схожий на ці 3 відомі шкідливі потоки»). Отже, пояснення можуть ґрунтуватися на прикладах.

-   **Переваги:** Дуже простий у реалізації та розумінні. Не робить припущень щодо розподілу даних (непараметричний). Природно підтримує задачі з кількома класами. Він **адаптивний** у тому сенсі, що межі прийняття рішень можуть бути дуже складними й формуватися розподілом даних.

-   **Обмеження:** Прогнозування може бути повільним для великих наборів даних (потрібно обчислювати багато відстаней). Потребує багато пам'яті — зберігає всі навчальні дані. У просторах ознак високої розмірності продуктивність погіршується, оскільки всі точки зазвичай стають майже рівновіддаленими (через що поняття «найближчого» стає менш змістовним). Потрібно правильно вибрати *k* (кількість сусідів) — надто мале k може призвести до шумних результатів, а надто велике k може включати нерелевантні точки інших класів. Крім того, ознаки потрібно належним чином масштабувати, оскільки обчислення відстаней чутливі до масштабу.

<details>
<summary>Приклад — k-NN для виявлення Phishing:</summary>

Ми знову використаємо NSL-KDD (бінарна класифікація). Оскільки k-NN потребує значних обчислювальних ресурсів, у цій демонстрації ми використаємо підмножину навчальних даних, щоб зберегти прийнятний час обробки. Візьмемо, наприклад, 20 000 навчальних зразків із повного набору у 125 тис. і використаємо k=5 сусідів. Після навчання (фактично лише збереження даних) ми оцінимо модель на тестовому наборі. Також масштабуємо ознаки для обчислення відстаней, щоб жодна окрема ознака не домінувала через свій масштаб.
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
Модель k-NN класифікує з'єднання, переглядаючи 5 найближчих з'єднань у підмножині навчального набору. Якщо, наприклад, 4 із цих сусідів є атаками (аномаліями), а 1 — нормальним, нове з'єднання буде класифіковано як атака. Продуктивність може бути прийнятною, хоча часто не такою високою, як у добре налаштованих Random Forest або SVM на тих самих даних. Однак k-NN іноді добре працює, коли розподіли класів є дуже нерегулярними та складними — фактично використовуючи пошук у пам'яті. У кібербезпеці k-NN (з k=1 або малим k) можна використовувати для виявлення відомих шаблонів атак за прикладами або як компонент складніших систем (наприклад, для кластеризації, а потім класифікації на основі належності до кластера).
</details>

### Gradient Boosting Machines (наприклад, XGBoost)

Gradient Boosting Machines є одними з найпотужніших алгоритмів для структурованих даних. **Gradient boosting** — це техніка побудови ансамблю слабких моделей (часто дерев рішень) послідовно, де кожна нова модель виправляє помилки попереднього ансамблю. На відміну від bagging (Random Forest), де дерева будуються паралельно та усереднюються, boosting будує дерева *одне за одним*, і кожне з них більше зосереджується на екземплярах, які попередні дерева класифікували неправильно.<sup>[[11]](#references)</sup>

Найпопулярнішими реалізаціями останніх років є **XGBoost**, **LightGBM** і **CatBoost** — усі вони є бібліотеками gradient boosting decision tree (GBDT). Вони надзвичайно успішні у змаганнях з машинного навчання та практичних застосуваннях, часто **досягаючи найкращої на сьогодні продуктивності на табличних наборах даних**. У кібербезпеці дослідники та практики використовують дерева з gradient boosting для таких завдань, як **виявлення malware** (із використанням ознак, отриманих із файлів або поведінки під час виконання) і **виявлення мережевих вторгнень**. Наприклад, модель gradient boosting може об'єднати багато слабких правил (дерев), таких як «якщо є багато SYN-пакетів і незвичний порт -> імовірно, сканування», у потужний комплексний детектор, який враховує безліч тонких шаблонів.

Чому boosted trees настільки ефективні? Кожне дерево в послідовності навчається на *залишкових помилках* (градієнтах) поточних прогнозів ансамблю. Таким чином модель поступово **«підсилює»** області, у яких вона слабка. Використання дерев рішень як базових моделей дає змогу фінальній моделі захоплювати складні взаємодії та нелінійні залежності. Крім того, boosting за своєю суттю має певну вбудовану регуляризацію: додавання багатьох малих дерев (і використання learning rate для масштабування їхнього внеску) часто забезпечує хорошу узагальнювальну здатність без значного перенавчання, за умови правильного вибору параметрів.

#### **Ключові характеристики Gradient Boosting:**

-   **Тип задачі:** Переважно класифікація та регресія. У security зазвичай використовується класифікація (наприклад, бінарна класифікація з'єднання або файлу). Підтримує бінарні, багатокласові задачі (з відповідною функцією втрат) і навіть задачі ранжування.

-   **Інтерпретованість:** Низька або середня. Хоча окреме boosted tree є невеликим, повна модель може містити сотні дерев, тому її загалом важко інтерпретувати людині. Однак, як і Random Forest, вона може надавати оцінки важливості ознак, а такі інструменти, як SHAP (SHapley Additive exPlanations), дають змогу певною мірою інтерпретувати окремі прогнози.

-   **Переваги:** Часто є алгоритмом із **найкращою продуктивністю** для структурованих/табличних даних. Може виявляти складні шаблони та взаємодії. Має багато параметрів для налаштування (кількість дерев, глибина дерев, learning rate, параметри регуляризації), що дає змогу адаптувати складність моделі та запобігати перенавчанню. Сучасні реалізації оптимізовані для швидкодії (наприклад, XGBoost використовує градієнтну інформацію другого порядку та ефективні структури даних). Як правило, краще працює з незбалансованими даними в поєднанні з відповідними функціями втрат або за умови коригування ваг зразків.

-   **Обмеження:** Налаштування складніше, ніж у простіших моделей; навчання може бути повільним, якщо дерева глибокі або їхня кількість велика (хоча зазвичай воно все одно швидше за навчання аналогічної deep neural network на тих самих даних). Модель може перенавчитися, якщо її не налаштувати (наприклад, за надто великої кількості глибоких дерев і недостатньої регуляризації). Через велику кількість hyperparameters ефективне використання gradient boosting може вимагати більшої експертизи або експериментів. Крім того, як і tree-based методи, він не має вбудованої здатності так само ефективно обробляти дуже розріджені багатовимірні дані, як linear models або Naive Bayes (хоча його можна застосовувати, наприклад, у класифікації тексту, але без feature engineering це може бути не першим вибором).

> [!TIP]
> *Випадки використання в кібербезпеці:* Майже всюди, де можна застосувати дерево рішень або random forest, модель gradient boosting може забезпечити вищу точність. Наприклад, у змаганнях із **виявлення malware від Microsoft** широко використовували XGBoost для інженерно створених ознак бінарних файлів. У дослідженнях **виявлення мережевих вторгнень** GBDT часто демонструють найкращі результати (наприклад, XGBoost на наборах даних CIC-IDS2017 або UNSW-NB15). Ці моделі можуть приймати широкий спектр ознак (типи протоколів, частоту певних подій, статистичні характеристики трафіку тощо) та комбінувати їх для виявлення загроз. У виявленні phishing gradient boosting може поєднувати лексичні ознаки URL, ознаки репутації домену та ознаки вмісту сторінки, забезпечуючи дуже високу точність. Ансамблевий підхід допомагає охопити безліч крайніх випадків і тонких особливостей у даних.

<details>
<summary>Приклад -- XGBoost для виявлення phishing:</summary>
Ми використаємо класифікатор gradient boosting на наборі даних phishing. Щоб зберегти приклад простим і самодостатнім, скористаємося `sklearn.ensemble.GradientBoostingClassifier` (повільнішою, але зрозумілою реалізацією). Зазвичай можна було б використовувати бібліотеки `xgboost` або `lightgbm` для кращої продуктивності та додаткових можливостей. Ми навчимо модель і оцінимо її аналогічно до попереднього прикладу.
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
Модель gradient boosting, імовірно, досягне дуже високих показників accuracy та AUC на цьому phishing dataset (часто такі моделі після належного налаштування можуть перевищувати 95% accuracy на подібних даних, як показано в наукових роботах. Це демонструє, чому GBDT вважаються *«найсучаснішою моделлю для табличних наборів даних»* -- вони часто перевершують простіші алгоритми, оскільки здатні виявляти складні закономірності.<sup>[[11]](#references)</sup> У контексті кібербезпеки це може означати виявлення більшої кількості phishing-сайтів або атак із меншою кількістю пропусків. Звісно, потрібно остерігатися перенавчання -- зазвичай під час розробки такої моделі для deployment ми використовуємо такі методи, як cross-validation, і відстежуємо performance на validation set.

</details>

### Комбінування моделей: Ensemble Learning і Stacking

Ensemble learning -- це стратегія **комбінування кількох моделей** для покращення загальної performance. Ми вже розглянули конкретні ensemble-методи: Random Forest (ensemble дерев за допомогою bagging) і Gradient Boosting (ensemble дерев за допомогою послідовного boosting). Але ensembles можна створювати й іншими способами, наприклад за допомогою **voting ensembles** або **stacked generalization (stacking)**. Основна ідея полягає в тому, що різні моделі можуть виявляти різні закономірності або мати різні слабкі місця; комбінуючи їх, ми можемо **компенсувати помилки кожної моделі сильними сторонами іншої**.<sup>[[12]](#references)</sup>

-   **Voting Ensemble:** У простому voting classifier ми навчаємо кілька різнопланових моделей (наприклад, logistic regression, decision tree і SVM), а потім даємо їм проголосувати за фінальний prediction (більшість голосів для classification). Якщо зважувати голоси (наприклад, надавати більшу вагу точнішим моделям), це називається weighted voting scheme. Зазвичай це покращує performance, коли окремі моделі є достатньо якісними та незалежними -- ensemble зменшує ризик помилки окремої моделі, оскільки інші можуть її виправити. Це схоже на залучення групи експертів замість однієї думки.

-   **Stacking (Stacked Ensemble):** Stacking робить ще один крок уперед. Замість простого голосування він навчає **meta-model**, щоб **вона навчилася найкращим чином комбінувати predictions** базових моделей. Наприклад, ви навчаєте 3 різні classifiers (base learners), а потім передаєте їхні outputs (або probabilities) як features до meta-classifier (часто це проста модель, наприклад logistic regression), яка навчається оптимально їх комбінувати. Meta-model навчається на validation set або за допомогою cross-validation, щоб уникнути перенавчання. Stacking часто може перевершувати просте голосування, навчаючись *визначати, яким моделям більше довіряти за певних обставин*. У кібербезпеці одна модель може краще виявляти network scans, тоді як інша -- malware beaconing; stacking-модель може навчитися належним чином покладатися на кожну з них.

Ensembles, створені за допомогою voting або stacking, зазвичай **підвищують accuracy** і robustness. Недоліком є зростання складності та інколи зниження interpretability (хоча деякі ensemble-підходи, наприклад усереднення decision trees, усе ще можуть надавати певну інформацію, як-от feature importance). На практиці, якщо operational constraints це дозволяють, використання ensemble може забезпечити вищі detection rates. Багато найкращих рішень у cybersecurity challenges (і Kaggle competitions загалом) використовують ensemble-техніки, щоб отримати останні додаткові відсотки performance.

<details>
<summary>Приклад -- Voting Ensemble для виявлення phishing:</summary>
Щоб продемонструвати model stacking, поєднаємо кілька моделей, які ми розглядали, на phishing dataset. Ми використаємо logistic regression, decision tree і k-NN як base learners, а Random Forest -- як meta-learner для агрегації їхніх predictions. Meta-learner буде навчено на outputs базових learners (із використанням cross-validation на training set). Ми очікуємо, що stacked model покаже таку саму або дещо кращу performance, ніж окремі моделі.
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
Стекований ensemble використовує взаємодоповнювальні сильні сторони базових моделей. Наприклад, logistic regression може обробляти лінійні аспекти даних, decision tree — виявляти специфічні взаємодії, подібні до правил, а k-NN — ефективно працювати з локальними околицями простору ознак. Meta-model (у цьому випадку random forest) може навчитися визначати вагу цих вхідних даних. Отримані метрики часто демонструють покращення (навіть незначне) порівняно з метриками будь-якої окремої моделі. У нашому прикладі з phishing, якщо F1 для logistic regression дорівнював, скажімо, 0.95, а для tree — 0.94, то stack міг би досягти 0.96, компенсуючи помилки кожної моделі.

Ensemble methods на кшталт цього демонструють принцип: *«поєднання кількох моделей зазвичай забезпечує кращу здатність до узагальнення»*.<sup>[[12]](#references)</sup> У cybersecurity це можна реалізувати за допомогою кількох detection engines (один може бути rule-based, інший — machine learning, ще один — anomaly-based), а потім додати рівень, який агрегує їхні alerts — фактично форму ensemble — щоб ухвалювати остаточне рішення з вищою впевненістю. Під час розгортання таких систем необхідно враховувати додаткову складність і переконатися, що ensemble не стане надто складним для керування або пояснення. Однак з погляду точності ensembles і stacking є потужними інструментами для підвищення продуктивності моделей.

</details>

## Посилання

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
