# Supervised Learning Algorithms

{{#include ../banners/hacktricks-training.md}}

## Basic Information

Supervised learning uses labeled data to train models that can make predictions on new, unseen inputs. In cybersecurity, supervised machine learning is widely applied to tasks such as intrusion detection (classifying network traffic as *normal* or *attack*), malware detection (distinguishing malicious software from benign), phishing detection (identifying fraudulent websites or emails), and spam filtering, among others. Each algorithm has its strengths and is suited to different types of problems (classification or regression). Below we review key supervised learning algorithms, explain how they work, and demonstrate their use on real cybersecurity datasets. We also discuss how combining models (ensemble learning) can often improve predictive performance.

## Algorithms

-   **Linear Regression:** A fundamental regression algorithm for predicting numeric outcomes by fitting a linear equation to data.

-   **Logistic Regression:** A classification algorithm (despite its name) that uses a logistic function to model the probability of a binary outcome.

-   **Decision Trees:** Tree-structured models that split data by features to make predictions; often used for their interpretability.

-   **Random Forests:** An ensemble of decision trees (via bagging) that improves accuracy and reduces overfitting.

-   **Support Vector Machines (SVM):** Max-margin classifiers that find the optimal separating hyperplane; can use kernels for non-linear data.

-   **Naive Bayes:** A probabilistic classifier based on Bayes' theorem with an assumption of feature independence, famously used in spam filtering.

-   **k-Nearest Neighbors (k-NN):** A simple "instance-based" classifier that labels a sample based on the majority class of its nearest neighbors.

-   **Gradient Boosting Machines:** Ensemble models (e.g., XGBoost, LightGBM) that build a strong predictor by sequentially adding weaker learners (typically decision trees).

Each section below provides an improved description of the algorithm and a **Python code example** using libraries like `pandas` and `scikit-learn` (and `PyTorch` for the neural network example). The examples use publicly available cybersecurity datasets (such as NSL-KDD for intrusion detection and a Phishing Websites dataset) and follow a consistent structure:

1.  **Load the dataset** (download via URL if available).

2.  **Preprocess the data** (e.g. encode categorical features, scale values, split into train/test sets).

3.  **Train the model** on the training data.

4.  **Evaluate** on a test set using metrics: accuracy, precision, recall, F1-score, and ROC AUC for classification (and mean squared error for regression).

Let's dive into each algorithm:

### Linear Regression

Linear regression is a **regression** algorithm used to predict continuous numeric values. It assumes a linear relationship between the input features (independent variables) and the output (dependent variable). The model attempts to fit a straight line (or hyperplane in higher dimensions) that best describes the relationship between features and the target. This is typically done by minimizing the sum of squared errors between predicted and actual values (Ordinary Least Squares method).

The simplest for to represent linear regression is with a line:

```plaintext
y = mx + b
```

Where:

- `y` is the predicted value (output)
- `m` is the slope of the line (coefficient)
- `x` is the input feature
- `b` is the y-intercept

The goal of linear regression is to find the best-fitting line that minimizes the difference between the predicted values and the actual values in the dataset. Of course, this is very simple, it would be a straight line sepparating 2 categories, but if more dimensions are added, the line becomes more complex:

```plaintext
y = w1*x1 + w2*x2 + ... + wn*xn + b
```

> [!TIP]
> *Use cases in cybersecurity:* Linear regression itself is less common for core security tasks (which are often classification), but it can be applied to predict numerical outcomes. For example, one could use linear regression to **predict the volume of network traffic** or **estimate the number of attacks in a time period** based on historical data. It could also predict a risk score or the expected time until detection of an attack, given certain system metrics. In practice, classification algorithms (like logistic regression or trees) are more frequently used for detecting intrusions or malware, but linear regression serves as a foundation and is useful for regression-oriented analyses.

#### **Key characteristics of Linear Regression:**

-   **Type of Problem:** Regression (predicting continuous values). Not suited for direct classification unless a threshold is applied to the output.

-   **Interpretability:** High -- coefficients are straightforward to interpret, showing the linear effect of each feature.

-   **Advantages:** Simple and fast; a good baseline for regression tasks; works well when the true relationship is approximately linear.

-   **Limitations:** Can't capture complex or non-linear relationships (without manual feature engineering); prone to underfitting if relationships are non-linear; sensitive to outliers which can skew the results.

-   **Finding the Best Fit:** To find the best fit line that sepparates the possible categories, we use a method called **Ordinary Least Squares (OLS)**. This method minimizes the sum of the squared differences between the observed values and the values predicted by the linear model.

<details>
<summary>Example -- Predicting Connection Duration (Regression) in an Intrusion Dataset
</summary>
Below we demonstrate linear regression using the NSL-KDD cybersecurity dataset. We'll treat this as a regression problem by predicting the `duration` of network connections based on other features. (In reality, `duration` is one feature of NSL-KDD; we use it here just to illustrate regression.) We load the dataset, preprocess it (encode categorical features), train a linear regression model, and evaluate the Mean Squared Error (MSE) and R² score on a test set.


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

In this example, the linear regression model tries to predict connection `duration` from other network features. We measure performance with Mean Squared Error (MSE) and R². An R² close to 1.0 would indicate the model explains most variance in `duration`, whereas a low or negative R² indicates a poor fit. (Don't be surprised if the R² is low here -- predicting `duration` might be difficult from the given features, and linear regression may not capture the patterns if they are complex.)
</details>

### Logistic Regression

Logistic regression is a **classification** algorithm that models the probability that an instance belongs to a particular class (typically the "positive" class). Despite its name, *logistic* regression is used for discrete outcomes (unlike linear regression which is for continuous outcomes). It is especially used for **binary classification** (two classes, e.g., malicious vs. benign), but it can be extended to multi-class problems (using softmax or one-vs-rest approaches).

The logistic regression uses the logistic function (also known as the sigmoid function) to map predicted values to probabilities. Note that the sigmoid function is a function with values between 0 and 1 that grows in a S-shaped curve according to the needs of the classification, which is useful for binary classification tasks. Therefore, each feature of each input is multiplied by its assigned weight, and the result is passed through the sigmoid function to produce a probability:

```plaintext
p(y=1|x) = 1 / (1 + e^(-z))
```

Where:

- `p(y=1|x)` is the probability that the output `y` is 1 given the input `x`
- `e` is the base of the natural logarithm
- `z` is a linear combination of the input features, typically represented as `z = w1*x1 + w2*x2 + ... + wn*xn + b`. Note how again in it simplest form it is a straight line, but in more complex cases it becomes a hyperplane with several dimensiones (one per feature).

> [!TIP]
> *Use cases in cybersecurity:* Because many security problems are essentially yes/no decisions, logistic regression is widely used. For instance, an intrusion detection system might use logistic regression to decide if a network connection is an attack based on features of that connection. In phishing detection, logistic regression can combine features of a website (URL length, presence of "@" symbol, etc.) into a probability of being phishing. It has been used in early-generation spam filters and remains a strong baseline for many classification tasks.

#### Logistic Regression for non binary classification

Logistic regression is designed for binary classification, but it can be extended to handle multi-class problems using techniques like **one-vs-rest** (OvR) or **softmax regression**. In OvR, a separate logistic regression model is trained for each class, treating it as the positive class against all others. The class with the highest predicted probability is chosen as the final prediction. Softmax regression generalizes logistic regression to multiple classes by applying the softmax function to the output layer, producing a probability distribution over all classes.

#### **Key characteristics of Logistic Regression:**

-   **Type of Problem:** Classification (usually binary). It predicts the probability of the positive class.

-   **Interpretability:** High -- like linear regression, the feature coefficients can indicate how each feature influences the log-odds of the outcome. This transparency is often appreciated in security for understanding which factors contribute to an alert.

-   **Advantages:** Simple and fast to train; works well when the relationship between features and log-odds of the outcome is linear. Outputs probabilities, enabling risk scoring. With appropriate regularization, it generalizes well and can handle multicollinearity better than plain linear regression.

-   **Limitations:** Assumes a linear decision boundary in feature space (fails if the true boundary is complex/non-linear). It may underperform on problems where interactions or non-linear effects are critical, unless you manually add polynomial or interaction features. Also, logistic regression is less effective if classes are not easily separable by a linear combination of features.


<details>
<summary>Example -- Phishing Website Detection with Logistic Regression:</summary>

We'll use a **Phishing Websites Dataset** (from the UCI repository) which contains extracted features of websites (like whether the URL has an IP address, the age of the domain, presence of suspicious elements in HTML, etc.) and a label indicating if the site is phishing or legitimate. We train a logistic regression model to classify websites and then evaluate its accuracy, precision, recall, F1-score, and ROC AUC on a test split.

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

In this phishing detection example, logistic regression produces a probability for each website being phishing. By evaluating accuracy, precision, recall, and F1, we get a sense of the model's performance. For instance, a high recall would mean it catches most phishing sites (important for security to minimize missed attacks), while high precision means it has few false alarms (important to avoid analyst fatigue). The ROC AUC (Area Under the ROC Curve) gives a threshold-independent measure of performance (1.0 is ideal, 0.5 is no better than chance). Logistic regression often performs well on such tasks, but if the decision boundary between phishing and legitimate sites is complex, more powerful non-linear models might be needed.

</details>

### Decision Trees

A decision tree is a versatile **supervised learning algorithm** that can be used for both classification and regression tasks. It learns a hierarchical tree-like model of decisions based on the features of the data. Each internal node of the tree represents a test on a particular feature, each branch represents an outcome of that test, and each leaf node represents a predicted class (for classification) or value (for regression).

To build a tree, algorithms like CART (Classification and Regression Tree) use measures such as **Gini impurity** or **information gain (entropy)** to choose the best feature and threshold to split the data at each step. The goal at each split is to partition the data to increase the homogeneity of the target variable in the resulting subsets (for classification, each node aims to be as pure as possible, containing predominantly a single class).

Decision trees are **highly interpretable** -- one can follow the path from root to leaf to understand the logic behind a prediction (e.g., *"IF `service = telnet` AND `src_bytes > 1000` AND `failed_logins > 3` THEN classify as attack"*). This is valuable in cybersecurity for explaining why a certain alert was raised. Trees can naturally handle both numerical and categorical data and require little preprocessing (e.g., feature scaling is not needed).

However, a single decision tree can easily overfit the training data, especially if grown deep (many splits). Techniques like pruning (limiting tree depth or requiring a minimum number of samples per leaf) are often used to prevent overfitting.

There are 3 main components of a decision tree:
- **Root Node**: The top node of the tree, representing the entire dataset.
- **Internal Nodes**: Nodes that represent features and decisions based on those features.
- **Leaf Nodes**: Nodes that represent the final outcome or prediction.

A tree might end up looking like this:

```plaintext
          [Root Node]
              /   \
         [Node A]  [Node B]
          /   \      /   \
     [Leaf 1] [Leaf 2] [Leaf 3] [Leaf 4]
```

> [!TIP]
> *Use cases in cybersecurity:* Decision trees have been used in intrusion detection systems to derive **rules** for identifying attacks. For example, early IDS like ID3/C4.5-based systems would generate human-readable rules to distinguish normal vs. malicious traffic. They are also used in malware analysis to decide if a file is malicious based on its attributes (file size, section entropy, API calls, etc.). The clarity of decision trees makes them useful when transparency is needed -- an analyst can inspect the tree to validate the detection logic.

#### **Key characteristics of Decision Trees:**

-   **Type of Problem:** Both classification and regression. Commonly used for classification of attacks vs. normal traffic, etc.

-   **Interpretability:** Very high -- the model's decisions can be visualized and understood as a set of if-then rules. This is a major advantage in security for trust and verification of model behavior.

-   **Advantages:** Can capture non-linear relationships and interactions between features (each split can be seen as an interaction). No need to scale features or one-hot encode categorical variables -- trees handle those natively. Fast inference (prediction is just following a path in the tree).

-   **Limitations:** Prone to overfitting if not controlled (a deep tree can memorize the training set). They can be unstable -- small changes in data might lead to a different tree structure. As single models, their accuracy might not match more advanced methods (ensembles like Random Forests typically perform better by reducing variance).

-   **Finding the Best Split:**
  - **Gini Impurity**: Measures the impurity of a node. A lower Gini impurity indicates a better split. The formula is:
  
  ```plaintext
  Gini = 1 - Σ(p_i^2)
  ```

  Where `p_i` is the proportion of instances in class `i`.
  
  - **Entropy**: Measures the uncertainty in the dataset. A lower entropy indicates a better split. The formula is:

  ```plaintext
  Entropy = -Σ(p_i * log2(p_i))
  ```

  Where `p_i` is the proportion of instances in class `i`.
  
  - **Information Gain**: The reduction in entropy or Gini impurity after a split. The higher the information gain, the better the split. It is calculated as:

  ```plaintext
  Information Gain = Entropy(parent) - (Weighted Average of Entropy(children))
  ```

Moreover, a tree is ended when:
- All instances in a node belong to the same class. This might lead to overfitting.
- The maximum depth (hardcoded) of the tree is reached. This is a way to prevent overfitting.
- The number of instances in a node is below a certain threshold. This is also a way to prevent overfitting.
- The information gain from further splits is below a certain threshold. This is also a way to prevent overfitting.

<details>
<summary>Example -- Decision Tree for Intrusion Detection:</summary>
We'll train a decision tree on the NSL-KDD dataset to classify network connections as either *normal* or *attack*. NSL-KDD is an improved version of the classic KDD Cup 1999 dataset, with features like protocol type, service, duration, number of failed logins, etc., and a label indicating the attack type or "normal". We will map all attack types to an "anomaly" class (binary classification: normal vs anomaly). After training, we'll evaluate the tree's performance on the test set.


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

In this decision tree example, we limited the tree depth to 10 to avoid extreme overfitting (the `max_depth=10` parameter). The metrics show how well the tree distinguishes normal vs. attack traffic. A high recall would mean it catches most attacks (important for an IDS), while high precision means few false alarms. Decision trees often achieve decent accuracy on structured data, but a single tree might not reach the best performance possible. Nonetheless, the *interpretability* of the model is a big plus -- we could examine the tree's splits to see, for instance, which features (e.g., `service`, `src_bytes`, etc.) are most influential in flagging a connection as malicious.

</details>

### Random Forests

Random Forest is an **ensemble learning** method that builds upon decision trees to improve performance. A random forest trains multiple decision trees (hence "forest") and combines their outputs to make a final prediction (for classification, typically by majority vote). The two main ideas in a random forest are **bagging** (bootstrap aggregating) and **feature randomness**:

-   **Bagging:** Each tree is trained on a random bootstrap sample of the training data (sampled with replacement). This introduces diversity among the trees.

-   **Feature Randomness:** At each split in a tree, a random subset of features is considered for splitting (instead of all features). This further decorrelates the trees.

By averaging the results of many trees, the random forest reduces the variance that a single decision tree might have. In simple terms, individual trees might overfit or be noisy, but a large number of diverse trees voting together smooths out those errors. The result is often a model with **higher accuracy** and better generalization than a single decision tree. In addition, random forests can provide an estimate of feature importance (by looking at how much each feature split reduces impurity on average).

Random forests have become a **workhorse in cybersecurity** for tasks like intrusion detection, malware classification, and spam detection. They often perform well out-of-the-box with minimal tuning and can handle large feature sets. For example, in intrusion detection, a random forest may outperform an individual decision tree by catching more subtle patterns of attacks with fewer false positives. Research has shown random forests performing favorably compared to other algorithms in classifying attacks in datasets like NSL-KDD and UNSW-NB15.

#### **Key characteristics of Random Forests:**

-   **Type of Problem:** Primarily classification (also used for regression). Very well-suited for high-dimensional structured data common in security logs.

-   **Interpretability:** Lower than a single decision tree -- you can't easily visualize or explain hundreds of trees at once. However, feature importance scores provide some insight into which attributes are most influential.

-   **Advantages:** Generally higher accuracy than single-tree models due to ensemble effect. Robust to overfitting -- even if individual trees overfit, the ensemble generalizes better. Handles both numerical and categorical features and can manage missing data to some extent. It's also relatively robust to outliers.

-   **Limitations:** Model size can be large (many trees, each potentially deep). Predictions are slower than a single tree (as you must aggregate over many trees). Less interpretable -- while you know important features, the exact logic isn't easily traceable as a simple rule. If the dataset is extremely high-dimensional and sparse, training a very large forest can be computationally heavy.

-   **Training Process:**
  1. **Bootstrap Sampling**: Randomly sample the training data with replacement to create multiple subsets (bootstrap samples).
  2. **Tree Construction**: For each bootstrap sample, build a decision tree using a random subset of features at each split. This introduces diversity among the trees.
  3. **Aggregation**: For classification tasks, the final prediction is made by taking a majority vote among the predictions of all trees. For regression tasks, the final prediction is the average of the predictions from all trees.

<details>
<summary>Example -- Random Forest for Intrusion Detection (NSL-KDD):</summary>
We'll use the same NSL-KDD dataset (binary labeled as normal vs anomaly) and train a Random Forest classifier. We expect the random forest to perform as well as or better than the single decision tree, thanks to the ensemble averaging reducing variance. We'll evaluate it with the same metrics.


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

The random forest typically achieves strong results on this intrusion detection task. We might observe an improvement in metrics like F1 or AUC compared to the single decision tree, especially in recall or precision, depending on the data. This aligns with the understanding that *"Random Forest (RF) is an ensemble classifier and performs well compared to other traditional classifiers for effective classification of attacks."*. In a security operations context, a random forest model might more reliably flag attacks while reducing false alarms, thanks to the averaging of many decision rules. Feature importance from the forest could tell us which network features are most indicative of attacks (e.g., certain network services or unusual counts of packets).

</details>

### Support Vector Machines (SVM)

Support Vector Machines are powerful supervised learning models used primarily for classification (and also regression as SVR). An SVM tries to find the **optimal separating hyperplane** that maximizes the margin between two classes. Only a subset of training points (the "support vectors" closest to the boundary) determines the position of this hyperplane. By maximizing the margin (distance between support vectors and the hyperplane), SVMs tend to achieve good generalization.

Key to SVM's power is the ability to use **kernel functions** to handle non-linear relationships. The data can be implicitly transformed into a higher-dimensional feature space where a linear separator might exist. Common kernels include polynomial, radial basis function (RBF), and sigmoid. For example, if network traffic classes aren't linearly separable in the raw feature space, an RBF kernel can map them into a higher dimension where the SVM finds a linear split (which corresponds to a non-linear boundary in original space). The flexibility of choosing kernels allows SVMs to tackle a variety of problems.

SVMs are known to perform well in situations with high-dimensional feature spaces (like text data or malware opcode sequences) and in cases where the number of features is large relative to number of samples. They were popular in many early cybersecurity applications such as malware classification and anomaly-based intrusion detection in the 2000s, often showing high accuracy.

However, SVMs do not scale easily to very large datasets (training complexity is super-linear in number of samples, and memory usage can be high since it may need to store many support vectors). In practice, for tasks like network intrusion detection with millions of records, SVM might be too slow without careful subsampling or using approximate methods.

#### **Key characteristics of SVM:**

-   **Type of Problem:** Classification (binary or multiclass via one-vs-one/one-vs-rest) and regression variants. Often used in binary classification with clear margin separation.

-   **Interpretability:** Medium -- SVMs are not as interpretable as decision trees or logistic regression. While you can identify which data points are support vectors and get some sense of which features might be influential (through the weights in the linear kernel case), in practice SVMs (especially with non-linear kernels) are treated as black-box classifiers.

-   **Advantages:** Effective in high-dimensional spaces; can model complex decision boundaries with kernel trick; robust to overfitting if margin is maximized (especially with a proper regularization parameter C); works well even when classes are not separated by a large distance (finds best compromise boundary).

-   **Limitations:** **Computationally intensive** for large datasets (both training and prediction scale poorly as data grows). Requires careful tuning of kernel and regularization parameters (C, kernel type, gamma for RBF, etc.). Doesn't directly provide probabilistic outputs (though one can use Platt scaling to get probabilities). Also, SVMs can be sensitive to the choice of kernel parameters --- a poor choice can lead to underfit or overfit.

*Use cases in cybersecurity:* SVMs have been used in **malware detection** (e.g., classifying files based on extracted features or opcode sequences), **network anomaly detection** (classifying traffic as normal vs malicious), and **phishing detection** (using features of URLs). For instance, an SVM could take features of an email (counts of certain keywords, sender reputation scores, etc.) and classify it as phishing or legitimate. They have also been applied to **intrusion detection** on feature sets like KDD, often achieving high accuracy at the cost of computation.

<details>
<summary>Example -- SVM for Malware Classification:</summary>
We'll use the phishing website dataset again, this time with an SVM. Because SVMs can be slow, we'll use a subset of the data for training if needed (the dataset is about 11k instances, which SVM can handle reasonably). We'll use an RBF kernel which is a common choice for non-linear data, and we'll enable probability estimates to calculate ROC AUC.

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

The SVM model will output metrics that we can compare to logistic regression on the same task. We might find that SVM achieves a high accuracy and AUC if the data is well-separated by the features. On the flip side, if the dataset had a lot of noise or overlapping classes, SVM might not significantly outperform logistic regression. In practice, SVMs can give a boost when there are complex, non-linear relations between features and class -- the RBF kernel can capture curved decision boundaries that logistic regression would miss. As with all models, careful tuning of the `C` (regularization) and kernel parameters (like `gamma` for RBF) is needed to balance bias and variance.

</details>

#### Difference Logistic Rergessions & SVM

| Aspect | **Logistic Regression** | **Support Vector Machines** |
|---|---|---|
| **Objective function** | Minimises **log‑loss** (cross‑entropy). | Maximises the **margin** while minimising **hinge‑loss**. |
| **Decision boundary** | Finds the **best‑fit hyperplane** that models _P(y\|x)_. | Finds the **maximum‑margin hyperplane** (largest gap to the closest points). |
| **Output** | **Probabilistic** – gives calibrated class probabilities via σ(w·x + b). | **Deterministic** – returns class labels; probabilities need extra work (e.g. Platt scaling). |
| **Regularisation** | L2 (default) or L1, directly balances under/over‑fitting. | C parameter trades off margin width vs. mis‑classifications; kernel parameters add complexity. |
| **Kernels / Non‑linear** | Native form is **linear**; non‑linearity added by feature engineering. | Built‑in **kernel trick** (RBF, poly, etc.) lets it model complex boundaries in high‑dim. space. |
| **Scalability** | Solves a convex optimisation in **O(nd)**; handles very large n well. | Training can be **O(n²–n³)** memory/time without specialised solvers; less friendly to huge n. |
| **Interpretability** | **High** – weights show feature influence; odds ratio intuitive. | **Low** for non‑linear kernels; support vectors are sparse but not easy to explain. |
| **Sensitivity to outliers** | Uses smooth log‑loss → less sensitive. | Hinge‑loss with hard margin can be **sensitive**; soft‑margin (C) mitigates. |
| **Typical use cases** | Credit scoring, medical risk, A/B testing – where **probabilities & explainability** matter. | Image/text classification, bio‑informatics – where **complex boundaries** and **high‑dimensional data** matter. |

* **If you need calibrated probabilities, interpretability, or operate on huge datasets — choose Logistic Regression.**
* **If you need a flexible model that can capture non‑linear relations without manual feature engineering — choose SVM (with kernels).**
* Both optimise convex objectives, so **global minima are guaranteed**, but SVM’s kernels add hyper‑parameters and computational cost.

### Naive Bayes

Naive Bayes is a family of **probabilistic classifiers** based on applying Bayes' Theorem with a strong independence assumption between features. Despite this "naive" assumption, Naive Bayes often works surprisingly well for certain applications, especially those involving text or categorical data, such as spam detection.


#### Bayes' Theorem

Bayes' theorem is the foundation of Naive Bayes classifiers. It relates the conditional and marginal probabilities of random events. The formula is:

```plaintext
P(A|B) = (P(B|A) * P(A)) / P(B)
```

Where:
- `P(A|B)` is the posterior probability of class `A` given feature `B`.
- `P(B|A)` is the likelihood of feature `B` given class `A`.
- `P(A)` is the prior probability of class `A`.
- `P(B)` is the prior probability of feature `B`.

For example, if we want to classify whether a text is written by a child or an adult, we can use the words in the text as features. Based on some initial data, the Naive Bayes classifier will previously calculate the probabilities of each word being on each potential class (child or adult). When a new text is given, it will calculate the probability of each potential class given the words in the text and choose the class with the highest probability.

As you can see in this example, the Naive Bayes classifier is very simple and fast, but it assumes that the features are independent, which is not always the case in real-world data.


#### Types of Naive Bayes Classifiers

There are several types of Naive Bayes classifiers, depending on the type of data and the distribution of the features:
- **Gaussian Naive Bayes**: Assumes that the features follow a Gaussian (normal) distribution. It is suitable for continuous data.
- **Multinomial Naive Bayes**: Assumes that the features follow a multinomial distribution. It is suitable for discrete data, such as word counts in text classification.
- **Bernoulli Naive Bayes**: Assumes that the features are binary (0 or 1). It is suitable for binary data, such as presence or absence of words in text classification.
- **Categorical Naive Bayes**: Assumes that the features are categorical variables. It is suitable for categorical data, such as classifying fruits based on their color and shape.


#### **Key characteristics of Naive Bayes:**

-   **Type of Problem:** Classification (binary or multi-class). Commonly used for text classification tasks in cybersecurity (spam, phishing, etc.).

-   **Interpretability:** Medium -- it's not as directly interpretable as a decision tree, but one can inspect the learned probabilities (e.g., which words are most likely in spam vs ham emails). The model's form (probabilities for each feature given the class) can be understood if needed.

-   **Advantages:** **Very fast** training and prediction, even on large datasets (linear in the number of instances * number of features). Requires relatively small amount of data to estimate probabilities reliably, especially with proper smoothing. It's often surprisingly accurate as a baseline, especially when features independently contribute evidence to the class. Works well with high-dimensional data (e.g., thousands of features from text). No complex tuning required beyond setting a smoothing parameter.

-   **Limitations:** The independence assumption can limit accuracy if features are highly correlated. For example, in network data, features like `src_bytes` and `dst_bytes` might be correlated; Naive Bayes won't capture that interaction. As data size grows very large, more expressive models (like ensembles or neural nets) can surpass NB by learning feature dependencies. Also, if a certain combination of features is needed to identify an attack (not just individual features independently), NB will struggle.

> [!TIP]
> *Use cases in cybersecurity:* The classic use is **spam detection** -- Naive Bayes was the core of early spam filters, using the frequencies of certain tokens (words, phrases, IP addresses) to calculate the probability an email is spam. It's also used in **phishing email detection** and **URL classification**, where presence of certain keywords or characteristics (like "login.php" in a URL, or `@` in a URL path) contribute to phishing probability. In malware analysis, one could imagine a Naive Bayes classifier that uses the presence of certain API calls or permissions in software to predict if it's malware. While more advanced algorithms often perform better, Naive Bayes remains a good baseline due to its speed and simplicity.

<details>
<summary>Example -- Naive Bayes for Phishing Detection:</summary>
To demonstrate Naive Bayes, we'll use Gaussian Naive Bayes on the NSL-KDD intrusion dataset (with binary labels). Gaussian NB will treat each feature as following a normal distribution per class. This is a rough choice since many network features are discrete or highly skewed, but it shows how one would apply NB to continuous feature data. We could also choose Bernoulli NB on a dataset of binary features (like a set of triggered alerts), but we'll stick with NSL-KDD here for continuity.

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

This code trains a Naive Bayes classifier to detect attacks. Naive Bayes will compute things like `P(service=http | Attack)` and `P(Service=http | Normal)` based on the training data, assuming independence among features. It will then use these probabilities to classify new connections as either normal or attack based on the features observed. The performance of NB on NSL-KDD may not be as high as more advanced models (since feature independence is violated), but it's often decent and comes with the benefit of extreme speed. In scenarios like real-time email filtering or initial triage of URLs, a Naive Bayes model can quickly flag obviously malicious cases with low resource usage.

</details>

### k-Nearest Neighbors (k-NN)

k-Nearest Neighbors is one of the simplest machine learning algorithms. It's a **non-parametric, instance-based** method that makes predictions based on the similarity to examples in the training set. The idea for classification is: to classify a new data point, find the **k** closest points in the training data (its "nearest neighbors"), and assign the majority class among those neighbors. "Closeness" is defined by a distance metric, typically Euclidean distance for numeric data (other distances can be used for different types of features or problems).

K-NN requires *no explicit training* -- the "training" phase is just storing the dataset. All the work happens during the query (prediction): the algorithm must compute distances from the query point to all training points to find the nearest ones. This makes prediction time **linear in the number of training samples**, which can be costly for large datasets. Due to this, k-NN is best suited for smaller datasets or scenarios where you can trade off memory and speed for simplicity.

Despite its simplicity, k-NN can model very complex decision boundaries (since effectively the decision boundary can be any shape dictated by the distribution of examples). It tends to do well when the decision boundary is very irregular and you have a lot of data -- essentially letting the data "speak for itself". However, in high dimensions, distance metrics can become less meaningful (curse of dimensionality), and the method can struggle unless you have a huge number of samples.

*Use cases in cybersecurity:* k-NN has been applied to anomaly detection -- for example, an intrusion detection system might label a network event as malicious if most of its nearest neighbors (previous events) were malicious. If normal traffic forms clusters and attacks are outliers, a K-NN approach (with k=1 or small k) essentially does a **nearest-neighbor anomaly detection**. K-NN has also been used for classifying malware families by binary feature vectors: a new file might be classified as a certain malware family if it's very close (in feature space) to known instances of that family. In practice, k-NN is not as common as more scalable algorithms, but it's conceptually straightforward and sometimes used as a baseline or for small-scale problems.

#### **Key characteristics of k-NN:**

-   **Type of Problem:** Classification (and regression variants exist). It's a *lazy learning* method -- no explicit model fitting.

-   **Interpretability:** Low to medium -- there is no global model or concise explanation, but one can interpret results by looking at the nearest neighbors that influenced a decision (e.g., "this network flow was classified as malicious because it's similar to these 3 known malicious flows"). So, explanations can be example-based.

-   **Advantages:** Very simple to implement and understand. Makes no assumptions about the data distribution (non-parametric). Can naturally handle multi-class problems. It's **adaptive** in the sense that decision boundaries can be very complex, shaped by the data distribution.

-   **Limitations:** Prediction can be slow for large datasets (must compute many distances). Memory-intensive -- it stores all training data. Performance degrades in high-dimensional feature spaces because all points tend to become nearly equidistant (making the concept of "nearest" less meaningful). Need to choose *k* (number of neighbors) appropriately -- too small k can be noisy, too large k can include irrelevant points from other classes. Also, features should be scaled appropriately because distance calculations are sensitive to scale.

<details>
<summary>Example -- k-NN for Phishing Detection:</summary>

We'll again use NSL-KDD (binary classification). Because k-NN is computationally heavy, we'll use a subset of the training data to keep it tractable in this demonstration. We'll pick, say, 20,000 training samples out of the full 125k, and use k=5 neighbors. After training (really just storing the data), we'll evaluate on the test set. We'll also scale features for distance calculation to ensure no single feature dominates due to scale.

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

The k-NN model will classify a connection by looking at the 5 closest connections in the training set subset. If, for example, 4 of those neighbors are attacks (anomalies) and 1 is normal, the new connection will be classified as an attack. The performance might be reasonable, though often not as high as a well-tuned Random Forest or SVM on the same data. However, k-NN can sometimes shine when the class distributions are very irregular and complex -- effectively using a memory-based lookup. In cybersecurity, k-NN (with k=1 or small k) could be used for detection of known attack patterns by example, or as a component in more complex systems (e.g., for clustering and then classifying based on cluster membership).
</details>

### Gradient Boosting Machines (e.g., XGBoost)

Gradient Boosting Machines are among the most powerful algorithms for structured data. **Gradient boosting** refers to the technique of building an ensemble of weak learners (often decision trees) in a sequential manner, where each new model corrects the errors of the previous ensemble. Unlike bagging (Random Forests) which build trees in parallel and average them, boosting builds trees *one by one*, each focusing more on the instances that previous trees mis-predicted.

The most popular implementations in recent years are **XGBoost**, **LightGBM**, and **CatBoost**, all of which are gradient boosting decision tree (GBDT) libraries. They have been extremely successful in machine learning competitions and applications, often **achieving state-of-the-art performance on tabular datasets**. In cybersecurity, researchers and practitioners have used gradient boosted trees for tasks like **malware detection** (using features extracted from files or runtime behavior) and **network intrusion detection**. For example, a gradient boosting model can combine many weak rules (trees) such as "if many SYN packets and unusual port -> likely scan" into a strong composite detector that accounts for many subtle patterns.

Why are boosted trees so effective? Each tree in the sequence is trained on the *residual errors* (gradients) of the current ensemble's predictions. This way, the model gradually **"boosts"** the areas where it's weak. The use of decision trees as base learners means the final model can capture complex interactions and non-linear relations. Also, boosting inherently has a form of built-in regularization: by adding many small trees (and using a learning rate to scale their contributions), it often generalizes well without huge overfitting, provided proper parameters are chosen.

#### **Key characteristics of Gradient Boosting:**

-   **Type of Problem:** Primarily classification and regression. In security, usually classification (e.g., binary classify a connection or file). It handles binary, multi-class (with appropriate loss), and even ranking problems.

-   **Interpretability:** Low to medium. While a single boosted tree is small, a full model might have hundreds of trees, which is not human-interpretable as a whole. However, like Random Forest, it can provide feature importance scores, and tools like SHAP (SHapley Additive exPlanations) can be used to interpret individual predictions to some extent.

-   **Advantages:** Often the **best performing** algorithm for structured/tabular data. Can detect complex patterns and interactions. Has many tuning knobs (number of trees, depth of trees, learning rate, regularization terms) to tailor model complexity and prevent overfitting. Modern implementations are optimized for speed (e.g., XGBoost uses second-order gradient info and efficient data structures). Tends to handle imbalanced data better when combined with appropriate loss functions or by adjusting sample weights.

-   **Limitations:** More complex to tune than simpler models; training can be slow if trees are deep or number of trees is large (though still usually faster than training a comparable deep neural network on the same data). The model can overfit if not tuned (e.g., too many deep trees with insufficient regularization). Because of many hyperparameters, using gradient boosting effectively may require more expertise or experimentation. Also, like tree-based methods, it doesn't inherently handle very sparse high-dimensional data as efficiently as linear models or Naive Bayes (though it can still be applied, e.g., in text classification, but might not be first choice without feature engineering).

> [!TIP]
> *Use cases in cybersecurity:* Almost anywhere a decision tree or random forest could be used, a gradient boosting model might achieve better accuracy. For example, **Microsoft's malware detection** competitions have seen heavy use of XGBoost on engineered features from binary files. **Network intrusion detection** research often reports top results with GBDTs (e.g., XGBoost on CIC-IDS2017 or UNSW-NB15 datasets). These models can take a wide range of features (protocol types, frequency of certain events, statistical features of traffic, etc.) and combine them to detect threats. In phishing detection, gradient boosting can combine lexical features of URLs, domain reputation features, and page content features to achieve very high accuracy. The ensemble approach helps cover many corner cases and subtleties in the data.

<details>
<summary>Example -- XGBoost for Phishing Detection:</summary>
We'll use a gradient boosting classifier on the phishing dataset. To keep things simple and self-contained, we'll use `sklearn.ensemble.GradientBoostingClassifier` (which is a slower but straightforward implementation). Normally, one might use `xgboost` or `lightgbm` libraries for better performance and additional features. We will train the model and evaluate it similarly to before.

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

The gradient boosting model will likely achieve very high accuracy and AUC on this phishing dataset (often these models can exceed 95% accuracy with proper tuning on such data, as seen in literature. This demonstrates why GBDTs are considered *"the state of the art model for tabular dataset"* -- they often outperform simpler algorithms by capturing complex patterns. In a cybersecurity context, this could mean catching more phishing sites or attacks with fewer misses. Of course, one must be cautious about overfitting -- we would typically use techniques like cross-validation and monitor performance on a validation set when developing such a model for deployment.

</details>

### Combining Models: Ensemble Learning and Stacking

Ensemble learning is a strategy of **combining multiple models** to improve overall performance. We already saw specific ensemble methods: Random Forest (an ensemble of trees via bagging) and Gradient Boosting (an ensemble of trees via sequential boosting). But ensembles can be created in other ways too, such as **voting ensembles** or **stacked generalization (stacking)**. The main idea is that different models may capture different patterns or have different weaknesses; by combining them, we can **compensate for each model's errors with another's strengths**.

-   **Voting Ensemble:** In a simple voting classifier, we train multiple diverse models (say, a logistic regression, a decision tree, and an SVM) and have them vote on the final prediction (majority vote for classification). If we weight the votes (e.g., higher weight to more accurate models), it's a weighted voting scheme. This typically improves performance when the individual models are reasonably good and independent -- the ensemble reduces the risk of an individual model's mistake since others may correct it. It's like having a panel of experts rather than a single opinion.

-   **Stacking (Stacked Ensemble):** Stacking goes a step further. Instead of a simple vote, it trains a **meta-model** to **learn how to best combine the predictions** of base models. For example, you train 3 different classifiers (base learners), then feed their outputs (or probabilities) as features into a meta-classifier (often a simple model like logistic regression) that learns the optimal way to blend them. The meta-model is trained on a validation set or via cross-validation to avoid overfitting. Stacking can often outperform simple voting by learning *which models to trust more in which circumstances*. In cybersecurity, one model might be better at catching network scans while another is better at catching malware beaconing; a stacking model could learn to rely on each appropriately.

Ensembles, whether by voting or stacking, tend to **boost accuracy** and robustness. The downside is increased complexity and sometimes reduced interpretability (though some ensemble approaches like an average of decision trees can still provide some insight, e.g., feature importance). In practice, if operational constraints allow, using an ensemble can lead to higher detection rates. Many winning solutions in cybersecurity challenges (and Kaggle competitions in general) use ensemble techniques to squeeze out the last bit of performance.

<details>
<summary>Example -- Voting Ensemble for Phishing Detection:</summary>
To illustrate model stacking, let's combine a few of the models we discussed on the phishing dataset. We'll use a logistic regression, a decision tree, and a k-NN as base learners, and use a Random Forest as a meta-learner to aggregate their predictions. The meta-learner will be trained on the outputs of the base learners (using cross-validation on the training set). We expect the stacked model to perform as well as or slightly better than the individual models.

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
The stacked ensemble takes advantage of the complementary strengths of the base models. For instance, logistic regression might handle linear aspects of the data, the decision tree might capture specific rule-like interactions, and k-NN might excel in local neighborhoods of the feature space. The meta-model (a random forest here) can learn how to weigh these inputs. The resulting metrics often show an improvement (even if slight) over any single model's metrics. In our phishing example, if logistic alone had an F1 of say 0.95 and the tree 0.94, the stack might achieve 0.96 by picking up where each model errs.

Ensemble methods like this demonstrate the principle that *"combining multiple models typically leads to better generalization"*. In cybersecurity, this can be implemented by having multiple detection engines (one might be rule-based, one machine learning, one anomaly-based) and then a layer that aggregates their alerts -- effectively a form of ensemble -- to make a final decision with higher confidence. When deploying such systems, one must consider the added complexity and ensure that the ensemble doesn't become too hard to manage or explain. But from an accuracy standpoint, ensembles and stacking are powerful tools for improving model performance.

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


