# Model Data Preparation & Evaluation

{{#include ../banners/hacktricks-training.md}}

Model data preparation is a crucial step in the machine learning pipeline, as it involves transforming raw data into a format suitable for training machine learning models. This process includes several key steps:

1. **Data Collection**: Gathering data from various sources, such as databases, APIs, or files. The data can be structured (e.g., tables) or unstructured (e.g., text, images).
2. **Data Cleaning**: Removing or correcting erroneous, incomplete, or irrelevant data points. This step may involve handling missing values, removing duplicates, and filtering outliers.
3. **Data Transformation**: Converting the data into a suitable format for modeling. This may include normalization, scaling, encoding categorical variables, and creating new features through techniques like feature engineering.
4. **Data Splitting**: Dividing the dataset into training, validation, and test sets to ensure the model can generalize well to unseen data.

## Data Collection

Data collection involves gathering data from various sources, which can include:
- **Databases**: Extracting data from relational databases (e.g., SQL databases) or NoSQL databases (e.g., MongoDB).
- **APIs**: Fetching data from web APIs, which can provide real-time or historical data.
- **Files**: Reading data from files in formats like CSV, JSON, or XML.
- **Web Scraping**: Collecting data from websites using web scraping techniques.

Depending on the goal of the machine learning project, the data will be extracted and collected from relevant sources to ensure it is representative of the problem domain.

## Data Cleaning

Data cleaning is the process of identifying and correcting errors or inconsistencies in the dataset. This step is essential to ensure the quality of the data used for training machine learning models. Key tasks in data cleaning include:
- **Handling Missing Values**: Identifying and addressing missing data points. Common strategies include:
  - Removing rows or columns with missing values.
  - Imputing missing values using techniques like mean, median, or mode imputation.
  - Using advanced methods like K-nearest neighbors (KNN) imputation or regression imputation.
- **Removing Duplicates**: Identifying and removing duplicate records to ensure each data point is unique.
- **Filtering Outliers**: Detecting and removing outliers that may skew the model's performance. Techniques like Z-score, IQR (Interquartile Range), or visualizations (e.g., box plots) can be used to identify outliers.

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

Data transformation involves converting the data into a format suitable for modeling. This step may include:
- **Normalization & Standarization**: Scaling numerical features to a common range, typically [0, 1] or [-1, 1]. This helps improve the convergence of optimization algorithms.
    - **Min-Max Scaling**: Rescaling features to a fixed range, usually [0, 1]. This is done using the formula: `X' = (X - X_{min}) / (X_{max} - X_{min})`
    - **Z-Score Normalization**: Standardizing features by subtracting the mean and dividing by the standard deviation, resulting in a distribution with a mean of 0 and a standard deviation of 1. This is done using the formula: `X' = (X - μ) / σ`, where μ is the mean and σ is the standard deviation.
    - **Skeyewness and Kurtosis**: Adjusting the distribution of features to reduce skewness (asymmetry) and kurtosis (peakedness). This can be done using transformations like logarithmic, square root, or Box-Cox transformations. For example, if a feature has a skewed distribution, applying a logarithmic transformation can help normalize it.
    - **String Normalization**: Converting strings to a consistent format, such as:
      - Lowercasing
      - Removing special characters (keeping the relevant ones)
      - Removing stop words (common words that do not contribute to the meaning, such as "the", "is", "and")
      - Removing too frequent words and too rare words (e.g., words that appear in more than 90% of the documents or less than 5 times in the corpus)
      - Trimming whitespace
      - Stemming/Lemmatization: Reducing words to their base or root form (e.g., "running" to "run").

- **Encoding Categorical Variables**: Converting categorical variables into numerical representations. Common techniques include:
  - **One-Hot Encoding**: Creating binary columns for each category.
    - For example, if a feature has categories "red", "green", and "blue", it will be transformed into three binary columns: `is_red`(100), `is_green`(010), and `is_blue`(001).
  - **Label Encoding**: Assigning a unique integer to each category.
    - For example, "red" = 0, "green" = 1, "blue" = 2.
  - **Ordinal Encoding**: Assigning integers based on the order of categories.
    - For example, if the categories are "low", "medium", and "high", they can be encoded as 0, 1, and 2, respectively.
  - **Hashing Encoding**: Using a hash function to convert categories into fixed-size vectors, which can be useful for high-cardinality categorical variables.
    - For example, if a feature has many unique categories, hashing can reduce the dimensionality while preserving some information about the categories.
  - **Bag of Words (BoW)**: Representing text data as a matrix of word counts or frequencies, where each row corresponds to a document and each column corresponds to a unique word in the corpus.
    - For example, if the corpus contains the words "cat", "dog", and "fish", a document containing "cat" and "dog" would be represented as [1, 1, 0]. This specific representation is called "unigram" and does not capture the order of words, so it loses semantic information.
    - **Bigram/Trigram**: Extending BoW to capture sequences of words (bigrams or trigrams) to retain some context. For example, "cat and dog" would be represented as a bigram [1, 1] for "cat and" and [1, 1] for "and dog". In these case more semantic information is gathered (increasing the dimensionality of the representation) but only for 2 or 3 words at a time.
  - **TF-IDF (Term Frequency-Inverse Document Frequency)**: A statistical measure that evaluates the importance of a word in a document relative to a collection of documents (corpus). It combines term frequency (how often a word appears in a document) and inverse document frequency (how rare a word is across all documents).
    - For example, if the word "cat" appears frequently in a document but is rare in the entire corpus, it will have a high TF-IDF score, indicating its importance in that document.


- **Feature Engineering**: Creating new features from existing ones to enhance the model's predictive power. This can involve combining features, extracting date/time components, or applying domain-specific transformations.

## Data Splitting

Data splitting involves dividing the dataset into separate subsets for training, validation, and testing. This is essential to evaluate the model's performance on unseen data and prevent overfitting. Common strategies include:
- **Train-Test Split**: Dividing the dataset into a training set (typically 60-80% of the data), a validation set (10-15% of the data) to tune hyperparameters, and a test set (10-15% of the data). The model is trained on the training set and evaluated on the test set.
  - For example, if you have a dataset of 1000 samples, you might use 700 samples for training, 150 for validation, and 150 for testing.
- **Stratified Sampling**: Ensuring that the distribution of classes in the training and test sets is similar to the overall dataset. This is particularly important for imbalanced datasets, where some classes may have significantly fewer samples than others.
- **Time Series Split**: For time series data, the dataset is split based on time, ensuring that the training set contains data from earlier time periods and the test set contains data from later periods. This helps evaluate the model's performance on future data.
- **K-Fold Cross-Validation**: Splitting the dataset into K subsets (folds) and training the model K times, each time using a different fold as the test set and the remaining folds as the training set. This helps ensure that the model is evaluated on different subsets of data, providing a more robust estimate of its performance.

## Model Evaluation

Model evaluation is the process of assessing the performance of a machine learning model on unseen data. It involves using various metrics to quantify how well the model generalizes to new data. Common evaluation metrics include:

### Accuracy

Accuracy is the proportion of correctly predicted instances out of the total instances. It is calculated as:
```plaintext
Accuracy = (Number of Correct Predictions) / (Total Number of Predictions)
```

> [!TIP]
> Accuracy is a simple and intuitive metric, but it may not be suitable for imbalanced datasets where one class dominates the others as it can give a misleading impression of model performance. For example, if 90% of the data belongs to class A and the model predicts all instances as class A, it will achieve 90% accuracy, but it won't be useful for predicting class B.

### Precision

Precision is the proportion of true positive predictions out of all positive predictions made by the model. It is calculated as:
```plaintext
Precision = (True Positives) / (True Positives + False Positives)
```

> [!TIP]
> Precision is particularly important in scenarios where false positives are costly or undesirable, such as in medical diagnoses or fraud detection. For example, if a model predicts 100 instances as positive, but only 80 of them are actually positive, the precision would be 0.8 (80%).

### Recall (Sensitivity)

Recall, also known as sensitivity or true positive rate, is the proportion of true positive predictions out of all actual positive instances. It is calculated as:
```plaintext
Recall = (True Positives) / (True Positives + False Negatives)
```

> [!TIP]
> Recall is crucial in scenarios where false negatives are costly or undesirable, such as in disease detection or spam filtering. For example, if a model identifies 80 out of 100 actual positive instances, the recall would be 0.8 (80%).

### F1 Score

The F1 score is the harmonic mean of precision and recall, providing a balance between the two metrics. It is calculated as:
```plaintext
F1 Score = 2 * (Precision * Recall) / (Precision + Recall)
```

> [!TIP]
> The F1 score is particularly useful when dealing with imbalanced datasets, as it considers both false positives and false negatives. It provides a single metric that captures the trade-off between precision and recall. For example, if a model has a precision of 0.8 and a recall of 0.6, the F1 score would be approximately 0.69.

### ROC-AUC (Receiver Operating Characteristic - Area Under the Curve)

The ROC-AUC metric evaluates the model's ability to distinguish between classes by plotting the true positive rate (sensitivity) against the false positive rate at various threshold settings. The area under the ROC curve (AUC) quantifies the model's performance, with a value of 1 indicating perfect classification and a value of 0.5 indicating random guessing.

> [!TIP]
> ROC-AUC is particularly useful for binary classification problems and provides a comprehensive view of the model's performance across different thresholds. It is less sensitive to class imbalance compared to accuracy. For example, a model with an AUC of 0.9 indicates that it has a high ability to distinguish between positive and negative instances.

### Specificity

Specificity, also known as true negative rate, is the proportion of true negative predictions out of all actual negative instances. It is calculated as:
```plaintext
Specificity = (True Negatives) / (True Negatives + False Positives)
```

> [!TIP]
> Specificity is important in scenarios where false positives are costly or undesirable, such as in medical testing or fraud detection. It helps assess how well the model identifies negative instances. For example, if a model correctly identifies 90 out of 100 actual negative instances, the specificity would be 0.9 (90%).

### Matthews Correlation Coefficient (MCC)
The Matthews Correlation Coefficient (MCC) is a measure of the quality of binary classifications. It takes into account true and false positives and negatives, providing a balanced view of the model's performance. The MCC is calculated as:
```plaintext
MCC = (TP * TN - FP * FN) / sqrt((TP + FP) * (TP + FN) * (TN + FP) * (TN + FN))
```
where:
- **TP**: True Positives
- **TN**: True Negatives
- **FP**: False Positives
- **FN**: False Negatives

> [!TIP]
> The MCC ranges from -1 to 1, where 1 indicates perfect classification, 0 indicates random guessing, and -1 indicates total disagreement between prediction and observation. It is particularly useful for imbalanced datasets, as it considers all four confusion matrix components.

### Mean Absolute Error (MAE)
Mean Absolute Error (MAE) is a regression metric that measures the average absolute difference between predicted and actual values. It is calculated as:
```plaintext
MAE = (1/n) * Σ|y_i - ŷ_i|
```
where:
- **n**: Number of instances
- **y_i**: Actual value for instance i
- **ŷ_i**: Predicted value for instance i

> [!TIP]
> MAE provides a straightforward interpretation of the average error in predictions, making it easy to understand. It is less sensitive to outliers compared to other metrics like Mean Squared Error (MSE). For example, if a model has an MAE of 5, it means that, on average, the model's predictions deviate from the actual values by 5 units.

### Confusion Matrix

The confusion matrix is a table that summarizes the performance of a classification model by showing the counts of true positive, true negative, false positive, and false negative predictions. It provides a detailed view of how well the model performs on each class.

|               | Predicted Positive | Predicted Negative |
|---------------|---------------------|---------------------|
| Actual Positive| True Positive (TP)  | False Negative (FN)  |
| Actual Negative| False Positive (FP) | True Negative (TN)   |

- **True Positive (TP)**: The model correctly predicted the positive class.
- **True Negative (TN)**: The model correctly predicted the negative class.
- **False Positive (FP)**: The model incorrectly predicted the positive class (Type I error).
- **False Negative (FN)**: The model incorrectly predicted the negative class (Type II error).

The confusion matrix can be used to calculate various evaluation metrics, such as accuracy, precision, recall, and F1 score.


{{#include ../banners/hacktricks-training.md}}

