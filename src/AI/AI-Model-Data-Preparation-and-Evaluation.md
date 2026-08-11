# Model Data Preparation & Evaluation

{{#include ../banners/hacktricks-training.md}}

Model data preparation machine learning pipeline का एक महत्वपूर्ण चरण है, क्योंकि इसमें raw data को ऐसे format में बदला जाता है जो machine learning models की training के लिए उपयुक्त हो। इस प्रक्रिया में कई प्रमुख चरण शामिल हैं:

1. **Data Collection**: विभिन्न sources, जैसे databases, APIs या files से data एकत्र करना। Data structured (जैसे tables) या unstructured (जैसे text, images) हो सकता है।
2. **Data Cleaning**: गलत, अधूरे या अप्रासंगिक data points को हटाना या ठीक करना। इस चरण में missing values को संभालना, duplicates हटाना और outliers को filter करना शामिल हो सकता है।
3. **Data Transformation**: Data को modeling के लिए उपयुक्त format में बदलना। इसमें normalization, scaling, categorical variables की encoding और feature engineering जैसी techniques के माध्यम से नए features बनाना शामिल हो सकता है।
4. **Data Splitting**: Dataset को training, validation और test sets में विभाजित करना, ताकि यह सुनिश्चित किया जा सके कि model unseen data पर अच्छी तरह generalize कर सके।

## Data Collection

Data collection में विभिन्न sources से data एकत्र करना शामिल है, जिनमें ये शामिल हो सकते हैं:
- **Databases**: Relational databases (जैसे SQL databases) या NoSQL databases (जैसे MongoDB) से data extract करना।
- **APIs**: Web APIs से data fetch करना, जो real-time या historical data प्रदान कर सकते हैं।
- **Files**: CSV, JSON या XML जैसे formats वाली files से data पढ़ना।
- **Web Scraping**: Web scraping techniques का उपयोग करके websites से data एकत्र करना।

Machine learning project के goal के आधार पर, problem domain का प्रतिनिधित्व सुनिश्चित करने के लिए data को relevant sources से extract और collect किया जाएगा।

## Data Cleaning <sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

Data cleaning dataset में errors या inconsistencies की पहचान करने और उन्हें ठीक करने की प्रक्रिया है। Machine learning models की training के लिए उपयोग किए जाने वाले data की quality सुनिश्चित करने हेतु यह चरण आवश्यक है। Data cleaning के प्रमुख tasks में शामिल हैं:
- **Handling Missing Values**: Missing data points की पहचान करना और उनका समाधान करना। सामान्य strategies में शामिल हैं:
- Missing values वाली rows या columns को हटाना।
- Mean, median या mode imputation जैसी techniques का उपयोग करके missing values को impute करना।
- K-nearest neighbors (KNN) imputation या regression imputation जैसी advanced methods का उपयोग करना।
- **Removing Duplicates**: यह सुनिश्चित करने के लिए duplicate records की पहचान करना और उन्हें हटाना कि प्रत्येक data point unique हो।
- **Filtering Outliers**: ऐसे outliers का पता लगाना और उन्हें हटाना जो model के performance को प्रभावित कर सकते हैं। Outliers की पहचान के लिए Z-score, IQR (Interquartile Range) या visualizations (जैसे box plots) जैसी techniques का उपयोग किया जा सकता है।

### Example of data cleaning
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

Data transformation में data को modeling के लिए उपयुक्त format में बदलना शामिल है। इस चरण में निम्न शामिल हो सकते हैं:
- **Normalization और standardization**: Numerical features को एक common range, आमतौर पर [0, 1] या [-1, 1], में scale करना। इससे optimization algorithms का convergence बेहतर हो सकता है।
- **Min-Max Scaling**: Features को एक fixed range, आमतौर पर [0, 1], में rescale करना। यह formula का उपयोग करके किया जाता है: `X' = (X - X_{min}) / (X_{max} - X_{min})`
- **Z-Score Normalization**: Mean को घटाकर और standard deviation से विभाजित करके features को standardize करना, जिससे mean 0 और standard deviation 1 वाला distribution प्राप्त होता है। यह formula का उपयोग करके किया जाता है: `X' = (X - μ) / σ`, जहाँ μ mean और σ standard deviation है।
- **Skewness और kurtosis**: Logarithm, square root या Box-Cox जैसे transformations के साथ feature distributions को adjust करना। उदाहरण के लिए, logarithmic transformation positive skew को कम कर सकता है।
- **String Normalization**: Strings को एक consistent format में बदलना, जैसे:
- Lowercasing
- Special characters हटाना (relevant characters को बनाए रखते हुए)
- Stop words हटाना (ऐसे common words जो meaning में योगदान नहीं देते, जैसे "the", "is", और "and")
- बहुत frequent और बहुत rare words हटाना (जैसे, वे words जो 90% से अधिक documents में दिखाई देते हैं या corpus में 5 बार से कम दिखाई देते हैं)
- Whitespace trim करना
- Stemming/Lemmatization: Words को उनके base या root form में बदलना (जैसे, "running" को "run" में)।

- **Categorical Variables की Encoding**: Categorical variables को numerical representations में बदलना। Common techniques में शामिल हैं:
- **One-Hot Encoding**: प्रत्येक category के लिए binary columns बनाना।
- उदाहरण के लिए, यदि किसी feature में "red", "green", और "blue" categories हैं, तो इसे तीन binary columns में बदला जाएगा: `is_red`(100), `is_green`(010), और `is_blue`(001)।
- **Label Encoding**: प्रत्येक category को एक unique integer देना।
- उदाहरण के लिए, "red" = 0, "green" = 1, "blue" = 2।
- **Ordinal Encoding**: Categories के order के आधार पर integers देना।
- उदाहरण के लिए, यदि categories "low", "medium", और "high" हैं, तो इन्हें क्रमशः 0, 1, और 2 के रूप में encode किया जा सकता है।
- **Hashing Encoding**: Categories को fixed-size vectors में बदलने के लिए hash function का उपयोग करना, जो high-cardinality categorical variables के लिए उपयोगी हो सकता है।
- उदाहरण के लिए, यदि किसी feature में कई unique categories हैं, तो hashing categories के बारे में कुछ information बनाए रखते हुए dimensionality को कम कर सकता है।
- **Bag of Words (BoW)**: Text data को word counts या frequencies के matrix के रूप में represent करना, जहाँ प्रत्येक row एक document और प्रत्येक column corpus में मौजूद एक unique word को दर्शाता है।
- उदाहरण के लिए, यदि corpus में "cat", "dog", और "fish" words हैं, तो "cat" और "dog" वाले document को [1, 1, 0] के रूप में represent किया जाएगा। इस specific representation को "unigram" कहा जाता है और यह words के order को capture नहीं करता, इसलिए semantic information खो जाती है।
- **Bigram/Trigram**: कुछ context बनाए रखने के लिए words के sequences (bigrams या trigrams) को capture करने हेतु BoW का विस्तार करना। उदाहरण के लिए, "cat and dog" को "cat and" के लिए bigram [1, 1] और "and dog" के लिए [1, 1] के रूप में represent किया जाएगा। इस case में अधिक semantic information एकत्र की जाती है (representation की dimensionality बढ़ाकर), लेकिन एक समय में केवल 2 या 3 words के लिए।
- **TF-IDF (Term Frequency-Inverse Document Frequency)**: एक statistical measure जो किसी document में किसी word की importance का मूल्यांकन documents के collection (corpus) के सापेक्ष करता है। यह term frequency (किसी document में कोई word कितनी बार दिखाई देता है) और inverse document frequency (सभी documents में कोई word कितना rare है) को combine करता है।
- उदाहरण के लिए, यदि "cat" word किसी document में frequently दिखाई देता है, लेकिन पूरे corpus में rare है, तो उसका TF-IDF score high होगा, जो उस document में उसकी importance दर्शाता है।

- **Feature Engineering**: Model की predictive power बढ़ाने के लिए existing features से नए features बनाना। इसमें features को combine करना, date/time components निकालना, या domain-specific transformations लागू करना शामिल हो सकता है।

## Data Splitting <sup>[[3]](#references)</sup>

Data splitting में dataset को training, validation, और testing के लिए अलग-अलग subsets में विभाजित करना शामिल है। यह unseen data पर model के performance का मूल्यांकन करने और overfitting को रोकने के लिए आवश्यक है। Common strategies में शामिल हैं:
- **Train-Test Split**: Dataset को training set (आमतौर पर data का 60-80%), validation set (hyperparameters tune करने के लिए data का 10-15%), और test set (data का 10-15%) में विभाजित करना। Model को training set पर train किया जाता है और test set पर evaluate किया जाता है।
- उदाहरण के लिए, यदि आपके पास 1000 samples का dataset है, तो आप training के लिए 700 samples, validation के लिए 150, और testing के लिए 150 samples का उपयोग कर सकते हैं।
- **Stratified Sampling**: यह सुनिश्चित करना कि training और test sets में classes का distribution overall dataset के समान हो। यह imbalanced datasets के लिए विशेष रूप से महत्वपूर्ण है, जहाँ कुछ classes में अन्य की तुलना में काफी कम samples हो सकते हैं।
- **Time Series Split**: Time series data के लिए dataset को time के आधार पर विभाजित करना, जिससे यह सुनिश्चित हो कि training set में पहले के time periods का data और test set में बाद के periods का data हो। इससे future data पर model के performance का मूल्यांकन करने में मदद मिलती है।
- **K-Fold Cross-Validation**: Dataset को K subsets (folds) में विभाजित करना और model को K बार train करना; प्रत्येक बार एक अलग fold को test set और बाकी folds को training set के रूप में उपयोग करना। इससे यह सुनिश्चित करने में मदद मिलती है कि model का मूल्यांकन data के अलग-अलग subsets पर हो, जिससे उसके performance का अधिक robust estimate मिलता है।

## Model Evaluation <sup>[[4]](#references)</sup>

Model evaluation unseen data पर machine learning model के performance का आकलन करने की process है। इसमें यह मापने के लिए विभिन्न metrics का उपयोग किया जाता है कि model नए data पर कितनी अच्छी तरह generalize करता है। Common evaluation metrics में शामिल हैं:

### Accuracy

Accuracy, total instances में से correctly predicted instances का proportion है। इसकी गणना इस प्रकार की जाती है:
```plaintext
Accuracy = (Number of Correct Predictions) / (Total Number of Predictions)
```
> [!TIP]
> सटीकता एक सरल और सहज metric है, लेकिन यह imbalanced datasets के लिए उपयुक्त नहीं हो सकती, जहाँ एक class अन्य classes पर हावी होती है, क्योंकि यह model performance का भ्रामक प्रभाव दे सकती है। उदाहरण के लिए, यदि 90% data class A से संबंधित है और model सभी instances को class A के रूप में predict करता है, तो यह 90% accuracy प्राप्त करेगा, लेकिन class B की prediction के लिए उपयोगी नहीं होगा।

### Precision

Precision, model द्वारा की गई सभी positive predictions में से true positive predictions का अनुपात है। इसकी गणना इस प्रकार की जाती है:
```plaintext
Precision = (True Positives) / (True Positives + False Positives)
```
> [!TIP]
> Precision उन scenarios में विशेष रूप से महत्वपूर्ण है जहाँ false positives महंगे या अवांछित होते हैं, जैसे medical diagnoses या fraud detection में। उदाहरण के लिए, यदि कोई model 100 instances को positive के रूप में predict करता है, लेकिन उनमें से केवल 80 वास्तव में positive हैं, तो precision 0.8 (80%) होगी।

### Recall (Sensitivity)

Recall, जिसे sensitivity या true positive rate के रूप में भी जाना जाता है, सभी वास्तविक positive instances में से true positive predictions का अनुपात है। इसकी गणना इस प्रकार की जाती है:
```plaintext
Recall = (True Positives) / (True Positives + False Negatives)
```
> [!TIP]
> Recall उन परिस्थितियों में महत्वपूर्ण होता है जहाँ false negatives महंगे या अवांछनीय होते हैं, जैसे disease detection या spam filtering में। उदाहरण के लिए, यदि कोई model वास्तविक रूप से positive 100 instances में से 80 की पहचान करता है, तो recall 0.8 (80%) होगा।

### F1 Score

F1 score, precision और recall का harmonic mean होता है, जो दोनों metrics के बीच संतुलन प्रदान करता है। इसकी गणना इस प्रकार की जाती है:
```plaintext
F1 Score = 2 * (Precision * Recall) / (Precision + Recall)
```
> [!TIP]
> F1 score imbalanced datasets के साथ काम करते समय विशेष रूप से उपयोगी होता है, क्योंकि यह false positives और false negatives दोनों पर विचार करता है। यह एक ऐसा single metric प्रदान करता है, जो precision और recall के बीच trade-off को दर्शाता है। उदाहरण के लिए, यदि किसी model की precision 0.8 और recall 0.6 है, तो F1 score लगभग 0.69 होगा।

### ROC-AUC (Receiver Operating Characteristic - Area Under the Curve)

ROC-AUC metric विभिन्न threshold settings पर true positive rate (sensitivity) को false positive rate के विरुद्ध plot करके classes के बीच अंतर करने की model की क्षमता का मूल्यांकन करता है। ROC curve के नीचे का क्षेत्रफल (AUC) model के performance को मापता है। 1 का मान perfect classification और 0.5 का मान random guessing को दर्शाता है।

> [!TIP]
> ROC-AUC binary classification problems के लिए विशेष रूप से उपयोगी है और विभिन्न thresholds पर model के performance का एक व्यापक दृष्टिकोण प्रदान करता है। यह accuracy की तुलना में class imbalance के प्रति कम sensitive होता है। उदाहरण के लिए, 0.9 AUC वाला model positive और negative instances के बीच अंतर करने की उच्च क्षमता दर्शाता है।

### Specificity

Specificity, जिसे true negative rate भी कहा जाता है, सभी वास्तविक negative instances में से true negative predictions का अनुपात है। इसकी गणना इस प्रकार की जाती है:
```plaintext
Specificity = (True Negatives) / (True Negatives + False Positives)
```
> [!TIP]
> Specificity उन परिस्थितियों में महत्वपूर्ण होती है जहाँ false positives महंगे या अवांछनीय होते हैं, जैसे medical testing या fraud detection में। यह आकलन करने में मदद करती है कि model negative instances की पहचान कितनी अच्छी तरह करता है। उदाहरण के लिए, यदि कोई model 100 वास्तविक negative instances में से 90 की सही पहचान करता है, तो specificity 0.9 (90%) होगी।

### Matthews Correlation Coefficient (MCC)
Matthews Correlation Coefficient (MCC) binary classifications की गुणवत्ता का एक माप है। यह true और false positives तथा negatives को ध्यान में रखता है और model के performance का संतुलित दृष्टिकोण प्रदान करता है। MCC की गणना इस प्रकार की जाती है:
```plaintext
MCC = (TP * TN - FP * FN) / sqrt((TP + FP) * (TP + FN) * (TN + FP) * (TN + FN))
```
जहाँ:
- **TP**: True Positives
- **TN**: True Negatives
- **FP**: False Positives
- **FN**: False Negatives

> [!TIP]
> MCC -1 से 1 तक होता है, जहाँ 1 perfect classification को दर्शाता है, 0 random guessing को दर्शाता है, और -1 prediction तथा observation के बीच total disagreement को दर्शाता है। यह imbalanced datasets के लिए विशेष रूप से उपयोगी है, क्योंकि इसमें confusion matrix के सभी चार components को ध्यान में रखा जाता है।

### Mean Absolute Error (MAE)
Mean Absolute Error (MAE) एक regression metric है, जो predicted और actual values के बीच average absolute difference को मापता है। इसकी गणना इस प्रकार की जाती है:
```plaintext
MAE = (1/n) * Σ|y_i - ŷ_i|
```
जहाँ:
- **n**: instances की संख्या
- **y_i**: instance i का वास्तविक मान
- **ŷ_i**: instance i के लिए predicted मान

> [!TIP]
> MAE predictions में औसत error की सीधी व्याख्या प्रदान करता है, जिससे इसे समझना आसान होता है। यह Mean Squared Error (MSE) जैसे अन्य metrics की तुलना में outliers के प्रति कम sensitive होता है। उदाहरण के लिए, यदि किसी model का MAE 5 है, तो इसका अर्थ है कि model की predictions, औसतन, वास्तविक values से 5 units तक अलग होती हैं।

### Confusion Matrix

Confusion matrix एक table है जो true positive, true negative, false positive और false negative predictions की counts दिखाकर classification model के performance का सारांश प्रस्तुत करती है। यह प्रत्येक class पर model के performance का विस्तृत view प्रदान करती है।

|               | Predicted Positive | Predicted Negative |
|---------------|---------------------|---------------------|
| Actual Positive| True Positive (TP)  | False Negative (FN)  |
| Actual Negative| False Positive (FP) | True Negative (TN)   |

- **True Positive (TP)**: Model ने positive class की सही prediction की।
- **True Negative (TN)**: Model ने negative class की सही prediction की।
- **False Positive (FP)**: Model ने positive class की गलत prediction की (Type I error)।
- **False Negative (FN)**: Model ने negative class की गलत prediction की (Type II error)।

Confusion matrix का उपयोग accuracy, precision, recall और F1 score जैसे evaluation metrics की गणना करने के लिए किया जा सकता है।

## References

- [1] [scikit-learn - Data का preprocessing](https://scikit-learn.org/stable/modules/preprocessing.html)
- [2] [scikit-learn - Missing values का imputation](https://scikit-learn.org/stable/modules/impute.html)
- [3] [scikit-learn - Cross-validation: estimator performance का evaluation](https://scikit-learn.org/stable/modules/cross_validation.html)
- [4] [scikit-learn - Metrics और scoring](https://scikit-learn.org/stable/modules/model_evaluation.html)
{{#include ../banners/hacktricks-training.md}}
