# LLM Training - Data Preparation

## Pretraining

The pre-training phase of a LLM is the moment where the LLM gets a lot of data that makes the LLM learn about the language and everything in general. This base is usually later used to fine-tune it in order to specialise the model into a specific topic.

## Tokenizing

Tokenizing consists on separating the data in specific chunks and assign them specific IDs (numbers).\
A very simple tokenizer for texts might to just get each word of a text separately, and also punctuation symbols and remove spaces.\
Therefore, `"Hello, world!"` would be: `["Hello", ",", "world", "!"]`

Then, in order to assign each of the words and symbols a token ID (number), it's needed to create the tokenizer **vocabulary**. If you are tokenizing for example a book, this could be **all the different word of the book** in alphabetic order with some extra tokens like:

* `[BOS] (Beginning of sequence)`: Placed at the beggining of a text, it indicates the start of a text (used to separate none related texts).
* `[EOS] (End of sequence)`: Placed at the end of a text, it indicates the end of a text (used to separate none related texts).
* `[PAD] (padding)`: When a batch size is larger than one (usually), this token is used to incrase the length of that batch to be as bigger as the others.
* `[UNK] (unknown)`: To represent unknown words.

Following the example, having tokenized a text assigning each word and symbol of the text a position in the vocabulary, the tokenized sentence `"Hello, world!"` -> `["Hello", ",", "world", "!"]` would be something like: `[64, 455, 78, 467]` supposing that `Hello` is at pos 64, "`,"` is at pos `455`... in the resulting vocabulary array.

However, if in the text used to generate the vocabulary the word `"Bye"` didn't exist, this will result in: `"Bye, world!"` -> `["[UNK]", ",", "world", "!"]` -> `[987, 455, 78, 467]` supposing the token for `[UNK]` is at 987.

### BPE - Byte Pair Encoding

In order to avoid problems like needing to tokenize all the possible words for texts, LLMs like GPT used BPE which basically **encodes frequent pairs of bytes** to reduce the size of the text in a more optimized format until it cannot be reduced more (check [**wikipedia**](https://en.wikipedia.org/wiki/Byte\_pair\_encoding)). Note that this way there aren't "unknown" words for the vocabulary and the final vocabulary will be all the discovered sets of frequent bytes together grouped as much as possible while bytes that aren't frequently linked with the same byte will be a token themselves.

### Code Example

Let's understand this better from a code example from [https://github.com/rasbt/LLMs-from-scratch/blob/main/ch02/01\_main-chapter-code/ch02.ipynb](https://github.com/rasbt/LLMs-from-scratch/blob/main/ch02/01\_main-chapter-code/ch02.ipynb):

```python
# Download a text to pre-train the model
import urllib.request
url = ("https://raw.githubusercontent.com/rasbt/LLMs-from-scratch/main/ch02/01_main-chapter-code/the-verdict.txt")
file_path = "the-verdict.txt"
urllib.request.urlretrieve(url, file_path)

with open("the-verdict.txt", "r", encoding="utf-8") as f:
    raw_text = f.read()

# Tokenize the code using GPT2 tokenizer version
import tiktoken
token_ids = tiktoken.get_encoding("gpt2").encode(txt, allowed_special={"[EOS]"}) # Allow the user of the tag "[EOS]"

# Print first 50 tokens
print(token_ids[:50])
#[40, 367, 2885, 1464, 1807, 3619, 402, 271, 10899, 2138, 257, 7026, 15632, 438, 2016, 257, 922, 5891, 1576, 438, 568, 340, 373, 645, 1049, 5975, 284, 502, 284, 3285, 326, 11, 287, 262, 6001, 286, 465, 13476, 11, 339, 550, 5710, 465, 12036, 11, 6405, 257, 5527, 27075, 11]
```

## Data Sampling

LLMs like GPT work by predicting the next word based on the previous ones, therefore in order to prepare some data for training it's necessary to prepare the data this way.

For example, using the text `"Lorem ipsum dolor sit amet, consectetur adipiscing elit,"`

In order to prepare the model to learn predicting the following word (supposing each word is a token using the very basic tokenizer), and using a max size of 4 and a sliding window of 1, this is how the text should be prepared:

```javascript
Input: [
  ["Lorem", "ipsum", "dolor", "sit"],
  ["ipsum", "dolor", "sit", "amet,"],
  ["dolor", "sit", "amet,", "consectetur"],
  ["sit", "amet,", "consectetur", "adipiscing"],
],
Target: [
  ["ipsum", "dolor", "sit", "amet,"],
  ["dolor", "sit", "amet,", "consectetur"],
  ["sit", "amet,", "consectetur", "adipiscing"],
  ["amet,", "consectetur", "adipiscing", "elit,"],
  ["consectetur", "adipiscing", "elit,", "sed"],
]
```

Note that if the sliding window would have been 2, it means that the next entry in the input array will start 2 tokens after and not just one, but the target array will still be predicting only 1 token. In `pytorch`, this sliding window is expressed in the parameter `stride` (the smaller `stride` is, the more overfitting, usually this is equals to the max\_length so the same tokens aren't repeated).

### Code Example

Let's understand this better from a code example from [https://github.com/rasbt/LLMs-from-scratch/blob/main/ch02/01\_main-chapter-code/ch02.ipynb](https://github.com/rasbt/LLMs-from-scratch/blob/main/ch02/01\_main-chapter-code/ch02.ipynb):

```python
# Download the text to pre-train the LLM
import urllib.request
url = ("https://raw.githubusercontent.com/rasbt/LLMs-from-scratch/main/ch02/01_main-chapter-code/the-verdict.txt")
file_path = "the-verdict.txt"
urllib.request.urlretrieve(url, file_path)

with open("the-verdict.txt", "r", encoding="utf-8") as f:
    raw_text = f.read()

"""
Create a class that will receive some params lie tokenizer and text
and will prepare the input chunks and the target chunks to prepare
the LLM to learn which next token to generate
"""
import torch
from torch.utils.data import Dataset, DataLoader

class GPTDatasetV1(Dataset):
    def __init__(self, txt, tokenizer, max_length, stride):
        self.input_ids = []
        self.target_ids = []

        # Tokenize the entire text
        token_ids = tokenizer.encode(txt, allowed_special={"<|endoftext|>"})

        # Use a sliding window to chunk the book into overlapping sequences of max_length
        for i in range(0, len(token_ids) - max_length, stride):
            input_chunk = token_ids[i:i + max_length]
            target_chunk = token_ids[i + 1: i + max_length + 1]
            self.input_ids.append(torch.tensor(input_chunk))
            self.target_ids.append(torch.tensor(target_chunk))

    def __len__(self):
        return len(self.input_ids)

    def __getitem__(self, idx):
        return self.input_ids[idx], self.target_ids[idx]


"""
Create a data loader which given the text and some params will
prepare the inputs and targets with the previous class and
then create a torch DataLoader with the info
"""

import tiktoken

def create_dataloader_v1(txt, batch_size=4, max_length=256, 
                         stride=128, shuffle=True, drop_last=True,
                         num_workers=0):

    # Initialize the tokenizer
    tokenizer = tiktoken.get_encoding("gpt2")

    # Create dataset
    dataset = GPTDatasetV1(txt, tokenizer, max_length, stride)

    # Create dataloader
    dataloader = DataLoader(
        dataset,
        batch_size=batch_size,
        shuffle=shuffle,
        drop_last=drop_last,
        num_workers=num_workers
    )

    return dataloader


"""
Finally, create the data loader with the params we want:
- The used text for training
- batch_size: The size of each batch
- max_length: The size of each entry on each batch
- stride: The sliding window (how many tokens should the next entry advance compared to the previous one). The smaller the more overfitting, usually this is equals to the max_length so the same tokens aren't repeated.
- shuffle: Re-order randomly
"""
dataloader = create_dataloader_v1(
    raw_text, batch_size=8, max_length=4, stride=1, shuffle=False
)

data_iter = iter(dataloader)
first_batch = next(data_iter)
print(first_batch)

# Note the batch_size of 8, the max_length of 4 and the stride of 1
[
# Input
tensor([[   40,   367,  2885,  1464],
        [  367,  2885,  1464,  1807],
        [ 2885,  1464,  1807,  3619],
        [ 1464,  1807,  3619,   402],
        [ 1807,  3619,   402,   271],
        [ 3619,   402,   271, 10899],
        [  402,   271, 10899,  2138],
        [  271, 10899,  2138,   257]]),
# Target
tensor([[  367,  2885,  1464,  1807],
        [ 2885,  1464,  1807,  3619],
        [ 1464,  1807,  3619,   402],
        [ 1807,  3619,   402,   271],
        [ 3619,   402,   271, 10899],
        [  402,   271, 10899,  2138],
        [  271, 10899,  2138,   257],
        [10899,  2138,   257,  7026]])
]

# With stride=4 this will be the result:
[
# Input
tensor([[   40,   367,  2885,  1464],
        [ 1807,  3619,   402,   271],
        [10899,  2138,   257,  7026],
        [15632,   438,  2016,   257],
        [  922,  5891,  1576,   438],
        [  568,   340,   373,   645],
        [ 1049,  5975,   284,   502],
        [  284,  3285,   326,    11]]),
# Target
tensor([[  367,  2885,  1464,  1807],
        [ 3619,   402,   271, 10899],
        [ 2138,   257,  7026, 15632],
        [  438,  2016,   257,   922],
        [ 5891,  1576,   438,   568],
        [  340,   373,   645,  1049],
        [ 5975,   284,   502,   284],
        [ 3285,   326,    11,   287]])
]
```

## Token Embeddings

Now that we have all the text encoded in tokens it's time to create **token embeddings**. This embeddings are going to be the **weights given each token in the vocabulary on each dimension to train**. They usually start by being random small values .

For example, for a **vocabulary of size 6  and 3 dimensions** (LLMs has ten of thousands of vocabs and billions of dimensions), this is how it's possible to generate some starting embeddings:&#x20;

```python
torch.manual_seed(123)
embedding_layer = torch.nn.Embedding(6, 3)
print(embedding_layer.weight)


Parameter containing:
tensor([[ 0.3374, -0.1778, -0.1690],
        [ 0.9178,  1.5810,  1.3010],
        [ 1.2753, -0.2010, -0.1606],
        [-0.4015,  0.9666, -1.1481],
        [-1.1589,  0.3255, -0.6315],
        [-2.8400, -0.7849, -1.4096]], requires_grad=True)

# This is a way to search the weights based on the index, "3" in this case:
print(embedding_layer(torch.tensor([3])))
tensor([[-0.4015,  0.9666, -1.1481]], grad_fn=<EmbeddingBackward0>)
```

Note how each token in the vocabulary (each of the `6` rows), has `3` dimensions (`3` columns) with a value on each.

Therefore, in our training, each token will have a set of values (dimensions) that will apply weights to it. Therefore, if a training batch is of size `8`, with max length of `4` and `256` dimensions. It means that each batch will be a matrix of `8 x 4 x 256` (imagine batches of hundreds of entries, with hundreds of tokens per entries with billions of dimensions...).

**The values of the dimensions are fine tuned during the training.**

### Token Positions Embeddings

If you noticed, the embeddings gives some weights to tokens based only on the token. So if a word (supposing a word is a token) is **at the beginning of a text, it'll have the same weights as if it's at the end**, although its contributions to the sentence might be different.

Therefore, it's possible to apply **absolute positional embeddings** or **relative positional embeddings**. One will take into account the position of the token in the whole sentence, while the other will take into account distances between tokens.\
OpenAI GPT uses **absolute positional embeddings.**

Note that because absolute positional embeddings uses the same dimensions as the token embeddings, they will be added with them but **won't add extra dimensions to the matrix**.

**The position values are fine tuned during the training.**

### Code Example

Following with the code example from [https://github.com/rasbt/LLMs-from-scratch/blob/main/ch02/01\_main-chapter-code/ch02.ipynb](https://github.com/rasbt/LLMs-from-scratch/blob/main/ch02/01\_main-chapter-code/ch02.ipynb):

```python
# Use previous code...

# Create dimensional emdeddings
"""
BPE uses a vocabulary of 50257 words
Let's supose we want to use 256 dimensions (instead of the millions used by LLMs)
"""

vocab_size = 50257
output_dim = 256
token_embedding_layer = torch.nn.Embedding(vocab_size, output_dim)

## Generate the dataloader like before
max_length = 4
dataloader = create_dataloader_v1(
    raw_text, batch_size=8, max_length=max_length,
    stride=max_length, shuffle=False
)
data_iter = iter(dataloader)
inputs, targets = next(data_iter)

# Apply embeddings
token_embeddings = token_embedding_layer(inputs)
print(token_embeddings.shape)
torch.Size([8, 4, 256]) # 8 x 4 x 256

# Generate absolute embeddings
context_length = max_length
pos_embedding_layer = torch.nn.Embedding(context_length, output_dim)

pos_embeddings = pos_embedding_layer(torch.arange(max_length))

input_embeddings = token_embeddings + pos_embeddings
print(input_embeddings.shape) # torch.Size([8, 4, 256])
```

## Attention Mechanisms & Self-Attention

These are the applied weights that helps select which inputs affects the most to one token. As an example, a translator from one language to another will need to have the context not only of the current sentence but of the complete context in order to properly translate each word.

Moreover, the concept **self-attention** means all the weights the tokens in the text have over to a specific one (the more related they are the bigger weight they will have).\
This means, that whenever we are trying to predict the next token it's not just a matter of the previous token weights and their position weights, but also about the weight respect to the word to predict.

In order to get the weight of a token over a specific token, each dimension weight of each token is multiplied by the weight from that token over the token and the results are added.

So for example, in the sentence "Hello shiny sun!", if 3 dimensions are used they might be like:

* `Hello` -> \[0.34, 0.22, 0.54]
* `shiny` -> \[0.53, 0.34, 0.98]
* `sun` -> \[0.29, 0.54, 0.93]

Then, `Hello` , `shiny` and `sun` will have its own weight over `shiny`, which might be `0.23` , `1.3` and `0.84`.

* The intermediate attention score of `Hello` over `shiny` would be: `0.34 * 0.53 + 0.22 * 0.34 + 0.54 * 0.98 = 0.7842`
* The one of `shiny` will be: `0.53 * 0.53 + 0.34 * 0.34 + 0.98 * 0.98 = 2.405`
* The one of `sun` over `shiny` will be: `0.29 * 0.53 + 0.54 * 0.34 + 0.93 * 0.98 = 1.2487`

This operation is called **dot product** can be easily performed with a code like:

```python
res = 0
for idx, element in enumerate(inputs[0]):
    res += inputs[0][idx] * query[idx]
print(res)
print(torch.dot(inputs[0], query))
```

Then, these results are usually **normalised** so all of them ads 1 using the `torch.softmax` function. In these case the values will be **`[ 0.13074, 0.66139, 0.20887 ]`**

With this we will have the normalized attention weight of every token over one of the tokens. And this allows to calculate the **context vector**, which will multiply the attention weight of every token over one token to each dimension of each token while adding them per dimension. So in this case this will be:

**`[0.34, 0.22, 0.54]*0.13074 + [0.53, 0.34, 0.98]*0.66139 + [0.29, 0.54, 0.93]*0.20887 = [ 0.4555606, 0.3664252, 0.9130109 ]`**

That will be the context vector of the word "shiny" in the sentence "Hello shiny sun" according to the stablished weights.

{% hint style="info" %}
As summary we first calculated the attention weights of each token to a specific token by performing the dot product of the dimensional values of each token to the specific token. Then, these values were normalized and finally the normalization was used to multiply each dimension of each token and sum the values.
{% endhint %}

### Self-Attention with trainable weights

For this, 3 new matrices are added: Wq (query), Wk (keys) and Wv (values).

Their dimensions will depend on the number of inputs and output we want. In the previous example the number of dimensions pe rtoken was 3, and we might be interested in 2 dimensions as output. Therfore:

```python
W_query = torch.nn.Parameter(torch.rand(d_in, d_out), requires_grad=False)
W_key = torch.nn.Parameter(torch.rand(d_in, d_out), requires_grad=False)
W_value = torch.nn.Parameter(torch.rand(d_in, d_out), requires_grad=False)
```

Then, we need to compute each Wq, Wk and Wv per token. For the "shiny" token previuosky thiw will be like:

* Wq\_shiny = \[0.53, 0.34, 0.98] \* Wq
* Wk\_shiny = \[0.53, 0.34, 0.98] \* Wk
* Wv\_shiny = \[0.53, 0.34, 0.98] \* Wv

It would be also possible to compute all the Wk in python for example with: **`keys = inputs @ W_key`** which will be a matrix of 3x2 (3 inputs we had with 3 dimensions each, 2 output).

Then, to compute the **attention score** of each token it's just needed to do a **dot product** of the **query** with the **key vector** (like before but using the key vector of the token instead of its dimensions).

Having all the attention scores, it's possible to get the attention weights it's just needed to normalize them. In this case you could use the softmax function of the scores divided by the square root of the number of dimensions of the keys: **`torch.softmax(att_score / d_k**0.5, dim=-1)`** (expo 0.5 is the same as sqrt).

Finally, to compute the context vectors it's just needed to **multiply the values matrices with the attention weight and add them.**

### Code Exaple

Grabbing an example from [https://github.com/rasbt/LLMs-from-scratch/blob/main/ch03/01\_main-chapter-code/ch03.ipynb](https://github.com/rasbt/LLMs-from-scratch/blob/main/ch03/01\_main-chapter-code/ch03.ipynb) you can check this class that implements the self-attendant functionality we talked about:

```python
import torch

inputs = torch.tensor(
  [[0.43, 0.15, 0.89], # Your     (x^1)
   [0.55, 0.87, 0.66], # journey  (x^2)
   [0.57, 0.85, 0.64], # starts   (x^3)
   [0.22, 0.58, 0.33], # with     (x^4)
   [0.77, 0.25, 0.10], # one      (x^5)
   [0.05, 0.80, 0.55]] # step     (x^6)
)

import torch.nn as nn
class SelfAttention_v2(nn.Module):

    def __init__(self, d_in, d_out, qkv_bias=False):
        super().__init__()
        self.W_query = nn.Linear(d_in, d_out, bias=qkv_bias)
        self.W_key   = nn.Linear(d_in, d_out, bias=qkv_bias)
        self.W_value = nn.Linear(d_in, d_out, bias=qkv_bias)

    def forward(self, x):
        keys = self.W_key(x)
        queries = self.W_query(x)
        values = self.W_value(x)
        
        attn_scores = queries @ keys.T
        attn_weights = torch.softmax(attn_scores / keys.shape[-1]**0.5, dim=-1)

        context_vec = attn_weights @ values
        return context_vec

d_in=3
d_out=2
torch.manual_seed(789)
sa_v2 = SelfAttention_v2(d_in, d_out)
print(sa_v2(inputs))
```

{% hint style="info" %}
Note that instead of initializing the matrices with random values, `nn.Linear` is used (because the guy of the book says it's better, TODO)
{% endhint %}













## Attention Mechanisms and Self-Attention in Neural Networks

Attention mechanisms allow neural networks to focus on specific parts of the input when generating each part of the output. They assign different weights to different inputs, helping the model decide which inputs are most relevant to the task at hand. This is crucial in tasks like machine translation, where understanding the context of the entire sentence is necessary for accurate translation.

### Understanding Attention Mechanisms

In traditional sequence-to-sequence models used for language translation, the model encodes an input sequence into a fixed-size context vector. However, this approach struggles with long sentences because the fixed-size context vector may not capture all necessary information. Attention mechanisms address this limitation by allowing the model to consider all input tokens when generating each output token.

#### Example: Machine Translation

Consider translating the German sentence "Kannst du mir helfen diesen Satz zu übersetzen" into English. A word-by-word translation would not produce a grammatically correct English sentence due to differences in grammatical structures between languages. An attention mechanism enables the model to focus on relevant parts of the input sentence when generating each word of the output sentence, leading to a more accurate and coherent translation.

### Introduction to Self-Attention

Self-attention, or intra-attention, is a mechanism where attention is applied within a single sequence to compute a representation of that sequence. It allows each token in the sequence to attend to all other tokens, helping the model capture dependencies between tokens regardless of their distance in the sequence.

#### Key Concepts

* **Tokens**: Individual elements of the input sequence (e.g., words in a sentence).
* **Embeddings**: Vector representations of tokens, capturing semantic information.
* **Attention Weights**: Values that determine the importance of each token relative to others.

### Calculating Attention Weights: A Step-by-Step Example

Let's consider the sentence **"Hello shiny sun!"** and represent each word with a 3-dimensional embedding:

* **Hello**: `[0.34, 0.22, 0.54]`
* **shiny**: `[0.53, 0.34, 0.98]`
* **sun**: `[0.29, 0.54, 0.93]`

Our goal is to compute the **context vector** for the word **"shiny"** using self-attention.

#### Step 1: Compute Attention Scores

For each word in the sentence, compute the **attention score** with respect to "shiny" by calculating the dot product of their embeddings.

**Attention Score between "Hello" and "shiny"**

scoreHello, shiny=(0.34×0.53)+(0.22×0.34)+(0.54×0.98)=0.1802+0.0748+0.5292=0.7842\begin{align\*} \text{score}\_{\text{Hello, shiny\}} &= (0.34 \times 0.53) + (0.22 \times 0.34) + (0.54 \times 0.98) \\\ &= 0.1802 + 0.0748 + 0.5292 \\\ &= 0.7842 \end{align\*}scoreHello, shiny​​=(0.34×0.53)+(0.22×0.34)+(0.54×0.98)=0.1802+0.0748+0.5292=0.7842​

**Attention Score between "shiny" and "shiny"**

scoreshiny, shiny=(0.53×0.53)+(0.34×0.34)+(0.98×0.98)=0.2809+0.1156+0.9604=1.3569\begin{align\*} \text{score}\_{\text{shiny, shiny\}} &= (0.53 \times 0.53) + (0.34 \times 0.34) + (0.98 \times 0.98) \\\ &= 0.2809 + 0.1156 + 0.9604 \\\ &= 1.3569 \end{align\*}scoreshiny, shiny​​=(0.53×0.53)+(0.34×0.34)+(0.98×0.98)=0.2809+0.1156+0.9604=1.3569​

**Attention Score between "sun" and "shiny"**

scoresun, shiny=(0.29×0.53)+(0.54×0.34)+(0.93×0.98)=0.1537+0.1836+0.9114=1.2487\begin{align\*} \text{score}\_{\text{sun, shiny\}} &= (0.29 \times 0.53) + (0.54 \times 0.34) + (0.93 \times 0.98) \\\ &= 0.1537 + 0.1836 + 0.9114 \\\ &= 1.2487 \end{align\*}scoresun, shiny​​=(0.29×0.53)+(0.54×0.34)+(0.93×0.98)=0.1537+0.1836+0.9114=1.2487​

#### Step 2: Normalize Attention Scores to Obtain Attention Weights

Apply the **softmax function** to the attention scores to convert them into attention weights that sum to 1.

αi=escorei∑jescorej\alpha\_i = \frac{e^{\text{score}\_i\}}{\sum\_{j} e^{\text{score}\_j\}}αi​=∑j​escorej​escorei​​

Calculating the exponentials:

e0.7842=2.1902e1.3569=3.8839e1.2487=3.4858\begin{align\*} e^{0.7842} &= 2.1902 \\\ e^{1.3569} &= 3.8839 \\\ e^{1.2487} &= 3.4858 \end{align\*}e0.7842e1.3569e1.2487​=2.1902=3.8839=3.4858​

Calculating the sum:

∑iescorei=2.1902+3.8839+3.4858=9.5599\sum\_{i} e^{\text{score}\_i} = 2.1902 + 3.8839 + 3.4858 = 9.5599i∑​escorei​=2.1902+3.8839+3.4858=9.5599

Calculating attention weights:

αHello=2.19029.5599=0.2291αshiny=3.88399.5599=0.4064αsun=3.48589.5599=0.3645\begin{align\*} \alpha\_{\text{Hello\}} &= \frac{2.1902}{9.5599} = 0.2291 \\\ \alpha\_{\text{shiny\}} &= \frac{3.8839}{9.5599} = 0.4064 \\\ \alpha\_{\text{sun\}} &= \frac{3.4858}{9.5599} = 0.3645 \end{align\*}αHello​αshiny​αsun​​=9.55992.1902​=0.2291=9.55993.8839​=0.4064=9.55993.4858​=0.3645​

#### Step 3: Compute the Context Vector

The **context vector** is computed as the weighted sum of the embeddings of all words, using the attention weights.

context vector=∑iαi×embeddingi\text{context vector} = \sum\_{i} \alpha\_i \times \text{embedding}\_icontext vector=i∑​αi​×embeddingi​

Calculating each component:

*   **Weighted Embedding of "Hello"**:

    αHello×embeddingHello=0.2291×\[0.34,0.22,0.54]=\[0.0779,0.0504,0.1237]\alpha\_{\text{Hello\}} \times \text{embedding}\_{\text{Hello\}} = 0.2291 \times \[0.34, 0.22, 0.54] = \[0.0779, 0.0504, 0.1237]αHello​×embeddingHello​=0.2291×\[0.34,0.22,0.54]=\[0.0779,0.0504,0.1237]
*   **Weighted Embedding of "shiny"**:

    αshiny×embeddingshiny=0.4064×\[0.53,0.34,0.98]=\[0.2156,0.1382,0.3983]\alpha\_{\text{shiny\}} \times \text{embedding}\_{\text{shiny\}} = 0.4064 \times \[0.53, 0.34, 0.98] = \[0.2156, 0.1382, 0.3983]αshiny​×embeddingshiny​=0.4064×\[0.53,0.34,0.98]=\[0.2156,0.1382,0.3983]
*   **Weighted Embedding of "sun"**:

    αsun×embeddingsun=0.3645×\[0.29,0.54,0.93]=\[0.1057,0.1972,0.3390]\alpha\_{\text{sun\}} \times \text{embedding}\_{\text{sun\}} = 0.3645 \times \[0.29, 0.54, 0.93] = \[0.1057, 0.1972, 0.3390]αsun​×embeddingsun​=0.3645×\[0.29,0.54,0.93]=\[0.1057,0.1972,0.3390]

Summing the weighted embeddings:

context vector=\[0.0779+0.2156+0.1057, 0.0504+0.1382+0.1972, 0.1237+0.3983+0.3390]=\[0.3992,0.3858,0.8610]\text{context vector} = \[0.0779 + 0.2156 + 0.1057, \ 0.0504 + 0.1382 + 0.1972, \ 0.1237 + 0.3983 + 0.3390] = \[0.3992, 0.3858, 0.8610]context vector=\[0.0779+0.2156+0.1057, 0.0504+0.1382+0.1972, 0.1237+0.3983+0.3390]=\[0.3992,0.3858,0.8610]

This context vector represents the enriched embedding for the word "shiny," incorporating information from all words in the sentence.

### Summary of the Process

1. **Compute Attention Scores**: Use the dot product between the embedding of the target word and the embeddings of all words in the sequence.
2. **Normalize Scores to Get Attention Weights**: Apply the softmax function to the attention scores to obtain weights that sum to 1.
3. **Compute Context Vector**: Multiply each word's embedding by its attention weight and sum the results.

### Self-Attention with Trainable Weights

In practice, self-attention mechanisms use **trainable weights** to learn the best representations for queries, keys, and values. This involves introducing three weight matrices:

* **WqW\_qWq​** (Weights for queries)
* **WkW\_kWk​** (Weights for keys)
* **WvW\_vWv​** (Weights for values)

#### Step 1: Compute Queries, Keys, and Values

For each token embedding xix\_ixi​:

* **Query**: qi=xi×Wqq\_i = x\_i \times W\_qqi​=xi​×Wq​
* **Key**: ki=xi×Wkk\_i = x\_i \times W\_kki​=xi​×Wk​
* **Value**: vi=xi×Wvv\_i = x\_i \times W\_vvi​=xi​×Wv​

These matrices transform the original embeddings into a new space suitable for computing attention.

**Example**

Assuming:

* Input dimension din=3d\_{\text{in\}} = 3din​=3 (embedding size)
* Output dimension dout=2d\_{\text{out\}} = 2dout​=2 (desired dimension for queries, keys, and values)

Initialize the weight matrices:

```python
pythonCopy codeimport torch.nn as nn

d_in = 3
d_out = 2

W_query = nn.Parameter(torch.rand(d_in, d_out))
W_key = nn.Parameter(torch.rand(d_in, d_out))
W_value = nn.Parameter(torch.rand(d_in, d_out))
```

Compute queries, keys, and values:

```python
pythonCopy codequeries = torch.matmul(inputs, W_query)
keys = torch.matmul(inputs, W_key)
values = torch.matmul(inputs, W_value)
```

#### Step 2: Compute Scaled Dot-Product Attention

**Compute Attention Scores**

For each query qiq\_iqi​ and key kjk\_jkj​:

scoreij=qi⋅kj\text{score}\_{ij} = q\_i \cdot k\_jscoreij​=qi​⋅kj​

**Scale the Scores**

To prevent the dot products from becoming too large, scale them by the square root of the key dimension dkd\_kdk​:

scaled scoreij=scoreijdk\text{scaled score}\_{ij} = \frac{\text{score}\_{ij\}}{\sqrt{d\_k\}}scaled scoreij​=dk​​scoreij​​

**Apply Softmax to Obtain Attention Weights**

αij=softmax(scaled scoreij)\alpha\_{ij} = \text{softmax}(\text{scaled score}\_{ij})αij​=softmax(scaled scoreij​)

#### Step 3: Compute Context Vectors

Compute the context vector for each token by taking the weighted sum of the value vectors:

context vectori=∑jαij×vj\text{context vector}\_i = \sum\_{j} \alpha\_{ij} \times v\_jcontext vectori​=j∑​αij​×vj​

#### Implementation in Code

```python
pythonCopy codeclass SelfAttention(nn.Module):
    def __init__(self, d_in, d_k):
        super(SelfAttention, self).__init__()
        self.W_query = nn.Linear(d_in, d_k, bias=False)
        self.W_key = nn.Linear(d_in, d_k, bias=False)
        self.W_value = nn.Linear(d_in, d_k, bias=False)

    def forward(self, x):
        queries = self.W_query(x)
        keys = self.W_key(x)
        values = self.W_value(x)
        
        scores = torch.matmul(queries, keys.transpose(-2, -1)) / (d_k ** 0.5)
        attention_weights = torch.softmax(scores, dim=-1)
        context = torch.matmul(attention_weights, values)
        return context
```

#### Exercise 1: Comparing `SelfAttention_v1` and `SelfAttention_v2`

In the implementations of `SelfAttention_v1` and `SelfAttention_v2`, there is a difference in how the weight matrices are initialized:

* **`SelfAttention_v1`** uses `nn.Parameter(torch.rand(d_in, d_out))`.
* **`SelfAttention_v2`** uses `nn.Linear(d_in, d_out, bias=False)`, which initializes weights using a more sophisticated method.

To ensure both implementations produce the same output, we need to transfer the weights from an instance of `SelfAttention_v2` to an instance of `SelfAttention_v1`. However, we must consider that `nn.Linear` stores weights in a transposed form compared to `nn.Parameter`.

**Solution**

1.  Create instances of both classes:

    ```python
    pythonCopy codesa_v1 = SelfAttention_v1(d_in, d_out)
    sa_v2 = SelfAttention_v2(d_in, d_out)
    ```
2.  Assign weights from `sa_v2` to `sa_v1` with appropriate transposition:

    ```python
    pythonCopy codesa_v1.W_query.data = sa_v2.W_query.weight.data.t()
    sa_v1.W_key.data = sa_v2.W_key.weight.data.t()
    sa_v1.W_value.data = sa_v2.W_value.weight.data.t()
    ```
3.  Verify that both produce the same output:

    ```python
    pythonCopy codeoutput_v1 = sa_v1(inputs)
    output_v2 = sa_v2(inputs)
    assert torch.allclose(output_v1, output_v2)
    ```

### Causal Attention: Hiding Future Words

In tasks like language modeling, we want the model to consider only the tokens that appear before the current position when predicting the next token. **Causal attention**, also known as **masked attention**, achieves this by modifying the attention mechanism to prevent access to future tokens.

#### Applying a Causal Attention Mask

To implement causal attention, we apply a mask to the attention scores before the softmax operation. This mask sets the attention scores of future tokens to negative infinity, ensuring that after the softmax, their attention weights are zero.

**Steps**

1. **Compute Attention Scores**: Same as before.
2.  **Apply Mask**: Use an upper triangular matrix filled with negative infinity above the diagonal.

    ```python
    pythonCopy codemask = torch.triu(torch.ones(seq_len, seq_len), diagonal=1) * float('-inf')
    masked_scores = attention_scores + mask
    ```
3.  **Apply Softmax**: Compute attention weights using the masked scores.

    ```python
    pythonCopy codeattention_weights = torch.softmax(masked_scores, dim=-1)
    ```

#### Masking Additional Attention Weights with Dropout

To prevent overfitting, we can apply **dropout** to the attention weights after the softmax operation. Dropout randomly zeroes some of the attention weights during training.

```python
pythonCopy codedropout = nn.Dropout(p=0.5)
attention_weights = dropout(attention_weights)
```

#### Implementing a Compact Causal Attention Class

We can encapsulate the causal attention mechanism into a PyTorch module:

```python
pythonCopy codeclass CausalAttention(nn.Module):
    def __init__(self, d_in, d_out, seq_len, dropout_rate):
        super(CausalAttention, self).__init__()
        self.W_query = nn.Linear(d_in, d_out, bias=False)
        self.W_key = nn.Linear(d_in, d_out, bias=False)
        self.W_value = nn.Linear(d_in, d_out, bias=False)
        self.dropout = nn.Dropout(dropout_rate)
        self.register_buffer('mask', torch.triu(torch.ones(seq_len, seq_len), diagonal=1) * float('-inf'))

    def forward(self, x):
        queries = self.W_query(x)
        keys = self.W_key(x)
        values = self.W_value(x)
        
        scores = torch.matmul(queries, keys.transpose(-2, -1)) / (d_out ** 0.5)
        scores += self.mask[:x.size(1), :x.size(1)]
        attention_weights = torch.softmax(scores, dim=-1)
        attention_weights = self.dropout(attention_weights)
        context = torch.matmul(attention_weights, values)
        return context
```

### Extending Single-Head Attention to Multi-Head Attention

**Multi-head attention** allows the model to attend to information from different representation subspaces at different positions. This is achieved by splitting the attention mechanism into multiple "heads," each with its own set of weight matrices.

#### Implementing Multi-Head Attention by Stacking Layers

We can create multiple instances of the attention mechanism and concatenate their outputs:

```python
pythonCopy codeclass MultiHeadAttention(nn.Module):
    def __init__(self, d_in, d_out, seq_len, num_heads, dropout_rate):
        super(MultiHeadAttention, self).__init__()
        self.num_heads = num_heads
        self.attention_heads = nn.ModuleList([CausalAttention(d_in, d_out // num_heads, seq_len, dropout_rate) for _ in range(num_heads)])
        self.linear = nn.Linear(d_out, d_out)

    def forward(self, x):
        head_outputs = [head(x) for head in self.attention_heads]
        concat = torch.cat(head_outputs, dim=-1)
        output = self.linear(concat)
        return output
```

#### Efficient Implementation with Weight Splits

To optimize the computation, we can perform all the attention computations in parallel without explicit loops by reshaping tensors:

```python
pythonCopy codeclass MultiHeadAttentionEfficient(nn.Module):
    def __init__(self, d_in, d_out, seq_len, num_heads, dropout_rate):
        super(MultiHeadAttentionEfficient, self).__init__()
        assert d_out % num_heads == 0
        self.num_heads = num_heads
        self.head_dim = d_out // num_heads
        self.W_query = nn.Linear(d_in, d_out, bias=False)
        self.W_key = nn.Linear(d_in, d_out, bias=False)
        self.W_value = nn.Linear(d_in, d_out, bias=False)
        self.dropout = nn.Dropout(dropout_rate)
        self.register_buffer('mask', torch.triu(torch.ones(seq_len, seq_len), diagonal=1) * float('-inf'))
        self.out_proj = nn.Linear(d_out, d_out)

    def forward(self, x):
        batch_size, seq_len, _ = x.size()
        queries = self.W_query(x).view(batch_size, seq_len, self.num_heads, self.head_dim).transpose(1,2)
        keys = self.W_key(x).view(batch_size, seq_len, self.num_heads, self.head_dim).transpose(1,2)
        values = self.W_value(x).view(batch_size, seq_len, self.num_heads, self.head_dim).transpose(1,2)
        
        scores = torch.matmul(queries, keys.transpose(-2, -1)) / (self.head_dim ** 0.5)
        scores += self.mask[:seq_len, :seq_len]
        attention_weights = torch.softmax(scores, dim=-1)
        attention_weights = self.dropout(attention_weights)
        
        context = torch.matmul(attention_weights, values).transpose(1,2).contiguous().view(batch_size, seq_len, -1)
        output = self.out_proj(context)
        return output
```

**Explanation of Code Components**

* **Reshaping**: The `view` and `transpose` operations split the embeddings into multiple heads.
* **Parallel Computation**: Matrix multiplications are performed in parallel across all heads.
* **Output Projection**: The outputs from all heads are concatenated and passed through a linear layer.

####



