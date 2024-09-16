# LLM Training - Data Preparation

**These are my notes from the book** [**https://www.manning.com/books/build-a-large-language-model-from-scratch**](https://www.manning.com/books/build-a-large-language-model-from-scratch) **(very recommended)**

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

{% hint style="success" %}
Just multiply each dimension value of the query with the relevant one of each token and add the results. You get 1 value per pair of tokens.
{% endhint %}

For each word in the sentence, compute the **attention score** with respect to "shiny" by calculating the dot product of their embeddings.

**Attention Score between "Hello" and "shiny"**

<figure><img src="../.gitbook/assets/image.png" alt="" width="563"><figcaption></figcaption></figure>

**Attention Score between "shiny" and "shiny"**

<figure><img src="../.gitbook/assets/image (1).png" alt="" width="563"><figcaption></figcaption></figure>

**Attention Score between "sun" and "shiny"**

<figure><img src="../.gitbook/assets/image (2).png" alt="" width="563"><figcaption></figcaption></figure>

#### Step 2: Normalize Attention Scores to Obtain Attention Weights

{% hint style="success" %}
Don't get lost in the mathematical terms, the goal of this function is simple, normalize all the weights so **they sum 1 in total**.

Moreover, **softmax** function is used because it accentuates differences due to the exponential part, making easier to detect useful values.
{% endhint %}

Apply the **softmax function** to the attention scores to convert them into attention weights that sum to 1.

<figure><img src="../.gitbook/assets/image (3).png" alt="" width="293"><figcaption></figcaption></figure>

Calculating the exponentials:

<figure><img src="../.gitbook/assets/image (4).png" alt="" width="249"><figcaption></figcaption></figure>

Calculating the sum:

<figure><img src="../.gitbook/assets/image (5).png" alt="" width="563"><figcaption></figcaption></figure>

Calculating attention weights:

<figure><img src="../.gitbook/assets/image (6).png" alt="" width="404"><figcaption></figcaption></figure>

#### Step 3: Compute the Context Vector

{% hint style="success" %}
Just get each attention weight and multiply it to the related token dimensions and then sum all the dimensions to get just 1 vector (the context vector)&#x20;
{% endhint %}

The **context vector** is computed as the weighted sum of the embeddings of all words, using the attention weights.

<figure><img src="../.gitbook/assets/image (16).png" alt="" width="369"><figcaption></figcaption></figure>

Calculating each component:

*   **Weighted Embedding of "Hello"**:

    <figure><img src="../.gitbook/assets/image (7).png" alt=""><figcaption></figcaption></figure>
*   **Weighted Embedding of "shiny"**:

    <figure><img src="../.gitbook/assets/image (8).png" alt=""><figcaption></figcaption></figure>
*   **Weighted Embedding of "sun"**:

    <figure><img src="../.gitbook/assets/image (9).png" alt=""><figcaption></figcaption></figure>

Summing the weighted embeddings:

`context vector=[0.0779+0.2156+0.1057, 0.0504+0.1382+0.1972, 0.1237+0.3983+0.3390]=[0.3992,0.3858,0.8610]`

**This context vector represents the enriched embedding for the word "shiny," incorporating information from all words in the sentence.**

### Summary of the Process

1. **Compute Attention Scores**: Use the dot product between the embedding of the target word and the embeddings of all words in the sequence.
2. **Normalize Scores to Get Attention Weights**: Apply the softmax function to the attention scores to obtain weights that sum to 1.
3. **Compute Context Vector**: Multiply each word's embedding by its attention weight and sum the results.

## Self-Attention with Trainable Weights

In practice, self-attention mechanisms use **trainable weights** to learn the best representations for queries, keys, and values. This involves introducing three weight matrices:

<figure><img src="../.gitbook/assets/image (10).png" alt="" width="239"><figcaption></figcaption></figure>

The query is the data to use like before, while the keys and values matrices are just random-trainable matrices.

#### Step 1: Compute Queries, Keys, and Values

Each token will have its own query, key and value matrix by multiplying its dimension values by the defined matrices:

<figure><img src="../.gitbook/assets/image (11).png" alt="" width="253"><figcaption></figcaption></figure>

These matrices transform the original embeddings into a new space suitable for computing attention.

**Example**

Assuming:

* Input dimension `din=3` (embedding size)
* Output dimension `dout=2` (desired dimension for queries, keys, and values)

Initialize the weight matrices:

```python
import torch.nn as nn

d_in = 3
d_out = 2

W_query = nn.Parameter(torch.rand(d_in, d_out))
W_key = nn.Parameter(torch.rand(d_in, d_out))
W_value = nn.Parameter(torch.rand(d_in, d_out))
```

Compute queries, keys, and values:

```python
queries = torch.matmul(inputs, W_query)
keys = torch.matmul(inputs, W_key)
values = torch.matmul(inputs, W_value)
```

#### Step 2: Compute Scaled Dot-Product Attention

**Compute Attention Scores**

Similar to the example from before, but this time, instead of using the values of the dimensions of the tokens, we use the key matrix of the token (calculated already using the dimensions):. So, for each query `qi`​ and key `kj​`:

<figure><img src="../.gitbook/assets/image (12).png" alt=""><figcaption></figcaption></figure>

**Scale the Scores**

To prevent the dot products from becoming too large, scale them by the square root of the key dimension `dk`​:

<figure><img src="../.gitbook/assets/image (13).png" alt="" width="295"><figcaption></figcaption></figure>

{% hint style="success" %}
The score is divided by the square root of the dimensions because dot products might become very large and this helps to regulate them.
{% endhint %}

**Apply Softmax to Obtain Attention Weights:** Like in the initial example, normalize all the values so they sum 1.&#x20;

<figure><img src="../.gitbook/assets/image (14).png" alt="" width="295"><figcaption></figcaption></figure>

#### Step 3: Compute Context Vectors

Like in the initial example, just sum all the values matrices multiplying each one by its attention weight:

<figure><img src="../.gitbook/assets/image (15).png" alt="" width="328"><figcaption></figcaption></figure>

### Code Example

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

## Causal Attention: Hiding Future Words

For LLMs we want the model to consider only the tokens that appear before the current position in order to **predict the next token**. **Causal attention**, also known as **masked attention**, achieves this by modifying the attention mechanism to prevent access to future tokens.

### Applying a Causal Attention Mask

To implement causal attention, we apply a mask to the attention scores **before the softmax operation** so the reminding ones will still sum 1. This mask sets the attention scores of future tokens to negative infinity, ensuring that after the softmax, their attention weights are zero.

**Steps**

1. **Compute Attention Scores**: Same as before.
2.  **Apply Mask**: Use an upper triangular matrix filled with negative infinity above the diagonal.

    ```python
    mask = torch.triu(torch.ones(seq_len, seq_len), diagonal=1) * float('-inf')
    masked_scores = attention_scores + mask
    ```
3.  **Apply Softmax**: Compute attention weights using the masked scores.

    ```python
    attention_weights = torch.softmax(masked_scores, dim=-1)
    ```

### Masking Additional Attention Weights with Dropout

To **prevent overfitting**, we can apply **dropout** to the attention weights after the softmax operation. Dropout **randomly zeroes some of the attention weights** during training.

```python
dropout = nn.Dropout(p=0.5)
attention_weights = dropout(attention_weights)
```

### Code Example

Code example from [https://github.com/rasbt/LLMs-from-scratch/blob/main/ch03/01\_main-chapter-code/ch03.ipynb](https://github.com/rasbt/LLMs-from-scratch/blob/main/ch03/01\_main-chapter-code/ch03.ipynb):

```python
import torch
import torch.nn as nn

inputs = torch.tensor(
  [[0.43, 0.15, 0.89], # Your     (x^1)
   [0.55, 0.87, 0.66], # journey  (x^2)
   [0.57, 0.85, 0.64], # starts   (x^3)
   [0.22, 0.58, 0.33], # with     (x^4)
   [0.77, 0.25, 0.10], # one      (x^5)
   [0.05, 0.80, 0.55]] # step     (x^6)
)

batch = torch.stack((inputs, inputs), dim=0)
print(batch.shape)

class CausalAttention(nn.Module):

    def __init__(self, d_in, d_out, context_length,
                 dropout, qkv_bias=False):
        super().__init__()
        self.d_out = d_out
        self.W_query = nn.Linear(d_in, d_out, bias=qkv_bias)
        self.W_key   = nn.Linear(d_in, d_out, bias=qkv_bias)
        self.W_value = nn.Linear(d_in, d_out, bias=qkv_bias)
        self.dropout = nn.Dropout(dropout)
        self.register_buffer('mask', torch.triu(torch.ones(context_length, context_length), diagonal=1)) # New

    def forward(self, x):
        b, num_tokens, d_in = x.shape
        # b is the num of batches
        # num_tokens is the number of tokens per batch
        # d_in is the dimensions er token
        
        keys = self.W_key(x) # This generates the keys of the tokens
        queries = self.W_query(x)
        values = self.W_value(x)

        attn_scores = queries @ keys.transpose(1, 2) # Moves the third dimension to the second one and the second one to the third one to be able to multiply
        attn_scores.masked_fill_(  # New, _ ops are in-place
            self.mask.bool()[:num_tokens, :num_tokens], -torch.inf)  # `:num_tokens` to account for cases where the number of tokens in the batch is smaller than the supported context_size
        attn_weights = torch.softmax(
            attn_scores / keys.shape[-1]**0.5, dim=-1
        )
        attn_weights = self.dropout(attn_weights)

        context_vec = attn_weights @ values
        return context_vec

torch.manual_seed(123)

context_length = batch.shape[1]
d_in = 3
d_out = 2
ca = CausalAttention(d_in, d_out, context_length, 0.0)

context_vecs = ca(batch)

print(context_vecs)
print("context_vecs.shape:", context_vecs.shape)
```

## Extending Single-Head Attention to Multi-Head Attention

**Multi-head attention** in practical terms consist on executing **multiple instances** of the self-attention function each of them with **their own weights** so different final vectors are calculated.

### Code Example

It could be possible to reuse the previous code and just add a wrapper that launches it several time, but this is a more optimised version from [https://github.com/rasbt/LLMs-from-scratch/blob/main/ch03/01\_main-chapter-code/ch03.ipynb](https://github.com/rasbt/LLMs-from-scratch/blob/main/ch03/01\_main-chapter-code/ch03.ipynb) that processes all the heads at the same time (reducing the number of expensive matrices operations). As you can see in the code, the dimensions of each token is diviedd in different dimensions according to the number of heads. This way if token have 8 dimensions and we want to use 3 heads, the dimensions will be divided in 2 arrays of 4 dimensions and each head will use one of them:

```python
class MultiHeadAttention(nn.Module):
    def __init__(self, d_in, d_out, context_length, dropout, num_heads, qkv_bias=False):
        super().__init__()
        assert (d_out % num_heads == 0), \
            "d_out must be divisible by num_heads"

        self.d_out = d_out
        self.num_heads = num_heads
        self.head_dim = d_out // num_heads # Reduce the projection dim to match desired output dim

        self.W_query = nn.Linear(d_in, d_out, bias=qkv_bias)
        self.W_key = nn.Linear(d_in, d_out, bias=qkv_bias)
        self.W_value = nn.Linear(d_in, d_out, bias=qkv_bias)
        self.out_proj = nn.Linear(d_out, d_out)  # Linear layer to combine head outputs
        self.dropout = nn.Dropout(dropout)
        self.register_buffer(
            "mask",
            torch.triu(torch.ones(context_length, context_length),
                       diagonal=1)
        )

    def forward(self, x):
        b, num_tokens, d_in = x.shape
        # b is the num of batches
        # num_tokens is the number of tokens per batch
        # d_in is the dimensions er token

        keys = self.W_key(x) # Shape: (b, num_tokens, d_out)
        queries = self.W_query(x)
        values = self.W_value(x)

        # We implicitly split the matrix by adding a `num_heads` dimension
        # Unroll last dim: (b, num_tokens, d_out) -> (b, num_tokens, num_heads, head_dim)
        keys = keys.view(b, num_tokens, self.num_heads, self.head_dim) 
        values = values.view(b, num_tokens, self.num_heads, self.head_dim)
        queries = queries.view(b, num_tokens, self.num_heads, self.head_dim)

        # Transpose: (b, num_tokens, num_heads, head_dim) -> (b, num_heads, num_tokens, head_dim)
        keys = keys.transpose(1, 2)
        queries = queries.transpose(1, 2)
        values = values.transpose(1, 2)

        # Compute scaled dot-product attention (aka self-attention) with a causal mask
        attn_scores = queries @ keys.transpose(2, 3)  # Dot product for each head

        # Original mask truncated to the number of tokens and converted to boolean
        mask_bool = self.mask.bool()[:num_tokens, :num_tokens]

        # Use the mask to fill attention scores
        attn_scores.masked_fill_(mask_bool, -torch.inf)
        
        attn_weights = torch.softmax(attn_scores / keys.shape[-1]**0.5, dim=-1)
        attn_weights = self.dropout(attn_weights)

        # Shape: (b, num_tokens, num_heads, head_dim)
        context_vec = (attn_weights @ values).transpose(1, 2) 
        
        # Combine heads, where self.d_out = self.num_heads * self.head_dim
        context_vec = context_vec.contiguous().view(b, num_tokens, self.d_out)
        context_vec = self.out_proj(context_vec) # optional projection

        return context_vec

torch.manual_seed(123)

batch_size, context_length, d_in = batch.shape
d_out = 2
mha = MultiHeadAttention(d_in, d_out, context_length, 0.0, num_heads=2)

context_vecs = mha(batch)

print(context_vecs)
print("context_vecs.shape:", context_vecs.shape)

```

For another compact and efficient implementation you could use the [`torch.nn.MultiheadAttention`](https://pytorch.org/docs/stable/generated/torch.nn.MultiheadAttention.html) class in PyTorch.

{% hint style="success" %}
Short answer of ChatGPT about why it's better to divide dimensions of tokens among the heads instead of hacing each head check all the dimensions of all the tokens:

While allowing each head to process all embedding dimensions might seem advantageous because each head would have access to the full information, the standard practice is to **divide the embedding dimensions among the heads**. This approach balances computational efficiency with model performance and encourages each head to learn diverse representations. Therefore, splitting the embedding dimensions is generally preferred over having each head check all dimensions.
{% endhint %}
