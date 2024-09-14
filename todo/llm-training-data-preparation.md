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
