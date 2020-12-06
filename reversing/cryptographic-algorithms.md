# Cryptographic Algorithms

## Identifying Algorithms

If you ends in a code **using shift rights and lefts, xors and several arithmetic operations** it's highly possible that it's the implementation of a **cryptographic algorithm**. Here it's going to be showed some ways to **identify the algorithm that it's used without needing to reverse each step**.

### API functions

#### CryptDeriveKey



### Code constants

Sometimes it's really easy to identify an algorithm thanks to the fact that it needs to use a special and unique value.

![](../.gitbook/assets/image%20%28121%29.png)

If you search for the first constant in Google this is what you get:

![](../.gitbook/assets/image%20%28144%29.png)

Therefore, you can assume that the decompiled function is a **sha256 calculator.**  
You can search any of the other constants and you will obtain \(probably\) the same result.

### data info

If the code doesn't have any significant constant it may be **loading information from the .data section**.  
You can access that data, **group the first dword** and search for it in google as we have done in the section before:

![](../.gitbook/assets/image%20%28158%29.png)

In this case, if you look for **0xA56363C6** you can find that it's related to the **tables of the AES algorithm**.

## RC4

It's composed of 3 main parts:

* **Initialization stage**: Creates a **table of values from 0x00 to 0xFF** \(256bytes in total, 0x100\).
* **Scrambling stage**: Will **loop through the table** crated before \(loop of 0x100 iterations, again\) creating modifying each value with **semi-random** bytes. In order to create this semi-random bytes, the RC4 **key is used**. RC4 keys can be between 1 and 256 bytes in length, however it is usually recommended that it is above 5 bytes. Commonly, RC4 keys are 16 bytes in length.
* **XOR stage**: Finally, the plain-text or cyphertext is **XORed with the values created before**. The function to encrypt and decrypt is the same. For this, a **loop through the created 256 bytes** will be performed as many times as necessary. This is usually recognized in a decompiled code with a **%256 \(mod 256\)**.

{% hint style="info" %}
**In order to identify a RC4 in a disassembly/decompiled code you can check for 2 loops of size 0x100 \(with the use of a key\) and then a XOR of the input data with the 256 values created before in the 2 loops probably using a %256 \(mod 256\)**
{% endhint %}

**Example Initialization stage:**  
\(Note the number 256 used as counter and how a 0 is written in each place of the 256 chars\)

![](../.gitbook/assets/image%20%2890%29.png)

**Example of the Scrambling Stage:**

![](../.gitbook/assets/image%20%28107%29.png)

**Example of XOR Stage:**

![](../.gitbook/assets/image%20%2873%29.png)

