# Cryptographic Algorithms

## RC4

It's composed of 3 main parts:

* **Initialization stage**: Creates a **table of values from 0x00 to 0xFF** \(256bytes in total, 0x100\).
* **Scrambling stage**: Will **loop through the table** crated before \(loop of 0x100 iterations, again\) creating modifying each value with **semi-random** bytes. In order to create this semi-random bytes, the RC4 **key is used**. RC4 keys can be between 1 and 256 bytes in length, however it is usually recommended that it is above 5 bytes. Commonly, RC4 keys are 16 bytes in length.
* **XOR stage**: Finally, the plain-text or cyphertext is **XORed with the values created before**. The function to encrypt and decrypt is the same. For this, a **loop through the created 256 bytes** will be performed as many times as necessary. This is usually recognized in a decompiled code with a **%256 \(mod 256\)**.

{% hint style="info" %}
**In order to identify a RC4 in a disassembly/decompiled code you can check for 2 loops of size 0x100 \(with the use of a key\) and then a XOR of the input data with the 256 values created before in the 2 loops probably using a %256 \(mod 256\)**
{% endhint %}

\*\*\*\*

