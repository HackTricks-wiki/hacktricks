# Cryptographic/Compression Algorithms

## Cryptographic/Compression Algorithms

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Identifying Algorithms

If you ends in a code **using shift rights and lefts, xors and several arithmetic operations** it's highly possible that it's the implementation of a **cryptographic algorithm**. Here it's going to be showed some ways to **identify the algorithm that it's used without needing to reverse each step**.

### API functions

**CryptDeriveKey**

If this function is used, you can find which **algorithm is being used** checking the value of the second parameter:

![](<../../.gitbook/assets/image (375) (1) (1) (1) (1).png>)

Check here the table of possible algorithms and their assigned values: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

Compresses and decompresses a given buffer of data.

**CryptAcquireContext**

The **CryptAcquireContext** function is used to acquire a handle to a particular key container within a particular cryptographic service provider (CSP). **This returned handle is used in calls to CryptoAPI** functions that use the selected CSP.

**CryptCreateHash**

Initiates the hashing of a stream of data. If this function is used, you can find which **algorithm is being used** checking the value of the second parameter:

![](<../../.gitbook/assets/image (376).png>)

\
Check here the table of possible algorithms and their assigned values: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### Code constants

Sometimes it's really easy to identify an algorithm thanks to the fact that it needs to use a special and unique value.

![](<../../.gitbook/assets/image (370).png>)

If you search for the first constant in Google this is what you get:

![](<../../.gitbook/assets/image (371).png>)

Therefore, you can assume that the decompiled function is a **sha256 calculator.**\
You can search any of the other constants and you will obtain (probably) the same result.

### data info

If the code doesn't have any significant constant it may be **loading information from the .data section**.\
You can access that data, **group the first dword** and search for it in google as we have done in the section before:

![](<../../.gitbook/assets/image (372).png>)

In this case, if you look for **0xA56363C6** you can find that it's related to the **tables of the AES algorithm**.

## RC4 **(Symmetric Crypt)**

### Characteristics

It's composed of 3 main parts:

* **Initialization stage/**: Creates a **table of values from 0x00 to 0xFF** (256bytes in total, 0x100). This table is commonly call **Substitution Box** (or SBox).
* **Scrambling stage**: Will **loop through the table** crated before (loop of 0x100 iterations, again) creating modifying each value with **semi-random** bytes. In order to create this semi-random bytes, the RC4 **key is used**. RC4 **keys** can be **between 1 and 256 bytes in length**, however it is usually recommended that it is above 5 bytes. Commonly, RC4 keys are 16 bytes in length.
* **XOR stage**: Finally, the plain-text or cyphertext is **XORed with the values created before**. The function to encrypt and decrypt is the same. For this, a **loop through the created 256 bytes** will be performed as many times as necessary. This is usually recognized in a decompiled code with a **%256 (mod 256)**.

{% hint style="info" %}
**In order to identify a RC4 in a disassembly/decompiled code you can check for 2 loops of size 0x100 (with the use of a key) and then a XOR of the input data with the 256 values created before in the 2 loops probably using a %256 (mod 256)**
{% endhint %}

### **Initialization stage/Substitution Box:** (Note the number 256 used as counter and how a 0 is written in each place of the 256 chars)

![](<../../.gitbook/assets/image (377).png>)

### **Scrambling Stage:**

![](<../../.gitbook/assets/image (378).png>)

### **XOR Stage:**

![](<../../.gitbook/assets/image (379).png>)

## **AES (Symmetric Crypt)**

### **Characteristics**

* Use of **substitution boxes and lookup tables**
  * It's possible to **distinguish AES thanks to the use of specific lookup table values** (constants). _Note that the **constant** can be **stored** in the binary **or created**_ _**dynamically**._
* The **encryption key** must be **divisible** by **16** (usually 32B) and usually an **IV** of 16B is used.

### SBox constants

![](<../../.gitbook/assets/image (380).png>)

## Serpent **(Symmetric Crypt)**

### Characteristics

* It's rare to find some malware using it but there are examples (Ursnif)
* Simple to determine if an algorithm is Serpent or not based on it's length (extremely long function)

### Identifying

In the following image notice how the constant **0x9E3779B9** is used (note that this constant is also used by other crypto algorithms like **TEA** -Tiny Encryption Algorithm).\
Also note the **size of the loop** (**132**) and the **number of XOR operations** in the **disassembly** instructions and in the **code** example:

![](<../../.gitbook/assets/image (381).png>)

As it was mentioned before, this code can be visualized inside any decompiler as a **very long function** as there **aren't jumps** inside of it. The decompiled code can look like the following:

![](<../../.gitbook/assets/image (382).png>)

Therefore, it's possible to identify this algorithm checking the **magic number** and the **initial XORs**, seeing a **very long function** and **comparing** some **instructions** of the long function **with an implementation** (like the shift left by 7 and the rotate left by 22).

## RSA **(Asymmetric Crypt)**

### Characteristics

* More complex than symmetric algorithms
* There are no constants! (custom implementation are difficult to determine)
* KANAL (a crypto analyzer) fails to show hints on RSA ad it relies on constants.

### Identifying by comparisons

![](<../../.gitbook/assets/image (383).png>)

* In line 11 (left) there is a `+7) >> 3` which is the same as in line 35 (right): `+7) / 8`
* Line 12 (left) is checking if `modulus_len < 0x040` and in line 36 (right) it's checking if `inputLen+11 > modulusLen`

## MD5 & SHA (hash)

### Characteristics

* 3 functions: Init, Update, Final
* Similar initialize functions

### Identify

**Init**

You can identify both of them checking the constants. Note that the sha\_init has 1 constant that MD5 doesn't have:

![](<../../.gitbook/assets/image (385).png>)

**MD5 Transform**

Note the use of more constants

![](<../../.gitbook/assets/image (253) (1) (1) (1).png>)

## CRC (hash)

* Smaller and more efficient as it's function is to find accidental changes in data
* Uses lookup tables (so you can identify constants)

### Identify

Check **lookup table constants**:

![](<../../.gitbook/assets/image (387).png>)

A CRC hash algorithm looks like:

![](<../../.gitbook/assets/image (386).png>)

## APLib (Compression)

### Characteristics

* Not recognizable constants
* You can try to write the algorithm in python and search for similar things online

### Identify

The graph is quiet large:

![](<../../.gitbook/assets/image (207) (2) (1).png>)

Check **3 comparisons to recognise it**:

![](<../../.gitbook/assets/image (384).png>)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
