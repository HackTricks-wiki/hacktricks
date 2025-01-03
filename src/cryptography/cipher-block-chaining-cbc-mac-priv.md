{{#include ../banners/hacktricks-training.md}}

# CBC

If the **cookie** is **only** the **username** (or the first part of the cookie is the username) and you want to impersonate the username "**admin**". Then, you can create the username **"bdmin"** and **bruteforce** the **first byte** of the cookie.

# CBC-MAC

**Cipher block chaining message authentication code** (**CBC-MAC**) is a method used in cryptography. It works by taking a message and encrypting it block by block, where each block's encryption is linked to the one before it. This process creates a **chain of blocks**, making sure that changing even a single bit of the original message will lead to an unpredictable change in the last block of encrypted data. To make or reverse such a change, the encryption key is required, ensuring security.

To calculate the CBC-MAC of message m, one encrypts m in CBC mode with zero initialization vector and keeps the last block. The following figure sketches the computation of the CBC-MAC of a message comprising blocks![https://wikimedia.org/api/rest_v1/media/math/render/svg/bbafe7330a5e40a04f01cc776c9d94fe914b17f5](https://wikimedia.org/api/rest_v1/media/math/render/svg/bbafe7330a5e40a04f01cc776c9d94fe914b17f5) using a secret key k and a block cipher E:

![https://upload.wikimedia.org/wikipedia/commons/thumb/b/bf/CBC-MAC_structure_(en).svg/570px-CBC-MAC_structure_(en).svg.png](<https://upload.wikimedia.org/wikipedia/commons/thumb/b/bf/CBC-MAC_structure_(en).svg/570px-CBC-MAC_structure_(en).svg.png>)

# Vulnerability

With CBC-MAC usually the **IV used is 0**.\
This is a problem because 2 known messages (`m1` and `m2`) independently will generate 2 signatures (`s1` and `s2`). So:

- `E(m1 XOR 0) = s1`
- `E(m2 XOR 0) = s2`

Then a message composed by m1 and m2 concatenated (m3) will generate 2 signatures (s31 and s32):

- `E(m1 XOR 0) = s31 = s1`
- `E(m2 XOR s1) = s32`

**Which is possible to calculate without knowing the key of the encryption.**

Imagine you are encrypting the name **Administrator** in **8bytes** blocks:

- `Administ`
- `rator\00\00\00`

You can create a username called **Administ** (m1) and retrieve the signature (s1).\
Then, you can create a username called the result of `rator\00\00\00 XOR s1`. This will generate `E(m2 XOR s1 XOR 0)` which is s32.\
now, you can use s32 as the signature of the full name **Administrator**.

### Summary

1. Get the signature of username **Administ** (m1) which is s1
2. Get the signature of username **rator\x00\x00\x00 XOR s1 XOR 0** is s32**.**
3. Set the cookie to s32 and it will be a valid cookie for the user **Administrator**.

# Attack Controlling IV

If you can control the used IV the attack could be very easy.\
If the cookies is just the username encrypted, to impersonate the user "**administrator**" you can create the user "**Administrator**" and you will get it's cookie.\
Now, if you can control the IV, you can change the first Byte of the IV so **IV\[0] XOR "A" == IV'\[0] XOR "a"** and regenerate the cookie for the user **Administrator.** This cookie will be valid to **impersonate** the user **administrator** with the initial **IV**.

## References

More information in [https://en.wikipedia.org/wiki/CBC-MAC](https://en.wikipedia.org/wiki/CBC-MAC)

{{#include ../banners/hacktricks-training.md}}



