# Cipher Block Chaining CBC-MAC

## CBC

If the **cookie **is **only **the **username **(or the first part of the cookie is the username) and you want to impersonate the username "**admin**". Then, you can create the username **"bdmin"** and **bruteforce **the **first byte **of the cookie.

## CBC-MAC

In cryptography, a **cipher block chaining message authentication code** (**CBC-MAC**) is a technique for constructing a message authentication code from a block cipher. The message is encrypted with some block cipher algorithm in CBC mode to create a **chain of blocks such that each block depends on the proper encryption of the previous block**. This interdependence ensures that a **change **to **any **of the plaintext **bits **will cause the **final encrypted block **to **change **in a way that cannot be predicted or counteracted without knowing the key to the block cipher.

To calculate the CBC-MAC of message m, one encrypts m in CBC mode with zero initialization vector and keeps the last block. The following figure sketches the computation of the CBC-MAC of a message comprising blocks![m\_{1}\\|m\_{2}\\|\cdots \\|m\_{x}](https://wikimedia.org/api/rest_v1/media/math/render/svg/bbafe7330a5e40a04f01cc776c9d94fe914b17f5) using a secret key k and a block cipher E:

![CBC-MAC structure (en).svg](https://upload.wikimedia.org/wikipedia/commons/thumb/b/bf/CBC-MAC_structure_\(en\).svg/570px-CBC-MAC_structure_\(en\).svg.png)

## Vulnerability

With CBC-MAC usually the **IV used is 0**.\
This is a problem because 2 known messages (`m1` and `m2`) independently will generate 2 signatures (`s1` and `s2`). So:

* `E(m1 XOR 0) = s1`
* `E(m2 XOR 0) = s2`

Then a message composed by m1 and m2 concatenated (m3) will generate 2 signatures (s31 and s32):

* `E(m1 XOR 0) = s31 = s1`
* `E(m2 XOR s1) = s32`

**Which is possible to calculate without knowing the key of the encryption.**

Imagine you are encrypting the name **Administrator **in **8bytes **blocks:

* `Administ`
* `rator\00\00\00`

You can create a username called **Administ **(m1) and retrieve the key (s1).\
Then, you can create a username called the result of `rator\00\00\00 XOR s1`. This will generate `E(m2 XOR s1 XOR 0)` which is s32.\
now, knowing s1 and s32 you can put them together an generate the encryption of the full name **Administrator**.

#### Summary

1. Get the signature of username **Administ **(m1) which is s1
2. Get the signature of username **rator\x00\x00\x00 XOR s1 XOR 0 **is s32**.**
3. Set the cookie to s1 followed by s32 and it will be a valid cookie for the user **Administrator**.

## Attack Controlling IV

If you can control the used IV the attack could be very easy.\
If the cookies is just the username encrypted, to impersonate the user "**administrator**" you can create the user "**Administrator**" and you will get it's cookie.\
Now, if you can control the IV, you can change the first Byte of the IV so **IV\[0] XOR "A" == IV'\[0] XOR "a"** and regenerate the cookie for the user **Administrator. **This cookie will be valid to **impersonate **the user **administrator **with the initial **IV**.

## References

More information in [https://en.wikipedia.org/wiki/CBC-MAC](https://en.wikipedia.org/wiki/CBC-MAC)
