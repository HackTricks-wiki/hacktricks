# Padding Oracle

## CBC - Cipher Block Chaining

In CBC mode the **previous encrypted block is used as IV** to XOR with the next block:

![CBC encryption](https://defuse.ca/images/cbc_encryption.png)

To decrypt CBC the **opposite** **operations** are done:

![CBC decryption](https://defuse.ca/images/cbc_decryption.png)

Notice how it's needed to use an **encryption** **key** and an **IV**.

## Message Padding

As the encryption is performed in **fixed** **size** **blocks**, **padding** is usually needed in the **last** **block** to complete its length.\
Usually **PKCS7** is used, which generates a padding **repeating** the **number** of **bytes** **needed** to **complete** the block. For example, if the last block is missing 3 bytes, the padding will be `\x03\x03\x03`.

Let's look at more examples with a **2 blocks of length 8bytes**:

| byte #0 | byte #1 | byte #2 | byte #3 | byte #4 | byte #5 | byte #6 | byte #7 | byte #0  | byte #1  | byte #2  | byte #3  | byte #4  | byte #5  | byte #6  | byte #7  |
| ------- | ------- | ------- | ------- | ------- | ------- | ------- | ------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | 6        | **0x02** | **0x02** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | **0x03** | **0x03** | **0x03** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | **0x05** | **0x05** | **0x05** | **0x05** | **0x05** |
| P       | A       | S       | S       | W       | O       | R       | D       | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** |

Note how in the last example the **last block was full so another one was generated only with padding**.

## Padding Oracle

When an application decrypts encrypted data, it will first decrypt the data; then it will remove the padding. During the cleanup of the padding, **if **an **invalid** **padding **triggers a detectable **behaviour**, you have a **padding oracle vulnerability**. The detectable behaviour can be an **error**, a **lack **of **results**, or a **slower response**.

If you detect this behaviour, you can** decrypt the encrypted data** and even** encrypt any cleartext**.

### How to exploit

You could use [https://github.com/AonCyberLabs/PadBuster](https://github.com/AonCyberLabs/PadBuster) to exploit this kind of vulnerability or just do 

```
sudo apt-get install padbuster
```

In order to test if the cookie of a site is vulnerable you could try: 

```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```

**Encoding 0** means that **base64 **is used (but others are available, check the help menu).

You could also **abuse **this **vulnerability **to **encrypt new data**. For example, imagine that the content of the cookie is "_user=MyUsername_", then you may change it to "_**user=administrator**_" and escalate privileges inside the application. You could also do it using `paduster`specifying the** -plaintext** parameter:

```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA==" -plaintext "user=administrator"
```

If the site is vulnerable `padbuster`will automatically try to find when the padding error occurs, but you can also indicating the error message it using the **-error** parameter.

```bash
perl ./padBuster.pl http://10.10.10.10/index.php "" 8 -encoding 0 -cookies "hcon=RVJDQrwUdTRWJUVUeBKkEA==" -error "Invalid padding"
```

### The theory

In **summary**, you can start decrypting the encrypted data by **guessing **the correct **values **that can be used to **create **all the **different paddings**. Then, the padding oracle attack will start **decrypting **bytes **from **the **end **to the start by **guessing **which will be the correct **value **that **creates a padding of 1, 2, 3, etc**.



![CBC decryption](https://assets.pentesterlab.com/padding_oracle/CBC_decryption.png)

Imagine you have some encrypted text that occupies **2 blocks** formed by the bytes from **E0 to E15**.\
In order to **decrypt** the **last** **block** (**E8** to **E15**), the whole block passes through the "block cipher decryption" generating the** intermediary bytes I0 to I15**.\
Finally, each intermediary byte is **XORed** with the previous encrypted bytes (E0 to E7). So:

* `C15 = D(E15) ^ E7 = I15 ^ E7`
* `C14 = I14 ^ E6`
* `C13 = I13 ^ E5 `
* `C12 = I12 ^ E4 `
* ...

Now, It's possible to **modify `E7` until `C15` is `0x01`**, which will also be a correct padding. So, in this case: `\x01 = I15 ^ E'7` 

So, finding E'7, it's **possible to calculate I15**: `I15 = 0x01 ^ E'7`

Which allow us to **calculate C15**: `C15 = E7 ^ I15 = E7 ^ \x01 ^ E'7`

Knowing **C15**, now it's possible to **calculate C14**, but this time brute-forcing the padding `\x02\x02`.

This BF is as complex as the previous one as it's possible to calculate the the `E''15` whose value is 0x02: `E''7 = \x02 ^ I15` so it's just needed to find the **`E'14`** that generates a **`C14` equals to `0x02`**.\
Then, do the same steps to decrypt C14: **`C14 = E6 ^ I14 = E6 ^ \x02 ^ E''6`**

**Follow this chain until you decrypt the whole encrypted text.**

### Detection of the vulnerability

Register and account and log in with this account .\
If you **log in many times** and always get the **same cookie**, there is probably **something** **wrong** in the application. The **cookie sent back should be unique** each time you log in. If the cookie is **always** the **same**, it will probably always be valid and there **won't be anyway to invalidate i**t.

Now, if you try to **modify** the **cookie**, you can see that you get an **error** from the application.\
But if you BF the padding (using padbuster for example) you manage to get another cookie valid for a different user. This scenario is highly probably vulnerable to padbuster.

## References

* [https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation)
