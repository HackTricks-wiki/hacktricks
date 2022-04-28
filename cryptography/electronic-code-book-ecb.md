# Electronic Code Book (ECB)

## ECB

(ECB) Electronic Code Book - symmetric encryption scheme which **replaces each block of the clear text** by the **block of ciphertext**. It is the **simplest** encryption scheme. The main idea is to **split** the clear text into **blocks of N bits** (depends on the size of the block of input data, encryption algorithm) and then to encrypt (decrypt) each block of clear text using the only key.

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

Using ECB has multiple security implications:

* **Blocks from encrypted message can be removed**
* **Blocks from encrypted message can be moved around**

## Detection of the vulnerability

Imagine you login into an application several times and you **always get the same cookie**. This is because the cookie of the application is **`<username>|<password>`**.\
Then, you generate to new users, both of them with the **same long password** and **almost** the **same** **username**.\
You find out that the **blocks of 8B** where the **info of both users** is the same are **equals**. Then, you imagine that this might be because **ECB is being used**. 

Like in the following example. Observe how these** 2 decoded cookies** has several times the block **`\x23U\xE45K\xCB\x21\xC8`**

```
\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8\x04\xB6\xE1H\xD1\x1E \xB6\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8+=\xD4F\xF7\x99\xD9\xA9

\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8\x04\xB6\xE1H\xD1\x1E \xB6\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8+=\xD4F\xF7\x99\xD9\xA9
```

This is because the **username and password of those cookies contained several times the letter "a"** (for example). The **blocks** that are **different** are blocks that contained **at least 1 different character** (maybe the delimiter "|" or some necessary difference in the username).

Now, the attacker just need to discover if the format is `<username><delimiter><password>` or `<password><delimiter><username>`. For doing that, he can just **generate several usernames **with s**imilar and long usernames and passwords until he find the format and the length of the delimiter:**

| Username length: | Password length: | Username+Password length: | Cookie's length (after decoding): |
| ---------------- | ---------------- | ------------------------- | --------------------------------- |
| 2                | 2                | 4                         | 8                                 |
| 3                | 3                | 6                         | 8                                 |
| 3                | 4                | 7                         | 8                                 |
| 4                | 4                | 8                         | 16                                |
| 7                | 7                | 14                        | 16                                |

## Exploitation of the vulnerability

### Removing entire blocks

Knowing the format of the cookie (`<username>|<password>`), in order to impersonate the username `admin` create a new user called `aaaaaaaaadmin` and get the cookie and decode it:

```
\x23U\xE45K\xCB\x21\xC8\xE0Vd8oE\x123\aO\x43T\x32\xD5U\xD4
```

We can see the pattern `\x23U\xE45K\xCB\x21\xC8` created previously with the username that contained only `a`.\
Then, you can remove the first block of 8B and you will et a valid cookie for the username `admin`:

```
\xE0Vd8oE\x123\aO\x43T\x32\xD5U\xD4
```

### Moving blocks

In many databases it is the same to search for `WHERE username='admin';` or for `WHERE username='admin    ';` _(Note the extra spaces)_

So, another way to impersonate the user `admin` would be to:

* Generate a username that: `len(<username>) + len(<delimiter) % len(block)`. With a block size of `8B` you can generate username called: `username       `, with the delimiter `|` the chunk `<username><delimiter>` will generate 2 blocks of 8Bs.
* Then, generate a password that will fill an exact number of blocks containing the username we want to impersonate and spaces, like: `admin   ` 

The cookie of this user is going to be composed by 3 blocks: the first 2 is the blocks of the username + delimiter and the third one of the password (which is faking the username): `username       |admin   `

** Then, just replace the first block with the last time and will be impersonating the user `admin`: `admin          |username`**

## References

* [http://cryptowiki.net/index.php?title=Electronic_Code_Book\_(ECB)](http://cryptowiki.net/index.php?title=Electronic_Code_Book_\(ECB\))
