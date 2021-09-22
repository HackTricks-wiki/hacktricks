---
description: 'https://pentesterlab.com/'
---

# Electronic Code Book \(ECB\)

## ECB

\(ECB\) Electronic Code Book - symmetric encryption scheme which **replaces each block of the clear text** by the **block of ciphertext**. It is the **simplest** encryption scheme. The main idea is to **split** the clear text into **blocks of N bits** \(depends on the size of the block of input data, encryption algorithm\) and then to encrypt \(decrypt\) each block of clear text using the only key.

![](https://assets.pentesterlab.com/ecb/ECB_encryption.png)

Using ECB has multiple security implications:

* **Blocks from encrypted message can be removed**
* **Blocks from encrypted message can be moved around**

## Detection of the vulnerability

Imagine you login into an application several times and you **always get the same cookie**. This is because the cookie of the application is **`<username>|<password>`**.  
Then, you generate to new users, both of them with the **same long password** and **almost** the **same** **username**.  
You find out that the **blocks of 8B** where the **info of both users** is the same are **equals**. Then, you imagine that this might be because **ECB is being used**. 

Like in the following example. Observe how these **2 decoded cookies** has several times the block **`\x23U\xE45K\xCB\x21\xC8`**

```text
\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8\x04\xB6\xE1H\xD1\x1E \xB6\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8+=\xD4F\xF7\x99\xD9\xA9

\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8\x04\xB6\xE1H\xD1\x1E \xB6\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8+=\xD4F\xF7\x99\xD9\xA9
```

This is because the **username and password of those cookies contained several times the letter "a"** \(for example\). The **blocks** that are **different** are blocks that contained **at least 1 different character** \(maybe the delimiter "\|" or some necessary difference in the username\).

Now, the attacker just need to discover if the format is `<username><delimiter><password>` or `<password><delimiter><username>`. For doing that, he can just **generate several usernames** with s**imilar and long usernames and passwords until he find the format and the length of the delimiter:**

| Username length: | Password length: | Username+Password length: | Cookie's length \(after decoding\): |
| :--- | :--- | :--- | :--- |
| 2 | 3 | 5 | 8 |
| 3 | 3 | 6 | 8 |
| 3 | 4 | 7 | 8 |
| 4 | 4 | 8 | 16 |
| 4 | 5 | 9 | 16 |

## Exploitation of the vulnerability

### Removing entire blocks

Knowing the format of the cookie \(`<username>|<password>`\), in order to impersonate the username `admin` create a new user called `aaaaaaaaadmin` and get the cookie and decode it:

```text
\x23U\xE45K\xCB\x21\xC8\xE0Vd8oE\x123\aO\x43T\x32\xD5U\xD4
```

We can see the pattern `\x23U\xE45K\xCB\x21\xC8` created previously with the username that contained only `a`.  
Then, you can remove the first block of 8B and you will et a valid cookie for the username `admin`:

```text
\xE0Vd8oE\x123\aO\x43T\x32\xD5U\xD4
```

### Moving blocks around

A more complicated way to bypass this is to swap data around. We can make the assumption that the application will use an SQL query to retrieve information from the user based on his `username`. For some databases, when using the type of data `VARCHAR` \(as opposed to `BINARY` for example\), the following will give the same result:

```text
SELECT * FROM users WHERE username='admin';
```

```text
SELECT * FROM users WHERE username='admin        ';
```

The spaces after the value `admin` are ignored during the string comparison. We will use this to play with the encrypted blocks.

Our goal is to end up with the following encrypted data:

```text
ECB(admin   [separator]password)
```

We know that our separator is only composed of one byte. We can use this information to create the perfect `username` and `password`to be able to swap the blocks and get the correct forged value.

We need to find a username and a password for which:

* the password starts with `admin` to be used as the new username.
* the encrypted password should be located at the start of a new block.
* the `username+delimiter` length should be divisible by the block size \(from previous conditions\)

By playing around, we can see that the following values work:

* a `username` composed of `password` \(8 bytes\) followed by 7 spaces \(1 byte will be used by the delimiter\).
* a `password` composed of `admin` followed by 3 spaces \(`8 - length("admin")`\).

When creating this user, use a proxy to intercept the request and make sure your browser didn't remove the space characters.

If you create correctly this user, the encrypted information will look like:![License](https://assets.pentesterlab.com/ecb/swap-b.png)

Using some Ruby \(or even with Burp decoder\), you can swap the first 8 bytes with the last 8 bytes to get the following encrypted stream:![License](https://assets.pentesterlab.com/ecb/swap-a.png)

Once you modify your cookie, and you reload the page, you should be logged in as `admin`:

![License](https://assets.pentesterlab.com/ecb/admin.png)

## References

* [http://cryptowiki.net/index.php?title=Electronic\_Code\_Book\_\(ECB\)](http://cryptowiki.net/index.php?title=Electronic_Code_Book_%28ECB%29)

