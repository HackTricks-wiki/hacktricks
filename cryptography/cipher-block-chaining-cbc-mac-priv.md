---
description: 'https://pentesterlab.com/'
---

# Cipher Block Chaining CBC-MAC

**Post from** [**https://pentesterlab.com/**](https://pentesterlab.com/)\*\*\*\*

## CBC

The easiest attack to test is that if the cookie just the username encrypted.

If the cookie is only the username \(or the first part of the cookie is the username\) and you want to impersonate the username "**admin**". Then, you can create the username **"bdmin"** and bruteforce the first byte of the cookie.

## CBC-MAC

CBC-MAC is a method to ensure integrity of a message by encrypting it using CBC mode and keeping the last encrypted block as "signature". This ensures that a malicious user can not modify any part of the data without having to change the signature. The key used for the "encryption" ensures that the signature can't be guessed.

However, when using CBC-MAC, the developer needs to be very careful if the message are not of fixed length. In this example, we will use the fact that there is no protection in place to get the application to sign two messages and build another message by concatenating the two messages.

## Theory

With CBC-MAC, we can generate two signatures `t` and `t'` for the messages `m` and `m'`. By using `m` and `m'` we can forge another message `m''` that will have the same signature as `m'` \(`t'`\). One thing to keep in mind is that the recommended way to use CBC-MAC is to use a NULL IV.

To keep things simple, we are going to work on a single block for each message.

We can see below how signing both messages works \(NB: both signatures are completely independent from each other\):

![](https://pentesterlab.com/cbc-mac/cbc-mac-1.png)

If we try to concatenate those messages, the signature is no longer valid \(since `t` is now the IV for the second block where it was only NULL before\):

![](https://pentesterlab.com/cbc-mac/cbc-mac-2.png)

However, if we XOR `m'` and `t`, the signature is now `t'`:

![](https://pentesterlab.com/cbc-mac/cbc-mac-3.png)

## Implementation

Based on the size of the signature, we can guess that the block size is likely to be 8. With this information, we will split `administrator`:

* `administ`
* `rator\00\00\00`

We can trivially generate the signature for the first block, by just logging in and retrieving the signature `t`.

For the second block, we want the `m'` XOR `t` to be equal to `rator\00\00\00`. So to generate the second username we will need to XOR `rator\00\00\00` with `t` \(since the application will sign it with a NULL IV instead of `t`\). Once we have this value, we can get the signature `t'`.

Finally, we just need to concatenate `m` and `m'` to get `administrator` and use `t'` as signature.

#### Resume

1. Get the signature of username **administ** =  **t**
2. Get the signature of username **rator\x00\x00\x00 XOR t** = **t'**
3. Set in the cookie the value **administrator+t'** \(**t'** will be a valid signature of **\(rator\x00\x00\x00 XOR t\) XOR t** = **rator\x00\x00\x00**

### CBC-MAC simple attack \(controlling IV\)

If you can control the used IV the attack could be very easy.

To impersonate the user "**administrator**" you can create the user "**Administrator**" and you will have the cookie with the **username+signature** and the cookie with the **IV**.

To generate the cookies of the username "**administrator**" change the first cookie and set the username from "**Administrator**" to "**administrator**". Change the first byte of the cookie of the **IV** so **IV\[0\] XOR "A" == IV'\[0\] XOR "a"**. Using these cookies you can login as administrator.

