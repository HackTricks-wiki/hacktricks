# Hash Length Extension Attack

## Summary of the attack

Imagine a server which is **signing** some **data** by **appending** a **secret** to some known clear text data and then hashing that data. If you know:

* **The length of the secret** \(this can be also bruteforced from a given length range\)
* **The clear text data**
* **The algorithm \(and it's vulnerable to this attack\)**
* **The padding is known** 
  * Usually a default one is used, so if the other 3 requirements are met, this also is
  * The padding vary depending on the length of the secret+data, that's why the length of the secret is needed

Then, it's possible for an **attacker** to **append** **data** and **generate** a valid **signature** for the **previos data + appended data**.

### How?

Basically the vulnerable algorithms generate the hashes by firstly **hashing a block of data**, and then, **from** the **previously** created **hash** \(state\), they **add the next block of data** and **hash it**.

Then, imagine that the secret is "secret" and the data is "data", the MD5 of "secretdata" is 6036708eba0d11f6ef52ad44e8b74d5b.  
If an attacker wants to append the string "append" he can:

* Generate a MD5 of 64 "A"s
* Change the state of the previously initialized hash to 6036708eba0d11f6ef52ad44e8b74d5b
* Append the string "append"
* Finish the hash and the resulting hash will be a **valid one for "secret" + "data" + "padding" + "append"**

### **Tool**

{% embed url="https://github.com/iagox86/hash\_extender" %}

## References

You can find this attack good explained in [https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)

