# Google CTF 2018 - Shall We Play a Game?

Download the APK here:

I am going to upload the APK to [https://appetize.io/](https://appetize.io/) \(free account\) to see how the apk is behaving:

![](../../.gitbook/assets/image%20%28322%29.png)

Looks like you need to win 1000000 times to get the flag.

Following the steps from [pentesting Android](./) you can decompile the application to get the smali code and read the Java code using jadx.

Reading the java code:

![](../../.gitbook/assets/image%20%28262%29.png)

It looks like the function that is going print the flag is **m\(\).** 

## **Smali changes**

### **Call m\(\) the first time**

Lets make the application call m\(\) if the variable _this.o != 1000000_ to do so, just cange the condition:

```text
 if-ne v0, v9, :cond_2 
```

to:

```text
 if-eq v0, v9, :cond_2 
```

![Before](../../.gitbook/assets/image%20%28204%29.png)

![After](../../.gitbook/assets/image%20%28329%29.png)

Follow the steps of [pentest Android](./) to recompile and sign the APK. Then, upload it to [https://appetize.io/](https://appetize.io/) and lets see what happens:

![](../../.gitbook/assets/image%20%28284%29.png)

Looks like the flag is written without being completely decrypted. Probably the m\(\) function should be called 1000000 times.

**Other way** to do this is to not change the instrucction but change the compared instructions:

![](../../.gitbook/assets/image%20%28167%29.png)

**Another way** is instead of comparing with 1000000, set the value to 1 so this.o is compared with 1:

![](../../.gitbook/assets/image%20%2811%29.png)

A forth way is to add an instruction to move to value of v9\(1000000\) to v0 _\(this.o\)_:

![](../../.gitbook/assets/image%20%28115%29.png)



![](../../.gitbook/assets/image%20%28238%29.png)

## Solution

Make the application run the loop 100000 times when you win the first time. To do so, you only need to create the **:goto\_6** loop and make the application **junp there if** _**this.o**_ **does not value 100000**:

![](../../.gitbook/assets/image%20%28102%29.png)

You need to do this inside a physical device as \(I don't know why\) this doesn't work in an emulated device.

