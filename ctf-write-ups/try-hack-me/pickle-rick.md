# Pickle Rick

![](../../.gitbook/assets/picklerick.gif)

This machine was categorised as easy and it was pretty easy.

## Enumeration

I started **enumerating the machine using my tool** [**Legion**](https://github.com/carlospolop/legion):

![](../../.gitbook/assets/image%20%2879%29.png)

In as you can see 2 ports are open: 80 \(**HTTP**\) and 22 \(**SSH**\)

So, I launched legion to enumerate the HTTP service:

![](../../.gitbook/assets/image%20%28140%29.png)

Note that in the image you can see that `robots.txt` contains the string `Wubbalubbadubdub`

After some seconds I reviewed what `disearch` has already discovered :

![](../../.gitbook/assets/image%20%28132%29.png)

![](../../.gitbook/assets/image%20%28105%29.png)

And as you may see in the last image a **login** page was discovered.

Checking the source code of the root page, a username is discovered: `R1ckRul3s`

![](../../.gitbook/assets/image%20%28324%29.png)

Therefore, you can login on the login page using the credentials `R1ckRul3s:Wubbalubbadubdub`

## User

Using those credentials you will access a portal where you can execute commands:

![](../../.gitbook/assets/image%20%28196%29.png)

Some commands like cat aren't allowed but you can read the first ingredient \(flag\) using for example grep:

![](../../.gitbook/assets/image%20%28218%29.png)

Then I used:

![](../../.gitbook/assets/image%20%28171%29.png)

To obtain a reverse shell:

![](../../.gitbook/assets/image%20%2851%29.png)

The **second ingredient** can be found in `/home/rick`

![](../../.gitbook/assets/image%20%2857%29.png)

## Root

The user **www-data can execute anything as sudo**:

![](../../.gitbook/assets/image%20%2884%29.png)

