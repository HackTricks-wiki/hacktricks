# Remote stealth pass brute force

## Outer Perimeter: Remote stealth pass brute force

**The versions 11.1.0.6, 11.1.0.7, 11.2.0.1, 11.2.0.2, and 11.2.0.3 are vulnerable** to this technique. In order to understand the idea behind this vulnerability, you need to consider how the authentication protocol works with the database. I will show it for version 11. The interaction with the server proceeds as follows:

1. The client connects to the server and sends the user name.
2. The server generates a session identifier \(‘AUTH\_SESSKEY’\) and encrypts it by using AES-192. As its key, the system uses SHA-1 hash generated from user password and salt \(‘AUTH\_VFR\_DATA’\).
3. The server sends an encrypted session ID and salt to the client.
4. The client generates the key by hashing its password and received salt. The client uses this key to decrypt the session data received from the server.
5. Based on decrypted server session ID, the client generates a new public key for future use.

Now, here’s the most interesting part: The session ID ‘AUTH\_SESSKEY’ sent by the server to the client has a length of 48 bytes. Of these, 40 bytes are random, and the last 8 are the duplicates of ‘0x08’. The initialization vector is 0x00 \(Null\).  
Knowing that the last 8 bytes of the public identifier always consist of ‘0x08’, we can bruteforce this password and, moreover, do it in offline mode, which means a tremendous speed, especially if you use GPU. To mount an attack, you need to know SID, valid login \(for example, ‘SYS’ account is very interesting\) and, of course, have the ability to connect to the database. In this case, there will be no records, such as ‘Invalid Login Attempt’, created in the Oracle audit logs!

Summing it all up:

1. Use Wireshark to **intercept** the **initial traffic** during **authorization**. This will be helped by ‘tns’ filter.
2. Extract **HEX values for AUTH\_SESSKEY, AUTH\_VFR\_DATA**.
3. Insert them into ****[**PoC script**](https://www.exploit-db.com/exploits/22069), which will perform a dictionary \(brute force\) attack.

### Using nmap and john

```text
root@kali:~# nmap -p1521 --script oracle-brute-stealth --script-args oracle-brute-stealth.sid=DB11g -n 10.11.21.30

Starting Nmap 6.49BETA4 (https://nmap.org) at 2016-03-02 14:58 EST
Nmap scan report for 10.11.21.30
PORT     STATE SERVICE
1521/tcp open  oracle
| oracle-brute-stealth:
|   Accounts
|     SYS:$o5logon$1245C95384E15E7F0C893FCD1893D8E19078170867E892CE86DF90880E09FAD3B4832CBCFDAC1
|     A821D2EA8E3D2209DB6*4202433F49DE9AE72AE2 - 
|     Hashed valid or invalid credentials
|   Statistics
|_    Performed 241 guesses in 12 seconds, average tps: 20

john hashes.txt
```

