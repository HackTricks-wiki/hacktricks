# 10000 - Pentesting Network Data Management Protocol \(ndmp\)

## **Protocol Information**

**NDMP**, or **Network Data Management Protocol**, is a protocol meant to transport data between network attached storage \([NAS](https://en.wikipedia.org/wiki/Network-attached_storage)\) devices and [backup](https://en.wikipedia.org/wiki/Backup) devices. This removes the need for transporting the data through the backup server itself, thus enhancing speed and removing load from the backup server.  
From [Wikipedia](https://en.wikipedia.org/wiki/NDMP).

**Default port:** 10000

```text
PORT      STATE SERVICE REASON  VERSION
10000/tcp open  ndmp    syn-ack Symantec/Veritas Backup Exec ndmp
```

## **Enumeration**

```bash
nmap -n -sV --script "ndmp-fs-info or ndmp-version" -p 10000 <IP> #Both are default scripts
```

### Shodan

`ndmp`

