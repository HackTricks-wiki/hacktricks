# 11211 - Pentesting Memcache

{{#include ../../banners/hacktricks-training.md}}

## Protocol Information

**Memcached** is a distributed in-memory key/value cache commonly used to reduce repeated database or API work. Its servers are intentionally simple: clients choose a server, send a key, and receive or update the associated opaque value.<sup>[[5]](#references)</sup>

Memcached's binary protocol can be built with **SASL** authentication, but authentication is not automatically enabled. Treat any reachable unauthenticated listener as an exposure and restrict the service to trusted networks.<sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

**Default port:** 11211

```
PORT      STATE SERVICE
11211/tcp open  unknown
```

## Enumeration

### Manual

To enumerate information saved inside a Memcached instance:

1. Find **slabs** with **active items**
2. Get the **key names** of the slabs detected before
3. Retrieve the **saved data** by requesting the discovered keys

Remember that this service is just a **cache**, so **data may be appearing and disappearing**.

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

## **Dumping Memcached Keys**

Memcached organizes items into slab classes. Historical diagnostic commands can reveal keys, but they have important constraints:<sup>[[1]](#references)</sup>

1. Keys can only be dumped by slab class, grouping keys of similar content size.
2. A limit exists of one page per slab class, equating to 1MB of data.
3. `stats cachedump` is an unofficial, version-sensitive diagnostic command rather than a complete production-safe export mechanism.<sup>[[2]](#references)</sup>

The limitation of only being able to dump 1MB from potentially gigabytes of data is particularly significant. However, this functionality can still offer insights into key usage patterns, depending on specific needs. For those less interested in the mechanics, a visit to the [tools section](https://lzone.de/cheat-sheet/memcached#tools) reveals utilities for comprehensive dumping. Alternatively, the process of using telnet for direct interaction with memcached setups is outlined below.<sup>[[1]](#references)</sup>

### **How it Works**

Memcached's memory organization is pivotal. Starting Memcached with `-vv` reveals the slab classes it generates, as shown below:<sup>[[1]](#references)</sup>

```bash
$ memcached -vv
slab class   1: chunk size        96 perslab   10922
[...]
```

To display all currently existing slabs, the following command is used:

```bash
stats slabs
```

Adding a single key to memcached 1.4.13 illustrates how slab classes are populated and managed. For instance:

```bash
set mykey 0 60 1
1
STORED
```

Executing the "stats slabs" command post key addition yields detailed statistics about slab utilization:

```bash
stats slabs
[...]
```

This output reveals the active slab types, utilized chunks, and operational statistics, offering insights into the efficiency of read and write operations.

Another useful command, "stats items", provides data on evictions, memory constraints, and item lifecycles:

```bash
stats items
[...]
```

These statistics allow for educated assumptions about application caching behavior, including cache efficiency for different content sizes, memory allocation, and capacity for caching large objects.

### **Dumping Keys**

For versions prior to 1.4.31, keys are dumped by slab class using:

```bash
stats cachedump <slab class> <number of items to dump>
```

For example, to dump a key in class #1:

```bash
stats cachedump 1 1000
ITEM mykey [1 b; 1350677968 s]
END
```

This method iterates over slab classes, extracting and optionally dumping key values.

### **Dumping Memcached Keys (1.4.31+)**

Memcached 1.4.31 introduced `lru_crawler metadump`, a non-blocking way to enumerate item metadata across slab classes. It may generate extensive output, so stream or filter the response rather than buffering it unnecessarily.<sup>[[3]](#references)</sup>

```bash
echo 'lru_crawler metadump all' | nc 127.0.0.1 11211 | head -1
echo 'lru_crawler metadump all' | nc 127.0.0.1 11211 | grep ee6ba58566e234ccbbce13f9a24f9a28
```

### **DUMPING TOOLS**

Table [from here](https://lzone.de/blog).<sup>[[4]](#references)</sup>

| Language/tool | Resource | Functionality |
| --- | --- | --- |
| PHP | [simple script](http://snipt.org/xtP) | Prints key names. |
| Perl | [simple script](https://wiki.jasig.org/download/attachments/13572172/memcached-clean.pl?version=1&modificationDate=1229693957401) | Prints keys and values. |
| Ruby | [simple script](https://gist.github.com/1365005) | Prints key names. |
| Perl/libmemcached | [memdump](https://search.cpan.org/~dmaki/Memcached-libmemcached-0.4202/src/libmemcached/docs/memdump.pod) / [module](https://search.cpan.org/~dmaki/Memcached-libmemcached/) | Dumps keys through the CPAN module. |
| PHP | [memcache.php](http://livebookmark.net/journal/2008/05/21/memcachephp-stats-like-apcphp/) | Historical monitoring GUI that can dump keys. |
| libmemcached | [peep](http://blog.evanweaver.com/2009/04/20/peeping-into-memcached/) | Historical dumper that can freeze the Memcached process. Do not run it against production without explicit authorization and an outage plan. |

## Troubleshooting <a href="#troubleshooting" id="troubleshooting"></a>

### 1MB Data Limit <a href="#1mb-data-limit" id="1mb-data-limit"></a>

The default maximum item size is 1 MiB. Modern Memcached versions can change it with the `-I` option, subject to server limits; do not infer a historical version solely from the 1 MiB default.<sup>[[8]](#references)</sup>

### Never Set a Timeout > 30 Days! <a href="#never-set-a-timeout--30-days" id="never-set-a-timeout--30-days"></a>

For storage commands, expiration values up to 30 days are interpreted as relative seconds; larger values are interpreted as absolute Unix timestamps. A timestamp in the past expires the item immediately, which can look like a silent failure.<sup>[[6]](#references)</sup>

So if you want to use the maximum lifetime specify 2592000. Example:

```
set my_key 0 2592000 1
1
```

### Disappearing Keys on Overflow <a href="#disappearing-keys-on-overflow" id="disappearing-keys-on-overflow"></a>

Counter behavior is implementation- and version-sensitive. If an `incr` operation causes a key to disappear in the tested version, recreate it with `add` or `set` and verify the result before relying on overflow behavior.<sup>[[1]](#references)</sup>

### Replication <a href="#replication" id="replication"></a>

Memcached itself does not provide replication; the following historical or third-party projects offer related behavior.<sup>[[5]](#references)</sup>

- [repcached](http://repcached.lab.klab.org/): Multi-master async replication (memcached 1.2 patch set)
- [Couchbase memcached interface](http://www.couchbase.com/memcached): Use CouchBase as memcached drop-in
- [yrmcds](https://cybozu.github.io/yrmcds/): Memcached-compatible primary/replica key-value store
- [twemproxy](https://github.com/twitter/twemproxy) (aka nutcracker): proxy with memcached support

### Commands Cheat-Sheet


{{#ref}}
memcache-commands.md
{{#endref}}

### **Shodan**

- `port:11211 "STAT pid"`
- `"STAT pid"`

## References

- [1] [Memcached Cheat Sheet](https://lzone.de/cheat-sheet/memcached)
- [2] [Memcached "stats cachedump" discussion](https://groups.google.com/forum/?fromgroups=#!topic/memcached/1-T8I-RVGKM)
- [3] [Release Notes for memcached 1.4.31 - lru_crawler metadump](https://github.com/memcached/memcached/wiki/ReleaseNotes1431)
- [4] [LZone Blog - Memcached dumping tools](https://lzone.de/blog)
- [5] [Memcached documentation: About Memcached](https://docs.memcached.org/)
- [6] [Memcached protocol documentation](https://github.com/memcached/memcached/blob/master/doc/protocol.txt)
- [7] [Memcached SASL documentation](https://github.com/memcached/memcached/wiki/SASLHowto)
- [8] [Memcached server options (`-I` maximum item size)](https://github.com/memcached/memcached/blob/master/doc/memcached.1)

{{#include ../../banners/hacktricks-training.md}}
