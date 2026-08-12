# 9042, 9160 - Pentesting Cassandra

{{#include ../banners/hacktricks-training.md}}

## Basic Information

**Apache Cassandra** is a distributed NoSQL database designed to store data across multiple nodes without a single point of failure.<sup>[[1]](#references)</sup>

The native CQL protocol listens on TCP port **9042** by default. TCP port **9160** belongs to the legacy Thrift RPC service; in Cassandra 3.11 it is disabled by default, and modern deployments normally use the native protocol.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

Historically, Cassandra's default `AllowAllAuthenticator` required no credentials. An exposed cluster with authentication disabled may therefore allow schema and data access, not merely credential guessing. Cassandra's security documentation recommends configuring authentication, authorization, and encryption together.<sup>[[3]](#references)</sup>

**Default/legacy ports:** 9042/TCP (native CQL), 9160/TCP (legacy Thrift)

```
PORT     STATE SERVICE   REASON
9042/tcp open  cassandra-native Apache Cassandra 3.10 or later (native protocol versions 3/v3, 4/v4, 5/v5-beta)
9160/tcp open  cassandra syn-ack
```

## Enumeration

### Manual

```sql
cqlsh <IP> 9042

-- Basic node information
SELECT cluster_name, data_center, rack, partitioner, native_protocol_version, release_version FROM system.local;

-- Older releases may also expose Thrift-specific version information
SELECT thrift_version FROM system.local;

-- Keyspace enumeration on current releases
SELECT keyspace_name FROM system_schema.keyspaces;
SELECT keyspace_name FROM system.schema_keyspaces; -- Cassandra 2.x and older
DESCRIBE KEYSPACES;
DESCRIBE KEYSPACE <keyspace_name>;
DESCRIBE KEYSPACE system_auth;

-- Role metadata, if the connected role is authorized to read it
SELECT role, is_superuser, can_login FROM system_auth.roles;
SELECT * FROM system_auth.roles;  -- May include password hashes in the configured backend

-- Application-specific tables discovered during keyspace enumeration
SELECT * FROM logdb.user_auth;
SELECT * FROM logdb.user;
SELECT * FROM configuration."config";
```

The `logdb` and `configuration` queries are examples from real deployments, not built-in Cassandra schemas. Run them only if enumeration shows those keyspaces and tables; otherwise, adapt the query to the application's discovered schema.

`cqlsh` ships with Cassandra and connects to one specified node through the native protocol. If the matching client is not otherwise available, a standalone package can be installed with `python3 -m pip install cqlsh`, but compatibility is guaranteed only between the `cqlsh` version and the Cassandra version with which it was released.<sup>[[4]](#references)[[6]](#references)</sup>

### Automated

Nmap's `cassandra-info` script attempts to retrieve basic server status. Its documented example targets the legacy Thrift service on port 9160, so it is not a replacement for CQL enumeration on port 9042.<sup>[[5]](#references)</sup>

```bash
nmap -sV --script cassandra-info -p <PORT> <IP>
```

### [**Brute force**](../generic-hacking/brute-force.md#cassandra)

### **Shodan**

`port:9160 Cluster`\
`port:9042 "Invalid or unsupported protocol version"`

## References

- [1] [Apache Cassandra FAQ - Default ports](https://cassandra.apache.org/doc/stable/cassandra/overview/faq/index.html#what-ports-does-cassandra-use)
- [2] [Apache Cassandra 3.11 configuration - Thrift and native transport](https://cassandra.apache.org/doc/3.11/cassandra/configuration/cass_yaml_file.html)
- [3] [Apache Cassandra documentation - Security](https://cassandra.apache.org/doc/stable/cassandra/managing/operating/security.html)
- [4] [Apache Cassandra documentation - cqlsh](https://cassandra.apache.org/doc/stable/cassandra/managing/tools/cqlsh.html)
- [5] [Nmap NSE documentation - cassandra-info](https://nmap.org/nsedoc/scripts/cassandra-info.html)
- [6] [PyPI - standalone `cqlsh` package](https://pypi.org/project/cqlsh/)

{{#include ../banners/hacktricks-training.md}}
