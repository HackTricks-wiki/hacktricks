# Cypher Injection (Neo4j)

{{#include ../../banners/hacktricks-training.md}}

Cypher injection occurs when an application constructs a Neo4j Cypher query by concatenating untrusted input. An attacker may alter the query structure to read or modify graph data and, depending on enabled procedures and cloud integrations, reach additional secrets or services.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

Use parameterized queries for values and allowlist any identifiers or query fragments that cannot be parameterized. The references below contain practical discovery and exploitation examples.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

## References

- [1] [Neo4jection: Secrets, Data, and Cloud Exploits](https://www.varonis.com/blog/neo4jection-secrets-data-and-cloud-exploits)
- [2] [The Most Underrated Injection of All Time — Cypher Injection](https://infosecwriteups.com/the-most-underrated-injection-of-all-time-cypher-injection-fa2018ba0de8)

{{#include ../../banners/hacktricks-training.md}}
