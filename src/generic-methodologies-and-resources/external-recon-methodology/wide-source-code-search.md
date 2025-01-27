# Wide Source Code Search

{{#include ../../banners/hacktricks-training.md}}

The goal of this page is to enumerate **platforms that allow to search for code** (literal or regex) in across thousands/millions of repos in one or more platforms.

This helps in several occasions to **search for leaked information** or for **vulnerabilities** patterns.

- [**Sourcebot**](https://www.sourcebot.dev/): Open source code search tool. Index and search across thousands of your repos through a modern web interface.
- [**SourceGraph**](https://sourcegraph.com/search): Search in millions of repos. There is a free version and an enterprise version (with 15 days free). It supports regexes. 
- [**Github Search**](https://github.com/search): Search across Github. It supports regexes.
  - Maybe it's also useful to check also [**Github Code Search**](https://cs.github.com/).
- [**Gitlab Advanced Search**](https://docs.gitlab.com/ee/user/search/advanced_search.html): Search across Gitlab projects. Support regexes.
- [**SearchCode**](https://searchcode.com/): Search code in millions of projects.

> [!WARNING]
> When you look for leaks in a repo and run something like `git log -p` don't forget there might be **other branches with other commits** containing secrets!

{{#include ../../banners/hacktricks-training.md}}



