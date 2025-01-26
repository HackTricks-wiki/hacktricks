# Wide Source Code Search

{{#include ../../banners/hacktricks-training.md}}

本页面的目标是列举**允许在一个或多个平台上搜索代码**（字面或正则表达式）的平台，这些平台可以在成千上万或数百万个代码库中进行搜索。

这在多个场合有助于**搜索泄露的信息**或**漏洞**模式。

- [**Sourcebot**](https://www.sourcebot.dev/): 开源代码搜索工具。通过现代网页界面索引和搜索成千上万的代码库。
- [**SourceGraph**](https://sourcegraph.com/search): 在数百万个代码库中搜索。有免费版本和企业版本（提供15天免费试用）。支持正则表达式。
- [**Github Search**](https://github.com/search): 在Github上搜索。支持正则表达式。
- 也许检查一下[**Github Code Search**](https://cs.github.com/)也很有用。
- [**Gitlab Advanced Search**](https://docs.gitlab.com/ee/user/search/advanced_search.html): 在Gitlab项目中搜索。支持正则表达式。
- [**SearchCode**](https://searchcode.com/): 在数百万个项目中搜索代码。

> [!WARNING]
> 当你在一个代码库中寻找泄露信息并运行类似`git log -p`的命令时，不要忘记可能还有**其他分支和其他提交**包含秘密！

{{#include ../../banners/hacktricks-training.md}}
