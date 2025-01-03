# Wide Source Code Search

{{#include ../../banners/hacktricks-training.md}}

이 페이지의 목표는 **코드를 검색할 수 있는 플랫폼**(리터럴 또는 정규 표현식)을 수천/수백만 개의 리포지토리에서 하나 이상의 플랫폼에 걸쳐 나열하는 것입니다.

이는 여러 경우에 **유출된 정보** 또는 **취약점** 패턴을 검색하는 데 도움이 됩니다.

- [**SourceGraph**](https://sourcegraph.com/search): 수백만 개의 리포지토리에서 검색합니다. 무료 버전과 15일 무료의 엔터프라이즈 버전이 있습니다. 정규 표현식을 지원합니다.
- [**Github Search**](https://github.com/search): Github 전역에서 검색합니다. 정규 표현식을 지원합니다.
- 아마도 [**Github Code Search**](https://cs.github.com/)도 확인하는 것이 유용할 것입니다.
- [**Gitlab Advanced Search**](https://docs.gitlab.com/ee/user/search/advanced_search.html): Gitlab 프로젝트에서 검색합니다. 정규 표현식을 지원합니다.
- [**SearchCode**](https://searchcode.com/): 수백만 개의 프로젝트에서 코드를 검색합니다.

> [!WARNING]
> 리포지토리에서 유출을 찾고 `git log -p`와 같은 명령을 실행할 때 **비밀을 포함한 다른 커밋이 있는 다른 브랜치**가 있을 수 있다는 것을 잊지 마세요!

{{#include ../../banners/hacktricks-training.md}}
