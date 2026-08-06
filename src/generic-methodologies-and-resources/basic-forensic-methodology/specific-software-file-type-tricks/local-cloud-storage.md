# 로컬 Cloud Storage

{{#include ../../../banners/hacktricks-training.md}}


## OneDrive

Windows에서는 OneDrive 폴더를 `\Users\<username>\AppData\Local\Microsoft\OneDrive`에서 찾을 수 있습니다. 그리고 `logs\Personal` 내부에서는 동기화된 파일과 관련된 흥미로운 데이터가 포함된 `SyncDiagnostics.log` 파일을 찾을 수 있습니다.

- 바이트 단위 크기
- 생성 날짜
- 수정 날짜
- cloud에 있는 파일 수
- 폴더에 있는 파일 수
- **CID**: OneDrive 사용자의 고유 ID
- 보고서 생성 시간
- OS가 설치된 HD의 크기

CID를 찾았다면 **이 ID가 포함된 파일을 검색**하는 것이 좋습니다. _**\<CID>.ini**_ 및 _**\<CID>.dat**_라는 이름의 파일을 찾을 수 있으며, 이러한 파일에는 OneDrive와 동기화된 파일 이름과 같은 흥미로운 정보가 포함되어 있을 수 있습니다.

## Google Drive

Windows에서는 기본 Google Drive 폴더를 `\Users\<username>\AppData\Local\Google\Drive\user_default`에서 찾을 수 있습니다.\
이 폴더에는 계정의 이메일 주소, 파일 이름, 타임스탬프, 파일의 MD5 해시 등의 정보가 포함된 Sync_log.log 파일이 있습니다. 삭제된 파일도 해당 MD5와 함께 이 로그 파일에 나타납니다.

**`Cloud_graph\Cloud_graph.db`** 파일은 **`cloud_graph_entry`** 테이블을 포함하는 sqlite 데이터베이스입니다. 이 테이블에서는 **동기화된** **파일**의 **이름**, 수정 시간, 크기 및 파일의 MD5 체크섬을 확인할 수 있습니다.

**`Sync_config.db`** 데이터베이스의 테이블 데이터에는 계정의 이메일 주소, 공유 폴더의 경로 및 Google Drive 버전이 포함되어 있습니다.

## Dropbox

Dropbox는 파일을 관리하기 위해 **SQLite databases**를 사용합니다. 이\
데이터베이스는 다음 폴더에서 찾을 수 있습니다.

- `\Users\<username>\AppData\Local\Dropbox`
- `\Users\<username>\AppData\Local\Dropbox\Instance1`
- `\Users\<username>\AppData\Roaming\Dropbox`

그리고 주요 데이터베이스는 다음과 같습니다.

- Sigstore.dbx
- Filecache.dbx
- Deleted.dbx
- Config.dbx

".dbx" 확장자는 **databases**가 **암호화**되어 있음을 의미합니다. Dropbox는 DPAPI를 사용합니다 ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](<https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN>))

Dropbox가 사용하는 암호화를 더 잘 이해하려면 [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html)을 읽을 수 있습니다.<sup>[[1]](#references)[[2]](#references)</sup>

그러나 주요 정보는 다음과 같습니다.<sup>[[1]](#references)</sup>

- **Entropy**: d114a55212655f74bd772e37e64aee9b
- **Salt**: 0D638C092E8B82FC452883F95F355B8E
- **Algorithm**: PBKDF2
- **Iterations**: 1066

이 정보 외에도 databases를 복호화하려면 다음 항목이 필요합니다.<sup>[[2]](#references)</sup>

- **암호화된 DPAPI key**: 레지스트리의 `NTUSER.DAT\Software\Dropbox\ks\client`에서 찾을 수 있습니다(이 데이터를 binary로 내보냅니다).
- **`SYSTEM`** 및 **`SECURITY`** hives
- **DPAPI master keys**: `\Users\<username>\AppData\Roaming\Microsoft\Protect`에서 찾을 수 있습니다.
- Windows 사용자의 **username** 및 **password**

그런 다음 [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi_data_decryptor.html)**:**

![Google Drive - Dropbox: 그런 다음 DataProtectionDecryptor 도구를 사용할 수 있습니다.](<../../../images/image (443).png>)

모든 과정이 예상대로 진행되면 도구는 **원래 key를 복구하는 데 사용해야 하는** **primary key**를 표시합니다. 원래 key를 복구하려면 이 [cyber_chef receipt](<https://gchq.github.io/CyberChef/index.html#recipe=Derive_PBKDF2_key(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D)>)를 사용하고 receipt 내부의 "passphrase"로 primary key를 입력하면 됩니다.

생성된 hex는 databases를 암호화하는 데 사용되는 최종 key이며, 다음을 사용하여 복호화할 수 있습니다:
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
**`config.dbx`** 데이터베이스에는 다음 정보가 포함됩니다:

- **Email**: 사용자의 이메일
- **usernamedisplayname**: 사용자의 이름
- **dropbox_path**: Dropbox 폴더가 위치한 경로
- **Host_id: Hash**: cloud에 인증하는 데 사용되는 Hash. 이는 웹에서만 revoke할 수 있습니다.
- **Root_ns**: 사용자 식별자

**`filecache.db`** 데이터베이스에는 Dropbox와 동기화된 모든 파일 및 폴더에 대한 정보가 포함됩니다. `File_journal` 테이블에 가장 유용한 정보가 있습니다:

- **Server_path**: 서버 내부에서 파일이 위치한 경로(이 경로 앞에는 client의 `host_id`가 붙습니다).
- **local_sjid**: 파일 버전
- **local_mtime**: 수정 날짜
- **local_ctime**: 생성 날짜

이 데이터베이스의 다른 테이블에도 더욱 흥미로운 정보가 포함되어 있습니다:

- **block_cache**: Dropbox의 모든 파일 및 폴더의 hash
- **block_ref**: `block_cache` 테이블의 hash ID와 `file_journal` 테이블의 파일 ID 연결
- **mount_table**: Dropbox의 공유 폴더
- **deleted_fields**: Dropbox에서 삭제된 파일
- **date_added**

## References

- [1] [A critical analysis of Dropbox software security (hack.lu 2012)](http://archive.hack.lu/2012/Dropbox%20security.pdf)
- [2] [Brush up on Dropbox DBX decryption](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html)

{{#include ../../../banners/hacktricks-training.md}}
