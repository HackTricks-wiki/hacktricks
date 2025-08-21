# Local Cloud Storage

{{#include ../../../banners/hacktricks-training.md}}


## OneDrive

In Windows, you can find the OneDrive folder in `\Users\<username>\AppData\Local\Microsoft\OneDrive`. And inside `logs\Personal` and `logs\Business1` it's possible to find the file `SyncDiagnostics.log` and multiple binary log files with extensions like `.odl`, `.odlgz`, `.odlsent`, `.aold` that contain detailed sync telemetry.

Interesting data you can extract from these logs and local state:

- Size in bytes
- Creation date
- Modification date
- Number of files in the cloud
- Number of files in the folder
- **CID**: Unique ID of the OneDrive user
- Report generation time
- Size of the HD of the OS

Once you have found the CID it's recommended to search files containing this ID. You may be able to find files with the name: `<CID>.ini` and `<CID>.dat` that may contain interesting information like the names of files synchronized with OneDrive.

### Parse OneDrive .ODL logs (modern clients)

- Paths (Windows):
  - `\AppData\Local\Microsoft\OneDrive\logs\Business1`
  - `\AppData\Local\Microsoft\OneDrive\logs\Personal`
- Required map for unobfuscation: `ObfuscationStringMap.txt` (usually present in one of the above folders). 
- Tooling: use the public parser to extract unobfuscated function names, parameters, timestamps and file paths from `.odl`/`.odlgz`:

```bash
# Example
python3 odl.py -s ObfuscationStringMap.txt \
  "C:\\Users\\<user>\\AppData\\Local\\Microsoft\\OneDrive\\logs\\Business1" 
```

This is extremely useful to prove upload/download/synchronization operations and to reconstruct activity even if the local artifact was removed.

### Files On-Demand reparse points (forensic tip)

OneDrive Files On-Demand implements cloud placeholders using NTFS reparse points. You can validate the placeholder tag and script file states:

```cmd
# Inspect a given file/folder reparse tag
fsutil reparsepoint query "C:\\Users\\<user>\\OneDrive\\path\\to\\item"

# Query or set Files On-Demand states
attrib <path>                 # shows current attributes
attrib +p <path>              # Pinned (Always available)
attrib -p <path>              # Clearpin (Locally available)
attrib +u <path>              # Unpinned (Online-only)
```

These attributes are commonly pivoted in timelines to demonstrate when content became local-only vs cloud-only and to locate artifacts that would have brought bytes on disk.


## Google Drive

Google’s Windows client evolved over time. Older “Backup and Sync” artifacts live under `...\Google\Drive\` with `snapshot.db`/`sync_config.db` and text logs. Modern "Drive for desktop" (DriveFS) uses a virtual drive and different paths and databases.

### Drive for desktop (DriveFS) artifacts (current)

- Mount and configuration:
  - `HKCU\Software\Google\DriveFS\Share` tracks the mapped virtual drive letter.
  - Optional cache relocation: `HKCU\Software\Google\DriveFS\ContentCachePath`.
- Per-account working directory: `\Users\<user>\AppData\Local\Google\DriveFS\<account_id>\`
  - `metadata_sqlite_db` (SQLite): primary metadata DB for files/folders (cloud-only, offline, and deleted). Key tables/fields:
    - `items(stable_id, id, trashed, is_owner, is_folder, local_title, file_size, modified_date, viewed_by_me_date, shared_with_me_date, proto)`
    - `item_properties(name, value)` — includes flags like `pinned`, `trashed-locally`, `content-entry` (links to cached content), etc.
  - `content_cache\` — local cached file bytes in nested numeric folders.
  - `lost_and_found\<account_token>` — items with sync errors.

Example: list deleted files and whether they were deleted locally vs in cloud:

```sql
-- Run with: sqlite3 metadata_sqlite_db
.headers on
.mode column
SELECT 
  items.local_title AS name,
  DATETIME(items.modified_date/1000,'unixepoch') AS last_mod,
  items.trashed AS in_trash,
  MAX(CASE WHEN item_properties.name='trashed-locally' THEN item_properties.value END) AS trashed_locally,
  MAX(CASE WHEN item_properties.name='pinned' THEN item_properties.value END) AS pinned,
  MAX(CASE WHEN item_properties.name='content-entry' THEN item_properties.value END) AS cache_ref
FROM items 
LEFT JOIN item_properties ON item_properties.stable_id = items.stable_id
WHERE items.trashed = 1
GROUP BY items.stable_id
ORDER BY last_mod DESC;
```

Tip: entries with a `content-entry` value typically correspond to a cached blob under `content_cache\` that can be carved by size/signature and correlated by `stable_id`/hash.

### Legacy Google Drive (“Backup and Sync”) artifacts

In Windows, you can find the main Google Drive folder in `\Users\<username>\AppData\Local\Google\Drive\user_default`.
This folder contains a file called `Sync_log.log` with information like the email address of the account, filenames, timestamps, MD5 hashes of the files, etc. Even deleted files appear in that log file with its corresponding MD5.

The file `Cloud_graph\Cloud_graph.db` is a SQLite database which contains the table `cloud_graph_entry`. In this table you can find the name of the synchronized files, modified time, size, and the MD5 checksum of the files.

The table data of the database `Sync_config.db` contains the email address of the account, the path of the shared folders and the Google Drive version.


## Dropbox

Dropbox uses SQLite databases to manage the files. In this
You can find the databases in the folders:

- `\Users\<username>\AppData\Local\Dropbox`
- `\Users\<username>\AppData\Local\Dropbox\Instance1`
- `\Users\<username>\AppData\Roaming\Dropbox`

And the main databases are:

- Sigstore.dbx
- Filecache.dbx
- Deleted.dbx
- Config.dbx

The ".dbx" extension means that the databases are encrypted. Dropbox uses DPAPI (https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN)

To understand better the encryption that Dropbox uses you can read https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html.

However, the main information is:

- **Entropy**: d114a55212655f74bd772e37e64aee9b
- **Salt**: 0D638C092E8B82FC452883F95F355B8E
- **Algorithm**: PBKDF2
- **Iterations**: 1066

Apart from that information, to decrypt the databases you still need:

- The **encrypted DPAPI key**: You can find it in the registry inside `NTUSER.DAT\Software\Dropbox\ks\client` (export this data as binary)
- The **`SYSTEM`** and **`SECURITY`** hives
- The **DPAPI master keys**: Which can be found in `\Users\<username>\AppData\Roaming\Microsoft\Protect`
- The **username** and **password** of the Windows user

Then you can use the tool [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi_data_decryptor.html):

![](<../../../images/image (443).png>)

If everything goes as expected, the tool will indicate the **primary key** that you need to **use to recover the original one**. To recover the original one, just use this [cyber_chef receipt](<https://gchq.github.io/CyberChef/index.html#recipe=Derive_PBKDF2_key(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D)>) putting the primary key as the "passphrase" inside the receipt.

The resulting hex is the final key used to encrypt the databases which can be decrypted with:

```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```

The **`config.dbx`** database contains:

- **Email**: The email of the user
- **usernamedisplayname**: The name of the user
- **dropbox_path**: Path where the dropbox folder is located
- **Host_id: Hash** used to authenticate to the cloud. This can only be revoked from the web.
- **Root_ns**: User identifier

The **`filecache.db`** database contains information about all the files and folders synchronized with Dropbox. The table `File_journal` is the one with more useful information:

- **Server_path**: Path where the file is located inside the server (this path is preceded by the `host_id` of the client).
- **local_sjid**: Version of the file
- **local_mtime**: Modification date
- **local_ctime**: Creation date

Other tables inside this database contain more interesting information:

- **block_cache**: hash of all the files and folders of Dropbox
- **block_ref**: Related the hash ID of the table `block_cache` with the file ID in the table `file_journal`
- **mount_table**: Share folders of dropbox
- **deleted_fields**: Dropbox deleted files
- **date_added**

Note: Some modern Dropbox client builds have changed or removed certain databases (e.g., `filecache.dbx` on newer versions). Prefer live acquisition of keys/DBs when possible.


## Box Drive (Windows)

- Paths:
  - Local cache: `%AppData%\Local\Box\Box\cache`
  - Databases: `%AppData%\Local\Box\Box\data` (e.g., `sync.db`, `streemsfs.db`, `metrics.db`)
  - Logs: `%AppData%\Local\Box\Box\logs` (`box_streem_#_<date>.log` provides detailed file operations)
- Useful DBs/fields:
  - `sync.db` and `streemsfs.db` track item names, SHA1, size, created/modified/accessed timestamps; `metrics.db` stores user account (email/login).
  - `streemsfs.db` → `fsnodes` (name, createdAtTimestamp, modifiedAtTimestamp, accessedAtTimestamp, markForOffline, inodeId, parentInodeId) and `cachefiles` (cacheDataId, size, inodeId, age).
- Forensics: Use inodeId to correlate cached bytes to logical paths; logs enumerate adds/updates/removals/opens and the local sync root location.


## References

- Reading OneDrive Logs (.ODL), unobfuscation map and parser: https://www.swiftforensics.com/2022/02/reading-onedrive-logs.html
- Google Drive for Desktop (DriveFS) artifact paths and DBs: https://havocontheharddrive.com/google-drive-for-desktop-artifacts

{{#include ../../../banners/hacktricks-training.md}}
