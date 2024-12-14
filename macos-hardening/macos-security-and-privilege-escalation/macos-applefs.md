# macOS AppleFS

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}

## Apple Propietary File System (APFS)

**Apple File System (APFS)** is a modern file system designed to supersede the Hierarchical File System Plus (HFS+). Its development was driven by the need for **improved performance, security, and efficiency**.

Some notable features of APFS include:

1. **Space Sharing**: APFS allows multiple volumes to **share the same underlying free storage** on a single physical device. This enables more efficient space utilization as the volumes can dynamically grow and shrink without the need for manual resizing or repartitioning.
   1. This means, compared with traditional partitions in file disks, **that in APFS different partitions (volumes) shares all the disk space**, while a regular partition usually had a fixed size.
2. **Snapshots**: APFS supports **creating snapshots**, which are **read-only**, point-in-time instances of the file system. Snapshots enable efficient backups and easy system rollbacks, as they consume minimal additional storage and can be quickly created or reverted.
3. **Clones**: APFS can **create file or directory clones that share the same storage** as the original until either the clone or the original file is modified. This feature provides an efficient way to create copies of files or directories without duplicating the storage space.
4. **Encryption**: APFS **natively supports full-disk encryption** as well as per-file and per-directory encryption, enhancing data security across different use cases.
5. **Crash Protection**: APFS uses a **copy-on-write metadata scheme that ensures file system consistency** even in cases of sudden power loss or system crashes, reducing the risk of data corruption.

Overall, APFS offers a more modern, flexible, and efficient file system for Apple devices, with a focus on improved performance, reliability, and security.

```bash
diskutil list # Get overview of the APFS volumes
```

## Firmlinks

The `Data` volume is mounted in **`/System/Volumes/Data`** (you can check this with `diskutil apfs list`).

The list of firmlinks can be found in the **`/usr/share/firmlinks`** file.

```bash
{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

{% endhint %}
</details>
{% endhint %}

