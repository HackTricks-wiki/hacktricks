

<details>

<summary><strong>Support HackTricks and get benefits!</strong></summary>

- Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

- Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)

- Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/carlospolopm)**.**

- **Share your hacking tricks by submitting PRs to the** [**hacktricks github repo**](https://github.com/carlospolop/hacktricks)**.**

</details>


Google has [a handful of database technologies](https://cloud.google.com/products/databases/) that you may have access to via the default service account or another set of credentials you have compromised thus far.

Databases will usually contain interesting information, so it would be completely recommended to check them. Each database type provides various **`gcloud` commands to export the data**. This typically involves **writing the database to a cloud storage bucket first**, which you can then download. It may be best to use an existing bucket you already have access to, but you can also create your own if you want.

As an example, you can follow [Google's documentation](https://cloud.google.com/sql/docs/mysql/import-export/exporting) to exfiltrate a Cloud SQL database.

## [Cloud SQL](https://cloud.google.com/sdk/gcloud/reference/sql/)

Cloud SQL instances are **fully managed, relational MySQL, PostgreSQL and SQL Server databases**. Google handles replication, patch management and database management to ensure availability and performance.[Learn more](https://cloud.google.com/sql/docs/)

If you find any of these instances in use, you could try to **access it from the internet** as they might be miss-configured and accessible.

```bash
# Cloud SQL
gcloud sql instances list
gcloud sql databases list --instance [INSTANCE]
gcloud sql backups list --instance [INSTANCE]
gcloud sql export sql <DATABASE_INSTANCE> gs://<CLOUD_STORAGE_BUCKET>/cloudsql/export.sql.gz --database <DATABASE_NAME>
```

## [Cloud Spanner](https://cloud.google.com/sdk/gcloud/reference/spanner/)

Fully managed relational database with unlimited scale, strong consistency, and up to 99.999% availability.

```bash
# Cloud Spanner
gcloud spanner instances list
gcloud spanner databases list --instance [INSTANCE]
gcloud spanner backups list --instance [INSTANCE]
```

## [Cloud Bigtable](https://cloud.google.com/sdk/gcloud/reference/bigtable/) <a href="#cloud-bigtable" id="cloud-bigtable"></a>

A fully managed, scalable NoSQL database service for large analytical and operational workloads with up to 99.999% availability. [Learn more](https://cloud.google.com/bigtable).

```bash
# Cloud Bigtable
gcloud bigtable instances list
gcloud bigtable clusters list
gcloud bigtable backups list --instance [INSTANCE]
```

## [Cloud Firestore](https://cloud.google.com/sdk/gcloud/reference/firestore/)

Cloud Firestore is a flexible, scalable database for mobile, web, and server development from Firebase and Google Cloud. Like Firebase Realtime Database, it keeps your data in sync across client apps through realtime listeners and offers offline support for mobile and web so you can build responsive apps that work regardless of network latency or Internet connectivity. Cloud Firestore also offers seamless integration with other Firebase and Google Cloud products, including Cloud Functions. [Learn more](https://firebase.google.com/docs/firestore).

```
gcloud firestore indexes composite list
gcloud firestore indexes fields list
gcloud firestore export gs://my-source-project-export/export-20190113_2109 --collection-ids='cameras','radios'
```

## [Firebase](https://cloud.google.com/sdk/gcloud/reference/firebase/)

The Firebase Realtime Database is a cloud-hosted NoSQL database that lets you store and sync data between your users in realtime. [Learn more](https://firebase.google.com/products/realtime-database/).

## Memorystore

Reduce latency with scalable, secure, and highly available in-memory service for [**Redis**](https://cloud.google.com/sdk/gcloud/reference/redis) and [**Memcached**](https://cloud.google.com/sdk/gcloud/reference/memcache). Learn more.

```bash
gcloud memcache instances list --region [region]
# You should try to connect to the memcache instances to access the data

gcloud redis instances list --region [region]
gcloud redis instances export gs://my-bucket/my-redis-instance.rdb my-redis-instance --region=us-central1
```

## [Bigquery](https://cloud.google.com/bigquery/docs/bq-command-line-tool)

BigQuery is a fully-managed enterprise data warehouse that helps you manage and analyze your data with built-in features like machine learning, geospatial analysis, and business intelligence. BigQuery’s serverless architecture lets you use SQL queries to answer your organization’s biggest questions with zero infrastructure management. BigQuery’s scalable, distributed analysis engine lets you query terabytes in seconds and petabytes in minutes. [Learn more](https://cloud.google.com/bigquery/docs/introduction).

```bash
bq ls -p #List rojects
bq ls -a #List all datasets
bq ls #List datasets from current project
bq ls <dataset_name> #List tables inside the DB

# Show information
bq show "<proj_name>:<dataset_name>"
bq show "<proj_name>:<dataset_name>.<table_name>"
bq show --encryption_service_account

bq query '<query>' #Query inside the dataset

# Dump the table or dataset
bq extract ds.table gs://mybucket/table.csv
bq extract -m ds.model gs://mybucket/model
```

Big query SQL Injection: [https://ozguralp.medium.com/bigquery-sql-injection-cheat-sheet-65ad70e11eac](https://ozguralp.medium.com/bigquery-sql-injection-cheat-sheet-65ad70e11eac)


<details>

<summary><strong>Support HackTricks and get benefits!</strong></summary>

- Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

- Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)

- Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/carlospolopm)**.**

- **Share your hacking tricks by submitting PRs to the** [**hacktricks github repo**](https://github.com/carlospolop/hacktricks)**.**

</details>


