# GCP - Databases

Google has [a handful of database technologies](https://cloud.google.com/products/databases/) that you may have access to via the default service account or another set of credentials you have compromised thus far.

Databases will usually contain interesting information, so it would be completely recommended to check them. Each database type provides various **`gcloud` commands to export the data**. This typically involves **writing the database to a cloud storage bucket first**, which you can then download. It may be best to use an existing bucket you already have access to, but you can also create your own if you want.

As an example, you can follow [Google's documentation](https://cloud.google.com/sql/docs/mysql/import-export/exporting) to exfiltrate a Cloud SQL database.

### [Cloud SQL](https://cloud.google.com/sdk/gcloud/reference/sql/)

Cloud SQL instances are **fully managed, relational MySQL, PostgreSQL and SQL Server databases**. Google handles replication, patch management and database management to ensure availability and performance.[Learn more](https://cloud.google.com/sql/docs/)

```bash
# Cloud SQL
gcloud sql instances list
gcloud sql databases list --instance [INSTANCE]
gcloud sql backups list --instance [INSTANCE]
```

### [Cloud Spanner](https://cloud.google.com/sdk/gcloud/reference/spanner/)

Fully managed relational database with unlimited scale, strong consistency, and up to 99.999% availability.

```bash
# Cloud Spanner
gcloud spanner instances list
gcloud spanner databases list --instance [INSTANCE]
gcloud spanner backups list --instance [INSTANCE]
```

### [Cloud Bigtable](https://cloud.google.com/sdk/gcloud/reference/bigtable/) <a href="cloud-bigtable" id="cloud-bigtable"></a>

A fully managed, scalable NoSQL database service for large analytical and operational workloads with up to 99.999% availability. [Learn more](https://cloud.google.com/bigtable).

```bash
# Cloud Bigtable
gcloud bigtable instances list
gcloud bigtable clusters list
gcloud bigtable backups list --instance [INSTANCE]
```

### [Cloud Firestore](https://cloud.google.com/sdk/gcloud/reference/firestore/)

Cloud Firestore is a flexible, scalable database for mobile, web, and server development from Firebase and Google Cloud. Like Firebase Realtime Database, it keeps your data in sync across client apps through realtime listeners and offers offline support for mobile and web so you can build responsive apps that work regardless of network latency or Internet connectivity. Cloud Firestore also offers seamless integration with other Firebase and Google Cloud products, including Cloud Functions. [Learn more](https://firebase.google.com/docs/firestore).

```
```

\
&#x20;

### &#x20;



* [Cloud Firestore](https://cloud.google.com/sdk/gcloud/reference/firestore/)
* [Firebase](https://cloud.google.com/sdk/gcloud/reference/firebase/)
* There are more databases

