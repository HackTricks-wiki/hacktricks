# GCP - Serverless Code Exec Services Enumeration

## Cloud Functions <a href="reviewing-cloud-functions" id="reviewing-cloud-functions"></a>

Google [Cloud Functions](https://cloud.google.com/functions/) allow you to host code that is executed when an event is triggered, without the requirement to manage a host operating system. These functions can also store environment variables to be used by the code.

```bash
# List functions
gcloud functions list

# Get function config including env variables
gcloud functions describe [FUNCTION NAME]

# Get logs of previous runs
# By default, limits to 10 lines
gcloud functions logs read [FUNCTION NAME] --limit [NUMBER]
```

## App Engine Configurations <a href="reviewing-app-engine-configurations" id="reviewing-app-engine-configurations"></a>

Google [App Engine](https://cloud.google.com/appengine/) is another ["serverless"](https://about.gitlab.com/topics/serverless/) offering for hosting applications, with a focus on scalability. As with Cloud Functions, **there is a chance that the application will rely on secrets that are accessed at run-time via environment variables**. These variables are stored in an `app.yaml` file which can be accessed as follows:

```bash
# First, get a list of all available versions of all services
gcloud app versions list

# Then, get the specific details on a given app
gcloud app describe [APP]
```

## Cloud Run Configurations <a href="reviewing-cloud-run-configurations" id="reviewing-cloud-run-configurations"></a>

Google [Cloud Run](https://cloud.google.com/run) is another serverless offer where you can search for env variables also. Cloud Run creates a small web server, running on port 8080, that sits around waiting for an HTTP GET request. When the request is received, a job is executed and the job log is output via an HTTP response.

The access to this web server might be public of managed via IAM permissions:

```bash
# First get a list of services across the available platforms
gcloud run services list --platform=managed
gcloud run services list --platform=gke

# To learn more, export as JSON and investigate what the services do
gcloud run services list --platform=managed --format=json
gcloud run services list --platform=gke --format=json

# Attempt to trigger a job unauthenticated
curl [URL]

# Attempt to trigger a job with your current gcloud authorization
curl -H \
    "Authorization: Bearer $(gcloud auth print-identity-token)" \
    [URL]
```

## References

* [https://about.gitlab.com/blog/2020/02/12/plundering-gcp-escalating-privileges-in-google-cloud-platform/#reviewing-stackdriver-logging](https://about.gitlab.com/blog/2020/02/12/plundering-gcp-escalating-privileges-in-google-cloud-platform/#reviewing-stackdriver-logging)
