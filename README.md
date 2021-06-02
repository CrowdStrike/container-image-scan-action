# container-image-scan action

## Usage

### Pre-requisites

1. Have a CrowdStrike Container Workload Protection (CWP) subscription
1. Create an OAUTH2 secret at [https://falcon.crowdstrike.com/support/api-clients-and-keys](https://falcon.crowdstrike.com/support/api-clients-and-keys)
1. Add your OAUTH2 secret called `FALCON_CLIENT_SECRET` to a GitHub secret at `https://github.com/<your_org>/<your_repo>/settings/secrets/actions`
1. Create a workflow `.yml` file in your `.github/workflows` directory. An [example workflow](#example-workflow) is available below.
  For more information, reference the GitHub Help Documentation for [Creating a workflow file](https://help.github.com/en/articles/configuring-a-workflow#creating-a-workflow-file)

### Inputs

-  `falcon_client_id`: Your CrowdStrike OAUTH2 Client ID
-  `container_repository`: The container image to scan (e.g. `my_image` or `myregistry.io/my_container`)
-  `container_tag`: The container tag to scan against (default: `latest`)
-  `crowdstrike_region`: The CrowdStrike Cloud region to submit for scanning (default: `us-1`)

### Optional input for vulnerability score threshold

-  `crowdstrike_score`: The score threshold used to allow for step success (default: `500`)

### Example Workflow

Create a workflow (eg: `.github/workflows/scan.yml`):

```yaml
name: Scan Container Images

on:
  push:
    branches:
      - master

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v2

      - name: CrowdStrike Container Image Scan
        uses: crowdstrike/container-image-scan-action@v0.3
        with:
          falcon_client_id: <my_falcon_client_id>
          container_repository: docker.io/library/busybox
        env:
          FALCON_CLIENT_SECRET: "${{ secrets.FALCON_CLIENT_SECRET }}"
```

Alternatively if you want to run all the configurations as secrets, set any the following under `env` instead of `uses`:

```yaml
name: Scan Container Images

on:
  push:
    branches:
      - master

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v2

      - name: CrowdStrike Container Image Scan
        uses: crowdstrike/container-image-scan-action@v0.3
        env:
          FALCON_CLIENT_ID: "${{ secrets.FALCON_CLIENT_ID }}"
          FALCON_CLIENT_SECRET: "${{ secrets.FALCON_CLIENT_SECRET }}"
          FALCON_CLOUD_REGION: "{{ secrets.FALCON_CLOUD_REGION }}"
          CONTAINER_REPO: "{{ secrets.CONTAINER_REPO }}"
          CONTAINER_TAG: "{{ secrets.CONTAINER_TAG }}"
```
