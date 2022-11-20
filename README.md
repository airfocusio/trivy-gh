# trivy-gh

## Usage with github actions

```yaml
# .trivy-gh.yaml
github:
  token: ${GITHUB_TOKEN}
  issueRepo: ${GITHUB_REPOSITORY}
# ...
```

```yaml
# .github/workflows/trivy-gh.yaml
name: Trivy GH
schedule:
- cron: "30 6 * * *"
jobs:
  trivy-gh:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    - id: trivy-gh
      uses: airfocusio/trivy-gh-test@main
      env:
        GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```
