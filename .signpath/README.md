# SignPath setup

The GitHub workflow in `.github/workflows/sign-nuget.yml` builds the NuGet
package on a GitHub-hosted runner, uploads it as a GitHub Actions artifact,
submits that artifact to SignPath, and uploads the signed package as a new
workflow artifact. Symbol packages are kept separate because they are not
NuGet author-signing targets.

## SignPath portal

1. Create a project for this repository and link the predefined `GitHub.com`
   trusted build system to it.
2. Create an artifact configuration and paste the contents of
   `artifact-configuration.xml`. Keep its slug for the GitHub configuration.
3. Select the self-signed test certificate in a signing policy and allow the
   workflow's submitter to use that policy.
4. Create an API token for that submitter.

The artifact configuration starts with `<zip-file>` because GitHub's
`upload-artifact` action stores the submitted package in a ZIP archive.

## GitHub repository settings

Add the following Actions repository secret:

- `SIGNPATH_API_TOKEN`

Add the following Actions repository variables using the exact values shown
in the SignPath portal:

- `SIGNPATH_ORGANIZATION_ID`
- `SIGNPATH_PROJECT_SLUG`
- `SIGNPATH_SIGNING_POLICY_SLUG`
- `SIGNPATH_ARTIFACT_CONFIGURATION_SLUG`

Run **Sign NuGet package** manually with a test version. After the test
certificate setup is approved, creating a tag such as `v2.0.1` will run the
same signing workflow automatically and use `2.0.1` as the package version.

The workflow intentionally does not publish to NuGet.org. Publishing should be
added only after SignPath has issued the production certificate and a signed
test package has been verified.
