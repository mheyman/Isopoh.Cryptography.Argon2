# Unity compatibility smoke test

This minimal Unity 2022.3 project verifies that the `netstandard2.0` Argon2,
Blake2b, and SecureArray assemblies load in Unity, hash and verify a password,
select the host's native `SecureArray` implementation, and successfully lock a
small buffer into RAM.

## Unity Build Automation

Create a Build Automation configuration with these settings:

- Repository: `https://github.com/mheyman/Isopoh.Cryptography.Argon2`
- Branch: `main`
- Project subfolder path: `test/UnitySmokeTest`
- Auto detect Unity version: enabled
- Platform: macOS for the first run
- Builder OS: macOS Sequoia
- Pre-build script path: `test/UnitySmokeTest/prepare-uba.sh`
- Run my project's unit tests when building: enabled
- Run EditMode tests: enabled
- Mark build as failed if any test fails: enabled
- Auto-build: disabled until the first manual build succeeds

The pre-build script installs a private .NET 10 SDK in the build workspace,
builds the current checkout's `netstandard2.0` assemblies, and copies them into
`Assets/Plugins` before Unity starts. Generated DLLs are not committed.

After the macOS test succeeds, add a Windows IL2CPP configuration. UBA can also
create UWP builds, but an EditMode test runs on the builder host; executing the
resulting player is a separate test.

Run the **Unity compatibility smoke test** workflow manually after configuring
these GitHub Actions repository secrets:

- `UNITY_LICENSE`: the complete contents of a Unity `.ulf` license file
- `UNITY_EMAIL`: the Unity account email address
- `UNITY_PASSWORD`: the Unity account password

The workflow builds fresh plugin assemblies before running the Unity EditMode
test, so generated DLLs are not committed.

## Licensing limitation

Unity no longer officially supports manual activation for new Personal
licenses. GameCI's activation-file action is consequently deprecated and now
fails without producing an `.alf`. An existing valid `.ulf` file may still
work with GameCI; put its complete contents in the `UNITY_LICENSE` secret.
Pro licenses can use GameCI's serial-number flow. Do not commit license files
or credentials.

For a new Personal account, use a Unity-supported licensing route such as an
activated self-hosted runner or Unity Build Automation until Unity and GameCI
provide a supported headless Personal activation flow.

## Scope

This first smoke test runs inside the Unity Editor. It validates Unity's
managed-assembly loading and the builder host's desktop P/Invoke memory-locking
path. It does not yet execute an IL2CPP player; that should be the next test
after the Build Automation path is proven.
