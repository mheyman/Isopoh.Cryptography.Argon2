# Unity compatibility smoke test

This minimal Unity 2022.3 project verifies that the `netstandard2.0` Argon2,
Blake2b, and SecureArray assemblies load in Unity, hash and verify a password,
select the Linux native `SecureArray` implementation, and successfully lock a
small buffer into RAM.

Run the **Unity compatibility smoke test** workflow manually after configuring
these GitHub Actions repository secrets:

- `UNITY_LICENSE`: the complete contents of a Unity `.ulf` license file
- `UNITY_EMAIL`: the Unity account email address
- `UNITY_PASSWORD`: the Unity account password

The workflow builds fresh plugin assemblies before running the Unity EditMode
test, so generated DLLs are not committed.

## Licensing limitation

Unity no longer officially supports manual activation for new Personal
licenses. GameCI's activation-file action is consequently deprecated. The
manual **Acquire Unity Activation File (legacy)** workflow is included so the
remaining GameCI flow can be tried without affecting normal CI. Download its
`.alf` artifact and submit it at `license.unity3d.com`; if Unity offers a
license download, put the complete downloaded `.ulf` contents in the
`UNITY_LICENSE` secret. An existing valid `.ulf` file may also work with
GameCI, while Pro licenses can use GameCI's serial-number flow. Do not commit
license files or credentials.

For a new Personal account, use a Unity-supported licensing route such as an
activated self-hosted runner or Unity Build Automation until Unity and GameCI
provide a supported headless Personal activation flow.

## Scope

This first smoke test runs inside the Linux Unity Editor. It validates Unity's
managed-assembly loading and the desktop P/Invoke memory-locking path. It does
not yet produce or execute an IL2CPP player; that should be the next test after
the licensing path is proven.
