param(
    [Parameter(HelpMessage="Path to signtool.exe")]
    [string]$SignTool = 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe',
    [Parameter(HelpMessage="Path to the pfx (key pair) file if there is a pfx file. There needs to be a pfx file or a subject to find the keypair in the certificate store.")]
    [string]$Pfx = 'isopoh-nopass.pfx',
    [Parameter(HelpMessage="Password")]
    [string]$Pwd = '',
    [Parameter(HelpMessage="The subject to find the keypar in the certificate store. There needs to be a pfx file or a subject.")]
    [string]$Subject = '',
    [Parameter(HelpMessage="The timestamp server URL.")]
    [string]$Ts = 'http://timestamp.digicert.com',
    [Parameter(HelpMessage="Semicolon separated list of directories to look under for DLLs or EXEs to sign.")]
    [string]$ProjRoots = 'lib/Isopoh.Cryptography.SecureArray;lib/Isopoh.Cryptography.Blake2b;lib/Isopoh.Cryptography.Argon2'
)
$signtool = $SignTool;
$pfx = $Pfx;
$pwd = $Pwd;
$subject = $Subject;
$ts = $Ts;
$projRoots = $ProjRoots -split ';';
foreach ($r in $projRoots) {
    $root = Join-Path -Path 'C:\Users\mheym\source\repos\argon2' -ChildPath $r.Trim()
    if (-not (Test-Path $root)) { Write-Host ('Project root not found: ' + $root); continue }
    $files = Get-ChildItem -Path $root -Recurse -File -Include *.dll,*.exe -ErrorAction SilentlyContinue | Where-Object { $_.FullName -like "*bin\Release*" }
    foreach ($f in $files) {
        echo $f
        Write-Host ('Signing managed: ' + $f.FullName)
        if ($pfx -and (Test-Path $pfx)) {
            & $signtool sign /debug /f $pfx /tr $ts /td SHA256 /fd SHA256 /v ($f.FullName) -or exit 2
        } elseif ($subject -ne '') {
            & $signtool sign /n $subject /tr $ts /td SHA256 /fd SHA256 /v ($f.FullName) -or exit 3
        } else {
            Write-Host 'No certificate configured (SIGNING_CERT_PFX or SIGNING_CERT_SUBJECT). Skipping signing for managed outputs.';
        }
    }
}