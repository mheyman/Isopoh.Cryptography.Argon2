for /f "delims=" %%f in ('dir /b/s "*.nupkg" ^| findstr Release') do (
    nuget sign %%f -CertificatePath isopoh-nopass.pfx -Timestamper http://timestamp.digicert.com -CertificatePassword ""
)

