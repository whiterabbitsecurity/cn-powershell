#!/usr/local/bin/pwsh
# batch.ps1 - Process CSR files from input dir using onbehalf enroll

# KNOWN LIMITATIONS:
# - Error handling is minimal
# - File names and paths with spaces are not handled properly

# Set parameters
$InputDir = "batch-spool"
$WorkDir = $InputDir
$CertNanny = "certnanny"

$CSR_Suffix = ".csr"
$CRT_Suffix = "-cert.pem"
$CHN_Suffix = "-chain.pem"
$LOG_Suffix = ".log"

$CN_Config = ""
$CN_LogLevel = "2"

# Use HMAC with "enroll" or auth keystore with "enroll-onbehalf"
#$CN_Command = "enroll"
# Common commands are 'enroll-onbehalf' (if using a signing certificate to
# authenticate the requests) or 'enroll' (if using an HMAC secret)
$CN_Command = "enroll-onbehalf"

$CN_KeyStore = "server"

# Use HMAC secret (with 'enroll') instead of an authentication certificate
#$CN_Secret = "verysecret"

# Loop for each CSR file in the input directory
foreach ($csr in Get-ChildItem -Path "$InputDir\*$CSR_Suffix") {
    # Get name/label to use for this CN request
    $i = [System.IO.Path]::GetFileNameWithoutExtension($csr.Name)
    $logFile = Join-Path $WorkDir "$i.d\$i$LOG_Suffix"

    New-Item -ItemType Directory -Force -Path (Join-Path $WorkDir "$i.d") | Out-Null

    # Run CN using supplied CSR and specify the options needed
    # to make each request unique
    $cnargs = @()
    if ( $CN_Config ) {
        $cnargs += '--config', $CN_Config
    }
    if ( $CN_LogLevel ) {
        $cnargs += "--loglevel=$CN_LogLevel"
    }
    $cnargs += "--option", "keystore.${CN_KeyStore}.location=$(Join-Path $WorkDir \${i}.d)",
        "--option", "keystore.${CN_KeyStore}.statedir=$(Join-Path $WorkDir \${i}.d)",
        "--option", "keystore.${CN_KeyStore}.certificatefile=${i}$CRT_Suffix",
        "--option", "keystore.${CN_KeyStore}.chainfile=${i}$CHN_Suffix",
        "run", $CN_Command,
        "--",
        "--keystore", $CN_KeyStore,
        "--pkcs10", $csr.FullName,
        "--pkistatus", 1,
        $CN_Secret_Str
    if ( $CN_Secret ) {
        $cnargs += '--secret', $CN_Secret
    }

    "INFO: Running certnanny for $i" | Tee-Object -Append -FilePath $logFile
    "DEBUG: Running command: $CertNanny $cnargs" | Tee-Object -Append -FilePath $logFile
    &$CertNanny $cnargs 2>&1 | Tee-Object -Append -FilePath $logFile
    $rc = $LASTEXITCODE

    Write-Host "INFO: Process LASTEXITCODE: $rc"

    switch ($rc) {
        0 {
            Write-Host "INFO: CN Successful for $i"
        }
        3 {
            Write-Host "INFO: CN Request Pending for $i"
        }
        default {
            Write-Host "ERROR: CN Failed for $i - $rc"
        }
    }
}
