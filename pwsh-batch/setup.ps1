# setup.ps1 - setup example for batch PowerShell script
#
# This creates a few example CSR files and the onbehalf
# authentication certificate used in the batch script.
#
# PREREQUISITES:
#
# - "certnanny" in the current path
# - license.lic in the current directory
# - openssl

$ErrorActionPreference = "Stop"

$datadir = "batch-spool"

# un-comment for test environment if you get an error running 'certnanny run caloader ...'
$caloader_opts = "--tls-insecure"

function Get-RandomHexString {
    $hexString = -join (Get-Random -Count 4 -Minimum 0 -Maximum 65536 | ForEach-Object { $_.ToString("X4") })
    return $hexString
}

if (-not (Test-Path $datadir)) {
    Write-Host "INFO: creating test CSRs..."
    New-Item -ItemType Directory -Path $datadir | Out-Null
    1..3 | ForEach-Object {
        $hostname = Get-RandomHexString
        $privkey = Join-Path $datadir "$hostname.key"
        $pkcs10 = Join-Path $datadir "$hostname.csr"

        Write-Host "INFO: generating CSR for $hostname..."
        $subj = "/C=US/ST=Florida/L=MelBch/O=Company Name/OU=Org/CN=${hostname}-demo.openxpki.test"
        openssl req -newkey rsa:2048 -keyout $privkey -out $pkcs10 -passout pass:1234 -subj $subj
    }
}

if (-not (Test-Path "trustedroot")) {
    Write-Host "INFO: creating on-behalf auth cert..."
    certnanny ${caloader_opts} run caloader -- --target local
    $rc = $LASTEXITCODE
    if ( $rc -ne 0 ) {
        Write-Host "ERROR: unable to fetch CA certificates with 'caloader'"
        exit $rc
    }
}
else {
    Write-Host "INFO: skipping on-behalf auth cert -- already exists"
}

if (-not (Test-Path "onbehalf")) {
    Write-Host "INFO: creating on-behalf auth cert..."
    $hostname = Get-RandomHexString
    certnanny run enroll -- --keystore onbehalf --variable "FQDN=${hostname}-batch-on-behalf.openxpki.test:pkiclient" --variable "hostname=${hostname}-batch-on-behalf" --secret verysecret
}
else {
    Write-Host "INFO: skipping on-behalf auth cert -- already exists"
}

