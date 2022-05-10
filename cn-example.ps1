# cn-example.ps1
#
# CertNanny PowerShell Example keystore implementation
#
# This script provides a basic demonstration of how to implement
# a PowerShell-based keystore backend for CertNanny. 
#
# The API Command functions are the functions called to implement
# each of the individual API Commands used by CertNanny.
#
# This example uses openssl as the underlying keystore because of
# the availability of openssl on non-Windows platforms. The goal
# is not to provide a reference implementation from a cryptography
# standpoint, but to merely demonstrate the API between CertNanny
# and the PowerShell subsystem.

# For the CMS demo, a recent version of OpenSSL is needed.
#if (Test-Path -Path "/usr/local/opt/openssl/bin/openssl" -PathType Leaf) {
#Set-Variable -Name "openssl" -Value "/usr/local/opt/openssl/bin/openssl"
#} else {
#    $openssl = "openssl"
#}

############################################################
# Fetch command line arguments and data passed on input
############################################################

# command line arguments
Param (
    $Command    # API Command to be run
)

# $params contains the input parameters from CertNanny that
# is passed as JSON and converted here into a native object
# variable.
$params = [Console]::In.ReadToEnd() | ConvertFrom-Json


############################################################
# Internal helper functions
############################################################

# ParseBool() is used to normalize truth. Anything that is
# not a commonly-accepted representation of a true value is
# assumed to be false. 
function ParseBool{
    [CmdletBinding()]
    param(
    [Parameter(Position=0)]
    [System.String]$inputVal
    )
    switch -regex ($inputVal.Trim())
    {
        "^(1|true|yes|on|enabled)$" { $true }
        default { $false }
    }
}

# Expand-ObjectName() is used to resolve the name of the file or object
# within the keystore. The 'mutable' parameter allows to
# toggle between the keystore itself and a temporary storage
# location used during enrollment while the new certificate
# is incomplete.
function Expand-ObjectName {
    param (
        [Parameter(Mandatory)]
        [string]$Name,
        [ValidateNotNullOrEmpty()]
        [string]$Location = $params.Location,
        [bool]$Mutable = $(ParseBool($params.Mutable)),
        [string]$Suffix = "-spool"
    )

    if ($Mutable) {
        Write-Output $(Join-Path -Path $Location -ChildPath "$Name$Suffix")
    } else {
        Write-Output $(Join-Path -Path $Location -ChildPath $Name)
    }
}

############################################################
# API Commands
############################################################

# Inspect()
#
# GIVEN:
#
#   $params contains the following attributes:
#
#       PrivateKeyName
#       CertificateName
#       ChainName
#       CertificateRequestTemplateName
#       CertificateRequestName
#       TrustAnchorName
#       EnrollmentID
#
# TASK: Inspect the contents of the keystore and indicate whether objects exist
#
# RETURN: JSON representation of the keystore status with the following attributes:
#
#       PrivateKeyExists
#       CertificateExists
#       CertificateRequestTemplateExists
#       CertificateRequestExists
#       ChainExists
#       TrustAnchorExists
#
function Private:Do-Inspect {
    $result = @{}

    if ($params.EnrollmentID) {
        # for unit tests
        $result += @{ "EnrollmentID"=$params.EnrollmentID }
    } else {
        $result += @{ "EnrollmentID"="<unset>" }
    }

    if ($params.PrivateKeyName -And (Test-Path -Path $(Expand-ObjectName -Name $params.PrivateKeyName) -PathType Leaf)) {
        $result += @{ "PrivateKeyExists"=$true }
    } else {
        $result += @{ "PrivateKeyExists"=$false }
    }

    if ($params.CertificateName -And (Test-Path -Path $(Expand-ObjectName -Name $params.CertificateName) -PathType Leaf)) {
        $result += @{"CertificateExists"=$true }
    } else {
        $result += @{"CertificateExists"=$false }
    }

    if ($params.CertificateRequestTemplateName -And (Test-Path -Path $(Expand-ObjectName -Name $params.CertificateRequestTemplateName) -PathType Leaf)) {
        $result += @{"CertificateRequestTemplateExists"=$true }
    } else {
        $result += @{"CertificateRequestTemplateExists"=$false }
    }

    if ($params.CertificateRequestName -And (Test-Path -Path $(Expand-ObjectName -Name $params.CertificateRequestName) -PathType Leaf)) {
        $result += @{"CertificateRequestExists"=$true }
    } else {
        $result += @{"CertificateRequestExists"=$false }
    }

    if ($params.ChainName -And (Test-Path -Path $(Expand-ObjectName -Name $params.ChainName) -PathType Leaf)) {
        $result += @{"ChainExists"=$true }
    } else {
        $result += @{"ChainExists"=$false }
    }

    if ($params.TrustAnchorsName -And (Test-Path -Path $(Expand-ObjectName -Name $params.TrustAnchorsName) -PathType Leaf)) {
        $result += @{"TrustAnchorsExists"=$true }
    } else {
        $result += @{"TrustAnchorsExists"=$false }
    }

    ConvertTo-Json $result
}

# Attach()
#
# GIVEN:
#
#   $params contains the following attributes:
#
#       PrivateKeyExists
#       PrivateKeyName (if PrivateKeyExists is true)
#       CertificateExists
#       CertificateName (if CertificateExists is true)
#       ChainExists
#       ChainName (if ChainExists is true)
#       CertificateRequestTemplateName
#       CertificateRequestName
#       TrustAnchorName
#       EnrollmentID
#
#   A missing value shall be interpreted as false or an empty string.
#
# TASK: For items that are flagged as Exists, read the contents of the
# corresponding file or object.
#
# NOTE: For testing CMS with OpenSSL, set the environment variable CNPS_FORCE_CMS=1.
#
# RETURN:
#
#   The output JSON contains the following attributes:
#
#       PrivateKey  - Private key in PEM, if exportable
#       Certificate - Certificate in PEM
#       Chain       - Certificate chain in PEM
#
function Private:Do-Attach {
    $result = @{}

    if ($params.PrivateKeyExists -And $params.PrivateKeyName -And (Test-Path -Path $(Expand-ObjectName -Name $params.PrivateKeyName) -PathType Leaf)) {
        $cert = Get-Content -Path $(Expand-ObjectName -Name $params.PrivateKeyName) -Raw
        if ( $cert ) {
            if ( $env:CNPS_FORCE_CMS -eq "1" ) {
                $result += @{ "debug_PrivateKey"="Not set - CNPS_FORCE_CMS=1" }
            } else {
                $result += @{ "PrivateKey"="$cert" }
            }
        } else {
            $err = @{ "Error"="Unable to read private key file" }
            ConvertTo-Json $err
            Exit 1
        }
    }

    if ($params.CertificateExists -And $params.CertificateName -And (Test-Path -Path $(Expand-ObjectName -Name $params.CertificateName) -PathType Leaf)) {
        $cert = Get-Content -Path $(Expand-ObjectName -Name $params.CertificateName) -Raw
        if ( $cert ) {
            $result += @{ "Certificate"="$cert" }
        } else {
            $err = @{ "Error"="Unable to read certificate file" }
            ConvertTo-Json $err
            Exit 1
        }
    }

    if ($params.ChainExists -And $params.ChainName -And (Test-Path -Path $(Expand-ObjectName -Name $params.ChainName) -PathType Leaf)) {
        $cert = Get-Content -Path $(Expand-ObjectName -Name $params.ChainName) -Raw
        if ( $cert ) {
            $result += @{ "Chain"="$cert" }
        } else {
            $err = @{ "Error"="Unable to read chain file" }
            ConvertTo-Json $err
            Exit 1
        }
    }

    if ($params.CertificateRequestExists -And $params.CertificateRequestName -And (Test-Path -Path $(Expand-ObjectName -Name $params.CertificateRequestName) -PathType Leaf)) {
        $csr = Get-Content -Path $(Expand-ObjectName -Name $params.CertificateRequestName) -Raw
        if ( $csr ) {
            $result += @{ "CertificateRequest"="$csr" }
        } else {
            $err = @{ "Error"="Unable to read Certificate Request file" }
            ConvertTo-Json $err
            Exit 1
        }
    }

    ConvertTo-Json $result
}

# GenerateKey()
#
# GIVEN:
#
#   $params contains the following attributes:
#
#       PrivateKeyName
#       KeyPin          passphrase for protecting key file/object
#       KeyType         (e.g. "rsa", "ec")
#       KeyParam        depends on keytype:
#                       - rsa: keysize
#                       - ec: named curve (e.g.:
#                               P224, P-224, scep224r1, 
#                               P256, P-256, prime256v1, scep256r1, 
#                               P384, P384, scep384r1,
#                               P521, P-521, scep521r1)
#       EnrollmentID
#
# TASK:
#
#   Generate the private key using the given arguments.
#
# !!!! IMPORTANT !!!!
#
# The purpose of this DEMO script is to demonstrate how CertNanny
# integrates with Powershell and is not intended as a "safe" example
# for how to generate a secure private key.
#
# YOU MUST ADAPT THIS TO YOUR OWN SECURITY REQUIREMENTS !!!
#
# RETURN:
#
#   The output JSON contains the following attributes:
#
#       PrivateKey  - Private key in PEM, if exportable
#
function Private:Do-GenerateKey {
    $result = @{}

    if ( -Not $params.PrivateKeyName ) {
        $err = @{ "Error"="GenerateKey requires PrivateKeyName" }
        ConvertTo-Json $err
        Exit 1
    }
    $datadir = Split-Path "$(Expand-ObjectName -Name $params.PrivateKeyName)"
    if ( -Not (Test-Path -Path $datadir )) {
        try {
            New-Item -Path $datadir -ItemType directory
        } catch {
            $err = @{ "Error"="Error creating folder ${datadir}: $PSItem" }
            ConvertTo-Json $err
            Exit 1
        }
    }
    Switch ($params.KeyType) {
        'rsa' {
            if ($params.KeyParam) {
                $errOutput = $( $output = & /usr/local/opt/openssl/bin/openssl genrsa -out $(Expand-ObjectName -Name $params.PrivateKeyName) $params.KeyParam ) 2>&1
                #Write-Error "Output from genrsa: $errOutput"
                if ($LastExitCode -eq 0) {
                    $key = Get-Content -Path $(Expand-ObjectName -Name $params.PrivateKeyName) -Raw
                    if ( $key ) {
                        $result += @{ "PrivateKey"="$key" }
                        $result += @{ "StdOut"="$output" }
                        $result += @{ "StdErr"="$errOutput" }
                    } else {
                        $err = @{ "Error"="Unable to read private key file: $errOutput" }
                        ConvertTo-Json $err
                        Exit 1
                    }
                } else {
                    $err = @{ "Error"="openssl genrsa failed ($LastExitCode): $errOutput" }
                    ConvertTo-Json $err
                    Exit 1
                } 
            } else {
                $err = @{ "Error"="KeyParam for KeyType=rsa missing" }
                ConvertTo-Json $err
                    Exit 1
            }
        }
        Default {
            $err = @{ "Error"="Unsupported KeyType '"+$params.KeyType+"'" }
            ConvertTo-Json $err
                Exit 1
                Break
        }

    }
    ConvertTo-Json $result
}


# Persist()
#
# GIVEN:
#
#   $params contains the following attributes:
#
#       Certificate
#       CertificateName
#       Chain
#       ChainName
#       CertificateRequest
#       CertificateRequestName
#       PrivateKey
#       PrivateKeyName
#       EnrollmentID
#
# TASK:
#
#   Write contents to target keystore, if needed.
#
#   This iterates through each object type (i.e. Certificate, Chain, etc.) and
#   if the filename and contents were passed as arguments and the file itself
#   does not already exist, the contents are written to the file system.
#
# RETURN:
#
#   None.
#
function Private:Do-Persist {
    $keys = @( "Certificate", "Chain", "CertificateRequest", "PrivateKey" )

    For ($i=0; $i -lt $keys.Length; $i++) {
        $label = $keys[$i]
        $namekey = $label + "Name"

        $shortfilename = $params.$namekey
        #Write-Error "Persist() label=$label, namekey=$namekey, shortfilename=$shortfilename, params=$params"

        if (-not [string]::IsNullOrEmpty($shortfilename)) {
            $filename = $(Expand-ObjectName -Name $shortfilename)
                $contents = $params.$label

                if ($contents -And $filename) {
                    if (-Not (Test-Path -Path $filename -PathType Leaf)) {
                        try {
                            Out-File -FilePath $filename -InputObject $contents -NoNewLine
                        } catch {
                            $err = @{ "Error"="Error writing ${label}: $PSItem" }
                            ConvertTo-Json $err
                                Exit 1
                        } 
                    }
                }
        }
    }
}

# CreateCertificateRequest()
#
# GIVEN:
#
#   $params contains the following attributes:
#
#       CertificateRequestName [NOT IMPLEMENTED]
#       PrivateKeyName
#       KeyPin          passphrase for protecting key file/object
#       Subject
#       SubjectRDN      Raw RDN of subject as array of entities
#                       (format may change in future versions)
#       SANS            Subject alternative names as array of key-
#                       value pairs where the key is the type
#                       (e.g.: DNS, IP, URI, email) and the value
#                       is the string value of that entry
#       EnrollmentID
#
#   Note: Additional template attributes like IPAddresses, URIs and 
#   ExtraExtensions are not currently supported.
#
# TASK:
#
#   Write contents to target keystore, if needed
#
# RETURN:
#
#   The output JSON contains the following attributes:
#
#       CertificateRequest  - Contents of the certificate request (PKCS10) as
#                             DER in a string encoded with Base-64
#
#
function Private:Do-CreateCertificateRequest {
    $result = @{}
    #$required_params = @( "PrivateKeyName", "Subject", "CertificateRequestName" )
    $required_params = @( "PrivateKeyName", "Subject" )

    For ($i=0; $i -lt $required_params.Length; $i++) {
        $key = $required_params[$i]
        if ( -Not $params.$key ) {
            $err = @{ "Error"="CreateCertificateRequest requires $key" }
            ConvertTo-Json $err
                Exit 1
        }
    }

    $args = @()

    if ( $params.KeyPin ) {
        $pin = $params.KeyPin
        $args += '-passin', "pass:$pin"
    }

    # Optimized for programmer efficiency and simplicity
    $subjArray = $params.Subject.Split(",")
    $subject = "/" + $($subjArray -join "/")

    try {
        $csr = & /usr/local/opt/openssl/bin/openssl req -new -key $(Expand-ObjectName -Name $params.PrivateKeyName) -subj $subject $args
        $csr = [string]::join("",$($csr | Select-String -Pattern '-----(BEGIN|END) CERTIFICATE REQUEST---' -NotMatch))
    } catch {
        $err = @{ "Error"="Error creating csr: $PSItem" }
        ConvertTo-Json $err
        Exit 1
    }

    if ( $csr ) {
        $result += @{ "CertificateRequest"="$csr" }
    } else {
        $err = @{ "Error"="Unable to read certificate request file" }
        $err += @{ "PrivateKeyName"=$(Expand-ObjectName -Name $params.PrivateKeyName) }
        $err += @{ "CertificateRequestName"=$(Expand-ObjectName -Name $params.CertificateRequestName) }
        $err += @{ "Subject"="$($params.Subject)" }
        $err += @{ "Params"=$params }
        ConvertTo-Json $err
            Exit 1
    }

    ConvertTo-Json $result
}

# ImportCertificate()
#
# GIVEN:
#
#   $params contains the following attributes:
#
#       CertificateName
#       ChainName
#       PrivateKeyName
#       EnrollmentID
#
# TASK:
#
#   Move newly-created certificate to target location in keystore
#
# RETURN:
#
#   The output JSON contains the following attributes:
#
#       <empty on success>
#
#
function Private:Do-ImportCertificate {
    $result = @{}
    $required_params = @( "CertificateName", "ChainName", "PrivateKeyName" )

    For ($i=0; $i -lt $required_params.Length; $i++) {
        $key = $required_params[$i]
        if ( -Not $params.$key ) {
            $err = @{ "Error"="ImportCertificate requires $key" }
            ConvertTo-Json $err
                Exit 1
        }
    }

    if ($params.PrivateKeyName -And (Test-Path -Path $(Expand-ObjectName -Name $params.PrivateKeyName -Mutable $true) -PathType Leaf)) {
         Move-Item -Path $(Expand-ObjectName -Name $params.PrivateKeyName -Mutable $true) -Destination $(Expand-ObjectName -Name $params.PrivateKeyName -Mutable $false)
    }

    if ($params.CertificateName -And (Test-Path -Path $(Expand-ObjectName -Name $params.CertificateName -Mutable $true) -PathType Leaf)) {
         Move-Item -Path $(Expand-ObjectName -Name $params.CertificateName -Mutable $true) -Destination $(Expand-ObjectName -Name $params.CertificateName -Mutable $false)
    }

    if ($params.ChainName -And (Test-Path -Path $(Expand-ObjectName -Name $params.ChainName -Mutable $true) -PathType Leaf)) {
         Move-Item -Path $(Expand-ObjectName -Name $params.ChainName -Mutable $true) -Destination $(Expand-ObjectName -Name $params.ChainName -Mutable $false)
    }
}

# CreateCMS()
#
# GIVEN:
#
#   $params contains the following attributes:
#
#       CertificateRequest  PKCS#10 CSR in PEM format
#       CertificateName     Name of certificate file/object to use for signing
#       PrivateKeyName      Name of private key file/object to use for signing
#       KeyPin          passphrase for protecting key file/object
#       EnrollmentID
#
# TASK:
#
#   Write contents to target keystore, if needed
#
# RETURN:
#
#   The output JSON contains the following attributes:
#
#       CMS  - Contents of the CMS in PKCS#7 format
#
#
function Private:Do-CreateCMS {
    $result = @{}
    $required_params = @( "PrivateKeyName", "CertificateRequest", "CertificateName" )

    For ($i=0; $i -lt $required_params.Length; $i++) {
        $key = $required_params[$i]
        if ( -Not $params.$key ) {
            $err = @{ "Error"="CreateCMS requires $key" }
            ConvertTo-Json $err
                Exit 1
        }
    }

    $args = @()

    if ( $params.KeyPin ) {
        $pin = $params.KeyPin
        $args += '-passin', "pass:$pin"
    }

    $pk = $(Expand-ObjectName -Name $params.PrivateKeyName)
    $crt = $(Expand-ObjectName -Name $params.CertificateName)
    $csr = $params.CertificateRequest

    # I'm a PS n00b, and instead of figuring out how to do the conversion below in a pipeline,
    # I use these temporary files and separate calls to openssl.
    $csrfile = "$($params.Location)/ps-csr.pem"
    $csrbinfile = "$($params.Location)/ps-csr.bin"
    $cmsfile = "$($params.Location)/ps-cms.pem"

    $csr > $csrfile

    try {
        & /usr/local/opt/openssl/bin/openssl enc -d -base64 -in $csrfile -out $csrbinfile
        & /usr/local/opt/openssl/bin/openssl cms -outform pem -sign -binary -nodetach -signer $crt -inkey $pk -in $csrbinfile -out $cmsfile
        $cms = Get-Content -Raw $cmsfile
    } catch {
        $err = @{ "Error"="Error creating cms: $PSItem" }
        ConvertTo-Json $err
        Exit 1
    }

    if ( $cms ) {
        $result += @{ "CMS"="$cms" }
    } else {
        $err = @{ "Error"="Unable to read CMS" }
        $err += @{ "PrivateKeyName"=$pk }
        $err += @{ "CertificateName"=$crt }
        $err += @{ "Params"=$params }
        ConvertTo-Json $err
        Exit 1
    }

    ConvertTo-Json $result
}


# GetTruststore()
#
# GIVEN:
#
#   $params contains the following attributes:
#
#       EnrollmentID
#
# TASK:
#
#   Return PEM string containing certificates to be trusted internally by CertNanny itself
#
# RETURN:
#
#   The output JSON contains the following attributes:
#
#       TrustedCertificates  - string of trusted certificates in PEM format
#
#
function Private:Do-GetTruststore {
    $result = @{}

    # These are the trust roots for the OpenXPKI Demo 
    $result += @{ "TrustedCertificates"="      -----BEGIN CERTIFICATE-----
MIIFKzCCAxOgAwIBAgIJAL22je1NVEGzMA0GCSqGSIb3DQEBCwUAMCQxIjAgBgNV
BAMMGU9wZW5YUEtJIENBLU9uZSBSb290IENBIDEwHhcNMTgwMzMxMDcyNjQxWhcN
MjgwNDAyMDcyNjQxWjAkMSIwIAYDVQQDDBlPcGVuWFBLSSBDQS1PbmUgUm9vdCBD
QSAxMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA6BEvDCHHaMs8eC46
0Vq5R6KQoUWV9Z8xr6R3MXhIidZvMouquKhgPL7CPDRvxIpCVGK5W14e5556L5oy
wryFWOoEM6B4cHbCvxsMFkHKGeBORqGs6BCJeV/jaJpFuMY5QJ39QCvgAVrrJdt4
slS9TdHlra0Ke7PCxAz6UUaPpCDQgGRVI7tAGk7I/+Pz79rqPCoJBsTCvWpTIZK1
9Jo4pjb+KPmxmaw0F0wN1Vob/SI++3KvdeLIDjygIOguIZHkFn9qmd6vysqvYGU8
0ZbkLpuVUX2n0LObkjOXglQ82WTiIX9Nvi/DNvkeTLfVfDD1S4knW6G7eyr/tRn5
bVyW3YWig+6+V0IErwSsqaiOZULXxsjnVmmH5eZz9DOOTyWsJswLyE4ywJr8O8YP
86q+tUkK0sNDnpJ0JPhboPpXRdsiDakw77DO/2J7yFLRC1NvALdOO95JqEiTOnqo
oSBGQa5L0DvXknPP1KllU4ZZHXsnW/YaJ0ZH7WIIi2qTaK2iVbkXTwdsJSqWdEeh
riGYli/I52sq8Qem8hyZaEd3cDOn55tOu6Hd1vDzMsGHEgdbCneqiLz8pZVTRIPn
kvBXyBaX5PE0qfEMgfjVogrpEZW7/bYL0EMbRaEvMbJz/rym61vxsnaNJbJyMLVO
JAmzYASNBO8N1mZnlyzA0hklRxcCAwEAAaNgMF4wHQYDVR0OBBYEFC+0yPvg/U1C
2eTVw2WThhx55WNoMAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1Ud
IwQYMBaAFC+0yPvg/U1C2eTVw2WThhx55WNoMA0GCSqGSIb3DQEBCwUAA4ICAQBz
e1o5TMaTa/qrAa98lrZafg21Sa+x94wDkqEubXhSTAifNEMbwxJBgLKzpZi8Voor
yzDHBOHn2NtnB7VnD1k5jYoJqdMRtdiROCB1Ag/MOJ8Ab4eSHQfOIRSL/3n9RS9W
Ag9RoPD+MCmz0dcsydssRqGoKXkJfvsEUJSnw/oHS/qzRWbZKB1xY3tbnkR+wbz5
ThDhSnaex5P/s4VrnaCBWySHP5KGIRkh8Y1z9ZeRaVNAUZ+o44M7evMN86Hj6vct
4iMEPZxA8RKTP2n8T68PgSJBhYb3hfHKCBN7OleYIy2DKnIZ8Y3wNJU/FZUpogLf
GvXEZCWQlL/L3L2mBhAQpk9vwKG83CX7PyaYkoO7MoDZqrve+d+u+ppc1O4gtLTc
5vANdErdNDmgUHO693dPR28y39agJalMebPuUcgJGjuGbTXNGX3saY6upZaGZz63
e6FnmcAkRLBaydqvBcgOYJtpEcW4uKMWmbspv5hg7U3EM+3E/bQulL8dbxFgEDAE
qtV+KgGzyQPFnYRZTn22Y52mqIntNZU/attgTLnc4UvWlp+sG+lLtaAWIQTZJUZ+
/RZzBYJLk2t64sLbGQ6rbWTW0KbcOkFkDeA70SHF2Rm13dEhSDA9qpq5cyPdmdT/
92/nxKlzLvr+8UypbjuEOD/AqUdjQa42BTC7t9rVcQ==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4
WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJu
ZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBY
MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygc
h77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+
0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6U
A5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sW
T8KOEUt+zwvo/7V3LvSye0rgTBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyH
B5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UC
B5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUv
KBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWn
OlFuhjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTn
jh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbw
qHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CI
rU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNV
HRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbjANBgkq
hkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZL
ubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ
3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KK
NFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5
ORAzI4JMPJ+GslWYHb4phowim57iaztXOoJwTdwJx4nLCgdNbOhdjsnvzqvHu7Ur
TkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdC
jNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVc
oyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq
4RgqsahDYVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPA
mRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57d
emyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIFFjCCAv6gAwIBAgIRAJErCErPDBinU/bWLiWnX1owDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMjAwOTA0MDAwMDAw
WhcNMjUwOTE1MTYwMDAwWjAyMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNTGV0J3Mg
RW5jcnlwdDELMAkGA1UEAxMCUjMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQC7AhUozPaglNMPEuyNVZLD+ILxmaZ6QoinXSaqtSu5xUyxr45r+XXIo9cP
R5QUVTVXjJ6oojkZ9YI8QqlObvU7wy7bjcCwXPNZOOftz2nwWgsbvsCUJCWH+jdx
sxPnHKzhm+/b5DtFUkWWqcFTzjTIUu61ru2P3mBw4qVUq7ZtDpelQDRrK9O8Zutm
NHz6a4uPVymZ+DAXXbpyb/uBxa3Shlg9F8fnCbvxK/eG3MHacV3URuPMrSXBiLxg
Z3Vms/EY96Jc5lP/Ooi2R6X/ExjqmAl3P51T+c8B5fWmcBcUr2Ok/5mzk53cU6cG
/kiFHaFpriV1uxPMUgP17VGhi9sVAgMBAAGjggEIMIIBBDAOBgNVHQ8BAf8EBAMC
AYYwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMBIGA1UdEwEB/wQIMAYB
Af8CAQAwHQYDVR0OBBYEFBQusxe3WFbLrlAJQOYfr52LFMLGMB8GA1UdIwQYMBaA
FHm0WeZ7tuXkAXOACIjIGlj26ZtuMDIGCCsGAQUFBwEBBCYwJDAiBggrBgEFBQcw
AoYWaHR0cDovL3gxLmkubGVuY3Iub3JnLzAnBgNVHR8EIDAeMBygGqAYhhZodHRw
Oi8veDEuYy5sZW5jci5vcmcvMCIGA1UdIAQbMBkwCAYGZ4EMAQIBMA0GCysGAQQB
gt8TAQEBMA0GCSqGSIb3DQEBCwUAA4ICAQCFyk5HPqP3hUSFvNVneLKYY611TR6W
PTNlclQtgaDqw+34IL9fzLdwALduO/ZelN7kIJ+m74uyA+eitRY8kc607TkC53wl
ikfmZW4/RvTZ8M6UK+5UzhK8jCdLuMGYL6KvzXGRSgi3yLgjewQtCPkIVz6D2QQz
CkcheAmCJ8MqyJu5zlzyZMjAvnnAT45tRAxekrsu94sQ4egdRCnbWSDtY7kh+BIm
lJNXoB1lBMEKIq4QDUOXoRgffuDghje1WrG9ML+Hbisq/yFOGwXD9RiX8F6sw6W4
avAuvDszue5L3sz85K+EC4Y/wFVDNvZo4TYXao6Z0f+lQKc0t8DQYzk1OXVu8rp2
yJMC6alLbBfODALZvYH7n7do1AZls4I9d1P4jnkDrQoxB3UqQ9hVl3LEKQ73xF1O
yK5GhDDX8oVfGKF5u+decIsH4YaTw7mP3GFxJSqv3+0lUFJoi5Lc5da149p90Ids
hCExroL1+7mryIkXPeFM5TgO9r0rvZaBFOvV2z0gp35Z0+L4WPlbuEjN/lxPFin+
HlUjr8gRsI3qfJOQFy/9rKIJR0Y/8Omwt/8oTWgy1mdeHmmjk7j1nYsvC9JSQ6Zv
MldlTTKB3zhThV1+XWYp6rjd5JW1zbVWEkLNxE7GJThEUG3szgBVGP7pSWTUTsqX
nLRbwHOoq7hHwg==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIFFjCCAv6gAwIBAgIRAIp5IlCr5SxSbO7Pf8lC3WIwDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMjAwOTA0MDAwMDAw
WhcNMjUwOTE1MTYwMDAwWjAyMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNTGV0J3Mg
RW5jcnlwdDELMAkGA1UEAxMCUjQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQCzKNx3KdPnkb7ztwoAx/vyVQslImNTNq/pCCDfDa8oPs3Gq1e2naQlGaXS
Mm1Jpgi5xy+hm5PFIEBrhDEgoo4wYCVg79kaiT8faXGy2uo/c0HEkG9m/X2eWNh3
z81ZdUTJoQp7nz8bDjpmb7Z1z4vLr53AcMX/0oIKr13N4uichZSk5gA16H5OOYHH
IYlgd+odlvKLg3tHxG0ywFJ+Ix5FtXHuo+8XwgOpk4nd9Z/buvHa4H6Xh3GBHhqC
VuQ+fBiiCOUWX6j6qOBIUU0YFKAMo+W2yrO1VRJrcsdafzuM+efZ0Y4STTMzAyrx
E+FCPMIuWWAubeAHRzNl39Jnyk2FAgMBAAGjggEIMIIBBDAOBgNVHQ8BAf8EBAMC
AYYwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMBIGA1UdEwEB/wQIMAYB
Af8CAQAwHQYDVR0OBBYEFDadPuCxQPYnLHy/jZ0xivZUpkYmMB8GA1UdIwQYMBaA
FHm0WeZ7tuXkAXOACIjIGlj26ZtuMDIGCCsGAQUFBwEBBCYwJDAiBggrBgEFBQcw
AoYWaHR0cDovL3gxLmkubGVuY3Iub3JnLzAnBgNVHR8EIDAeMBygGqAYhhZodHRw
Oi8veDEuYy5sZW5jci5vcmcvMCIGA1UdIAQbMBkwCAYGZ4EMAQIBMA0GCysGAQQB
gt8TAQEBMA0GCSqGSIb3DQEBCwUAA4ICAQCJbu5CalWO+H+Az0lmIG14DXmlYHQE
k26umjuCyioWs2icOlZznPTcZvbfq02YPHGTCu3ctggVDULJ+fwOxKekzIqeyLNk
p8dyFwSAr23DYBIVeXDpxHhShvv0MLJzqqDFBTHYe1X5X2Y7oogy+UDJxV2N24/g
Z8lxG4Vr2/VEfUOrw4Tosl5Z+1uzOdvTyBcxD/E5rGgTLczmulctHy3IMTmdTFr0
FnU0/HMQoquWQuODhFqzMqNcsdbjANUBwOEQrKI8Sy6+b84kHP7PtO+S4Ik8R2k7
ZeMlE1JmxBi/PZU860YlwT8/qOYToCHVyDjhv8qutbf2QnUl3SV86th2I1QQE14s
0y7CdAHcHkw3sAEeYGkwCA74MO+VFtnYbf9B2JBOhyyWb5087rGzitu5MTAW41X9
DwTeXEg+a24tAeht+Y1MionHUwa4j7FB/trN3Fnb/r90+4P66ZETVIEcjseUSMHO
w6yqv10/H/dw/8r2EDUincBBX3o9DL3SadqragkKy96HtMiLcqMMGAPm0gti1b6f
bnvOdr0mrIVIKX5nzOeGZORaYLoSD4C8qvFT7U+Um6DMo36cVDNsPmkF575/s3C2
CxGiCPQqVxPgfNSh+2CPd2Xv04lNeuw6gG89DlOhHuoFKRlmPnom+gwqhz3ZXMfz
TfmvjrBokzCICA==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIEYDCCAkigAwIBAgIQB55JKIY3b9QISMI/xjHkYzANBgkqhkiG9w0BAQsFADBP
MQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJuZXQgU2VjdXJpdHkgUmVzZWFy
Y2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBYMTAeFw0yMDA5MDQwMDAwMDBa
Fw0yNTA5MTUxNjAwMDBaME8xCzAJBgNVBAYTAlVTMSkwJwYDVQQKEyBJbnRlcm5l
dCBTZWN1cml0eSBSZXNlYXJjaCBHcm91cDEVMBMGA1UEAxMMSVNSRyBSb290IFgy
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEzZvVn4CDCuwJSvMWSj5cz3es3mcFDR0H
ttwW+1qLFNvicWDEukWVEYmO6gbf9yoWHKS5xcUy4APgHoIYOIvXRdgKam7mAHf7
AlF9ItgKbppbd9/w+kHsOdx1ymgHDB/qo4HlMIHiMA4GA1UdDwEB/wQEAwIBBjAP
BgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBR8Qpau3ktIO/qS+J6Mz22LqXI3lTAf
BgNVHSMEGDAWgBR5tFnme7bl5AFzgAiIyBpY9umbbjAyBggrBgEFBQcBAQQmMCQw
IgYIKwYBBQUHMAKGFmh0dHA6Ly94MS5pLmxlbmNyLm9yZy8wJwYDVR0fBCAwHjAc
oBqgGIYWaHR0cDovL3gxLmMubGVuY3Iub3JnLzAiBgNVHSAEGzAZMAgGBmeBDAEC
ATANBgsrBgEEAYLfEwEBATANBgkqhkiG9w0BAQsFAAOCAgEAG38lK5B6CHYAdxjh
wy6KNkxBfr8XS+Mw11sMfpyWmG97sGjAJETM4vL80erb0p8B+RdNDJ1V/aWtbdIv
P0tywC6uc8clFlfCPhWt4DHRCoSEbGJ4QjEiRhrtekC/lxaBRHfKbHtdIVwH8hGR
Ib/hL8Lvbv0FIOS093nzLbs3KvDGsaysUfUfs1oeZs5YBxg4f3GpPIO617yCnpp2
D56wKf3L84kHSBv+q5MuFCENX6+Ot1SrXQ7UW0xx0JLqPaM2m3wf4DtVudhTU8yD
ZrtK3IEGABiL9LPXSLETQbnEtp7PLHeOQiALgH6fxatI27xvBI1sRikCDXCKHfES
c7ZGJEKeKhcY46zHmMJyzG0tdm3dLCsmlqXPIQgb5dovy++fc5Ou+DZfR4+XKM6r
4pgmmIv97igyIintTJUJxCD6B+GGLET2gUfA5GIy7R3YPEiIlsNekbave1mk7uOG
nMeIWMooKmZVm4WAuR3YQCvJHBM8qevemcIWQPb1pK4qJWxSuscETLQyu/w4XKAM
YXtX7HdOUM+vBqIPN4zhDtLTLxq9nHE+zOH40aijvQT2GcD5hq/1DhqqlWvvykdx
S2McTZbbVSMKnQ+BdaDmQPVkRgNuzvpqfQbspDQGdNpT2Lm4xiN9qfgqLaSCpi4t
EcrmzTFYeYXmchynn9NM0GbQp7s=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIICxjCCAk2gAwIBAgIRALO93/inhFu86QOgQTWzSkUwCgYIKoZIzj0EAwMwTzEL
MAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2VhcmNo
IEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDIwHhcNMjAwOTA0MDAwMDAwWhcN
MjUwOTE1MTYwMDAwWjAyMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNTGV0J3MgRW5j
cnlwdDELMAkGA1UEAxMCRTEwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAQkXC2iKv0c
S6Zdl3MnMayyoGli72XoprDwrEuf/xwLcA/TmC9N/A8AmzfwdAVXMpcuBe8qQyWj
+240JxP2T35p0wKZXuskR5LBJJvmsSGPwSSB/GjMH2m6WPUZIvd0xhajggEIMIIB
BDAOBgNVHQ8BAf8EBAMCAYYwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMB
MBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFFrz7Sv8NsI3eblSMOpUb89V
yy6sMB8GA1UdIwQYMBaAFHxClq7eS0g7+pL4nozPbYupcjeVMDIGCCsGAQUFBwEB
BCYwJDAiBggrBgEFBQcwAoYWaHR0cDovL3gyLmkubGVuY3Iub3JnLzAnBgNVHR8E
IDAeMBygGqAYhhZodHRwOi8veDIuYy5sZW5jci5vcmcvMCIGA1UdIAQbMBkwCAYG
Z4EMAQIBMA0GCysGAQQBgt8TAQEBMAoGCCqGSM49BAMDA2cAMGQCMHt01VITjWH+
Dbo/AwCd89eYhNlXLr3pD5xcSAQh8suzYHKOl9YST8pE9kLJ03uGqQIwWrGxtO3q
YJkgsTgDyj2gJrjubi1K9sZmHzOa25JK1fUpE8ZwYii6I4zPPS/Lgul/
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIICxjCCAkygAwIBAgIQTtI99q9+x/mwxHJv+VEqdzAKBggqhkjOPQQDAzBPMQsw
CQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJuZXQgU2VjdXJpdHkgUmVzZWFyY2gg
R3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBYMjAeFw0yMDA5MDQwMDAwMDBaFw0y
NTA5MTUxNjAwMDBaMDIxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNy
eXB0MQswCQYDVQQDEwJFMjB2MBAGByqGSM49AgEGBSuBBAAiA2IABCOaLO3lixmN
YVWex+ZVYOiTLgi0SgNWtU4hufk50VU4Zp/LbBVDxCsnsI7vuf4xp4Cu+ETNggGE
yBqJ3j8iUwe5Yt/qfSrRf1/D5R58duaJ+IvLRXeASRqEL+VkDXrW3qOCAQgwggEE
MA4GA1UdDwEB/wQEAwIBhjAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEw
EgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUbZkq9U0C6+MRwWC6km+NPS7x
6kQwHwYDVR0jBBgwFoAUfEKWrt5LSDv6kviejM9ti6lyN5UwMgYIKwYBBQUHAQEE
JjAkMCIGCCsGAQUFBzAChhZodHRwOi8veDIuaS5sZW5jci5vcmcvMCcGA1UdHwQg
MB4wHKAaoBiGFmh0dHA6Ly94Mi5jLmxlbmNyLm9yZy8wIgYDVR0gBBswGTAIBgZn
gQwBAgEwDQYLKwYBBAGC3xMBAQEwCgYIKoZIzj0EAwMDaAAwZQIxAPJCN9qpyDmZ
tX8K3m8UYQvK51BrXclM6WfrdeZlUBKyhTXUmFAtJw4X6A0x9mQFPAIwJa/No+KQ
UAM1u34E36neL/Zba7ombkIOchSgx1iVxzqtFWGddgoG+tppRPWhuhhn
-----END CERTIFICATE-----" }

    ConvertTo-Json $result
}


############################################################
# MAIN - Process API Command
############################################################

Switch -Regex ($Command)
{
    '^Inspect|Attach|GenerateKey|Persist|CreateCertificateRequest|ImportCertificate|GetTruststore|CreateCMS$'  {& "Do-$Command"; Break}
    Default {
        $err = @{ "Error"="Unsupported API command '$command'" }
        ConvertTo-Json $err
        Exit 1
        Break
    }
}
