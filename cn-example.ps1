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
            $result += @{ "PrivateKey"="$cert" }
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
                $errOutput = $( $output = & openssl genrsa -out $(Expand-ObjectName -Name $params.PrivateKeyName) $params.KeyParam ) 2>&1
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
        $csr = & openssl req -new -key $(Expand-ObjectName -Name $params.PrivateKeyName) -subj $subject $args
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


############################################################
# MAIN - Process API Command
############################################################

Switch -Regex ($Command)
{
    '^Inspect|Attach|GenerateKey|Persist|CreateCertificateRequest|ImportCertificate$'  {& "Do-$Command"; Break}
    Default {
        $err = @{ "Error"="Unsupported API command '$command'" }
        ConvertTo-Json $err
        Exit 1
        Break
    }
}
