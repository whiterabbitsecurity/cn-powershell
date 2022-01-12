# CertNanny PowerShell Keystore

CertNanny is a tool for decentralized certificate management on servers,
workstations and IoT devices. This single program file takes care of the
automatic initial enrollment, renewal and replacement of the certificate
directly on the device, automating the entire management lifecycle of your
certificates.

In CertNanny, keystore backends are used to perform the underlying operations
on the local keystores available. The PowerShell keystore backend allows
the user or system administrator to write their own backend in a powershell
script that interfaces with CertNanny via a common API commands. This opens
up access to any native keystore that is not directly supported by CertNanny,
but provides some form of executable or library that is available in
PowerShell.

## Notes

Running scripts may need to be enabled on your system for CertNanny to be able to call the PowerShell script.
For more information, see about\_Execution\_Policies at https://go.microsoft.com/fwlink/?linkID=135170.

For example, to allow execution of PowerShell scripts on a test server, start PowerShell as administrator and enter the command:

```
Set-ExecutionPolicy -ExecutionPolicy Unrestricted
```


# API Basics

When an API command is called by CertNanny, the PowerShell script specified
in the CertNanny keystore configuration is executed and the name of the API
command is passed as the first parameter to the script. This can be read into
the `$Command` parameter in PowerShell with the following code:

    Param (
        $Command
    )

See the API Commands below for the supported commands and the expected inputs
and outputs.

Any input data needed in the PowerShell script by the given API command is
supplied by CertNanny on standard input of the PowerShell script in JSON
format. For example, this can be read into the `$params` variable in the script:

    # in PowerShell 7
    $params = $input | ConvertFrom-Json

    # in PowerShell 5
    $params = [Console]::In.ReadToEnd() | CovertFrom-Json


On success, the script returns the resulting data as standard output in JSON
format to CertNanny. On error, the script shall exit with a non-zero
value and may print the error reason as a JSON structure in the format
`{ "Error": "<error message string>" }`.

Here is an example of reading the certificate file and returning
the contents to CertNanny:

    $result = @{}
    $result += @{ "Certificate" = "$cert"

    $cert = Get-Content -Path $params.CertificateName -Raw
    if ( $cert ) {
        $result += @{ "Certificate"="$cert" }
    } else {
        $err = @{ "Error"="Unable to read certificate file" }
        ConvertTo-Json $err
        Exit 1
    }
    ConvertTo-Json $result

The script can implement each of the API commands as a function and then at
the end of the script, the main program block could run the valid commands:

    Switch -Regex ($Command)
    {
        '^Inspect|Attach|GenerateKey|Persist|CreateCertificateRequest$'  {
            & $Command;
            Break
        }
        Default {
            $err = @{ "Error"="Unsupported API command '$command'" }
            ConvertTo-Json $err
            Exit 1
            Break
        }
    }

## Common Input Attributes

The following attributes are used as common input parameters for most of the API commands. Attributes that are relevant for single API Commands are documented below in the "API Commands" section.

### Mutable

The keystore is used as the storage location for an enrollment that is in progress. For renewal, this is typically a clone of an existing keystore with the currently-used certificate. The powershell implementation must honor the Mutable flag and, when set, adjust the location and file/object name attributes as needed to avoid corrupting the existing keystore contents.

### Location

The location may be a file path or identifier to distinguish the location of the keystore (e.g. "C:\openssl\server-a" or "\LocalMachine\My").

### \*Name

The file name or object identifier for the attribute within the given Location (e.g.: "server-cert.pem").


# API Commands

The API Commands currently supported are: Inspect, Attach, GenerateKey, Persist, and
CreateCertificateRequest.

Unless otherwise specified, the input and output of each command is a name-value list of 
attributes.

## Inspect

Inspect the contents of the keystore and indicate whether objects exist.

### Input

The names may refer to either files or objects, depending on how an individual keystore
stores these objects internally.

- Mutable
- Location
- PrivateKeyName
- CertificateName
- ChainName
- CertificateRequestTemplateName
- CertificateRequestName
- TrustAnchorName [reserved]

### Output

Each attribute is assigned a boolean value that indicates whether the given object exists
in the keystore.

- PrivateKeyExists
- CertificateExists
- CertificateRequestTemplateExists
- CertificateRequestExists
- ChainExists
- TrustAnchorExists [reserved]

## Attach

Read the contents of each of the objects into CertNanny. 

When called by CertNanny, the input parameters will contain only the names for the objects that
were found in the call to `Inspect`.

The output may depend on the capabilities of the individual keystore being implemented. For example,
if the keystore itself does the key generation and certificate request signing, there is no need for
the private key to be returned by the script.

### Input

The names may refer to either files or objects, depending on how an individual keystore
stores these objects internally.

- Mutable
- Location
- PrivateKeyName
- CertificateName
- ChainName
- CertificateRequestTemplateName
- CertificateRequestName
- TrustAnchorName [reserved]

### Output

The contents of each object is returned, if available and applicable.

in the keystore.

- PrivateKey
- Certificate
- CertificateRequestTemplate [reserved]
- CertificateRequest
- Chain

## GenerateKey

Generate the private key using the given arguments.

### Input

- Mutable
- Location
- PrivateKeyName
- KeyPin: passphrase for protecting the key file/object
- KeyType: either "rsa" or "ec"
- KeyParam: parameters for key generation, depending on the KeyType:
For rsa, this is the key size.  For ec, this is the named curve (e.g.:
P224, P-224, scep224r1, P256, P-256, prime256v1, scep256r1, 
P384, P384, scep384r1, P521, P-521, scep521r1)

### Output

- PrivateKey: private key in PEM, if exportable from the underlying keystore

## Persist

Write the contents to the target keystore, if needed.

### Input

- Mutable
- Location
- Certificate
- CertificateName
- Chain
- ChainName
- CertificateRequest
- CertificateRequestName
- PrivateKey
- PrivateKeyName

### Output

- _None_

## CreateCertificateRequest

### Input

- Mutable
- Location
- CertificateRequestName: [NOT IMPLEMENTED]
- PrivateKeyName
- KeyPin: passphrase for protecting key file/object
- Subject
- SubjectRDN: raw RDN of subject as array of entities (format may change
in future versions)
- SANS: subject alternative names as array of key-value pairs where the
key is the type (e.g.: DNS, IP, URI, email) and the value is the string
value of that entry

Note: Additional template attributes like IPAddresses, URIs and 
ExtraExtensions are not currently supported.

### Output

- CertificateRequest: contents of the certificate request (PKCS10) as
DER in a string encoded with Base-64

# Debugging With CertNanny

When debugging a PowerShell script, keep in mind that the output of the script must be in a valid JSON structure to be parsed properly by CertNanny.

There are three ways to debug a PowerShell script using CertNanny:

1. Return the needed debugging information in extra attributes in the JSON structure printed to stdout of the PowerShell script. The data structure can then be logged in CertNanny by setting the log level in CertNanny to `debug`.

2. Return error details in the "Error" attribute of the JSON structure printed to stdout of the PowerShell script and exit from the script with a non-zero return code. CertNanny will stop with a fatal error message containing the string in the "Error" attribute.

3. Write the error information to stderr in the PowerShell script and the output will will be logged as a non-fatal error.

# Running Without CertNanny

Since the data exchange consists of JSON structures via standard input and output, 
a PowerShell script may be easily tested without CertNanny itself. Simply pipe
the input parameters to the PowerShell script:

    echo '{"CertificateName":"test-cert.pem","PrivateKeyName":"test-key.pem"}' | \
    pwsh cn-example.ps1 Inspect


