# cn-example.ps1
#
# CertNanny PowerShell Example keystore implementation
#
# This script demonstrates how variables can be assigned
# and modified in PowerShell. 
#

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
$params = $input | ConvertFrom-Json

############################################################
# Test/Example Commands
############################################################

# This example shows how to add a member to the native object
# returned by ConvertFrom-Json.
function test_1 {
    $params | Add-Member -Type NoteProperty -Name "key2" -Value "value 2"
    ConvertTo-Json -Compress $params
}

# This example shows how to create a new hash map and later add a member
function test_3 {
    $result = @{ "key3"="value 3" }
    $result += @{ "key4"="value 4" }
    ConvertTo-Json -Compress $result
}

# This example shows how to throw an error that is added to the input
# params object for debugging purposes
function test_err {
    $params | Add-Member -Type NoteProperty -Name "Error" -Value "Expected error"
    ConvertTo-Json -Compress $params
    Exit 1
}



############################################################
# MAIN - Process API Command
############################################################

Switch -Regex ($Command)
{
    '^test_.*$'  {& $Command; Break}
    Default {
        $err = @{ "Error"="Unsupported API command '$command'" }
        ConvertTo-Json $err
        Exit 1
        Break
    }
}
