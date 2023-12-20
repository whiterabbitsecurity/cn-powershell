# CertNanny Batch Processing with PowerShell

This demo shows how to run CertNanny for multiple CSR files in a spool
directory using PowerShell.

# Preparation

The following are needed for this demonstration:

- a directory (e.g., 'batch-spool') containing the CSR files
- the directory 'trustedroot' containing the CA certificates for the endpoint
  (see "Fetch CA Certificates" in CertNanny-EE-Quickstart.md for details)
- an "on behalf" signing certificate to authenticate the requests to endpoint
- a valid license.lic file (regular or evaluation)
  (see "Enable License" in CertNanny-EE-Quickstart.md for details)
- local config containing the local endpoints, keystore names, etc., as needed (optional)

Run the PowerShell script `setup.ps1` to create the above prerequisites (with the exception of the license file).

# Running the PowerShell Script

Run the PowerShell script `batch.ps1` to process the CSR files in the
spool directory with CertNanny.

On successful enrollment, the new certificates will be saved to the spool
directory. If any requests are pending in the PKI (e.g., manual approval
is required), once the reason is resolved and the certificat has been
issued, the batch script can be run again to collect the remaining 
certificates.
