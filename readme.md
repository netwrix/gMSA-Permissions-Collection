# gMSA Permissions Collection
gMSA Permissions Collection script by Kevin Joyce

## Description
Looks up permissions within Active Directory on a gMSA to determine access to modify the gMSA attribute (ms-ds-GroupMSAMembership).
Requirements: Active Directory PowerShell module, Domain Administrator privileges (to ensure the capability to get attribute GUIDs and view all permissions on all computer objects)


## Usage
1. Popuplate the $target varbiable with the samaccountname of a gMSA.
2. OPTIONAL: To output the results to a text file run the following .\LAPS_Permissions_Collection.ps1 > output.txt
