<#
Author: Kevin Joyce
Requirements: Active Directory PowerShell module, Domain Administrator privileges (to ensure the capability to get attribute GUIDs and view all permissions on all gMSA objects)
Description: Looks up permissions within Active Directory on a gMSA to determine access to modify the gMSA attribute (ms-ds-GroupMSAMembership).
Usage: opuplate the $target varbiable with the samaccountname of a gMSA.
To output the results to a text file run the following .\gMSA_Permissions_Collection.ps1 > output.txt
#>
Import-Module ActiveDirectory
##Get the GUID of the extended attribute ms-ds-GroupMSAMembership from Schema
$schemaIDGUID = @{}
Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext -LDAPFilter '(name=ms-ds-GroupMSAMembership)' -Properties name, schemaIDGUID |
ForEach-Object {$schemaIDGUID.add([System.GUID]$_.schemaIDGUID,$_.name)}

<# **REPLACE DN VARIABLE BELOW**
Declare the samaccountname of the gMSA to search for#>
$target = 'gmsa'

##Get distinguished name of all gMSAs objects from the OU
$gMSAs = Get-ADServiceAccount -identity $target 


<#Get objects that have specific permissions on the target(s): 
Full Control(GenericAll) 
Write all Properties (WriteProperty where ObjectType = 00000000-0000-0000-0000-000000000000  
#>
Set-Location ad:
foreach ($gmsa in $gMSAs){
(Get-Acl $gmsa.distinguishedname).access | 
Where-Object { (($_.AccessControlType -eq 'Allow') -and ($_.activedirectoryrights -in ('GenericAll') -and $_.inheritancetype -in ('All', 'None')) -or (($_.activedirectoryrights -like '*WriteProperty*') -and ($_.objecttype -eq '00000000-0000-0000-0000-000000000000')))} |
 ft ([string]$gmsa.name),identityreference, activedirectoryrights, objecttype, isinherited -autosize 
 }
 <#Get objects that have specific permissions on the target(s) and specifically the gMSA attribute:
 WriteProperty 
 #>
Set-Location ad:
foreach ($gmsa in $gMSAs){
(Get-Acl $gmsa.distinguishedname).access | 
Where-Object {(($_.AccessControlType -eq 'Allow') -and (($_.activedirectoryrights -like '*WriteProperty*') -and ($_.objecttype -in $schemaIDGUID.Keys)))} |
 ft ([string]$gmsa.name),identityreference, activedirectoryrights, objecttype, isinherited -AutoSize
 } 
