
Import-Module ActiveDirectory
##Get the GUID of the extended attribute ms-ds-GroupMSAMembership from Schema
$schemaIDGUID = @{}
Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext -LDAPFilter '(name=ms-ds-GroupMSAMembership)' -Properties name, schemaIDGUID |
ForEach-Object {$schemaIDGUID.add([System.GUID]$_.schemaIDGUID,$_.name)}

<# **REPLACE DN VARIABLE BELOW**
Declare the distinguishedName of the OU to search for gMSAs within - by default this may be the Managed Service Accounts OU#>
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
