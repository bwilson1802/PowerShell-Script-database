# 81	Create bulk Users 
# 215	New AD Group 
# 222	Update users in group 
# 232	Create bulk Users V2   
# 265	Add user from csv 
# 276	IP config 
# 290	Install IIS 
# 296	Sort and Filter 
# 303	Hash table 
# 314	Get AD User 
# 349	Powershell calculator options 
# 353	Advanced filters 
# 361	making an alias 
# 366	WMI Object 
# 374	connect with multi machines 
# 393	powershell drives 
# 406	Date and Time 
# 422	Array 
# 451	Find script / run script 
# 501	script cert 
# 533	Loops 
# 557	parallel process 
# 562	elseif 
# 574	switch 
# 594	while or do until 
# 608	goes until max 
# 620	get-content 
# 627	get-cred 
# 637	Add help block 
# 643	Debug 
# 648	PSBreakpoint 
# 667	Functions 
# 722	psremoting 
# 784	scriptblock 
# 795	persistant connection 
# 850	Azure cred 
# 871	New Azure VM 
# 891	Azure add AD user / group 
# 919	Azure exchange online 
# 937	Jobs 
# 974   Azure VM lab create
# 1104  Network fix
# 
# 
# 
# 
# 
# 
# 
# 
# 
# 
# 
# 
# 
# 
# 
# 
# 
# 
# 
# 
# 
# 
# 
# 
# 
# 
# 
# 
# 
# 
# 
# 
# 
# 
# 
# 
# 
# 
##################################### Create bulk Users ######################################################


$memberof = read-host "Enter the membership of the new user"
$Lastname = read-host "Enter the last name of the new user"
$firstname = read-host "Enter the first name of the new user"
$newpass = read-host "Enter the password of the new user"

function new-labuser {
  

param (
    
    [parameter(mandatory=$true)]
    [string]$memberof,
    [parameter(mandatory=$true)]
    [string]$Lastname, 
    [parameter(mandatory=$true)]
    [string]$firstname, 
    [parameter(mandatory=$true)]
    # hash the password
    [system.security.securestring]$newpass
    )

# md = make dir, make a log folder
md C:\Logs -erroraction SilentlyContinue | out-null

# combine First and Last without space
$spacename = "$firstname $lastname"
# combine First and Last with space
$fullname = "$firstname&$lastname"

# must call it out in the script start for it to work.  ex .\ADWizard.PS1 -Debug
write-debug "check values" 

#add if needed for that host
import-module activedirectory 

#create new user. will promt for answer if not provided
try {
new-aduser -name $spacename `
            -samaccountname $fullname `
            -givenname $firstname `
            -surname $lastname `
            -userprinciplename "$fullname@hq.local" `
            -path "ou=xx,dc=xx,dc=xx" `
            -enable $true `
            -changepasswordatlogon $false `
            -accountpassword (convertto-securestring $newpass -asplaintext -force) 
            -ErrorAction Stop
            -ErrorVariable ADUserErr
} catch { 
    write "Error creating user $Spacename" | out-file C:\logs\error.log -append
    $ADUserErr | out-file C:\Logs\Error.log -append
    #makes yellow words (throw could be used - red)
    write-warning "could not create user $spacename"
}

add-adgroupmember $memberof $fullname

}

$memberof = read-host "Enter the membership of the new user"
$Lastname = read-host "Enter the last name of the new user"
$firstname = read-host "Enter the first name of the new user"
$newpass = read-host "Enter the password of the new user"

New-ADGroup -Name IPPhoneTest -GroupScope Universal -GroupCategory Security
Move-ADObject "CN=IPPhoneTest,CN=Users,DC=Adatum,DC=com" -TargetPath "OU=IT,DC=Adatum,DC=com"
Add-ADGroupMember IPPhoneTest -Members Abbi,Ida,Parsa,Tonia


$users = Get-ADGroupMember IPPhoneTest

ForEach ($u in $users) {
    $fullUser = Get-ADUser $u
    $ipPhone = $fullUser.GivenName + "." + $fullUser.Surname + "@adatum.com"
    Set-ADUser $fullUser -replace @{ipPhone="$ipPhone"}
}

function new-labuser {
  

param (
    
    [parameter(mandatory=$true)]
    [string]$memberof,
    [parameter(mandatory=$true)]
    [string]$Lastname, 
    [parameter(mandatory=$true)]
    [string]$firstname, 
    [parameter(mandatory=$true)]
    # hash the password
    [system.security.securestring]$newpass
    )

# md = make dir, make a log folder
md C:\Logs -erroraction SilentlyContinue | out-null

# combine First and Last without space
$spacename = "$firstname $lastname"
# combine First and Last with space
$fullname = "$firstname&$lastname"

# must call it out in the script start for it to work.  ex .\ADWizard.PS1 -Debug
write-debug "check values" 

#add if needed for that host
import-module activedirectory 

#create new user. will promt for answer if not provided
try {
new-aduser -name $spacename `
            -samaccountname $fullname `
            -givenname $firstname `
            -surname $lastname `
            -userprinciplename "$fullname@hq.local" `
            -path "ou=xx,dc=xx,dc=xx" `
            -enable $true `
            -changepasswordatlogon $false `
            -accountpassword (convertto-securestring $newpass -asplaintext -force) 
            -ErrorAction Stop
            -ErrorVariable ADUserErr
} catch { 
    write "Error creating user $Spacename" | out-file C:\logs\error.log -append
    $ADUserErr | out-file C:\Logs\Error.log -append
    #makes yellow words (throw could be used - red)
    write-warning "could not create user $spacename"
}

add-adgroupmember $memberof $fullname

}

##################################### New AD Group ######################################################

New-ADGroup -Name IPPhoneTest -GroupScope Universal -GroupCategory Security
Move-ADObject "CN=IPPhoneTest,CN=Users,DC=Adatum,DC=com" -TargetPath "OU=IT,DC=Adatum,DC=com"
Add-ADGroupMember IPPhoneTest -Members Abbi,Ida,Parsa,Tonia


##################################### Update users in group ######################################################

$users = Get-ADGroupMember IPPhoneTest

ForEach ($u in $users) {
    $fullUser = Get-ADUser $u
    $ipPhone = $fullUser.GivenName + "." + $fullUser.Surname + "@adatum.com"
    Set-ADUser $fullUser -replace @{ipPhone="$ipPhone"}
}

##################################### Create bulk Users V2 ######################################################

$users = Import-CSV users.csv

ForEach ($u in $users) {
    $path = "OU=" + $u.Department + ",DC=Adatum,DC=com"
    $upn = $u.UserID + "@adatum.com"
    $display = $u.First + " " + $u.Last
    Write-Host "Creating $display in $path"
    New-ADUser -GivenName $u.First -Surname $u.Last -Name $display -DisplayName $display -SamAccountName $u.UserID -UserPrincipalName $UPN -Path $path -Department $u.Department
}

# CSV 
# First, Last, UserID, Department
# Madeline, Parrish, MParrish, Sales
# Phil, Alfonso, PAlfonso, IT
# Rigoberto, Nowell, RNowell, Research
# Amparo, Harrington, AHarrington, Development




get-service | where-object {$_.status -eq "running"}

#   $_ (empty system verriable) (where you are storing the info)
#   |  (stop - store in memory (collection or object))
#   .property (dot notation)

get-service "s*" | sort-object status 
get-service -name "winrm" -computername "localhost", "server01", "server02" | format-table -property machinename, status, name, displayname -auto

#   -showwindow - gives a popout like out-gridview

##################################### Add user from csv ######################################################

$users = import-csv <path>
# headers must be there - First, Last, UserID, Department
$user[2].UserID

# import-clixml or convertfrom-jason 
# invoke-restmethod 

#read-host must have a varriable to go into

##################################### IP config ######################################################
  
#   IP Config  
get-netipconfiguration
#   New IP  
New-NetIPAddress -InterfaceAlias Ethernet -IPAddress 172.16.0.15 -PrefixLength 16
#   Remove old
Remove-NetIPAddress -InterfaceAlias Ethernet -IPAddress 172.16.0.11
#   Set DNS
Set-DnsClientServerAddress -InterfaceAlias Ethernet -ServerAddress 172.16.0.12
Remove-NetRoute -InterfaceAlias Ethernet -DestinationPrefix 0.0.0.0/0 -Confirm:$false
#   Default Gateway
New-NetRoute -InterfaceAlias Ethernet -DestinationPrefix 0.0.0.0/0 -NextHop 172.16.0.2

######################################   Install IIS ######################################################

Install-WindowsFeature Web-Server
New-Item C:\inetpub\wwwroot\London -Type directory
New-IISSite London -PhysicalPath C:\inetpub\wwwroot\london -BindingInformation "172.16.0.15:8080:"

######################################   Sort and Fileter ######################################################

get-adobject -filter * -properties *| ft -property name, objectclass, description -autosize -wrap
get-aduser -f * | format-wide -Column 4
                                - autosize
get-service | sort-object -Property DisplayName -Descending

##################################### Hash table ######################################################

#   hash table starts with @

Get-Service | sort -Property @{expression="status";decending=$true},@{expression=="name";accending=$true}

get-process | sort-object ws -desc | out-file workingsetsort.txt
.\workingsetsort
get-process | measure-object -Property ws, cpu -sum -Average -Maximum -Minimum
get-aduser -f * | measure

##################################### Get AD User ######################################################

#   aduser has name not computer name. use hash to rename name to computername so service can use it
get-adcomputer -f * -searchbase "ou" | Select-Object -Property @{l="computername";e={$_.name}} | get-service -name spooler

get-adcomputer -f * -searchbase "ou=lab computers,dc=hq,dc=local" | select -expand Name | out-file computers.csv 
import-csv .\computers.csv | get-service -name Spooler
                            get-process -name csrss
import-csv .\computers.csv | get-process -name winlog | ft machinename, name, ws,id

get-adcomputer -f * -searchbase "ou=lab computers,dc=hq,dc=local" | select @{l="computername";e={$_.name}} | get-service -name spooler | ft machinename, status,name,displayname 

,  | add-adgroupmember -members (get-aduser -filter {city -eq 'London'}) 

Get-ADUser –Filter * -SearchBase "cn=Users,dc=Adatum,dc=com" | ft

Get-ADUser -Filter * -Properties Department,City | Where {$PSItem.Department -eq ‘IT’ -and $PSItem.City -eq ‘London’} | Select-Object -Property Name,Department,City| Sort Name

Get-ADUser -Filter * -Properties Department,City,Office | 
Where {$PSItem.Department -eq 'IT' -and $PSItem.City -eq 'London'} | 
Sort Name | 
Select-Object -Property Name,Department,City,Office |
ConvertTo-Html –Property Name,Department,City -PreContent Users | 
Out-File E:\UserReport.html

# this works well - add a filter for only letter A
Get-ADUser -Filter * -Properties Department,City | Where {$_.Department -eq 'Managers' -and $_.City -eq 'London'} | Sort Name | Select-Object -Property Name,Department,City | out-gridview

Get-ADUser -Filter * -Properties Department,City | Where {$_.Department -eq 'Managers' -and $_.City -eq 'London'} | Where Name -like 'A*' | Select-Object -Property Name,Department,City,Caption,Domain,SID,FullName | out-gridview 
Get-CimInstance -Class Win32_UserAccount | Format-Table -Property Caption,Domain,SID,FullName,Name

get-aduser -f * | where {$_.lastlogondate -le "1/1/2021"}
get-aduser speck -properties *
get-aduser -f * -properties lastlogondate | where {$_.lastlogondate -le "9/1/2017"}
                                                                    -le (get-date).adddays(-90)}
##################################### Powershell calculator options ######################################################

#   round to 2 decimals '{0:N2} -f (123456789 / 1mb)

##################################### Advanced filters ######################################################

#    Advanced filtering - where-object only does one (where-object = where = ?)
get-service | ? { $_.status -eq "running" -and $_.name -like "*win*" }

#    $_ = $PSItem
#    foreach = %

##################################### making an alias ######################################################

Format-Custom = FC
get-alias | Where-Object -property name -eq FC

##################################### WMI Object ######################################################

Set-Location ScriptShare:

#gwmi = get-wmiobject
Get-WmiObject -class win32_logicaldisk | where {$_.drivetype -eq 3 -and $_.freespace -gt 1mb}
get-siminstance -classname cim_logicaldisk

##################################### connect with multi machines ######################################################

#  create session with cim to connect with multi machines
$alphasession = new-cimsession -computername alpha, bravo, charlie
get-ciminstance cim_logicaldisk -cimsession $alphasession 

gwmi win32_service | where name -eq spooler | foreach {$_.startservice()}
                                              invoke-wmimethod -name startservice
                                              foreach {$_.changestartmode("Manual")}
                                              invoke-wmimethod -name changestartmode -argumentlist Manual

Get-WmiObject -Namespace root\cimv2 -List | Where Name -like '*configuration*' | Sort Name
Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where DHCPEnabled -eq $False | Select IPAddress
Get-WmiObject -Namespace root\cimv2 -List | Where Name -like '*operating*' | Sort Name
Get-WmiObject -Class Win32_OperatingSystem | Get-Member
Get-WmiObject -Class Win32_Service | FL *
Get-WmiObject –Class Win32_Service –Filter "Name LIKE 'S%'" | Select Name,State,StartName
Get-CimInstance -ClassName Win32_Group -ComputerName LON-DC1

##################################### powershell drives ######################################################

get-psprovider 
Import-Module activedirectory 
get-psdrive
cd function:
cd alias:

# create a drive for PS.  Then just jump to tools
New-PSDrive tools -psprovider filesystem -root C:\users\bwils 
# remote sys
new-psdrive S -psprovider FileSystem -root \\XXXXX   -persist 

##################################### Date and Time ######################################################

Get-Date
$date = get-date 
$date.minute
$date.kind
(get-date).minute 
$date.adddays(-45)
$date = get-date 
[datetime]"12/31/2022" - $date
get-date | fl *

get-date | Get-Member
dir | gm
dir | where {$_.LastWriteTime -ge "6/14/2017"}

##################################### Array ######################################################

$Arr1 = "Monday","Tuesday","Wednesday","Thursday","Friday"
$Arr1
$Arr1[1]

$Arr1 = "Monday","Tuesday","Wednesday","Thursday","Friday"
foreach ($item in $Arr1) {write "The current item is $item"}
"Monday" -in $Arr1 
        -contains

# wipes the list and adds new item
$arr1 = new-object system.collections.arraylist
$arr1.add("Saturday")
$arr1.add("Monday")

# make an array to add to later
$computers = new-object system.collections.arraylist
#add items to array
[system.collections.arraylist]$computers = "alpha","bravo"

[System.Collections.ArrayList]$computers="LON-SRV1","LON-SRV2","LON-DC1"
$computers.IsFixedSize
$computers.Add("LON-DC2")
$computers.Remove("LON-SRV2")

$computers = new-object system.collections.arraylist
$computers.add("charlie")

##################################### Find script / run script ######################################################

#verify script location
get-location D:\allfiles\mod7\democode
getchild helloworld.ps1
dir *.ps1

#run a script using full path
D:\allfiles\mod7\democode

#run a script from the current dir
helloworld.ps1
.\helloworld.ps1

#set the execution policy
Get-ExecutionPolicy
Set-ExecutionPolicy restricted
.\helloworld.ps1
Set-ExecutionPolicy unrestricted 
#remotesigned, allsigned, restricted, unrestricted, bypass

# self-signed certificate option
# create the new code signing cert
# set a self-signed cert
$cert = new-selfsignedcertificate -certstorelocation "cert:\currentuser\my" `
                                    -dnsname "cn=powershell-ss-cert" `
                                    -subject "cn=powershell-ss-cert" `
                                    -textextension @("2.5.29.37={text}1.3.6.1.5.5.7.3.3") `

# confirm that the cert is there
get-childitem cert:\localmachine\root | where {$_.subject -eq "cn=powershell-ss-cert"}
get-childitem cert:\currentuser\my | where {$_.subject -eq "cn=powershell-ss-cert"}

$cert =  Get-ChildItem -Path "Cert:\CurrentUser\My" -CodeSigningCert

Set-AuthenticodeSignature -FilePath "C:\Scripts\MyScript.ps1" -Certificate $cert

#from the book
# To review the code-signing certificates installed for the current user, at the Windows PowerShell prompt, run the following command:

Get-ChildItem Cert:\CurrentUser\My\ -CodeSigningCert

# To place the code-signing certificate in a variable, at the Windows PowerShell prompt, run the following command:

$cert = Get-ChildItem Cert:\CurrentUser\My\ -CodeSigningCert

# To digitally sign a script, at the Windows PowerShell prompt, run the following command:

Set-AuthenticodeSignature -FilePath E:\Mod07\Democode\HelloWorld.ps1 -Certificate $cert

##################################### script cert ######################################################

New-SelfSignedCertificate -FriendlyName "Code Signing" -CertStoreLocation Cert:\CurrentUser\My -Subject "MyCert" -Type CodeSigningCert

get-psdrive

dir cert:\currentuser -Recurse -CodeSigningCert -OutVariable MyCert

$MyCert
#pins certs to $a

$cert = $MyCert[0]

Get-ExecutionPolicy
#will tell the current policy

Set-ExecutionPolicy "allsigned"

Set-AuthenticodeSignature  -Certificate $Cert -filepath "C:\users\bwils\Desktop\MSSA\powershell\99 bottles\morning automationV2.ps1"
 
dir C:\users\bwils\Desktop\MSSA\scripts 

cat C:\users\bwils\Desktop\MSSA\scripts\test.ps1

get-childitem cert:currentuser\my\ -codesigningcert
$cert = get-childitem cert:currentuser\my\ -codesigningcert
set-location documents\windowspowershell\
Set-AuthenticodeSignature -FilePath HelloWorld.ps1 -Certificate $cert
Set-ExecutionPolicy AllSigned
Set-ExecutionPolicy bypass 
get-help Set-ExecutionPolicy -Detailed

##################################### Loops ######################################################

$services = get-service

for ($i=0;$i -lt $services.count;$i++) {
    write "service $i is: $($services[$i].name)"
}

foreach ($item in $services) {
    write "The service name is: $($item.name)"
}

get-service | foreach-object {write "the service name is: $($_.name)"}

$users = get-aduser -f *

foreach ($user in $users) {
    set-aduser $user -department "marketing"
    }

for($i=1; $i -le 10; $i++) {
write-host "creating user $i"
}

##################################### parallel process ######################################################

# -parallel process 5 at a time, can be increased..... helps speed it up bc 4each does one at a time
$users | foreach-object -parallel { set-aduser $user -department "marketing" }

##################################### elseif ######################################################

$freespace = 15GB

if ($freespace -le 5GB) {
write-host "free disk space is less than 5GB"
} elseif ($freespace -le 10GB) {
write-host "free disk space is less than 10 GB"
} elseif }
write-host "free disk space is less more 10 GB"
}

##################################### switch ####################################################### 

$choice = read-host "please enter your choice"

switch ($choice) {
1 { write-host "you selected menu item 1" }
2 { write-host "you selected menu item 2" }
3 { write-host "you selected menu item 3" }
Default { write-host "you did not select a valid option" }


Switch -wildcard ($ip) {
"10.*" { write-host "This computer in on the internal network" }
"10.1.*" { write-host "This computer is on the London network" }
"10.2.*" { write-host "This computer is on the Vancover network" }
Default { write-host "This computer is not on the internal network" }


$answer = read-host "please input stop or go"

##################################### while or do until #######################################################

# while or do until / do while (while evals first)
while ($answer -eq "go") {
write-host "script block to process"
}

##################################### continue means skip #######################################################

foreach ($user in $users) {
    if ($user.name -eq "Administrator") {continue}
    write-host "Modify user object"
}

##################################### goes until max #######################################################

# goes until max is hit then it will stop, changes the first 20
$user = get-aduser -f *
$max = 20

foreach ($user in $users) {
    $number++
    write-host "Modify user object $number" 
    if ($number -ge $max) {break}
}

##################################### get-content #######################################################

# get-content used for log files
$computers = get-content <path>
get-content -path <path> -include <log or text>
get-content -path <path> -totalcount 10

##################################### get-cred #######################################################

$cred = get-credential
set-aduser -identity $user -department "marketing" -credential $cred
$cred | export-climax <path>

secretmanagement uses lastpass
Install-Module Microsoft.PowerShell.SecretManagement


##################################### Add help block #######################################################

<#
help block here
#>

##################################### Debug #######################################################

#write debug line will stop at that line and start debug what has already been done
write-debug

##################################### PSBreakpoint #######################################################

# Set-PSBreakpoint -script .\ADWizard.PS1 -command/-line/-variable 
Set-PSBreakpoint -script .\ADWizard.PS1 -variable spacename -mode readwrite
# a way to troubleshoot.  let it go little by little
remove-psbreakpoint -id 0

# only so many possible errors.  could write something for each
try {
new-item $file
} catch [System.IO.DirectoryNotFoundException] {
write-host "Directory was not found"
} catch [System.IO.IOException]{
write-host "the file already exsits"
} catch {
wrtie-host "an unknown error occurred"
}


##################################### Functions #######################################################

# set it to run at startup or at a time
# functions have their own store
# you can call 1 of the functions from ps

function.ps1

function 1 {
everything in script 1
}
function 2 {
everything in script 2
}
function 3 {
everything in script 3
}
function 4 {
everything in script 4
}

# wont run until its loaded / loads when you run it
function addme ($num1,$num2) {
    $result = $num1 + $num2
    return $result
}
addme 5 10

function addme {
    $result = 5+5
    return $result
}
addme 

#Folder must have the same name as the script
# location C:\Users\bwils\Documents\WindowsPowerShell\modules\Function1
# script changes to psm1???????????
# once its in there, when you open powershell it loads

# User functions
user\powershell\functions
                        functions.ps1

#machine
machine\powershell\functions
                        functions.ps1
# location C:\Program Files\WindowsPowerShell\Modules

Function Get-SecurityEvent {
   Param (
      [string]$ComputerName
   ) #end Param
   Get-EventLog -LogName Security -ComputerName -$ComputerName -Newest 10
}

##################################### psremoting #######################################################


# ws-man and cim to remote computers
# managed through win-rm service
# get-service -computername = ws-man

enable-psremoting
# use GPO to enable on all    GPO computer-policy-windows-sys services-windows remote gmgt
# must set firewall aswell if using GPO - 

# what is in the bracket gets handed off (not all cmd supports remote with the -computername)
invoke-command {restart-service spooler} -computername RTR, DC1, LON-SVR1

get-windowsfeature 
add-windowsfeature windows-server-backup -includemanagementtools -computername RTR
# will fail bc it doesnt support remote
invoke-command {add-windowsfeature windows-server-backup -includemanagementtools} -computername RTR

# load the function then run -Get-RemoteEvents <Alpha>

function get-remoteEvents {
    param (
            [string]$computername = ".",
            [int]$eventID = 4624,
            [int]$numItems = 10
          )

    Invoke-Command ArgumentList $EventID,$NumItems {
        Param ($EventID,$NumItems)
        Get-Eventlog Security | where {$_.EventID -eq $EventID} | select -First $NumItems
    } -computername $computername 
}

# would this work?
Invoke-Command -VMName RTR {set-netipaddress 

Invoke-Command –ScriptBlock { Do-Something –Credential (Get-Credential) } -ComputerName LON-DC1

Invoke-Command –ScriptBlock { Param($c) Do-Something –Credential $c }
               -ComputerName LON-DC1
               -ArgumentList (Get-Credential)

$quantity = Read-Host "Query how many log entries?"

Set-ExecutionPolicy RemoteSigned
Enable-PSremoting
Get-PSSessionConfiguration

Enter-PSSession –ComputerName LON-DC1

Invoke-Command –ComputerName LON-CL1,LON-DC1 –ScriptBlock { Get-NetAdapter –Physical }
Invoke-Command –ComputerName LON-DC1 –ScriptBlock { Get-Process } | Get-Member

$dc = New-PSSession –ComputerName LON-DC1
$dc
Get-Module –ListAvailable –PSSession $dc
Get-Module –ListAvailable –PSSession $dc | Where { $_.Name –Like '*share*' }
Import-Module –PSSession $dc –Name SMBShare –Prefix DC
Get-DCSMBShare
Get-SMBShare

##################################### scriptblock #######################################################

# scriptblock is what is inside { }
# $x is $quantity - it doesnt have to match it goes in order
Invoke-Command –ArgumentList $quantity –ComputerName LON-DC1 –ScriptBlock { Param($x) Get-EventLog –LogName Security –newest $x }

# scope modifier = $Using:quantity passes the param $quantity

Invoke-Command -ComputerName lon-dc1 -ScriptBlock {Get-EventLog -LogName Security –
Newest $Using:quantity}

##################################### persistant connection #######################################################

# persistant connection to multiple machines
$Alphasession = new-pssession Alpha, Bravo, Charlie
enter-pssession -session $Alphasession 
# exit leaves it open
remove-pssession $alphasession 

# mulit-hop remoting
# send the session to a stronger computer to open a session with 500 others

# You're signed in to ServerA.
# From ServerA, you start a remote PowerShell session to connect to ServerB.
# A command you run on ServerB via your PowerShell Remoting session attempts to access a resource on ServerC.
# Access to the resource on ServerC is denied because the credentials you used to create the PowerShell Remoting session are not passed from ServerB to ServerC.

# cash the creds on B so it can use them
Enable-WsManCredSSP –Role Client –Delegate SVRB


Set-ExecutionPolicy RemoteSigned
Enable-PSremoting
Get-PSSessionConfiguration

Enter-PSSession –ComputerName LON-DC1

Invoke-Command –ComputerName LON-CL1,LON-DC1 –ScriptBlock { Get-NetAdapter –Physical }
Invoke-Command –ComputerName LON-DC1 –ScriptBlock { Get-Process } | Get-Member

$dc = New-PSSession –ComputerName LON-DC1
$dc
Get-Module –ListAvailable –PSSession $dc
Get-Module –ListAvailable –PSSession $dc | Where { $_.Name –Like '*share*' }
Import-Module –PSSession $dc –Name SMBShare –Prefix DC
Get-DCSMBShare
Get-SMBShare

#remember to close all open sessions
Get-PSSession | Remove-PSSession
Get-PSSession

# PS multi machines at once, limit is 32, will process 32 then do the rest in 32 blocks
$computers = New-PSSession –ComputerName LON-CL1,LON-DC1
$computers

Invoke-Command –Session $computers –ScriptBlock { Import-Module NetSecurity }
Get-Command –Module NetSecurity
Help Get-NetFirewallRule -ShowWindow
Invoke-Command –Session $computers –ScriptBlock { Get-NetFirewallRule –Enabled True } | Select Name,PSComputerName
Invoke-Command –Session $computers –ScriptBlock { Remove-Module NetSecurity }

Get-WmiObject –Class Win32_LogicalDisk –Filter "DriveType=3"
Invoke-Command –Session $computers –ScriptBlock { Get-WmiObject –Class Win32_LogicalDisk –Filter "DriveType=3" } | ConvertTo-Html –Property PSComputerName,DeviceID,FreeSpace,Size
Get-PSSession | Remove-PSSession

##################################### Azure cred #######################################################


$PSVersionTable.PSVersion
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
Install-Module -Name Az -Scope CurrentUser -Repository PSGallery -Force
Connect-AzAccount
Get-AzSubscription
Get-AzResourceGroup
$cred = Get-Credential -Message "Enter a username and password for the virtual machine."

$vmParams = @{
  ResourceGroupName = 'myRG-YOS9Z0B6LY'
  Name = 'TestVM1'
  Location = 'eastus'
  ImageName = 'Win2016Datacenter'
  PublicIpAddressName = 'TestPublicIp'
  Credential = $cred
  OpenPorts = 3389
}

##################################### New Azure VM #######################################################

$newVM1 = New-AzVM @vmParams

$NewVM1
$newVM1.OSProfile | Select-Object ComputerName,AdminUserName
$newVM1 | Get-AzNetworkInterface | Select-Object -ExpandProperty IpConfigurations | Select-Object Name,PrivateIpAddress

$publicIp = Get-AzPublicIpAddress -Name TestPublicIp -ResourceGroupName myRG-YOS9Z0B6LY
$publicIp | Select-Object Name,IpAddress,@{label='FQDN';expression={$_.DnsSettings.Fqdn}}

mstsc.exe /v <PUBLIC_IP_ADDRESS>

$VirtualMachine = Get-AzVM -ResourceGroupName "myRG-YOS9Z0B6LY" -Name "TestVM1"
Add-AzVMDataDisk -VM $VirtualMachine -Name "disk1" -LUN 0 -Caching ReadOnly -DiskSizeinGB 1 -CreateOption Empty
Update-AzVM -ResourceGroupName "myRG-YOS9Z0B6LY" -VM $VirtualMachine

Install-Module AzureAD
Connect-AzureAD

##################################### Azure add AD user / group #######################################################

# ad to AD and assign Global admin
Get-AzureADUser
$PasswordProfile = New-Object -TypeName Microsoft.Open.AzureAD.Model.PasswordProfile
$PasswordProfile.Password = "<password>"
New-AzureADUser -DisplayName "Noreen Riggs" -UserPrincipalName Noreen@M365x29412888.onmicrosoft.com -AccountEnabled $true -PasswordProfile $PasswordProfile -MailNickName Noreen
$user = Get-AzureADUser -ObjectID Noreen@M365x29412888.onmicrosoft.com
Add-AzureADDirectoryRoleMember -ObjectId $role.ObjectId -RefObjectId $user.ObjectID
Get-AzureADDirectoryRoleMember -ObjectId $role.ObjectId

New-AzureADUser -DisplayName "Allan Yoo" -UserPrincipalName Allan@M365x29412888.onmicrosoft.com -AccountEnabled $true -PasswordProfile $PasswordProfile -MailNickName Allan
Set-AzureADUser -ObjectId Allan@M365x29412888.onmicrosoft.com -UsageLocation US
Get-AzureADSubscribedSku | FL
$SkuId = (Get-AzureADSubscribedSku | Where SkuPartNumber -eq "ENTERPRISEPREMIUM").SkuID
$License = New-Object -TypeName Microsoft.Open.AzureAD.Model.AssignedLicense
$License.SkuId = $SkuId
$LicensesToAssign = New-Object -TypeName Microsoft.Open.AzureAD.Model.AssignedLicenses
$LicensesToAssign.AddLicenses = $License
Set-AzureADUserLicense -ObjectId Allan@M365x29412888.onmicrosoft.com -AssignedLicenses $LicensesToAssign

Get-AzureADGroup
New-AzureADGroup -DisplayName "Sales Security Group" -SecurityEnabled $true -MailEnabled $false -MailNickName "SalesSecurityGroup"
$group = Get-AzureAdGroup -SearchString "Sales Security"
$user = Get-AzureADUser -ObjectId Allan@M365x29412888.onmicrosoft.com
Add-AzureADGroupMember -ObjectId $group.ObjectId -RefObjectId $user.ObjectId
Get-AzureADGroupMember -ObjectId $group.ObjectId

##################################### Azure exchange online #######################################################

Install-Module ExchangeOnlineManagement
Connect-ExchangeOnline
Get-EXOMailbox

New-Mailbox -Room -Name BoardRoom
Set-CalendarProcessing BoardRoom -AutomateProcessing AutoAccept

Install-Module -Name Microsoft.Online.SharePoint.PowerShell
Connect-SPOService -Url https://M365x29412888-admin.sharepoint.com
Get-SPOSite
Get-SPOWebTemplate
New-SPOSite -Url https://M365x29412888.sharepoint.com/sites/Sales -Owner noreen@M365x29412888.onmicrosoft.com -StorageQuota 256 -Template EHS#1

Get-SPOSite | FL Url,Status
Disconnect-SPOService

##################################### Jobs #######################################################

start-job {get-eventlog security -computername Alpha} -name Evtjob
# shows the status of the job
get-job
stop-job Evtjob
# one shot.  cuts the info
recieve-job -Evtjob | 
# -keep will make a copy
$events | where eventid -eq 4624 | select -first 10 

$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-command &{get-process | sort WS -Desc | select -first 10 | out-file C:\Logs\Top10Procs.txt}"
$Trigger = New-ScheduledTaskTrigger -at "12:28 pm" -once
New-ScheduledTask -action $action -Trigger $trigger | register-scheduledtask
Register-ScheduledJob -trigger (New-JobTrigger -once -at "12:38pm") -name Top10jobs {get-process | sort ws -desc | 

Invoke-Command –ScriptBlock { Get-NetAdapter –Physical } –ComputerName LON-DC1,LON-SVR1 –AsJob –JobName RemoteNetAdapt
Invoke-Command –ScriptBlock { Get-SMBShare } –ComputerName LON-DC1,LON-SVR1 –AsJob –JobName RemoteShares
Invoke-Command –ScriptBlock { Get-CimInstance –ClassName Win32_Volume } –ComputerName (Get-ADComputer –Filter * | Select –Expand Name) –AsJob –JobName RemoteDisks

Start-Job –ScriptBlock { Get-EventLog –LogName Security } –Name LocalSecurity
Start-Job –ScriptBlock { 1..100 | ForEach-Object { Dir C:\ -Recurse } } –Name LocalDir

Get-Job
Get-Job –Name Remote*
Stop-Job –Name LocalDir

Receive-Job –Name RemoteNetAdapt
# if error run enable-psremoting 

$option = New-ScheduledJobOption –WakeToRun -RunElevated
$trigger1 = New-JobTrigger –Once –At (Get-Date).AddMinutes(5)
Register-ScheduledJob –ScheduledJobOption $option –Trigger $trigger1 –ScriptBlock { Get-EventLog –LogName Security } –MaxResultCount 5 –Name LocalSecurityLog
Get-ScheduledJob –Name LocalSecurityLog | Select –Expand JobTriggers

#task sched action PowerShell.exe then put where the ps1 is in the optional argument box

##################################### Azure VM lab create  ######################################################

##CREATES 3 VIRTUAL NETWORKS WITH 3 SUBNETS ON EACH, AND 3 VIRTUAL MACHINES, ONE ON EACH VNET##
##UPLOAD TO AZURE CLOUDSHELL##
##TO RUN, INPUT "./buildvms.ps1" AND PRESS ENTER##

##VARIABLES-NAMES##

##VARIABLES-NETWORK##
$Vnet = "DemoVNet"
$NICName = "demovmnic"
$PIPName = "demovmpip"
$DNSName = "demodns"
$SubName1 = "DemoSubnet1"
$SubName2 = "DemoSubnet2"
$SubName3 = "DemoSubnet3"

##VARIABLES-VM##
$VMName = "DemoVM"
$DiskName = "DemoVMDisk"
$VMSize = "Standard_B2s"
$ComputerName = "DemoVM"
$Publisher = "MicrosoftWindowsServer"
$Offer = "WindowsServer"
$Sku = "2016-Datacenter"
$username = "azureuser"
$password = "Pa55w.rd1234" | ConvertTo-SecureString -AsPlainText
$Credential = New-Object -TypeName PSCredential -ArgumentList ($username, $password)

##GET CURRENT SUBSCRIPTION##
$Sub = Get-AzContext
$Sub = $Sub.Name
$Continue = Read-Host -Prompt "Active subscription is '$sub', is this correct? (Y/N)"
if ($Continue -eq "N"){
    Write-Host "Select a Subscription:"
    $Subscription = Get-AzSubscription
    $menu = @{}
    for ($i=1;$i -le $Subscription.count; $i++) {
       Write-Host "$i. $($Subscription[$i-1].name), $($Subscription[$i-1].Id)"
        $menu.Add($i,($Subscription[$i-1].name))
        }
    
    [int]$ans = Read-Host 'Enter selection'
    $selection = $menu.Item($ans)
    $Sid = (Get-AzSubscription -Subscriptionname $selection)
    $Sid


##SETS SUBSCRIPTION##
Set-AzContext -Subscription $Sid.id
$SetSub = (Get-AzContext).name

##DISPLAYS NEW ACTIVE SUBSCRIPTION##
Write-Host "Subscription changed to '$SetSub'"
}

##ASK IF USING EXISTING RESOURCE GROUP OR MAKE A NEW RESOURCE GROUP##
$ExistingRG = Read-Host -Prompt "Use existing resource group? (Y/N)"
If ($ExistingRG -eq "N"){
    $RGName = Read-Host -Prompt "Input New Resource Group Name"

    ##GET THE REGION AND SELECT FROM MENU##
    Write-Host "Select a Region:"
    $Region = get-azlocation | Where-Object {$_.DisplayName -Match "US"} | Where-Object {$_.DisplayName -CNotMatch "Australia"}
    $menu = @{}
    for ($i=1;$i -le $Region.count; $i++) {
        Write-Host "$i. $($Region[$i-1].DisplayName)"
        $menu.Add($i,($Region[$i-1].location))
        }
    
    [int]$ans = Read-Host 'Enter selection'
    $Location = $menu.Item($ans)

    Write-host "$Location"

    ##CREATE A RESOURCE GROUP##

    New-AzResourceGroup `
    -name $RGName `
    -location $Location 
}else {
    $RGName = Read-Host -Prompt "Input existing Resource Group Name"
    $Location = (Get-AzResourceGroup -Name $RGName).location

    Get-AzResourceGroup -Name $RGName
    $Location
} 

##CREATES SUBNETS AND VNETS##

for (($a = 0), ($i = 1); $a -le 2; ($a++), ($i++)){
    $subnet1 = New-AzVirtualNetworkSubnetConfig -Name $SubName1 -AddressPrefix 192.168.$a.0/25
    $subnet2 = New-AzVirtualNetworkSubnetConfig -Name $SubName2 -AddressPrefix 192.168.$a.128/26
    $subnet3 = New-AzVirtualNetworkSubnetConfig -Name $SubName3 -AddressPrefix 192.168.$a.192/26
    
    $VN = New-AzVirtualNetwork -Name $VNet$i -ResourceGroup $RGName -Location $Location -addressprefix 192.168.$a.0/24 -Subnet $subnet1, $subnet2, $subnet3 -Verbose
    
    ##CREATING NETWORK RESOURCES##
    $SubnetID = Get-AzVirtualNetworkSubnetConfig -name $SubName1 -VirtualNetwork $VN
    
    $g = [guid]::NewGuid()
    $v = [string]$g
    $v = $v.Replace("-","")
    $v = $v.substring(0, 5)
    $v

    $PIP = New-AzPublicIpAddress -Name $PIPName$i -DomainNameLabel $DNSName$v -ResourceGroupName $RGName -Location $Location -AllocationMethod Dynamic
    $NIC = New-AzNetworkInterface -Name $NICName$i -ResourceGroupName $RGName -Location $Location -SubnetId $SubnetID.id -PublicIpAddressId $PIP.Id
    
    ##CREATE CONFIG FOR VIRTUAL MACHINE##
    $VirtualMachine = New-AzVMConfig -VMName $VMName$i -VMSize $VMSize
    $VirtualMachine = Set-AzVMOperatingSystem -VM $VirtualMachine -Windows -ComputerName $ComputerName$i -Credential $Credential
    $VirtualMachine = Add-AzVMNetworkInterface -VM $VirtualMachine -Id $NIC.id
    $VirtualMachine = Set-AzVMSourceImage -VM $VirtualMachine -PublisherName $Publisher -Offer $Offer -Skus $Sku -Version Latest
    $VirtualMachine = Set-AzVMOSDisk -Name $DiskName$i -VM $VirtualMachine -StorageAccountType Standard_LRS -CreateOption FromImage

    ##CREATES VIRTUAL MACHINE##
    New-AzVM `
    -ResourceGroupName $RGName `
    -Location $Location `
    -VM $VirtualMachine `
    -AsJob `
    -Verbose
    
    ##VM FEEDBACK##
    Get-AzureRMVM -ResourceGroupName $RGName | Format-Table -Property Name
}
##SHOWS JOB STATUS OF VM CREATION##
Get-Job

##################################### Network fix  ######################################################

# packetlosstest.com
#speed.measurementlab.net

#Labs
Clear-DnsClientCache
Get-NetAdapter -physical | where status -eq 'up' | Restart-NetAdapter 
Restart-Service DNS
Restart-Service DHCPServer
Restart-Service Certsvc
Get-NetConnectionProfile

Clear-DnsClientCache
Restart-NetAdapter *
Restart-Service DNS
Restart-Service DHCPServer
Restart-Service Certsvc
Get-NetConnectionProfile

Clear-DnsClientCache
Restart-NetAdapter *
Get-NetConnectionProfile


ipconfig /release
ipconfig /renew
ipconfig /flushdns
ipconfig /registerdns
netstat -rr
netsh int ip reset all
netsh winsock reset





##################################### Enumerate expired user accounts  ######################################################

##################################### Enumerate user accounts expired within last 24-hour period  ######################################################

##################################### Locate and unlock specific user account  ######################################################

##################################### Retrieve all locked accounts  ######################################################

##################################### Disable user accounts that have that have not been used to logon with in 30 or more days  ######################################################

##################################### Move disabled users into a specific OU  ######################################################

##################################### Remove Disabled Users from all Security Groups except Domain Users  ######################################################

##################################### Add Users into Groups  ######################################################

##################################### Create OUs  ######################################################

##################################### Create Groups  ######################################################

##################################### Create list of computers with a particular operating system installed  ######################################################

##################################### Create list of computers that have not logged onto the network within 30 days  ######################################################

##################################### Automatically remove items from Downloads folders 60+ days old  ######################################################

##################################### Create script to remote restart computer  ######################################################

##################################### Retrieve disk size and amount of free space on a remote host  ######################################################

##################################### Stop and start process on remote host  ######################################################

##################################### Stop and start services on remote host  ######################################################

##################################### Retrieve a list of printers installed on a computer  ######################################################

##################################### List Ip address for a remote host  ######################################################

##################################### Retrieve network Adapter properties for remote computers  ######################################################

##################################### Release and renew DHCP leases on Adapters or   ######################################################

##################################### Create a network Share   ######################################################

##################################### Get Service ######################################################










