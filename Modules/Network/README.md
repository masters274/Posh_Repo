# Powershell_Stuff
A few PowerShell scripts and modules that help with everyday tasks for the Net/Sys Admin


INSTALLATION:
This module is available in the PowerShell Gallery (PSGallery)
Install-Module Network


HISTORY:
Version 0.1
- Day one

Version 0.2
- Function (WEB) Added : Get-WebCertificate
- Function (DNS) Changed : Added progress to the Get-DnsDebugLog 

Version 0.3
- Function (WEB) added : Get-WebSecurityProtocol
- Function (WEB) added : Set-WebSecurityProtocol 
- Function (WEB) added : Import-509Certificate

Version 0.4
- Function (DNS) added : Get-HostsFile : Pretty self explainatory
- Function (DNS) added : Add-HostsFileEntry : Offers elevation if not running as admin
- Function (DNS) added : Remove-HostsFileEntry : Elevation offered. Only IP arg for now. 

Version 0.5
- Function (WEB) added : Expand-Uri : for seeing the destination of a shortened URL w/o going there...
- Function (WEB) changed : Set-WebSecurityProtocol had a problem with looking up current protocols. 
- Function (NET) added : Get-Netstat returns an object with established and listening port info
- Module : changed : Removed the prerequisite installer of the core module. 
- Module : changed : Module now requires PowerShell version 5.0

Version 0.6
- Function (NET) added : Send-WakeOnLan added

Version 0.7
- Function (WEB) added : Disable-Proxy added. Disables IE proxy settings via registry keys. 
- Function (WEB) added : Enable-Proxy added. Enables IE proxy settings via registry keys. 
- Module : changed : now requires core version to be 1.4 or higher

Version 0.7.1
- Function (WEB) updated : Enable-Proxy now tries to figure out if you had proxy or auto URL configured

Version 0.7.2
- Function (WEB) added : Get-Proxy. Returns True or False based on the proxy status

Version 0.8
- Module updated : Changed the requires statement to not include NetAdapter or NetTCPIP. This way it will work with
older operating systems. This will only exclude one function (ifconfig). 

Version 0.9
- Module updated : Cheanged the RequiredVersion, to ModuleVersion
- Function (DNS) : added : Get-DNSScavengeRecord returns records to be scavenged on DNS servers, if you enable it.

Version 0.9.1
- Function (DNS) : added : Invoke-DNSManualCleanUp. Just could not wait to add this one in, thus ver 0.9.!

Version 0.9.2
- Function (DNS) : updated : Invoke-DNSManualCleanUp. Added parameter RRType, just in case you wanna clean PTRs
