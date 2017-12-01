##
# Created by: Christopher Day
# Last Modified: 14 Oct 14
# Description: It is used to capture raw data to help identify false positives that occur in vulnerability assessment tools.
# Tested on: Windows 7 and 8
# Booz Allen Hamilton Air Force Airborne CyberSecurity Team
##

Try{
#Create a folder on the desktop to save results
$desktopPath = [Environment]::GetFolderPath("Desktop")
$savePath = $desktopPath + "\\PowerShellOutput"
md $savePath
$scriptPath = split-path -parent $MyInvocation.MyCommand.Definition
$xslt = New-Object System.Xml.Xsl.XslCompiledTransform;

#Command requires Administrator Priviliges to execute
Write-Host "Capturing Security Policy"
secedit /export /configure | Out-File -FilePath $savePath\\Security_Policy.txt -ErrorAction Continue
net session | Out-File -FilePath $savePath\\Network_Data.txt -ErrorAction Continue
net view | Out-File -FilePath $savePath\\Network_Data.txt -Append -ErrorAction Continue

Write-Host "Capturing Security Log"
Get-EventLog Security | Out-File -FilePath $savePath\\Security_Log.txt -ErrorAction Continue

Write-Host "Running Session, Users, Termserver Queriers"
query session /counter | Out-File -FilePath $savePath\\Query_Session.txt -ErrorAction Continue
query termserver | Out-File -FilePath $savePath\\Query_TerminalServer.txt -ErrorAction Continue
query user | Out-File -FilePath $savePath\\Query_User.txt

Write-Host "Capturing Whoami Groups and Privilieges"
whoami /groups /priv | ConvertTo-XML -As Stream -NoTypeInformation |Out-File -FilePath $savePath\\whoami.xml

Write-Host "Capturing Group Policy Settings"
gpresult /z | Out-File -FilePath $savePath\\Group_Policy.txt -ErrorAction Continue

Write-Host "Capturing Audit Policy"
auditpol /get /category:* | Out-File -FilePath $savePath\\Audit_Policy.txt -ErrorAction Continue

Write-Host "Capturing Network Data"
net accounts | Out-File -FilePath $savePath\\Network_Data.txt -ErrorAction Continue
net share | Out-File -FilePath $savePath\\Network_Data.txt -Append -ErrorAction Continue
net use | Out-File -FilePath $savePath\\Network_Data.txt -Append -ErrorAction Continue

Write-Host "Capturing Network Statistics"
netstat -ano | Out-File -FilePath $savePath\\Network_Data.txt -Append -ErrorAction Continue
netstat -r | Out-File -FilePath $savePath\\Network_Data.txt -Append -ErrorAction Continue
ipconfig | Out-File -FilePath $savePath\\Network_Data.txt -ErrorAction Continue

Write-Host "Capturing Address Resolution Protocol (ARP) Data"
arp -a | Out-File -FilePath $savePath\\Network_Data.txt -Append -ErrorAction Continue

Write-Host "Capturing Firewall Statistics"
netsh advfirewall show allprofiles | Out-File -FilePath $savePath\\Firewall_Stats.txt -ErrorAction Continue
netsh firewall show config | Out-File -FilePath $savePath\\Firewall_Stats.txt -Append -ErrorAction Continue
netsh firewall show state | Out-File -FilePath $savePath\\Firewall_Stats.txt -Append -ErrorAction Continue

Write-Host "Capturing Current System Log"
Get-EventLog System | ConvertTo-Xml -As String -NoTypeInformation | Out-File -FilePath $savePath\\System_Log.xml -ErrorAction Continue

Write-Host "Capturing Application Log"
Get-EventLog Application | ConvertTo-Xml -As String -NoTypeInformation | Out-File -FilePath $savePath\\Application_Log.xml -ErrorAction Continue

Write-Host "Capturing Current Services"
Get-Service | ConvertTo-XML -As String -NoTypeInformation | Out-File -FilePath $savePath\\Stauts_Of_Serivces.xml -ErrorAction Continue

$saveXML = $savePath + "\\XML_Out.xml" 
$xslt = New-Object System.Xml.Xsl.XslCompiledTransform 
$xslt.Load($scriptPath + "\\Test_Report_v1.xslt")
 
Write-Host "Capturing Software List"
$installedSW = @(Get-ChildItem -Path HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall |
    Get-ItemProperty | Sort-Object -Property DisplayName | Select-Object -Property DisplayName, DisplayVersion, Publisher,PSPath, PSProvider, InstallLocation) | 
    ConvertTo-XML -As String -NoTypeInformation | Out-File -FilePath $savePath\\Software_List.xml -ErrorAction Continue
    
Write-Host "Capturing Windows Management Instrumentation Command-Line (WMIC) Data"
gwmi Win32_BaseBoard | Select-Object Name, Manfacturer, Model, PartNumber,Product, Version, SerialNumber, HotSwappable, 
    Removable, Replaceable |
    ConvertTo-XML -As String -NoTypeInformation | Out-File -FilePath $savePath\\MotherBoard_Info.xml -ErrorAction Continue
$moboPathXML = $savePath + "\\MotherBoard_Info.xml"
$moboPathHTML = $savePath + "\\MotherBoard_Info.html"
$xslt.Transform($moboPathXML, $moboPathHTML)
$pcInfo += $moboPathHTML | ConvertTo-Html -Fragment -PreContent "<H2>Motherboard Information</H2>" | Out-String

gwmi Win32_Bios | Select-Object Name, BIOSVersion, Description, Manufacturer, PrimaryBIOS, ReleaseDate, Version,
    SMBIOSPresent, SMBIOSBIOSVersion, SMBIOSMajorVersion, SMBIOSMinorVersion|
    ConvertTo-XML -As String -NoTypeInformation | Out-File -FilePath $savePath\\Bios_Info.xml -ErrorAction Continue

gwmi Win32_ComputerSystem | Select-Object Name, Description, AdminPasswordStatus, BootupState, Domain, DNSHostName, InfraredSupported,
    NetworkServerModeEnabled, NumberOfProcessors, PartOfDomain, PrimaryOwnerName,
    Roles, SystemStartupOptions, SystemStartUpSetting, SystemType, TotalPhysicalMemory, UserName | 
    ConvertTo-XML -As String -NoTypeInformation | Out-File -FilePath $savePath\\System_Settings.xml -ErrorAction Continue
    
gwmi Win32_Desktop | Select-Object __SERVER, Name, Description, ScreenSaverActive, ScreenSaverExecutable, ScreenSaverSecure, 
    ScreenSaverTimeout, Wallpaper |
    ConvertTo-XML -As String -NoTypeInformation | Out-File -FilePath $savePath\\ScreenSaver_Info.xml -ErrorAction Continue

gwmi Win32_LogicalDisk | Select-Object DeviceID, Caption, Compressed, Description, FileSystem, FreeSpace, MediaType, Size, 
    SupportsFileBasedCompression, SystemName, VolumeSerialNumber, ProviderName |
    ConvertTo-XML -As String -NoTypeInformation | Out-File -FilePath $savePath\\Logical_Disk_Info.xml -ErrorAction Continue

gwmi Win32_DiskDrive | Select-Object DeviceID, Model, Partitions, InterfaceType, BytesPerSector, SectorsPerTrack,
    Size, TotalCylinders, CapabilityDescriptions, Caption, FirmwareRevision, MediaType,
    PNPDeviceID, SerialNumber, TotalHeads, TotalSectors, TotalTracks, TracksPerCylinder |
    ConvertTo-XML -As String -NoTypeInformation | Out-File -FilePath $savePath\\Hard_Drive_Info.xml -ErrorAction Continue

gwmi Win32_NetworkAdapter | Select-Object Name, Status, __SERVER, AdapterType, Caption, Description, Installed, MACAddress,
    Manufacturer, NetConnectionID, NetConnectionStatus, NetEnabled, PhysicalAdapter, PNPDeviceID, 
    ServiceName |
    ConvertTo-XML -As String -NoTypeInformation | Out-File -FilePath $savePath\\Network_Adapter_Info.xml -ErrorAction Continue

gwmi Win32_NetworkAdapterConfiguration | Select-Object DNSHostName, DHCPLeaseExpires, Descriptions, DHCPEnabled, DHCPLeaseObtained, DHCPServer, DNSDomain,
    IPAddress, IPEnabled, IPFilterSecurityEnabled, WINDSPrimaryServer, MACAddress, ServiceName,
    TCPMaxConnectRetransmissions, TCPMaxDataRetransmission, TCPNumConnections, WINSEnableLMHostsLookup,
    WINSHostLookupFile, WINSScopeID, WINSSecondaryServer, FullDNSRegistrationEnabled |
    ConvertTo-XML -As String -NoTypeInformation | Out-File -FilePath $savePath\\Network_Adapter_Configuration.xml -ErrorAction Continue

gwmi Win32_NetworkLoginProfile | Select-Object Name, AccountExpires, BadPasswordCount, Caption, __SERVER, Description, Flags, FullName,
    LastLogoff, LastLogOn, LogonHours, LogonServer, MaximumStorage, NumberOfLogons, PasswordAge, PasswordExpires,
    UserComment, UserType, Workstations |
    ConvertTo-XML -As String -NoTypeInformation | Out-File -FilePath $savePath\\Network_Login_Profile.xml -ErrorAction Continue

gwmi Win32_OnBoardDevice | Select-Object Name, Description, __SERVER, Caption, Enabled, HotSwappable, Manufacturer, Model,
    PoweredOn, Removable, Replacable, SerialNumber, Version |
    ConvertTo-XML -As String -NoTypeInformation | Out-File -FilePath $savePath\\OnBoardDevices_Info.xml -ErrorAction Continue

gwmi Win32_OSRecoveryConfiguration | Select-Object Description, ExpandedDebugFilePath, KernelDumpOnly, Name, OverwriteExistingDebugFile, 
    SendAdminAlert, WriteToSystemLog |
    ConvertTo-XML -As String -NoTypeInformation | Out-File -FilePath $savePath\\OS_Recovery_Configuration.xml -ErrorAction Continue

gwmi Win32_PortConnector | Select-Object Name, ExternalReferenceDesignator, Description, ConnectorType, InternalReferenceDesignator,
    Manufacture, Model, PortType, SerialNumber, Tag, Version |
    ConvertTo-XML -As String -NoTypeInformation | Out-File -FilePath $savePath\\Port_Connector_Info.xml -ErrorAction Continue

gwmi Win32_Printer | Select-Object Name, __RELPATH, CapabilityDescriptions, Caption, DriverName, Location, Hidden, 
    KeepPrintedJobs, Network, DeviceID, PortName, PrintProcessor, Shared, SpoolEnabled, Status |
    ConvertTo-XML -As String -NoTypeInformation | Out-File -FilePath $savePath\\Printer_Info.xml -ErrorAction Continue

gwmi Win32_Process | Select-Object ProcessName, ProcessId |
    ConvertTo-XML -As String -NoTypeInformation | Out-File -FilePath $savePath\\Processes.xml -ErrorAction Continue

gwmi Win32_Processor | Select-Object Caption, CpuStatus, CurrentVoltage, Description, DeviceID, L2CacheSize, L3CacheSize,
    LoadPercentage, Name, Manufacturer, MaxClockSpeed, ProcessorID, NumberOfCores, NumberOfLogicalProcessors,
    SocketDesignation | 
    ConvertTo-XML -As String -NoTypeInformation | Out-File -FilePath $savePath\\Processor_Info.xml -ErrorAction Continue

gwmi Win32_Service | Select-Object Name, Caption, DesktopInteract, PathName, ServiceType, StartMode,  DisplayName, Started, 
    StartName |
    ConvertTo-XML -As String -NoTypeInformation | Out-File -FilePath $savePath\\Services.xml -ErrorAction Continue

gwmi Win32_Share | Select-Object Name, Type, AccessMask, AllowMaximum, Caption, Description, MaximumAllowed, Path | 
    ConvertTo-XML -As String -NoTypeInformation | Out-File -FilePath $savePath\\Share_Info.xml -ErrorAction Continue

#Lists statup services
gwmi Win32_StartupCommand | Select-Object Caption, Command, Location, User, Path, Description |
    ConvertTo-XML -As String -NoTypeInformation | Out-File -FilePath $savePath\\StartUp-Services.xml -ErrorAction Continue

gwmi Win32_SystemAccount |
    ConvertTo-XML -As String -NoTypeInformation | Out-File -FilePath $savePath\\System_Account_Info.xml -ErrorAction Continue

gwmi Win32_TimeZone | Select-Object StandardName, Caption, Bias, SettingID |
    ConvertTo-XML -As String -NoTypeInformation | Out-File -FilePath $savePath\\Clock_Settings.xml -ErrorAction Continue

gwmi Win32_OperatingSystem | Select-Object Caption, BuildType, BuildNumber, CSDVersion, Description, EncryptionLevel,
    InstallDate, LastBootUpTime, Manufacturer, NumberOfProcesses, NumberOfUsers, Organization, OSArchitecture, 
    RegisteredUser, SerialNumber, ServicePackMajorVersion, ServicePackMinorVersion, Version |
    ConvertTo-XML -As String -NoTypeInformation | Out-File -FilePath $savePath\\System_Info.xml -ErrorAction Continue

Get-Hotfix | Select-Object HotFixID, InstalledBy, InstalledOn | 
    ConvertTo-XML -As String -NoTypeInformation | Out-File -FilePath $savePath\\Installed_HotFixes.xml -ErrorAction Continue
Write-Host "Data Collection Complete"

} 
Catch
{
    $_| Out-File $savePath\\ErrorLog.txt -Append
}