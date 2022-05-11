#Function 1 -Enable File Download on Windows Server Internet Explorer
Function Enable-IEFileDownload
{
    $HKLM = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
    $HKCU = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
    Set-ItemProperty -Path $HKLM -Name "1803" -Value 0 -ErrorAction SilentlyContinue -Verbose
    Set-ItemProperty -Path $HKCU -Name "1803" -Value 0 -ErrorAction SilentlyContinue -Verbose
    Set-ItemProperty -Path $HKLM -Name "1604" -Value 0 -ErrorAction SilentlyContinue -Verbose
    Set-ItemProperty -Path $HKCU -Name "1604" -Value 0 -ErrorAction SilentlyContinue -Verbose
}

#Function 2 -Install Chocolatey
Function InstallChocolatey
{   
    #[Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls
    #[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls" 
    $env:chocolateyUseWindowsCompression = 'true'
    Set-ExecutionPolicy Bypass -Scope Process -Force; Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1')) -Verbose
    choco feature enable -n allowGlobalConfirmation

}
#Function 3 -Disable PopUp for network configuration

Function DisableServerMgrNetworkPopup
{
    Set-Location -Path HKLM:\
    New-Item -Path HKLM:\System\CurrentControlSet\Control\Network -Name NewNetworkWindowOff -Force 

    Get-ScheduledTask -TaskName ServerManager | Disable-ScheduledTask -Verbose
}

#Function 4
Function CreateLabFilesDirectory
{
    New-Item -ItemType directory -Path C:\LabFiles -force
}
#Function 5
Function Show-File-Extension
{
    $key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
    Set-ItemProperty $key HideFileExt 0
    Stop-Process -processname explorer
}

#Function 6 -Install Azure Powershell Az Module
Function InstallAzPowerShellModule
{
    choco install az.powershell -y -force

}

#Function 7
Function InstallAzCLI
{
    choco install azure-cli -y -force
}

#Function 8
Function Install7Zip
{

    choco install 7zip.install -y -force

}

#Function 9
Function InstallEdgeChromium
{

    choco install microsoft-edge -y -force
    $WshShell = New-Object -comObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut("C:\Users\Public\Desktop\Azure Portal.lnk")
    $Shortcut.TargetPath = """C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"""
    $argA = """https://portal.azure.com"""
    $Shortcut.Arguments = $argA 
    $Shortcut.Save()

}
#Function 10   
Function DisableShutDownEventPopUp   
{
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\" -Name "Reliability" –Force
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Reliability' `
                    -Name ShutdownReasonOn `
                    -Value 0x00000000 `
                    -PropertyType DWORD `
                    -Force 
    New-Item -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows NT\" -Name "Reliability" –Force
    New-ItemProperty -Path 'HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows NT\Reliability' `
                    -Name ShutdownReasonOn `
                    -Value 0x00000000 `
                    -PropertyType DWORD `
                    -Force
} 


Enable-IEFileDownload
InstallChocolatey
DisableServerMgrNetworkPopup
CreateLabFilesDirectory
Show-File-Extension
InstallAzPowerShellModule
InstallAzCLI
Install7Zip
InstallEdgeChromium
DisableShutDownEventPopUp
