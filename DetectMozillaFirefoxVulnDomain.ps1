<#
.SYNOPSIS
    Mozilla Firefox Vulnerability Scanner for Domain
    
.DESCRIPTION
    Script in PowerShell to detect vulnerable versions of Mozilla Firefox in a Windows domain.
    
    CVEs: CVE-2019-17026 and previous.
   
   
    Considerations: 
        - Well configured WinRM on remote machines
        - Well configured firewall rules
        - Run the script with the Unrestricted or Bypass execution policies from Domain Controller
    
.NOTES
    File Name      : DetectMozillaFirefoxVulnDomain.ps1
    Author         : Author: Roberto Berrio (@v3nt4n1t0)
    Website        : https://github.com/v3nt4n1t0
    
    This software is provided under under the BSD 3-Clause License.
    See the accompanying LICENSE file for more information.
    
.LINK
    https://github.com/v3nt4n1t0/DetectMozillaFirefoxVulnDomain.ps1
    
.EXAMPLE
    .\DetectMozillaFirefoxVulnDomain.ps1
    
.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File 'E:\Pruebas C# PowerShell\DetectMozillaFirefoxVulnDomain.ps1'
    
.EXAMPLE
    iex(New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/v3nt4n1t0/DetectMozillaFirefoxVulnDomain.ps1/master/DetectMozillaFirefoxVulnDomain.ps1") 
#>

$c = Get-ADComputer -Properties IPv4Address -Filter {Enabled -eq $true}
$cred = Get-Credential

echo ""
if($cred){
    foreach ($cname in $c.name ) {
    
        if(test-connection -ComputerName $cname -Count 1 -Quiet){
            try{
            $session = New-PSSession -ComputerName $cname -Credential $cred
            Invoke-Command -Session $session -ScriptBlock{
                $machine = (Get-WmiObject -class win32_NetworkAdapterConfiguration -Filter 'ipenabled = "true"').ipaddress[0] + "," +[Environment]::GetEnvironmentVariable("ComputerName") 
            
                ls HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall | ForEach-Object -Process {      
            
                    if($_.GetValue("DisplayName") -like "Mozilla Firefox*"){
                    $mozilla = $_.GetValue("DisplayName")
                    $mozillaSplit = $mozilla.Split(" ")
                    $versionmozilla = $mozillaSplit[2]
                    $versionmozilla = $versionmozilla.Replace(".","")
                    }
                }

                ls HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | ForEach-Object -Process {
                        if($_.GetValue("DisplayName") -like "Mozilla Firefox*"){
                        $mozilla = $_.GetValue("DisplayName")
                        $mozillaSplit = $mozilla.Split(" ")
                        $versionmozilla = $mozillaSplit[2]
                        $versionmozilla = $versionmozilla.Replace(".","")
                        }
                }
     
            if(!$mozilla){"$machine -> Does not contain Mozilla Firefox"}
            elseif($versionmozilla -lt 7201){Write-Host -ForegroundColor Red "$machine -> Vulnerable!"}
            else{"$machine -> Non-vulnerable"}
            }

    
            Remove-PSSession -Session $session

            }catch{Write-Host -ForegroundColor Red -BackgroundColor Yellow "$cname is active, but the check can not be performed. Verify that the Administrator credentials are correct, that the remote computer has WinRM actived, or that Firewall rules are not blocking the connection"}
        }
        else{Write-Host -ForegroundColor DarkYellow "$cname does not respond to ping or the machine is off. Check that firewall rules are not blocking the connection"}
    }

Write-Host "`n To fix the vulnerability UPDATE Mozilla Firefox to 72.0.1 or higher`n"

}
else{Write-Host -ForegroundColor Red -BackgroundColor Yellow "`n Administrator credentials are required to run the script`n"}
