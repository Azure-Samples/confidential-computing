#.WinGuestAttestation.ps1 v2
# Simon Gallagher, Microsoft https://github.com/vinfnet
# NO warranties implied, use at your own risk
# Review and customize code before running in your environment
# Script to run on a Confidential Virtual machine (https://aka.ms/accdocs) to check if it is running on a Confidential VM (CVM) and attested by Azure Attestation service
# More detailed version https://github.com/Azure/confidential-computing-cvm-guest-attestation/tree/main/cvm-platform-checker-exe
# it will download a sample app from GitHub to get the JWT token from the attestation service and decode it
# it will install + uninstall dependencies like VC Redist and JWTDetails (https://github.com/darrenjrobinson/JWTDetails) PowerShell module

#force install of NuGet provider, otherwise script prompts for install on a 'fresh' VM
Install-PackageProvider -Name NuGet -force
write-output "Installing JWTDetails module"
install-module -name JWTDetails -Force
write-output "Downloading attestation client binaries"
Invoke-WebRequest -uri https://github.com/Azure/confidential-computing-cvm-guest-attestation/raw/main/cvm-platform-checker-exe/Windows/cvm_windows_attestation_client.zip -OutFile windowsattestationclient.zip
Expand-Archive -Path .\windowsattestationclient.zip -DestinationPath . -force # added -force to overwrite existing files, for example if you run the script multiple times
cd .\cvm_windows_attestation_client

write-output "Installing VC redistributable"
$vcProcess = Start-Process -FilePath ".\VC_redist.x64.exe" -ArgumentList "/install /passive /norestart" -Wait -PassThru

# Check the exit code of the process
if ($vcProcess.ExitCode -eq 3010) {
    Write-Host "VC Redistributable requires a reboot, please reboot the VM and run the script again." -ForegroundColor Yellow
    exit $vcProcess.ExitCode
} elseif ($vcProcess.ExitCode -ne 0) {
    Write-Host "Error: VC redistributable installation failed with exit code $($vcProcess.ExitCode)" -ForegroundColor Red
    exit $vcProcess.ExitCode
} else {
    Write-Host "VC redistributable installed successfully."
}

#get the JWT output from the attestation service
$attestationJWT = .\AttestationClientApp.exe -a "sharedweu.weu.attest.azure.net" -n "12345" -o token
$attestationJSON = Get-JWTDetails($attestationJWT)
Write-Host "This " $attestationJSON."x-ms-azurevm-ostype" " OS is running on " $attestationJSON."x-ms-isolation-tee"."x-ms-attestation-type" "VM hardware"

if ($attestationJSON."x-ms-isolation-tee"."x-ms-compliance-status" -eq "azure-compliant-cvm") 
{
    Write-Host "This VM is an Azure compliant CVM attested by " $attestationJSON.iss -ForegroundColor Green
}
else {
    Write-Host "This VM is NOT an Azure compliant CVM" -ForegroundColor Red
}
# optional - uninstall VC redist and PowerShell module afterwards
write-output "Removing VC redistributable"
$vcUninstallProcess = Start-Process -FilePath ".\VC_redist.x64.exe" -ArgumentList "/uninstall /passive /norestart" -Wait -PassThru

# Check the exit code of the process
if ($vcUninstallProcess.ExitCode -ne 0) {
    Write-Host "Error: VC redistributable uninstallation failed with exit code $($vcUninstallProcess.ExitCode)" -ForegroundColor Red
    exit $vcUninstallProcess.ExitCode
} else {
    Write-Host "VC redistributable uninstalled successfully."
}

write-output "Removing JWTDetails module"
Uninstall-module -name JWTDetails -Force
cd ..
write-output "Cleaning-up files"
remove-item -path .\cvm_windows_attestation_client -recurse
remove-item -path .\windowsattestationclient.zip -Recurse
write-output "Finished"