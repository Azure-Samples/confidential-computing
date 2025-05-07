# This script remotely call the WindowsAttest.ps1 script inside a Confidential VM in Azure to check if it is running on a Confidential VM (CVM) and attested by the Azure Attestation service. It uses the `Invoke-AzVMRunCommand` cmdlet to execute the script on the specified VM.

# Variables
$ResourceGroupName = "your resource group name" # Replace with your resource group name
$VMName = "your VM name" # Replace with your VM name

# Read the script content from GitHub (same repo as this script)
$ScriptUrl = "https://raw.githubusercontent.com/vinfnet/simple-cvm-cmk-demo/main/WindowsAttest.ps1"
$ScriptContent = Invoke-WebRequest -Uri $ScriptUrl -UseBasicParsing | Select-Object -ExpandProperty Content

# Execute the script INSIDE the Azure CVM using PowerShell triggered from your local machine
Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName `
    -VMName $VMName `
    -CommandId "RunPowerShellScript" `
    -ScriptString $ScriptContent