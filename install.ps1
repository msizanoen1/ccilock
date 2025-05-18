$unlockPolicyId = (Get-Content policyInfo.json | ConvertFrom-Json).UnlockPolicyID

$unlockPolicyDestPath = "$ENV:SystemRoot\System32\CodeIntegrity\CIPolicies\Active\{$unlockPolicyId}.cip"
Copy-Item -Path out\DeviceProtection_Unlock.cip.p7 -Destination $unlockPolicyDestPath
$result = (citool --refresh --json | ConvertFrom-Json).OperationResult
if ($result -ne 0) {
  Write-Host "An error occured: $result"
  exit $result
}

$result = (citool --update-policy out\DeviceProtection_Lock.cip.p7 --json | ConvertFrom-Json).OperationResult
if ($result -ne 0) {
  Write-Host "An error occured: $result"
  exit $result
}

Write-Host 'Reboot to complete installation'
