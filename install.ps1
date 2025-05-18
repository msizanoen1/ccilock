$unlockPolicyId = (Get-Content policyInfo.json | ConvertFrom-Json).UnlockPolicyID
$unlockPolicyDestPath = "$ENV:SystemRoot\System32\CodeIntegrity\CIPolicies\Active\{$unlockPolicyId}.cip"
Copy-Item -Path out\DeviceProtection_Unlock.cip.p7 -Destination $unlockPolicyDestPath
citool --refresh --json
Write-Host
citool --update-policy out\DeviceProtection_Lock.cip.p7 --json
Write-Host
