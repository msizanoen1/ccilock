$xml = [xml](Get-Content templates\DeviceProtection_Lock.xml)

foreach ($deny in $xml.SiPolicy.FileRules.GetElementsByTagName("Deny")) {
  $denyRuleID = $deny.ID
  Write-Host "<ExceptDenyRule DenyRuleID=`"$denyRuleID`" />"
}
