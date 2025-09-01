
rule Suspicious_Powershell_Use
{
  strings:
    $a = "powershell -nop -w hidden"
    $b = "Invoke-Expression"
    $c = "New-Object Net.WebClient"
    $d = "FromBase64String"
  condition:
    2 of them
}
