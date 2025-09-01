
rule Office_Macro_Artifacts
{
  strings:
    $a = "Attribute VB_Name"
    $b = "Sub AutoOpen"
    $c = "Document_Open"
  condition:
    any of them
}
