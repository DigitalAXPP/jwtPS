# .ExternalHelp jwtPS-help.xml

$files = Get-ChildItem -Path $PSScriptRoot -Filter *.ps1 -Recurse -File -Force

foreach ($file in $files) {
    . $file.FullName
}