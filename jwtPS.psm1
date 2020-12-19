$files = Get-ChildItem -Path $PSScriptRoot -Filter .ps1 -Recurse -File

foreach ($file in $files) {
    . $file.FullName
}