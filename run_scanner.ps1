Set-Location -Path $PSScriptRoot
python scanner.py --target 127.0.0.1 --start 1 --end 1024
Read-Host -Prompt "Press Enter to exit"
