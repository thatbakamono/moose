param(
    [switch][Alias('d')]$debugging = $false,
    [switch][Alias('l')]$logs = $false,
    [switch][Alias('r')]$release = $false
)

$command = [System.Text.StringBuilder]::new()

[void]$command.Append('qemu-system-x86_64 ')

if ($debugging) {
    [void]$command.Append('-S -gdb tcp:0.0.0.0:1234 ')
}

if ($logs) {
    [void]$command.Append('-d int -D ./log.txt ')
}

[void]$command.Append('-no-reboot -cpu qemu64,apic,fsgsbase -smp 4 -m 256M -drive file=moose.img,format=raw,if=ide -drive file=fat.img,format=raw -serial stdio ')

if ($release) {
    ./package.ps1 -r
}
else {
    ./package.ps1
}

Invoke-Expression $command.ToString()
