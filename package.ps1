param(
    [switch][Alias('r')]$release = $false
)

function package_moose([string]$mode) {
    wsl sh package_wsl.sh $mode
}

$mode = "debug"

if ($release) {
    $mode = "release"
}

if (-not (Test-Path -Path iso_root)) {
    New-Item -Path iso_root -ItemType Directory
    New-Item -Path iso_root/boot -ItemType Directory
    New-Item -Path iso_root/boot/limine -ItemType Directory
    New-Item -Path iso_root/EFI/BOOT -ItemType Directory
}

if (-not (Test-Path -Path limine)) {
    git clone https://github.com/limine-bootloader/limine.git --branch=v7.x-binary --depth=1

    Copy-Item limine/limine-bios.sys -Destination iso_root/boot/limine/
    Copy-Item limine/limine-bios-cd.bin -Destination iso_root/boot/limine/
    Copy-Item limine/limine-uefi-cd.bin -Destination iso_root/boot/limine/
    Copy-Item limine/BOOTX64.EFI -Destination iso_root/EFI/BOOT/
    Copy-Item limine/BOOTIA32.EFI -Destination iso_root/EFI/BOOT/
}

if ($release) {
    cargo build -r
}
else {
    cargo build
}

if (Test-Path -Path moose.iso) {
    $buildLastWriteTime = (Get-Item target/x86_64-moose/$mode/moose).LastWriteTime
    $isoLastWriteTime = (Get-Item moose.iso).LastWriteTime

    if ($buildLastWriteTime -ge $isoLastWriteTime) {
        package_moose -mode $mode
    }
}
else {
    package_moose -mode $mode
}
