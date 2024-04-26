git clone https://github.com/limine-bootloader/limine.git --branch=v7.x-binary --depth=1

mkdir iso_root 
mkdir iso_root/boot
mkdir iso_root/boot/limine
mkdir iso_root/EFI/BOOT

cp -v target/x86_64-moose/debug/moose iso_root/boot/

cp -v limine.cfg limine/limine-bios.sys limine/limine-bios-cd.bin \
      limine/limine-uefi-cd.bin iso_root/boot/limine/
 
cp -v limine/BOOTX64.EFI iso_root/EFI/BOOT/
cp -v limine/BOOTIA32.EFI iso_root/EFI/BOOT/
 
xorriso -as mkisofs -b boot/limine/limine-bios-cd.bin \
        -no-emul-boot -boot-load-size 4 -boot-info-table \
        --efi-boot boot/limine/limine-uefi-cd.bin \
        -efi-boot-part --efi-boot-image --protective-msdos-label \
        iso_root -o moose.iso
 
./limine/limine.exe bios-install moose.iso
