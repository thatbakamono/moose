sudo mount /dev/loop5 /mnt/image
sudo cp ./target/x86_64-moose/release/moose /mnt/image/boot
sudo umount /mnt/image