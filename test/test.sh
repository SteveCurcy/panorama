#!/usr/bin/bash
cat c
touch 1
rm 1
mkdir 1d
rmdir 1d
gzip g
gzip -d g.gz
split s
zip z.zip z
unzip z.zip
cp c extra/
mv m extra/
mv extra/m ./
rm extra/c xa* z.zip
sshpass -p '123' scp scp_text.txt root@172.17.0.2:/root
