#!/usr/bin/bash
cat c
cat c z
touch 1
rm 1
touch 1 2
rm 1 2
mkdir 1d
rmdir 1d
mkdir 1d 2d
rmdir 1d 2d
gzip g
gzip -d g.gz
gzip g g2
gzip -d g.gz g2.gz
split s
split -l 1 s
zip z.zip z
zip z.zip z1
zip z.zip z z1 z2
echo -e "y\nn\nr\nz3\n" | unzip z.zip
cp c c.bk
cp c c.bk
rm c.bk
cp c extra/
cp c extra/
rm extra/*
cp c m extra/
cp c m extra/
rm extra/*
mv c x
mv x c
mv c m extra/
cp extra/* ./
mv c m extra/
mv extra/* ./
rm xa* z.zip z3
sshpass -p 123 scp scp_text.txt root@172.17.0.2:/root
