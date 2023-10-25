#!/usr/bin/bash
cat c z
touch 1 2
rm 1 2
mkdir 1d 2d
rmdir 1d 2d
gzip g g2
gzip -d g.gz g2.gz
split -l 1 s
zip z.zip z z1
zip z.zip z z1 z2
unzip z.zip
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
scp scp_text.txt root@172.17.0.2:/root
