#!/bin/bash

#Watcful_IP - Find RSA KEYs in TP-Link firmware and write them to include dir
#VERSION=0.0.1
#VDATE=29-12-24

CORRECT_SHA256="0a7857d40fb02ff1b8d3cbce769e6c402a82a8094b4af553c54e4ffbdc4b6e64"

BINWALK=`which binwalk`
[ -z "$BINWALK" ] && echo Error: no binwalk found please install it && exit 1


TMP_DIR=tmp.fwextract
mkdir "$TMP_DIR"
cd "$TMP_DIR"



if [ ! -d fw ]; then
	mkdir -p fw
	cd fw
	wget 'http://download.tplinkcloud.com/firmware/ax6000v2-up-ver1-1-2-P1[20230731-rel41066]_1024_nosign_2023-07-31_11.26.17_1693471186048.bin.rollback'
	wget 'http://download.tplinkcloud.com/firmware/Tapo_C210v1_en_1.3.1_Build_221218_Rel.73283n_u_1679534600836.bin'
	cd ..
fi


echo -e "\nExtracting '../fw/ax6000v2-up-ver1-1-2-P1[20230731-rel41066]_1024_nosign_2023-07-31_11.26.17_1693471186048.bin.rollback'  .......\n"

binwalk -e -C 1 fw/'ax6000v2-up-ver1-1-2-P1[20230731-rel41066]_1024_nosign_2023-07-31_11.26.17_1693471186048.bin.rollback' 
RSAKEY_1=`find -type f -name nvrammanager | head -n 1 | xargs strings | grep BgIAAAwk`
echo -e "\nRSAKEY_1 is $RSAKEY_1\n"

echo -e "Extracting ../fw/Tapo_C210v1_en_1.3.1_Build_221218_Rel.73283n_u_1679534600836.bin .......\n"
binwalk  -C 0 -e fw/Tapo_C210v1_en_1.3.1_Build_221218_Rel.73283n_u_1679534600836.bin
RSAKEY_0=`find -type f -name slpupgrade | head -n 1 | xargs strings | grep BgIAAAwk`

echo -e "\nRSAKEY_0 is $RSAKEY_0\n"

 
CALC_SHA256=`echo -n "$RSAKEY_0 $RSAKEY_1" | sha256sum | awk '{print $1}'`

#echo $CALC_SHA256

if [ "$CORRECT_SHA256" != "$CALC_SHA256" ]; then
	echo Extracted RSA keys do not match expected data - exiting.....
	exit 1
else
	echo Extracted RSA keys match expected data!
	echo -n "$RSAKEY_0" > RSA_0
	xxd -i RSA_0 > ../include/RSA_0.h	
	echo -n "$RSAKEY_1" > RSA_1
	xxd -i RSA_1 > ../include/RSA_1.h
	echo RSA keys written to include - ready for make
fi

cd ..

echo -e "\nOK to remove $TMP_DIR if you like with   rm -rf $TMP_DIR\n"

#rm -rf 	"$TMP_DIR"

