#!/bin/bash

test_gen_path="/var/build/TestGenerator/target/"
TEMPLATEPATH="../Templates/"
EXTENSIONPATH="../Extensions/"
INPUT=TestsToGenerate.csv

slave="../SlaveUnderTest/SlaveUnderTest.dcpx"
rm -f ListOfTests.txt
rm -rf Procedures
mkdir Procedures
OLDIFS=$IFS
IFS=','


[ ! -f $INPUT ] && { echo "$INPUT file not found"; exit 99; }
while read template extension 
do
    [[ "$template" =~ ^[[:space:]]*# ]] && continue
	echo $template
	echo $extension
	TPname=proc_"${extension}"
	java -jar "${test_gen_path}"PathExpander-0.0.1-SNAPSHOT-shaded.jar  -dcpx "./${slave}" -UDP  -extension "${EXTENSIONPATH}""${extension}".xml -template "${TEMPLATEPATH}""${template}".xml -out Procedures/"${TPname}".xml
	echo $TPname >> ListOfTests.txt
done < $INPUT
IFS=$OLDIFS
