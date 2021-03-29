#!/bin/bash

rm -rf logs
mkdir logs
rm -f summary.log

TESTER_PATH="/var/build/DCPTester/build/"
SLAVE="../SlaveUnderTest/build/dcpslave"

file=ListOfTests.txt

#for name in "${arr[@]}";do
while read name; do
	echo $name
	"${SLAVE}" > logs/slave_$name.log &
	pid_slave=$!
	echo $pid_slave
	${TESTER_PATH}dcp-tester -t Procedures/$name'.xml' --udp -v   | tee logs/tester_$name.log  && kill -KILL $pid_slave
	SUCCESS=$(grep "DCP Test Procedure successfull." logs/tester_$name.log) 
	if [ "$SUCCESS" ]; then
		#echo $name "$SUCCESS">> summary.log
		echo $name $(date +%Y-%m-%d_%H:%M:%S) "SUCCESS" >> summary.log
	else
		echo $name "FAILED" >>summary.log
	fi
	wait
done < $file
