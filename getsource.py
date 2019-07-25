#!/usr/bin/python

'''

@Author: CybeRazor
@Title: getsource.py
@Date: 19/05/2019
@License: GPLv3

@Description:
PHP source file parser and downloader

It fetches for a specific word in a PHP file, parses all the matching lines to retrieve the
filenames and their paths, and downloads the files recreating their directory structure

It can be used for instance to find from a PHP file all the other required PHP files by
fetching "require" or "include" keywords

Very useful for exploiting LFI from a vulnerable website by having just one PHP file

@Usage:
$ python getsource.py  [-s, --server SERVER_URL/IP] [-w, --word-fetch WORD_TO_FETCH] [-f, --file-fetch PATH/TO/FILE]
OR
$ chmod +x getsource.py
$ ./getsource.py  [-s, --server SERVER_URL/IP] [-w, --word-fetch WORD_TO_FETCH] [-f, --file-fetch PATH/TO/FILE]

@Dependencies:
requests Python package

To install:
$ pip install requests

'''

import requests, sys, os
from getopt import getopt, GetoptError
from time import time

# function that prints error in stderr, usage and exits
def error(err):
	sys.stderr.write(err)
	sys.stderr.write('\nUsage: python getsource.py  [-s, --server SERVER_URL/IP] [-w, --word-fetch WORD_TO_FETCH] [-f, --file-fetch PATH/TO/FILE]\n')
	sys.exit(1)

# function for string parsing
def parse_string(string):
	
	'''
		not_parsed.txt is a list of matches not parsed because they didn't represent a specific URL location
		for instance if we choose "include" as keyword "include('core/templates/'.$this->template.'/test.php')" isn't a parsable URL
		or just comments that includes matching keywords, for instance "//include the database configuration file"
	'''
	
	with open('not_parsed.txt', 'a') as not_parsed:
		
		# removing spaces
		string_to_parse = ''.join(string.split())
		
		# checking if ' or " are in the string, not parsing otherwise
		if "'" in string_to_parse:
			parsing_string = string_to_parse.split("'")[1]
		elif '"' in string_to_parse:
			parsing_string = string_to_parse.split('"')[1]
		else:
			not_parsed.write(string_to_parse + '\n')
			print('Added to not_parsed: ' + string_to_parse)
			return False
		
		# removing '.' if first char
		if parsing_string[0] == '.':
			parsing_string = parsing_string[1:]
		
		# adding '/' if not first char
		if parsing_string[0] != '/':
			parsing_string = '/' + parsing_string
		
		# not parsing if the entire string is just '/php'
		if parsing_string == '/php':
			not_parsed.write(string_to_parse + '\n')
			print('Added to not_parsed: ' + string_to_parse)
			return False
		
		# if last character is a '/' not parsing
		if parsing_string[-1:] == '/':
			not_parsed.write(string_to_parse + '\n')
			print('Added to not_parsed: ' + string_to_parse)
			return False
		
	return parsing_string

# function for file downloading
def download_file(url, filepath, filename):
	print('Getting file from: ' + url)
	# checking if internet connection is available
	try:
		# allowing stream for this request
		r = requests.get(url, stream = True)
	except requests.exceptions.ConnectionError:
		error('Error: Internet connection not available')
	if r.status_code == 200:
		# retrieving filesize from Content-Lenght header
		total_length = int(r.headers['Content-Length'])
		# initializing progressbar var
		dl = 0
		# opening file in write-binary mode
		with open(filename, 'wb') as file_save:
			# saving content in chunks of 4096 bytes (4KiB)
			for chunk in r.iter_content(chunk_size = 4096):
				if chunk:
					# incrementing the progress bar
					dl += len(chunk)
					file_save.write(chunk)
					done = int(50 * dl / total_length)
					# writing the progress bar
					sys.stdout.write('\r[%s%s]' % ('=' * done, ' ' * (50-done)))
					sys.stdout.flush()
		print('\nSaved file in ' + filepath)
	return r.status_code

# function that logs any request error
def error_request(file_fetch, url, filepath, filename, status_code):
	print('\nERROR: Status code not OK, not saving response')
	with open('bad_requests.txt', 'a') as bad_req:
		bad_req.write('File fetch = ' + file_fetch + '\nURL = ' + url + '\nFile path = ' + filepath + '\nFile name = ' + filename + '\nStatus code = ' + str(status_code) + '\n\n')
	print('Check bad_requests.txt for more details\n')

# main function
def main(argv):
	
	# getting current time
	start_time = time()
	
	# retrieving arguments
	server_addr = ''
	word_fetch = ''
	file_fetch = ''
	try:
		opts, args = getopt(argv, 's:w:f:', ['server=', 'word-fetch=', 'file-fetch='])
	except GetoptError:
		error('Error while fetching args')
	for opt, arg in opts:
		if opt in ('-s', '--server'):
			server_addr = arg
		elif opt in ('-w', '--word-fetch'):
			word_fetch = arg
		elif opt in ('-f', '--file-fetch'):
			file_fetch = arg
	if not server_addr:
		error('Error: Server address not specified')
	if not word_fetch:
		error('Error: Word to fetch not specified')
	if not file_fetch:
		error('Error: File to fetch not specified')
	elif not os.path.isfile(file_fetch):
		error('Error: File to fetch doesn\'t exist')
	
	# creating a list containing all the lines in which the keyword is found
	with open(file_fetch, 'r') as match_file:
		matchlist = [line for line in match_file if word_fetch in line]
	
	# if there are no matches, stop the script
	if len(matchlist) == 0:
		print('There are no matches for "' + word_fetch + '" in "' + file_fetch + '"')
		sys.exit(2)
	
	# if server URL/IP does not start with http, append 'http://' to avoid Python requests library error
	if server_addr[:4] != 'http':
		server_addr = 'http://' + server_addr
	
	# saving current directory pathname
	orig_dir = os.getcwd()
	
	# initializing counters
	request_counter = 0
	not_parsed_counter = 0
	already_exists_counter = 0
	
	for word in matchlist:
		
		# parsing string from matchlist lines
		parsed = parse_string(word)
		if not parsed:
			not_parsed_counter += 1
			continue
		# appending the parsed string to the url
		url_request = server_addr + parsed
		# getting the filename and the pathname by splitting the string
		arr = parsed.split('/')
		# the last part will be the filename
		filename = arr[len(arr) - 1]
		# all the previous parts are directories
		for i in range(1, len(arr) - 1):
			# if the directory does not exist: create it, then change working directory into it
			if not os.path.isdir(arr[i]):
				os.mkdir(arr[i])
			os.chdir(arr[i])
		# if file already exists do not send request
		if os.path.isfile(filename):
			print('File "' + parsed + '" already exists, request not sent')
			already_exists_counter += 1
			# go back to main directory
			os.chdir(orig_dir)
		else:
			# sending request and retrieving status code
			r = download_file(url_request, parsed, filename)
			os.chdir(orig_dir)
			# if status code not OK
			if r != 200:
				# log error to bad_requests.txt file
				error_request(file_fetch, url_request, parsed, filename, r)
			request_counter += 1
	
	print('\nDone.')
	print(str(request_counter) + ' HTTP request sent')
	print(str(not_parsed_counter) + ' files not parsed')
	print(str(already_exists_counter) + ' files already existed')
	
	# calculating elapsed time by subtracting current time with start time
	elapsed_time = time() - start_time
	print('Elapsed time: ' + str(elapsed_time) + ' seconds')

# calling main function
if __name__ == '__main__':
	main(sys.argv[1:])
