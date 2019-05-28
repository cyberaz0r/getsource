# getsource
PHP source file parser and downloader

It fetches for a specific word in a PHP file, parses all the matching lines to retrieve the
filenames and their paths, and downloads the files recreating their directory structure
It can be used for instance to find from a PHP file all the other required PHP files by
fetching "require" or "include" keywords
Very useful for exploiting LFI from a vulnerable website by having just one PHP file
Usage:
$ python getsource.py  [-s, --server SERVER_URL/IP] [-w, --word-fetch WORD_TO_FETCH] [-f, --file-fetch PATH/TO/FILE]

OR

$ chmod +x getsource.py
$ ./getsource.py  [-s, --server SERVER_URL/IP] [-w, --word-fetch WORD_TO_FETCH] [-f, --file-fetch PATH/TO/FILE]

Dependencies:
requests Python package

To install:
$ pip install requests
