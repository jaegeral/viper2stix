# README #

This script is a helper script for Viper ([Viper.li](http://viper.li) available at [Github](https://github.com/botherder/viper)

### What is this repository for? ###

* This script is to create stix files based on your viper API
* 0.03
* [Learn Markdown](https://bitbucket.org/tutorials/markdowndemo)

### Usage ###

```
python viper2stix.py -h
usage: viper2stix.py [-h] [-H HOST] [-p PORT] -a [{test,find}]
                     [-m [MD5 [MD5 ...]]] [-t [TAGS [TAGS ...]]]
                     [-e EXPORT_FILENAME]

Viper API Actions: find / test

optional arguments:
  -h, --help            show this help message and exit
  -H HOST, --host HOST  Host of Viper API server
  -p PORT, --port PORT  Port of Viper API server
  -a [{test,find}], --action [{test,find}]
                        Action to be performed
  -m [MD5 [MD5 ...]], --md5 [MD5 [MD5 ...]]
                        list of md5 hashes
  -t [TAGS [TAGS ...]], --tags [TAGS [TAGS ...]]
                        list of tags to search for
  -e EXPORT_FILENAME, --export EXPORT_FILENAME
                        filename of stix file to be exported
```

### How do I get set up? ###

#### Installation

```
git clone the repository
pip install -r requirements.txt
```

#### Configuration

```
    cp sample.cfg config.cfg
    vi config.cfg
```


### Contribution guidelines ###

* Writing tests
* Code review
* Other guidelines

### Who do I talk to? ###

* Repo owner or admin
* Join ###viper on irc.freenode.net