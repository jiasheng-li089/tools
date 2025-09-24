## ImageOptimize

ImageOptimize is based on Python3. This tool can scan all the PNG and JPG files in a specific directory and upload them to the tinypng server for compression. After the compression, it will download these files and replace the original ones. It also marks these compressed files to avoid repeatedly processing them.

##### Depends On

* [Python3](https://www.python.org/download/releases/3.0/) (>= 3.5)
* [Pillow](https://pypi.python.org/pypi/Pillow/5.0.0) (>= 5.0.0)
* [Piexif](https://pypi.python.org/pypi/piexif) (>=1.1.0)
* [Requests](https://pypi.python.org/pypi/requests) (>=2.18.0)
* [threadpool](https://pypi.python.org/pypi/threadpool/1.3.2)(>=1.3.2)

##### Getting started

```shell
python3 ./optimizemain.py --token=<tokenFile> [--path=<path>] [--ignore=<ignoreFile>]
```

* tokenFile：Save tokens registered in [Tiny](https://tinypng.com/developers). Lines beginning with ‘#’ are considered comments.
* path：Specify the folder that needed to be scanned.
* ignoreFile：Specify the files that should be ignored. Fully matching and regex pattern matching are support. Lines beginning with '#' are considered comments.