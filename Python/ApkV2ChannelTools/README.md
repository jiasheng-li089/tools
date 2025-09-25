##### **ApkV2ChannelTools**

ApkV2ChannelTools is a Python 3-based script that adds additional information to APKs signed with Signature Scheme v2. It is currently used to add channel information to v2-signed APKs. It does this by appending a key-value pair to the APK's signing block. Note that the key stored in the signing block can only contain 4-byte data.


##### Depends On

* [Python3](https://www.python.org/download/releases/3.0/) (>= 3.5)

###### **Getting started**

```shell
python3 ./apkv2channeltools.py --source-apk=<sourceApk> --channels=<channelsFile> [--target-dir=<targetDir>] [--format=<formatStr>]
```

* sourceApk: the path of the APK signed with Scheme v2
* channelsFile：path of the file that stores channel information. One line is a channel. Lines starting with '#' are comments.
* targetDir：the target folder to save the generated APK files
* formatStr：file name format of the generated APK file. (e.g., app-%s.apk, %s is a placeholder for the channel)
* exit code：Returns 1 if the parameter is incorrect, returns 2 if the APK is not signed with scheme v2, and returns 0 if the APK is generated successfully.