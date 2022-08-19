<h1 align="center">
  PyExtractor 🐍
</h1>

<h1 align="center">
  Star please ⭐
</h1>

<p align="center"> 
  <kbd>
<img src="https://raw.githubusercontent.com/hissquare/images/main/image_2022-08-19_121139253.png"></img>
  </kbd>
</p>

<p align="center">
  <img src="https://img.shields.io/github/languages/top/hissquare/PyExtractor?style=flat-square"/>
  <img src="https://img.shields.io/github/last-commit/hissquare/PyExtractor?style=flat-square"/>
  <img src="https://sonarcloud.io/api/project_badges/measure?project=hissquare_PyExtractor&metric=ncloc"/>
  <img src="https://img.shields.io/github/stars/hissquare/PyExtractor?color=9acd32&label=Stars&style=flat-square"/>
  <img src="https://img.shields.io/github/forks/hissquare/PyExtractor?color=9acd32&label=Forks&style=flat-square"/>
</p>

<h4 align="center">
  <a href="https://discord.gg/YNbxve522h">🌌・Discord</a>
  ⋮
  <a href="https://github.com/hissquare/PyExtractor#-%E3%80%A2-getting-started-with-pyextractor">🐍・Getting started</a>
  ⋮
  <a href="https://github.com/hissquare/PyExtractor#-%E3%80%A2-changelog">📜・ChangeLog</a>
  ⋮
  <a href="https://cheataway.com/">🌑・Rdimo's Discord</a>
</h4>

<h2 align="center">
  PyExtractor was made by

Love ❌ code ✅
</h2>

<h2 align="center">
This repo is not mine. This repo has some slight modifications from the real one.
Rdimo's account has been flagged, not banned. Wait for it to be unflagged.
If you wanna use hazard, use https://github.com/dekrypted/Hazard-Archive
</h2>

---

## 🔰 〢 Features

✔ Fully Decompiles executables compiled with `pyinstaller` or `py2exe` (.exe --> .py) \
✔ Decrypts `Encrypted pyinstaller executables` and detects `pyarmor` \
✔ Configurable with json config \
✔ Exe must **NOT** be compiled with a python compiler in order for PyExtractor to check it\
✔ Checks file(s) for suspicious words, discord webhooks, discord invites, pastebins, urls, ips etc..\
✔ Check if the file hash is a known malware/virus \
✔ Fetches general info and sections about the binary

---

<img src="https://raw.githubusercontent.com/hissquare/images/main/image_2022-08-19_121113321.png" height="75%" width="75%"/>

## 🐍 〢 Getting started with PyExtractor!

First go ahead and download [Git](https://git-scm.com)

```sh-session
git@2.17.1 or higher
```

Open cmd in a chosen directory and do the following:

```sh-session
$ git clone https://github.com/hissquare/PyExtractor
...
$ cd .\PyExtractor
$ start setup.bat
...
$ echo Done!
```

### or

```bash
# Downloading as zip
$ Press big green code button top right of the screen
$ Press download ZIP
$ Drag the zip out to your desktop or some other place
$ Extract it. . .
...
$ Open the extracted folder
$ Run setup.bat
$ Done!
```

Make sure to open [config.json](https://github.com/hissquare/PyExtractor/blob/master/config.json) and change the settings to your preferences ⇣⇣⇣

```json
{
  "detailed_logs": false, //Console logs the binary sections and general info
  "error_stack_logs": true, //Send out full error message
  "time_stamp_logging": true, //Timestamp in the logs.log file

  "analyse_file": true, //Checks the file(s) for suspicious words, discord webhooks, discord invites, pastebins, urls, ips etc..
  "malware_recognize": true //Check if the file hash is a known malware/virus
}
```

## 🎉 〢 ideas/todo?

- Check for more things
- Better malware recognizer
- Remove chdir
- More config options

## 💀 〢 Download Links

- [Git](https://git-scm.com)
- [Python](https://python.org/downloads)

## 💭 〢 ChangeLog

```diff
v0.0.6 ⋮ 2022-8-19
+ Updated README.md

v0.0.5 ⋮ 2022-8-19
+ Revived PyExtractor
+ Fixed images
+ Updated / created files (banner.py) (utilities/common/README.md)

v0.0.4 ⋮ 2022-06-30
+ Loads of bug fixes
+ Cleaner code

v0.0.3 ⋮ 2022-05-09
+ Cleaner code

v0.0.2 ⋮ 2022-05-09
+ Bug fixes

v0.0.1 ⋮ 2022-05-09
+ Official release
```
