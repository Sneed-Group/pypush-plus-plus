> [!WARNING]
> Pypush is broken at the moment.  We thank you for your continued support of the project!  The Pypush demo will not work without significant modification to the code to remediate challenges posed as a response to third party iMessage clients growing in popularity. Also, this is meant for educational purposes ONLY. Do NOT use for evil!

# pypush++
`pypush++` is a POC demo of iMessage reverse-engineering (fork of "pypush" by "JJTech0130.")
It can currently register as a fake Apple ID, set up false encryption keys, and (soon) ***send and receive iMessages!*** Basically, like a cracked Minecraft client but for iMessage!

`pypush` is completely platform-independent, and does not require a Mac or other Apple device to use!

## Installation
It's pretty self explanatory:
1. `git clone https://github.com/JJTech0130/pypush`
2. If on a Mac, ensure `cmake` is installed. Otherwise, run `brew install cmake`
3. `pip3 install -r requirements.txt`
4. `python3 ./demo.py`

## Troubleshooting
If you have any issues, please feel free to debug and contribute to the code! :-)

## Operation
`pypush` will generate a `config.json` in the repository when you run demo.py. DO NOT SHARE THIS FILE.
It contains all the encryption keys necessary to log into you Apple ID and send iMessages as you.

Once it loads, it should prompt you with `>>`. Type `help` and press enter for a list of supported commands.

## Special Notes
### Unicorn dependency
`pypush` currently uses the Unicorn CPU emulator and a custom MachO loader to load a framework from an old version of macOS,
in order to call some obfuscated functions.

This is only necessary during initial registration, so theoretically you can register on one device, and then copy the `config.json`
to another device that doesn't support the Unicorn emulator. Or you could switch out the emulator for another x86 emulator if you really wanted to.

## "data.plist" and Mac serial numbers
This repository contains a sample [`data.plist`](https://github.com/JJTech0130/pypush/blob/main/emulated/data.plist), which contains the serial number and several other identifiers from a real Mac device. If you run into issues related to rate-limiting or messages failing to deliver, you may regenerate this file by cloning [nacserver](https://github.com/JJTech0130/nacserver) and running `build.sh` on a non-M1 Mac. It should place the generated file in the current directory, which you can then copy to the emulated/ folder in pypush.

## Licensing
This project is licensed under the terms of the [SSPL](https://www.mongodb.com/licensing/server-side-public-license). Portions of this project are based on [macholibre by Aaron Stephens](https://github.com/aaronst/macholibre/blob/master/LICENSE) under the Apache 2.0 license.
