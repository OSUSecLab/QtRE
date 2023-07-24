# QtRE

QtRE is a tool tailored for reverse engineering [Qt](https://www.qt.io/) binaries. It is developed atop the [Ghidra](https://ghidra-sre.org/) reverse engineering framework in Java language, and its analysis is conducted at the Ghidra's [PCode IR](https://ghidra.re/ghidra_docs/api/ghidra/program/model/pcode/PcodeOp.html) level. Given a Qt-based binary program, QtRE leverages domain-specific insights in Qt to accomplish the following tasks:

- Recovering Qt-specific function callbacks. QtRE will identify all the `QObject::connect()` type of functions and resolve the callback connection between the function caller (the signal) and the function callee (the callee). Such relationships cannot be resolved by state-of-the-art decompilers by default.

- Recovering Qt-specific class metadata. QtRE will repurpose the dynamic introspection mechanism of Qt to extract class symbols (e.g., defined signals, slots, attributes, parameters, return types, etc.). It also uses Ghidra's emulator to compute the relative addresses of class attributes.

- Light-weight taint analysis. We provide a simple use case of taint analysis operating on Ghidra's PCode level.

For more details, please refer to our full paper (in USENIX Security 2023): [Egg Hunt in Tesla Infotainment: A First Look at Reverse Engineering of Qt Binaries](https://www.usenix.org/system/files/sec23summer_181-wen-prepub.pdf).



## Prerequisites

QtRE was developed and tested on Java 11.0.19 and Ghidra [v9.2.2](https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_9.2.2_build). Please carefully select your build environment before proceeding, as some Ghidra APIs used in this project may be deprecated in newer versions.

To build this project, we recommend using [Apache Maven](https://maven.apache.org/). Below are the detailed instructions:


### Apache Maven

Please refer to [https://maven.apache.org/install.html](https://maven.apache.org/install.html). If you use Debian-based Linux distributions, simply run:

```sudo apt install maven```

The maven build config file to build this project is `pom.xml` in the root folder, which specifies all the project dependencies and build environment (JAVA version). Please change them accordingly to your settings.


### Ghidra Jar Library

QtRE depends on the Ghidra library. Since this library dependency cannot be automatically resolved by Maven, you need to build it on your own. To build the library on your machine, please refer to [https://ghidra-sre.org/InstallationGuide.html#RunJar](https://ghidra-sre.org/InstallationGuide.html#RunJar).

After you successfully build the JAR file, rename it as `ghidra.jar` and put it under `<QtRE_ROOT>/lib/`.
 

### Compile QtRE with Maven

Go to the project's main folder and simply run:

```mvn package```

After successful compilation, QtRE will be generated as a JAR executable (`QtRE-1.0.0.jar`).


## Running instructions

Currently, QtRE operates in Ghidra's [headless analyzer mode](https://static.grumpycoder.net/pixel/support/analyzeHeadlessREADME.html) (command-line-based, fully independent from Ghidra's GUI). As such, we provide a bash running script `run.sh`.

```
$ ./run.sh 
Usage: QtRE run.sh [-h] -p qtre_path -c config_path [-g ghidra_path] [--analyze-connect] [--analyze-meta]
Example: ./run.sh -p QtRE-1.0.0.jar -c env.json --analyze-connect --analyze-meta
Argument descriptions: 
  -h, --help: Display this help message.
  -p, --qtre-path: Path to the compiled QtRE Jar executable.
  -c, --config-path: Path to the json configuration file.
  -g, --ghidra-path: Path to Ghidra jar library (default: ./lib/ghidra.jar).
  --analyze-connect: Enable analysis on Qt Connect.
  --analyze-meta: Enable analysis on Qt Metadata.
```

To run QtRE, you need to provide two mandatory arguments to the run script: the compiled QtRE JAR executable and a json config file. A template json config file has been provided (`env.json`), which allows you to configure several key parameters and input paths. The `example_qt_bins/input_bins` specifies the paths for binaries that will be taken as inputs to QtRE. Explanation of several key config parameters:

- `DIRECTORY_NAME` specifies the directory to initialize a Ghidra project for QtRE. Select a directory where you have ample space.
- `OUTPUT_DIR` specifies the output directory.
- `BINARY_FILE_LIST` specifies the list of Qt binaries to be analyzed by QtRE. Each line should be the absolute path (or relative path to the execution folder) of a binary. 
- `LANGUAGE_NAME` sets the architecture / endianness. Check [https://github.com/NationalSecurityAgency/ghidra/tree/master/Ghidra/Processors](https://github.com/NationalSecurityAgency/ghidra/tree/master/Ghidra/Processors) for the supported types.
- `DECOMPILE_MODE` sets the Ghidra's decompiler mode. See [https://ghidra.re/ghidra_docs/api/ghidra/program/model/lang/CompilerSpecID.html](https://ghidra.re/ghidra_docs/api/ghidra/program/model/lang/CompilerSpecID.html) for details.


## Running example

We have provided an example Qt binary (`example_qt_bins/example.so`). 

You can run it with the following command:

```./run.sh -p QtRE-1.0.0.jar -c env.json --analyze-connect --analyze-meta```

This will run QtRE to analyze the Qt connect callback and class metadata.

Afterwards, the example outputs are generated in `./output/Connect/example.so.json` and `./output/Meta/example.so.json`. These json results include the callback relationships extracted as well as the Qt class metadata and symbols recovered by QtRE.



## Limitation & TODOs

QtRE currently supports a few architectures: `x86:LE:32`, `x86:LE:64`, and `ARM:LE:32:v8` (per Ghidra's supporting language description [https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Processors](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Processors)).

TODOs:

- Develop Ghidra plugin mode to run QtRE within Ghidra's GUI.
- Develop plugins to let Ghidra interpret QtRE's output and aid manual reverse engineering.


## Citation

Please cite our paper if you develop a research work or product based on QtRE.

```
@inproceedings{QtRE:security23,
  title     = {Egg Hunt in Tesla Infotainment: A First Look at Reverse Engineering of Qt Binaries},
  author    = {Wen, Haohuang and Lin, Zhiqiang},
  booktitle = {32nd {USENIX} Security Symposium ({USENIX} Security 23)},
  address   = {Anaheim, CA},
  url       = {https://www.usenix.org/conference/usenixsecurity23/presentation/wen},
  month     = {August},
  year      = 2023,
}
```
