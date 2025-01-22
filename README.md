# List Process Handles

## Build Requirements

* Visual Studio 2022
* `phnt` - collection of Native API header files; you can get it here: [https://github.com/winsiderss/systeminformer/tree/master/phnt](https://github.com/winsiderss/systeminformer/tree/master/phnt).

## Configuring project

1. Open a terminal or [Git Bash on Windows](https://github.com/git-for-windows/git).
2. Goto your projects directory, for example: `cd C:\Projects\CPP`.
3. Clone `systeminformer` repository: `git clone https://github.com/winsiderss/systeminformer.git`.
4. Open `ListProcessHandles.sln` in Visual Studio.
5. Open `ListProcessHandles Property Pages` dialog.
6. Select `All Configurations` and `All Platforms`.
7. Click `Configuration Properties`.
8. Click `VC++ Directories`.
6. Add the path to the phnt include directory (for example: `C:\Projects\CPP\systeminformer\phnt\include`) into `Include Directories`.

## Usage

```shell
listph.exe [-h] (-p NAME | -t TYPE) [-f PATH] [--terminate] [--mem-size MEM_SIZE] [--running-time TIME] [--silent] [--print-handles yes/no]
```

### options

```text
  -h, --help                        show help message and exit
  -p [NAME], --process-name [NAME]  filter processes whose name is NAME
  -t [TYPE], --handle-type [TYPE]   filter handles whose type is TYPE
  -f [PATH], --file-path [PATH]     filter file handles that contain PATH in their path
  --terminate                       terminate filtered processes
  --mem-size [MEM_SIZE]             terminate filtered processes that consume more memory than MEM_SIZE (in megabytes)
  --running-time [TIME]             terminate filtered processes that run longer than TIME (in seconds)
  --silent                          silent terminate mode
  --print-handles [yes/no]          print filtered handles info; default: yes
```

### handle types
```text
  Directory
  SymbolicLink
  Token
  Process
  Thread
  Event
  EventPair
  Mutant
  Semaphore
  Timer
  Profile
  WindowStation
  Desktop
  Section
  Key
  Port
  WaitablePort
  IoCompletion
  File
```
