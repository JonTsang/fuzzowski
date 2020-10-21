#  Fuzzowski

#

[![Travis](https://travis-ci.com/nccgroup/fuzzowski.svg?branch=master)](https://travis-ci.com/nccgroup/fuzzowski)

The idea is to be the Network Protocol Fuzzer that we will __want__ to use.

The aim of this tool is to assist during the whole process of fuzzing a network protocol, 
allowing to define the communications, helping to identify the "suspects" of crashing a service,
and much more

#### Last Changes

[16/12/2019]
* **Data Generation modules** fully recoded (Primitives, Blocks, Requests)
  * Improved Strings fuzzing libraries, allowing also for custom lists, files and callback commands
  * **Variable** data type, which takes a variable set by the session, the user or a Response
* **Session** fully recoded. Now it is based on **TestCase**s, which contains all the information needed to perform the request, check the response, store data such as errors received, etc.
* **Responses** added. Now you can define responses with s_response(), This allows to check the response from the server, set variables and even perform additional tests on the response to check if something is wrong
* **Monitors** now automatically mark TestCases as suspect if they fail
* Added the **IPP (Internet Printing Protocol)** Fuzzer that we used to find several vulnerabilities in different printer brands during our printers research project (https://www.youtube.com/watch?v=3X-ZnlyGuWc&t=7s) 

#### Features
* Based on Sulley Fuzzer for data generation [https://github.com/OpenRCE/sulley]
* Actually, forked BooFuzz (which is a fork of Sulley) [https://github.com/jtpereyda/boofuzz ]
* Python3
* Not random (finite number of possibilities)
* Requires to “create the packets” with types (spike fuzzer style)
* Also allows to create ""Raw"" packets from parameters, with injection points (quite useful for fuzzing simple protocols)
* Has a nice console to pause, review and retest any suspect (prompt_toolkit ftw)
* Allows to skip parameters that cause errors, automatically or with the console
* Nice print formats for suspect packets (to know exactly what was fuzzed)
* It saves PoCs as python scripts for you when you mark a test case as a crash
* Monitor modules to gather information of the target, detecting odd behaviours and marking suspects
* Restarter modules that will restart the target if the connection is lost (e.g. powering off and on an smart plug)

#### Protocols implemented
* **LPD (Line Printing Daemon)**: Fully implemented
* **IPP (Internet Printing Protocol)**: Partially implemented
* **BACnet (Building Automation and Control networks Protocol)**: Partially implemented
* **Modbus (ICS communication protocol)**: Partially implemented

#### Installation
```
virtualenv venv -p python3
source venv/bin/activate
pip install -r requirements.txt
```
#### Help
```
usage: python -m fuzzowski [-h] [-p {tcp,udp,ssl}] [-b BIND] [-st SEND_TIMEOUT] [-rt RECV_TIMEOUT] [--sleep-time SLEEP_TIME]
                   [-nc] [-tn] [-br] [-nr] [-nrf] [-cr] [--threshold-request CRASH_THRESHOLD_REQUEST]
                   [--threshold-element CRASH_THRESHOLD_ELEMENT] [--error-fuzz-issues] [-c CALLBACK | --file FILENAME]
                   [-i PATH [PATH ...]] -f {bacnet,dhcp,ipp,lpd,modbus,telnet_cli,tftp,raw}
                   [-r FUZZ_REQUESTS [FUZZ_REQUESTS ...]] [--restart module_name [args ...]]
                   [--restart-sleep RESTART_SLEEP_TIME]
                   [--monitors {BACnetMon,IPPMon,modbusMon} [{BACnetMon,IPPMon,modbusMon} ...]] [--path PATH]
                   [--document_url DOCUMENT_URL]
                   host port

Fuzzowski Network Fuzzer

positional arguments:
  host                  Destination Host
  port                  Destination Port

optional arguments:
  -h, --help            show this help message and exit

Connection Options:
  -p {tcp,udp,ssl}, --protocol {tcp,udp,ssl}
                        Protocol (Default tcp)
  -b BIND, --bind BIND  Bind to port
  -st SEND_TIMEOUT, --send_timeout SEND_TIMEOUT
                        Set send() timeout (Default 5s)
  -rt RECV_TIMEOUT, --recv_timeout RECV_TIMEOUT
                        Set recv() timeout (Default 5s)
  --sleep-time SLEEP_TIME
                        Sleep time between each test (Default 0)
  -nc, --new-conns      Open a new connection after each packet of the same test
  -tn, --transmit_full_path
                        Transmit the next node in the graph of the fuzzed node
  -br, --broadcast      Set to True to enable UDP broadcast

Recv Options:
  -nr, --no-recv        Do not recv() in the socket after each send
  -nrf, --no-recv-fuzz  Do not recv() in the socket after sending a fuzzed request
  -cr, --check-recv     Check that data has been received in recv()

Crashes Options:
  --threshold-request CRASH_THRESHOLD_REQUEST
                        Set the number of allowed crashes in a Request before skipping it (Default 9999)
  --threshold-element CRASH_THRESHOLD_ELEMENT
                        Set the number of allowed crashes in a Primitive before skipping it (Default 3)
  --error-fuzz-issues   Log as error when there is any connection issue in the fuzzed node

Fuzz Options:
  -c CALLBACK, --callback CALLBACK
                        Set a callback address to fuzz with callback generator instead of normal mutations
  --file FILENAME       Use contents of a file for fuzz mutations

Fuzzers:
  -i PATH [PATH ...]    Include modules from path[s]
  -f {bacnet,dhcp,ipp,lpd,modbus,telnet_cli,tftp,raw}
                        Available Protocols
  -r FUZZ_REQUESTS [FUZZ_REQUESTS ...]
                        Requests of the protocol to fuzz, default All

Restart options:
  --restart module_name [args ...]
                        Restarter Modules:
                          run: '<executable> [<argument> ...]' (Pass command and arguments within quotes, as only one argument)
  --restart-sleep RESTART_SLEEP_TIME
                        Set sleep seconds after a crash before continue (Default 5)

Monitor options:
  --monitors {BACnetMon,IPPMon,modbusMon} [{BACnetMon,IPPMon,modbusMon} ...], -m {BACnetMon,IPPMon,modbusMon} [{BACnetMon,IPPMon,modbusMon} ...]
                        Monitor Modules:
                          BACnetMon: Sends a query for Property Identifier id to the target in order to get the BACnet device information and check the response
                          IPPMon: Sends a get-attributes IPP message to the target
                          modbusMon: Sends a query for MODBUS device id to the target and check the response

Other Options:
  --path PATH           Set path when fuzzing HTTP based protocols (Default /)
  --document_url DOCUMENT_URL
                        Set Document URL for print_uri

```

#### Examples
Fuzz the get_printer_attribs IPP operation with default options:

```python -m fuzzowski printer1 631 -f ipp -r get_printer_attribs --restart smartplug```

[![asciicast](https://asciinema.org/a/0RMDMrJWiFo4RoRwAjx61BXDY.svg)](https://asciinema.org/a/0RMDMrJWiFo4RoRwAjx61BXDY)

Use the raw feature of IPP to fuzz the finger protocol:

```python -m fuzzowski printer 79 -f raw -r '{{root}}\n'```

[![asciicast](https://asciinema.org/a/Pch0JbkNK97dgrCUMK8iIfJv5.svg)](https://asciinema.org/a/Pch0JbkNK97dgrCUMK8iIfJv5)

Use the raw feature of IPP to fuzz the finger protocol, but instead of using the predefined mutations, use a file:

```python -m fuzzowski printer 79 -f raw -r '{{root}}\n' --file 'path/to/my/fuzzlist'```
