# DCP Tester

### Build the DCP Tester
To Build the DCP Tester the following Libararies needed to be installed: 
- Asio
- Codesynthesis XSD
- DCPLib
- Xerces-C

You can use CMake to build the DCP Tester. On a linux host e. g.:
```
cd /directory/of/DCPLib
mkdir -p build
pushd build
cmake ..
cmake --build 
```

## How to Use the DCP Tester
To test a DCP slave implementation you need to do the following steps:
- Generate a test file, e.g. with the [dcp-test-generator](https://github.com/modelica/DCPTestGenerator)
- Execute the test

#### Generate a test file
Generate a test file from the slaves description file (dcpx), which will be tested, and a choosen transport protocol. E. g. the following snippet can be used to generate a test file for an slave implementation over UDP, by using the [dcp-test-generator](https://github.com/modelica/DCPTestGenerator).
```
dcp-test-generator -dcpx /Path/To/Dcpx -UDP
```
Depending on the information about the transport protocol in the dcpx, some informations may needed additionally by the test generator. E. g. the UDP host and port is not given in the dcpx.
```
dcp-test-generator -dcpx /Path/To/Dcpx -UDP --host 127.0.0.1 --port 6000
```
#### Execute the test
To execute a test file the tool dcp-tester is used.  E. g. the following snippet can be used to execute a test file.
```
dcp-tester -test /Path/to/Test
```
### Usage of the DCP Tester
```
Usage: dcp-tester [OPTIONS]

Options:
  -h,--help                   Print this help message and exit
  -t,--test TEXT REQUIRED     DCP test file to test.
  -i,--ip TEXT                IP address of the slave to test. Default: Value from test file.
  -p,--port UINT              Port of the slave to test. Default: Value from test file.
  --tester-port UINT          Port of the tester. Default: 25000
  -l,--logfile TEXT           Logfile in which the logs will be written.
  --udp                       UDP/IPv4 will be used as transport protocol.
  --tcp                       TCP/IPv4 will be used as transport protocol.
  -v,--verbose                If set Logs will be displayed.
```
## Acknowledgement ##
- 2020 - 2021: Improvement of this tool was supported by Modelica Association.
- 2018 - 2019: The work on this tool was done by the Simulation & Modelling Group of the Leibniz Universität Hannover.
- 2015 - 2018: The work on this tool was done in the contex of the ITEA3 Project ACOSAR (N◦14004) by the Simulation & Modelling Group of the Leibniz Universität Hannover. The ACOSAR project was partially funded by the Austrian Competence Centers for Excellent Technologies (COMET) program, the Austrian Research Promotion Agency (FFG), and by the German Federal Ministry of Education and Research (BMBF) under the support code 01lS15033A.
