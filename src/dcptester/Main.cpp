/*
 * Copyright (C) 2019, FG Simulation und Modellierung, Leibniz Universität Hannover, Germany
 *
 * All rights reserved.
 *
 * This software may be modified and distributed under the terms
 * of the BSD 3-CLause license.  See the LICENSE file for details.
 */

#include <CLI11.hpp>
#include <dcptester/xml/DcpTestProcedureReader.h>
#include <dcptester/DcpTester.h>
#include <dcp/driver/ethernet/tcp/TcpDriver.hpp>
#include <dcp/driver/ethernet/udp/UdpDriver.hpp>



int main(int argc, char *argv[]) {
    //using namespace boost::filesystem;

    CLI::App app{"DCP Tester"};

    std::string filename;
    app.add_option("-t,--test", filename, "DCP test file to test.")->required(true);

    std::string ip;
    app.add_option("-i,--ip", ip, "IP address of the slave to test. Default: Value from test file.");

    uint16_t port = 0;
    app.add_option("-p,--port", port, "Port of the slave to test. Default: Value from test file.");

    uint16_t testerPort = 25000;
    app.add_option("--tester-port", testerPort, "Port of the tester. Default: 25000");

    std::string logfile;
    app.add_option("-l,--logfile", logfile, "Logfile in which the logs will be written.");

    uint32_t delay = 0;
    /* Just for presentation purpose
    app.add_option("--delay", delay, "Delay between two sending PDUs without Clock Time in micro seconds");
    */

    int udp = 1;
    app.add_flag("--udp", udp, "UDP/IPv4 will be used as transport protocol");

    int tcp = 0;
    app.add_flag("--tcp", tcp, "TCP/IPv4 will be used as transport protocol.");

    int verbose = 0;
    app.add_flag("-v,--verbose", verbose, "If set Logs will be displayed.");

    CLI11_PARSE(app, argc, argv);

    DcpManagerMaster* manager;
    TcpDriver* tcpDriver;
    UdpDriver* udpDriver;
    DcpTester* tester;

    if(udp){
        udpDriver = new UdpDriver("0.0.0.0", testerPort);
        manager = new DcpManagerMaster(udpDriver->getDcpDriver());
        tester = new DcpTester(udpDriver->getDcpDriver(), manager, verbose, logfile, DcpTransportProtocol::UDP_IPv4, ip, port);
    } else if(tcp){
        tcpDriver = new TcpDriver("0.0.0.0", testerPort);
        manager = new DcpManagerMaster(tcpDriver->getDcpDriver());
        tester = new DcpTester(tcpDriver->getDcpDriver(), manager, verbose, logfile, DcpTransportProtocol::TCP_IPv4, ip, port);
    }

    std::set<DcpTestSuite::DcpTestProcedure*> procedures;
    if(filename.length() > 0){
        procedures.insert(readDcpTestProcedure(filename.c_str()));
    }

    tester->setTestProcedures(procedures);
    tester->setDelay(delay);
    tester->start();





}
