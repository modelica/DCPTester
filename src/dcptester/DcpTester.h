/*
 * Copyright (C) 2019, FG Simulation und Modellierung, Leibniz Universität Hannover, Germany
 *
 * All rights reserved.
 *
 * This software may be modified and distributed under the terms
 * of the BSD 3-CLause license.  See the LICENSE file for details.
 */

#ifndef DCP_TESTER_DCPTESTER_H
#define DCP_TESTER_DCPTESTER_H

#include <dcp/logic/DcpManagerMaster.hpp>
#include <dcp/helper/Helper.hpp>
#include <dcp/driver/ethernet/udp/UdpDriver.hpp>
#include <string>
#include <map>
#include <mutex>
#include <set>
#include <dcp/log/OstreamLog.hpp>
#include <fstream>
#include <chrono>
#include <dcp/model/DcpString.hpp>
#include <dcp/model/DcpBinary.hpp>

#include <limits>
#include <cmath>
#include <thread>
#include <algorithm>

#include <dcptester/xml/DcpTestProcedure.hxx>
#include <dcptester/automaton/Automaton.h>

using namespace DcpTestSuite;

// Macros
#define checkField(name, datatype) \
if(field.name().present()){ \
    size_t dim = field.name().get().dimensionSize(); \
    for(size_t i = 0; i < dim; ++i){\
        datatype val = *((datatype*) (payload + (offset + sizeof(datatype) * i))); \
        if(field.name().get().min().present() && field.name().get().max().present()){ \
            if(val < field.name().get().min().get() || val > field.name().get().max().get()){ \
                correctFields = false; \
                break;\
            } \
        } else if(field.name().get().value().present()){\
            if(val != field.name().get().value().get()[i]){\
                correctFields = false; \
                break;\
            }\
        }\
    }\
    offset += sizeof(datatype) * dim; \
} \

#define sendIfHead(name) \
    if (sending.name().present()) { \
        const Sending::name##_type &name = sending.name().get();

#define assign(type, name) \
    if (field->name().present()) { \
        for(size_t i = 0; i < field->name().get().value().size(); ++i){ \
            *((type*) (payload + offset)) = field->name().get().value()[i]; \
            offset += sizeof(type);\
        }\
    }

#define checkSendingPresence(msg) \
    if (transition->Sending().get().msg().present()) { \
        return DcpPduType::msg; \
    }

#define checkReceivingPresence(msg) \
    if (transition->Receiving().get().msg().present()) { \
        return DcpPduType::msg; \
    }

class DcpTester {
public:
    DcpTester(DcpDriver driver, DcpManagerMaster *manager, bool verbose, std::string logFile, DcpTransportProtocol dcpProtocol, std::string ip, int32_t port) : stdLog(std::cout), fileLog(fileStream){
        this->driver = driver;
        this->manager = manager;
        this->dcpProtocol = dcpProtocol;
        if(logFile.length() > 0){
            manager->addLogListener(std::bind(&OstreamLog::logOstream, fileLog, std::placeholders::_1));
            manager->setPduMissedListener<FunctionType::SYNC>(std::bind(&DcpTester::pduMissed, this, std::placeholders::_1));
            manager->setGenerateLogString(true);
            fileStream.open(logFile);
        }
        if(verbose){
            manager->addLogListener(std::bind(&OstreamLog::logOstream, stdLog, std::placeholders::_1));
            manager->setGenerateLogString(true);
        }

        this->ip = ip;
        this->port = port;
    }

    ~DcpTester() {
        fileStream.close();
    }


    void start(){
        /*LogInstance::getInstance().addSendPduListener(
            std::bind(&DcpTester::logPdu, this, std::string("Send"), std::placeholders::_1));
    LogInstance::getInstance().addReceivedPduListener(
            std::bind(&DcpTester::logPdu, this, std::string("Received"), std::placeholders::_1));*/

        manager->setPDUListener(std::bind(&DcpTester::receive, this, std::placeholders::_1));
        std::thread b(&DcpManagerMaster::start, manager);
        std::chrono::seconds dura(2);
        std::this_thread::sleep_for(dura);
        for (DcpTestProcedure *ptr : testProcedures) {
            nextExecution.clear();
            driver.stop();
            driver.disconnect();
            if(dcpProtocol == DcpTransportProtocol::UDP_IPv4){
                uint8_t *networkInformation = new uint8_t[6];
                if(ip.length() > 0){
                    *((uint32_t *) (networkInformation + 2)) = asio::ip::address_v4::from_string(ip).to_ulong();
                } else if(ptr->TransportProtocols().UDP_IPv4().get().Control().host().present()){
                    *((uint32_t *) (networkInformation + 2)) = asio::ip::address_v4::from_string(ptr->TransportProtocols().UDP_IPv4().get().Control().host().get()).to_ulong();
                } else {
                    //IP = 127.0.0.1
                    *((uint32_t *) (networkInformation + 2)) = 2130706433;
                }

                if(port > 0) {
                    *((uint16_t *) networkInformation) = port;
                } else {
                    *((uint16_t *) networkInformation) = ptr->TransportProtocols().UDP_IPv4().get().Control().port();
                }

                driver.setSlaveNetworkInformation(1, networkInformation);


                delete[] networkInformation;
            } else if(dcpProtocol == DcpTransportProtocol::TCP_IPv4){
                uint8_t *networkInformation = new uint8_t[6];
                if(ip.length() > 0){
                    *((uint32_t *) (networkInformation + 2)) = asio::ip::address_v4::from_string(ip).to_ulong();
                } else if(ptr->TransportProtocols().TCP_IPv4().get().Control().host().present()){
                    *((uint32_t *) (networkInformation + 2)) = asio::ip::address_v4::from_string(ptr->TransportProtocols().TCP_IPv4().get().Control().host().get()).to_ulong();
                } else {
                    //IP = 127.0.0.1
                    *((uint32_t *) (networkInformation + 2)) = 2130706433;
                }

                if(port > 0) {
                    *((uint16_t *) networkInformation) = port;
                } else {
                    *((uint16_t *) networkInformation) = ptr->TransportProtocols().TCP_IPv4().get().Control().port();
                }

                driver.setSlaveNetworkInformation(1, networkInformation);


                delete[] networkInformation;
            }

            step = 0;
            std::cout << "create Automaton" << std::endl;
            automaton = new Automaton();
            automaton->init(*ptr);
            if (ptr->name().present()) {
                testProcedureName = std::string(ptr->name().get());
            }
            std::cout << "Start Procedure" << std::endl;
            runTestProcedure(ptr);
            delete automaton;

        }
    }

    void receive(DcpPdu& pdu){
        {
            std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now();

            switch (pdu.getTypeId()) {
                case DcpPduType::RSP_ack: {
                    DcpPduRspAck &ack = static_cast<DcpPduRspAck &>(pdu);
                    receive_RSP_ack(now, ack.getSender(), ack.getRespSeqId());
                    break;
                }
                case DcpPduType::RSP_nack: {
                    DcpPduRspNack &nack = static_cast<DcpPduRspNack &>(pdu);
                    receive_RSP_nack(now, nack.getSender(), nack.getRespSeqId(), nack.getErrorCode());
                    break;
                }
                case DcpPduType::RSP_state_ack: {
                    DcpPduRspStateAck &stateAck = static_cast<DcpPduRspStateAck &>(pdu);
                    receive_RSP_state_ack(now, stateAck.getSender(), stateAck.getRespSeqId(), stateAck.getStateId());
                    break;
                }
                case DcpPduType::RSP_error_ack: {
                    DcpPduRspErrorAck &errorAck = static_cast<DcpPduRspErrorAck &>(pdu);
                    receive_RSP_error_ack(now, errorAck.getSender(), errorAck.getRespSeqId(), errorAck.getErrorCode());
                    break;
                }
                case DcpPduType::RSP_log_ack: {
                    DcpPduRspLogAck &logAck = static_cast<DcpPduRspLogAck &>(pdu);
                    receive_RSP_log(now, logAck.getSender(), logAck.getRespSeqId(), logAck.getSerializedSize());
                    break;
                }
                case DcpPduType::NTF_state_changed: {
                    DcpPduNtfStateChanged &stateChanged = static_cast<DcpPduNtfStateChanged &>(pdu);
                    std::thread t(&DcpTester::receive_NTF_state_changed, this, now, stateChanged.getSender(), stateChanged.getStateId());
                    t.detach();
                    break;
                }
                case DcpPduType::NTF_log: {
                    DcpPduNtfLog &log = static_cast<DcpPduNtfLog &>(pdu);
                    receive_NTF_log(now, log.getSender(), log.getSerializedSize());
                    break;
                }
                case DcpPduType::DAT_input_output: {
                    DcpPduDatInputOutput &inputOutput = static_cast<DcpPduDatInputOutput &>(pdu);
                    size_t size = inputOutput.getSerializedSize() - 9;
                    uint8_t* payloadCpy = new uint8_t[size];
                    std::memcpy(payloadCpy, inputOutput.getPayload(), size);

                    std::thread t(&DcpTester::receive_DAT_input_output, this, now, inputOutput.getDataId(), payloadCpy, size);
                    t.join();

                    break;
                }
                case DcpPduType::DAT_parameter: {
                    DcpPduDatParameter &parameter = static_cast<DcpPduDatParameter &>(pdu);
                    receive_DAT_parameter(now, parameter.getParamId(), parameter.getConfiguration(),
                                          parameter.getSerializedSize() - 9);
                    break;
                }
                default:

                    break;
            }
        }
    }

    void setDelay(uint32_t delay){
        DcpTester::delay = delay;
    }

    void setTestProcedures(const std::set<DcpTestProcedure *> &testProcedures){
        DcpTester::testProcedures = testProcedures;
    }

private:
    std::mutex mutex;

    DcpTransportProtocol dcpProtocol;

    std::map<Transition*, int64_t> nextExecution;
    std::map<Transition*, int64_t> nextExecutionDefault;

    std::set<DcpTestProcedure*> testProcedures;

    uint32_t step = 0;
    uint32_t delay = 0;
    uint32_t lastAction = 0;

    uint16_t lastRegisterSeq;
    uint16_t lastRegisterSuccessfullSeq;
    uint16_t lastClearSeq;

    std::map<Transition*, std::vector<int64_t>> statistic;
    std::map<Transition*, std::chrono::steady_clock::time_point> lastCheck;

    std::string testProcedureName = "";

    Automaton* automaton;

    DcpDriver driver;

    DcpManagerMaster* manager;

    OstreamLog fileLog;
    OstreamLog stdLog;
    std::ofstream fileStream;

    std::string ip;
    uint16_t port;

    void failure(std::string msg){
        std::cout << msg << std::endl;
        std::exit(1);
        //logger.logMsg(msg);
    }

    void log(std::chrono::steady_clock::time_point time, Transition* transition){
        if (transition->log()) {
            if(lastCheck.count(transition)){
                statistic[transition].push_back(std::chrono::duration_cast<std::chrono::microseconds>(time - lastCheck[transition]).count());
                lastCheck[transition] = time;
            } else {
                lastCheck[transition] = time;
            }
        }
    }

    void printStatistic();

    void setStep(const Transition* transition){
        this->step = transition->to();
        //logger.logStep(step);
        //std::cout << unsigned(step) << std::endl;
    }

    void sendTransition(const Transition* transition){

        const Transition::Sending_type &sending = transition->Sending().get();
        sendIfHead(STC_register)
            if (STC_register.slave_uuid().present()) {
                manager->STC_register(STC_register.receiver(), (DcpState) STC_register.state_id(),
                                      convertToUUID(STC_register.slave_uuid().get()), (DcpOpMode) STC_register.op_mode(),
                                      STC_register.major_version(), STC_register.minor_version());

            } else {
                uint128_t uuid;
                manager->STC_register(STC_register.receiver(), (DcpState) STC_register.state_id(),
                                      uuid, (DcpOpMode) STC_register.op_mode(),
                                      STC_register.major_version(), STC_register.minor_version());
            }
        } else sendIfHead(STC_deregister)
            manager->STC_deregister(STC_deregister.receiver(), (DcpState) STC_deregister.state_id());
        } else sendIfHead(STC_prepare)
            manager->STC_prepare(STC_prepare.receiver(), (DcpState) STC_prepare.state_id());
        } else sendIfHead(STC_configure)
            manager->STC_configure(STC_configure.receiver(), (DcpState) STC_configure.state_id());
        } else sendIfHead(STC_initialize)
            manager->STC_initialize(STC_initialize.receiver(), (DcpState) STC_initialize.state_id());
        } else sendIfHead(STC_run)
            if (STC_run.start_time().present()) {
                manager->STC_run(STC_run.receiver(), (DcpState) STC_run.state_id(), STC_run.start_time().get());
            } else {
                std::time_t now=std::time(0);
                manager->STC_run(STC_run.receiver(), (DcpState) STC_run.state_id(), now + 1);
            }
        }else sendIfHead(STC_do_step)
            manager->STC_do_step(STC_do_step.receiver(), (DcpState) STC_do_step.state_id(), STC_do_step.steps());
        } else sendIfHead(STC_send_outputs)
            manager->STC_send_outputs(STC_send_outputs.receiver(), (DcpState) STC_send_outputs.state_id());
        } else sendIfHead(STC_stop)
            manager->STC_stop(STC_stop.receiver(), (DcpState) STC_stop.state_id());
        } else sendIfHead(STC_reset)
            manager->STC_reset(STC_reset.receiver(), (DcpState) STC_reset.state_id());
        } else sendIfHead(INF_state)
            manager->INF_state(INF_state.receiver());
        } else sendIfHead(INF_error)
            manager->INF_error(INF_error.receiver());
        } else sendIfHead(INF_log)
            manager->INF_log(INF_log.receiver(), INF_log.log_category(), INF_log.log_max_num());
        } else sendIfHead(CFG_time_res)
            manager->CFG_time_res(CFG_time_res.receiver(), CFG_time_res.numerator(),
                                  CFG_time_res.denominator());
        } else sendIfHead(CFG_steps)
            manager->CFG_steps(CFG_steps.receiver(), CFG_steps.data_id(), CFG_steps.steps());
        } else sendIfHead(CFG_input)
            manager->CFG_input(CFG_input.receiver(), CFG_input.data_id(), CFG_input.pos(),
                               CFG_input.target_vr(), (DcpDataType) CFG_input.source_data_type());
        } else sendIfHead(CFG_output)
            manager->CFG_output(CFG_output.receiver(), CFG_output.data_id(), CFG_output.pos(),
                                CFG_output.source_vr());
        } else sendIfHead(CFG_clear)
            manager->CFG_clear(CFG_clear.receiver());
        } else sendIfHead(CFG_target_network_information_UDP_IPv4)
            manager->CFG_target_network_information_UDP(CFG_target_network_information_UDP_IPv4.receiver(),
                                                        CFG_target_network_information_UDP_IPv4.data_id(),
                                                        CFG_target_network_information_UDP_IPv4.ip_address(),
                                                        CFG_target_network_information_UDP_IPv4.port());
            uint8_t* netInfo = new uint8_t[6];
            *((uint16_t*) netInfo) = CFG_target_network_information_UDP_IPv4.port();
            *((uint32_t*) (netInfo + 2)) = CFG_target_network_information_UDP_IPv4.ip_address();
            driver.setSourceNetworkInformation(CFG_target_network_information_UDP_IPv4.data_id(), netInfo);
            delete[] netInfo;
        } else sendIfHead(CFG_source_network_information_UDP_IPv4)
            manager->CFG_source_network_information_UDP(CFG_source_network_information_UDP_IPv4.receiver(),
                                                        CFG_source_network_information_UDP_IPv4.data_id(),
                                                        CFG_source_network_information_UDP_IPv4.ip_address(),
                                                        CFG_source_network_information_UDP_IPv4.port());
            uint8_t* netInfo = new uint8_t[6];
            *((uint16_t*) netInfo) = CFG_source_network_information_UDP_IPv4.port();
            *((uint32_t*) (netInfo + 2)) = CFG_source_network_information_UDP_IPv4.ip_address();
            driver.setTargetNetworkInformation(CFG_source_network_information_UDP_IPv4.data_id(), netInfo);
            delete[] netInfo;

        } else sendIfHead(CFG_target_network_information_TCP_IPv4)
            manager->CFG_target_network_information_TCP(CFG_target_network_information_TCP_IPv4.receiver(),
                                                        CFG_target_network_information_TCP_IPv4.data_id(),
                                                        CFG_target_network_information_TCP_IPv4.ip_address(),
                                                        CFG_target_network_information_TCP_IPv4.port());
            uint8_t* netInfo = new uint8_t[6];
            *((uint16_t*) netInfo) = CFG_target_network_information_TCP_IPv4.port();
            *((uint32_t*) (netInfo + 2)) = CFG_target_network_information_TCP_IPv4.ip_address();
            driver.setSourceNetworkInformation(CFG_target_network_information_TCP_IPv4.data_id(), netInfo);
            delete[] netInfo;
        } else sendIfHead(CFG_source_network_information_TCP_IPv4)
            manager->CFG_source_network_information_TCP(CFG_source_network_information_TCP_IPv4.receiver(),
                                                        CFG_source_network_information_TCP_IPv4.data_id(),
                                                        CFG_source_network_information_TCP_IPv4.ip_address(),
                                                        CFG_source_network_information_TCP_IPv4.port());
            uint8_t* netInfo = new uint8_t[6];
            *((uint16_t*) netInfo) = CFG_source_network_information_TCP_IPv4.port();
            *((uint32_t*) (netInfo + 2)) = CFG_source_network_information_TCP_IPv4.ip_address();
            driver.setTargetNetworkInformation(CFG_source_network_information_TCP_IPv4.data_id(), netInfo);
            delete[] netInfo;

        } else sendIfHead(CFG_parameter)
            const auto *field = &CFG_parameter.Payload();

            uint8_t payload[2048];
            size_t offset = 0;
            assign(int8_t, Int8)
            else assign(int16_t, Int16)
            else assign(int32_t, Int32)
            else assign(int64_t, Int64)
            else assign(uint8_t, Uint8)
            else assign(uint16_t, Uint16)
            else assign(uint32_t, Uint32)
            else assign(uint64_t, Uint64)
            else assign(float32_t, Float32)
            else assign(float64_t, Float64)
            else if (field->String().present()) {
                std::string val(field->String().get().value());
                DcpString dcpStr(val, 2048);
                int length = dcpStr.getSize() + 2;
                memcpy(payload + offset, dcpStr.getChar(), length);
                offset += length;
            } else if (field->Binary().present()) {
                std::string hex(field->Binary().get().value().encode());
                if (hex.size() % 2 == 1) {
                    hex = "0" + hex;
                }
                offset += 2;
                *((uint16_t *) payload) = hex.length() / 2;
                for (unsigned int i = 0; i < hex.length(); i += 2) {
                    std::string byteString = hex.substr(i, 2);
                    char byte = (char) strtol(byteString.c_str(), NULL, 16);
                    payload[offset] = *((uint8_t *) &byte);
                    offset++;
                }
            }

            manager->CFG_parameter(CFG_parameter.receiver(), CFG_parameter.target_vr(),
                                   (DcpDataType) CFG_parameter.source_data_type(), payload, offset);
        } else sendIfHead(CFG_tunable_parameter)
            manager->CFG_tunable_parameter(CFG_tunable_parameter.receiver(),
                                           CFG_tunable_parameter.param_id(),
                                           CFG_tunable_parameter.pos(),
                                           CFG_tunable_parameter.target_vr(),
                                           (DcpDataType) CFG_tunable_parameter.source_data_type());
        } else sendIfHead(CFG_param_network_information_UDP_IPv4)
            manager->CFG_param_network_information_UDP(CFG_param_network_information_UDP_IPv4.receiver(),
                                                       CFG_param_network_information_UDP_IPv4.param_id(),
                                                       CFG_param_network_information_UDP_IPv4.ip_address(),
                                                       CFG_param_network_information_UDP_IPv4.port());
            uint8_t* netInfo = new uint8_t[6];
            *((uint16_t*) netInfo) = CFG_param_network_information_UDP_IPv4.port();
            *((uint32_t*) (netInfo + 2)) = CFG_param_network_information_UDP_IPv4.ip_address();
            driver.setTargetParamNetworkInformation(CFG_param_network_information_UDP_IPv4.param_id(), netInfo);
        } else sendIfHead(CFG_param_network_information_TCP_IPv4)
            manager->CFG_param_network_information_TCP(CFG_param_network_information_TCP_IPv4.receiver(),
                                                       CFG_param_network_information_TCP_IPv4.param_id(),
                                                       CFG_param_network_information_TCP_IPv4.ip_address(),
                                                       CFG_param_network_information_TCP_IPv4.port());
            uint8_t* netInfo = new uint8_t[6];
            *((uint16_t*) netInfo) = CFG_param_network_information_TCP_IPv4.port();
            *((uint32_t*) (netInfo + 2)) = CFG_param_network_information_TCP_IPv4.ip_address();
            driver.setTargetParamNetworkInformation(CFG_param_network_information_TCP_IPv4.param_id(), netInfo);
        } else sendIfHead(CFG_logging)
            manager->CFG_logging(CFG_logging.receiver(), CFG_logging.log_category(),
                                 (DcpLogLevel) CFG_logging.log_level(), (DcpLogMode) CFG_logging.log_mode());
        } else sendIfHead(CFG_scope)
            manager->CFG_scope(CFG_scope.receiver(), CFG_scope.data_id(), (DcpScope) CFG_scope.scope());
        } else sendIfHead(DAT_input_output)
            std::vector<const SendingPayloadField *> fields;
            for (const SendingPayloadField &field: DAT_input_output.SendingPayloadField()) {
                if (fields.size() == 0) {
                    fields.push_back(&field);
                } else {
                    for (std::vector<const SendingPayloadField *>::iterator it = fields.begin(); it != fields.end(); ++it) {
                        if (field.pos() < (*it)->pos()) {
                            fields.insert(it, &field);
                        }
                    }
                }
            }
            size_t offset = 0;
            uint8_t payload[2048];

            for (const SendingPayloadField *field: fields) {
                assign(int8_t, Int8)
                else assign(int16_t, Int16)
                else assign(int32_t, Int32)
                else assign(int64_t, Int64)
                else assign(uint8_t, Uint8)
                else assign(uint16_t, Uint16)
                else assign(uint32_t, Uint32)
                else assign(uint64_t, Uint64)
                else assign(float32_t, Float32)
                else assign(float64_t, Float64)
                else if (field->String().present()) {
                    std::string val(field->String().get().value());
                    DcpString dcpStr(val, 2048);
                    int length = dcpStr.getSize() + 2;
                    memcpy(payload + offset, dcpStr.getChar(), length);
                    offset += length;
                } else if (field->Binary().present()) {
                    std::string hex(field->Binary().get().value().encode());
                    if (hex.size() % 2 == 1) {
                        hex = "0" + hex;
                    }
                    offset += 2;
                    *((uint16_t *) payload) = hex.length() / 2;
                    for (unsigned int i = 0; i < hex.length(); i += 2) {
                        std::string byteString = hex.substr(i, 2);
                        char byte = (char) strtol(byteString.c_str(), NULL, 16);
                        payload[offset] = *((uint8_t *) &byte);
                        offset++;
                    }
                }
            }
            manager->DAT_input_output(DAT_input_output.data_id(), payload, offset);

        } else sendIfHead(DAT_parameter)
            std::vector<const SendingPayloadField *> fields;
            for (const SendingPayloadField &field: DAT_parameter.SendingPayloadField()) {
                if (fields.size() == 0) {
                    fields.push_back(&field);
                } else {
                    for (std::vector<const SendingPayloadField *>::iterator it = fields.begin(); it != fields.end(); ++it) {
                        if (field.pos() < (*it)->pos()) {
                            fields.insert(it, &field);
                        }
                    }
                }
            }

            size_t offset = 0;
            uint8_t payload[2048];

            for (const SendingPayloadField *field: fields) {
                assign(int8_t, Int8)
                else assign(int16_t, Int16)
                else assign(int32_t, Int32)
                else assign(int64_t, Int64)
                else assign(uint8_t, Uint8)
                else assign(uint16_t, Uint16)
                else assign(uint32_t, Uint32)
                else assign(uint64_t, Uint64)
                else assign(float32_t, Float32)
                else assign(float64_t, Float64)
                else if (field->String().present()) {
                    std::string val(field->String().get().value());
                    DcpString dcpStr(val, 2048);
                    memcpy(payload + offset, dcpStr.getChar(), dcpStr.getSize() + 2);
                } else if (field->Binary().present()) {
                    std::string hex(field->Binary().get().value().encode());
                    if (hex.size() % 2 == 1) {
                        hex = "0" + hex;
                    }
                    offset += 2;
                    *((uint16_t *) payload) = hex.length() / 2;
                    for (unsigned int i = 0; i < hex.length(); i += 2) {
                        std::string byteString = hex.substr(i, 2);
                        char byte = (char) strtol(byteString.c_str(), NULL, 16);
                        payload[offset] = *((uint8_t *) &byte);
                        offset++;
                    }
                }
            }
            manager->DAT_parameter(DAT_parameter.param_id(), payload, offset);
        }

    }

    DcpPduType getDcpPduType(const Transition* transition)  {
        if (transition->Sending().present()) {
            checkSendingPresence(STC_register)
            checkSendingPresence(STC_deregister)
            checkSendingPresence(STC_configure)
            checkSendingPresence(STC_initialize)
            checkSendingPresence(STC_run)
            checkSendingPresence(STC_do_step)
            checkSendingPresence(STC_send_outputs)
            checkSendingPresence(STC_stop)
            checkSendingPresence(STC_reset)
            checkSendingPresence(INF_state)
            checkSendingPresence(INF_error)
            checkSendingPresence(INF_log)
            checkSendingPresence(CFG_time_res)
            checkSendingPresence(CFG_steps)
            checkSendingPresence(CFG_input)
            checkSendingPresence(CFG_output)
            checkSendingPresence(CFG_clear)
            if (transition->Sending().get().CFG_target_network_information_UDP_IPv4().present()) {
                return DcpPduType::CFG_target_network_information;
            }
            if (transition->Sending().get().CFG_target_network_information_TCP_IPv4().present()) {
                return DcpPduType::CFG_target_network_information;
            }
            if (transition->Sending().get().CFG_source_network_information_UDP_IPv4().present()) {
                return DcpPduType::CFG_source_network_information;
            }
            if (transition->Sending().get().CFG_source_network_information_TCP_IPv4().present()) {
                return DcpPduType::CFG_source_network_information;
            }
            checkSendingPresence(CFG_parameter)
            checkSendingPresence(CFG_tunable_parameter)
            if (transition->Sending().get().CFG_param_network_information_UDP_IPv4().present()) {
                return DcpPduType::CFG_param_network_information;
            }
            if (transition->Sending().get().CFG_param_network_information_TCP_IPv4().present()) {
                return DcpPduType::CFG_param_network_information;
            }
            checkSendingPresence(CFG_logging)
            checkSendingPresence(CFG_scope)
            checkSendingPresence(DAT_input_output)
            checkSendingPresence(DAT_parameter)
        } else {
            checkReceivingPresence(RSP_ack)
            checkReceivingPresence(RSP_error_ack)
            checkReceivingPresence(RSP_nack)
            checkReceivingPresence(RSP_state_ack)
            checkReceivingPresence(RSP_log_ack)
            checkReceivingPresence(NTF_state_changed)
            checkReceivingPresence(NTF_log)
            checkReceivingPresence(DAT_input_output)
            checkReceivingPresence(DAT_parameter)
        }

        assert(false);
    }

    void receive_RSP_ack(std::chrono::steady_clock::time_point time, uint8_t sender, uint16_t pduSeqId){
        mutex.lock();
        bool found = false;
        bool correctFields = false;
        Transition *transitionPtr = NULL;
        for (Transition * transition: automaton->getReceivingSuccessors(step)) {
            if (getDcpPduType(transition) == DcpPduType::RSP_ack) {
                found = true;
                Receiving::RSP_ack_type &ack = transition->Receiving().get().RSP_ack().get();
                if (ack.sender() == sender) {
                    correctFields = true;
                    transitionPtr = transition;
                    break;
                }
            }
        }
        check(time, found, correctFields, "RSP_ack", transitionPtr);
        mutex.unlock();

    }

    void receive_RSP_nack(std::chrono::steady_clock::time_point time, uint8_t sender, uint16_t pduSeqId,
                          DcpError errorCode){
        mutex.lock();
        bool found = false;
        bool correctFields = false;
        Transition *transitionPtr = NULL;
        for (Transition* transition: automaton->getReceivingSuccessors(step)) {
            if (getDcpPduType(transition) == DcpPduType::RSP_nack) {
                found = true;
                Receiving::RSP_nack_type &nack = transition->Receiving().get().RSP_nack().get();
                if (nack.sender() == sender && nack.error_code() == (uint16_t) errorCode) {
                    correctFields = true;
                    transitionPtr = transition;
                    break;
                }
            }
        }
        check(time, found, correctFields, "RSP_nack", transitionPtr);
        mutex.unlock();

    }

    void receive_RSP_state_ack(std::chrono::steady_clock::time_point time, uint8_t sender, uint16_t pduSeqId,
                               DcpState state){
        mutex.lock();
        bool found = false;
        bool correctFields = false;
        Transition *transitionPtr = NULL;

        for (Transition* transition: automaton->getReceivingSuccessors(step)) {
            if (getDcpPduType(transition) == DcpPduType::RSP_state_ack) {
                found = true;
                Receiving::RSP_state_ack_type &stateAck = transition->Receiving().get().RSP_state_ack().get();
                if (stateAck.sender() == sender && stateAck.state_id() == (uint8_t) state) {
                    correctFields = true;
                    transitionPtr = transition;
                    break;
                }
            }
        }
        check(time, found, correctFields, "RSP_state_ack", transitionPtr);
        mutex.unlock();

    }

    void receive_RSP_error_ack(std::chrono::steady_clock::time_point time, uint8_t sender, uint16_t pduSeqId,
                               DcpError errorCode){
        mutex.lock();

        bool found = false;
        bool correctFields = false;
        Transition *transitionPtr = NULL;
        for (Transition* transition: automaton->getReceivingSuccessors(step)) {
            if (getDcpPduType(transition) == DcpPduType::RSP_error_ack) {
                found = true;
                Receiving::RSP_error_ack_type &errorAck = transition->Receiving().get().RSP_error_ack().get();
                if (errorAck.sender() == sender && errorAck.error_code() == (uint16_t) errorCode) {
                    correctFields = true;
                    transitionPtr = transition;
                    break;
                }
            }
        }
        check(time, found, correctFields, "RSP_error_ack", transitionPtr);
        mutex.unlock();

    }
    void receive_RSP_log(std::chrono::steady_clock::time_point time, uint8_t sender, uint16_t pduSeqId, uint32_t length){
        mutex.lock();

        bool found = false;
        bool correctFields = false;
        Transition *transitionPtr = NULL;
        for (Transition* transition: automaton->getReceivingSuccessors(step)) {
            if (getDcpPduType(transition) == DcpPduType::RSP_error_ack) {
                found = true;
                Receiving::RSP_log_ack_type &log = transition->Receiving().get().RSP_log_ack().get();
                if (log.sender() == sender && log.length() == length) {
                    correctFields = true;
                    transitionPtr = transition;
                    break;
                }
            }
        }
        check(time, found, correctFields, "RSP_log", transitionPtr);
        mutex.unlock();

    }


    void receive_NTF_state_changed(std::chrono::steady_clock::time_point time, uint8_t sender,
                                   DcpState state){
        mutex.lock();
        if(state == DcpState::ALIVE){
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }

        bool found = false;
        bool correctFields = false;
        Transition *transitionPtr = NULL;



        for (Transition* transition: automaton->getReceivingSuccessors(step)) {
            if (getDcpPduType(transition) == DcpPduType::NTF_state_changed) {
                found = true;
                Receiving::NTF_state_changed_type &stateChanged = transition->Receiving().get().NTF_state_changed().get();
                if (stateChanged.sender() == sender && stateChanged.state_id() == (uint8_t) state) {
                    correctFields = true;
                    transitionPtr = transition;
                    lastCheck.clear();

                    break;
                }
            }
        }
        if(found && correctFields && state == DcpState::PREPARING){
            driver.prepare();
        }
        if(found && correctFields && state == DcpState::CONFIGURING){
            driver.configure();
        }
        check(time, found, correctFields, "NTF_state_changed", transitionPtr);
        mutex.unlock();

    }

    void receive_NTF_log(std::chrono::steady_clock::time_point time, uint8_t sender, uint32_t length){
        mutex.lock();

        bool found = false;
        bool correctFields = false;
        Transition *transitionPtr = NULL;
        for (Transition* transition: automaton->getReceivingSuccessors(step)) {
            if (getDcpPduType(transition) == DcpPduType::RSP_error_ack) {
                found = true;
                Receiving::NTF_log_type &log = transition->Receiving().get().NTF_log().get();
                if (log.sender() == sender && log.length() == length) {
                    correctFields = true;
                    transitionPtr = transition;
                    break;

                }
            }
        }
        check(time, found, correctFields, "NTF_log", transitionPtr);
        mutex.unlock();


    }

    void receive_DAT_input_output(std::chrono::steady_clock::time_point time, uint16_t dataId, uint8_t *payload, size_t length){
        mutex.lock();

        bool found = false;
        bool correctFields = false;
        Transition *transitionPtr = NULL;

        for (Transition* transition: automaton->getReceivingSuccessors(step)) {
            if (getDcpPduType(transition) == DcpPduType::DAT_input_output) {
                found = true;
                Receiving::DAT_input_output_type &data = transition->Receiving().get().DAT_input_output().get();
                uint16_t correctLength;
                size_t offset = 0;
                if (data.data_id() == dataId) {
                    correctFields = true;
                    for (ReceivingPayloadField &field :data.ReceivingPayloadField()) {
                        checkField(Uint8, uint8_t)
                        else checkField(Uint16, uint16_t)
                        else checkField(Uint32, uint32_t)
                        else checkField(Uint64, uint64_t)
                        else checkField(Int8, int8_t)
                        else checkField(Int16, int16_t)
                        else checkField(Int32, int32_t)
                        else checkField(Int64, int64_t)
                        else checkField(Float32, float32_t)
                        else checkField(Float64, float64_t)
                        else if (field.String().present()) {
                            DcpString string((char*) (payload + offset));

                            if(field.String().get().value().present()){
                                if(string.getString() != field.String().get().value().get()){
                                    correctFields = false;
                                    break;
                                }
                            }
                            offset += string.getSize() + 4;
                        } else if (field.Binary().present()) {
                            DcpBinary binary(payload + offset);
                            //toDo check if value is defined
                            offset += binary.getSize() + 4;
                        }
                    }
                    if (correctFields && offset == length) {
                        transitionPtr = transition;
                        break;
                    } else {
                        correctFields = false;
                    }

                }
            }
        }
        check(time, found, correctFields, "DAT_input_output", transitionPtr);
        delete payload;
        mutex.unlock();

    }

    void receive_DAT_parameter(std::chrono::steady_clock::time_point time, uint16_t paramId, uint8_t *payload, size_t length){
        mutex.lock();

        bool found = false;
        bool correctFields = false;
        Transition *transitionPtr = NULL;

        for (Transition* transition: automaton->getReceivingSuccessors(step)) {
            if (getDcpPduType(transition) == DcpPduType::DAT_parameter) {
                found = true;
                Receiving::DAT_parameter_type &parameter = transition->Receiving().get().DAT_parameter().get();
                uint16_t correctLength;
                size_t offset = 0;

                if (parameter.param_id() == paramId) {
                    correctFields = true;
                    for (ReceivingPayloadField &field :parameter.ReceivingPayloadField()) {
                        checkField(Uint8, uint8_t)
                        else checkField(Uint16, uint16_t)
                        else checkField(Uint32, uint32_t)
                        else checkField(Uint64, uint64_t)
                        else checkField(Int8, int8_t)
                        else checkField(Int16, int16_t)
                        else checkField(Int32, int32_t)
                        else checkField(Int64, int64_t)
                        else checkField(Float32, float32_t)
                        else checkField(Float64, float64_t)
                        else if (field.String().present()) {
                            DcpString string((char*) (payload + offset));

                            if(field.String().get().value().present()){
                                if(string.getString() != field.String().get().value().get()){
                                    correctFields = false;
                                    break;
                                }
                            }
                            offset += string.getSize() + 4;
                        } else if (field.Binary().present()) {
                            DcpBinary binary(payload + offset);
                            //toDo check if value is defined
                            offset += binary.getSize() + 4;
                        }
                    }
                    if (correctFields && offset == length) {
                        transitionPtr = transition;
                        break;
                    }
                }
            }
        }
        check(time, found, correctFields, "DAT_parameter", transitionPtr);
        mutex.unlock();

    }

    void runTestProcedure(DcpTestProcedure* testProcedure){
        using namespace std::chrono;

        step = 0;
        //logger.logStep(step);
        for (Transition& transition: testProcedure->Transition()) {
            if (transition.Sending().present() && transition.Sending().get().ClockTime().present()) {
                const ClockTime::numerator_type &numerator = transition.Sending().get().ClockTime().get().numerator();
                const ClockTime::denominator_type &denominator = transition.Sending().get().ClockTime().get().denominator();
                int64_t between = (uint64_t) (1000000 *
                                              ((double) numerator) /
                                              ((double) denominator));
                nextExecution.insert(std::make_pair(&transition, between));
                nextExecutionDefault.insert(std::make_pair(&transition, between));

            }
        }
        time_point<system_clock, microseconds> lastCheck;


        while (!automaton->isAccepting(step)) {
            mutex.lock();


            Transition *minTrans = NULL;
            int64_t min = std::numeric_limits<int64_t>::max();

            const time_point<system_clock, microseconds> &now = time_point_cast<microseconds>(system_clock::now());
            int64_t between = duration_cast<microseconds>(now - lastCheck).count();
            lastCheck = now;
            lastAction += between;

            for (Transition* transition: automaton->getSendingSuccessorsWithClock(step)) {
                const ClockTime::numerator_type &numerator = transition->Sending().get().ClockTime().get().numerator();
                const ClockTime::denominator_type &denominator = transition->Sending().get().ClockTime().get().denominator();
                nextExecution[transition] -= between;
                if (nextExecution[transition] < min) {
                    min = nextExecution[transition];
                    minTrans = transition;
                }
            }

            if (minTrans != NULL && min <= 0) {
                sendTransition(minTrans);
                setStep(minTrans);
                nextExecution[minTrans] = nextExecutionDefault[minTrans];

            } else {
                for (const auto &transition: automaton->getSendingSuccessorsWithoutClock(step)) {
                    if (lastAction >= delay) {
                        sendTransition(transition);
                        setStep(transition);
                        lastAction = 0;
                    }
                    //use first occourence of transition
                    break;
                }
            }
            mutex.unlock();
        }
        manager->Log(SUCCESS);
        for(auto& entry: statistic){
            Transition* trans = entry.first;

            std::vector<int64_t> &values = entry.second;
            std::sort(values.begin(), values.end());
            std::string tranStr = "Transition (" + std::to_string(trans->from()) + " -> " + std::to_string(trans->to()) + ")";

            if(trans->Receiving().present() && trans->Receiving().get().DAT_input_output().present()){
                tranStr += " DAT_input_output data_id = " + std::to_string(trans->Receiving().get().DAT_input_output().get().data_id());
            }
            manager->Log(STATISTIK, tranStr, (uint64_t) values.size(), (values.at((values.size() * 5) / 100) / 1000.0), (values.at((values.size() * 25) / 100) / 1000.0), (values.at((values.size() * 50) / 100) / 1000.0), (values.at((values.size() * 75) / 100) / 1000.0), (values.at((values.size() * 95) / 100) / 1000.0));
        }
        std::exit(0);


    }

    void logPdu(std::string, DcpPdu& msg);


    void pduMissed(uint8_t dcpId){
        manager->Log(FAIL_SEQ_ID_DIFFER, dcpId);
        std::exit(1);
    }



    inline void check(std::chrono::steady_clock::time_point time, bool found, bool correctFields, const char* msg, Transition* transition){
        if(found && correctFields){
            setStep(transition);
            log(time, transition);
        } else {
            if(found){
                manager->Log(FAIL_VALUES_DIFFER, std::string(msg), getAllowedSuccessor());
            } else {
                manager->Log(FAIL_NOT_ALLOWED, std::string(msg), getAllowedSuccessor());
            }
            std::exit(1);
        }
    }

#define printHead(name) \
    if (transition->Receiving()->name().present()) { \
        const Receiving::name##_type &name = transition->Receiving()->name().get();

#define printValue(name) \
    if(field.name().present()){ \
    oss << #name"["; \
    if(field.name().get().value().present()){ \
        oss << "value=["; \
        for(auto& val : field.name().get().value().get()){ \
            oss << std::to_string(val) << ", "; \
        } \
        oss << "], "; \
    } \
    if(field.name().get().min().present()){ \
        oss << "min=" << std::to_string(field.name().get().min().get()) << ", "; \
    } \
    if(field.name().get().max().present()){ \
        oss << "max=" << std::to_string(field.name().get().min().get()) << ", "; \
    } \
}

    std::string getAllowedSuccessor(){
        std::ostringstream oss;
        for(Transition* transition : automaton->getReceivingSuccessors(step)) {

            printHead(RSP_ack)
                oss <<  "RSP_ack[sender=" << std::to_string(RSP_ack.sender()) << "]" << " ";
            } else printHead(RSP_nack)
                oss <<  "RSP_nack[sender=" << std::to_string(RSP_nack.sender()) << ", error_code=" << to_string((DcpError)RSP_nack.error_code())  <<"]" << " ";
            } else printHead(RSP_state_ack)
                oss <<  "RSP_state_ack[sender=" << std::to_string(RSP_state_ack.sender()) << ", state_id=" << to_string(DcpState (RSP_state_ack.state_id())) << "]" << " ";
            } else printHead(RSP_error_ack)
                oss <<  "RSP_error_ack[sender=" << std::to_string(RSP_error_ack.sender()) << ", error_code=" << to_string((DcpError)RSP_error_ack.error_code()) <<"]" << " ";
            } else printHead(RSP_log_ack)
                oss <<  "RSP_log_ack[sender=" << std::to_string(RSP_log_ack.sender()) << ", length=" << std::to_string(RSP_log_ack.length()) << "]" << " ";
            } else printHead(NTF_state_changed)
                oss <<  "NTF_state_changed[sender=" << std::to_string(NTF_state_changed.sender()) << ", state_id=" << to_string(DcpState (NTF_state_changed.state_id())) <<"]" << " ";
            } else printHead(NTF_log)
                oss <<  "NTF_log[sender=" << std::to_string(NTF_log.sender()) << ", length=" << NTF_log.length() << "]" << " ";
            } else printHead(DAT_input_output)
                oss <<  "DAT_input_output[data_id=" << " " << std::to_string(DAT_input_output.data_id()) << ", payload=[";
                for(auto& field: DAT_input_output.ReceivingPayloadField()){
                    oss << "[pos=" << field.pos() << ", ";
                    printValue(Int8);
                    printValue(Int16);
                    printValue(Int32);
                    printValue(Int64);
                    printValue(Uint8);
                    printValue(Uint16);
                    printValue(Uint32);
                    printValue(Uint64);
                    printValue(Float32);
                    printValue(Float64);
                    if(field.String().present()){
                        oss << "String[";
                        for(auto& val : field.String().get().value().get()){
                            oss << val << ", "; \
                        }
                        oss << "]";
                    }
                    if(field.Binary().present()){
                        oss << "Binary[";
                        for(auto& val : field.Binary().get().value().get()){
                            oss << val << ", "; \
                        }
                        oss << "]";
                    }
                    oss << "]";
                }
                oss << "]";
            } else printHead(DAT_parameter)
                oss <<  "DAT_parameter[param_id=" << " " << std::to_string(DAT_parameter.param_id()) << ", payload=[";
                for(auto& field: DAT_parameter.ReceivingPayloadField()){
                    oss << "[pos=" << field.pos() << ", ";
                    printValue(Int8);
                    printValue(Int16);
                    printValue(Int32);
                    printValue(Int64);
                    printValue(Uint8);
                    printValue(Uint16);
                    printValue(Uint32);
                    printValue(Uint64);
                    printValue(Float32);
                    printValue(Float64);
                    if(field.String().present()){
                        oss << "String[";
                        for(auto& val : field.String().get().value().get()){
                            oss << val << ", "; \
                        }
                        oss << "]";
                    }
                    if(field.Binary().present()){
                        oss << "Binary[";
                        for(auto& val : field.Binary().get().value().get()){
                            oss << val << ", "; \
                        }
                        oss << "]";
                    }
                    oss << "]";
                }
                oss << "]";

            }
        }
        return oss.str();
    }

    const LogTemplate SUCCESS = LogTemplate(1, 1, DcpLogLevel::LVL_INFORMATION,"DCP Test Procedure successfull.",{});
    const LogTemplate FAIL_VALUES_DIFFER = LogTemplate(2, 1, DcpLogLevel::LVL_INFORMATION,"The values for %string are not as expected. One of the following PDUs are allowed to receive: %string",{DcpDataType::string, DcpDataType::string});
    const LogTemplate FAIL_NOT_ALLOWED = LogTemplate(3, 1, DcpLogLevel::LVL_INFORMATION,"%string is not allowed. One of the following PDUs are allowed to receive: %string",{DcpDataType::string, DcpDataType::string});
    const LogTemplate FAIL_SEQ_ID_DIFFER = LogTemplate(4, 1, DcpLogLevel::LVL_INFORMATION,"A receiving rsp_seq_id for slave %uint8 was out of sync.",{DcpDataType::uint8});
    const LogTemplate STATISTIK = LogTemplate(5, 1, DcpLogLevel::LVL_INFORMATION,"Statistic [Time Between PDUs] for %string [N=%uint64]: 5th Percentile=%float64, 25th Percentile=%float64, 50th Percentile=%float64, 75th Percentile=%float64, 95th Percentile=%float64",{DcpDataType::string, DcpDataType::uint64, DcpDataType::float64, DcpDataType::float64,DcpDataType::float64, DcpDataType::float64, DcpDataType::float64});

};





#endif //DCP_TESTER_DCPTESTER_H
