
#ifndef SLAVE_H_
#define SLAVE_H_

#include <dcp/helper/Helper.hpp>
#include <dcp/log/OstreamLog.hpp>
#include <dcp/logic/DcpManagerSlave.hpp>
#include <dcp/model/pdu/DcpPduFactory.hpp>
#include <dcp/driver/ethernet/udp/UdpDriver.hpp>

#include <cstdint>
#include <cstdio>
#include <stdarg.h>
#include <thread>
#include <cmath>

#include <dcp/xml/DcpSlaveDescriptionWriter.hpp>

static std::string to_string(const uint8_t* binary, uint32_t len) {
    std::stringstream hs;
    for (size_t i = 0; i < len; ++i)
        hs << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << (int)binary[i];
    return hs.str();
}
class Slave {
public:
    Slave() : stdLog(std::cout) {
        udpDriver = new UdpDriver(HOST, PORT);

        SlaveDescription = getSlaveDescription();
        //std::string descFile = std::string("SlaveUnderTest.dcpx");
        writeDcpSlaveDescription(SlaveDescription, "SlaveUnderTest.dcpx");

        manager = new DcpManagerSlave(SlaveDescription, udpDriver->getDcpDriver());
        manager->setInitializeCallback<SYNC>(
                std::bind(&Slave::initialize, this));
        manager->setConfigureCallback<SYNC>(
                std::bind(&Slave::configure, this));
        
        manager->setSynchronizingStepCallback<SYNC>(
                std::bind(&Slave::doStep, this, std::placeholders::_1));
        manager->setSynchronizedStepCallback<SYNC>(
                std::bind(&Slave::doStep, this, std::placeholders::_1));
        manager->setRunningStepCallback<SYNC>(
                std::bind(&Slave::doStep, this, std::placeholders::_1));
        manager->setTimeResListener<SYNC>(std::bind(&Slave::setTimeRes, this,
                                                    std::placeholders::_1,
                                                    std::placeholders::_2));

        //Display log messages on console
        manager->addLogListener(
                std::bind(&OstreamLog::logOstream, stdLog, std::placeholders::_1));
        manager->setGenerateLogString(true);


    }

    ~Slave() {
        delete manager;
        delete udpDriver;

        delete [] tmpbin;
    }


    void configure() {
        simulationTime = 0;
        currentStep = 0;

        OutputUInt8 = manager->getOutput<uint8_t *>(OutputUInt8_vr);
        InputUInt8 = manager->getInput<uint8_t *>(InputUInt8_vr);

        OutputUInt16 = manager->getOutput<uint16_t *>(OutputUInt16_vr);
        InputUInt16 = manager->getInput<uint16_t *>(InputUInt16_vr);

        OutputUInt32 = manager->getOutput<uint32_t *>(OutputUInt32_vr);
        InputUInt32 = manager->getInput<uint32_t *>(InputUInt32_vr);

        OutputUInt64 = manager->getOutput<uint64_t *>(OutputUInt64_vr);
        InputUInt64 = manager->getInput<uint64_t *>(InputUInt64_vr);

        OutputInt8 = manager->getOutput<int8_t *>(OutputInt8_vr);
        InputInt8 = manager->getInput<int8_t *>(InputInt8_vr);

        OutputInt16 = manager->getOutput<int16_t *>(OutputInt16_vr);
        InputInt16 = manager->getInput<int16_t *>(InputInt16_vr);

        OutputInt32 = manager->getOutput<int32_t *>(OutputInt32_vr);
        InputInt32 = manager->getInput<int32_t *>(InputInt32_vr);

        OutputInt64 = manager->getOutput<int64_t *>(OutputInt64_vr);
        InputInt64 = manager->getInput<int64_t *>(InputInt64_vr);

        Outputf32 = manager->getOutput<float32_t *>(Outputf32_vr);
        Inputf32 = manager->getInput<float32_t *>(Inputf32_vr);

        Outputf64 = manager->getOutput<float64_t *>(Outputf64_vr);
        Inputf64 = manager->getInput<float64_t *>(Inputf64_vr);

        InputtStr = manager->getInput<char*>(InputStr_vr);
        InputDcpstr = new DcpString(InputtStr);
        OutputStr = manager->getOutput<char*>(OutputStr_vr);
        OutputDcpstr = new DcpString(OutputStr);

        InputBin = manager->getInput<uint8_t*>(InputBin_vr);
        InputDcpbin = new DcpBinary(InputBin);

        OutputBin = manager->getOutput<uint8_t*>(OutputBin_vr);
        OutputDcpbin = new DcpBinary(OutputBin);
    }

    void initialize() {
    }

    void ModStr(std::string &input) {
        for (char& c : input)
        {
            c = (char)(((int)c +1 - 97) % 26 + 97);
        }
    }
    void doStep(uint64_t steps) {
        float64_t timeDiff =
                ((double) numerator) / ((double) denominator) * ((double) steps);

        uint32_t size = InputDcpbin->getSize();
        std::cout << "Size of binary input " << size << std::endl;
        std::cout << "Value of binary input " << to_string(InputDcpbin->getBinary(),size) << std::endl;
        std::cout << "Value of binary input(payload) " << to_string(InputDcpbin->getPayload(), size + 4) << std::endl;
        std::copy(InputDcpbin->getBinary(), InputDcpbin->getBinary() + size, tmpbin);
        tmpbin[0] += 1;
        tmpbin[1] += 1;
        tmpbin[2] += 1;
        tmpbin[3] += 1;
        tmpbin[4] += 1;
        tmpbin[5] += 1;
        tmpbin[6] += 1;
        tmpbin[7] += 1;
        OutputDcpbin->setBinary(8, tmpbin);
        
        std::cout << "Value of Input64 " << *Inputf64 << std::endl;
        *Outputf64 = *Inputf64 + 1;

        std::cout << "Value of Input32 " << *Inputf64 << std::endl;
        *Outputf32 = *Inputf32 + 1;

        *OutputUInt8  = *InputUInt8  + 1;
        *OutputUInt16 = *InputUInt16 + 1;

        *OutputUInt32 = *InputUInt32 + 1;
        *OutputUInt64 = *InputUInt64 + 1;


        *OutputInt8  = *InputInt8  + 1;
        *OutputInt16 = *InputInt16 + 1;
        *OutputInt32 = *InputInt32 + 1;
        *OutputInt64 = *InputInt64 + 1;

        std::cout << "Value of string input " << InputDcpstr->getString() << std::endl;
        std::string input = InputDcpstr->getString();
        ModStr(input);
        std::cout << "Modstring " << input << std::endl;
        OutputDcpstr->setString(input);
        std::cout << "Value of string output " << OutputDcpstr->getString() << std::endl;
        
        

        //manager->Log(SIM_LOG, simulationTime, currentStep, *a, *y);
        simulationTime += timeDiff;
        currentStep += steps;
    }

    void setTimeRes(const uint32_t numerator, const uint32_t denominator) {
        this->numerator = numerator;
        this->denominator = denominator;
    }

    void start() { manager->start(); }

    SlaveDescription_t getSlaveDescription(){
        SlaveDescription_t slaveDescription = make_SlaveDescription(1, 0, "SlaveUnderTest", "0d7217ea-ac72-11ea-bb37-0242ac130002");
        slaveDescription.OpMode.SoftRealTime = make_SoftRealTime_ptr();
        slaveDescription.OpMode.NonRealTime = make_NonRealTime_ptr();
        Resolution_t resolution = make_Resolution();
        resolution.numerator = 10;
        resolution.denominator = 10000;
        resolution.fixed = false;
        slaveDescription.TimeRes.resolutions.push_back(resolution);
        Resolution_t resolution2 = make_Resolution();
        resolution2.numerator = 10;
        resolution2.denominator = 100;
        resolution2.fixed = false;
        slaveDescription.TimeRes.resolutions.push_back(resolution2);
		Resolution_t resolution3 = make_Resolution();
        resolution3.numerator = 5;
        resolution3.denominator = 100;
        resolution3.fixed = false;
        slaveDescription.TimeRes.resolutions.push_back(resolution3);
        slaveDescription.TransportProtocols.UDP_IPv4 = make_UDP_ptr();
        slaveDescription.TransportProtocols.UDP_IPv4->Control =
                make_Control_ptr(HOST, 8080);
        ;
        slaveDescription.TransportProtocols.UDP_IPv4->DAT_input_output = make_DAT_ptr();
        slaveDescription.TransportProtocols.UDP_IPv4->DAT_input_output->availablePortRanges.push_back(
                make_AvailablePortRange(2048, 65535));
        slaveDescription.TransportProtocols.UDP_IPv4->DAT_parameter = make_DAT_ptr();
        slaveDescription.TransportProtocols.UDP_IPv4->DAT_parameter->availablePortRanges.push_back(
                make_AvailablePortRange(2048, 65535));
        slaveDescription.CapabilityFlags.canAcceptConfigPdus = true;
        slaveDescription.CapabilityFlags.canHandleReset = true;
        slaveDescription.CapabilityFlags.canHandleVariableSteps = true;
        slaveDescription.CapabilityFlags.canMonitorHeartbeat = false;
        slaveDescription.CapabilityFlags.canAcceptConfigPdus = true;

        // TODO
        slaveDescription.CapabilityFlags.canProvideLogOnRequest = true;
        slaveDescription.CapabilityFlags.canProvideLogOnNotification = true;

        slaveDescription.Variables.push_back(make_Variable_output("OutputUInt8", OutputUInt8_vr, make_Output_ptr<uint8_t>()));
        std::shared_ptr<CommonCausality_t> caus_InputUInt8_vr = make_CommonCausality_ptr<uint8_t>();
        caus_InputUInt8_vr->Uint8->start = std::make_shared<std::vector<uint8_t>>();
        caus_InputUInt8_vr->Uint8->start->push_back(97);
        slaveDescription.Variables.push_back(make_Variable_input("InputUInt8", InputUInt8_vr, caus_InputUInt8_vr));

        slaveDescription.Variables.push_back(make_Variable_output("OutputUInt16", OutputUInt16_vr, make_Output_ptr<uint16_t>()));
        std::shared_ptr<CommonCausality_t> caus_InputUInt16_vr = make_CommonCausality_ptr<uint16_t>();
        caus_InputUInt16_vr->Uint16->start = std::make_shared<std::vector<uint16_t>>();
        caus_InputUInt16_vr->Uint16->start->push_back(2);
        slaveDescription.Variables.push_back(make_Variable_input("InputUInt16", InputUInt16_vr, caus_InputUInt16_vr));

        slaveDescription.Variables.push_back(make_Variable_output("OutputUInt32", OutputUInt32_vr, make_Output_ptr<uint32_t>()));
        std::shared_ptr<CommonCausality_t> caus_InputUInt32_vr = make_CommonCausality_ptr<uint32_t>();
        caus_InputUInt32_vr->Uint32->start = std::make_shared<std::vector<uint32_t>>();
        caus_InputUInt32_vr->Uint32->start->push_back(2);
        slaveDescription.Variables.push_back(make_Variable_input("InputUInt32", InputUInt32_vr, caus_InputUInt32_vr));

        slaveDescription.Variables.push_back(make_Variable_output("OutputUInt64", OutputUInt64_vr, make_Output_ptr<uint64_t>()));
        std::shared_ptr<CommonCausality_t> caus_InputUInt64_vr = make_CommonCausality_ptr<uint64_t>();
        caus_InputUInt64_vr->Uint64->start = std::make_shared<std::vector<uint64_t>>();
        caus_InputUInt64_vr->Uint64->start->push_back(2);
        slaveDescription.Variables.push_back(make_Variable_input("InputUInt64", InputUInt64_vr, caus_InputUInt64_vr));

        slaveDescription.Variables.push_back(make_Variable_output("OutputInt8", OutputInt8_vr, make_Output_ptr<int8_t>()));
        std::shared_ptr<CommonCausality_t> caus_InputInt8_vr = make_CommonCausality_ptr<int8_t>();
        caus_InputInt8_vr->Int8->start = std::make_shared<std::vector<int8_t>>();
        caus_InputInt8_vr->Int8->start->push_back((int8_t)97);
        slaveDescription.Variables.push_back(make_Variable_input("InputInt8", InputInt8_vr, caus_InputInt8_vr));

        slaveDescription.Variables.push_back(make_Variable_output("OutputInt16", OutputInt16_vr, make_Output_ptr<int16_t>()));
        std::shared_ptr<CommonCausality_t> caus_InputInt16_vr = make_CommonCausality_ptr<int16_t>();
        caus_InputInt16_vr->Int16->start = std::make_shared<std::vector<int16_t>>();
        caus_InputInt16_vr->Int16->start->push_back(2);
        slaveDescription.Variables.push_back(make_Variable_input("InputInt16", InputInt16_vr, caus_InputInt16_vr));

        slaveDescription.Variables.push_back(make_Variable_output("OutputInt32", OutputInt32_vr, make_Output_ptr<int32_t>()));
        std::shared_ptr<CommonCausality_t> caus_InputInt32_vr = make_CommonCausality_ptr<int32_t>();
        caus_InputInt32_vr->Int32->start = std::make_shared<std::vector<int32_t>>();
        caus_InputInt32_vr->Int32->start->push_back(2);
        slaveDescription.Variables.push_back(make_Variable_input("InputInt32", InputInt32_vr, caus_InputInt32_vr));

        slaveDescription.Variables.push_back(make_Variable_output("OutputInt64", OutputInt64_vr, make_Output_ptr<int64_t>()));
        std::shared_ptr<CommonCausality_t> caus_InputInt64_vr = make_CommonCausality_ptr<int64_t>();
        caus_InputInt64_vr->Int64->start = std::make_shared<std::vector<int64_t>>();
        caus_InputInt64_vr->Int64->start->push_back(2);
        slaveDescription.Variables.push_back(make_Variable_input("InputInt64", InputInt64_vr, caus_InputInt64_vr));

        slaveDescription.Variables.push_back(make_Variable_output("Outputf32", Outputf32_vr, make_Output_ptr<float32_t>()));
        std::shared_ptr<CommonCausality_t> caus_Inputf32 = make_CommonCausality_ptr<float32_t>();
        caus_Inputf32->Float32->start = std::make_shared<std::vector<float32_t>>();
        caus_Inputf32->Float32->start->push_back(10.0);
        slaveDescription.Variables.push_back(make_Variable_input("Inputf32", Inputf32_vr, caus_Inputf32));

        slaveDescription.Variables.push_back(make_Variable_output("Outputf64", Outputf64_vr, make_Output_ptr<float64_t>()));
        std::shared_ptr<CommonCausality_t> caus_Inputf64 = make_CommonCausality_ptr<float64_t>();
        caus_Inputf64->Float64->start = std::make_shared<std::vector<float64_t>>();
        caus_Inputf64->Float64->start->push_back(10.0);
        slaveDescription.Variables.push_back(make_Variable_input("Inputf64", Inputf64_vr, caus_Inputf64));

        std::shared_ptr<Output_t> caus_OutputBin = make_Output_Binary_ptr();
        caus_OutputBin->Binary->maxSize = std::make_shared<uint32_t>(100);
        slaveDescription.Variables.push_back(make_Variable_output("OutputBin", OutputBin_vr, caus_OutputBin));

        std::shared_ptr<CommonCausality_t> caus_InputBin = make_CommonCausality_Binary_ptr();
        caus_InputBin->Binary->maxSize = std::make_shared<uint32_t>(100);
        
        caus_InputBin->Binary->start = std::make_shared<BinaryStartValue>();
        caus_InputBin->Binary->start->length = 12;

        caus_InputBin->Binary->start->value = new uint8_t[12];
        caus_InputBin->Binary->start->value[0] = 1;
        caus_InputBin->Binary->start->value[1] = 2;
        caus_InputBin->Binary->start->value[2] = 3;
        caus_InputBin->Binary->start->value[3] = 4;
        caus_InputBin->Binary->start->value[4] = 5;
        caus_InputBin->Binary->start->value[5] = 6;
        caus_InputBin->Binary->start->value[6] = 7;
        caus_InputBin->Binary->start->value[7] = 8;
        caus_InputBin->Binary->start->value[8] = 7;
        caus_InputBin->Binary->start->value[9] = 8;
        caus_InputBin->Binary->start->value[10] = 7;
        caus_InputBin->Binary->start->value[11] = 8;
        
        slaveDescription.Variables.push_back(make_Variable_input("InputBin", InputBin_vr, caus_InputBin));
        

        std::shared_ptr<Output_t> caus_OutputStr = make_Output_String_ptr();
        caus_OutputStr->String->maxSize = std::make_shared<uint32_t>(200);
        slaveDescription.Variables.push_back(make_Variable_output("OutputStr", OutputStr_vr, caus_OutputStr));

        std::shared_ptr<CommonCausality_t> caus_InputStr = make_CommonCausality_String_ptr();
        caus_InputStr->String->maxSize = std::make_shared<uint32_t>(200);
        caus_InputStr->String->start = std::make_shared<std::string>("abaab");
        slaveDescription.Variables.push_back(make_Variable_input("InputStr", InputStr_vr, caus_InputStr));

        ////////// Parameter:////////// Parameter:
        std::shared_ptr<CommonCausality_t> caus_ParaUInt8 = make_CommonCausality_ptr<uint8_t>();
        caus_ParaUInt8->Uint8->start = std::make_shared<std::vector<uint8_t>>();
        caus_ParaUInt8->Uint8->start->push_back(3);
        slaveDescription.Variables.push_back(make_Variable_parameter("ParaUInt8", ParaUInt8_vr, caus_ParaUInt8));

        std::shared_ptr<CommonCausality_t> caus_ParaUInt16 = make_CommonCausality_ptr<uint16_t>();
        caus_ParaUInt16->Uint16->start = std::make_shared<std::vector<uint16_t>>();
        caus_ParaUInt16->Uint16->start->push_back(3);
        slaveDescription.Variables.push_back(make_Variable_parameter("ParaUInt16", ParaUInt16_vr, caus_ParaUInt16));

        std::shared_ptr<CommonCausality_t> caus_ParaUInt32 = make_CommonCausality_ptr<uint32_t>();
        caus_ParaUInt32->Uint32->start = std::make_shared<std::vector<uint32_t>>();
        caus_ParaUInt32->Uint32->start->push_back(3);
        slaveDescription.Variables.push_back(make_Variable_parameter("ParaUInt32", ParaUInt32_vr, caus_ParaUInt32));

        std::shared_ptr<CommonCausality_t> caus_ParaUInt64 = make_CommonCausality_ptr<uint64_t>();
        caus_ParaUInt64->Uint64->start = std::make_shared<std::vector<uint64_t>>();
        caus_ParaUInt64->Uint64->start->push_back(3);
        slaveDescription.Variables.push_back(make_Variable_parameter("ParaUInt64", ParaUInt64_vr, caus_ParaUInt64));

        std::shared_ptr<CommonCausality_t> caus_ParaInt8 = make_CommonCausality_ptr<int8_t>();
        caus_ParaInt8->Int8->start = std::make_shared<std::vector<int8_t>>();
        caus_ParaInt8->Int8->start->push_back(-3);
        slaveDescription.Variables.push_back(make_Variable_parameter("ParaInt8", ParaInt8_vr, caus_ParaInt8));

        std::shared_ptr<CommonCausality_t> caus_ParaInt16 = make_CommonCausality_ptr<int16_t>();
        caus_ParaInt16->Int16->start = std::make_shared<std::vector<int16_t>>();
        caus_ParaInt16->Int16->start->push_back(-3);
        slaveDescription.Variables.push_back(make_Variable_parameter("ParaInt16", ParaInt16_vr, caus_ParaInt16));

        std::shared_ptr<CommonCausality_t> caus_ParaInt32 = make_CommonCausality_ptr<int32_t>();
        caus_ParaInt32->Int32->start = std::make_shared<std::vector<int32_t>>();
        caus_ParaInt32->Int32->start->push_back(-3);
        slaveDescription.Variables.push_back(make_Variable_parameter("ParaInt32", ParaInt32_vr, caus_ParaInt32));

        std::shared_ptr<CommonCausality_t> caus_ParaInt64 = make_CommonCausality_ptr<int64_t>();
        caus_ParaInt64->Int64->start = std::make_shared<std::vector<int64_t>>();
        caus_ParaInt64->Int64->start->push_back(-3);
        slaveDescription.Variables.push_back(make_Variable_parameter("ParaInt64", ParaInt64_vr, caus_ParaInt64));

        std::shared_ptr<CommonCausality_t> caus_Paraf32 = make_CommonCausality_ptr<float32_t>();
        caus_Paraf32->Float32->start = std::make_shared<std::vector<float32_t>>();
        caus_Paraf32->Float32->start->push_back(3.0);
        slaveDescription.Variables.push_back(make_Variable_parameter("Paraf32", Paraf32_vr, caus_Paraf32));

        std::shared_ptr<CommonCausality_t> caus_Paraf64 = make_CommonCausality_ptr<float64_t>();
        caus_Paraf64->Float64->start = std::make_shared<std::vector<float64_t>>();
        caus_Paraf64->Float64->start->push_back(3.0);
        slaveDescription.Variables.push_back(make_Variable_parameter("Paraf64", Paraf64_vr, caus_Paraf64));



        slaveDescription.Log = make_Log_ptr();
        slaveDescription.Log->categories.push_back(make_Category(1, "DCP_SLAVE"));
        slaveDescription.Log->templates.push_back(make_Template(
                1, 1, (uint8_t) DcpLogLevel::LVL_INFORMATION, "[Time = %float64]: sin(%uint64 + %float64) = %float64"));

       return slaveDescription;
    }

private:
    DcpManagerSlave *manager;
    OstreamLog stdLog;

    UdpDriver* udpDriver;
    const char *const HOST = "127.0.0.1";
    //const char *const HOST = "172.20.8.141";
    const int PORT = 8080;

    uint32_t numerator;
    uint32_t denominator;

    double simulationTime;
    uint64_t currentStep;

    const LogTemplate SIM_LOG = LogTemplate(
            1, 1, DcpLogLevel::LVL_INFORMATION,
            "[Time = %float64]: sin(%uint64 + %float64) = %float64",
            {DcpDataType::float64, DcpDataType::uint64, DcpDataType::float64, DcpDataType::float64});

    SlaveDescription_t SlaveDescription;

    uint8_t *OutputUInt8;
    const uint32_t OutputUInt8_vr = 1;
    uint8_t *InputUInt8;
    const uint32_t InputUInt8_vr = 2;

    uint16_t *OutputUInt16;
    const uint32_t OutputUInt16_vr = 3;
    uint16_t *InputUInt16;
    const uint32_t InputUInt16_vr = 4;

    uint32_t *OutputUInt32;
    const uint32_t OutputUInt32_vr = 5;
    uint32_t *InputUInt32;
    const uint32_t InputUInt32_vr = 6;

    uint64_t *OutputUInt64;
    const uint64_t OutputUInt64_vr = 7;
    uint64_t *InputUInt64;
    const uint32_t InputUInt64_vr = 8;

    int8_t *OutputInt8;
    const uint32_t OutputInt8_vr = 9;
    int8_t *InputInt8;
    const uint32_t InputInt8_vr = 10;

    int16_t *OutputInt16;
    const uint32_t OutputInt16_vr = 11;
    int16_t *InputInt16;
    const uint32_t InputInt16_vr = 12;

    int32_t *OutputInt32;
    const uint32_t OutputInt32_vr = 13;
    int32_t *InputInt32;
    const uint32_t InputInt32_vr = 14;

    int64_t *OutputInt64;
    const uint64_t OutputInt64_vr = 15;
    int64_t *InputInt64;
    const uint32_t InputInt64_vr = 16;

    float32_t *Outputf32;
    const uint32_t Outputf32_vr = 17;
    float32_t *Inputf32;
    const uint32_t Inputf32_vr = 18;

    float64_t *Outputf64;
    const uint32_t Outputf64_vr = 19;
    float64_t *Inputf64;
    const uint32_t Inputf64_vr = 20;

    uint8_t *OutputBin;
    uint8_t *InputBin;
    DcpBinary *OutputDcpbin;
    const uint32_t OutputBin_vr = 21;
    DcpBinary *InputDcpbin;
    const uint32_t InputBin_vr = 22;

    char *OutputStr;
    DcpString *OutputDcpstr;
    const uint32_t OutputStr_vr = 23;
    char *InputtStr;
    DcpString *InputDcpstr;
    const uint32_t InputStr_vr = 24;

    const uint32_t ParaUInt8_vr  = 26;
    const uint32_t ParaUInt16_vr = 27;
    const uint32_t ParaUInt32_vr = 28;
    const uint32_t ParaUInt64_vr = 29;

    const uint32_t ParaInt8_vr  = 30;
    const uint32_t ParaInt16_vr = 31;
    const uint32_t ParaInt32_vr = 32;
    const uint32_t ParaInt64_vr = 33;

    const uint32_t Paraf32_vr = 34;
    const uint32_t Paraf64_vr = 35;

    const uint32_t ParaBin_vr = 36;
    const uint32_t ParaStr_vr = 37;
   

    uint8_t* tmpbin = new uint8_t[48];

};

#endif /* SLAVE_H_ */
