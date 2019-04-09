/*
 * Copyright (C) 2019, FG Simulation und Modellierung, Leibniz Universität Hannover, Germany
 *
 * All rights reserved.
 *
 * This software may be modified and distributed under the terms
 * of the BSD 3-CLause license.  See the LICENSE file for details.
 */

#ifndef DCP_TESTER_AUTOMATON_H
#define DCP_TESTER_AUTOMATON_H


#include <dcp/model/pdu/DcpPduFactory.hpp>
#include "dcptester/xml/DcpTestProcedure.hxx"
#include <vector>

using namespace DcpTestSuite;

class Automaton {

public:

    Automaton(){

    }

    inline void init(DcpTestProcedure& testProcedure){
        for(Transition& transition: testProcedure.Transition()){
            if(transition.Sending().present()){
                if(transition.Sending().get().ClockTime().present()){
                    sendingSuccessorsWithClock[transition.from()].push_back(&transition);
                } else {
                    sendingSuccessorsWithoutClock[transition.from()].push_back(&transition);
                }
            } else if(transition.Receiving().present()){
                receivingSuccessors[transition.from()].push_back(&transition);
            } else {
                //toDO find better exception
                throw std::exception();
            }
        }
        for(uint32_t step : testProcedure.acceptingSteps().get()){
            acceptingSteps.insert(step);
        }
    }

    inline std::vector<Transition*>& getSendingSuccessorsWithClock(uint32_t step){
        return sendingSuccessorsWithClock[step];
    }

    inline std::vector<Transition*>& getSendingSuccessorsWithoutClock(uint32_t step){
        return sendingSuccessorsWithoutClock[step];
    }

    inline std::vector<Transition*> getReceivingSuccessors(uint32_t step){
        return receivingSuccessors[step];
    }

    inline bool isAccepting(uint32_t step){
        return acceptingSteps.count(step) > 0;
    }

private:

    std::map<uint32_t, std::vector<Transition*>> sendingSuccessorsWithClock;
    std::map<uint32_t, std::vector<Transition*>> sendingSuccessorsWithoutClock;

    std::map<uint32_t, std::vector<Transition*>> receivingSuccessors;
    std::set<uint32_t> acceptingSteps;

};


#endif //DCP_TESTER_AUTOMATON_H
