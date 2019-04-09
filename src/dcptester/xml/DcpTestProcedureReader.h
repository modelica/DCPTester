/*
 * Copyright (C) 2019, FG Simulation und Modellierung, Leibniz Universität Hannover, Germany
 *
 * All rights reserved.
 *
 * This software may be modified and distributed under the terms
 * of the BSD 3-CLause license.  See the LICENSE file for details.
 */

#ifndef DCP_TESTER_DCPTESTPROCEDUREREADER_H
#define DCP_TESTER_DCPTESTPROCEDUREREADER_H

#include <xercesc/parsers/XercesDOMParser.hpp>
#include <iostream>
#include <xercesc/sax/SAXParseException.hpp>
#include "DcpTestProcedure.hxx"
#define XERCES_VERSION xercesc

static DcpTestSuite::DcpTestProcedure* readDcpTestProcedure(const char *acuDFile) {
    using namespace XERCES_VERSION;
    // Initialize xerces
    try {
        XMLPlatformUtils::Initialize();
    }
    catch (const XMLException& toCatch) {
        char* message = XMLString::transcode(toCatch.getMessage());
        XMLString::release(&message);
        //toDo
    }
    /*MemBufInputSource mAciAnnotation ((const XMLByte* ) ACI_XSD_ACI_ANNOTATION.c_str (), ACI_XSD_ACI_ANNOTATION.size (), "/aciAnnotation.xsd");
    MemBufInputSource mAciAttributeGroups ((const XMLByte* ) ACI_XSD_ACI_ATTRIBUTE_GROUPS.c_str (), ACI_XSD_ACI_ATTRIBUTE_GROUPS.size (), "/aciAttributeGroups.xsd");
    MemBufInputSource mAciDescription ((const XMLByte* ) ACI_XSD_ACI_DESCRIPTION.c_str (), ACI_XSD_ACI_DESCRIPTION.size (), "/aciDescription.xsd");
    MemBufInputSource mAciType ((const XMLByte* ) ACI_XSD_ACI_TYPE.c_str (), ACI_XSD_ACI_TYPE.size (), "/aciType.xsd");
    MemBufInputSource mAciUnit ((const XMLByte* ) ACI_XSD_ACI_UNIT.c_str (), ACI_XSD_ACI_UNIT.size (), "/aciUnit.xsd");
    MemBufInputSource mAciVariable ((const XMLByte* ) ACI_XSD_ACI_VARIABLE.c_str (), ACI_XSD_ACI_VARIABLE.size (), "/aciVariable.xsd");
    MemBufInputSource mAciVariableDependency ((const XMLByte* ) ACI_XSD_ACI_VARIABLE.c_str (), ACI_XSD_ACI_VARIABLE.size (), "/aciVariableDependency.xsd");*/

    XercesDOMParser* parser = new XercesDOMParser();
   /* parser->setExternalNoNamespaceSchemaLocation("DcpTestProcedure.xsd");
    parser->setExitOnFirstFatalError(true);
    parser->setValidationConstraintFatal(true);
    parser->setValidationScheme(XercesDOMParser::Val_Auto);
    parser->setDoNamespaces(true);
    parser->setDoSchema(true);*/


    try
    {
        parser->parse(XMLString::transcode(acuDFile));
    }
    catch (const  xercesc::XMLException& toCatch)
    {
        char* message =  xercesc::XMLString::transcode(toCatch.getMessage());
        std::cout << "Exception message is: "<< message << std::endl;;
        xercesc::XMLString::release(&message);
    }
    catch (const  xercesc::SAXParseException& toCatch)
    {
        char* message =  xercesc::XMLString::transcode(toCatch.getMessage());
        std::cout << "Exception message is: " << message << std::endl;;
        xercesc::XMLString::release(&message);
    }
    if (parser->getErrorCount() != 0) {
        std::cout << "Invalid XML vs. XSD: found " << parser->getErrorCount() << " errors!" << std::endl;

    } else {
        std::cout << "Parsing found no errors" << std::endl;
    }
    DOMElement* acuDescriptionElement;
    DOMDocument* doc;
    doc = parser->getDocument();
    acuDescriptionElement = doc->getDocumentElement();

    return new DcpTestSuite::DcpTestProcedure(*acuDescriptionElement);
}
#endif //DCP_TESTER_DCPTESTPROCEDUREREADER_H
