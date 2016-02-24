// Copyright (c) 2008 The Board of Trustees of The Leland Stanford Junior University
// Copyright (c) 2011, 2012 Open Networking Foundation
// Copyright (c) 2012, 2013 Big Switch Networks, Inc.
// This library was generated by the LoxiGen Compiler.
// See the file LICENSE.txt which should have been included in the source distribution

// Automatically generated by LOXI from template of_interface.java
// Do not modify

package org.projectfloodlight.openflow.protocol;

import org.projectfloodlight.openflow.protocol.*;
import org.projectfloodlight.openflow.protocol.action.*;
import org.projectfloodlight.openflow.protocol.actionid.*;
import org.projectfloodlight.openflow.protocol.bsntlv.*;
import org.projectfloodlight.openflow.protocol.errormsg.*;
import org.projectfloodlight.openflow.protocol.meterband.*;
import org.projectfloodlight.openflow.protocol.instruction.*;
import org.projectfloodlight.openflow.protocol.instructionid.*;
import org.projectfloodlight.openflow.protocol.match.*;
import org.projectfloodlight.openflow.protocol.oxm.*;
import org.projectfloodlight.openflow.protocol.queueprop.*;
import org.projectfloodlight.openflow.types.*;
import org.projectfloodlight.openflow.util.*;
import org.projectfloodlight.openflow.exceptions.*;
import java.util.Set;
import org.jboss.netty.buffer.ChannelBuffer;

public interface OFCalientPortDescPropOptical extends OFObject, OFCalientPortDescProp {
    int getType();
    Set<OFCalientOpticalPortAdminState> getInAdminStatus();
    Set<OFCalientOpticalPortOperState> getInOperStatus();
    Set<OFCalientOpticalPortOperCapability> getInOperCapability();
    Set<OFCalientOpticalPortAdminState> getOutAdminStatus();
    Set<OFCalientOpticalPortOperState> getOutOperStatus();
    Set<OFCalientOpticalPortOperCapability> getOutOperCapability();
    String getInportPower();
    String getOutportPower();
    U64 getInPeerNode();
    U64 getOutPeerNode();
    int getInPeerPort();
    int getOutPeerPort();
    String getInCircuitId();
    String getOutCircuitId();
    String getInAlias();
    String getOutAlias();
    OFVersion getVersion();


    void writeTo(ChannelBuffer channelBuffer);

    Builder createBuilder();
    public interface Builder extends OFCalientPortDescProp.Builder {
        OFCalientPortDescPropOptical build();
        int getType();
        Set<OFCalientOpticalPortAdminState> getInAdminStatus();
        Builder setInAdminStatus(Set<OFCalientOpticalPortAdminState> inAdminStatus);
        Set<OFCalientOpticalPortOperState> getInOperStatus();
        Builder setInOperStatus(Set<OFCalientOpticalPortOperState> inOperStatus);
        Set<OFCalientOpticalPortOperCapability> getInOperCapability();
        Builder setInOperCapability(Set<OFCalientOpticalPortOperCapability> inOperCapability);
        Set<OFCalientOpticalPortAdminState> getOutAdminStatus();
        Builder setOutAdminStatus(Set<OFCalientOpticalPortAdminState> outAdminStatus);
        Set<OFCalientOpticalPortOperState> getOutOperStatus();
        Builder setOutOperStatus(Set<OFCalientOpticalPortOperState> outOperStatus);
        Set<OFCalientOpticalPortOperCapability> getOutOperCapability();
        Builder setOutOperCapability(Set<OFCalientOpticalPortOperCapability> outOperCapability);
        String getInportPower();
        Builder setInportPower(String inportPower);
        String getOutportPower();
        Builder setOutportPower(String outportPower);
        U64 getInPeerNode();
        Builder setInPeerNode(U64 inPeerNode);
        U64 getOutPeerNode();
        Builder setOutPeerNode(U64 outPeerNode);
        int getInPeerPort();
        Builder setInPeerPort(int inPeerPort);
        int getOutPeerPort();
        Builder setOutPeerPort(int outPeerPort);
        String getInCircuitId();
        Builder setInCircuitId(String inCircuitId);
        String getOutCircuitId();
        Builder setOutCircuitId(String outCircuitId);
        String getInAlias();
        Builder setInAlias(String inAlias);
        String getOutAlias();
        Builder setOutAlias(String outAlias);
        OFVersion getVersion();
    }
}
