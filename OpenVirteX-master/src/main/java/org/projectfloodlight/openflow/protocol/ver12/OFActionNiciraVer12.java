// Copyright (c) 2008 The Board of Trustees of The Leland Stanford Junior University
// Copyright (c) 2011, 2012 Open Networking Foundation
// Copyright (c) 2012, 2013 Big Switch Networks, Inc.
// This library was generated by the LoxiGen Compiler.
// See the file LICENSE.txt which should have been included in the source distribution

// Automatically generated by LOXI from template of_virtual_class.java
// Do not modify

package org.projectfloodlight.openflow.protocol.ver12;

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
import org.jboss.netty.buffer.ChannelBuffer;
import java.util.Set;

abstract class OFActionNiciraVer12 {
    // version: 1.2
    final static byte WIRE_VERSION = 3;
    final static int MINIMUM_LENGTH = 16;


    public final static OFActionNiciraVer12.Reader READER = new Reader();

    static class Reader implements OFMessageReader<OFActionNicira> {
        @Override
        public OFActionNicira readFrom(ChannelBuffer bb) throws OFParseError {
            if(bb.readableBytes() < MINIMUM_LENGTH)
                return null;
            int start = bb.readerIndex();
            // fixed value property type == 65535
            short type = bb.readShort();
            if(type != (short) 0xffff)
                throw new OFParseError("Wrong type: Expected=OFActionType.EXPERIMENTER(65535), got="+type);
            int length = U16.f(bb.readShort());
            if(length < MINIMUM_LENGTH)
                throw new OFParseError("Wrong length: Expected to be >= " + MINIMUM_LENGTH + ", was: " + length);
            // fixed value property experimenter == 0x2320L
            int experimenter = bb.readInt();
            if(experimenter != 0x2320)
                throw new OFParseError("Wrong experimenter: Expected=0x2320L(0x2320L), got="+experimenter);
            short subtype = bb.readShort();
            bb.readerIndex(start);
            switch(subtype) {
               case (short) 0x12:
                   // discriminator value 0x12=0x12 for class OFActionNiciraDecTtlVer12
                   return OFActionNiciraDecTtlVer12.READER.readFrom(bb);
               case (short) 0x7:
                   // discriminator value 0x7=0x7 for class OFActionNiciraLoadVer12
                   return OFActionNiciraLoadVer12.READER.readFrom(bb);
               case (short) 0x6:
                   // discriminator value 0x6=0x6 for class OFActionNiciraMoveVer12
                   return OFActionNiciraMoveVer12.READER.readFrom(bb);
               case (short) 0x5:
                   // discriminator value 0x5=0x5 for class OFActionNiciraPopQueueVer12
                   return OFActionNiciraPopQueueVer12.READER.readFrom(bb);
               case (short) 0x1:
                   // discriminator value 0x1=0x1 for class OFActionNiciraResubmitVer12
                   return OFActionNiciraResubmitVer12.READER.readFrom(bb);
               case (short) 0xe:
                   // discriminator value 0xe=0xe for class OFActionNiciraResubmitTableVer12
                   return OFActionNiciraResubmitTableVer12.READER.readFrom(bb);
               case (short) 0x22:
                   // discriminator value 0x22=0x22 for class OFActionNiciraSetNshc1Ver12
                   return OFActionNiciraSetNshc1Ver12.READER.readFrom(bb);
               case (short) 0x23:
                   // discriminator value 0x23=0x23 for class OFActionNiciraSetNshc2Ver12
                   return OFActionNiciraSetNshc2Ver12.READER.readFrom(bb);
               case (short) 0x24:
                   // discriminator value 0x24=0x24 for class OFActionNiciraSetNshc3Ver12
                   return OFActionNiciraSetNshc3Ver12.READER.readFrom(bb);
               case (short) 0x25:
                   // discriminator value 0x25=0x25 for class OFActionNiciraSetNshc4Ver12
                   return OFActionNiciraSetNshc4Ver12.READER.readFrom(bb);
               case (short) 0x21:
                   // discriminator value 0x21=0x21 for class OFActionNiciraSetNsiVer12
                   return OFActionNiciraSetNsiVer12.READER.readFrom(bb);
               case (short) 0x20:
                   // discriminator value 0x20=0x20 for class OFActionNiciraSetNspVer12
                   return OFActionNiciraSetNspVer12.READER.readFrom(bb);
               case (short) 0x4:
                   // discriminator value 0x4=0x4 for class OFActionNiciraSetQueueVer12
                   return OFActionNiciraSetQueueVer12.READER.readFrom(bb);
               default:
                   throw new OFParseError("Unknown value for discriminator subtype of class OFActionNiciraVer12: " + subtype);
            }
        }
    }
}
