// Copyright (c) 2008 The Board of Trustees of The Leland Stanford Junior University
// Copyright (c) 2011, 2012 Open Networking Foundation
// Copyright (c) 2012, 2013 Big Switch Networks, Inc.
// This library was generated by the LoxiGen Compiler.
// See the file LICENSE.txt which should have been included in the source distribution

// Automatically generated by LOXI from template of_class.java
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
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.jboss.netty.buffer.ChannelBuffer;
import com.google.common.hash.PrimitiveSink;
import com.google.common.hash.Funnel;

class OFActionNiciraSetNshc2Ver12 implements OFActionNiciraSetNshc2 {
    private static final Logger logger = LoggerFactory.getLogger(OFActionNiciraSetNshc2Ver12.class);
    // version: 1.2
    final static byte WIRE_VERSION = 3;
    final static int LENGTH = 16;

        private final static long DEFAULT_NSHC2 = 0x0L;

    // OF message fields
    private final long nshc2;
//
    // Immutable default instance
    final static OFActionNiciraSetNshc2Ver12 DEFAULT = new OFActionNiciraSetNshc2Ver12(
        DEFAULT_NSHC2
    );

    // package private constructor - used by readers, builders, and factory
    OFActionNiciraSetNshc2Ver12(long nshc2) {
        this.nshc2 = nshc2;
    }

    // Accessors for OF message fields
    @Override
    public OFActionType getType() {
        return OFActionType.EXPERIMENTER;
    }

    @Override
    public long getExperimenter() {
        return 0x2320L;
    }

    @Override
    public int getSubtype() {
        return 0x23;
    }

    @Override
    public long getNshc2() {
        return nshc2;
    }

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_12;
    }



    public OFActionNiciraSetNshc2.Builder createBuilder() {
        return new BuilderWithParent(this);
    }

    static class BuilderWithParent implements OFActionNiciraSetNshc2.Builder {
        final OFActionNiciraSetNshc2Ver12 parentMessage;

        // OF message fields
        private boolean nshc2Set;
        private long nshc2;

        BuilderWithParent(OFActionNiciraSetNshc2Ver12 parentMessage) {
            this.parentMessage = parentMessage;
        }

    @Override
    public OFActionType getType() {
        return OFActionType.EXPERIMENTER;
    }

    @Override
    public long getExperimenter() {
        return 0x2320L;
    }

    @Override
    public int getSubtype() {
        return 0x23;
    }

    @Override
    public long getNshc2() {
        return nshc2;
    }

    @Override
    public OFActionNiciraSetNshc2.Builder setNshc2(long nshc2) {
        this.nshc2 = nshc2;
        this.nshc2Set = true;
        return this;
    }
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_12;
    }



        @Override
        public OFActionNiciraSetNshc2 build() {
                long nshc2 = this.nshc2Set ? this.nshc2 : parentMessage.nshc2;

                //
                return new OFActionNiciraSetNshc2Ver12(
                    nshc2
                );
        }

    }

    static class Builder implements OFActionNiciraSetNshc2.Builder {
        // OF message fields
        private boolean nshc2Set;
        private long nshc2;

    @Override
    public OFActionType getType() {
        return OFActionType.EXPERIMENTER;
    }

    @Override
    public long getExperimenter() {
        return 0x2320L;
    }

    @Override
    public int getSubtype() {
        return 0x23;
    }

    @Override
    public long getNshc2() {
        return nshc2;
    }

    @Override
    public OFActionNiciraSetNshc2.Builder setNshc2(long nshc2) {
        this.nshc2 = nshc2;
        this.nshc2Set = true;
        return this;
    }
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_12;
    }

//
        @Override
        public OFActionNiciraSetNshc2 build() {
            long nshc2 = this.nshc2Set ? this.nshc2 : DEFAULT_NSHC2;


            return new OFActionNiciraSetNshc2Ver12(
                    nshc2
                );
        }

    }


    final static Reader READER = new Reader();
    static class Reader implements OFMessageReader<OFActionNiciraSetNshc2> {
        @Override
        public OFActionNiciraSetNshc2 readFrom(ChannelBuffer bb) throws OFParseError {
            int start = bb.readerIndex();
            // fixed value property type == 65535
            short type = bb.readShort();
            if(type != (short) 0xffff)
                throw new OFParseError("Wrong type: Expected=OFActionType.EXPERIMENTER(65535), got="+type);
            int length = U16.f(bb.readShort());
            if(length != 16)
                throw new OFParseError("Wrong length: Expected=16(16), got="+length);
            if(bb.readableBytes() + (bb.readerIndex() - start) < length) {
                // Buffer does not have all data yet
                bb.readerIndex(start);
                return null;
            }
            if(logger.isTraceEnabled())
                logger.trace("readFrom - length={}", length);
            // fixed value property experimenter == 0x2320L
            int experimenter = bb.readInt();
            if(experimenter != 0x2320)
                throw new OFParseError("Wrong experimenter: Expected=0x2320L(0x2320L), got="+experimenter);
            // fixed value property subtype == 0x23
            short subtype = bb.readShort();
            if(subtype != (short) 0x23)
                throw new OFParseError("Wrong subtype: Expected=0x23(0x23), got="+subtype);
            // pad: 2 bytes
            bb.skipBytes(2);
            long nshc2 = U32.f(bb.readInt());

            OFActionNiciraSetNshc2Ver12 actionNiciraSetNshc2Ver12 = new OFActionNiciraSetNshc2Ver12(
                    nshc2
                    );
            if(logger.isTraceEnabled())
                logger.trace("readFrom - read={}", actionNiciraSetNshc2Ver12);
            return actionNiciraSetNshc2Ver12;
        }
    }

    public void putTo(PrimitiveSink sink) {
        FUNNEL.funnel(this, sink);
    }

    final static OFActionNiciraSetNshc2Ver12Funnel FUNNEL = new OFActionNiciraSetNshc2Ver12Funnel();
    static class OFActionNiciraSetNshc2Ver12Funnel implements Funnel<OFActionNiciraSetNshc2Ver12> {
        private static final long serialVersionUID = 1L;
        @Override
        public void funnel(OFActionNiciraSetNshc2Ver12 message, PrimitiveSink sink) {
            // fixed value property type = 65535
            sink.putShort((short) 0xffff);
            // fixed value property length = 16
            sink.putShort((short) 0x10);
            // fixed value property experimenter = 0x2320L
            sink.putInt(0x2320);
            // fixed value property subtype = 0x23
            sink.putShort((short) 0x23);
            // skip pad (2 bytes)
            sink.putLong(message.nshc2);
        }
    }


    public void writeTo(ChannelBuffer bb) {
        WRITER.write(bb, this);
    }

    final static Writer WRITER = new Writer();
    static class Writer implements OFMessageWriter<OFActionNiciraSetNshc2Ver12> {
        @Override
        public void write(ChannelBuffer bb, OFActionNiciraSetNshc2Ver12 message) {
            // fixed value property type = 65535
            bb.writeShort((short) 0xffff);
            // fixed value property length = 16
            bb.writeShort((short) 0x10);
            // fixed value property experimenter = 0x2320L
            bb.writeInt(0x2320);
            // fixed value property subtype = 0x23
            bb.writeShort((short) 0x23);
            // pad: 2 bytes
            bb.writeZero(2);
            bb.writeInt(U32.t(message.nshc2));


        }
    }

    @Override
    public String toString() {
        StringBuilder b = new StringBuilder("OFActionNiciraSetNshc2Ver12(");
        b.append("nshc2=").append(nshc2);
        b.append(")");
        return b.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        OFActionNiciraSetNshc2Ver12 other = (OFActionNiciraSetNshc2Ver12) obj;

        if( nshc2 != other.nshc2)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;

        result = prime *  (int) (nshc2 ^ (nshc2 >>> 32));
        return result;
    }

}
