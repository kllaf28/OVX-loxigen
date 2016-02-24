// Copyright (c) 2008 The Board of Trustees of The Leland Stanford Junior University
// Copyright (c) 2011, 2012 Open Networking Foundation
// Copyright (c) 2012, 2013 Big Switch Networks, Inc.
// This library was generated by the LoxiGen Compiler.
// See the file LICENSE.txt which should have been included in the source distribution

// Automatically generated by LOXI from template of_class.java
// Do not modify

package org.projectfloodlight.openflow.protocol.ver11;

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

class OFActionNiciraSetNspVer11 implements OFActionNiciraSetNsp {
    private static final Logger logger = LoggerFactory.getLogger(OFActionNiciraSetNspVer11.class);
    // version: 1.1
    final static byte WIRE_VERSION = 2;
    final static int LENGTH = 16;

        private final static long DEFAULT_NSP = 0x0L;

    // OF message fields
    private final long nsp;
//
    // Immutable default instance
    final static OFActionNiciraSetNspVer11 DEFAULT = new OFActionNiciraSetNspVer11(
        DEFAULT_NSP
    );

    // package private constructor - used by readers, builders, and factory
    OFActionNiciraSetNspVer11(long nsp) {
        this.nsp = nsp;
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
        return 0x20;
    }

    @Override
    public long getNsp() {
        return nsp;
    }

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_11;
    }



    public OFActionNiciraSetNsp.Builder createBuilder() {
        return new BuilderWithParent(this);
    }

    static class BuilderWithParent implements OFActionNiciraSetNsp.Builder {
        final OFActionNiciraSetNspVer11 parentMessage;

        // OF message fields
        private boolean nspSet;
        private long nsp;

        BuilderWithParent(OFActionNiciraSetNspVer11 parentMessage) {
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
        return 0x20;
    }

    @Override
    public long getNsp() {
        return nsp;
    }

    @Override
    public OFActionNiciraSetNsp.Builder setNsp(long nsp) {
        this.nsp = nsp;
        this.nspSet = true;
        return this;
    }
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_11;
    }



        @Override
        public OFActionNiciraSetNsp build() {
                long nsp = this.nspSet ? this.nsp : parentMessage.nsp;

                //
                return new OFActionNiciraSetNspVer11(
                    nsp
                );
        }

    }

    static class Builder implements OFActionNiciraSetNsp.Builder {
        // OF message fields
        private boolean nspSet;
        private long nsp;

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
        return 0x20;
    }

    @Override
    public long getNsp() {
        return nsp;
    }

    @Override
    public OFActionNiciraSetNsp.Builder setNsp(long nsp) {
        this.nsp = nsp;
        this.nspSet = true;
        return this;
    }
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_11;
    }

//
        @Override
        public OFActionNiciraSetNsp build() {
            long nsp = this.nspSet ? this.nsp : DEFAULT_NSP;


            return new OFActionNiciraSetNspVer11(
                    nsp
                );
        }

    }


    final static Reader READER = new Reader();
    static class Reader implements OFMessageReader<OFActionNiciraSetNsp> {
        @Override
        public OFActionNiciraSetNsp readFrom(ChannelBuffer bb) throws OFParseError {
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
            // fixed value property subtype == 0x20
            short subtype = bb.readShort();
            if(subtype != (short) 0x20)
                throw new OFParseError("Wrong subtype: Expected=0x20(0x20), got="+subtype);
            // pad: 2 bytes
            bb.skipBytes(2);
            long nsp = U32.f(bb.readInt());

            OFActionNiciraSetNspVer11 actionNiciraSetNspVer11 = new OFActionNiciraSetNspVer11(
                    nsp
                    );
            if(logger.isTraceEnabled())
                logger.trace("readFrom - read={}", actionNiciraSetNspVer11);
            return actionNiciraSetNspVer11;
        }
    }

    public void putTo(PrimitiveSink sink) {
        FUNNEL.funnel(this, sink);
    }

    final static OFActionNiciraSetNspVer11Funnel FUNNEL = new OFActionNiciraSetNspVer11Funnel();
    static class OFActionNiciraSetNspVer11Funnel implements Funnel<OFActionNiciraSetNspVer11> {
        private static final long serialVersionUID = 1L;
        @Override
        public void funnel(OFActionNiciraSetNspVer11 message, PrimitiveSink sink) {
            // fixed value property type = 65535
            sink.putShort((short) 0xffff);
            // fixed value property length = 16
            sink.putShort((short) 0x10);
            // fixed value property experimenter = 0x2320L
            sink.putInt(0x2320);
            // fixed value property subtype = 0x20
            sink.putShort((short) 0x20);
            // skip pad (2 bytes)
            sink.putLong(message.nsp);
        }
    }


    public void writeTo(ChannelBuffer bb) {
        WRITER.write(bb, this);
    }

    final static Writer WRITER = new Writer();
    static class Writer implements OFMessageWriter<OFActionNiciraSetNspVer11> {
        @Override
        public void write(ChannelBuffer bb, OFActionNiciraSetNspVer11 message) {
            // fixed value property type = 65535
            bb.writeShort((short) 0xffff);
            // fixed value property length = 16
            bb.writeShort((short) 0x10);
            // fixed value property experimenter = 0x2320L
            bb.writeInt(0x2320);
            // fixed value property subtype = 0x20
            bb.writeShort((short) 0x20);
            // pad: 2 bytes
            bb.writeZero(2);
            bb.writeInt(U32.t(message.nsp));


        }
    }

    @Override
    public String toString() {
        StringBuilder b = new StringBuilder("OFActionNiciraSetNspVer11(");
        b.append("nsp=").append(nsp);
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
        OFActionNiciraSetNspVer11 other = (OFActionNiciraSetNspVer11) obj;

        if( nsp != other.nsp)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;

        result = prime *  (int) (nsp ^ (nsp >>> 32));
        return result;
    }

}
