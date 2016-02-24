// Copyright (c) 2008 The Board of Trustees of The Leland Stanford Junior University
// Copyright (c) 2011, 2012 Open Networking Foundation
// Copyright (c) 2012, 2013 Big Switch Networks, Inc.
// This library was generated by the LoxiGen Compiler.
// See the file LICENSE.txt which should have been included in the source distribution

// Automatically generated by LOXI from template of_class.java
// Do not modify

package org.projectfloodlight.openflow.protocol.ver13;

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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.Set;
import org.jboss.netty.buffer.ChannelBuffer;
import com.google.common.hash.PrimitiveSink;
import com.google.common.hash.Funnel;

class OFActionPushPbbVer13 implements OFActionPushPbb {
    private static final Logger logger = LoggerFactory.getLogger(OFActionPushPbbVer13.class);
    // version: 1.3
    final static byte WIRE_VERSION = 4;
    final static int LENGTH = 8;

        private final static EthType DEFAULT_ETHERTYPE = EthType.NONE;

    // OF message fields
    private final EthType ethertype;
//
    // Immutable default instance
    final static OFActionPushPbbVer13 DEFAULT = new OFActionPushPbbVer13(
        DEFAULT_ETHERTYPE
    );

    // package private constructor - used by readers, builders, and factory
    OFActionPushPbbVer13(EthType ethertype) {
        if(ethertype == null) {
            throw new NullPointerException("OFActionPushPbbVer13: property ethertype cannot be null");
        }
        this.ethertype = ethertype;
    }

    // Accessors for OF message fields
    @Override
    public OFActionType getType() {
        return OFActionType.PUSH_PBB;
    }

    @Override
    public EthType getEthertype() {
        return ethertype;
    }

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_13;
    }



    public OFActionPushPbb.Builder createBuilder() {
        return new BuilderWithParent(this);
    }

    static class BuilderWithParent implements OFActionPushPbb.Builder {
        final OFActionPushPbbVer13 parentMessage;

        // OF message fields
        private boolean ethertypeSet;
        private EthType ethertype;

        BuilderWithParent(OFActionPushPbbVer13 parentMessage) {
            this.parentMessage = parentMessage;
        }

    @Override
    public OFActionType getType() {
        return OFActionType.PUSH_PBB;
    }

    @Override
    public EthType getEthertype() {
        return ethertype;
    }

    @Override
    public OFActionPushPbb.Builder setEthertype(EthType ethertype) {
        this.ethertype = ethertype;
        this.ethertypeSet = true;
        return this;
    }
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_13;
    }



        @Override
        public OFActionPushPbb build() {
                EthType ethertype = this.ethertypeSet ? this.ethertype : parentMessage.ethertype;
                if(ethertype == null)
                    throw new NullPointerException("Property ethertype must not be null");

                //
                return new OFActionPushPbbVer13(
                    ethertype
                );
        }

    }

    static class Builder implements OFActionPushPbb.Builder {
        // OF message fields
        private boolean ethertypeSet;
        private EthType ethertype;

    @Override
    public OFActionType getType() {
        return OFActionType.PUSH_PBB;
    }

    @Override
    public EthType getEthertype() {
        return ethertype;
    }

    @Override
    public OFActionPushPbb.Builder setEthertype(EthType ethertype) {
        this.ethertype = ethertype;
        this.ethertypeSet = true;
        return this;
    }
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_13;
    }

//
        @Override
        public OFActionPushPbb build() {
            EthType ethertype = this.ethertypeSet ? this.ethertype : DEFAULT_ETHERTYPE;
            if(ethertype == null)
                throw new NullPointerException("Property ethertype must not be null");


            return new OFActionPushPbbVer13(
                    ethertype
                );
        }

    }


    final static Reader READER = new Reader();
    static class Reader implements OFMessageReader<OFActionPushPbb> {
        @Override
        public OFActionPushPbb readFrom(ChannelBuffer bb) throws OFParseError {
            int start = bb.readerIndex();
            // fixed value property type == 26
            short type = bb.readShort();
            if(type != (short) 0x1a)
                throw new OFParseError("Wrong type: Expected=OFActionType.PUSH_PBB(26), got="+type);
            int length = U16.f(bb.readShort());
            if(length != 8)
                throw new OFParseError("Wrong length: Expected=8(8), got="+length);
            if(bb.readableBytes() + (bb.readerIndex() - start) < length) {
                // Buffer does not have all data yet
                bb.readerIndex(start);
                return null;
            }
            if(logger.isTraceEnabled())
                logger.trace("readFrom - length={}", length);
            EthType ethertype = EthType.read2Bytes(bb);
            // pad: 2 bytes
            bb.skipBytes(2);

            OFActionPushPbbVer13 actionPushPbbVer13 = new OFActionPushPbbVer13(
                    ethertype
                    );
            if(logger.isTraceEnabled())
                logger.trace("readFrom - read={}", actionPushPbbVer13);
            return actionPushPbbVer13;
        }
    }

    public void putTo(PrimitiveSink sink) {
        FUNNEL.funnel(this, sink);
    }

    final static OFActionPushPbbVer13Funnel FUNNEL = new OFActionPushPbbVer13Funnel();
    static class OFActionPushPbbVer13Funnel implements Funnel<OFActionPushPbbVer13> {
        private static final long serialVersionUID = 1L;
        @Override
        public void funnel(OFActionPushPbbVer13 message, PrimitiveSink sink) {
            // fixed value property type = 26
            sink.putShort((short) 0x1a);
            // fixed value property length = 8
            sink.putShort((short) 0x8);
            message.ethertype.putTo(sink);
            // skip pad (2 bytes)
        }
    }


    public void writeTo(ChannelBuffer bb) {
        WRITER.write(bb, this);
    }

    final static Writer WRITER = new Writer();
    static class Writer implements OFMessageWriter<OFActionPushPbbVer13> {
        @Override
        public void write(ChannelBuffer bb, OFActionPushPbbVer13 message) {
            // fixed value property type = 26
            bb.writeShort((short) 0x1a);
            // fixed value property length = 8
            bb.writeShort((short) 0x8);
            message.ethertype.write2Bytes(bb);
            // pad: 2 bytes
            bb.writeZero(2);


        }
    }

    @Override
    public String toString() {
        StringBuilder b = new StringBuilder("OFActionPushPbbVer13(");
        b.append("ethertype=").append(ethertype);
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
        OFActionPushPbbVer13 other = (OFActionPushPbbVer13) obj;

        if (ethertype == null) {
            if (other.ethertype != null)
                return false;
        } else if (!ethertype.equals(other.ethertype))
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;

        result = prime * result + ((ethertype == null) ? 0 : ethertype.hashCode());
        return result;
    }

}
