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
import com.google.common.collect.ImmutableSet;
import org.jboss.netty.buffer.ChannelBuffer;
import com.google.common.hash.PrimitiveSink;
import com.google.common.hash.Funnel;

class OFCalientPortStatsRequestVer13 implements OFCalientPortStatsRequest {
    private static final Logger logger = LoggerFactory.getLogger(OFCalientPortStatsRequestVer13.class);
    // version: 1.3
    final static byte WIRE_VERSION = 4;
    final static int LENGTH = 32;

        private final static long DEFAULT_XID = 0x0L;
        private final static Set<OFStatsRequestFlags> DEFAULT_FLAGS = ImmutableSet.<OFStatsRequestFlags>of();
        private final static OFPort DEFAULT_PORT_NO = OFPort.ANY;

    // OF message fields
    private final long xid;
    private final Set<OFStatsRequestFlags> flags;
    private final OFPort portNo;
//
    // Immutable default instance
    final static OFCalientPortStatsRequestVer13 DEFAULT = new OFCalientPortStatsRequestVer13(
        DEFAULT_XID, DEFAULT_FLAGS, DEFAULT_PORT_NO
    );

    // package private constructor - used by readers, builders, and factory
    OFCalientPortStatsRequestVer13(long xid, Set<OFStatsRequestFlags> flags, OFPort portNo) {
        if(flags == null) {
            throw new NullPointerException("OFCalientPortStatsRequestVer13: property flags cannot be null");
        }
        if(portNo == null) {
            throw new NullPointerException("OFCalientPortStatsRequestVer13: property portNo cannot be null");
        }
        this.xid = xid;
        this.flags = flags;
        this.portNo = portNo;
    }

    // Accessors for OF message fields
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_13;
    }

    @Override
    public OFType getType() {
        return OFType.STATS_REQUEST;
    }

    @Override
    public long getXid() {
        return xid;
    }

    @Override
    public OFStatsType getStatsType() {
        return OFStatsType.EXPERIMENTER;
    }

    @Override
    public Set<OFStatsRequestFlags> getFlags() {
        return flags;
    }

    @Override
    public long getExperimenter() {
        return 0x80f958L;
    }

    @Override
    public long getSubtype() {
        return 0x3L;
    }

    @Override
    public OFPort getPortNo() {
        return portNo;
    }



    public OFCalientPortStatsRequest.Builder createBuilder() {
        return new BuilderWithParent(this);
    }

    static class BuilderWithParent implements OFCalientPortStatsRequest.Builder {
        final OFCalientPortStatsRequestVer13 parentMessage;

        // OF message fields
        private boolean xidSet;
        private long xid;
        private boolean flagsSet;
        private Set<OFStatsRequestFlags> flags;
        private boolean portNoSet;
        private OFPort portNo;

        BuilderWithParent(OFCalientPortStatsRequestVer13 parentMessage) {
            this.parentMessage = parentMessage;
        }

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_13;
    }

    @Override
    public OFType getType() {
        return OFType.STATS_REQUEST;
    }

    @Override
    public long getXid() {
        return xid;
    }

    @Override
    public OFCalientPortStatsRequest.Builder setXid(long xid) {
        this.xid = xid;
        this.xidSet = true;
        return this;
    }
    @Override
    public OFStatsType getStatsType() {
        return OFStatsType.EXPERIMENTER;
    }

    @Override
    public Set<OFStatsRequestFlags> getFlags() {
        return flags;
    }

    @Override
    public OFCalientPortStatsRequest.Builder setFlags(Set<OFStatsRequestFlags> flags) {
        this.flags = flags;
        this.flagsSet = true;
        return this;
    }
    @Override
    public long getExperimenter() {
        return 0x80f958L;
    }

    @Override
    public long getSubtype() {
        return 0x3L;
    }

    @Override
    public OFPort getPortNo() {
        return portNo;
    }

    @Override
    public OFCalientPortStatsRequest.Builder setPortNo(OFPort portNo) {
        this.portNo = portNo;
        this.portNoSet = true;
        return this;
    }


        @Override
        public OFCalientPortStatsRequest build() {
                long xid = this.xidSet ? this.xid : parentMessage.xid;
                Set<OFStatsRequestFlags> flags = this.flagsSet ? this.flags : parentMessage.flags;
                if(flags == null)
                    throw new NullPointerException("Property flags must not be null");
                OFPort portNo = this.portNoSet ? this.portNo : parentMessage.portNo;
                if(portNo == null)
                    throw new NullPointerException("Property portNo must not be null");

                //
                return new OFCalientPortStatsRequestVer13(
                    xid,
                    flags,
                    portNo
                );
        }

    }

    static class Builder implements OFCalientPortStatsRequest.Builder {
        // OF message fields
        private boolean xidSet;
        private long xid;
        private boolean flagsSet;
        private Set<OFStatsRequestFlags> flags;
        private boolean portNoSet;
        private OFPort portNo;

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_13;
    }

    @Override
    public OFType getType() {
        return OFType.STATS_REQUEST;
    }

    @Override
    public long getXid() {
        return xid;
    }

    @Override
    public OFCalientPortStatsRequest.Builder setXid(long xid) {
        this.xid = xid;
        this.xidSet = true;
        return this;
    }
    @Override
    public OFStatsType getStatsType() {
        return OFStatsType.EXPERIMENTER;
    }

    @Override
    public Set<OFStatsRequestFlags> getFlags() {
        return flags;
    }

    @Override
    public OFCalientPortStatsRequest.Builder setFlags(Set<OFStatsRequestFlags> flags) {
        this.flags = flags;
        this.flagsSet = true;
        return this;
    }
    @Override
    public long getExperimenter() {
        return 0x80f958L;
    }

    @Override
    public long getSubtype() {
        return 0x3L;
    }

    @Override
    public OFPort getPortNo() {
        return portNo;
    }

    @Override
    public OFCalientPortStatsRequest.Builder setPortNo(OFPort portNo) {
        this.portNo = portNo;
        this.portNoSet = true;
        return this;
    }
//
        @Override
        public OFCalientPortStatsRequest build() {
            long xid = this.xidSet ? this.xid : DEFAULT_XID;
            Set<OFStatsRequestFlags> flags = this.flagsSet ? this.flags : DEFAULT_FLAGS;
            if(flags == null)
                throw new NullPointerException("Property flags must not be null");
            OFPort portNo = this.portNoSet ? this.portNo : DEFAULT_PORT_NO;
            if(portNo == null)
                throw new NullPointerException("Property portNo must not be null");


            return new OFCalientPortStatsRequestVer13(
                    xid,
                    flags,
                    portNo
                );
        }

    }


    final static Reader READER = new Reader();
    static class Reader implements OFMessageReader<OFCalientPortStatsRequest> {
        @Override
        public OFCalientPortStatsRequest readFrom(ChannelBuffer bb) throws OFParseError {
            int start = bb.readerIndex();
            // fixed value property version == 4
            byte version = bb.readByte();
            if(version != (byte) 0x4)
                throw new OFParseError("Wrong version: Expected=OFVersion.OF_13(4), got="+version);
            // fixed value property type == 18
            byte type = bb.readByte();
            if(type != (byte) 0x12)
                throw new OFParseError("Wrong type: Expected=OFType.STATS_REQUEST(18), got="+type);
            int length = U16.f(bb.readShort());
            if(length != 32)
                throw new OFParseError("Wrong length: Expected=32(32), got="+length);
            if(bb.readableBytes() + (bb.readerIndex() - start) < length) {
                // Buffer does not have all data yet
                bb.readerIndex(start);
                return null;
            }
            if(logger.isTraceEnabled())
                logger.trace("readFrom - length={}", length);
            long xid = U32.f(bb.readInt());
            // fixed value property statsType == 65535
            short statsType = bb.readShort();
            if(statsType != (short) 0xffff)
                throw new OFParseError("Wrong statsType: Expected=OFStatsType.EXPERIMENTER(65535), got="+statsType);
            Set<OFStatsRequestFlags> flags = OFStatsRequestFlagsSerializerVer13.readFrom(bb);
            // pad: 4 bytes
            bb.skipBytes(4);
            // fixed value property experimenter == 0x80f958L
            int experimenter = bb.readInt();
            if(experimenter != 0x80f958)
                throw new OFParseError("Wrong experimenter: Expected=0x80f958L(0x80f958L), got="+experimenter);
            // fixed value property subtype == 0x3L
            int subtype = bb.readInt();
            if(subtype != 0x3)
                throw new OFParseError("Wrong subtype: Expected=0x3L(0x3L), got="+subtype);
            OFPort portNo = OFPort.read4Bytes(bb);
            // pad: 4 bytes
            bb.skipBytes(4);

            OFCalientPortStatsRequestVer13 calientPortStatsRequestVer13 = new OFCalientPortStatsRequestVer13(
                    xid,
                      flags,
                      portNo
                    );
            if(logger.isTraceEnabled())
                logger.trace("readFrom - read={}", calientPortStatsRequestVer13);
            return calientPortStatsRequestVer13;
        }
    }

    public void putTo(PrimitiveSink sink) {
        FUNNEL.funnel(this, sink);
    }

    final static OFCalientPortStatsRequestVer13Funnel FUNNEL = new OFCalientPortStatsRequestVer13Funnel();
    static class OFCalientPortStatsRequestVer13Funnel implements Funnel<OFCalientPortStatsRequestVer13> {
        private static final long serialVersionUID = 1L;
        @Override
        public void funnel(OFCalientPortStatsRequestVer13 message, PrimitiveSink sink) {
            // fixed value property version = 4
            sink.putByte((byte) 0x4);
            // fixed value property type = 18
            sink.putByte((byte) 0x12);
            // fixed value property length = 32
            sink.putShort((short) 0x20);
            sink.putLong(message.xid);
            // fixed value property statsType = 65535
            sink.putShort((short) 0xffff);
            OFStatsRequestFlagsSerializerVer13.putTo(message.flags, sink);
            // skip pad (4 bytes)
            // fixed value property experimenter = 0x80f958L
            sink.putInt(0x80f958);
            // fixed value property subtype = 0x3L
            sink.putInt(0x3);
            message.portNo.putTo(sink);
            // skip pad (4 bytes)
        }
    }


    public void writeTo(ChannelBuffer bb) {
        WRITER.write(bb, this);
    }

    final static Writer WRITER = new Writer();
    static class Writer implements OFMessageWriter<OFCalientPortStatsRequestVer13> {
        @Override
        public void write(ChannelBuffer bb, OFCalientPortStatsRequestVer13 message) {
            // fixed value property version = 4
            bb.writeByte((byte) 0x4);
            // fixed value property type = 18
            bb.writeByte((byte) 0x12);
            // fixed value property length = 32
            bb.writeShort((short) 0x20);
            bb.writeInt(U32.t(message.xid));
            // fixed value property statsType = 65535
            bb.writeShort((short) 0xffff);
            OFStatsRequestFlagsSerializerVer13.writeTo(bb, message.flags);
            // pad: 4 bytes
            bb.writeZero(4);
            // fixed value property experimenter = 0x80f958L
            bb.writeInt(0x80f958);
            // fixed value property subtype = 0x3L
            bb.writeInt(0x3);
            message.portNo.write4Bytes(bb);
            // pad: 4 bytes
            bb.writeZero(4);


        }
    }

    @Override
    public String toString() {
        StringBuilder b = new StringBuilder("OFCalientPortStatsRequestVer13(");
        b.append("xid=").append(xid);
        b.append(", ");
        b.append("flags=").append(flags);
        b.append(", ");
        b.append("portNo=").append(portNo);
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
        OFCalientPortStatsRequestVer13 other = (OFCalientPortStatsRequestVer13) obj;

        if( xid != other.xid)
            return false;
        if (flags == null) {
            if (other.flags != null)
                return false;
        } else if (!flags.equals(other.flags))
            return false;
        if (portNo == null) {
            if (other.portNo != null)
                return false;
        } else if (!portNo.equals(other.portNo))
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;

        result = prime *  (int) (xid ^ (xid >>> 32));
        result = prime * result + ((flags == null) ? 0 : flags.hashCode());
        result = prime * result + ((portNo == null) ? 0 : portNo.hashCode());
        return result;
    }

}
