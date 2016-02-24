// Copyright (c) 2008 The Board of Trustees of The Leland Stanford Junior University
// Copyright (c) 2011, 2012 Open Networking Foundation
// Copyright (c) 2012, 2013 Big Switch Networks, Inc.
// This library was generated by the LoxiGen Compiler.
// See the file LICENSE.txt which should have been included in the source distribution

// Automatically generated by LOXI from template of_class.java
// Do not modify

package org.projectfloodlight.openflow.protocol.ver10;

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

class OFQueueStatsRequestVer10 implements OFQueueStatsRequest {
    private static final Logger logger = LoggerFactory.getLogger(OFQueueStatsRequestVer10.class);
    // version: 1.0
    final static byte WIRE_VERSION = 1;
    final static int LENGTH = 20;

        private final static long DEFAULT_XID = 0x0L;
        private final static Set<OFStatsRequestFlags> DEFAULT_FLAGS = ImmutableSet.<OFStatsRequestFlags>of();
        private final static OFPort DEFAULT_PORT_NO = OFPort.ANY;
        private final static long DEFAULT_QUEUE_ID = 0x0L;

    // OF message fields
    private final long xid;
    private final Set<OFStatsRequestFlags> flags;
    private final OFPort portNo;
    private final long queueId;
//
    // Immutable default instance
    final static OFQueueStatsRequestVer10 DEFAULT = new OFQueueStatsRequestVer10(
        DEFAULT_XID, DEFAULT_FLAGS, DEFAULT_PORT_NO, DEFAULT_QUEUE_ID
    );

    // package private constructor - used by readers, builders, and factory
    OFQueueStatsRequestVer10(long xid, Set<OFStatsRequestFlags> flags, OFPort portNo, long queueId) {
        if(flags == null) {
            throw new NullPointerException("OFQueueStatsRequestVer10: property flags cannot be null");
        }
        if(portNo == null) {
            throw new NullPointerException("OFQueueStatsRequestVer10: property portNo cannot be null");
        }
        this.xid = xid;
        this.flags = flags;
        this.portNo = portNo;
        this.queueId = queueId;
    }

    // Accessors for OF message fields
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_10;
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
        return OFStatsType.QUEUE;
    }

    @Override
    public Set<OFStatsRequestFlags> getFlags() {
        return flags;
    }

    @Override
    public OFPort getPortNo() {
        return portNo;
    }

    @Override
    public long getQueueId() {
        return queueId;
    }



    public OFQueueStatsRequest.Builder createBuilder() {
        return new BuilderWithParent(this);
    }

    static class BuilderWithParent implements OFQueueStatsRequest.Builder {
        final OFQueueStatsRequestVer10 parentMessage;

        // OF message fields
        private boolean xidSet;
        private long xid;
        private boolean flagsSet;
        private Set<OFStatsRequestFlags> flags;
        private boolean portNoSet;
        private OFPort portNo;
        private boolean queueIdSet;
        private long queueId;

        BuilderWithParent(OFQueueStatsRequestVer10 parentMessage) {
            this.parentMessage = parentMessage;
        }

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_10;
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
    public OFQueueStatsRequest.Builder setXid(long xid) {
        this.xid = xid;
        this.xidSet = true;
        return this;
    }
    @Override
    public OFStatsType getStatsType() {
        return OFStatsType.QUEUE;
    }

    @Override
    public Set<OFStatsRequestFlags> getFlags() {
        return flags;
    }

    @Override
    public OFQueueStatsRequest.Builder setFlags(Set<OFStatsRequestFlags> flags) {
        this.flags = flags;
        this.flagsSet = true;
        return this;
    }
    @Override
    public OFPort getPortNo() {
        return portNo;
    }

    @Override
    public OFQueueStatsRequest.Builder setPortNo(OFPort portNo) {
        this.portNo = portNo;
        this.portNoSet = true;
        return this;
    }
    @Override
    public long getQueueId() {
        return queueId;
    }

    @Override
    public OFQueueStatsRequest.Builder setQueueId(long queueId) {
        this.queueId = queueId;
        this.queueIdSet = true;
        return this;
    }


        @Override
        public OFQueueStatsRequest build() {
                long xid = this.xidSet ? this.xid : parentMessage.xid;
                Set<OFStatsRequestFlags> flags = this.flagsSet ? this.flags : parentMessage.flags;
                if(flags == null)
                    throw new NullPointerException("Property flags must not be null");
                OFPort portNo = this.portNoSet ? this.portNo : parentMessage.portNo;
                if(portNo == null)
                    throw new NullPointerException("Property portNo must not be null");
                long queueId = this.queueIdSet ? this.queueId : parentMessage.queueId;

                //
                return new OFQueueStatsRequestVer10(
                    xid,
                    flags,
                    portNo,
                    queueId
                );
        }

    }

    static class Builder implements OFQueueStatsRequest.Builder {
        // OF message fields
        private boolean xidSet;
        private long xid;
        private boolean flagsSet;
        private Set<OFStatsRequestFlags> flags;
        private boolean portNoSet;
        private OFPort portNo;
        private boolean queueIdSet;
        private long queueId;

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_10;
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
    public OFQueueStatsRequest.Builder setXid(long xid) {
        this.xid = xid;
        this.xidSet = true;
        return this;
    }
    @Override
    public OFStatsType getStatsType() {
        return OFStatsType.QUEUE;
    }

    @Override
    public Set<OFStatsRequestFlags> getFlags() {
        return flags;
    }

    @Override
    public OFQueueStatsRequest.Builder setFlags(Set<OFStatsRequestFlags> flags) {
        this.flags = flags;
        this.flagsSet = true;
        return this;
    }
    @Override
    public OFPort getPortNo() {
        return portNo;
    }

    @Override
    public OFQueueStatsRequest.Builder setPortNo(OFPort portNo) {
        this.portNo = portNo;
        this.portNoSet = true;
        return this;
    }
    @Override
    public long getQueueId() {
        return queueId;
    }

    @Override
    public OFQueueStatsRequest.Builder setQueueId(long queueId) {
        this.queueId = queueId;
        this.queueIdSet = true;
        return this;
    }
//
        @Override
        public OFQueueStatsRequest build() {
            long xid = this.xidSet ? this.xid : DEFAULT_XID;
            Set<OFStatsRequestFlags> flags = this.flagsSet ? this.flags : DEFAULT_FLAGS;
            if(flags == null)
                throw new NullPointerException("Property flags must not be null");
            OFPort portNo = this.portNoSet ? this.portNo : DEFAULT_PORT_NO;
            if(portNo == null)
                throw new NullPointerException("Property portNo must not be null");
            long queueId = this.queueIdSet ? this.queueId : DEFAULT_QUEUE_ID;


            return new OFQueueStatsRequestVer10(
                    xid,
                    flags,
                    portNo,
                    queueId
                );
        }

    }


    final static Reader READER = new Reader();
    static class Reader implements OFMessageReader<OFQueueStatsRequest> {
        @Override
        public OFQueueStatsRequest readFrom(ChannelBuffer bb) throws OFParseError {
            int start = bb.readerIndex();
            // fixed value property version == 1
            byte version = bb.readByte();
            if(version != (byte) 0x1)
                throw new OFParseError("Wrong version: Expected=OFVersion.OF_10(1), got="+version);
            // fixed value property type == 16
            byte type = bb.readByte();
            if(type != (byte) 0x10)
                throw new OFParseError("Wrong type: Expected=OFType.STATS_REQUEST(16), got="+type);
            int length = U16.f(bb.readShort());
            if(length != 20)
                throw new OFParseError("Wrong length: Expected=20(20), got="+length);
            if(bb.readableBytes() + (bb.readerIndex() - start) < length) {
                // Buffer does not have all data yet
                bb.readerIndex(start);
                return null;
            }
            if(logger.isTraceEnabled())
                logger.trace("readFrom - length={}", length);
            long xid = U32.f(bb.readInt());
            // fixed value property statsType == 5
            short statsType = bb.readShort();
            if(statsType != (short) 0x5)
                throw new OFParseError("Wrong statsType: Expected=OFStatsType.QUEUE(5), got="+statsType);
            Set<OFStatsRequestFlags> flags = OFStatsRequestFlagsSerializerVer10.readFrom(bb);
            OFPort portNo = OFPort.read2Bytes(bb);
            // pad: 2 bytes
            bb.skipBytes(2);
            long queueId = U32.f(bb.readInt());

            OFQueueStatsRequestVer10 queueStatsRequestVer10 = new OFQueueStatsRequestVer10(
                    xid,
                      flags,
                      portNo,
                      queueId
                    );
            if(logger.isTraceEnabled())
                logger.trace("readFrom - read={}", queueStatsRequestVer10);
            return queueStatsRequestVer10;
        }
    }

    public void putTo(PrimitiveSink sink) {
        FUNNEL.funnel(this, sink);
    }

    final static OFQueueStatsRequestVer10Funnel FUNNEL = new OFQueueStatsRequestVer10Funnel();
    static class OFQueueStatsRequestVer10Funnel implements Funnel<OFQueueStatsRequestVer10> {
        private static final long serialVersionUID = 1L;
        @Override
        public void funnel(OFQueueStatsRequestVer10 message, PrimitiveSink sink) {
            // fixed value property version = 1
            sink.putByte((byte) 0x1);
            // fixed value property type = 16
            sink.putByte((byte) 0x10);
            // fixed value property length = 20
            sink.putShort((short) 0x14);
            sink.putLong(message.xid);
            // fixed value property statsType = 5
            sink.putShort((short) 0x5);
            OFStatsRequestFlagsSerializerVer10.putTo(message.flags, sink);
            message.portNo.putTo(sink);
            // skip pad (2 bytes)
            sink.putLong(message.queueId);
        }
    }


    public void writeTo(ChannelBuffer bb) {
        WRITER.write(bb, this);
    }

    final static Writer WRITER = new Writer();
    static class Writer implements OFMessageWriter<OFQueueStatsRequestVer10> {
        @Override
        public void write(ChannelBuffer bb, OFQueueStatsRequestVer10 message) {
            // fixed value property version = 1
            bb.writeByte((byte) 0x1);
            // fixed value property type = 16
            bb.writeByte((byte) 0x10);
            // fixed value property length = 20
            bb.writeShort((short) 0x14);
            bb.writeInt(U32.t(message.xid));
            // fixed value property statsType = 5
            bb.writeShort((short) 0x5);
            OFStatsRequestFlagsSerializerVer10.writeTo(bb, message.flags);
            message.portNo.write2Bytes(bb);
            // pad: 2 bytes
            bb.writeZero(2);
            bb.writeInt(U32.t(message.queueId));


        }
    }

    @Override
    public String toString() {
        StringBuilder b = new StringBuilder("OFQueueStatsRequestVer10(");
        b.append("xid=").append(xid);
        b.append(", ");
        b.append("flags=").append(flags);
        b.append(", ");
        b.append("portNo=").append(portNo);
        b.append(", ");
        b.append("queueId=").append(queueId);
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
        OFQueueStatsRequestVer10 other = (OFQueueStatsRequestVer10) obj;

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
        if( queueId != other.queueId)
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
        result = prime *  (int) (queueId ^ (queueId >>> 32));
        return result;
    }

}
