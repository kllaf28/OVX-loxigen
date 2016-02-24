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
import java.util.List;
import com.google.common.collect.ImmutableList;
import java.util.Set;
import org.jboss.netty.buffer.ChannelBuffer;
import com.google.common.hash.PrimitiveSink;
import com.google.common.hash.Funnel;

class OFBsnPortCounterStatsEntryVer13 implements OFBsnPortCounterStatsEntry {
    private static final Logger logger = LoggerFactory.getLogger(OFBsnPortCounterStatsEntryVer13.class);
    // version: 1.3
    final static byte WIRE_VERSION = 4;
    final static int MINIMUM_LENGTH = 8;

        private final static OFPort DEFAULT_PORT_NO = OFPort.ANY;
        private final static List<U64> DEFAULT_VALUES = ImmutableList.<U64>of();

    // OF message fields
    private final OFPort portNo;
    private final List<U64> values;
//
    // Immutable default instance
    final static OFBsnPortCounterStatsEntryVer13 DEFAULT = new OFBsnPortCounterStatsEntryVer13(
        DEFAULT_PORT_NO, DEFAULT_VALUES
    );

    // package private constructor - used by readers, builders, and factory
    OFBsnPortCounterStatsEntryVer13(OFPort portNo, List<U64> values) {
        if(portNo == null) {
            throw new NullPointerException("OFBsnPortCounterStatsEntryVer13: property portNo cannot be null");
        }
        if(values == null) {
            throw new NullPointerException("OFBsnPortCounterStatsEntryVer13: property values cannot be null");
        }
        this.portNo = portNo;
        this.values = values;
    }

    // Accessors for OF message fields
    @Override
    public OFPort getPortNo() {
        return portNo;
    }

    @Override
    public List<U64> getValues() {
        return values;
    }

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_13;
    }



    public OFBsnPortCounterStatsEntry.Builder createBuilder() {
        return new BuilderWithParent(this);
    }

    static class BuilderWithParent implements OFBsnPortCounterStatsEntry.Builder {
        final OFBsnPortCounterStatsEntryVer13 parentMessage;

        // OF message fields
        private boolean portNoSet;
        private OFPort portNo;
        private boolean valuesSet;
        private List<U64> values;

        BuilderWithParent(OFBsnPortCounterStatsEntryVer13 parentMessage) {
            this.parentMessage = parentMessage;
        }

    @Override
    public OFPort getPortNo() {
        return portNo;
    }

    @Override
    public OFBsnPortCounterStatsEntry.Builder setPortNo(OFPort portNo) {
        this.portNo = portNo;
        this.portNoSet = true;
        return this;
    }
    @Override
    public List<U64> getValues() {
        return values;
    }

    @Override
    public OFBsnPortCounterStatsEntry.Builder setValues(List<U64> values) {
        this.values = values;
        this.valuesSet = true;
        return this;
    }
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_13;
    }



        @Override
        public OFBsnPortCounterStatsEntry build() {
                OFPort portNo = this.portNoSet ? this.portNo : parentMessage.portNo;
                if(portNo == null)
                    throw new NullPointerException("Property portNo must not be null");
                List<U64> values = this.valuesSet ? this.values : parentMessage.values;
                if(values == null)
                    throw new NullPointerException("Property values must not be null");

                //
                return new OFBsnPortCounterStatsEntryVer13(
                    portNo,
                    values
                );
        }

    }

    static class Builder implements OFBsnPortCounterStatsEntry.Builder {
        // OF message fields
        private boolean portNoSet;
        private OFPort portNo;
        private boolean valuesSet;
        private List<U64> values;

    @Override
    public OFPort getPortNo() {
        return portNo;
    }

    @Override
    public OFBsnPortCounterStatsEntry.Builder setPortNo(OFPort portNo) {
        this.portNo = portNo;
        this.portNoSet = true;
        return this;
    }
    @Override
    public List<U64> getValues() {
        return values;
    }

    @Override
    public OFBsnPortCounterStatsEntry.Builder setValues(List<U64> values) {
        this.values = values;
        this.valuesSet = true;
        return this;
    }
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_13;
    }

//
        @Override
        public OFBsnPortCounterStatsEntry build() {
            OFPort portNo = this.portNoSet ? this.portNo : DEFAULT_PORT_NO;
            if(portNo == null)
                throw new NullPointerException("Property portNo must not be null");
            List<U64> values = this.valuesSet ? this.values : DEFAULT_VALUES;
            if(values == null)
                throw new NullPointerException("Property values must not be null");


            return new OFBsnPortCounterStatsEntryVer13(
                    portNo,
                    values
                );
        }

    }


    final static Reader READER = new Reader();
    static class Reader implements OFMessageReader<OFBsnPortCounterStatsEntry> {
        @Override
        public OFBsnPortCounterStatsEntry readFrom(ChannelBuffer bb) throws OFParseError {
            int start = bb.readerIndex();
            int length = U16.f(bb.readShort());
            if(length < MINIMUM_LENGTH)
                throw new OFParseError("Wrong length: Expected to be >= " + MINIMUM_LENGTH + ", was: " + length);
            if(bb.readableBytes() + (bb.readerIndex() - start) < length) {
                // Buffer does not have all data yet
                bb.readerIndex(start);
                return null;
            }
            if(logger.isTraceEnabled())
                logger.trace("readFrom - length={}", length);
            // pad: 2 bytes
            bb.skipBytes(2);
            OFPort portNo = OFPort.read4Bytes(bb);
            List<U64> values = ChannelUtils.readList(bb, length - (bb.readerIndex() - start), U64.READER);

            OFBsnPortCounterStatsEntryVer13 bsnPortCounterStatsEntryVer13 = new OFBsnPortCounterStatsEntryVer13(
                    portNo,
                      values
                    );
            if(logger.isTraceEnabled())
                logger.trace("readFrom - read={}", bsnPortCounterStatsEntryVer13);
            return bsnPortCounterStatsEntryVer13;
        }
    }

    public void putTo(PrimitiveSink sink) {
        FUNNEL.funnel(this, sink);
    }

    final static OFBsnPortCounterStatsEntryVer13Funnel FUNNEL = new OFBsnPortCounterStatsEntryVer13Funnel();
    static class OFBsnPortCounterStatsEntryVer13Funnel implements Funnel<OFBsnPortCounterStatsEntryVer13> {
        private static final long serialVersionUID = 1L;
        @Override
        public void funnel(OFBsnPortCounterStatsEntryVer13 message, PrimitiveSink sink) {
            // FIXME: skip funnel of length
            // skip pad (2 bytes)
            message.portNo.putTo(sink);
            FunnelUtils.putList(message.values, sink);
        }
    }


    public void writeTo(ChannelBuffer bb) {
        WRITER.write(bb, this);
    }

    final static Writer WRITER = new Writer();
    static class Writer implements OFMessageWriter<OFBsnPortCounterStatsEntryVer13> {
        @Override
        public void write(ChannelBuffer bb, OFBsnPortCounterStatsEntryVer13 message) {
            int startIndex = bb.writerIndex();
            // length is length of variable message, will be updated at the end
            int lengthIndex = bb.writerIndex();
            bb.writeShort(U16.t(0));

            // pad: 2 bytes
            bb.writeZero(2);
            message.portNo.write4Bytes(bb);
            ChannelUtils.writeList(bb, message.values);

            // update length field
            int length = bb.writerIndex() - startIndex;
            bb.setShort(lengthIndex, length);

        }
    }

    @Override
    public String toString() {
        StringBuilder b = new StringBuilder("OFBsnPortCounterStatsEntryVer13(");
        b.append("portNo=").append(portNo);
        b.append(", ");
        b.append("values=").append(values);
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
        OFBsnPortCounterStatsEntryVer13 other = (OFBsnPortCounterStatsEntryVer13) obj;

        if (portNo == null) {
            if (other.portNo != null)
                return false;
        } else if (!portNo.equals(other.portNo))
            return false;
        if (values == null) {
            if (other.values != null)
                return false;
        } else if (!values.equals(other.values))
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;

        result = prime * result + ((portNo == null) ? 0 : portNo.hashCode());
        result = prime * result + ((values == null) ? 0 : values.hashCode());
        return result;
    }

}
