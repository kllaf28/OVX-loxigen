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

class OFExpPortDescPropOpticalTransportVer13 implements OFExpPortDescPropOpticalTransport {
    private static final Logger logger = LoggerFactory.getLogger(OFExpPortDescPropOpticalTransportVer13.class);
    // version: 1.3
    final static byte WIRE_VERSION = 4;
    final static int MINIMUM_LENGTH = 8;

        private final static short DEFAULT_RESERVED = (short) 0x0;
        private final static List<OFExpPortOpticalTransportLayerStack> DEFAULT_FEATURES = ImmutableList.<OFExpPortOpticalTransportLayerStack>of();

    // OF message fields
    private final OFPortOpticalTransportSignalType portSignalType;
    private final short reserved;
    private final List<OFExpPortOpticalTransportLayerStack> features;
//

    // package private constructor - used by readers, builders, and factory
    OFExpPortDescPropOpticalTransportVer13(OFPortOpticalTransportSignalType portSignalType, short reserved, List<OFExpPortOpticalTransportLayerStack> features) {
        if(portSignalType == null) {
            throw new NullPointerException("OFExpPortDescPropOpticalTransportVer13: property portSignalType cannot be null");
        }
        if(features == null) {
            throw new NullPointerException("OFExpPortDescPropOpticalTransportVer13: property features cannot be null");
        }
        this.portSignalType = portSignalType;
        this.reserved = reserved;
        this.features = features;
    }

    // Accessors for OF message fields
    @Override
    public int getType() {
        return 0x2;
    }

    @Override
    public OFPortOpticalTransportSignalType getPortSignalType() {
        return portSignalType;
    }

    @Override
    public short getReserved() {
        return reserved;
    }

    @Override
    public List<OFExpPortOpticalTransportLayerStack> getFeatures() {
        return features;
    }

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_13;
    }



    public OFExpPortDescPropOpticalTransport.Builder createBuilder() {
        return new BuilderWithParent(this);
    }

    static class BuilderWithParent implements OFExpPortDescPropOpticalTransport.Builder {
        final OFExpPortDescPropOpticalTransportVer13 parentMessage;

        // OF message fields
        private boolean portSignalTypeSet;
        private OFPortOpticalTransportSignalType portSignalType;
        private boolean reservedSet;
        private short reserved;
        private boolean featuresSet;
        private List<OFExpPortOpticalTransportLayerStack> features;

        BuilderWithParent(OFExpPortDescPropOpticalTransportVer13 parentMessage) {
            this.parentMessage = parentMessage;
        }

    @Override
    public int getType() {
        return 0x2;
    }

    @Override
    public OFPortOpticalTransportSignalType getPortSignalType() {
        return portSignalType;
    }

    @Override
    public OFExpPortDescPropOpticalTransport.Builder setPortSignalType(OFPortOpticalTransportSignalType portSignalType) {
        this.portSignalType = portSignalType;
        this.portSignalTypeSet = true;
        return this;
    }
    @Override
    public short getReserved() {
        return reserved;
    }

    @Override
    public OFExpPortDescPropOpticalTransport.Builder setReserved(short reserved) {
        this.reserved = reserved;
        this.reservedSet = true;
        return this;
    }
    @Override
    public List<OFExpPortOpticalTransportLayerStack> getFeatures() {
        return features;
    }

    @Override
    public OFExpPortDescPropOpticalTransport.Builder setFeatures(List<OFExpPortOpticalTransportLayerStack> features) {
        this.features = features;
        this.featuresSet = true;
        return this;
    }
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_13;
    }



        @Override
        public OFExpPortDescPropOpticalTransport build() {
                OFPortOpticalTransportSignalType portSignalType = this.portSignalTypeSet ? this.portSignalType : parentMessage.portSignalType;
                if(portSignalType == null)
                    throw new NullPointerException("Property portSignalType must not be null");
                short reserved = this.reservedSet ? this.reserved : parentMessage.reserved;
                List<OFExpPortOpticalTransportLayerStack> features = this.featuresSet ? this.features : parentMessage.features;
                if(features == null)
                    throw new NullPointerException("Property features must not be null");

                //
                return new OFExpPortDescPropOpticalTransportVer13(
                    portSignalType,
                    reserved,
                    features
                );
        }

    }

    static class Builder implements OFExpPortDescPropOpticalTransport.Builder {
        // OF message fields
        private boolean portSignalTypeSet;
        private OFPortOpticalTransportSignalType portSignalType;
        private boolean reservedSet;
        private short reserved;
        private boolean featuresSet;
        private List<OFExpPortOpticalTransportLayerStack> features;

    @Override
    public int getType() {
        return 0x2;
    }

    @Override
    public OFPortOpticalTransportSignalType getPortSignalType() {
        return portSignalType;
    }

    @Override
    public OFExpPortDescPropOpticalTransport.Builder setPortSignalType(OFPortOpticalTransportSignalType portSignalType) {
        this.portSignalType = portSignalType;
        this.portSignalTypeSet = true;
        return this;
    }
    @Override
    public short getReserved() {
        return reserved;
    }

    @Override
    public OFExpPortDescPropOpticalTransport.Builder setReserved(short reserved) {
        this.reserved = reserved;
        this.reservedSet = true;
        return this;
    }
    @Override
    public List<OFExpPortOpticalTransportLayerStack> getFeatures() {
        return features;
    }

    @Override
    public OFExpPortDescPropOpticalTransport.Builder setFeatures(List<OFExpPortOpticalTransportLayerStack> features) {
        this.features = features;
        this.featuresSet = true;
        return this;
    }
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_13;
    }

//
        @Override
        public OFExpPortDescPropOpticalTransport build() {
            if(!this.portSignalTypeSet)
                throw new IllegalStateException("Property portSignalType doesn't have default value -- must be set");
            if(portSignalType == null)
                throw new NullPointerException("Property portSignalType must not be null");
            short reserved = this.reservedSet ? this.reserved : DEFAULT_RESERVED;
            List<OFExpPortOpticalTransportLayerStack> features = this.featuresSet ? this.features : DEFAULT_FEATURES;
            if(features == null)
                throw new NullPointerException("Property features must not be null");


            return new OFExpPortDescPropOpticalTransportVer13(
                    portSignalType,
                    reserved,
                    features
                );
        }

    }


    final static Reader READER = new Reader();
    static class Reader implements OFMessageReader<OFExpPortDescPropOpticalTransport> {
        @Override
        public OFExpPortDescPropOpticalTransport readFrom(ChannelBuffer bb) throws OFParseError {
            int start = bb.readerIndex();
            // fixed value property type == 0x2
            short type = bb.readShort();
            if(type != (short) 0x2)
                throw new OFParseError("Wrong type: Expected=0x2(0x2), got="+type);
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
            OFPortOpticalTransportSignalType portSignalType = OFPortOpticalTransportSignalTypeSerializerVer13.readFrom(bb);
            short reserved = U8.f(bb.readByte());
            // pad: 2 bytes
            bb.skipBytes(2);
            List<OFExpPortOpticalTransportLayerStack> features = ChannelUtils.readList(bb, length - (bb.readerIndex() - start), OFExpPortOpticalTransportLayerStackVer13.READER);

            OFExpPortDescPropOpticalTransportVer13 expPortDescPropOpticalTransportVer13 = new OFExpPortDescPropOpticalTransportVer13(
                    portSignalType,
                      reserved,
                      features
                    );
            if(logger.isTraceEnabled())
                logger.trace("readFrom - read={}", expPortDescPropOpticalTransportVer13);
            return expPortDescPropOpticalTransportVer13;
        }
    }

    public void putTo(PrimitiveSink sink) {
        FUNNEL.funnel(this, sink);
    }

    final static OFExpPortDescPropOpticalTransportVer13Funnel FUNNEL = new OFExpPortDescPropOpticalTransportVer13Funnel();
    static class OFExpPortDescPropOpticalTransportVer13Funnel implements Funnel<OFExpPortDescPropOpticalTransportVer13> {
        private static final long serialVersionUID = 1L;
        @Override
        public void funnel(OFExpPortDescPropOpticalTransportVer13 message, PrimitiveSink sink) {
            // fixed value property type = 0x2
            sink.putShort((short) 0x2);
            // FIXME: skip funnel of length
            OFPortOpticalTransportSignalTypeSerializerVer13.putTo(message.portSignalType, sink);
            sink.putShort(message.reserved);
            // skip pad (2 bytes)
            FunnelUtils.putList(message.features, sink);
        }
    }


    public void writeTo(ChannelBuffer bb) {
        WRITER.write(bb, this);
    }

    final static Writer WRITER = new Writer();
    static class Writer implements OFMessageWriter<OFExpPortDescPropOpticalTransportVer13> {
        @Override
        public void write(ChannelBuffer bb, OFExpPortDescPropOpticalTransportVer13 message) {
            int startIndex = bb.writerIndex();
            // fixed value property type = 0x2
            bb.writeShort((short) 0x2);
            // length is length of variable message, will be updated at the end
            int lengthIndex = bb.writerIndex();
            bb.writeShort(U16.t(0));

            OFPortOpticalTransportSignalTypeSerializerVer13.writeTo(bb, message.portSignalType);
            bb.writeByte(U8.t(message.reserved));
            // pad: 2 bytes
            bb.writeZero(2);
            ChannelUtils.writeList(bb, message.features);

            // update length field
            int length = bb.writerIndex() - startIndex;
            bb.setShort(lengthIndex, length);

        }
    }

    @Override
    public String toString() {
        StringBuilder b = new StringBuilder("OFExpPortDescPropOpticalTransportVer13(");
        b.append("portSignalType=").append(portSignalType);
        b.append(", ");
        b.append("reserved=").append(reserved);
        b.append(", ");
        b.append("features=").append(features);
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
        OFExpPortDescPropOpticalTransportVer13 other = (OFExpPortDescPropOpticalTransportVer13) obj;

        if (portSignalType == null) {
            if (other.portSignalType != null)
                return false;
        } else if (!portSignalType.equals(other.portSignalType))
            return false;
        if( reserved != other.reserved)
            return false;
        if (features == null) {
            if (other.features != null)
                return false;
        } else if (!features.equals(other.features))
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;

        result = prime * result + ((portSignalType == null) ? 0 : portSignalType.hashCode());
        result = prime * result + reserved;
        result = prime * result + ((features == null) ? 0 : features.hashCode());
        return result;
    }

}
