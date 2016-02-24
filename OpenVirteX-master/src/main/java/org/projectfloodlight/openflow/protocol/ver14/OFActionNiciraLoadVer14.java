// Copyright (c) 2008 The Board of Trustees of The Leland Stanford Junior University
// Copyright (c) 2011, 2012 Open Networking Foundation
// Copyright (c) 2012, 2013 Big Switch Networks, Inc.
// This library was generated by the LoxiGen Compiler.
// See the file LICENSE.txt which should have been included in the source distribution

// Automatically generated by LOXI from template of_class.java
// Do not modify

package org.projectfloodlight.openflow.protocol.ver14;

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

class OFActionNiciraLoadVer14 implements OFActionNiciraLoad {
    private static final Logger logger = LoggerFactory.getLogger(OFActionNiciraLoadVer14.class);
    // version: 1.4
    final static byte WIRE_VERSION = 5;
    final static int LENGTH = 24;

        private final static int DEFAULT_OFS_NBITS = 0x0;
        private final static long DEFAULT_DST = 0x0L;
        private final static U64 DEFAULT_VALUE = U64.ZERO;

    // OF message fields
    private final int ofsNbits;
    private final long dst;
    private final U64 value;
//
    // Immutable default instance
    final static OFActionNiciraLoadVer14 DEFAULT = new OFActionNiciraLoadVer14(
        DEFAULT_OFS_NBITS, DEFAULT_DST, DEFAULT_VALUE
    );

    // package private constructor - used by readers, builders, and factory
    OFActionNiciraLoadVer14(int ofsNbits, long dst, U64 value) {
        if(value == null) {
            throw new NullPointerException("OFActionNiciraLoadVer14: property value cannot be null");
        }
        this.ofsNbits = ofsNbits;
        this.dst = dst;
        this.value = value;
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
        return 0x7;
    }

    @Override
    public int getOfsNbits() {
        return ofsNbits;
    }

    @Override
    public long getDst() {
        return dst;
    }

    @Override
    public U64 getValue() {
        return value;
    }

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_14;
    }



    public OFActionNiciraLoad.Builder createBuilder() {
        return new BuilderWithParent(this);
    }

    static class BuilderWithParent implements OFActionNiciraLoad.Builder {
        final OFActionNiciraLoadVer14 parentMessage;

        // OF message fields
        private boolean ofsNbitsSet;
        private int ofsNbits;
        private boolean dstSet;
        private long dst;
        private boolean valueSet;
        private U64 value;

        BuilderWithParent(OFActionNiciraLoadVer14 parentMessage) {
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
        return 0x7;
    }

    @Override
    public int getOfsNbits() {
        return ofsNbits;
    }

    @Override
    public OFActionNiciraLoad.Builder setOfsNbits(int ofsNbits) {
        this.ofsNbits = ofsNbits;
        this.ofsNbitsSet = true;
        return this;
    }
    @Override
    public long getDst() {
        return dst;
    }

    @Override
    public OFActionNiciraLoad.Builder setDst(long dst) {
        this.dst = dst;
        this.dstSet = true;
        return this;
    }
    @Override
    public U64 getValue() {
        return value;
    }

    @Override
    public OFActionNiciraLoad.Builder setValue(U64 value) {
        this.value = value;
        this.valueSet = true;
        return this;
    }
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_14;
    }



        @Override
        public OFActionNiciraLoad build() {
                int ofsNbits = this.ofsNbitsSet ? this.ofsNbits : parentMessage.ofsNbits;
                long dst = this.dstSet ? this.dst : parentMessage.dst;
                U64 value = this.valueSet ? this.value : parentMessage.value;
                if(value == null)
                    throw new NullPointerException("Property value must not be null");

                //
                return new OFActionNiciraLoadVer14(
                    ofsNbits,
                    dst,
                    value
                );
        }

    }

    static class Builder implements OFActionNiciraLoad.Builder {
        // OF message fields
        private boolean ofsNbitsSet;
        private int ofsNbits;
        private boolean dstSet;
        private long dst;
        private boolean valueSet;
        private U64 value;

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
        return 0x7;
    }

    @Override
    public int getOfsNbits() {
        return ofsNbits;
    }

    @Override
    public OFActionNiciraLoad.Builder setOfsNbits(int ofsNbits) {
        this.ofsNbits = ofsNbits;
        this.ofsNbitsSet = true;
        return this;
    }
    @Override
    public long getDst() {
        return dst;
    }

    @Override
    public OFActionNiciraLoad.Builder setDst(long dst) {
        this.dst = dst;
        this.dstSet = true;
        return this;
    }
    @Override
    public U64 getValue() {
        return value;
    }

    @Override
    public OFActionNiciraLoad.Builder setValue(U64 value) {
        this.value = value;
        this.valueSet = true;
        return this;
    }
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_14;
    }

//
        @Override
        public OFActionNiciraLoad build() {
            int ofsNbits = this.ofsNbitsSet ? this.ofsNbits : DEFAULT_OFS_NBITS;
            long dst = this.dstSet ? this.dst : DEFAULT_DST;
            U64 value = this.valueSet ? this.value : DEFAULT_VALUE;
            if(value == null)
                throw new NullPointerException("Property value must not be null");


            return new OFActionNiciraLoadVer14(
                    ofsNbits,
                    dst,
                    value
                );
        }

    }


    final static Reader READER = new Reader();
    static class Reader implements OFMessageReader<OFActionNiciraLoad> {
        @Override
        public OFActionNiciraLoad readFrom(ChannelBuffer bb) throws OFParseError {
            int start = bb.readerIndex();
            // fixed value property type == 65535
            short type = bb.readShort();
            if(type != (short) 0xffff)
                throw new OFParseError("Wrong type: Expected=OFActionType.EXPERIMENTER(65535), got="+type);
            int length = U16.f(bb.readShort());
            if(length != 24)
                throw new OFParseError("Wrong length: Expected=24(24), got="+length);
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
            // fixed value property subtype == 0x7
            short subtype = bb.readShort();
            if(subtype != (short) 0x7)
                throw new OFParseError("Wrong subtype: Expected=0x7(0x7), got="+subtype);
            int ofsNbits = U16.f(bb.readShort());
            long dst = U32.f(bb.readInt());
            U64 value = U64.ofRaw(bb.readLong());

            OFActionNiciraLoadVer14 actionNiciraLoadVer14 = new OFActionNiciraLoadVer14(
                    ofsNbits,
                      dst,
                      value
                    );
            if(logger.isTraceEnabled())
                logger.trace("readFrom - read={}", actionNiciraLoadVer14);
            return actionNiciraLoadVer14;
        }
    }

    public void putTo(PrimitiveSink sink) {
        FUNNEL.funnel(this, sink);
    }

    final static OFActionNiciraLoadVer14Funnel FUNNEL = new OFActionNiciraLoadVer14Funnel();
    static class OFActionNiciraLoadVer14Funnel implements Funnel<OFActionNiciraLoadVer14> {
        private static final long serialVersionUID = 1L;
        @Override
        public void funnel(OFActionNiciraLoadVer14 message, PrimitiveSink sink) {
            // fixed value property type = 65535
            sink.putShort((short) 0xffff);
            // fixed value property length = 24
            sink.putShort((short) 0x18);
            // fixed value property experimenter = 0x2320L
            sink.putInt(0x2320);
            // fixed value property subtype = 0x7
            sink.putShort((short) 0x7);
            sink.putInt(message.ofsNbits);
            sink.putLong(message.dst);
            message.value.putTo(sink);
        }
    }


    public void writeTo(ChannelBuffer bb) {
        WRITER.write(bb, this);
    }

    final static Writer WRITER = new Writer();
    static class Writer implements OFMessageWriter<OFActionNiciraLoadVer14> {
        @Override
        public void write(ChannelBuffer bb, OFActionNiciraLoadVer14 message) {
            // fixed value property type = 65535
            bb.writeShort((short) 0xffff);
            // fixed value property length = 24
            bb.writeShort((short) 0x18);
            // fixed value property experimenter = 0x2320L
            bb.writeInt(0x2320);
            // fixed value property subtype = 0x7
            bb.writeShort((short) 0x7);
            bb.writeShort(U16.t(message.ofsNbits));
            bb.writeInt(U32.t(message.dst));
            bb.writeLong(message.value.getValue());


        }
    }

    @Override
    public String toString() {
        StringBuilder b = new StringBuilder("OFActionNiciraLoadVer14(");
        b.append("ofsNbits=").append(ofsNbits);
        b.append(", ");
        b.append("dst=").append(dst);
        b.append(", ");
        b.append("value=").append(value);
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
        OFActionNiciraLoadVer14 other = (OFActionNiciraLoadVer14) obj;

        if( ofsNbits != other.ofsNbits)
            return false;
        if( dst != other.dst)
            return false;
        if (value == null) {
            if (other.value != null)
                return false;
        } else if (!value.equals(other.value))
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;

        result = prime * result + ofsNbits;
        result = prime *  (int) (dst ^ (dst >>> 32));
        result = prime * result + ((value == null) ? 0 : value.hashCode());
        return result;
    }

}
