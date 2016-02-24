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

class OFOxmUdpSrcMaskedVer13 implements OFOxmUdpSrcMasked {
    private static final Logger logger = LoggerFactory.getLogger(OFOxmUdpSrcMaskedVer13.class);
    // version: 1.3
    final static byte WIRE_VERSION = 4;
    final static int LENGTH = 8;

        private final static TransportPort DEFAULT_VALUE = TransportPort.NONE;
        private final static TransportPort DEFAULT_VALUE_MASK = TransportPort.NONE;

    // OF message fields
    private final TransportPort value;
    private final TransportPort mask;
//
    // Immutable default instance
    final static OFOxmUdpSrcMaskedVer13 DEFAULT = new OFOxmUdpSrcMaskedVer13(
        DEFAULT_VALUE, DEFAULT_VALUE_MASK
    );

    // package private constructor - used by readers, builders, and factory
    OFOxmUdpSrcMaskedVer13(TransportPort value, TransportPort mask) {
        if(value == null) {
            throw new NullPointerException("OFOxmUdpSrcMaskedVer13: property value cannot be null");
        }
        if(mask == null) {
            throw new NullPointerException("OFOxmUdpSrcMaskedVer13: property mask cannot be null");
        }
        this.value = value;
        this.mask = mask;
    }

    // Accessors for OF message fields
    @Override
    public long getTypeLen() {
        return 0x80001f04L;
    }

    @Override
    public TransportPort getValue() {
        return value;
    }

    @Override
    public TransportPort getMask() {
        return mask;
    }

    @Override
    public MatchField<TransportPort> getMatchField() {
        return MatchField.UDP_SRC;
    }

    @Override
    public boolean isMasked() {
        return true;
    }

    public OFOxm<TransportPort> getCanonical() {
        if (TransportPort.NO_MASK.equals(mask)) {
            return new OFOxmUdpSrcVer13(value);
        } else if(TransportPort.FULL_MASK.equals(mask)) {
            return null;
        } else {
            return this;
        }
    }

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_13;
    }



    public OFOxmUdpSrcMasked.Builder createBuilder() {
        return new BuilderWithParent(this);
    }

    static class BuilderWithParent implements OFOxmUdpSrcMasked.Builder {
        final OFOxmUdpSrcMaskedVer13 parentMessage;

        // OF message fields
        private boolean valueSet;
        private TransportPort value;
        private boolean maskSet;
        private TransportPort mask;

        BuilderWithParent(OFOxmUdpSrcMaskedVer13 parentMessage) {
            this.parentMessage = parentMessage;
        }

    @Override
    public long getTypeLen() {
        return 0x80001f04L;
    }

    @Override
    public TransportPort getValue() {
        return value;
    }

    @Override
    public OFOxmUdpSrcMasked.Builder setValue(TransportPort value) {
        this.value = value;
        this.valueSet = true;
        return this;
    }
    @Override
    public TransportPort getMask() {
        return mask;
    }

    @Override
    public OFOxmUdpSrcMasked.Builder setMask(TransportPort mask) {
        this.mask = mask;
        this.maskSet = true;
        return this;
    }
    @Override
    public MatchField<TransportPort> getMatchField() {
        return MatchField.UDP_SRC;
    }

    @Override
    public boolean isMasked() {
        return true;
    }

    @Override
    public OFOxm<TransportPort> getCanonical()throws UnsupportedOperationException {
        throw new UnsupportedOperationException("Property canonical not supported in version 1.3");
    }

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_13;
    }



        @Override
        public OFOxmUdpSrcMasked build() {
                TransportPort value = this.valueSet ? this.value : parentMessage.value;
                if(value == null)
                    throw new NullPointerException("Property value must not be null");
                TransportPort mask = this.maskSet ? this.mask : parentMessage.mask;
                if(mask == null)
                    throw new NullPointerException("Property mask must not be null");

                //
                return new OFOxmUdpSrcMaskedVer13(
                    value,
                    mask
                );
        }

    }

    static class Builder implements OFOxmUdpSrcMasked.Builder {
        // OF message fields
        private boolean valueSet;
        private TransportPort value;
        private boolean maskSet;
        private TransportPort mask;

    @Override
    public long getTypeLen() {
        return 0x80001f04L;
    }

    @Override
    public TransportPort getValue() {
        return value;
    }

    @Override
    public OFOxmUdpSrcMasked.Builder setValue(TransportPort value) {
        this.value = value;
        this.valueSet = true;
        return this;
    }
    @Override
    public TransportPort getMask() {
        return mask;
    }

    @Override
    public OFOxmUdpSrcMasked.Builder setMask(TransportPort mask) {
        this.mask = mask;
        this.maskSet = true;
        return this;
    }
    @Override
    public MatchField<TransportPort> getMatchField() {
        return MatchField.UDP_SRC;
    }

    @Override
    public boolean isMasked() {
        return true;
    }

    @Override
    public OFOxm<TransportPort> getCanonical()throws UnsupportedOperationException {
        throw new UnsupportedOperationException("Property canonical not supported in version 1.3");
    }

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_13;
    }

//
        @Override
        public OFOxmUdpSrcMasked build() {
            TransportPort value = this.valueSet ? this.value : DEFAULT_VALUE;
            if(value == null)
                throw new NullPointerException("Property value must not be null");
            TransportPort mask = this.maskSet ? this.mask : DEFAULT_VALUE_MASK;
            if(mask == null)
                throw new NullPointerException("Property mask must not be null");


            return new OFOxmUdpSrcMaskedVer13(
                    value,
                    mask
                );
        }

    }


    final static Reader READER = new Reader();
    static class Reader implements OFMessageReader<OFOxmUdpSrcMasked> {
        @Override
        public OFOxmUdpSrcMasked readFrom(ChannelBuffer bb) throws OFParseError {
            // fixed value property typeLen == 0x80001f04L
            int typeLen = bb.readInt();
            if(typeLen != (int) 0x80001f04)
                throw new OFParseError("Wrong typeLen: Expected=0x80001f04L(0x80001f04L), got="+typeLen);
            TransportPort value = TransportPort.read2Bytes(bb);
            TransportPort mask = TransportPort.read2Bytes(bb);

            OFOxmUdpSrcMaskedVer13 oxmUdpSrcMaskedVer13 = new OFOxmUdpSrcMaskedVer13(
                    value,
                      mask
                    );
            if(logger.isTraceEnabled())
                logger.trace("readFrom - read={}", oxmUdpSrcMaskedVer13);
            return oxmUdpSrcMaskedVer13;
        }
    }

    public void putTo(PrimitiveSink sink) {
        FUNNEL.funnel(this, sink);
    }

    final static OFOxmUdpSrcMaskedVer13Funnel FUNNEL = new OFOxmUdpSrcMaskedVer13Funnel();
    static class OFOxmUdpSrcMaskedVer13Funnel implements Funnel<OFOxmUdpSrcMaskedVer13> {
        private static final long serialVersionUID = 1L;
        @Override
        public void funnel(OFOxmUdpSrcMaskedVer13 message, PrimitiveSink sink) {
            // fixed value property typeLen = 0x80001f04L
            sink.putInt((int) 0x80001f04);
            message.value.putTo(sink);
            message.mask.putTo(sink);
        }
    }


    public void writeTo(ChannelBuffer bb) {
        WRITER.write(bb, this);
    }

    final static Writer WRITER = new Writer();
    static class Writer implements OFMessageWriter<OFOxmUdpSrcMaskedVer13> {
        @Override
        public void write(ChannelBuffer bb, OFOxmUdpSrcMaskedVer13 message) {
            // fixed value property typeLen = 0x80001f04L
            bb.writeInt((int) 0x80001f04);
            message.value.write2Bytes(bb);
            message.mask.write2Bytes(bb);


        }
    }

    @Override
    public String toString() {
        StringBuilder b = new StringBuilder("OFOxmUdpSrcMaskedVer13(");
        b.append("value=").append(value);
        b.append(", ");
        b.append("mask=").append(mask);
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
        OFOxmUdpSrcMaskedVer13 other = (OFOxmUdpSrcMaskedVer13) obj;

        if (value == null) {
            if (other.value != null)
                return false;
        } else if (!value.equals(other.value))
            return false;
        if (mask == null) {
            if (other.mask != null)
                return false;
        } else if (!mask.equals(other.mask))
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;

        result = prime * result + ((value == null) ? 0 : value.hashCode());
        result = prime * result + ((mask == null) ? 0 : mask.hashCode());
        return result;
    }

}
