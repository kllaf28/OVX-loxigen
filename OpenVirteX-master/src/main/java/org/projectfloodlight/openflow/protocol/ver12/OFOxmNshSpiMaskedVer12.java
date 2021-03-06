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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.Set;
import org.jboss.netty.buffer.ChannelBuffer;
import com.google.common.hash.PrimitiveSink;
import com.google.common.hash.Funnel;

class OFOxmNshSpiMaskedVer12 implements OFOxmNshSpiMasked {
    private static final Logger logger = LoggerFactory.getLogger(OFOxmNshSpiMaskedVer12.class);
    // version: 1.2
    final static byte WIRE_VERSION = 3;
    final static int LENGTH = 12;

        private final static U32 DEFAULT_VALUE = U32.ZERO;
        private final static U32 DEFAULT_VALUE_MASK = U32.ZERO;

    // OF message fields
    private final U32 value;
    private final U32 mask;
//
    // Immutable default instance
    final static OFOxmNshSpiMaskedVer12 DEFAULT = new OFOxmNshSpiMaskedVer12(
        DEFAULT_VALUE, DEFAULT_VALUE_MASK
    );

    // package private constructor - used by readers, builders, and factory
    OFOxmNshSpiMaskedVer12(U32 value, U32 mask) {
        if(value == null) {
            throw new NullPointerException("OFOxmNshSpiMaskedVer12: property value cannot be null");
        }
        if(mask == null) {
            throw new NullPointerException("OFOxmNshSpiMaskedVer12: property mask cannot be null");
        }
        this.value = value;
        this.mask = mask;
    }

    // Accessors for OF message fields
    @Override
    public long getTypeLen() {
        return 0x14b08L;
    }

    @Override
    public U32 getValue() {
        return value;
    }

    @Override
    public U32 getMask() {
        return mask;
    }

    @Override
    public MatchField<U32> getMatchField() {
        return MatchField.NSH_SPI;
    }

    @Override
    public boolean isMasked() {
        return true;
    }

    public OFOxm<U32> getCanonical() {
        if (U32.NO_MASK.equals(mask)) {
            return new OFOxmNshSpiVer12(value);
        } else if(U32.FULL_MASK.equals(mask)) {
            return null;
        } else {
            return this;
        }
    }

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_12;
    }



    public OFOxmNshSpiMasked.Builder createBuilder() {
        return new BuilderWithParent(this);
    }

    static class BuilderWithParent implements OFOxmNshSpiMasked.Builder {
        final OFOxmNshSpiMaskedVer12 parentMessage;

        // OF message fields
        private boolean valueSet;
        private U32 value;
        private boolean maskSet;
        private U32 mask;

        BuilderWithParent(OFOxmNshSpiMaskedVer12 parentMessage) {
            this.parentMessage = parentMessage;
        }

    @Override
    public long getTypeLen() {
        return 0x14b08L;
    }

    @Override
    public U32 getValue() {
        return value;
    }

    @Override
    public OFOxmNshSpiMasked.Builder setValue(U32 value) {
        this.value = value;
        this.valueSet = true;
        return this;
    }
    @Override
    public U32 getMask() {
        return mask;
    }

    @Override
    public OFOxmNshSpiMasked.Builder setMask(U32 mask) {
        this.mask = mask;
        this.maskSet = true;
        return this;
    }
    @Override
    public MatchField<U32> getMatchField() {
        return MatchField.NSH_SPI;
    }

    @Override
    public boolean isMasked() {
        return true;
    }

    @Override
    public OFOxm<U32> getCanonical()throws UnsupportedOperationException {
        throw new UnsupportedOperationException("Property canonical not supported in version 1.2");
    }

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_12;
    }



        @Override
        public OFOxmNshSpiMasked build() {
                U32 value = this.valueSet ? this.value : parentMessage.value;
                if(value == null)
                    throw new NullPointerException("Property value must not be null");
                U32 mask = this.maskSet ? this.mask : parentMessage.mask;
                if(mask == null)
                    throw new NullPointerException("Property mask must not be null");

                //
                return new OFOxmNshSpiMaskedVer12(
                    value,
                    mask
                );
        }

    }

    static class Builder implements OFOxmNshSpiMasked.Builder {
        // OF message fields
        private boolean valueSet;
        private U32 value;
        private boolean maskSet;
        private U32 mask;

    @Override
    public long getTypeLen() {
        return 0x14b08L;
    }

    @Override
    public U32 getValue() {
        return value;
    }

    @Override
    public OFOxmNshSpiMasked.Builder setValue(U32 value) {
        this.value = value;
        this.valueSet = true;
        return this;
    }
    @Override
    public U32 getMask() {
        return mask;
    }

    @Override
    public OFOxmNshSpiMasked.Builder setMask(U32 mask) {
        this.mask = mask;
        this.maskSet = true;
        return this;
    }
    @Override
    public MatchField<U32> getMatchField() {
        return MatchField.NSH_SPI;
    }

    @Override
    public boolean isMasked() {
        return true;
    }

    @Override
    public OFOxm<U32> getCanonical()throws UnsupportedOperationException {
        throw new UnsupportedOperationException("Property canonical not supported in version 1.2");
    }

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_12;
    }

//
        @Override
        public OFOxmNshSpiMasked build() {
            U32 value = this.valueSet ? this.value : DEFAULT_VALUE;
            if(value == null)
                throw new NullPointerException("Property value must not be null");
            U32 mask = this.maskSet ? this.mask : DEFAULT_VALUE_MASK;
            if(mask == null)
                throw new NullPointerException("Property mask must not be null");


            return new OFOxmNshSpiMaskedVer12(
                    value,
                    mask
                );
        }

    }


    final static Reader READER = new Reader();
    static class Reader implements OFMessageReader<OFOxmNshSpiMasked> {
        @Override
        public OFOxmNshSpiMasked readFrom(ChannelBuffer bb) throws OFParseError {
            // fixed value property typeLen == 0x14b08L
            int typeLen = bb.readInt();
            if(typeLen != 0x14b08)
                throw new OFParseError("Wrong typeLen: Expected=0x14b08L(0x14b08L), got="+typeLen);
            U32 value = U32.of(bb.readInt());
            U32 mask = U32.of(bb.readInt());

            OFOxmNshSpiMaskedVer12 oxmNshSpiMaskedVer12 = new OFOxmNshSpiMaskedVer12(
                    value,
                      mask
                    );
            if(logger.isTraceEnabled())
                logger.trace("readFrom - read={}", oxmNshSpiMaskedVer12);
            return oxmNshSpiMaskedVer12;
        }
    }

    public void putTo(PrimitiveSink sink) {
        FUNNEL.funnel(this, sink);
    }

    final static OFOxmNshSpiMaskedVer12Funnel FUNNEL = new OFOxmNshSpiMaskedVer12Funnel();
    static class OFOxmNshSpiMaskedVer12Funnel implements Funnel<OFOxmNshSpiMaskedVer12> {
        private static final long serialVersionUID = 1L;
        @Override
        public void funnel(OFOxmNshSpiMaskedVer12 message, PrimitiveSink sink) {
            // fixed value property typeLen = 0x14b08L
            sink.putInt(0x14b08);
            message.value.putTo(sink);
            message.mask.putTo(sink);
        }
    }


    public void writeTo(ChannelBuffer bb) {
        WRITER.write(bb, this);
    }

    final static Writer WRITER = new Writer();
    static class Writer implements OFMessageWriter<OFOxmNshSpiMaskedVer12> {
        @Override
        public void write(ChannelBuffer bb, OFOxmNshSpiMaskedVer12 message) {
            // fixed value property typeLen = 0x14b08L
            bb.writeInt(0x14b08);
            bb.writeInt(message.value.getRaw());
            bb.writeInt(message.mask.getRaw());


        }
    }

    @Override
    public String toString() {
        StringBuilder b = new StringBuilder("OFOxmNshSpiMaskedVer12(");
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
        OFOxmNshSpiMaskedVer12 other = (OFOxmNshSpiMaskedVer12) obj;

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
