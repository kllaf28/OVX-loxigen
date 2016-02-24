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

class OFOxmNshCh2MaskedVer14 implements OFOxmNshCh2Masked {
    private static final Logger logger = LoggerFactory.getLogger(OFOxmNshCh2MaskedVer14.class);
    // version: 1.4
    final static byte WIRE_VERSION = 5;
    final static int LENGTH = 12;

        private final static U32 DEFAULT_VALUE = U32.ZERO;
        private final static U32 DEFAULT_VALUE_MASK = U32.ZERO;

    // OF message fields
    private final U32 value;
    private final U32 mask;
//
    // Immutable default instance
    final static OFOxmNshCh2MaskedVer14 DEFAULT = new OFOxmNshCh2MaskedVer14(
        DEFAULT_VALUE, DEFAULT_VALUE_MASK
    );

    // package private constructor - used by readers, builders, and factory
    OFOxmNshCh2MaskedVer14(U32 value, U32 mask) {
        if(value == null) {
            throw new NullPointerException("OFOxmNshCh2MaskedVer14: property value cannot be null");
        }
        if(mask == null) {
            throw new NullPointerException("OFOxmNshCh2MaskedVer14: property mask cannot be null");
        }
        this.value = value;
        this.mask = mask;
    }

    // Accessors for OF message fields
    @Override
    public long getTypeLen() {
        return 0x15108L;
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
        return MatchField.NSH_CH2;
    }

    @Override
    public boolean isMasked() {
        return true;
    }

    public OFOxm<U32> getCanonical() {
        if (U32.NO_MASK.equals(mask)) {
            return new OFOxmNshCh2Ver14(value);
        } else if(U32.FULL_MASK.equals(mask)) {
            return null;
        } else {
            return this;
        }
    }

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_14;
    }



    public OFOxmNshCh2Masked.Builder createBuilder() {
        return new BuilderWithParent(this);
    }

    static class BuilderWithParent implements OFOxmNshCh2Masked.Builder {
        final OFOxmNshCh2MaskedVer14 parentMessage;

        // OF message fields
        private boolean valueSet;
        private U32 value;
        private boolean maskSet;
        private U32 mask;

        BuilderWithParent(OFOxmNshCh2MaskedVer14 parentMessage) {
            this.parentMessage = parentMessage;
        }

    @Override
    public long getTypeLen() {
        return 0x15108L;
    }

    @Override
    public U32 getValue() {
        return value;
    }

    @Override
    public OFOxmNshCh2Masked.Builder setValue(U32 value) {
        this.value = value;
        this.valueSet = true;
        return this;
    }
    @Override
    public U32 getMask() {
        return mask;
    }

    @Override
    public OFOxmNshCh2Masked.Builder setMask(U32 mask) {
        this.mask = mask;
        this.maskSet = true;
        return this;
    }
    @Override
    public MatchField<U32> getMatchField() {
        return MatchField.NSH_CH2;
    }

    @Override
    public boolean isMasked() {
        return true;
    }

    @Override
    public OFOxm<U32> getCanonical()throws UnsupportedOperationException {
        throw new UnsupportedOperationException("Property canonical not supported in version 1.4");
    }

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_14;
    }



        @Override
        public OFOxmNshCh2Masked build() {
                U32 value = this.valueSet ? this.value : parentMessage.value;
                if(value == null)
                    throw new NullPointerException("Property value must not be null");
                U32 mask = this.maskSet ? this.mask : parentMessage.mask;
                if(mask == null)
                    throw new NullPointerException("Property mask must not be null");

                //
                return new OFOxmNshCh2MaskedVer14(
                    value,
                    mask
                );
        }

    }

    static class Builder implements OFOxmNshCh2Masked.Builder {
        // OF message fields
        private boolean valueSet;
        private U32 value;
        private boolean maskSet;
        private U32 mask;

    @Override
    public long getTypeLen() {
        return 0x15108L;
    }

    @Override
    public U32 getValue() {
        return value;
    }

    @Override
    public OFOxmNshCh2Masked.Builder setValue(U32 value) {
        this.value = value;
        this.valueSet = true;
        return this;
    }
    @Override
    public U32 getMask() {
        return mask;
    }

    @Override
    public OFOxmNshCh2Masked.Builder setMask(U32 mask) {
        this.mask = mask;
        this.maskSet = true;
        return this;
    }
    @Override
    public MatchField<U32> getMatchField() {
        return MatchField.NSH_CH2;
    }

    @Override
    public boolean isMasked() {
        return true;
    }

    @Override
    public OFOxm<U32> getCanonical()throws UnsupportedOperationException {
        throw new UnsupportedOperationException("Property canonical not supported in version 1.4");
    }

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_14;
    }

//
        @Override
        public OFOxmNshCh2Masked build() {
            U32 value = this.valueSet ? this.value : DEFAULT_VALUE;
            if(value == null)
                throw new NullPointerException("Property value must not be null");
            U32 mask = this.maskSet ? this.mask : DEFAULT_VALUE_MASK;
            if(mask == null)
                throw new NullPointerException("Property mask must not be null");


            return new OFOxmNshCh2MaskedVer14(
                    value,
                    mask
                );
        }

    }


    final static Reader READER = new Reader();
    static class Reader implements OFMessageReader<OFOxmNshCh2Masked> {
        @Override
        public OFOxmNshCh2Masked readFrom(ChannelBuffer bb) throws OFParseError {
            // fixed value property typeLen == 0x15108L
            int typeLen = bb.readInt();
            if(typeLen != 0x15108)
                throw new OFParseError("Wrong typeLen: Expected=0x15108L(0x15108L), got="+typeLen);
            U32 value = U32.of(bb.readInt());
            U32 mask = U32.of(bb.readInt());

            OFOxmNshCh2MaskedVer14 oxmNshCh2MaskedVer14 = new OFOxmNshCh2MaskedVer14(
                    value,
                      mask
                    );
            if(logger.isTraceEnabled())
                logger.trace("readFrom - read={}", oxmNshCh2MaskedVer14);
            return oxmNshCh2MaskedVer14;
        }
    }

    public void putTo(PrimitiveSink sink) {
        FUNNEL.funnel(this, sink);
    }

    final static OFOxmNshCh2MaskedVer14Funnel FUNNEL = new OFOxmNshCh2MaskedVer14Funnel();
    static class OFOxmNshCh2MaskedVer14Funnel implements Funnel<OFOxmNshCh2MaskedVer14> {
        private static final long serialVersionUID = 1L;
        @Override
        public void funnel(OFOxmNshCh2MaskedVer14 message, PrimitiveSink sink) {
            // fixed value property typeLen = 0x15108L
            sink.putInt(0x15108);
            message.value.putTo(sink);
            message.mask.putTo(sink);
        }
    }


    public void writeTo(ChannelBuffer bb) {
        WRITER.write(bb, this);
    }

    final static Writer WRITER = new Writer();
    static class Writer implements OFMessageWriter<OFOxmNshCh2MaskedVer14> {
        @Override
        public void write(ChannelBuffer bb, OFOxmNshCh2MaskedVer14 message) {
            // fixed value property typeLen = 0x15108L
            bb.writeInt(0x15108);
            bb.writeInt(message.value.getRaw());
            bb.writeInt(message.mask.getRaw());


        }
    }

    @Override
    public String toString() {
        StringBuilder b = new StringBuilder("OFOxmNshCh2MaskedVer14(");
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
        OFOxmNshCh2MaskedVer14 other = (OFOxmNshCh2MaskedVer14) obj;

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
