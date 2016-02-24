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

class OFOxmVlanVidMaskedVer14 implements OFOxmVlanVidMasked {
    private static final Logger logger = LoggerFactory.getLogger(OFOxmVlanVidMaskedVer14.class);
    // version: 1.4
    final static byte WIRE_VERSION = 5;
    final static int LENGTH = 8;

        private final static OFVlanVidMatch DEFAULT_VALUE = OFVlanVidMatch.NONE;
        private final static OFVlanVidMatch DEFAULT_VALUE_MASK = OFVlanVidMatch.NONE;

    // OF message fields
    private final OFVlanVidMatch value;
    private final OFVlanVidMatch mask;
//
    // Immutable default instance
    final static OFOxmVlanVidMaskedVer14 DEFAULT = new OFOxmVlanVidMaskedVer14(
        DEFAULT_VALUE, DEFAULT_VALUE_MASK
    );

    // package private constructor - used by readers, builders, and factory
    OFOxmVlanVidMaskedVer14(OFVlanVidMatch value, OFVlanVidMatch mask) {
        if(value == null) {
            throw new NullPointerException("OFOxmVlanVidMaskedVer14: property value cannot be null");
        }
        if(mask == null) {
            throw new NullPointerException("OFOxmVlanVidMaskedVer14: property mask cannot be null");
        }
        this.value = value;
        this.mask = mask;
    }

    // Accessors for OF message fields
    @Override
    public long getTypeLen() {
        return 0x80000d04L;
    }

    @Override
    public OFVlanVidMatch getValue() {
        return value;
    }

    @Override
    public OFVlanVidMatch getMask() {
        return mask;
    }

    @Override
    public MatchField<OFVlanVidMatch> getMatchField() {
        return MatchField.VLAN_VID;
    }

    @Override
    public boolean isMasked() {
        return true;
    }

    public OFOxm<OFVlanVidMatch> getCanonical() {
        if (OFVlanVidMatch.NO_MASK.equals(mask)) {
            return new OFOxmVlanVidVer14(value);
        } else if(OFVlanVidMatch.FULL_MASK.equals(mask)) {
            return null;
        } else {
            return this;
        }
    }

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_14;
    }



    public OFOxmVlanVidMasked.Builder createBuilder() {
        return new BuilderWithParent(this);
    }

    static class BuilderWithParent implements OFOxmVlanVidMasked.Builder {
        final OFOxmVlanVidMaskedVer14 parentMessage;

        // OF message fields
        private boolean valueSet;
        private OFVlanVidMatch value;
        private boolean maskSet;
        private OFVlanVidMatch mask;

        BuilderWithParent(OFOxmVlanVidMaskedVer14 parentMessage) {
            this.parentMessage = parentMessage;
        }

    @Override
    public long getTypeLen() {
        return 0x80000d04L;
    }

    @Override
    public OFVlanVidMatch getValue() {
        return value;
    }

    @Override
    public OFOxmVlanVidMasked.Builder setValue(OFVlanVidMatch value) {
        this.value = value;
        this.valueSet = true;
        return this;
    }
    @Override
    public OFVlanVidMatch getMask() {
        return mask;
    }

    @Override
    public OFOxmVlanVidMasked.Builder setMask(OFVlanVidMatch mask) {
        this.mask = mask;
        this.maskSet = true;
        return this;
    }
    @Override
    public MatchField<OFVlanVidMatch> getMatchField() {
        return MatchField.VLAN_VID;
    }

    @Override
    public boolean isMasked() {
        return true;
    }

    @Override
    public OFOxm<OFVlanVidMatch> getCanonical()throws UnsupportedOperationException {
        throw new UnsupportedOperationException("Property canonical not supported in version 1.4");
    }

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_14;
    }



        @Override
        public OFOxmVlanVidMasked build() {
                OFVlanVidMatch value = this.valueSet ? this.value : parentMessage.value;
                if(value == null)
                    throw new NullPointerException("Property value must not be null");
                OFVlanVidMatch mask = this.maskSet ? this.mask : parentMessage.mask;
                if(mask == null)
                    throw new NullPointerException("Property mask must not be null");

                //
                return new OFOxmVlanVidMaskedVer14(
                    value,
                    mask
                );
        }

    }

    static class Builder implements OFOxmVlanVidMasked.Builder {
        // OF message fields
        private boolean valueSet;
        private OFVlanVidMatch value;
        private boolean maskSet;
        private OFVlanVidMatch mask;

    @Override
    public long getTypeLen() {
        return 0x80000d04L;
    }

    @Override
    public OFVlanVidMatch getValue() {
        return value;
    }

    @Override
    public OFOxmVlanVidMasked.Builder setValue(OFVlanVidMatch value) {
        this.value = value;
        this.valueSet = true;
        return this;
    }
    @Override
    public OFVlanVidMatch getMask() {
        return mask;
    }

    @Override
    public OFOxmVlanVidMasked.Builder setMask(OFVlanVidMatch mask) {
        this.mask = mask;
        this.maskSet = true;
        return this;
    }
    @Override
    public MatchField<OFVlanVidMatch> getMatchField() {
        return MatchField.VLAN_VID;
    }

    @Override
    public boolean isMasked() {
        return true;
    }

    @Override
    public OFOxm<OFVlanVidMatch> getCanonical()throws UnsupportedOperationException {
        throw new UnsupportedOperationException("Property canonical not supported in version 1.4");
    }

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_14;
    }

//
        @Override
        public OFOxmVlanVidMasked build() {
            OFVlanVidMatch value = this.valueSet ? this.value : DEFAULT_VALUE;
            if(value == null)
                throw new NullPointerException("Property value must not be null");
            OFVlanVidMatch mask = this.maskSet ? this.mask : DEFAULT_VALUE_MASK;
            if(mask == null)
                throw new NullPointerException("Property mask must not be null");


            return new OFOxmVlanVidMaskedVer14(
                    value,
                    mask
                );
        }

    }


    final static Reader READER = new Reader();
    static class Reader implements OFMessageReader<OFOxmVlanVidMasked> {
        @Override
        public OFOxmVlanVidMasked readFrom(ChannelBuffer bb) throws OFParseError {
            // fixed value property typeLen == 0x80000d04L
            int typeLen = bb.readInt();
            if(typeLen != (int) 0x80000d04)
                throw new OFParseError("Wrong typeLen: Expected=0x80000d04L(0x80000d04L), got="+typeLen);
            OFVlanVidMatch value = OFVlanVidMatch.read2Bytes(bb);
            OFVlanVidMatch mask = OFVlanVidMatch.read2Bytes(bb);

            OFOxmVlanVidMaskedVer14 oxmVlanVidMaskedVer14 = new OFOxmVlanVidMaskedVer14(
                    value,
                      mask
                    );
            if(logger.isTraceEnabled())
                logger.trace("readFrom - read={}", oxmVlanVidMaskedVer14);
            return oxmVlanVidMaskedVer14;
        }
    }

    public void putTo(PrimitiveSink sink) {
        FUNNEL.funnel(this, sink);
    }

    final static OFOxmVlanVidMaskedVer14Funnel FUNNEL = new OFOxmVlanVidMaskedVer14Funnel();
    static class OFOxmVlanVidMaskedVer14Funnel implements Funnel<OFOxmVlanVidMaskedVer14> {
        private static final long serialVersionUID = 1L;
        @Override
        public void funnel(OFOxmVlanVidMaskedVer14 message, PrimitiveSink sink) {
            // fixed value property typeLen = 0x80000d04L
            sink.putInt((int) 0x80000d04);
            message.value.putTo(sink);
            message.mask.putTo(sink);
        }
    }


    public void writeTo(ChannelBuffer bb) {
        WRITER.write(bb, this);
    }

    final static Writer WRITER = new Writer();
    static class Writer implements OFMessageWriter<OFOxmVlanVidMaskedVer14> {
        @Override
        public void write(ChannelBuffer bb, OFOxmVlanVidMaskedVer14 message) {
            // fixed value property typeLen = 0x80000d04L
            bb.writeInt((int) 0x80000d04);
            message.value.write2Bytes(bb);
            message.mask.write2Bytes(bb);


        }
    }

    @Override
    public String toString() {
        StringBuilder b = new StringBuilder("OFOxmVlanVidMaskedVer14(");
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
        OFOxmVlanVidMaskedVer14 other = (OFOxmVlanVidMaskedVer14) obj;

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
