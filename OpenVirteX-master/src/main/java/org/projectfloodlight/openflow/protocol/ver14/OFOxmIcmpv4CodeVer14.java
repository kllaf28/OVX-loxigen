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

class OFOxmIcmpv4CodeVer14 implements OFOxmIcmpv4Code {
    private static final Logger logger = LoggerFactory.getLogger(OFOxmIcmpv4CodeVer14.class);
    // version: 1.4
    final static byte WIRE_VERSION = 5;
    final static int LENGTH = 5;

        private final static ICMPv4Code DEFAULT_VALUE = ICMPv4Code.NONE;

    // OF message fields
    private final ICMPv4Code value;
//
    // Immutable default instance
    final static OFOxmIcmpv4CodeVer14 DEFAULT = new OFOxmIcmpv4CodeVer14(
        DEFAULT_VALUE
    );

    // package private constructor - used by readers, builders, and factory
    OFOxmIcmpv4CodeVer14(ICMPv4Code value) {
        if(value == null) {
            throw new NullPointerException("OFOxmIcmpv4CodeVer14: property value cannot be null");
        }
        this.value = value;
    }

    // Accessors for OF message fields
    @Override
    public long getTypeLen() {
        return 0x80002801L;
    }

    @Override
    public ICMPv4Code getValue() {
        return value;
    }

    @Override
    public MatchField<ICMPv4Code> getMatchField() {
        return MatchField.ICMPV4_CODE;
    }

    @Override
    public boolean isMasked() {
        return false;
    }

    public OFOxm<ICMPv4Code> getCanonical() {
        // exact match OXM is always canonical
        return this;
    }

    @Override
    public ICMPv4Code getMask()throws UnsupportedOperationException {
        throw new UnsupportedOperationException("Property mask not supported in version 1.4");
    }

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_14;
    }



    public OFOxmIcmpv4Code.Builder createBuilder() {
        return new BuilderWithParent(this);
    }

    static class BuilderWithParent implements OFOxmIcmpv4Code.Builder {
        final OFOxmIcmpv4CodeVer14 parentMessage;

        // OF message fields
        private boolean valueSet;
        private ICMPv4Code value;

        BuilderWithParent(OFOxmIcmpv4CodeVer14 parentMessage) {
            this.parentMessage = parentMessage;
        }

    @Override
    public long getTypeLen() {
        return 0x80002801L;
    }

    @Override
    public ICMPv4Code getValue() {
        return value;
    }

    @Override
    public OFOxmIcmpv4Code.Builder setValue(ICMPv4Code value) {
        this.value = value;
        this.valueSet = true;
        return this;
    }
    @Override
    public MatchField<ICMPv4Code> getMatchField() {
        return MatchField.ICMPV4_CODE;
    }

    @Override
    public boolean isMasked() {
        return false;
    }

    @Override
    public OFOxm<ICMPv4Code> getCanonical()throws UnsupportedOperationException {
        throw new UnsupportedOperationException("Property canonical not supported in version 1.4");
    }

    @Override
    public ICMPv4Code getMask()throws UnsupportedOperationException {
        throw new UnsupportedOperationException("Property mask not supported in version 1.4");
    }

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_14;
    }



        @Override
        public OFOxmIcmpv4Code build() {
                ICMPv4Code value = this.valueSet ? this.value : parentMessage.value;
                if(value == null)
                    throw new NullPointerException("Property value must not be null");

                //
                return new OFOxmIcmpv4CodeVer14(
                    value
                );
        }

    }

    static class Builder implements OFOxmIcmpv4Code.Builder {
        // OF message fields
        private boolean valueSet;
        private ICMPv4Code value;

    @Override
    public long getTypeLen() {
        return 0x80002801L;
    }

    @Override
    public ICMPv4Code getValue() {
        return value;
    }

    @Override
    public OFOxmIcmpv4Code.Builder setValue(ICMPv4Code value) {
        this.value = value;
        this.valueSet = true;
        return this;
    }
    @Override
    public MatchField<ICMPv4Code> getMatchField() {
        return MatchField.ICMPV4_CODE;
    }

    @Override
    public boolean isMasked() {
        return false;
    }

    @Override
    public OFOxm<ICMPv4Code> getCanonical()throws UnsupportedOperationException {
        throw new UnsupportedOperationException("Property canonical not supported in version 1.4");
    }

    @Override
    public ICMPv4Code getMask()throws UnsupportedOperationException {
        throw new UnsupportedOperationException("Property mask not supported in version 1.4");
    }

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_14;
    }

//
        @Override
        public OFOxmIcmpv4Code build() {
            ICMPv4Code value = this.valueSet ? this.value : DEFAULT_VALUE;
            if(value == null)
                throw new NullPointerException("Property value must not be null");


            return new OFOxmIcmpv4CodeVer14(
                    value
                );
        }

    }


    final static Reader READER = new Reader();
    static class Reader implements OFMessageReader<OFOxmIcmpv4Code> {
        @Override
        public OFOxmIcmpv4Code readFrom(ChannelBuffer bb) throws OFParseError {
            // fixed value property typeLen == 0x80002801L
            int typeLen = bb.readInt();
            if(typeLen != (int) 0x80002801)
                throw new OFParseError("Wrong typeLen: Expected=0x80002801L(0x80002801L), got="+typeLen);
            ICMPv4Code value = ICMPv4Code.readByte(bb);

            OFOxmIcmpv4CodeVer14 oxmIcmpv4CodeVer14 = new OFOxmIcmpv4CodeVer14(
                    value
                    );
            if(logger.isTraceEnabled())
                logger.trace("readFrom - read={}", oxmIcmpv4CodeVer14);
            return oxmIcmpv4CodeVer14;
        }
    }

    public void putTo(PrimitiveSink sink) {
        FUNNEL.funnel(this, sink);
    }

    final static OFOxmIcmpv4CodeVer14Funnel FUNNEL = new OFOxmIcmpv4CodeVer14Funnel();
    static class OFOxmIcmpv4CodeVer14Funnel implements Funnel<OFOxmIcmpv4CodeVer14> {
        private static final long serialVersionUID = 1L;
        @Override
        public void funnel(OFOxmIcmpv4CodeVer14 message, PrimitiveSink sink) {
            // fixed value property typeLen = 0x80002801L
            sink.putInt((int) 0x80002801);
            message.value.putTo(sink);
        }
    }


    public void writeTo(ChannelBuffer bb) {
        WRITER.write(bb, this);
    }

    final static Writer WRITER = new Writer();
    static class Writer implements OFMessageWriter<OFOxmIcmpv4CodeVer14> {
        @Override
        public void write(ChannelBuffer bb, OFOxmIcmpv4CodeVer14 message) {
            // fixed value property typeLen = 0x80002801L
            bb.writeInt((int) 0x80002801);
            message.value.writeByte(bb);


        }
    }

    @Override
    public String toString() {
        StringBuilder b = new StringBuilder("OFOxmIcmpv4CodeVer14(");
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
        OFOxmIcmpv4CodeVer14 other = (OFOxmIcmpv4CodeVer14) obj;

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

        result = prime * result + ((value == null) ? 0 : value.hashCode());
        return result;
    }

}
