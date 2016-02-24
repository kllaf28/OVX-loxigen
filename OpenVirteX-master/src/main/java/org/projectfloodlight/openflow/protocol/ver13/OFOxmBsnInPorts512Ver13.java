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

class OFOxmBsnInPorts512Ver13 implements OFOxmBsnInPorts512 {
    private static final Logger logger = LoggerFactory.getLogger(OFOxmBsnInPorts512Ver13.class);
    // version: 1.3
    final static byte WIRE_VERSION = 4;
    final static int LENGTH = 68;

        private final static OFBitMask512 DEFAULT_VALUE = OFBitMask512.NONE;

    // OF message fields
    private final OFBitMask512 value;
//
    // Immutable default instance
    final static OFOxmBsnInPorts512Ver13 DEFAULT = new OFOxmBsnInPorts512Ver13(
        DEFAULT_VALUE
    );

    // package private constructor - used by readers, builders, and factory
    OFOxmBsnInPorts512Ver13(OFBitMask512 value) {
        if(value == null) {
            throw new NullPointerException("OFOxmBsnInPorts512Ver13: property value cannot be null");
        }
        this.value = value;
    }

    // Accessors for OF message fields
    @Override
    public long getTypeLen() {
        return 0x32640L;
    }

    @Override
    public OFBitMask512 getValue() {
        return value;
    }

    @Override
    public MatchField<OFBitMask512> getMatchField() {
        return MatchField.BSN_IN_PORTS_512;
    }

    @Override
    public boolean isMasked() {
        return false;
    }

    public OFOxm<OFBitMask512> getCanonical() {
        // exact match OXM is always canonical
        return this;
    }

    @Override
    public OFBitMask512 getMask()throws UnsupportedOperationException {
        throw new UnsupportedOperationException("Property mask not supported in version 1.3");
    }

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_13;
    }



    public OFOxmBsnInPorts512.Builder createBuilder() {
        return new BuilderWithParent(this);
    }

    static class BuilderWithParent implements OFOxmBsnInPorts512.Builder {
        final OFOxmBsnInPorts512Ver13 parentMessage;

        // OF message fields
        private boolean valueSet;
        private OFBitMask512 value;

        BuilderWithParent(OFOxmBsnInPorts512Ver13 parentMessage) {
            this.parentMessage = parentMessage;
        }

    @Override
    public long getTypeLen() {
        return 0x32640L;
    }

    @Override
    public OFBitMask512 getValue() {
        return value;
    }

    @Override
    public OFOxmBsnInPorts512.Builder setValue(OFBitMask512 value) {
        this.value = value;
        this.valueSet = true;
        return this;
    }
    @Override
    public MatchField<OFBitMask512> getMatchField() {
        return MatchField.BSN_IN_PORTS_512;
    }

    @Override
    public boolean isMasked() {
        return false;
    }

    @Override
    public OFOxm<OFBitMask512> getCanonical()throws UnsupportedOperationException {
        throw new UnsupportedOperationException("Property canonical not supported in version 1.3");
    }

    @Override
    public OFBitMask512 getMask()throws UnsupportedOperationException {
        throw new UnsupportedOperationException("Property mask not supported in version 1.3");
    }

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_13;
    }



        @Override
        public OFOxmBsnInPorts512 build() {
                OFBitMask512 value = this.valueSet ? this.value : parentMessage.value;
                if(value == null)
                    throw new NullPointerException("Property value must not be null");

                //
                return new OFOxmBsnInPorts512Ver13(
                    value
                );
        }

    }

    static class Builder implements OFOxmBsnInPorts512.Builder {
        // OF message fields
        private boolean valueSet;
        private OFBitMask512 value;

    @Override
    public long getTypeLen() {
        return 0x32640L;
    }

    @Override
    public OFBitMask512 getValue() {
        return value;
    }

    @Override
    public OFOxmBsnInPorts512.Builder setValue(OFBitMask512 value) {
        this.value = value;
        this.valueSet = true;
        return this;
    }
    @Override
    public MatchField<OFBitMask512> getMatchField() {
        return MatchField.BSN_IN_PORTS_512;
    }

    @Override
    public boolean isMasked() {
        return false;
    }

    @Override
    public OFOxm<OFBitMask512> getCanonical()throws UnsupportedOperationException {
        throw new UnsupportedOperationException("Property canonical not supported in version 1.3");
    }

    @Override
    public OFBitMask512 getMask()throws UnsupportedOperationException {
        throw new UnsupportedOperationException("Property mask not supported in version 1.3");
    }

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_13;
    }

//
        @Override
        public OFOxmBsnInPorts512 build() {
            OFBitMask512 value = this.valueSet ? this.value : DEFAULT_VALUE;
            if(value == null)
                throw new NullPointerException("Property value must not be null");


            return new OFOxmBsnInPorts512Ver13(
                    value
                );
        }

    }


    final static Reader READER = new Reader();
    static class Reader implements OFMessageReader<OFOxmBsnInPorts512> {
        @Override
        public OFOxmBsnInPorts512 readFrom(ChannelBuffer bb) throws OFParseError {
            // fixed value property typeLen == 0x32640L
            int typeLen = bb.readInt();
            if(typeLen != 0x32640)
                throw new OFParseError("Wrong typeLen: Expected=0x32640L(0x32640L), got="+typeLen);
            OFBitMask512 value = OFBitMask512.read64Bytes(bb);

            OFOxmBsnInPorts512Ver13 oxmBsnInPorts512Ver13 = new OFOxmBsnInPorts512Ver13(
                    value
                    );
            if(logger.isTraceEnabled())
                logger.trace("readFrom - read={}", oxmBsnInPorts512Ver13);
            return oxmBsnInPorts512Ver13;
        }
    }

    public void putTo(PrimitiveSink sink) {
        FUNNEL.funnel(this, sink);
    }

    final static OFOxmBsnInPorts512Ver13Funnel FUNNEL = new OFOxmBsnInPorts512Ver13Funnel();
    static class OFOxmBsnInPorts512Ver13Funnel implements Funnel<OFOxmBsnInPorts512Ver13> {
        private static final long serialVersionUID = 1L;
        @Override
        public void funnel(OFOxmBsnInPorts512Ver13 message, PrimitiveSink sink) {
            // fixed value property typeLen = 0x32640L
            sink.putInt(0x32640);
            message.value.putTo(sink);
        }
    }


    public void writeTo(ChannelBuffer bb) {
        WRITER.write(bb, this);
    }

    final static Writer WRITER = new Writer();
    static class Writer implements OFMessageWriter<OFOxmBsnInPorts512Ver13> {
        @Override
        public void write(ChannelBuffer bb, OFOxmBsnInPorts512Ver13 message) {
            // fixed value property typeLen = 0x32640L
            bb.writeInt(0x32640);
            message.value.write64Bytes(bb);


        }
    }

    @Override
    public String toString() {
        StringBuilder b = new StringBuilder("OFOxmBsnInPorts512Ver13(");
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
        OFOxmBsnInPorts512Ver13 other = (OFOxmBsnInPorts512Ver13) obj;

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
