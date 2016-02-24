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
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.jboss.netty.buffer.ChannelBuffer;
import com.google.common.hash.PrimitiveSink;
import com.google.common.hash.Funnel;

class OFActionNiciraSetNsiVer12 implements OFActionNiciraSetNsi {
    private static final Logger logger = LoggerFactory.getLogger(OFActionNiciraSetNsiVer12.class);
    // version: 1.2
    final static byte WIRE_VERSION = 3;
    final static int LENGTH = 16;

        private final static short DEFAULT_NSI = (short) 0x0;

    // OF message fields
    private final short nsi;
//
    // Immutable default instance
    final static OFActionNiciraSetNsiVer12 DEFAULT = new OFActionNiciraSetNsiVer12(
        DEFAULT_NSI
    );

    // package private constructor - used by readers, builders, and factory
    OFActionNiciraSetNsiVer12(short nsi) {
        this.nsi = nsi;
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
        return 0x21;
    }

    @Override
    public short getNsi() {
        return nsi;
    }

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_12;
    }



    public OFActionNiciraSetNsi.Builder createBuilder() {
        return new BuilderWithParent(this);
    }

    static class BuilderWithParent implements OFActionNiciraSetNsi.Builder {
        final OFActionNiciraSetNsiVer12 parentMessage;

        // OF message fields
        private boolean nsiSet;
        private short nsi;

        BuilderWithParent(OFActionNiciraSetNsiVer12 parentMessage) {
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
        return 0x21;
    }

    @Override
    public short getNsi() {
        return nsi;
    }

    @Override
    public OFActionNiciraSetNsi.Builder setNsi(short nsi) {
        this.nsi = nsi;
        this.nsiSet = true;
        return this;
    }
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_12;
    }



        @Override
        public OFActionNiciraSetNsi build() {
                short nsi = this.nsiSet ? this.nsi : parentMessage.nsi;

                //
                return new OFActionNiciraSetNsiVer12(
                    nsi
                );
        }

    }

    static class Builder implements OFActionNiciraSetNsi.Builder {
        // OF message fields
        private boolean nsiSet;
        private short nsi;

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
        return 0x21;
    }

    @Override
    public short getNsi() {
        return nsi;
    }

    @Override
    public OFActionNiciraSetNsi.Builder setNsi(short nsi) {
        this.nsi = nsi;
        this.nsiSet = true;
        return this;
    }
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_12;
    }

//
        @Override
        public OFActionNiciraSetNsi build() {
            short nsi = this.nsiSet ? this.nsi : DEFAULT_NSI;


            return new OFActionNiciraSetNsiVer12(
                    nsi
                );
        }

    }


    final static Reader READER = new Reader();
    static class Reader implements OFMessageReader<OFActionNiciraSetNsi> {
        @Override
        public OFActionNiciraSetNsi readFrom(ChannelBuffer bb) throws OFParseError {
            int start = bb.readerIndex();
            // fixed value property type == 65535
            short type = bb.readShort();
            if(type != (short) 0xffff)
                throw new OFParseError("Wrong type: Expected=OFActionType.EXPERIMENTER(65535), got="+type);
            int length = U16.f(bb.readShort());
            if(length != 16)
                throw new OFParseError("Wrong length: Expected=16(16), got="+length);
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
            // fixed value property subtype == 0x21
            short subtype = bb.readShort();
            if(subtype != (short) 0x21)
                throw new OFParseError("Wrong subtype: Expected=0x21(0x21), got="+subtype);
            short nsi = U8.f(bb.readByte());
            // pad: 5 bytes
            bb.skipBytes(5);

            OFActionNiciraSetNsiVer12 actionNiciraSetNsiVer12 = new OFActionNiciraSetNsiVer12(
                    nsi
                    );
            if(logger.isTraceEnabled())
                logger.trace("readFrom - read={}", actionNiciraSetNsiVer12);
            return actionNiciraSetNsiVer12;
        }
    }

    public void putTo(PrimitiveSink sink) {
        FUNNEL.funnel(this, sink);
    }

    final static OFActionNiciraSetNsiVer12Funnel FUNNEL = new OFActionNiciraSetNsiVer12Funnel();
    static class OFActionNiciraSetNsiVer12Funnel implements Funnel<OFActionNiciraSetNsiVer12> {
        private static final long serialVersionUID = 1L;
        @Override
        public void funnel(OFActionNiciraSetNsiVer12 message, PrimitiveSink sink) {
            // fixed value property type = 65535
            sink.putShort((short) 0xffff);
            // fixed value property length = 16
            sink.putShort((short) 0x10);
            // fixed value property experimenter = 0x2320L
            sink.putInt(0x2320);
            // fixed value property subtype = 0x21
            sink.putShort((short) 0x21);
            sink.putShort(message.nsi);
            // skip pad (5 bytes)
        }
    }


    public void writeTo(ChannelBuffer bb) {
        WRITER.write(bb, this);
    }

    final static Writer WRITER = new Writer();
    static class Writer implements OFMessageWriter<OFActionNiciraSetNsiVer12> {
        @Override
        public void write(ChannelBuffer bb, OFActionNiciraSetNsiVer12 message) {
            // fixed value property type = 65535
            bb.writeShort((short) 0xffff);
            // fixed value property length = 16
            bb.writeShort((short) 0x10);
            // fixed value property experimenter = 0x2320L
            bb.writeInt(0x2320);
            // fixed value property subtype = 0x21
            bb.writeShort((short) 0x21);
            bb.writeByte(U8.t(message.nsi));
            // pad: 5 bytes
            bb.writeZero(5);


        }
    }

    @Override
    public String toString() {
        StringBuilder b = new StringBuilder("OFActionNiciraSetNsiVer12(");
        b.append("nsi=").append(nsi);
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
        OFActionNiciraSetNsiVer12 other = (OFActionNiciraSetNsiVer12) obj;

        if( nsi != other.nsi)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;

        result = prime * result + nsi;
        return result;
    }

}
