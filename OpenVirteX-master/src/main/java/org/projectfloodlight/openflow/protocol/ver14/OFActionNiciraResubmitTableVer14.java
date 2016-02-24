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

class OFActionNiciraResubmitTableVer14 implements OFActionNiciraResubmitTable {
    private static final Logger logger = LoggerFactory.getLogger(OFActionNiciraResubmitTableVer14.class);
    // version: 1.4
    final static byte WIRE_VERSION = 5;
    final static int LENGTH = 16;

        private final static int DEFAULT_IN_PORT = 0x0;
        private final static short DEFAULT_TABLE = (short) 0x0;

    // OF message fields
    private final int inPort;
    private final short table;
//
    // Immutable default instance
    final static OFActionNiciraResubmitTableVer14 DEFAULT = new OFActionNiciraResubmitTableVer14(
        DEFAULT_IN_PORT, DEFAULT_TABLE
    );

    // package private constructor - used by readers, builders, and factory
    OFActionNiciraResubmitTableVer14(int inPort, short table) {
        this.inPort = inPort;
        this.table = table;
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
        return 0xe;
    }

    @Override
    public int getInPort() {
        return inPort;
    }

    @Override
    public short getTable() {
        return table;
    }

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_14;
    }



    public OFActionNiciraResubmitTable.Builder createBuilder() {
        return new BuilderWithParent(this);
    }

    static class BuilderWithParent implements OFActionNiciraResubmitTable.Builder {
        final OFActionNiciraResubmitTableVer14 parentMessage;

        // OF message fields
        private boolean inPortSet;
        private int inPort;
        private boolean tableSet;
        private short table;

        BuilderWithParent(OFActionNiciraResubmitTableVer14 parentMessage) {
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
        return 0xe;
    }

    @Override
    public int getInPort() {
        return inPort;
    }

    @Override
    public OFActionNiciraResubmitTable.Builder setInPort(int inPort) {
        this.inPort = inPort;
        this.inPortSet = true;
        return this;
    }
    @Override
    public short getTable() {
        return table;
    }

    @Override
    public OFActionNiciraResubmitTable.Builder setTable(short table) {
        this.table = table;
        this.tableSet = true;
        return this;
    }
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_14;
    }



        @Override
        public OFActionNiciraResubmitTable build() {
                int inPort = this.inPortSet ? this.inPort : parentMessage.inPort;
                short table = this.tableSet ? this.table : parentMessage.table;

                //
                return new OFActionNiciraResubmitTableVer14(
                    inPort,
                    table
                );
        }

    }

    static class Builder implements OFActionNiciraResubmitTable.Builder {
        // OF message fields
        private boolean inPortSet;
        private int inPort;
        private boolean tableSet;
        private short table;

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
        return 0xe;
    }

    @Override
    public int getInPort() {
        return inPort;
    }

    @Override
    public OFActionNiciraResubmitTable.Builder setInPort(int inPort) {
        this.inPort = inPort;
        this.inPortSet = true;
        return this;
    }
    @Override
    public short getTable() {
        return table;
    }

    @Override
    public OFActionNiciraResubmitTable.Builder setTable(short table) {
        this.table = table;
        this.tableSet = true;
        return this;
    }
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_14;
    }

//
        @Override
        public OFActionNiciraResubmitTable build() {
            int inPort = this.inPortSet ? this.inPort : DEFAULT_IN_PORT;
            short table = this.tableSet ? this.table : DEFAULT_TABLE;


            return new OFActionNiciraResubmitTableVer14(
                    inPort,
                    table
                );
        }

    }


    final static Reader READER = new Reader();
    static class Reader implements OFMessageReader<OFActionNiciraResubmitTable> {
        @Override
        public OFActionNiciraResubmitTable readFrom(ChannelBuffer bb) throws OFParseError {
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
            // fixed value property subtype == 0xe
            short subtype = bb.readShort();
            if(subtype != (short) 0xe)
                throw new OFParseError("Wrong subtype: Expected=0xe(0xe), got="+subtype);
            int inPort = U16.f(bb.readShort());
            short table = U8.f(bb.readByte());
            // pad: 3 bytes
            bb.skipBytes(3);

            OFActionNiciraResubmitTableVer14 actionNiciraResubmitTableVer14 = new OFActionNiciraResubmitTableVer14(
                    inPort,
                      table
                    );
            if(logger.isTraceEnabled())
                logger.trace("readFrom - read={}", actionNiciraResubmitTableVer14);
            return actionNiciraResubmitTableVer14;
        }
    }

    public void putTo(PrimitiveSink sink) {
        FUNNEL.funnel(this, sink);
    }

    final static OFActionNiciraResubmitTableVer14Funnel FUNNEL = new OFActionNiciraResubmitTableVer14Funnel();
    static class OFActionNiciraResubmitTableVer14Funnel implements Funnel<OFActionNiciraResubmitTableVer14> {
        private static final long serialVersionUID = 1L;
        @Override
        public void funnel(OFActionNiciraResubmitTableVer14 message, PrimitiveSink sink) {
            // fixed value property type = 65535
            sink.putShort((short) 0xffff);
            // fixed value property length = 16
            sink.putShort((short) 0x10);
            // fixed value property experimenter = 0x2320L
            sink.putInt(0x2320);
            // fixed value property subtype = 0xe
            sink.putShort((short) 0xe);
            sink.putInt(message.inPort);
            sink.putShort(message.table);
            // skip pad (3 bytes)
        }
    }


    public void writeTo(ChannelBuffer bb) {
        WRITER.write(bb, this);
    }

    final static Writer WRITER = new Writer();
    static class Writer implements OFMessageWriter<OFActionNiciraResubmitTableVer14> {
        @Override
        public void write(ChannelBuffer bb, OFActionNiciraResubmitTableVer14 message) {
            // fixed value property type = 65535
            bb.writeShort((short) 0xffff);
            // fixed value property length = 16
            bb.writeShort((short) 0x10);
            // fixed value property experimenter = 0x2320L
            bb.writeInt(0x2320);
            // fixed value property subtype = 0xe
            bb.writeShort((short) 0xe);
            bb.writeShort(U16.t(message.inPort));
            bb.writeByte(U8.t(message.table));
            // pad: 3 bytes
            bb.writeZero(3);


        }
    }

    @Override
    public String toString() {
        StringBuilder b = new StringBuilder("OFActionNiciraResubmitTableVer14(");
        b.append("inPort=").append(inPort);
        b.append(", ");
        b.append("table=").append(table);
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
        OFActionNiciraResubmitTableVer14 other = (OFActionNiciraResubmitTableVer14) obj;

        if( inPort != other.inPort)
            return false;
        if( table != other.table)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;

        result = prime * result + inPort;
        result = prime * result + table;
        return result;
    }

}
