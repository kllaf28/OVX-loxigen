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

class OFCalientPortDescStatsEntryVer13 implements OFCalientPortDescStatsEntry {
    private static final Logger logger = LoggerFactory.getLogger(OFCalientPortDescStatsEntryVer13.class);
    // version: 1.3
    final static byte WIRE_VERSION = 4;
    final static int MINIMUM_LENGTH = 40;

        private final static OFPort DEFAULT_PORT_NO = OFPort.ANY;
        private final static MacAddress DEFAULT_HW_ADDR = MacAddress.NONE;
        private final static String DEFAULT_NAME = "";
        private final static long DEFAULT_CONFIG = 0x0L;
        private final static long DEFAULT_STATE = 0x0L;
        private final static List<OFCalientPortDescProp> DEFAULT_PROPERTIES = ImmutableList.<OFCalientPortDescProp>of();

    // OF message fields
    private final OFPort portNo;
    private final MacAddress hwAddr;
    private final String name;
    private final long config;
    private final long state;
    private final List<OFCalientPortDescProp> properties;
//
    // Immutable default instance
    final static OFCalientPortDescStatsEntryVer13 DEFAULT = new OFCalientPortDescStatsEntryVer13(
        DEFAULT_PORT_NO, DEFAULT_HW_ADDR, DEFAULT_NAME, DEFAULT_CONFIG, DEFAULT_STATE, DEFAULT_PROPERTIES
    );

    // package private constructor - used by readers, builders, and factory
    OFCalientPortDescStatsEntryVer13(OFPort portNo, MacAddress hwAddr, String name, long config, long state, List<OFCalientPortDescProp> properties) {
        if(portNo == null) {
            throw new NullPointerException("OFCalientPortDescStatsEntryVer13: property portNo cannot be null");
        }
        if(hwAddr == null) {
            throw new NullPointerException("OFCalientPortDescStatsEntryVer13: property hwAddr cannot be null");
        }
        if(name == null) {
            throw new NullPointerException("OFCalientPortDescStatsEntryVer13: property name cannot be null");
        }
        if(properties == null) {
            throw new NullPointerException("OFCalientPortDescStatsEntryVer13: property properties cannot be null");
        }
        this.portNo = portNo;
        this.hwAddr = hwAddr;
        this.name = name;
        this.config = config;
        this.state = state;
        this.properties = properties;
    }

    // Accessors for OF message fields
    @Override
    public OFPort getPortNo() {
        return portNo;
    }

    @Override
    public MacAddress getHwAddr() {
        return hwAddr;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public long getConfig() {
        return config;
    }

    @Override
    public long getState() {
        return state;
    }

    @Override
    public List<OFCalientPortDescProp> getProperties() {
        return properties;
    }

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_13;
    }



    public OFCalientPortDescStatsEntry.Builder createBuilder() {
        return new BuilderWithParent(this);
    }

    static class BuilderWithParent implements OFCalientPortDescStatsEntry.Builder {
        final OFCalientPortDescStatsEntryVer13 parentMessage;

        // OF message fields
        private boolean portNoSet;
        private OFPort portNo;
        private boolean hwAddrSet;
        private MacAddress hwAddr;
        private boolean nameSet;
        private String name;
        private boolean configSet;
        private long config;
        private boolean stateSet;
        private long state;
        private boolean propertiesSet;
        private List<OFCalientPortDescProp> properties;

        BuilderWithParent(OFCalientPortDescStatsEntryVer13 parentMessage) {
            this.parentMessage = parentMessage;
        }

    @Override
    public OFPort getPortNo() {
        return portNo;
    }

    @Override
    public OFCalientPortDescStatsEntry.Builder setPortNo(OFPort portNo) {
        this.portNo = portNo;
        this.portNoSet = true;
        return this;
    }
    @Override
    public MacAddress getHwAddr() {
        return hwAddr;
    }

    @Override
    public OFCalientPortDescStatsEntry.Builder setHwAddr(MacAddress hwAddr) {
        this.hwAddr = hwAddr;
        this.hwAddrSet = true;
        return this;
    }
    @Override
    public String getName() {
        return name;
    }

    @Override
    public OFCalientPortDescStatsEntry.Builder setName(String name) {
        this.name = name;
        this.nameSet = true;
        return this;
    }
    @Override
    public long getConfig() {
        return config;
    }

    @Override
    public OFCalientPortDescStatsEntry.Builder setConfig(long config) {
        this.config = config;
        this.configSet = true;
        return this;
    }
    @Override
    public long getState() {
        return state;
    }

    @Override
    public OFCalientPortDescStatsEntry.Builder setState(long state) {
        this.state = state;
        this.stateSet = true;
        return this;
    }
    @Override
    public List<OFCalientPortDescProp> getProperties() {
        return properties;
    }

    @Override
    public OFCalientPortDescStatsEntry.Builder setProperties(List<OFCalientPortDescProp> properties) {
        this.properties = properties;
        this.propertiesSet = true;
        return this;
    }
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_13;
    }



        @Override
        public OFCalientPortDescStatsEntry build() {
                OFPort portNo = this.portNoSet ? this.portNo : parentMessage.portNo;
                if(portNo == null)
                    throw new NullPointerException("Property portNo must not be null");
                MacAddress hwAddr = this.hwAddrSet ? this.hwAddr : parentMessage.hwAddr;
                if(hwAddr == null)
                    throw new NullPointerException("Property hwAddr must not be null");
                String name = this.nameSet ? this.name : parentMessage.name;
                if(name == null)
                    throw new NullPointerException("Property name must not be null");
                long config = this.configSet ? this.config : parentMessage.config;
                long state = this.stateSet ? this.state : parentMessage.state;
                List<OFCalientPortDescProp> properties = this.propertiesSet ? this.properties : parentMessage.properties;
                if(properties == null)
                    throw new NullPointerException("Property properties must not be null");

                //
                return new OFCalientPortDescStatsEntryVer13(
                    portNo,
                    hwAddr,
                    name,
                    config,
                    state,
                    properties
                );
        }

    }

    static class Builder implements OFCalientPortDescStatsEntry.Builder {
        // OF message fields
        private boolean portNoSet;
        private OFPort portNo;
        private boolean hwAddrSet;
        private MacAddress hwAddr;
        private boolean nameSet;
        private String name;
        private boolean configSet;
        private long config;
        private boolean stateSet;
        private long state;
        private boolean propertiesSet;
        private List<OFCalientPortDescProp> properties;

    @Override
    public OFPort getPortNo() {
        return portNo;
    }

    @Override
    public OFCalientPortDescStatsEntry.Builder setPortNo(OFPort portNo) {
        this.portNo = portNo;
        this.portNoSet = true;
        return this;
    }
    @Override
    public MacAddress getHwAddr() {
        return hwAddr;
    }

    @Override
    public OFCalientPortDescStatsEntry.Builder setHwAddr(MacAddress hwAddr) {
        this.hwAddr = hwAddr;
        this.hwAddrSet = true;
        return this;
    }
    @Override
    public String getName() {
        return name;
    }

    @Override
    public OFCalientPortDescStatsEntry.Builder setName(String name) {
        this.name = name;
        this.nameSet = true;
        return this;
    }
    @Override
    public long getConfig() {
        return config;
    }

    @Override
    public OFCalientPortDescStatsEntry.Builder setConfig(long config) {
        this.config = config;
        this.configSet = true;
        return this;
    }
    @Override
    public long getState() {
        return state;
    }

    @Override
    public OFCalientPortDescStatsEntry.Builder setState(long state) {
        this.state = state;
        this.stateSet = true;
        return this;
    }
    @Override
    public List<OFCalientPortDescProp> getProperties() {
        return properties;
    }

    @Override
    public OFCalientPortDescStatsEntry.Builder setProperties(List<OFCalientPortDescProp> properties) {
        this.properties = properties;
        this.propertiesSet = true;
        return this;
    }
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_13;
    }

//
        @Override
        public OFCalientPortDescStatsEntry build() {
            OFPort portNo = this.portNoSet ? this.portNo : DEFAULT_PORT_NO;
            if(portNo == null)
                throw new NullPointerException("Property portNo must not be null");
            MacAddress hwAddr = this.hwAddrSet ? this.hwAddr : DEFAULT_HW_ADDR;
            if(hwAddr == null)
                throw new NullPointerException("Property hwAddr must not be null");
            String name = this.nameSet ? this.name : DEFAULT_NAME;
            if(name == null)
                throw new NullPointerException("Property name must not be null");
            long config = this.configSet ? this.config : DEFAULT_CONFIG;
            long state = this.stateSet ? this.state : DEFAULT_STATE;
            List<OFCalientPortDescProp> properties = this.propertiesSet ? this.properties : DEFAULT_PROPERTIES;
            if(properties == null)
                throw new NullPointerException("Property properties must not be null");


            return new OFCalientPortDescStatsEntryVer13(
                    portNo,
                    hwAddr,
                    name,
                    config,
                    state,
                    properties
                );
        }

    }


    final static Reader READER = new Reader();
    static class Reader implements OFMessageReader<OFCalientPortDescStatsEntry> {
        @Override
        public OFCalientPortDescStatsEntry readFrom(ChannelBuffer bb) throws OFParseError {
            int start = bb.readerIndex();
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
            // pad: 2 bytes
            bb.skipBytes(2);
            OFPort portNo = OFPort.read4Bytes(bb);
            MacAddress hwAddr = MacAddress.read6Bytes(bb);
            // pad: 2 bytes
            bb.skipBytes(2);
            String name = ChannelUtils.readFixedLengthString(bb, 16);
            long config = U32.f(bb.readInt());
            long state = U32.f(bb.readInt());
            List<OFCalientPortDescProp> properties = ChannelUtils.readList(bb, length - (bb.readerIndex() - start), OFCalientPortDescPropVer13.READER);

            OFCalientPortDescStatsEntryVer13 calientPortDescStatsEntryVer13 = new OFCalientPortDescStatsEntryVer13(
                    portNo,
                      hwAddr,
                      name,
                      config,
                      state,
                      properties
                    );
            if(logger.isTraceEnabled())
                logger.trace("readFrom - read={}", calientPortDescStatsEntryVer13);
            return calientPortDescStatsEntryVer13;
        }
    }

    public void putTo(PrimitiveSink sink) {
        FUNNEL.funnel(this, sink);
    }

    final static OFCalientPortDescStatsEntryVer13Funnel FUNNEL = new OFCalientPortDescStatsEntryVer13Funnel();
    static class OFCalientPortDescStatsEntryVer13Funnel implements Funnel<OFCalientPortDescStatsEntryVer13> {
        private static final long serialVersionUID = 1L;
        @Override
        public void funnel(OFCalientPortDescStatsEntryVer13 message, PrimitiveSink sink) {
            // FIXME: skip funnel of length
            // skip pad (2 bytes)
            message.portNo.putTo(sink);
            message.hwAddr.putTo(sink);
            // skip pad (2 bytes)
            sink.putUnencodedChars(message.name);
            sink.putLong(message.config);
            sink.putLong(message.state);
            FunnelUtils.putList(message.properties, sink);
        }
    }


    public void writeTo(ChannelBuffer bb) {
        WRITER.write(bb, this);
    }

    final static Writer WRITER = new Writer();
    static class Writer implements OFMessageWriter<OFCalientPortDescStatsEntryVer13> {
        @Override
        public void write(ChannelBuffer bb, OFCalientPortDescStatsEntryVer13 message) {
            int startIndex = bb.writerIndex();
            // length is length of variable message, will be updated at the end
            int lengthIndex = bb.writerIndex();
            bb.writeShort(U16.t(0));

            // pad: 2 bytes
            bb.writeZero(2);
            message.portNo.write4Bytes(bb);
            message.hwAddr.write6Bytes(bb);
            // pad: 2 bytes
            bb.writeZero(2);
            ChannelUtils.writeFixedLengthString(bb, message.name, 16);
            bb.writeInt(U32.t(message.config));
            bb.writeInt(U32.t(message.state));
            ChannelUtils.writeList(bb, message.properties);

            // update length field
            int length = bb.writerIndex() - startIndex;
            bb.setShort(lengthIndex, length);

        }
    }

    @Override
    public String toString() {
        StringBuilder b = new StringBuilder("OFCalientPortDescStatsEntryVer13(");
        b.append("portNo=").append(portNo);
        b.append(", ");
        b.append("hwAddr=").append(hwAddr);
        b.append(", ");
        b.append("name=").append(name);
        b.append(", ");
        b.append("config=").append(config);
        b.append(", ");
        b.append("state=").append(state);
        b.append(", ");
        b.append("properties=").append(properties);
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
        OFCalientPortDescStatsEntryVer13 other = (OFCalientPortDescStatsEntryVer13) obj;

        if (portNo == null) {
            if (other.portNo != null)
                return false;
        } else if (!portNo.equals(other.portNo))
            return false;
        if (hwAddr == null) {
            if (other.hwAddr != null)
                return false;
        } else if (!hwAddr.equals(other.hwAddr))
            return false;
        if (name == null) {
            if (other.name != null)
                return false;
        } else if (!name.equals(other.name))
            return false;
        if( config != other.config)
            return false;
        if( state != other.state)
            return false;
        if (properties == null) {
            if (other.properties != null)
                return false;
        } else if (!properties.equals(other.properties))
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;

        result = prime * result + ((portNo == null) ? 0 : portNo.hashCode());
        result = prime * result + ((hwAddr == null) ? 0 : hwAddr.hashCode());
        result = prime * result + ((name == null) ? 0 : name.hashCode());
        result = prime *  (int) (config ^ (config >>> 32));
        result = prime *  (int) (state ^ (state >>> 32));
        result = prime * result + ((properties == null) ? 0 : properties.hashCode());
        return result;
    }

}
