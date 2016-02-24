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
import com.google.common.collect.ImmutableSet;
import java.util.List;
import com.google.common.collect.ImmutableList;
import org.jboss.netty.buffer.ChannelBuffer;
import com.google.common.hash.PrimitiveSink;
import com.google.common.hash.Funnel;

class OFPortOpticalVer13 implements OFPortOptical {
    private static final Logger logger = LoggerFactory.getLogger(OFPortOpticalVer13.class);
    // version: 1.3
    final static byte WIRE_VERSION = 4;
    final static int MINIMUM_LENGTH = 40;

        private final static OFPort DEFAULT_PORT_NO = OFPort.ANY;
        private final static MacAddress DEFAULT_HW_ADDR = MacAddress.NONE;
        private final static String DEFAULT_NAME = "";
        private final static Set<OFPortConfig> DEFAULT_CONFIG = ImmutableSet.<OFPortConfig>of();
        private final static Set<OFPortState> DEFAULT_STATE = ImmutableSet.<OFPortState>of();
        private final static List<OFPortDescPropOpticalTransport> DEFAULT_DESC = ImmutableList.<OFPortDescPropOpticalTransport>of();

    // OF message fields
    private final OFPort portNo;
    private final MacAddress hwAddr;
    private final String name;
    private final Set<OFPortConfig> config;
    private final Set<OFPortState> state;
    private final List<OFPortDescPropOpticalTransport> desc;
//
    // Immutable default instance
    final static OFPortOpticalVer13 DEFAULT = new OFPortOpticalVer13(
        DEFAULT_PORT_NO, DEFAULT_HW_ADDR, DEFAULT_NAME, DEFAULT_CONFIG, DEFAULT_STATE, DEFAULT_DESC
    );

    // package private constructor - used by readers, builders, and factory
    OFPortOpticalVer13(OFPort portNo, MacAddress hwAddr, String name, Set<OFPortConfig> config, Set<OFPortState> state, List<OFPortDescPropOpticalTransport> desc) {
        if(portNo == null) {
            throw new NullPointerException("OFPortOpticalVer13: property portNo cannot be null");
        }
        if(hwAddr == null) {
            throw new NullPointerException("OFPortOpticalVer13: property hwAddr cannot be null");
        }
        if(name == null) {
            throw new NullPointerException("OFPortOpticalVer13: property name cannot be null");
        }
        if(config == null) {
            throw new NullPointerException("OFPortOpticalVer13: property config cannot be null");
        }
        if(state == null) {
            throw new NullPointerException("OFPortOpticalVer13: property state cannot be null");
        }
        if(desc == null) {
            throw new NullPointerException("OFPortOpticalVer13: property desc cannot be null");
        }
        this.portNo = portNo;
        this.hwAddr = hwAddr;
        this.name = name;
        this.config = config;
        this.state = state;
        this.desc = desc;
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
    public Set<OFPortConfig> getConfig() {
        return config;
    }

    @Override
    public Set<OFPortState> getState() {
        return state;
    }

    @Override
    public List<OFPortDescPropOpticalTransport> getDesc() {
        return desc;
    }

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_13;
    }



    public OFPortOptical.Builder createBuilder() {
        return new BuilderWithParent(this);
    }

    static class BuilderWithParent implements OFPortOptical.Builder {
        final OFPortOpticalVer13 parentMessage;

        // OF message fields
        private boolean portNoSet;
        private OFPort portNo;
        private boolean hwAddrSet;
        private MacAddress hwAddr;
        private boolean nameSet;
        private String name;
        private boolean configSet;
        private Set<OFPortConfig> config;
        private boolean stateSet;
        private Set<OFPortState> state;
        private boolean descSet;
        private List<OFPortDescPropOpticalTransport> desc;

        BuilderWithParent(OFPortOpticalVer13 parentMessage) {
            this.parentMessage = parentMessage;
        }

    @Override
    public OFPort getPortNo() {
        return portNo;
    }

    @Override
    public OFPortOptical.Builder setPortNo(OFPort portNo) {
        this.portNo = portNo;
        this.portNoSet = true;
        return this;
    }
    @Override
    public MacAddress getHwAddr() {
        return hwAddr;
    }

    @Override
    public OFPortOptical.Builder setHwAddr(MacAddress hwAddr) {
        this.hwAddr = hwAddr;
        this.hwAddrSet = true;
        return this;
    }
    @Override
    public String getName() {
        return name;
    }

    @Override
    public OFPortOptical.Builder setName(String name) {
        this.name = name;
        this.nameSet = true;
        return this;
    }
    @Override
    public Set<OFPortConfig> getConfig() {
        return config;
    }

    @Override
    public OFPortOptical.Builder setConfig(Set<OFPortConfig> config) {
        this.config = config;
        this.configSet = true;
        return this;
    }
    @Override
    public Set<OFPortState> getState() {
        return state;
    }

    @Override
    public OFPortOptical.Builder setState(Set<OFPortState> state) {
        this.state = state;
        this.stateSet = true;
        return this;
    }
    @Override
    public List<OFPortDescPropOpticalTransport> getDesc() {
        return desc;
    }

    @Override
    public OFPortOptical.Builder setDesc(List<OFPortDescPropOpticalTransport> desc) {
        this.desc = desc;
        this.descSet = true;
        return this;
    }
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_13;
    }



        @Override
        public OFPortOptical build() {
                OFPort portNo = this.portNoSet ? this.portNo : parentMessage.portNo;
                if(portNo == null)
                    throw new NullPointerException("Property portNo must not be null");
                MacAddress hwAddr = this.hwAddrSet ? this.hwAddr : parentMessage.hwAddr;
                if(hwAddr == null)
                    throw new NullPointerException("Property hwAddr must not be null");
                String name = this.nameSet ? this.name : parentMessage.name;
                if(name == null)
                    throw new NullPointerException("Property name must not be null");
                Set<OFPortConfig> config = this.configSet ? this.config : parentMessage.config;
                if(config == null)
                    throw new NullPointerException("Property config must not be null");
                Set<OFPortState> state = this.stateSet ? this.state : parentMessage.state;
                if(state == null)
                    throw new NullPointerException("Property state must not be null");
                List<OFPortDescPropOpticalTransport> desc = this.descSet ? this.desc : parentMessage.desc;
                if(desc == null)
                    throw new NullPointerException("Property desc must not be null");

                //
                return new OFPortOpticalVer13(
                    portNo,
                    hwAddr,
                    name,
                    config,
                    state,
                    desc
                );
        }

    }

    static class Builder implements OFPortOptical.Builder {
        // OF message fields
        private boolean portNoSet;
        private OFPort portNo;
        private boolean hwAddrSet;
        private MacAddress hwAddr;
        private boolean nameSet;
        private String name;
        private boolean configSet;
        private Set<OFPortConfig> config;
        private boolean stateSet;
        private Set<OFPortState> state;
        private boolean descSet;
        private List<OFPortDescPropOpticalTransport> desc;

    @Override
    public OFPort getPortNo() {
        return portNo;
    }

    @Override
    public OFPortOptical.Builder setPortNo(OFPort portNo) {
        this.portNo = portNo;
        this.portNoSet = true;
        return this;
    }
    @Override
    public MacAddress getHwAddr() {
        return hwAddr;
    }

    @Override
    public OFPortOptical.Builder setHwAddr(MacAddress hwAddr) {
        this.hwAddr = hwAddr;
        this.hwAddrSet = true;
        return this;
    }
    @Override
    public String getName() {
        return name;
    }

    @Override
    public OFPortOptical.Builder setName(String name) {
        this.name = name;
        this.nameSet = true;
        return this;
    }
    @Override
    public Set<OFPortConfig> getConfig() {
        return config;
    }

    @Override
    public OFPortOptical.Builder setConfig(Set<OFPortConfig> config) {
        this.config = config;
        this.configSet = true;
        return this;
    }
    @Override
    public Set<OFPortState> getState() {
        return state;
    }

    @Override
    public OFPortOptical.Builder setState(Set<OFPortState> state) {
        this.state = state;
        this.stateSet = true;
        return this;
    }
    @Override
    public List<OFPortDescPropOpticalTransport> getDesc() {
        return desc;
    }

    @Override
    public OFPortOptical.Builder setDesc(List<OFPortDescPropOpticalTransport> desc) {
        this.desc = desc;
        this.descSet = true;
        return this;
    }
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_13;
    }

//
        @Override
        public OFPortOptical build() {
            OFPort portNo = this.portNoSet ? this.portNo : DEFAULT_PORT_NO;
            if(portNo == null)
                throw new NullPointerException("Property portNo must not be null");
            MacAddress hwAddr = this.hwAddrSet ? this.hwAddr : DEFAULT_HW_ADDR;
            if(hwAddr == null)
                throw new NullPointerException("Property hwAddr must not be null");
            String name = this.nameSet ? this.name : DEFAULT_NAME;
            if(name == null)
                throw new NullPointerException("Property name must not be null");
            Set<OFPortConfig> config = this.configSet ? this.config : DEFAULT_CONFIG;
            if(config == null)
                throw new NullPointerException("Property config must not be null");
            Set<OFPortState> state = this.stateSet ? this.state : DEFAULT_STATE;
            if(state == null)
                throw new NullPointerException("Property state must not be null");
            List<OFPortDescPropOpticalTransport> desc = this.descSet ? this.desc : DEFAULT_DESC;
            if(desc == null)
                throw new NullPointerException("Property desc must not be null");


            return new OFPortOpticalVer13(
                    portNo,
                    hwAddr,
                    name,
                    config,
                    state,
                    desc
                );
        }

    }


    final static Reader READER = new Reader();
    static class Reader implements OFMessageReader<OFPortOptical> {
        @Override
        public OFPortOptical readFrom(ChannelBuffer bb) throws OFParseError {
            int start = bb.readerIndex();
            OFPort portNo = OFPort.read4Bytes(bb);
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
            MacAddress hwAddr = MacAddress.read6Bytes(bb);
            // pad: 2 bytes
            bb.skipBytes(2);
            String name = ChannelUtils.readFixedLengthString(bb, 16);
            Set<OFPortConfig> config = OFPortConfigSerializerVer13.readFrom(bb);
            Set<OFPortState> state = OFPortStateSerializerVer13.readFrom(bb);
            List<OFPortDescPropOpticalTransport> desc = ChannelUtils.readList(bb, length - (bb.readerIndex() - start), OFPortDescPropOpticalTransportVer13.READER);

            OFPortOpticalVer13 portOpticalVer13 = new OFPortOpticalVer13(
                    portNo,
                      hwAddr,
                      name,
                      config,
                      state,
                      desc
                    );
            if(logger.isTraceEnabled())
                logger.trace("readFrom - read={}", portOpticalVer13);
            return portOpticalVer13;
        }
    }

    public void putTo(PrimitiveSink sink) {
        FUNNEL.funnel(this, sink);
    }

    final static OFPortOpticalVer13Funnel FUNNEL = new OFPortOpticalVer13Funnel();
    static class OFPortOpticalVer13Funnel implements Funnel<OFPortOpticalVer13> {
        private static final long serialVersionUID = 1L;
        @Override
        public void funnel(OFPortOpticalVer13 message, PrimitiveSink sink) {
            message.portNo.putTo(sink);
            // FIXME: skip funnel of length
            // skip pad (2 bytes)
            message.hwAddr.putTo(sink);
            // skip pad (2 bytes)
            sink.putUnencodedChars(message.name);
            OFPortConfigSerializerVer13.putTo(message.config, sink);
            OFPortStateSerializerVer13.putTo(message.state, sink);
            FunnelUtils.putList(message.desc, sink);
        }
    }


    public void writeTo(ChannelBuffer bb) {
        WRITER.write(bb, this);
    }

    final static Writer WRITER = new Writer();
    static class Writer implements OFMessageWriter<OFPortOpticalVer13> {
        @Override
        public void write(ChannelBuffer bb, OFPortOpticalVer13 message) {
            int startIndex = bb.writerIndex();
            message.portNo.write4Bytes(bb);
            // length is length of variable message, will be updated at the end
            int lengthIndex = bb.writerIndex();
            bb.writeShort(U16.t(0));

            // pad: 2 bytes
            bb.writeZero(2);
            message.hwAddr.write6Bytes(bb);
            // pad: 2 bytes
            bb.writeZero(2);
            ChannelUtils.writeFixedLengthString(bb, message.name, 16);
            OFPortConfigSerializerVer13.writeTo(bb, message.config);
            OFPortStateSerializerVer13.writeTo(bb, message.state);
            ChannelUtils.writeList(bb, message.desc);

            // update length field
            int length = bb.writerIndex() - startIndex;
            bb.setShort(lengthIndex, length);

        }
    }

    @Override
    public String toString() {
        StringBuilder b = new StringBuilder("OFPortOpticalVer13(");
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
        b.append("desc=").append(desc);
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
        OFPortOpticalVer13 other = (OFPortOpticalVer13) obj;

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
        if (config == null) {
            if (other.config != null)
                return false;
        } else if (!config.equals(other.config))
            return false;
        if (state == null) {
            if (other.state != null)
                return false;
        } else if (!state.equals(other.state))
            return false;
        if (desc == null) {
            if (other.desc != null)
                return false;
        } else if (!desc.equals(other.desc))
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
        result = prime * result + ((config == null) ? 0 : config.hashCode());
        result = prime * result + ((state == null) ? 0 : state.hashCode());
        result = prime * result + ((desc == null) ? 0 : desc.hashCode());
        return result;
    }

}
