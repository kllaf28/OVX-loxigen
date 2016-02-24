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
import org.jboss.netty.buffer.ChannelBuffer;
import com.google.common.hash.PrimitiveSink;
import com.google.common.hash.Funnel;

class OFCircuitPortStatusVer13 implements OFCircuitPortStatus {
    private static final Logger logger = LoggerFactory.getLogger(OFCircuitPortStatusVer13.class);
    // version: 1.3
    final static byte WIRE_VERSION = 4;
    final static int LENGTH = 72;

        private final static long DEFAULT_XID = 0x0L;
        private final static OFPort DEFAULT_PORT_NO = OFPort.ANY;
        private final static int DEFAULT_LENGTHS = 0x0;
        private final static MacAddress DEFAULT_HW_ADDR = MacAddress.NONE;
        private final static String DEFAULT_NAME = "";
        private final static Set<OFPortConfig> DEFAULT_CONFIG = ImmutableSet.<OFPortConfig>of();
        private final static Set<OFPortState> DEFAULT_STATE = ImmutableSet.<OFPortState>of();
        private final static U64 DEFAULT_IGNORE = U64.ZERO;

    // OF message fields
    private final long xid;
    private final OFPortReason reason;
    private final OFPort portNo;
    private final int lengths;
    private final MacAddress hwAddr;
    private final String name;
    private final Set<OFPortConfig> config;
    private final Set<OFPortState> state;
    private final U64 ignore;
//

    // package private constructor - used by readers, builders, and factory
    OFCircuitPortStatusVer13(long xid, OFPortReason reason, OFPort portNo, int lengths, MacAddress hwAddr, String name, Set<OFPortConfig> config, Set<OFPortState> state, U64 ignore) {
        if(reason == null) {
            throw new NullPointerException("OFCircuitPortStatusVer13: property reason cannot be null");
        }
        if(portNo == null) {
            throw new NullPointerException("OFCircuitPortStatusVer13: property portNo cannot be null");
        }
        if(hwAddr == null) {
            throw new NullPointerException("OFCircuitPortStatusVer13: property hwAddr cannot be null");
        }
        if(name == null) {
            throw new NullPointerException("OFCircuitPortStatusVer13: property name cannot be null");
        }
        if(config == null) {
            throw new NullPointerException("OFCircuitPortStatusVer13: property config cannot be null");
        }
        if(state == null) {
            throw new NullPointerException("OFCircuitPortStatusVer13: property state cannot be null");
        }
        if(ignore == null) {
            throw new NullPointerException("OFCircuitPortStatusVer13: property ignore cannot be null");
        }
        this.xid = xid;
        this.reason = reason;
        this.portNo = portNo;
        this.lengths = lengths;
        this.hwAddr = hwAddr;
        this.name = name;
        this.config = config;
        this.state = state;
        this.ignore = ignore;
    }

    // Accessors for OF message fields
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_13;
    }

    @Override
    public OFType getType() {
        return OFType.EXPERIMENTER;
    }

    @Override
    public long getXid() {
        return xid;
    }

    @Override
    public long getExperimenter() {
        return 0x748771L;
    }

    @Override
    public long getExpType() {
        return 0xcL;
    }

    @Override
    public OFPortReason getReason() {
        return reason;
    }

    @Override
    public OFPort getPortNo() {
        return portNo;
    }

    @Override
    public int getLengths() {
        return lengths;
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
    public U64 getIgnore() {
        return ignore;
    }



    public OFCircuitPortStatus.Builder createBuilder() {
        return new BuilderWithParent(this);
    }

    static class BuilderWithParent implements OFCircuitPortStatus.Builder {
        final OFCircuitPortStatusVer13 parentMessage;

        // OF message fields
        private boolean xidSet;
        private long xid;
        private boolean reasonSet;
        private OFPortReason reason;
        private boolean portNoSet;
        private OFPort portNo;
        private boolean lengthsSet;
        private int lengths;
        private boolean hwAddrSet;
        private MacAddress hwAddr;
        private boolean nameSet;
        private String name;
        private boolean configSet;
        private Set<OFPortConfig> config;
        private boolean stateSet;
        private Set<OFPortState> state;
        private boolean ignoreSet;
        private U64 ignore;

        BuilderWithParent(OFCircuitPortStatusVer13 parentMessage) {
            this.parentMessage = parentMessage;
        }

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_13;
    }

    @Override
    public OFType getType() {
        return OFType.EXPERIMENTER;
    }

    @Override
    public long getXid() {
        return xid;
    }

    @Override
    public OFCircuitPortStatus.Builder setXid(long xid) {
        this.xid = xid;
        this.xidSet = true;
        return this;
    }
    @Override
    public long getExperimenter() {
        return 0x748771L;
    }

    @Override
    public long getExpType() {
        return 0xcL;
    }

    @Override
    public OFPortReason getReason() {
        return reason;
    }

    @Override
    public OFCircuitPortStatus.Builder setReason(OFPortReason reason) {
        this.reason = reason;
        this.reasonSet = true;
        return this;
    }
    @Override
    public OFPort getPortNo() {
        return portNo;
    }

    @Override
    public OFCircuitPortStatus.Builder setPortNo(OFPort portNo) {
        this.portNo = portNo;
        this.portNoSet = true;
        return this;
    }
    @Override
    public int getLengths() {
        return lengths;
    }

    @Override
    public OFCircuitPortStatus.Builder setLengths(int lengths) {
        this.lengths = lengths;
        this.lengthsSet = true;
        return this;
    }
    @Override
    public MacAddress getHwAddr() {
        return hwAddr;
    }

    @Override
    public OFCircuitPortStatus.Builder setHwAddr(MacAddress hwAddr) {
        this.hwAddr = hwAddr;
        this.hwAddrSet = true;
        return this;
    }
    @Override
    public String getName() {
        return name;
    }

    @Override
    public OFCircuitPortStatus.Builder setName(String name) {
        this.name = name;
        this.nameSet = true;
        return this;
    }
    @Override
    public Set<OFPortConfig> getConfig() {
        return config;
    }

    @Override
    public OFCircuitPortStatus.Builder setConfig(Set<OFPortConfig> config) {
        this.config = config;
        this.configSet = true;
        return this;
    }
    @Override
    public Set<OFPortState> getState() {
        return state;
    }

    @Override
    public OFCircuitPortStatus.Builder setState(Set<OFPortState> state) {
        this.state = state;
        this.stateSet = true;
        return this;
    }
    @Override
    public U64 getIgnore() {
        return ignore;
    }

    @Override
    public OFCircuitPortStatus.Builder setIgnore(U64 ignore) {
        this.ignore = ignore;
        this.ignoreSet = true;
        return this;
    }


        @Override
        public OFCircuitPortStatus build() {
                long xid = this.xidSet ? this.xid : parentMessage.xid;
                OFPortReason reason = this.reasonSet ? this.reason : parentMessage.reason;
                if(reason == null)
                    throw new NullPointerException("Property reason must not be null");
                OFPort portNo = this.portNoSet ? this.portNo : parentMessage.portNo;
                if(portNo == null)
                    throw new NullPointerException("Property portNo must not be null");
                int lengths = this.lengthsSet ? this.lengths : parentMessage.lengths;
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
                U64 ignore = this.ignoreSet ? this.ignore : parentMessage.ignore;
                if(ignore == null)
                    throw new NullPointerException("Property ignore must not be null");

                //
                return new OFCircuitPortStatusVer13(
                    xid,
                    reason,
                    portNo,
                    lengths,
                    hwAddr,
                    name,
                    config,
                    state,
                    ignore
                );
        }

    }

    static class Builder implements OFCircuitPortStatus.Builder {
        // OF message fields
        private boolean xidSet;
        private long xid;
        private boolean reasonSet;
        private OFPortReason reason;
        private boolean portNoSet;
        private OFPort portNo;
        private boolean lengthsSet;
        private int lengths;
        private boolean hwAddrSet;
        private MacAddress hwAddr;
        private boolean nameSet;
        private String name;
        private boolean configSet;
        private Set<OFPortConfig> config;
        private boolean stateSet;
        private Set<OFPortState> state;
        private boolean ignoreSet;
        private U64 ignore;

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_13;
    }

    @Override
    public OFType getType() {
        return OFType.EXPERIMENTER;
    }

    @Override
    public long getXid() {
        return xid;
    }

    @Override
    public OFCircuitPortStatus.Builder setXid(long xid) {
        this.xid = xid;
        this.xidSet = true;
        return this;
    }
    @Override
    public long getExperimenter() {
        return 0x748771L;
    }

    @Override
    public long getExpType() {
        return 0xcL;
    }

    @Override
    public OFPortReason getReason() {
        return reason;
    }

    @Override
    public OFCircuitPortStatus.Builder setReason(OFPortReason reason) {
        this.reason = reason;
        this.reasonSet = true;
        return this;
    }
    @Override
    public OFPort getPortNo() {
        return portNo;
    }

    @Override
    public OFCircuitPortStatus.Builder setPortNo(OFPort portNo) {
        this.portNo = portNo;
        this.portNoSet = true;
        return this;
    }
    @Override
    public int getLengths() {
        return lengths;
    }

    @Override
    public OFCircuitPortStatus.Builder setLengths(int lengths) {
        this.lengths = lengths;
        this.lengthsSet = true;
        return this;
    }
    @Override
    public MacAddress getHwAddr() {
        return hwAddr;
    }

    @Override
    public OFCircuitPortStatus.Builder setHwAddr(MacAddress hwAddr) {
        this.hwAddr = hwAddr;
        this.hwAddrSet = true;
        return this;
    }
    @Override
    public String getName() {
        return name;
    }

    @Override
    public OFCircuitPortStatus.Builder setName(String name) {
        this.name = name;
        this.nameSet = true;
        return this;
    }
    @Override
    public Set<OFPortConfig> getConfig() {
        return config;
    }

    @Override
    public OFCircuitPortStatus.Builder setConfig(Set<OFPortConfig> config) {
        this.config = config;
        this.configSet = true;
        return this;
    }
    @Override
    public Set<OFPortState> getState() {
        return state;
    }

    @Override
    public OFCircuitPortStatus.Builder setState(Set<OFPortState> state) {
        this.state = state;
        this.stateSet = true;
        return this;
    }
    @Override
    public U64 getIgnore() {
        return ignore;
    }

    @Override
    public OFCircuitPortStatus.Builder setIgnore(U64 ignore) {
        this.ignore = ignore;
        this.ignoreSet = true;
        return this;
    }
//
        @Override
        public OFCircuitPortStatus build() {
            long xid = this.xidSet ? this.xid : DEFAULT_XID;
            if(!this.reasonSet)
                throw new IllegalStateException("Property reason doesn't have default value -- must be set");
            if(reason == null)
                throw new NullPointerException("Property reason must not be null");
            OFPort portNo = this.portNoSet ? this.portNo : DEFAULT_PORT_NO;
            if(portNo == null)
                throw new NullPointerException("Property portNo must not be null");
            int lengths = this.lengthsSet ? this.lengths : DEFAULT_LENGTHS;
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
            U64 ignore = this.ignoreSet ? this.ignore : DEFAULT_IGNORE;
            if(ignore == null)
                throw new NullPointerException("Property ignore must not be null");


            return new OFCircuitPortStatusVer13(
                    xid,
                    reason,
                    portNo,
                    lengths,
                    hwAddr,
                    name,
                    config,
                    state,
                    ignore
                );
        }

    }


    final static Reader READER = new Reader();
    static class Reader implements OFMessageReader<OFCircuitPortStatus> {
        @Override
        public OFCircuitPortStatus readFrom(ChannelBuffer bb) throws OFParseError {
            int start = bb.readerIndex();
            // fixed value property version == 4
            byte version = bb.readByte();
            if(version != (byte) 0x4)
                throw new OFParseError("Wrong version: Expected=OFVersion.OF_13(4), got="+version);
            // fixed value property type == 4
            byte type = bb.readByte();
            if(type != (byte) 0x4)
                throw new OFParseError("Wrong type: Expected=OFType.EXPERIMENTER(4), got="+type);
            int length = U16.f(bb.readShort());
            if(length != 72)
                throw new OFParseError("Wrong length: Expected=72(72), got="+length);
            if(bb.readableBytes() + (bb.readerIndex() - start) < length) {
                // Buffer does not have all data yet
                bb.readerIndex(start);
                return null;
            }
            if(logger.isTraceEnabled())
                logger.trace("readFrom - length={}", length);
            long xid = U32.f(bb.readInt());
            // fixed value property experimenter == 0x748771L
            int experimenter = bb.readInt();
            if(experimenter != 0x748771)
                throw new OFParseError("Wrong experimenter: Expected=0x748771L(0x748771L), got="+experimenter);
            // fixed value property expType == 0xcL
            int expType = bb.readInt();
            if(expType != 0xc)
                throw new OFParseError("Wrong expType: Expected=0xcL(0xcL), got="+expType);
            OFPortReason reason = OFPortReasonSerializerVer13.readFrom(bb);
            // pad: 7 bytes
            bb.skipBytes(7);
            OFPort portNo = OFPort.read4Bytes(bb);
            int lengths = U16.f(bb.readShort());
            // pad: 2 bytes
            bb.skipBytes(2);
            MacAddress hwAddr = MacAddress.read6Bytes(bb);
            // pad: 2 bytes
            bb.skipBytes(2);
            String name = ChannelUtils.readFixedLengthString(bb, 16);
            Set<OFPortConfig> config = OFPortConfigSerializerVer13.readFrom(bb);
            Set<OFPortState> state = OFPortStateSerializerVer13.readFrom(bb);
            U64 ignore = U64.ofRaw(bb.readLong());

            OFCircuitPortStatusVer13 circuitPortStatusVer13 = new OFCircuitPortStatusVer13(
                    xid,
                      reason,
                      portNo,
                      lengths,
                      hwAddr,
                      name,
                      config,
                      state,
                      ignore
                    );
            if(logger.isTraceEnabled())
                logger.trace("readFrom - read={}", circuitPortStatusVer13);
            return circuitPortStatusVer13;
        }
    }

    public void putTo(PrimitiveSink sink) {
        FUNNEL.funnel(this, sink);
    }

    final static OFCircuitPortStatusVer13Funnel FUNNEL = new OFCircuitPortStatusVer13Funnel();
    static class OFCircuitPortStatusVer13Funnel implements Funnel<OFCircuitPortStatusVer13> {
        private static final long serialVersionUID = 1L;
        @Override
        public void funnel(OFCircuitPortStatusVer13 message, PrimitiveSink sink) {
            // fixed value property version = 4
            sink.putByte((byte) 0x4);
            // fixed value property type = 4
            sink.putByte((byte) 0x4);
            // fixed value property length = 72
            sink.putShort((short) 0x48);
            sink.putLong(message.xid);
            // fixed value property experimenter = 0x748771L
            sink.putInt(0x748771);
            // fixed value property expType = 0xcL
            sink.putInt(0xc);
            OFPortReasonSerializerVer13.putTo(message.reason, sink);
            // skip pad (7 bytes)
            message.portNo.putTo(sink);
            sink.putInt(message.lengths);
            // skip pad (2 bytes)
            message.hwAddr.putTo(sink);
            // skip pad (2 bytes)
            sink.putUnencodedChars(message.name);
            OFPortConfigSerializerVer13.putTo(message.config, sink);
            OFPortStateSerializerVer13.putTo(message.state, sink);
            message.ignore.putTo(sink);
        }
    }


    public void writeTo(ChannelBuffer bb) {
        WRITER.write(bb, this);
    }

    final static Writer WRITER = new Writer();
    static class Writer implements OFMessageWriter<OFCircuitPortStatusVer13> {
        @Override
        public void write(ChannelBuffer bb, OFCircuitPortStatusVer13 message) {
            // fixed value property version = 4
            bb.writeByte((byte) 0x4);
            // fixed value property type = 4
            bb.writeByte((byte) 0x4);
            // fixed value property length = 72
            bb.writeShort((short) 0x48);
            bb.writeInt(U32.t(message.xid));
            // fixed value property experimenter = 0x748771L
            bb.writeInt(0x748771);
            // fixed value property expType = 0xcL
            bb.writeInt(0xc);
            OFPortReasonSerializerVer13.writeTo(bb, message.reason);
            // pad: 7 bytes
            bb.writeZero(7);
            message.portNo.write4Bytes(bb);
            bb.writeShort(U16.t(message.lengths));
            // pad: 2 bytes
            bb.writeZero(2);
            message.hwAddr.write6Bytes(bb);
            // pad: 2 bytes
            bb.writeZero(2);
            ChannelUtils.writeFixedLengthString(bb, message.name, 16);
            OFPortConfigSerializerVer13.writeTo(bb, message.config);
            OFPortStateSerializerVer13.writeTo(bb, message.state);
            bb.writeLong(message.ignore.getValue());


        }
    }

    @Override
    public String toString() {
        StringBuilder b = new StringBuilder("OFCircuitPortStatusVer13(");
        b.append("xid=").append(xid);
        b.append(", ");
        b.append("reason=").append(reason);
        b.append(", ");
        b.append("portNo=").append(portNo);
        b.append(", ");
        b.append("lengths=").append(lengths);
        b.append(", ");
        b.append("hwAddr=").append(hwAddr);
        b.append(", ");
        b.append("name=").append(name);
        b.append(", ");
        b.append("config=").append(config);
        b.append(", ");
        b.append("state=").append(state);
        b.append(", ");
        b.append("ignore=").append(ignore);
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
        OFCircuitPortStatusVer13 other = (OFCircuitPortStatusVer13) obj;

        if( xid != other.xid)
            return false;
        if (reason == null) {
            if (other.reason != null)
                return false;
        } else if (!reason.equals(other.reason))
            return false;
        if (portNo == null) {
            if (other.portNo != null)
                return false;
        } else if (!portNo.equals(other.portNo))
            return false;
        if( lengths != other.lengths)
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
        if (ignore == null) {
            if (other.ignore != null)
                return false;
        } else if (!ignore.equals(other.ignore))
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;

        result = prime *  (int) (xid ^ (xid >>> 32));
        result = prime * result + ((reason == null) ? 0 : reason.hashCode());
        result = prime * result + ((portNo == null) ? 0 : portNo.hashCode());
        result = prime * result + lengths;
        result = prime * result + ((hwAddr == null) ? 0 : hwAddr.hashCode());
        result = prime * result + ((name == null) ? 0 : name.hashCode());
        result = prime * result + ((config == null) ? 0 : config.hashCode());
        result = prime * result + ((state == null) ? 0 : state.hashCode());
        result = prime * result + ((ignore == null) ? 0 : ignore.hashCode());
        return result;
    }

}
