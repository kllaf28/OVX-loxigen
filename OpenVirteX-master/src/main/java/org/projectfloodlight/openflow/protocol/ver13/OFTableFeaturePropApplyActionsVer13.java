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

class OFTableFeaturePropApplyActionsVer13 implements OFTableFeaturePropApplyActions {
    private static final Logger logger = LoggerFactory.getLogger(OFTableFeaturePropApplyActionsVer13.class);
    // version: 1.3
    final static byte WIRE_VERSION = 4;
    final static int MINIMUM_LENGTH = 4;

        private final static List<OFActionId> DEFAULT_ACTION_IDS = ImmutableList.<OFActionId>of();

    // OF message fields
    private final List<OFActionId> actionIds;
//
    // Immutable default instance
    final static OFTableFeaturePropApplyActionsVer13 DEFAULT = new OFTableFeaturePropApplyActionsVer13(
        DEFAULT_ACTION_IDS
    );

    // package private constructor - used by readers, builders, and factory
    OFTableFeaturePropApplyActionsVer13(List<OFActionId> actionIds) {
        if(actionIds == null) {
            throw new NullPointerException("OFTableFeaturePropApplyActionsVer13: property actionIds cannot be null");
        }
        this.actionIds = actionIds;
    }

    // Accessors for OF message fields
    @Override
    public int getType() {
        return 0x6;
    }

    @Override
    public List<OFActionId> getActionIds() {
        return actionIds;
    }

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_13;
    }



    public OFTableFeaturePropApplyActions.Builder createBuilder() {
        return new BuilderWithParent(this);
    }

    static class BuilderWithParent implements OFTableFeaturePropApplyActions.Builder {
        final OFTableFeaturePropApplyActionsVer13 parentMessage;

        // OF message fields
        private boolean actionIdsSet;
        private List<OFActionId> actionIds;

        BuilderWithParent(OFTableFeaturePropApplyActionsVer13 parentMessage) {
            this.parentMessage = parentMessage;
        }

    @Override
    public int getType() {
        return 0x6;
    }

    @Override
    public List<OFActionId> getActionIds() {
        return actionIds;
    }

    @Override
    public OFTableFeaturePropApplyActions.Builder setActionIds(List<OFActionId> actionIds) {
        this.actionIds = actionIds;
        this.actionIdsSet = true;
        return this;
    }
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_13;
    }



        @Override
        public OFTableFeaturePropApplyActions build() {
                List<OFActionId> actionIds = this.actionIdsSet ? this.actionIds : parentMessage.actionIds;
                if(actionIds == null)
                    throw new NullPointerException("Property actionIds must not be null");

                //
                return new OFTableFeaturePropApplyActionsVer13(
                    actionIds
                );
        }

    }

    static class Builder implements OFTableFeaturePropApplyActions.Builder {
        // OF message fields
        private boolean actionIdsSet;
        private List<OFActionId> actionIds;

    @Override
    public int getType() {
        return 0x6;
    }

    @Override
    public List<OFActionId> getActionIds() {
        return actionIds;
    }

    @Override
    public OFTableFeaturePropApplyActions.Builder setActionIds(List<OFActionId> actionIds) {
        this.actionIds = actionIds;
        this.actionIdsSet = true;
        return this;
    }
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_13;
    }

//
        @Override
        public OFTableFeaturePropApplyActions build() {
            List<OFActionId> actionIds = this.actionIdsSet ? this.actionIds : DEFAULT_ACTION_IDS;
            if(actionIds == null)
                throw new NullPointerException("Property actionIds must not be null");


            return new OFTableFeaturePropApplyActionsVer13(
                    actionIds
                );
        }

    }


    final static Reader READER = new Reader();
    static class Reader implements OFMessageReader<OFTableFeaturePropApplyActions> {
        @Override
        public OFTableFeaturePropApplyActions readFrom(ChannelBuffer bb) throws OFParseError {
            int start = bb.readerIndex();
            // fixed value property type == 0x6
            short type = bb.readShort();
            if(type != (short) 0x6)
                throw new OFParseError("Wrong type: Expected=0x6(0x6), got="+type);
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
            List<OFActionId> actionIds = ChannelUtils.readList(bb, length - (bb.readerIndex() - start), OFActionIdVer13.READER);
            // align message to 8 bytes (length does not contain alignment)
            bb.skipBytes(((length + 7)/8 * 8 ) - length );

            OFTableFeaturePropApplyActionsVer13 tableFeaturePropApplyActionsVer13 = new OFTableFeaturePropApplyActionsVer13(
                    actionIds
                    );
            if(logger.isTraceEnabled())
                logger.trace("readFrom - read={}", tableFeaturePropApplyActionsVer13);
            return tableFeaturePropApplyActionsVer13;
        }
    }

    public void putTo(PrimitiveSink sink) {
        FUNNEL.funnel(this, sink);
    }

    final static OFTableFeaturePropApplyActionsVer13Funnel FUNNEL = new OFTableFeaturePropApplyActionsVer13Funnel();
    static class OFTableFeaturePropApplyActionsVer13Funnel implements Funnel<OFTableFeaturePropApplyActionsVer13> {
        private static final long serialVersionUID = 1L;
        @Override
        public void funnel(OFTableFeaturePropApplyActionsVer13 message, PrimitiveSink sink) {
            // fixed value property type = 0x6
            sink.putShort((short) 0x6);
            // FIXME: skip funnel of length
            FunnelUtils.putList(message.actionIds, sink);
        }
    }


    public void writeTo(ChannelBuffer bb) {
        WRITER.write(bb, this);
    }

    final static Writer WRITER = new Writer();
    static class Writer implements OFMessageWriter<OFTableFeaturePropApplyActionsVer13> {
        @Override
        public void write(ChannelBuffer bb, OFTableFeaturePropApplyActionsVer13 message) {
            int startIndex = bb.writerIndex();
            // fixed value property type = 0x6
            bb.writeShort((short) 0x6);
            // length is length of variable message, will be updated at the end
            int lengthIndex = bb.writerIndex();
            bb.writeShort(U16.t(0));

            ChannelUtils.writeList(bb, message.actionIds);

            // update length field
            int length = bb.writerIndex() - startIndex;
            int alignedLength = ((length + 7)/8 * 8);
            bb.setShort(lengthIndex, length);
            // align message to 8 bytes
            bb.writeZero(alignedLength - length);

        }
    }

    @Override
    public String toString() {
        StringBuilder b = new StringBuilder("OFTableFeaturePropApplyActionsVer13(");
        b.append("actionIds=").append(actionIds);
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
        OFTableFeaturePropApplyActionsVer13 other = (OFTableFeaturePropApplyActionsVer13) obj;

        if (actionIds == null) {
            if (other.actionIds != null)
                return false;
        } else if (!actionIds.equals(other.actionIds))
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;

        result = prime * result + ((actionIds == null) ? 0 : actionIds.hashCode());
        return result;
    }

}
