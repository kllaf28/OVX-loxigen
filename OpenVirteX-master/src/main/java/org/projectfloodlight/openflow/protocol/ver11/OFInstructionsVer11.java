// Copyright (c) 2008 The Board of Trustees of The Leland Stanford Junior University
// Copyright (c) 2011, 2012 Open Networking Foundation
// Copyright (c) 2012, 2013 Big Switch Networks, Inc.
// This library was generated by the LoxiGen Compiler.
// See the file LICENSE.txt which should have been included in the source distribution

// Automatically generated by LOXI from template of_factory_class.java
// Do not modify

package org.projectfloodlight.openflow.protocol.ver11;

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
import java.util.List;


public class OFInstructionsVer11 implements OFInstructions {
    public final static OFInstructionsVer11 INSTANCE = new OFInstructionsVer11();




    public OFInstructionApplyActions.Builder buildApplyActions() {
        return new OFInstructionApplyActionsVer11.Builder();
    }
    public OFInstructionApplyActions applyActions(List<OFAction> actions) {
        return new OFInstructionApplyActionsVer11(
                actions
                    );
    }

    public OFInstructionClearActions clearActions() {
        return OFInstructionClearActionsVer11.INSTANCE;
    }

    public OFInstructionGotoTable.Builder buildGotoTable() {
        return new OFInstructionGotoTableVer11.Builder();
    }
    public OFInstructionGotoTable gotoTable(TableId tableId) {
        return new OFInstructionGotoTableVer11(
                tableId
                    );
    }

    public OFInstructionWriteActions.Builder buildWriteActions() {
        return new OFInstructionWriteActionsVer11.Builder();
    }
    public OFInstructionWriteActions writeActions(List<OFAction> actions) {
        return new OFInstructionWriteActionsVer11(
                actions
                    );
    }

    public OFInstructionWriteMetadata.Builder buildWriteMetadata() {
        return new OFInstructionWriteMetadataVer11.Builder();
    }
    public OFInstructionWriteMetadata writeMetadata(U64 metadata, U64 metadataMask) {
        return new OFInstructionWriteMetadataVer11(
                metadata,
                      metadataMask
                    );
    }

    public OFInstructionBsnArpOffload bsnArpOffload() {
        throw new UnsupportedOperationException("OFInstructionBsnArpOffload not supported in version 1.1");
    }

    public OFInstructionBsnAutoNegotiation bsnAutoNegotiation() {
        throw new UnsupportedOperationException("OFInstructionBsnAutoNegotiation not supported in version 1.1");
    }

    public OFInstructionBsnDeny bsnDeny() {
        throw new UnsupportedOperationException("OFInstructionBsnDeny not supported in version 1.1");
    }

    public OFInstructionBsnDhcpOffload bsnDhcpOffload() {
        throw new UnsupportedOperationException("OFInstructionBsnDhcpOffload not supported in version 1.1");
    }

    public OFInstructionBsnDisableL3 bsnDisableL3() {
        throw new UnsupportedOperationException("OFInstructionBsnDisableL3 not supported in version 1.1");
    }

    public OFInstructionBsnDisableSplitHorizonCheck bsnDisableSplitHorizonCheck() {
        throw new UnsupportedOperationException("OFInstructionBsnDisableSplitHorizonCheck not supported in version 1.1");
    }

    public OFInstructionBsnDisableSrcMacCheck bsnDisableSrcMacCheck() {
        throw new UnsupportedOperationException("OFInstructionBsnDisableSrcMacCheck not supported in version 1.1");
    }

    public OFInstructionBsnDisableVlanCounters bsnDisableVlanCounters() {
        throw new UnsupportedOperationException("OFInstructionBsnDisableVlanCounters not supported in version 1.1");
    }

    public OFInstructionBsnInternalPriority.Builder buildBsnInternalPriority() {
        throw new UnsupportedOperationException("OFInstructionBsnInternalPriority not supported in version 1.1");
    }
    public OFInstructionBsnInternalPriority bsnInternalPriority(long value) {
        throw new UnsupportedOperationException("OFInstructionBsnInternalPriority not supported in version 1.1");
    }

    public OFInstructionBsnPacketOfDeath bsnPacketOfDeath() {
        throw new UnsupportedOperationException("OFInstructionBsnPacketOfDeath not supported in version 1.1");
    }

    public OFInstructionBsnPermit bsnPermit() {
        throw new UnsupportedOperationException("OFInstructionBsnPermit not supported in version 1.1");
    }

    public OFInstructionBsnPrioritizePdus bsnPrioritizePdus() {
        throw new UnsupportedOperationException("OFInstructionBsnPrioritizePdus not supported in version 1.1");
    }

    public OFInstructionBsnRequireVlanXlate bsnRequireVlanXlate() {
        throw new UnsupportedOperationException("OFInstructionBsnRequireVlanXlate not supported in version 1.1");
    }

    public OFInstructionBsnSpanDestination bsnSpanDestination() {
        throw new UnsupportedOperationException("OFInstructionBsnSpanDestination not supported in version 1.1");
    }

    public OFInstructionMeter.Builder buildMeter() {
        throw new UnsupportedOperationException("OFInstructionMeter not supported in version 1.1");
    }
    public OFInstructionMeter meter(long meterId) {
        throw new UnsupportedOperationException("OFInstructionMeter not supported in version 1.1");
    }

    public OFMessageReader<OFInstruction> getReader() {
        return OFInstructionVer11.READER;
    }


    public OFVersion getVersion() {
            return OFVersion.OF_11;
    }
}
