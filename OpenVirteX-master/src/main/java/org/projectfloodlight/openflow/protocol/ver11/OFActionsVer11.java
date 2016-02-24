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
import java.util.Set;
import java.util.List;


public class OFActionsVer11 implements OFActions {
    public final static OFActionsVer11 INSTANCE = new OFActionsVer11();




    public OFActionBsnChecksum.Builder buildBsnChecksum() {
        return new OFActionBsnChecksumVer11.Builder();
    }
    public OFActionBsnChecksum bsnChecksum(U128 checksum) {
        return new OFActionBsnChecksumVer11(
                checksum
                    );
    }

    public OFActionBsnMirror.Builder buildBsnMirror() {
        return new OFActionBsnMirrorVer11.Builder();
    }

    public OFActionBsnSetTunnelDst.Builder buildBsnSetTunnelDst() {
        return new OFActionBsnSetTunnelDstVer11.Builder();
    }
    public OFActionBsnSetTunnelDst bsnSetTunnelDst(long dst) {
        return new OFActionBsnSetTunnelDstVer11(
                dst
                    );
    }

    public OFActionEnqueue.Builder buildEnqueue() {
        throw new UnsupportedOperationException("OFActionEnqueue not supported in version 1.1");
    }
    public OFActionEnqueue enqueue(OFPort port, long queueId) {
        throw new UnsupportedOperationException("OFActionEnqueue not supported in version 1.1");
    }

    public OFActionNiciraDecTtl niciraDecTtl() {
        return OFActionNiciraDecTtlVer11.INSTANCE;
    }

    public OFActionNiciraLoad.Builder buildNiciraLoad() {
        return new OFActionNiciraLoadVer11.Builder();
    }

    public OFActionNiciraMove.Builder buildNiciraMove() {
        return new OFActionNiciraMoveVer11.Builder();
    }

    public OFActionNiciraPopQueue niciraPopQueue() {
        return OFActionNiciraPopQueueVer11.INSTANCE;
    }

    public OFActionNiciraResubmit.Builder buildNiciraResubmit() {
        return new OFActionNiciraResubmitVer11.Builder();
    }
    public OFActionNiciraResubmit niciraResubmit(int inPort, short table) {
        return new OFActionNiciraResubmitVer11(
                inPort,
                      table
                    );
    }

    public OFActionNiciraResubmitTable.Builder buildNiciraResubmitTable() {
        return new OFActionNiciraResubmitTableVer11.Builder();
    }
    public OFActionNiciraResubmitTable niciraResubmitTable(int inPort, short table) {
        return new OFActionNiciraResubmitTableVer11(
                inPort,
                      table
                    );
    }

    public OFActionNiciraSetNshc1.Builder buildNiciraSetNshc1() {
        return new OFActionNiciraSetNshc1Ver11.Builder();
    }
    public OFActionNiciraSetNshc1 niciraSetNshc1(long nshc1) {
        return new OFActionNiciraSetNshc1Ver11(
                nshc1
                    );
    }

    public OFActionNiciraSetNshc2.Builder buildNiciraSetNshc2() {
        return new OFActionNiciraSetNshc2Ver11.Builder();
    }
    public OFActionNiciraSetNshc2 niciraSetNshc2(long nshc2) {
        return new OFActionNiciraSetNshc2Ver11(
                nshc2
                    );
    }

    public OFActionNiciraSetNshc3.Builder buildNiciraSetNshc3() {
        return new OFActionNiciraSetNshc3Ver11.Builder();
    }
    public OFActionNiciraSetNshc3 niciraSetNshc3(long nshc3) {
        return new OFActionNiciraSetNshc3Ver11(
                nshc3
                    );
    }

    public OFActionNiciraSetNshc4.Builder buildNiciraSetNshc4() {
        return new OFActionNiciraSetNshc4Ver11.Builder();
    }
    public OFActionNiciraSetNshc4 niciraSetNshc4(long nshc4) {
        return new OFActionNiciraSetNshc4Ver11(
                nshc4
                    );
    }

    public OFActionNiciraSetNsi.Builder buildNiciraSetNsi() {
        return new OFActionNiciraSetNsiVer11.Builder();
    }
    public OFActionNiciraSetNsi niciraSetNsi(short nsi) {
        return new OFActionNiciraSetNsiVer11(
                nsi
                    );
    }

    public OFActionNiciraSetNsp.Builder buildNiciraSetNsp() {
        return new OFActionNiciraSetNspVer11.Builder();
    }
    public OFActionNiciraSetNsp niciraSetNsp(long nsp) {
        return new OFActionNiciraSetNspVer11(
                nsp
                    );
    }

    public OFActionNiciraSetQueue.Builder buildNiciraSetQueue() {
        return new OFActionNiciraSetQueueVer11.Builder();
    }
    public OFActionNiciraSetQueue niciraSetQueue(long queueId) {
        return new OFActionNiciraSetQueueVer11(
                queueId
                    );
    }

    public OFActionOutput.Builder buildOutput() {
        return new OFActionOutputVer11.Builder();
    }
    public OFActionOutput output(OFPort port, int maxLen) {
        return new OFActionOutputVer11(
                port,
                      maxLen
                    );
    }

    public OFActionSetDlDst.Builder buildSetDlDst() {
        return new OFActionSetDlDstVer11.Builder();
    }
    public OFActionSetDlDst setDlDst(MacAddress dlAddr) {
        return new OFActionSetDlDstVer11(
                dlAddr
                    );
    }

    public OFActionSetDlSrc.Builder buildSetDlSrc() {
        return new OFActionSetDlSrcVer11.Builder();
    }
    public OFActionSetDlSrc setDlSrc(MacAddress dlAddr) {
        return new OFActionSetDlSrcVer11(
                dlAddr
                    );
    }

    public OFActionSetNwDst.Builder buildSetNwDst() {
        return new OFActionSetNwDstVer11.Builder();
    }
    public OFActionSetNwDst setNwDst(IPv4Address nwAddr) {
        return new OFActionSetNwDstVer11(
                nwAddr
                    );
    }

    public OFActionSetNwSrc.Builder buildSetNwSrc() {
        return new OFActionSetNwSrcVer11.Builder();
    }
    public OFActionSetNwSrc setNwSrc(IPv4Address nwAddr) {
        return new OFActionSetNwSrcVer11(
                nwAddr
                    );
    }

    public OFActionSetNwTos.Builder buildSetNwTos() {
        return new OFActionSetNwTosVer11.Builder();
    }
    public OFActionSetNwTos setNwTos(short nwTos) {
        return new OFActionSetNwTosVer11(
                nwTos
                    );
    }

    public OFActionSetTpDst.Builder buildSetTpDst() {
        return new OFActionSetTpDstVer11.Builder();
    }
    public OFActionSetTpDst setTpDst(TransportPort tpPort) {
        return new OFActionSetTpDstVer11(
                tpPort
                    );
    }

    public OFActionSetTpSrc.Builder buildSetTpSrc() {
        return new OFActionSetTpSrcVer11.Builder();
    }
    public OFActionSetTpSrc setTpSrc(TransportPort tpPort) {
        return new OFActionSetTpSrcVer11(
                tpPort
                    );
    }

    public OFActionSetVlanPcp.Builder buildSetVlanPcp() {
        return new OFActionSetVlanPcpVer11.Builder();
    }
    public OFActionSetVlanPcp setVlanPcp(VlanPcp vlanPcp) {
        return new OFActionSetVlanPcpVer11(
                vlanPcp
                    );
    }

    public OFActionSetVlanVid.Builder buildSetVlanVid() {
        return new OFActionSetVlanVidVer11.Builder();
    }
    public OFActionSetVlanVid setVlanVid(VlanVid vlanVid) {
        return new OFActionSetVlanVidVer11(
                vlanVid
                    );
    }

    public OFActionStripVlan stripVlan() {
        throw new UnsupportedOperationException("OFActionStripVlan not supported in version 1.1");
    }

    public OFActionCopyTtlIn copyTtlIn() {
        return OFActionCopyTtlInVer11.INSTANCE;
    }

    public OFActionCopyTtlOut copyTtlOut() {
        return OFActionCopyTtlOutVer11.INSTANCE;
    }

    public OFActionDecMplsTtl decMplsTtl() {
        return OFActionDecMplsTtlVer11.INSTANCE;
    }

    public OFActionDecNwTtl decNwTtl() {
        return OFActionDecNwTtlVer11.INSTANCE;
    }

    public OFActionGroup.Builder buildGroup() {
        return new OFActionGroupVer11.Builder();
    }
    public OFActionGroup group(OFGroup group) {
        return new OFActionGroupVer11(
                group
                    );
    }

    public OFActionPopMpls.Builder buildPopMpls() {
        return new OFActionPopMplsVer11.Builder();
    }
    public OFActionPopMpls popMpls(EthType ethertype) {
        return new OFActionPopMplsVer11(
                ethertype
                    );
    }

    public OFActionPopVlan popVlan() {
        return OFActionPopVlanVer11.INSTANCE;
    }

    public OFActionPushMpls.Builder buildPushMpls() {
        return new OFActionPushMplsVer11.Builder();
    }
    public OFActionPushMpls pushMpls(EthType ethertype) {
        return new OFActionPushMplsVer11(
                ethertype
                    );
    }

    public OFActionPushVlan.Builder buildPushVlan() {
        return new OFActionPushVlanVer11.Builder();
    }
    public OFActionPushVlan pushVlan(EthType ethertype) {
        return new OFActionPushVlanVer11(
                ethertype
                    );
    }

    public OFActionSetMplsLabel.Builder buildSetMplsLabel() {
        return new OFActionSetMplsLabelVer11.Builder();
    }
    public OFActionSetMplsLabel setMplsLabel(long mplsLabel) {
        return new OFActionSetMplsLabelVer11(
                mplsLabel
                    );
    }

    public OFActionSetMplsTc.Builder buildSetMplsTc() {
        return new OFActionSetMplsTcVer11.Builder();
    }
    public OFActionSetMplsTc setMplsTc(short mplsTc) {
        return new OFActionSetMplsTcVer11(
                mplsTc
                    );
    }

    public OFActionSetMplsTtl.Builder buildSetMplsTtl() {
        return new OFActionSetMplsTtlVer11.Builder();
    }
    public OFActionSetMplsTtl setMplsTtl(short mplsTtl) {
        return new OFActionSetMplsTtlVer11(
                mplsTtl
                    );
    }

    public OFActionSetNwEcn.Builder buildSetNwEcn() {
        return new OFActionSetNwEcnVer11.Builder();
    }
    public OFActionSetNwEcn setNwEcn(IpEcn nwEcn) {
        return new OFActionSetNwEcnVer11(
                nwEcn
                    );
    }

    public OFActionSetNwTtl.Builder buildSetNwTtl() {
        return new OFActionSetNwTtlVer11.Builder();
    }
    public OFActionSetNwTtl setNwTtl(short nwTtl) {
        return new OFActionSetNwTtlVer11(
                nwTtl
                    );
    }

    public OFActionSetQueue.Builder buildSetQueue() {
        return new OFActionSetQueueVer11.Builder();
    }
    public OFActionSetQueue setQueue(long queueId) {
        return new OFActionSetQueueVer11(
                queueId
                    );
    }

    public OFActionSetField.Builder buildSetField() {
        throw new UnsupportedOperationException("OFActionSetField not supported in version 1.1");
    }
    public OFActionSetField setField(OFOxm<?> field) {
        throw new UnsupportedOperationException("OFActionSetField not supported in version 1.1");
    }

    public OFActionBsnGentable.Builder buildBsnGentable() {
        throw new UnsupportedOperationException("OFActionBsnGentable not supported in version 1.1");
    }
    public OFActionBsnGentable bsnGentable(long tableId, List<OFBsnTlv> key) {
        throw new UnsupportedOperationException("OFActionBsnGentable not supported in version 1.1");
    }

    public OFActionCircuit.Builder buildCircuit() {
        throw new UnsupportedOperationException("OFActionCircuit not supported in version 1.1");
    }
    public OFActionCircuit circuit(OFOxm<?> field) {
        throw new UnsupportedOperationException("OFActionCircuit not supported in version 1.1");
    }

    public OFActionPopPbb popPbb() {
        throw new UnsupportedOperationException("OFActionPopPbb not supported in version 1.1");
    }

    public OFActionPushPbb.Builder buildPushPbb() {
        throw new UnsupportedOperationException("OFActionPushPbb not supported in version 1.1");
    }
    public OFActionPushPbb pushPbb(EthType ethertype) {
        throw new UnsupportedOperationException("OFActionPushPbb not supported in version 1.1");
    }

    public OFMessageReader<OFAction> getReader() {
        return OFActionVer11.READER;
    }


    public OFVersion getVersion() {
            return OFVersion.OF_11;
    }
}
