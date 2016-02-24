/*******************************************************************************
 * Copyright 2014 Open Networking Laboratory
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 ******************************************************************************/
package net.onrc.openvirtex.util;

import java.util.HashMap;
import java.util.Map;

//import net.onrc.openvirtex.elements.address.PhysicalIPAddress;
import net.onrc.openvirtex.exceptions.UnknownActionException;

//yk
/*
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionDataLayerDestination;
import org.openflow.protocol.action.OFActionDataLayerSource;
import org.openflow.protocol.action.OFActionEnqueue;
import org.openflow.protocol.action.OFActionNetworkLayerDestination;
import org.openflow.protocol.action.OFActionNetworkLayerSource;
import org.openflow.protocol.action.OFActionNetworkTypeOfService;
import org.openflow.protocol.action.OFActionOutput;
import org.openflow.protocol.action.OFActionTransportLayerDestination;
import org.openflow.protocol.action.OFActionTransportLayerSource;
import org.openflow.protocol.action.OFActionVirtualLanIdentifier;
import org.openflow.protocol.action.OFActionVirtualLanPriorityCodePoint;
*/
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.action.OFActionEnqueue;
import org.projectfloodlight.openflow.protocol.action.OFActionOutput;
import org.projectfloodlight.openflow.protocol.action.OFActionSetDlDst;
import org.projectfloodlight.openflow.protocol.action.OFActionSetDlSrc;
import org.projectfloodlight.openflow.protocol.action.OFActionSetNwDst;
import org.projectfloodlight.openflow.protocol.action.OFActionSetNwSrc;
import org.projectfloodlight.openflow.protocol.action.OFActionSetNwTos;
import org.projectfloodlight.openflow.protocol.action.OFActionSetTpDst;
import org.projectfloodlight.openflow.protocol.action.OFActionSetTpSrc;
import org.projectfloodlight.openflow.protocol.action.OFActionSetVlanPcp;
import org.projectfloodlight.openflow.protocol.action.OFActionSetVlanVid;


/**
 * OVX utility class that implements various methods.
 */
public final class OVXUtil {

    /**
     * Override default constructor with no-op private constructor.
     * Needed for checkstyle.
     */
    private OVXUtil() {
    }

    /**
     * Gets the minimum number of bits needed to represent the given
     * integer.
     *
     * @param x the integer to represent in binary
     * @return the number of bits
     */
    public static int numBitsneeded(int x) {
        int counter = 0;
        while (x != 0) {
            x >>= 1;
            counter++;
        }
        return counter;
    }

    /**
     * Gets a map with string keys and object values from
     * the given action.
     *
     * @param act the action
     * @return string-to-object map
     * @throws UnknownActionException
     */
    public static Map<String, Object> actionToMap(OFAction act)
            throws UnknownActionException {
        HashMap<String, Object> ret = new HashMap<String, Object>();

        switch (act.getType()) {
        case OUTPUT:
            OFActionOutput out = (OFActionOutput) act;
            ret.put("type", "OUTPUT");
            ret.put("port", out.getPort());
            break;
        case SET_DL_DST:
        	//yk
        	//OFActionDataLayerDestination dldst = (OFActionDataLayerDestination) act;
        	OFActionSetDlDst dldst = (OFActionSetDlDst) act;
            ret.put("type", "DL_DST");
            //yk
            //ret.put("dl_dst",
            //        new MACAddress(dldst.getDataLayerAddress()).toString());
            ret.put("dl_dst", (dldst.getDlAddr()).toString());
            break;
        case SET_DL_SRC:
            //yk
        	//OFActionDataLayerSource dlsrc = (OFActionDataLayerSource) act;
        	OFActionSetDlSrc dlsrc = (OFActionSetDlSrc) act;
            ret.put("type", "DL_SRC");
            
            //yk
            //ret.put("dl_src",
            //        new MACAddress(dlsrc.getDataLayerAddress()).toString());
            ret.put("dl_src", (dlsrc.getDlAddr()).toString());
            
            break;
        case SET_NW_DST:
            //yk
        	//OFActionNetworkLayerDestination nwdst = (OFActionNetworkLayerDestination) act;
        	OFActionSetNwDst nwdst = (OFActionSetNwDst) act;
            ret.put("type", "NW_DST");
            //yk
            //ret.put("nw_dst", new PhysicalIPAddress(nwdst.getNetworkAddress())
            ret.put("nw_dst", (nwdst.getNwAddr()).toString());
            break;
        case SET_NW_SRC:
            //yk
        	//OFActionNetworkLayerSource nwsrc = (OFActionNetworkLayerSource) act;
        	OFActionSetNwSrc nwsrc = (OFActionSetNwSrc) act;
            ret.put("type", "NW_SRC");
            //yk
            //ret.put("nw_src", new PhysicalIPAddress(nwsrc.getNetworkAddress())
            //        .toSimpleString());
            ret.put("nw_src", (nwsrc.getNwAddr()).toString());
            break;
        case SET_NW_TOS:
        	//yk
        	//OFActionNetworkTypeOfService nwtos = (OFActionNetworkTypeOfService) act;
        	OFActionSetNwTos nwtos = (OFActionSetNwTos) act;
            ret.put("type", "NW_TOS");
            ret.put("nw_tos", nwtos.getNwTos());
            break;
        case SET_TP_DST:
            //yk
        	//OFActionTransportLayerDestination tpdst = (OFActionTransportLayerDestination) act;
        	OFActionSetTpDst tpdst = (OFActionSetTpDst) act;
            ret.put("type", "TP_DST");
            //yk
            //ret.put("tp_dst", tpdst.getTransportPort());
            ret.put("tp_dst", tpdst.getTpPort());
            break;
        case SET_TP_SRC:
        	//yk
        	//OFActionTransportLayerSource tpsrc = (OFActionTransportLayerSource) act;
            OFActionSetTpSrc tpsrc = (OFActionSetTpSrc) act;
            ret.put("type", "TP_SRC");
            //yk
            //ret.put("tp_src", tpsrc.getTransportPort());
            ret.put("tp_src", tpsrc.getTpPort());
            break;
        //yk
        //case SET_VLAN_ID:
        case SET_VLAN_VID:
        	//yk
        	//OFActionVirtualLanIdentifier vlan = (OFActionVirtualLanIdentifier) act;
        	OFActionSetVlanVid vlan = (OFActionSetVlanVid) act;
            ret.put("type", "SET_VLAN");
            //yk
            //ret.put("vlan_id", vlan.getVirtualLanIdentifier());
            ret.put("vlan_id", vlan.getVlanVid());
            break;
        case SET_VLAN_PCP:
        	//yk
        	//OFActionVirtualLanPriorityCodePoint pcp = (OFActionVirtualLanPriorityCodePoint) act;
            OFActionSetVlanPcp pcp = (OFActionSetVlanPcp) act;
            ret.put("type", "SET_VLAN_PCP");
            ret.put("vlan_pcp", pcp.getVlanPcp());
            break;
        case STRIP_VLAN:
            ret.put("type", "STRIP_VLAN");
            break;
            
        //yk
        //case OPAQUE_ENQUEUE:
        case ENQUEUE:
            //yk
        	//OFActionEnqueue enq = (OFActionEnqueue) act;
        	OFActionEnqueue enq = (OFActionEnqueue) act;
            ret.put("type", "ENQUEUE");
            ret.put("queue", enq.getQueueId());
            break;
        
        //yk
        //case VENDOR:
        case EXPERIMENTER:
        	//yk
        	//ret.put("type", "VENDOR");
        	ret.put("type", "EXPERIMENTER");
            break;
        default:
            throw new UnknownActionException("Action " + act.getType()
                    + " is unknown.");
        }
        return ret;
    }

}
