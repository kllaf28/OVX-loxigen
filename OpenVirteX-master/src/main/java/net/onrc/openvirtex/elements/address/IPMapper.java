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
package net.onrc.openvirtex.elements.address;

import java.util.LinkedList;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

//yk
/*
import org.openflow.protocol.OFMatch;
import org.openflow.protocol.Wildcards.Flag;
import org.openflow.protocol.action.OFAction;
*/
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;


import net.onrc.openvirtex.elements.Mappable;
import net.onrc.openvirtex.elements.OVXMap;
import net.onrc.openvirtex.exceptions.IndexOutOfBoundException;
import net.onrc.openvirtex.exceptions.AddressMappingException;
import net.onrc.openvirtex.exceptions.NetworkMappingException;
import net.onrc.openvirtex.messages.actions.OVXActionNetworkLayerDestination;
import net.onrc.openvirtex.messages.actions.OVXActionNetworkLayerSource;

/**
 * Utility class for IP mapping operations. Implements methods
 * rewrite or add actions for IP translation.
 */
public final class IPMapper {
    private static Logger log = LogManager.getLogger(IPMapper.class.getName());

    /**
     * Overrides default constructor to no-op private constructor.
     * Required by checkstyle.
     */
    private IPMapper() {
    }

    public static Integer getPhysicalIp(Integer tenantId, Integer virtualIP) {
        final Mappable map = OVXMap.getInstance();
        final OVXIPAddress vip = new OVXIPAddress(tenantId, virtualIP);
        try {
            PhysicalIPAddress pip;
            if (map.hasPhysicalIP(vip, tenantId)) {
                pip = map.getPhysicalIP(vip, tenantId);
            } else {
                pip = new PhysicalIPAddress(map.getVirtualNetwork(tenantId)
                        .nextIP());
                log.debug("Adding IP mapping {} -> {} for tenant {}", vip, pip,
                        tenantId);
                map.addIP(pip, vip);
            }
            return pip.getIp();
        } catch (IndexOutOfBoundException e) {
            log.error(
                    "No available physical IPs for virtual ip {} in tenant {}",
                    vip, tenantId);
        } catch (NetworkMappingException e) {
            log.error(e);
        } catch (AddressMappingException e) {
            log.error("Inconsistency in Physical-Virtual mapping : {}", e);
        }
        return 0;
    }

    //yk
    //public static void rewriteMatch(final Integer tenantId, final OFMatch match) {
    public static void rewriteMatch(final Integer tenantId, final Match match) {
        match.setNetworkSource(getPhysicalIp(tenantId, match.getNetworkSource()));
        match.setNetworkDestination(getPhysicalIp(tenantId,
                match.getNetworkDestination()));
    }

    //yk
    //public static List<OFAction> prependRewriteActions(final Integer tenantId,
    //        final OFMatch match) {
    public static List<OFAction> prependRewriteActions(final Integer tenantId,
            final Match match) {
    	final List<OFAction> actions = new LinkedList<OFAction>();
    	
    	//yk
    	//if (!match.getWildcardObj().isWildcarded(Flag.NW_SRC)) {
        if (!match.isPartiallyMasked(MatchField.IPV4_SRC)) {
            final OVXActionNetworkLayerSource srcAct = new OVXActionNetworkLayerSource();
            //yk
            //srcAct.setNetworkAddress(getPhysicalIp(tenantId,
            //        match.getNetworkSource()));
            srcAct.setNetworkAddress(getPhysicalIp(tenantId,
                    match.get(MatchField.IPV4_SRC)));
            actions.add(srcAct);
        }
        
        //yk
        //if (!match.getWildcardObj().isWildcarded(Flag.NW_DST)) {
        if (!match.isPartiallyMasked(MatchField.IPV4_DST)) {
            final OVXActionNetworkLayerDestination dstAct = new OVXActionNetworkLayerDestination();
            
            //yk
            //dstAct.setNetworkAddress(getPhysicalIp(tenantId,
            //        match.getNetworkDestination()));
            dstAct.setNetworkAddress(getPhysicalIp(tenantId,
                    match.get(MatchField.IPV4_DST)));
            actions.add(dstAct);
        }
        return actions;
    }

    //yk
    //public static List<OFAction> prependUnRewriteActions(final OFMatch match) {
    public static List<OFAction> prependUnRewriteActions(final Match match) {
    	
        final List<OFAction> actions = new LinkedList<OFAction>();
    	//yk
    	//if (!match.getWildcardObj().isWildcarded(Flag.NW_SRC)) {
    	if (!match.isPartiallyMasked(MatchField.IPV4_SRC)) {
            final OVXActionNetworkLayerSource srcAct = new OVXActionNetworkLayerSource();
            //yk
            //srcAct.setNetworkAddress(match.getNetworkSource());
            srcAct.setNetworkAddress(match.get(MatchField.IPV4_SRC));
            actions.add(srcAct);
        }
    	//yk
    	//if (!match.getWildcardObj().isWildcarded(Flag.NW_DST)) {
    	if (!match.isPartiallyMasked(MatchField.IPV4_DST)) {
            final OVXActionNetworkLayerDestination dstAct = new OVXActionNetworkLayerDestination();
            //yk
            //dstAct.setNetworkAddress(match.getNetworkDestination());
            dstAct.setNetworkAddress(match.get(MatchField.IPV4_DST));
            actions.add(dstAct);
        }
        return actions;
    }
}
