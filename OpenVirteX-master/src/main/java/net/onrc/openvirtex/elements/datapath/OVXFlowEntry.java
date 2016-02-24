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
package net.onrc.openvirtex.elements.datapath;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import net.onrc.openvirtex.messages.OVXFlowMod;
import net.onrc.openvirtex.protocol.OVXMatch;
import net.onrc.openvirtex.util.MACAddress;

//yk
//import org.openflow.protocol.OFMatch;
//import org.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.match.*;

//by
import org.projectfloodlight.openflow.protocol.OFFlowWildcards;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.ver13.OFMatchV3Ver13;
import org.projectfloodlight.openflow.protocol.ver11.OFMatchV2Ver11;

/**
 * Class representing a virtual flow entry - a wrapper for FlowMods that enables
 * the flow table to do matching on contents.
 */
public class OVXFlowEntry implements Comparable<OVXFlowEntry> {

    /* relation of this FlowEntry to another FlowEntry during comparison */
    public static final int EQUAL = 0; // exactly same
    public static final int SUPERSET = 1; // more general
    public static final int SUBSET = 2; // more specific
    public static final int INTERSECT = 3; // mix of wildcards and matching fields
    public static final int DISJOINT = 4; // non-matching non-wildcarded fields

    // The FlowMod this Entry represents
    protected OVXFlowMod flowmod;
    // The newly generated cookie for the FlowMod
    protected long newcookie;

    public OVXFlowEntry() {
    }

    public OVXFlowEntry(OVXFlowMod fm, long cookie) {
        this.flowmod = fm.clone();
        this.newcookie = cookie;
    }

    /**
     * Compares this entry against another, and tries to determine if it is a
     * superset, subset, or equal to it. Required for non-strict matching and
     * overlap checking
     * <p>
     * For each field, we first check wildcard equality. If both are equal, they
     * are either 1 or 0. If 0, we further check for field equality. If the
     * fields are not equal, the flow entries are considered disjoint and we
     * exit comparison.
     * <p>
     * If both wildcards are not equal, we check if one subsumes the other.
     * <p>
     * The result is tracked for each field in three ints - equality, superset,
     * and subset. At the end, either 1) one of the ints are 0x3fffff, or 2)
     * none are.
     *
     * @param omatch
     *            The other FlowEntry to compare this one against.
     * @param strict
     *            whether FlowMod from which the match came was strict or not.
     * @return Union enum representing the relationship
     */
    
    //yk
    //public int compare(OFMatch omatch, boolean strict) {
    public int compare(Match omatch, boolean strict) {
        // to allow pass by reference...in order: equal, superset, subset
        int[] intersect = new int[] {0, 0, 0};

        //yk
        //OFMatch tmatch = this.flowmod.getMatch();
        //Match tmatch = this.flowmod.getMatch();

        //by
        OFMatchV2Ver11 tmatch = (OFMatchV2Ver11) this.flowmod.getMatch();
        
        int twcard = tmatch.getWildcards();
        int owcard = this.convertToWcards(omatch);
        
        /* inport */
        //yk
        //if ((twcard & OFMatch.OFPFW_IN_PORT) == (owcard & OFMatch.OFPFW_IN_PORT)) {
        if ((tmatch.isPartiallyMasked(MatchField.IN_PORT)) == (omatch.isPartiallyMasked(MatchField.IN_PORT))) {
            
        	//yk
        	//if (findDisjoint(twcard, OFMatch.OFPFW_IN_PORT, intersect,
            //        tmatch.getInputPort(), omatch.getInputPort())) {
            if (findDisjoint(twcard, OFFlowWildcards.IN_PORT.ordinal(), intersect,
                    tmatch.get(MatchField.IN_PORT).getPortNumber(),
                    omatch.get(MatchField.IN_PORT).getPortNumber())) {
                return DISJOINT;
            }
        } else { /* check if super or subset */
        	//by
            //findRelation(twcard, owcard, OFMatch.OFPFW_IN_PORT, intersect);
        	findRelation(twcard, owcard, OFFlowWildcards.IN_PORT, intersect);
        }

        /* L2 */
        //by
//        if ((twcard & OFMatch.OFPFW_DL_DST) == (owcard & OFMatch.OFPFW_DL_DST)) {      
//            if (findDisjoint(twcard, OFMatch.OFPFW_DL_DST, intersect,
//                    tmatch.getDataLayerDestination(),
//                    omatch.getDataLayerDestination())) {
        if ((twcard & OFFlowWildcards.DL_DST.ordinal()) == (owcard & OFFlowWildcards.DL_DST.ordinal())) {
        	if (findDisjoint(twcard, OFFlowWildcards.DL_DST, intersect,
        			tmatch.getEthDst().getBytes(),
        			omatch.get(MatchField.ETH_DST).getBytes())) {
                return DISJOINT;
            }
        } else { /* check if super or subset */
//            findRelation(twcard, owcard, OFMatch.OFPFW_DL_DST, intersect);
        	findRelation(twcard, owcard, OFFlowWildcards.DL_DST, intersect);
        }
//        if ((twcard & OFMatch.OFPFW_DL_SRC) == (owcard & OFMatch.OFPFW_DL_SRC)) {
        if ((twcard & OFFlowWildcards.DL_SRC.ordinal()) == (owcard & OFFlowWildcards.DL_SRC.ordinal())) {
//            if (findDisjoint(twcard, OFMatch.OFPFW_DL_SRC, intersect,
        	if (findDisjoint(twcard, OFFlowWildcards.DL_SRC, intersect,
//                    tmatch.getDataLayerSource(), omatch.getDataLayerSource())) {
        			tmatch.get(MatchField.ETH_SRC).getBytes(), omatch.get(MatchField.ETH_SRC).getBytes())) {
                return DISJOINT;
            }
        } else { /* check if super or subset */
//            findRelation(twcard, owcard, OFMatch.OFPFW_DL_SRC, intersect);
        	findRelation(twcard, owcard, OFFlowWildcards.DL_SRC, intersect);
        }
//        if ((twcard & OFMatch.OFPFW_DL_TYPE) == (owcard & OFMatch.OFPFW_DL_TYPE)) {
        if ((twcard & OFFlowWildcards.DL_TYPE.ordinal()) == (owcard & OFFlowWildcards.DL_TYPE.ordinal())) {
//            if (findDisjoint(twcard, OFMatch.OFPFW_DL_TYPE, intersect,
        	if (findDisjoint(twcard, OFFlowWildcards.DL_TYPE.ordinal(), intersect,
                    tmatch.get(MatchField.ETH_TYPE).getValue(), omatch.get(MatchField.ETH_TYPE).getValue())) {
                return DISJOINT;
            }
        } else { /* check if super or subset */
//            findRelation(twcard, owcard, OFMatch.OFPFW_DL_TYPE, intersect);
        	findRelation(twcard, owcard, OFFlowWildcards.DL_TYPE, intersect);
        }
//        if ((twcard & OFMatch.OFPFW_DL_VLAN) == (owcard & OFMatch.OFPFW_DL_VLAN)) {
        if ((twcard & OFFlowWildcards.DL_VLAN.ordinal()) == (owcard & OFFlowWildcards.DL_VLAN.ordinal())) {
//            if (findDisjoint(twcard, OFMatch.OFPFW_DL_VLAN, intersect,
        	if (findDisjoint(twcard, OFFlowWildcards.DL_VLAN.ordinal(), intersect,
//                    tmatch.getDataLayerVirtualLan(),
//                    omatch.getDataLayerVirtualLan())) {
        			tmatch.get(MatchField.VLAN_VID).getVlan(),
        			omatch.get(MatchField.VLAN_VID).getVlan())) {
                return DISJOINT;
            }
        } else { /* check if super or subset */
//            findRelation(twcard, owcard, OFMatch.OFPFW_DL_VLAN, intersect);
        	findRelation(twcard, owcard, OFFlowWildcards.DL_VLAN, intersect);
        }
//        if ((twcard & OFMatch.OFPFW_DL_VLAN_PCP) == (owcard & OFMatch.OFPFW_DL_VLAN_PCP)) {
        if ((twcard & OFFlowWildcards.DL_VLAN_PCP.ordinal()) == (owcard & OFFlowWildcards.DL_VLAN_PCP.ordinal())) {
//            if (findDisjoint(twcard, OFMatch.OFPFW_DL_VLAN_PCP, intersect,
//                    tmatch.getDataLayerVirtualLanPriorityCodePoint(),
//                    omatch.getDataLayerVirtualLanPriorityCodePoint())) {
        	if (findDisjoint(twcard, OFFlowWildcards.DL_VLAN_PCP.ordinal(), intersect,
                    tmatch.get(MatchField.VLAN_PCP).getValue(),
                    omatch.get(MatchField.VLAN_PCP).getValue())) {
                return DISJOINT;
            }
        } else { /* check if super or subset */
//            findRelation(twcard, owcard, OFMatch.OFPFW_DL_VLAN_PCP, intersect);
        	findRelation(twcard, owcard, OFFlowWildcards.DL_VLAN_PCP, intersect);
        }

        /* L3 */
//        if ((twcard & OFMatch.OFPFW_NW_PROTO) == (owcard & OFMatch.OFPFW_NW_PROTO)) {
        if ((twcard & OFFlowWildcards.NW_PROTO.ordinal()) == (owcard & OFFlowWildcards.NW_PROTO.ordinal())) {
            if (findDisjoint(twcard, OFFlowWildcards.NW_PROTO, intersect,
//                    tmatch.getNetworkProtocol(), omatch.getNetworkProtocol())) {
            	tmatch.get(MatchField.IP_PROTO).getIpProtocolNumber(), omatch.get(MatchField.IP_PROTO).getIpProtocolNumber())) {
                return DISJOINT;
            }
        } else { /* check if super or subset */
            findRelation(twcard, owcard, OFFlowWildcards.NW_PROTO, intersect);
        }
        if ((twcard & OFFlowWildcards.NW_TOS.ordinal()) == (owcard & OFFlowWildcards.NW_TOS.ordinal())) {
            if (findDisjoint(twcard, OFFlowWildcards.NW_TOS, intersect,
//                    tmatch.getNetworkTypeOfService(),
//                    omatch.getNetworkTypeOfService())) {
            		tmatch.get(MatchField.IP_DSCP).getDscpValue(),
            		omatch.get(MatchField.IP_DSCP).getDscpValue())) {
                return DISJOINT;
            }
        } else { /* check if super or subset */
            findRelation(twcard, owcard, OFFlowWildcards.NW_TOS, intersect);
        }
        if ((twcard & OFFlowWildcards.NW_DST_ALL.ordinal()) == (owcard & OFFlowWildcards.NW_DST_ALL.ordinal())) {
            if (findDisjoint(twcard,
                    (OFFlowWildcards.NW_DST_ALL.ordinal() | OFFlowWildcards.NW_DST_MASK.ordinal()),
//                    intersect, tmatch.getNetworkDestination(),
//                    omatch.getNetworkDestination())) {
                    intersect, tmatch.get(MatchField.IPV4_DST).getBytes(),
                    omatch.get(MatchField.IPV4_DST).getBytes())) {

                return DISJOINT;
            }
        } else { /* check if super or subset */
            findRelation(twcard, owcard, OFFlowWildcards.NW_DST_ALL.ordinal()
                    | OFFlowWildcards.NW_DST_MASK.ordinal(), intersect);
        }
        if ((twcard & OFFlowWildcards.NW_SRC_ALL.ordinal()) == (owcard & OFFlowWildcards.NW_SRC_ALL.ordinal())) {
            if (findDisjoint(twcard,
                    (OFFlowWildcards.NW_SRC_ALL.ordinal() | OFFlowWildcards.NW_SRC_MASK.ordinal()),
//                    intersect, tmatch.getNetworkSource(),
//                    omatch.getNetworkSource())) {
                    intersect, tmatch.get(MatchField.IPV4_SRC).getBytes(),
                    omatch.get(MatchField.IPV4_SRC).getBytes())) {
                return DISJOINT;
            }
        } else { /* check if super or subset */
            findRelation(twcard, owcard, OFFlowWildcards.NW_SRC_ALL.ordinal()
                    | OFFlowWildcards.NW_SRC_MASK.ordinal(), intersect);
        }

        /* L4 */
        if ((twcard & OFFlowWildcards.TP_SRC.ordinal()) == (owcard & OFFlowWildcards.TP_SRC.ordinal())) {
            if (findDisjoint(twcard, OFFlowWildcards.TP_SRC, intersect,
//                    tmatch.getTransportSource(), omatch.getTransportSource())) {
            		tmatch.get(MatchField.TCP_SRC).getPort(), omatch.get(MatchField.TCP_SRC).getPort())) {
                return DISJOINT;
            }
        } else { /* check if super or subset */
            findRelation(twcard, owcard, OFFlowWildcards.TP_SRC, intersect);
        }
        if ((twcard & OFFlowWildcards.TP_DST.ordinal()) == (owcard & OFFlowWildcards.TP_DST.ordinal())) {
            if (findDisjoint(twcard, OFFlowWildcards.TP_DST, intersect,
//                    tmatch.getTransportDestination(),
//                    omatch.getTransportDestination())) {
            		 tmatch.get(MatchField.TCP_DST).getPort(),
                     omatch.get(MatchField.TCP_DST).getPort())) {
                return DISJOINT;
            }
        } else { /* check if super or subset */
            findRelation(twcard, owcard, OFFlowWildcards.TP_DST, intersect);
        }

        int equal = intersect[EQUAL];
        int superset = intersect[SUPERSET];
        int subset = intersect[SUBSET];

        if (!strict) {
            equal |= subset;
        }
        if (equal == OFFlowWildcards.ALL.ordinal()) {
            return EQUAL;
        }
        if (superset == OFFlowWildcards.ALL.ordinal()) {
            return SUPERSET;
        }
        if (subset == OFFlowWildcards.ALL.ordinal()) {
            return SUBSET;
        }
        return INTERSECT;
    }

    /**
     * Checks for "ANY" values that should be wildcards but aren't, such as
     * NW_SRC/DST 0.0.0.0, and TCP/UDP port 0.
     *
     * @param omatch
     *            The OFMatch of the FlowMod we are comparing entries against
     * @param owcard
     *            The wildcard field of the FlowMod.
     * @return the modified wildcard value (a copy).
     */
    private int convertToWcards(Match omatch) {
//by
    	//        int owcard = omatch.getWildcards();
    	int owcard = ((OFMatchV2Ver11) omatch).getWildcards();
//        if (omatch.getNetworkDestination() == 0) {
    	if (omatch.get(MatchField.IPV4_DST).getInt() == 0) {
            owcard |= OFFlowWildcards.NW_DST_ALL.ordinal() | OFFlowWildcards.NW_DST_MASK.ordinal();
        }
//        if (omatch.getNetworkSource() == 0) {
    	if (omatch.get(MatchField.IPV4_SRC).getInt() == 0) {
            owcard |= OFFlowWildcards.NW_SRC_ALL.ordinal() | OFFlowWildcards.NW_SRC_MASK.ordinal();
        }
//        if (omatch.getNetworkProtocol() == 0) {
    	if (omatch.get(MatchField.IP_PROTO).getIpProtocolNumber() == 0) {
            owcard |= OFFlowWildcards.NW_PROTO.ordinal();
        }
//        if (omatch.getTransportDestination() == 0) {
    	if (omatch.get(MatchField.TCP_DST).getPort() == 0) {
            owcard |= OFFlowWildcards.TP_DST.ordinal();
        }
//        if (omatch.getTransportSource() == 0) {
    	if (omatch.get(MatchField.TCP_SRC).getPort() == 0) {
            owcard |= OFFlowWildcards.TP_SRC.ordinal();
        }
        return owcard;
    }

    /**
     * determine if a field is not equal-valued, for non-array fields first
     * checks if the OFMatch wildcard is fully wildcarded for the field. If not,
     * it checks the equality of the field value.
     *
     * @param wcard
     * @param field
     * @param equal
     * @param val1
     * @param val2
     * @return true if disjoint FlowEntries
     */
    
    //yk
//    private boolean findDisjoint(int wcard, int field, int[] intersect,
//    //private boolean findDisjoint(Match tmatch, MatchField field, int[] intersect,
    //by
    private boolean findDisjoint(int wcard, int field, int[] intersect,
    		//Number val1, Number val2) {
    		int val1, int val2){
        //if (((wcard & field)== field ) || (val1.equals(val2))) {
    	if (((wcard & field)== field ) || (val1 == val2)) {
            updateIntersect(intersect, field);
            return false;
            
        }
        return true;
    }
    
<<<<<<< HEAD
=======
    private boolean findDisjoint(int wcard, OFFlowWildcards field, int[] intersect,
    		int val1, int val2){
    	return findDisjoint(wcard, field.ordinal(), intersect, val1, val2);
    }
    
>>>>>>> refs/remotes/origin/OVX-loxigen-yk

    /**
     * determine if fields are disjoint, for byte arrays.
     *
     * @param wcard
     * @param field
     * @param equal
     * @param val1
     * @param val2
     * @return
     */
    private boolean findDisjoint(int wcard, int field, int[] intersect,
            byte[] val1, byte[] val2) {
        if ((wcard & field) == field) {
            updateIntersect(intersect, field);
            return false;
        }
        for (int i = 0; i < MACAddress.MAC_ADDRESS_LENGTH; i++) {
            if (val1[i] != val2[i]) {
                return true;
            }
        }
        updateIntersect(intersect, field);
        return false;
    }
    
//by
    private boolean findDisjoint(int wcard, OFFlowWildcards field, int[] intersect, 
    		byte[] val1, byte[] val2) {
    	return findDisjoint(wcard, field.ordinal(), intersect, val1, val2);
    }

    private void updateIntersect(int[] intersect, int field) {
        intersect[EQUAL] |= field;
        intersect[SUPERSET] |= field;
        intersect[SUBSET] |= field;
    }

    /**
     * Determines if one or the other field is wildcarded. If this flow entry's
     * field is wildcarded i.e. its wildcard value for the field is bigger, we
     * are superset; Else, we are subset.
     *
     * @param wcard1
     *            our wildcard field
     * @param wcard2
     *            other wildcard field
     * @param field
     *            OFMatch wildcard value
     * @param intersect
     *            intersection sets
     */
    private void findRelation(int wcard1, int wcard2, int field, int[] intersect) {
        if ((wcard1 & field) > (wcard2 & field)) {
            intersect[SUPERSET] |= field;
        } else {
            intersect[SUBSET] |= field;
        }
    }
    
    //by
    private void findRelation(int wcard1, int wcard2, OFFlowWildcards field, int[] intersect) {
        findRelation(wcard1, wcard2, field.ordinal(), intersect);
    }

    /** @return original OFMatch */
    public Match getMatch() {
        return this.flowmod.getMatch();
    }

    /** @return the virtual output port */
    public short getOutport() {
        return this.flowmod.getOutPort().getShortPortNumber();
    }

    public short getPriority() {
        return (short) this.flowmod.getPriority();
    }

    public OVXFlowMod getFlowMod() {
        return this.flowmod;
    }

    public OVXFlowEntry setFlowMod(OVXFlowMod fm) {
        this.flowmod = fm;
        return this;
    }

    /**
     * @return The new (Physical) cookie
     */
    public long getNewCookie() {
        return this.newcookie;
    }

    /**
     * Sets the new cookie for this entry.
     *
     * @param cookie the cookie
     */
    public OVXFlowEntry setNewCookie(Long cookie) {
        this.newcookie = cookie;
        return this;
    }

    /**
     * Gets the cookie associated with this flow entry.
     *
     * @return The original (virtual) cookie
     */
    public long getCookie() {
        return this.flowmod.getCookie().getValue();
    }

    public List<OFAction> getActionsList() {
        return this.flowmod.getActions();
    }

    /*
     * (non-Javadoc)
     *
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * this.flowmod.hashCode();
        result = prime * result + (int) (newcookie ^ (newcookie >>> 32));
        return result;
    }

    /*
     * (non-Javadoc)
     *
     * @see java.lang.Object#equals(java.lang.Object)
     */
    @Override
    public boolean equals(final Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (this.getClass() != obj.getClass()) {
            return false;
        }
        final OVXFlowEntry other = (OVXFlowEntry) obj;
        if (this.newcookie != other.newcookie) {
            return false;
        }
        if (this.flowmod == null) {
            if (other.flowmod != null) {
                return false;
            }
        } else if (!this.flowmod.equals(other.flowmod)) {
            return false;
        }
        return true;
    }

    /**
     * compare this FlowEntry to another FlowMod.
     *
     * @param other
     * @return
     */
    public boolean equals(final OVXFlowMod other) {
        return this.flowmod.equals(other);
    }

    @Override
    public int compareTo(final OVXFlowEntry other) {
        // sort on priority, tie break on IDs
        if (this.flowmod.getPriority() != other.flowmod.getPriority()) {
            return other.flowmod.getPriority() - this.flowmod.getPriority();
        }
        return this.hashCode() - other.hashCode();
    }

    public Map<String, Object> toMap() {
        final HashMap<String, Object> map = new LinkedHashMap<String, Object>();
        if (this.flowmod.getMatch() != null) {
            map.put("match", ((OVXMatch) this.flowmod.getMatch()).toMap());
        }
        map.put("actionsList", this.flowmod.getActions());
        map.put("priority", String.valueOf(this.flowmod.getPriority()));
        return map;
    }

    @Override
    public String toString() {
        return "OVXFlowEntry [FlowMod=" + this.flowmod + "\n" + "newcookie="
                + this.newcookie + "]";
    }
}
