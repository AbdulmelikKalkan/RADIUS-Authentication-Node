/**
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright (c) 2007 Sun Microsystems Inc. All Rights Reserved
 *
 * The contents of this file are subject to the terms
 * of the Common Development and Distribution License
 * (the License). You may not use this file except in
 * compliance with the License.
 *
 * You can obtain a copy of the License at
 * https://opensso.dev.java.net/public/CDDLv1.0.html or
 * opensso/legal/CDDLv1.0.txt
 * See the License for the specific language governing
 * permission and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL
 * Header Notice in each file and include the License file
 * at opensso/legal/CDDLv1.0.txt.
 * If applicable, add the following below the CDDL Header,
 * with the fields enclosed by brackets [] replaced by
 * your own identifying information:
 * "Portions Copyrighted [year] [name of copyright owner]"
 *
 * $Id: AccessAccept.java,v 1.2 2008/06/25 05:42:00 qcheng Exp $
 *
 */

/*
 * Portions Copyrighted [2011] [ForgeRock AS]
 * Portions Copyrighted [2015] [Intellectual Reserve, Inc (IRI)]
 */
package org.forgerock.openam.RadiusNode.common.packet;

import org.forgerock.openam.RadiusNode.common.Attribute;
import org.forgerock.openam.RadiusNode.common.AttributeType;
import org.forgerock.openam.RadiusNode.common.OctetUtils;

/**
 * Class representing the structure of the Filter-Id attribute as specified in section 5.11 of RFC 2865 and
 * able to be instantiated from the on-the-wire bytes or from its text value.
 */
public class FilterIdAttribute extends Attribute {
    /**
     * The filter id string.
     */
    private String filterId = null;

    /**
     * Constructs a new instance from the filter string to be embedded. Since attribute fields in a radius packet are
     * limited to 256 octets in length the string will be truncated accordingly if it exceeds 254 bytes due to the
     * preceding attriute type code octet and attribute length octets being included in the overall attribute length.
     *
     * @param filter the filter id
     */
    public FilterIdAttribute(String filter) {
        super(OctetUtils.toOctets(AttributeType.FILTER_ID, filter));
        filterId = new String(super.getOctets(), 2, super.getOctets().length - 2);
    }

    /**
     * Constructs a new instance from the on-the-wire bytes for this attribute including the prefixing attribute-type
     * code octet and length octet.
     *
     * @param octets the on-the-wire bytes from which to construct this instance
     */
    public FilterIdAttribute(byte[] octets) {
        super(octets);
        this.filterId = new String(octets, 2, octets.length - 2);
    }

    /**
     * Returns the filter id.
     * @return the filter id.
     */
    public String getFilterId() {
        return filterId;
    }

    /**
     * Used by super class to log the attribute's contents when packet logging is enabled.
     *
     * @return content representation for traffic logging
     */
    public String toStringImpl() {

        return filterId;
    }
}
