/*
 * XMLRSS - A Java Crypto Provider for Redactable Signatures and their
 * XML Signature encoding.
 *
 * Copyright (c) 2017 Wolfgang Popp
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package de.unipassau.wolfgangpopp.xmlrss.wpprovider.grss;

import java.security.PrivateKey;

/**
 * @author Wolfgang Popp
 */
public class GSRSSPrivateKey extends GRSSKey implements PrivateKey {
    private final PrivateKey dsigKey;
    private final PrivateKey accKey;

    public GSRSSPrivateKey(String algorithm, PrivateKey dsigKey, PrivateKey accKey) {
        super(algorithm);
        this.dsigKey = dsigKey;
        this.accKey = accKey;
    }

    public PrivateKey getDSigKey() {
        return dsigKey;
    }

    public PrivateKey getAccumulatorKey() {
        return accKey;
    }
}
