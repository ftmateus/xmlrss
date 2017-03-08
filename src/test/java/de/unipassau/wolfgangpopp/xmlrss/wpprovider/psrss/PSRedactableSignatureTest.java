/*
 * XMLRSS - A Java Crypto Provider for Redactable Signatures and their
 * XML Signature encoding.
 *
 * Copyright (c) 2016 Wolfgang Popp
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

package de.unipassau.wolfgangpopp.xmlrss.wpprovider.psrss;

import de.unipassau.wolfgangpopp.xmlrss.wpprovider.RedactableSignature;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.SignatureOutput;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.WPProvider;
import org.junit.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.SignatureException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * @author Wolfgang Popp
 */
public class PSRedactableSignatureTest {

    private static KeyPair keyPair;

    static {
        Security.insertProviderAt(new WPProvider(), 0);
        KeyPairGenerator generator = null;
        try {
            generator = KeyPairGenerator.getInstance("PSRSS");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        generator.initialize(512);
        keyPair = generator.generateKeyPair();
    }


    public PSRedactableSignatureTest() throws NoSuchAlgorithmException {
    }

    @Test
    public void getInstance() throws Exception {
        RedactableSignature rss1 = RedactableSignature.getInstance("RSSwithPSA");
        assertEquals(rss1.getAlgorithm(), "RSSwithPSA");
    }

    @Test
    public void engineSign() throws Exception {
        RedactableSignature rssWithPSA = RedactableSignature.getInstance("RSSwithPSA");
        rssWithPSA.initSign(keyPair);

        rssWithPSA.addPart("test1".getBytes(), false);
        rssWithPSA.addPart("test2".getBytes(), false);

        SignatureOutput signature = rssWithPSA.sign();

        assertTrue(signature.containsAll("test1".getBytes(), "test2".getBytes()));
    }

    @Test
    public void engineVerify() throws Exception {
        RedactableSignature rssWithPSA = RedactableSignature.getInstance("RSSwithPSA");
        rssWithPSA.initSign(keyPair);

        rssWithPSA.addPart("test3".getBytes(), false);
        rssWithPSA.addPart("test2".getBytes(), false);
        rssWithPSA.addPart("test4".getBytes(), false);

        SignatureOutput signature = rssWithPSA.sign();

        rssWithPSA.initVerify(keyPair.getPublic());
        assertTrue(rssWithPSA.verify(signature));
    }

    @Test
    public void engineRedact() throws Exception {
        byte[][] message = {
                "test1".getBytes(),
                "test2".getBytes(),
                "test3".getBytes(),
                "test4".getBytes(),
                "test5".getBytes(),
        };

        byte[][] toRedact = {
                "test1".getBytes(),
                "test2".getBytes(),
        };

        RedactableSignature rss = RedactableSignature.getInstance("RSSwithPSA");
        rss.initSign(keyPair);
        rss.addParts(message);

        SignatureOutput signedMessage = rss.sign();

        rss.initRedact(keyPair.getPublic());
        rss.addParts(toRedact);
        SignatureOutput redactedMessage = rss.redact(signedMessage);

        rss.initVerify(keyPair.getPublic());
        assertTrue(rss.verify(redactedMessage));
        assertFalse(redactedMessage.contains(toRedact[0]));
        assertFalse(redactedMessage.contains(toRedact[1]));
    }

    @Test
    public void engineMerge() throws Exception {
        byte[][] message = {
                "test1".getBytes(),
                "test2".getBytes(),
                "test3".getBytes(),
                "test4".getBytes(),
                "test5".getBytes(),
        };

        RedactableSignature rss = RedactableSignature.getInstance("RSSwithPSA");

        rss.initSign(keyPair);
        rss.addParts(message);
        SignatureOutput wholeMessage = rss.sign();

        rss.initRedact(keyPair.getPublic());
        rss.addPart("test4".getBytes());
        rss.addPart("test5".getBytes());
        SignatureOutput redacted1 = rss.redact(wholeMessage);

        rss.initRedact(keyPair.getPublic());
        rss.addPart("test2".getBytes());
        rss.addPart("test3".getBytes());
        SignatureOutput redacted2 = rss.redact(wholeMessage);

        rss.initMerge(keyPair.getPublic());
        SignatureOutput merged = rss.merge(redacted1, redacted2);
    }

    @Test
    public void engineUpdate() throws Exception {
        RedactableSignature rss = RedactableSignature.getInstance("RSSwithPSA");

        rss.initSign(keyPair);
        rss.addPart("test1".getBytes(), false);
        rss.addPart("test2".getBytes(), false);
        rss.addPart("test3".getBytes(), false);
        SignatureOutput signedMessage = rss.sign();

        rss.initUpdate(keyPair);
        rss.addPart("test4".getBytes(), false);
        rss.addPart("test5".getBytes(), false);
        SignatureOutput updated = rss.update(signedMessage);

        rss.initVerify(keyPair.getPublic());
        assertTrue(rss.verify(updated));
    }
}