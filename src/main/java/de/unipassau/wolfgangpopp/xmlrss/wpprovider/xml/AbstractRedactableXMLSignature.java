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

package de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml;

import de.unipassau.wolfgangpopp.xmlrss.wpprovider.Identifier;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.RedactableSignature;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.RedactableSignatureException;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.SignatureOutput;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.utils.ByteArray;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.utils.XMLUtils;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.binding.Pointer;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.binding.Proof;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.binding.Reference;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.binding.Signature;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.binding.SignatureInfo;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.binding.SignatureValue;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

import javax.xml.bind.JAXBException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static de.unipassau.wolfgangpopp.xmlrss.wpprovider.utils.XMLUtils.checkNode;
import static de.unipassau.wolfgangpopp.xmlrss.wpprovider.utils.XMLUtils.getSignatureNode;

/**
 * @author Wolfgang Popp
 */
public abstract class AbstractRedactableXMLSignature<S extends SignatureValue, P extends Proof>
        extends RedactableXMLSignatureSpi {

    private final RedactableSignature rss;
    private final Class<P> proofClass;
    private final Class<S> signatureValueClass;
    private Node root;
    private final Map<ByteArray, Pointer> pointers = new HashMap<>();
    private final List<String> uris = new ArrayList<>();
    private final Set<String> redactUris = new HashSet<>();

    protected AbstractRedactableXMLSignature(RedactableSignature rss, Class<P> proofClass,
                                             Class<S> signatureValueClass) {
        super();
        this.rss = rss;
        this.proofClass = proofClass;
        this.signatureValueClass = signatureValueClass;
    }

    @Override
    public void engineInitSign(KeyPair keyPair, SecureRandom random) throws InvalidKeyException {
        reset();
        rss.initSign(keyPair, random);
    }

    @Override
    public void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        reset();
        rss.initVerify(publicKey);
    }

    @Override
    public void engineInitRedact(PublicKey publicKey) throws InvalidKeyException {
        reset();
        rss.initRedact(publicKey);
    }

    private void reset() {
        root = null;
        pointers.clear();
        uris.clear();
        redactUris.clear();
    }

    @Override
    public void engineAddSignSelector(String uri, boolean isRedactable) throws RedactableXMLSignatureException {
        if (pointers.size() < 1) {
            SignatureInfo signatureInfo = new SignatureInfo(getCanonicalizationMethod(), getRedactableSignatureMethod());

            Pointer signatureInfoPointer = new Pointer("SignatureInfo");
            Document document = XMLUtils.getOwnerDocument(root);
            byte[] pointerConcatSINode = signatureInfoPointer.concatNode(signatureInfo.marshall(document), root);
            pointers.put(new ByteArray(pointerConcatSINode), signatureInfoPointer);
            try {
                rss.addPart(pointerConcatSINode);
            } catch (RedactableSignatureException e) {
                throw new RedactableXMLSignatureException(e);
            }
        }

        Pointer pointer = new Pointer(uri, isRedactable);
        if (pointers.put(new ByteArray(pointer.concatDereference(root)), pointer) != null) {
            throw new RedactableXMLSignatureException("A URI cannot be added twice");
        }
        try {
            rss.addPart(pointer.concatDereference(root), isRedactable);
        } catch (RedactableSignatureException e) {
            throw new RedactableXMLSignatureException(e);
        }
    }

    @Override
    public void engineAddRedactSelector(String uri) throws RedactableXMLSignatureException {
        if (!redactUris.add(uri)) {
            throw new RedactableXMLSignatureException("A URI cannot be added twice");
        }
    }

    @Override
    public void engineSetRootNode(Node root) {
        this.root = root;
    }

    @Override
    public Document engineSign() throws RedactableXMLSignatureException {
        if (root == null) {
            throw new RedactableXMLSignatureException("root node not set");
        }

        SignatureOutput output;
        try {
            output = rss.sign();
        } catch (RedactableSignatureException e) {
            throw new RedactableXMLSignatureException(e);
        }

        return marshall(output);
    }

    @Override
    public boolean engineVerify() throws RedactableXMLSignatureException {
        if (root == null) {
            throw new RedactableXMLSignatureException("root node not set");
        }
        checkNode(getSignatureNode(root).getFirstChild(), "SignatureInfo");
        try {
            return rss.verify(unmarshall());
        } catch (RedactableSignatureException e) {
            throw new RedactableXMLSignatureException(e);
        }
    }

    @Override
    public Document engineRedact() throws RedactableXMLSignatureException {
        if (root == null) {
            throw new RedactableXMLSignatureException("root node not set");
        }
        SignatureOutput redacted;
        SignatureOutput original = unmarshall();

        if (!checkRedactUris()) {
            throw new RedactableXMLSignatureException("Cannot perform redaction. Invalid redaction detected");
        }

        for (String uri : redactUris) {
            Pointer pointer = new Pointer(uri, true);
            try {
                rss.addIdentifier(createIdentifier(pointer.concatDereference(root), uris.indexOf(uri)));
            } catch (RedactableSignatureException e) {
                throw new RedactableXMLSignatureException(e);
            }
        }

        try {
            redacted = rss.redact(original);
        } catch (RedactableSignatureException e) {
            throw new RedactableXMLSignatureException(e);
        }

        removeNodes(root, redactUris);
        root.removeChild(getSignatureNode(root));

        return marshall(redacted);
    }

    private boolean checkRedactUris() {
        for (Pointer pointer : pointers.values()) {
            if (!pointer.isRedactable()) {
                return false;
            }
        }
        return true;
    }

    protected Pointer getPointerForMessagePart(byte[] messagePart) {
        return pointers.get(new ByteArray(messagePart));
    }

    protected byte[] getMessagePartForPointer(Pointer pointer) throws RedactableXMLSignatureException {
        return pointer.concatDereference(root);
    }

    private Document marshall(SignatureOutput output) throws RedactableXMLSignatureException {
        Signature<S, P> sigElement = new Signature<>(proofClass, signatureValueClass);

        sigElement.setSignatureValue(marshallSignatureValue(output))
                .setSignatureInfo(new SignatureInfo(getCanonicalizationMethod(), getRedactableSignatureMethod()));

        for (Reference<P> reference : marshallReferences(output)) {
            sigElement.addReference(reference);
        }

        Document ownerDocument = XMLUtils.getOwnerDocument(root);
        Node signature = sigElement.marshall(ownerDocument);
        root.appendChild(signature);
        return ownerDocument;
    }

    private SignatureOutput unmarshall() throws RedactableXMLSignatureException {
        return convertSignature(unmarshallXML());
    }

    private Signature<S, P> unmarshallXML() throws RedactableXMLSignatureException {
        Node signatureNode = getSignatureNode(root);
        Signature<S, P> signature = new Signature<>(proofClass, signatureValueClass);
        return signature.unmarshall(signatureNode);
    }

    private SignatureOutput convertSignature(Signature<S, P> signature) throws RedactableXMLSignatureException {
        List<Reference<P>> references = signature.getReferences();
        prepareUnmarshallSignatureValue(references.size(), signature.getSignatureValue());

        for (int i = 0; i < references.size(); i++) {
            Pointer pointer = references.get(i).getPointer();
            pointers.put(new ByteArray(pointer.concatDereference(root)), pointer);
            uris.add(pointer.getUri());
            P proof = references.get(i).getProof();
            prepareUnmarshallReference(references.size(), i, pointer, proof);
        }

        return doUnmarshall();
    }

    protected abstract String getRedactableSignatureMethod();

    protected abstract String getCanonicalizationMethod();

    protected abstract S marshallSignatureValue(SignatureOutput signatureOutput) throws RedactableXMLSignatureException;

    protected abstract Collection<Reference<P>> marshallReferences(SignatureOutput signatureOutput)
            throws RedactableXMLSignatureException;

    protected abstract Identifier createIdentifier(byte[] messagePart, int index) throws RedactableXMLSignatureException;

    protected abstract void prepareUnmarshallReference(int messageSize, int index, Pointer pointer, P proof)
            throws RedactableXMLSignatureException;

    protected abstract void prepareUnmarshallSignatureValue(int messageSize, S signatureValue)
            throws RedactableXMLSignatureException;

    protected abstract SignatureOutput doUnmarshall() throws RedactableXMLSignatureException;
}
