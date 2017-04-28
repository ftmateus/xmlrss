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

package de.unipassau.wolfgangpopp.xmlrss.wpprovider.grss.xml;

import de.unipassau.wolfgangpopp.xmlrss.wpprovider.Identifier;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.RedactableSignature;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.RedactableSignatureException;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.grss.GSRSSSignatureOutput;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.utils.ByteArray;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.Pointer;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.RedactableXMLSignatureException;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.RedactableXMLSignatureSpi;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.Reference;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.Signature;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

import javax.xml.bind.JAXBException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.ListIterator;
import java.util.Set;

/**
 * @author Wolfgang Popp
 */
public class GSRedactableXMLSignature extends RedactableXMLSignatureSpi {

    private final RedactableSignature gsrss;
    private Node root;
    private Set<Pointer> pointers = new HashSet<>();


    protected GSRedactableXMLSignature(RedactableSignature gsrss) throws RedactableXMLSignatureException {
        super();
        this.gsrss = gsrss;
    }

    @Override
    public void engineInitSign(KeyPair keyPair, SecureRandom random) throws InvalidKeyException {
        reset();
        gsrss.initSign(keyPair, random);
    }

    @Override
    public void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        reset();
        gsrss.initVerify(publicKey);
    }

    @Override
    public void engineInitRedact(PublicKey publicKey) throws InvalidKeyException {
        reset();
        gsrss.initRedact(publicKey);
    }

    @Override
    public void engineAddSignSelector(String uri, boolean isRedactable) throws RedactableXMLSignatureException {
        Pointer pointer = new Pointer(uri, isRedactable);
        if (!pointers.add(pointer)) {
            throw new RedactableXMLSignatureException("Cannot add the given URI twice");
        }
        try {
            gsrss.addPart(pointer.getConcatDereference(root), isRedactable);
        } catch (RedactableSignatureException e) {
            throw new RedactableXMLSignatureException(e);
        }
    }

    @Override
    public void engineAddRedactSelector(String uri) throws RedactableXMLSignatureException {
        Pointer pointer = new Pointer(uri, true);
        if (!pointers.add(pointer)) {
            throw new RedactableXMLSignatureException("Cannot add the given URI twice");
        }
    }

    @Override
    public void engineSetRootNode(Node root) {
        this.root = root;
    }

    @Override
    public Document engineSign() throws RedactableXMLSignatureException {
        GSRSSSignatureOutput output;
        try {
            output = (GSRSSSignatureOutput) gsrss.sign();
        } catch (RedactableSignatureException e) {
            throw new RedactableXMLSignatureException(e);
        }

        Signature<GSSignatureValue, GSProof> sigElement = new Signature<>(GSSignatureValue.class, GSProof.class);

        for (Pointer pointer : pointers) {
            GSProof proof = new GSProof(output.getProof(new Identifier(pointer.getConcatDereference(root))));
            Reference<GSProof> reference = new Reference<>(pointer, proof);
            sigElement.addReference(reference);
        }
        sigElement.setSignatureValue(new GSSignatureValue(output.getDSigValue(), output.getAccumulatorValue()));

        try {
            return sigElement.marshall(getOwnerDocument(root));
        } catch (JAXBException e) {
            throw new RedactableXMLSignatureException(e);
        }
    }

    @Override
    public boolean engineVerify() throws RedactableXMLSignatureException {
        Signature<GSSignatureValue, GSProof> signature;
        Node signatureNode = getSignatureNode(root, "https://sec.uni-passau.de/2017/03/xmlrss");

        try {
            signature = Signature.unmarshall(GSSignatureValue.class, GSProof.class, signatureNode);
        } catch (JAXBException e) {
            throw new RedactableXMLSignatureException(e);
        }

        GSSignatureValue signatureValue = signature.getSignatureValue();
        List<Reference<GSProof>> references = signature.getReferences();
        GSRSSSignatureOutput.Builder builder = new GSRSSSignatureOutput.Builder()
                .setAccumulatorValue(signatureValue.getAccumulatorValue())
                .setDSigValue(signatureValue.getDSigValue());

        for (Reference<GSProof> reference : references) {
            Pointer pointer = reference.getPointer();
            builder.addSignedPart(new ByteArray(pointer.getConcatDereference(root)),
                    reference.getProof().getBytes(), pointer.isRedactable());
        }

        try {
            return gsrss.verify(builder.build());
        } catch (RedactableSignatureException e) {
            throw new RedactableXMLSignatureException(e);
        }
    }

    @Override
    public Document engineRedact() throws RedactableXMLSignatureException {
        Signature<GSSignatureValue, GSProof> signature;
        Node signatureNode = getSignatureNode(root, "https://sec.uni-passau.de/2017/03/xmlrss");

        try {
            signature = Signature.unmarshall(GSSignatureValue.class, GSProof.class, signatureNode);
        } catch (JAXBException e) {
            throw new RedactableXMLSignatureException(e);
        }

        List<Node> selectedNodes = new ArrayList<>(pointers.size());

        for (Pointer pointer : pointers) {
            selectedNodes.add(dereference(pointer.getUri(), root));
        }

        selectedNodes.sort(new Comparator<Node>() {
            @Override
            public int compare(Node node1, Node node2) {
                if (isDescendant(node1, node2)) {
                    return 1;
                }
                return -1;
            }
        });

        for (Node selectedNode : selectedNodes) {
            selectedNode.getParentNode().removeChild(selectedNode);
        }

        root.removeChild(signatureNode);
        ListIterator<Reference<GSProof>> it = signature.getReferences().listIterator();
        while (it.hasNext()) {
            Reference<GSProof> reference = it.next();
            if (pointers.contains(reference.getPointer())) {
                it.remove();
            }
        }

        try {
            return signature.marshall(getOwnerDocument(root));
        } catch (JAXBException e) {
            throw new RedactableXMLSignatureException(e);
        }
    }

    private void reset() {
        root = null;
        pointers.clear();
    }

    public static class GSRSSwithBPAccumulatorAndRSA extends GSRedactableXMLSignature {
        public GSRSSwithBPAccumulatorAndRSA() throws NoSuchAlgorithmException, RedactableXMLSignatureException {
            super(RedactableSignature.getInstance("GSRSSwithRSAandBPA"));
        }
    }
}