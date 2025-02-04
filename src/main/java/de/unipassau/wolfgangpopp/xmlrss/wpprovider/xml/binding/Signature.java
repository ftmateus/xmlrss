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

package de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.binding;

import de.unipassau.wolfgangpopp.xmlrss.wpprovider.grss.BPPublicKey;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.grss.GSRSSPublicKey;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.grss.GSRedactableSignature;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.grss.xml.GSSignatureValue;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.RedactableXMLSignature;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.RedactableXMLSignatureException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * The Signature class is responsible for marshalling and unmarshalling the <code>Signature</code> element of the
 * redactable signature XML encoding. The signature element is the root element of the XML encoding. The redactable XML
 * signature allows different implementations to use their own implementations of Proof and Signature value classes.
 * Those classes are denoted by the type parameters <code>S</code> and <code>P</code>.
 * <p>
 * The XSD Schema of the signature element is defined as following
 * <pre>
 * {@code
 * <element name="Signature">
 *     <complexType>
 *         <sequence>
 *             <element ref="drs:SignatureInfo"/>
 *             <element ref="drs:References"/>
 *             <element name="SignatureValue" type="anyType"/>
 *             <element name="KeyInfo" type="anyType" minOccurs="0" maxOccurs="1"/>
 *         </sequence>
 *     </complexType>
 * </element>
 * }
 * </pre>
 *
 * @author Wolfgang Popp
 */
public final class Signature<S extends SignatureValue, P extends Proof> extends BindingElement<Signature> {

    private final Class<P> proofClass;
    private final Class<S> signatureValueClass;
    private List<Reference<P>> references = new ArrayList<>();
    private S signatureValue;
    private java.security.PublicKey publicKey;
    private SignatureInfo signatureInfo;

    private final Base64.Encoder base64Encoder = Base64.getEncoder();
    private final Base64.Decoder base64Decoder = Base64.getDecoder();

    /**
     * Constructs a new signature object whose signature value and proofs are the given classes.
     *
     * @param proofClass          the class of the used proof (same as the type parameter P)
     * @param signatureValueClass the class of the used signature value (same as the type parameter S)
     */
    public Signature(Class<P> proofClass, Class<S> signatureValueClass) {
        this(proofClass, signatureValueClass, null);
    }

    public Signature(Class<P> proofClass, Class<S> signatureValueClass, PublicKey publicKey) {
        this.proofClass = proofClass;
        this.signatureValueClass = signatureValueClass;
        this.publicKey = publicKey;
    }

    /**
     * Returns the signature info element.
     *
     * @return the signature info element
     */
    public SignatureInfo getSignatureInfo() {
        return signatureInfo;
    }

    public PublicKey getPublicKey() { return publicKey; }

    /**
     * Returns the list of references.
     *
     * @return the list of references
     */
    public List<Reference<P>> getReferences() {
        return references;
    }

    /**
     * Returns the signature value.
     *
     * @return the signature value.
     */
    public S getSignatureValue() {
        return signatureValue;
    }

    /**
     * Sets the signature info.
     *
     * @param signatureInfo the signature info
     * @return this signature object
     */
    public Signature setSignatureInfo(SignatureInfo signatureInfo) {
        this.signatureInfo = signatureInfo;
        return this;
    }

    /**
     * Sets the references.
     *
     * @param reference the references
     * @return this signature object
     */
    public Signature addReference(Reference<P> reference) {
        references.add(reference);
        return this;
    }

    /**
     * Sets the signature value.
     *
     * @param signatureValue the signature value
     * @return this signature object
     */
    public Signature setSignatureValue(S signatureValue) {
        this.signatureValue = signatureValue;
        return this;
    }

    @SuppressWarnings("unchecked")
    @Override
    public Signature<S, P> unmarshall(Node node) throws RedactableXMLSignatureException {
        Node signature = checkThisNode(node);
        Node signatureInfo = signature.getFirstChild();
        this.signatureInfo = new SignatureInfo().unmarshall(signatureInfo);

        Node referencesNode = signatureInfo.getNextSibling();
        NodeList references = referencesNode.getChildNodes();
        this.references.clear();
        for (int i = 0; i < references.getLength(); i++) {
            this.references.add(new Reference<>(proofClass).unmarshall(references.item(i)));
        }

        Node signatureValue = referencesNode.getNextSibling();
        try {
            this.signatureValue = (S) signatureValueClass.newInstance().unmarshall(signatureValue);
        } catch (InstantiationException | IllegalAccessException e) {
            throw new RedactableXMLSignatureException(signatureValueClass.getName() +
                    " has no public default constructor", e);
        }

        try {
            unmarshallPublicKeys(node);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RedactableXMLSignatureException(signatureValueClass.getName() +
                    ": Error on public keys unmarshall.", e);
        }

        return this;
    }

    private void unmarshallPublicKeys(Node signature) throws RedactableXMLSignatureException, NoSuchAlgorithmException, InvalidKeySpecException {
        Node publicKeysNode = signature.getLastChild();

        if(publicKeysNode == null
        || !publicKeysNode.getNodeName().equals("PublicKeys"))
            return;

        if(signatureValueClass == GSSignatureValue.class)  {
            PublicKey dSigPublicKey = unmarshallPublicKey(publicKeysNode, "DSigPublicKey", "RSA");
            PublicKey accPublicKey = unmarshallPublicKey(publicKeysNode, "AccPublicKey", "BPA");

            this.publicKey = new GSRSSPublicKey("GSRSSwithRSAandBPA", dSigPublicKey, accPublicKey);
        }


    }

    private java.security.PublicKey unmarshallPublicKey(Node publicKeysNode, String publicKeyNodeName, String algorithm) throws RedactableXMLSignatureException, NoSuchAlgorithmException, InvalidKeySpecException {
        NodeList elems = publicKeysNode.getChildNodes();
        Node publicKeyElem = null;

        for(int e = 0; e < elems.getLength(); e++) {
            publicKeyElem = elems.item(e);
            if(publicKeyElem.getNodeName().equals(publicKeyNodeName))
                break;
        }

        if(publicKeyElem == null
        || !publicKeyElem.getNodeName().equals(publicKeyNodeName))
            return null;

        byte[] decodedDSigPublicKey = base64Decoder.decode(publicKeyElem.getTextContent());

        if(publicKeyNodeName.equals("AccPublicKey"))
            return parseAccumulatorPublicKey(decodedDSigPublicKey);

        return parsePublicKey(decodedDSigPublicKey, algorithm);
    }

    private java.security.PublicKey parseAccumulatorPublicKey(byte[] data) {
        BigInteger bigint = new BigInteger(data);
        return new BPPublicKey(bigint);
    }

    private java.security.PublicKey parsePublicKey(byte[] data, String algorithm) throws NoSuchAlgorithmException, InvalidKeySpecException {
        X509EncodedKeySpec spec = new X509EncodedKeySpec(data);

        return KeyFactory.getInstance(algorithm)
                .generatePublic(spec);
    }

    @Override
    public Node marshall(Document document) {
        Element docElem = createThisElement(document);
        docElem.appendChild(signatureInfo.marshall(document));
        Node references = docElem.appendChild(createElement(document, "References"));
        for (Reference reference : this.references) {
            references.appendChild(reference.marshall(document));
        }

        docElem.appendChild(references);
        docElem.appendChild(signatureValue.marshall(document));
        docElem.setAttribute("xmlns", RedactableXMLSignature.XML_NAMESPACE);

        if(publicKey != null)
            marshallPublicKeys(document, docElem);

        return docElem;
    }

    private void marshallPublicKeys(Document document, Node signature) {

        Element publicKeysElem = createElement(document, "PublicKeys");
        PublicKey dSigPublicKey = null;

        if(signatureValueClass == GSSignatureValue.class)  {
            PublicKey accPublicKey = ((GSRSSPublicKey) publicKey).getAccumulatorKey();
            marshallPublicKey(document, publicKeysElem, "AccPublicKey", accPublicKey);

            dSigPublicKey = ((GSRSSPublicKey) publicKey).getDSigKey();
        }
        else
            dSigPublicKey = publicKey;

        marshallPublicKey(document, publicKeysElem, "DSigPublicKey", dSigPublicKey);

        signature.appendChild(publicKeysElem);
    }

    private void marshallPublicKey(
            Document document,
            Node publicKeysNode,
            String publicKeyNodeName,
            PublicKey publicKey) {
        Element publicKeyElem = createElement(document, publicKeyNodeName);
        publicKeyElem.setTextContent(base64Encoder.encodeToString(publicKey.getEncoded()));
        publicKeysNode.appendChild(publicKeyElem);

    }
}
