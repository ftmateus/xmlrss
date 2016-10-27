package de.unipassau.wolfgangpopp.xmlrss.wpprovider;

import sun.security.jca.GetInstance;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.util.List;

public abstract class RedactableSignature extends RedactableSignatureSPI {

    //TODO Debug mode

    private Provider provider;
    private String algorithm;
    private STATE state;

    private enum STATE {
        UNINITIALIZED, SIGN, REDACT, VERIFY
    }

    protected RedactableSignature(String algorithm) {
        this.algorithm = algorithm;
        this.state = STATE.UNINITIALIZED;
    }

    public static RedactableSignature getInstance(String algorithm) throws NoSuchAlgorithmException {
        NoSuchAlgorithmException failure = new NoSuchAlgorithmException(algorithm + "RedactableSignature not available");
        List<Provider.Service> services = GetInstance.getServices("RedactableSignature", algorithm);

        for (Provider.Service service : services) {
            try {
                GetInstance.Instance instance = GetInstance.getInstance(service, RedactableSignatureSPI.class);
                return getInstance(instance, algorithm);
            } catch (NoSuchAlgorithmException e) {
                failure = e;
            }
        }
        throw failure;
    }

    public static RedactableSignature getInstance(String algorithm, String provider)
            throws NoSuchProviderException, NoSuchAlgorithmException {

        GetInstance.Instance instance = GetInstance.getInstance("RedactableSignature",
                RedactableSignatureSPI.class, algorithm, provider);
        return getInstance(instance, algorithm);
    }

    public static RedactableSignature getInstance(String algorithm, Provider provider) throws NoSuchAlgorithmException {
        GetInstance.Instance instance = GetInstance.getInstance("RedactableSignature",
                RedactableSignatureSPI.class, algorithm, provider);
        return getInstance(instance, algorithm);
    }

    private static RedactableSignature getInstance(GetInstance.Instance instance, String algorithm) {
        RedactableSignature sig;
        if (instance.impl instanceof RedactableSignature) {
            sig = (RedactableSignature) instance.impl;
            sig.algorithm = algorithm;
        } else {
            RedactableSignatureSPI spi = (RedactableSignatureSPI) instance.impl;
            sig = new Delegate(spi, algorithm);
        }
        sig.provider = instance.provider;
        return sig;
    }

    public final Provider getProvider() {
        return this.provider;
    }

    public final void initSign(PrivateKey privateKey) throws InvalidKeyException {
        state = STATE.SIGN;
        engineInitSign(privateKey);
    }

    public final void initSign(PrivateKey privateKey, SecureRandom random) throws InvalidKeyException {
        state = STATE.SIGN;
        engineInitSign(privateKey, random);
    }

    public final void initVerify(PublicKey publicKey) throws InvalidKeyException {
        state = STATE.VERIFY;
        engineInitVerify(publicKey);
    }

    public final void initRedact(PublicKey publicKey) throws InvalidKeyException {
        state = STATE.REDACT;
        engineInitRedact(publicKey);
    }

    public final void addPart(byte[] part, boolean admissible) throws SignatureException {
        if (state != STATE.UNINITIALIZED) {
            engineAddPart(part, admissible);
        }
        throw new SignatureException("not initialized");
    }

    public final SignatureOutput sign() throws SignatureException {
        if (state == STATE.SIGN) {
            return engineSign();
        }
        throw new SignatureException("not initialized for signing");
    }

    public final boolean verify(SignatureOutput signature) throws SignatureException {
        if (state == STATE.VERIFY) {
            return engineVerify(signature);
        }
        throw new SignatureException("not initialized for verification");
    }

    public final SignatureOutput redact(SignatureOutput signature, ModificationInstruction mod) throws SignatureException {
        if (state == STATE.REDACT) {
            return engineRedact(signature, mod);
        }
        throw new SignatureException("not initialized for redaction");
    }

    public final String getAlgorithm() {
        return this.algorithm;
    }

    public final AlgorithmParameters getParameters() {
        return engineGetParameters();
    }

    public final void setParameters(AlgorithmParameters parameters) throws InvalidAlgorithmParameterException{
        engineSetParameters(parameters);
    }

    @Override
    public String toString() {
        return "RedactableSignature (Algorithm: " + getAlgorithm() + ", Initialization state: " + state + ")";
    }

    static class Delegate extends RedactableSignature {

        private RedactableSignatureSPI rssSPI;

        Delegate(RedactableSignatureSPI spi, String algorithm) {
            super(algorithm);
            this.rssSPI = spi;
        }

        @Override
        protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
            rssSPI.engineInitSign(privateKey);
        }

        protected void engineInitSign(PrivateKey privateKey, SecureRandom random) throws InvalidKeyException {
            rssSPI.engineInitSign(privateKey, random);
        }

        @Override
        protected void engineAddPart(byte[] part, boolean admissible) throws SignatureException {
            rssSPI.engineAddPart(part, admissible);
        }

        @Override
        protected SignatureOutput engineSign() throws SignatureException {
            return rssSPI.engineSign();
        }

        @Override
        protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
            rssSPI.engineInitVerify(publicKey);
        }

        @Override
        protected boolean engineVerify(SignatureOutput signature) throws SignatureException {
            return rssSPI.engineVerify(signature);
        }

        @Override
        protected void engineInitRedact(PublicKey publicKey) throws InvalidKeyException {
            rssSPI.engineInitRedact(publicKey);
        }

        @Override
        protected SignatureOutput engineRedact(SignatureOutput signature, ModificationInstruction mod) throws SignatureException {
            return rssSPI.engineRedact(signature, mod);
        }

        protected void engineSetParameters(AlgorithmParameters parameters) throws InvalidAlgorithmParameterException{
            rssSPI.engineSetParameters(parameters);
        }

        protected AlgorithmParameters engineGetParameters() {
            return rssSPI.engineGetParameters();
        }
    }
}