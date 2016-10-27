package de.unipassau.wolfgangpopp.xmlrss.wpprovider;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;

public abstract class RedactableSignatureSPI {

    protected SecureRandom appRandom = null;

    protected abstract void engineInitSign(PrivateKey privateKey) throws InvalidKeyException;

    protected abstract void engineInitSign(PrivateKey privateKey, SecureRandom random) throws InvalidKeyException;

    protected abstract void engineInitVerify(PublicKey publicKey) throws InvalidKeyException;

    protected abstract void engineInitRedact(PublicKey publicKey) throws InvalidKeyException;

    protected abstract void engineAddPart(byte[] part, boolean admissible) throws SignatureException;

    protected abstract SignatureOutput engineSign() throws SignatureException;

    protected abstract boolean engineVerify(SignatureOutput signature) throws SignatureException;

    protected abstract SignatureOutput engineRedact(SignatureOutput signature, ModificationInstruction mod) throws SignatureException;

    protected abstract void engineSetParameters(AlgorithmParameters parameters) throws InvalidAlgorithmParameterException;

    protected abstract AlgorithmParameters engineGetParameters();

}