/*
 * Copyright (c) 2012, Georgia Institute of Technology. All Rights Reserved.
 * This code was developed by Georgia Tech Research Institute (GTRI) under
 * a grant from the U.S. Dept. of Justice, Bureau of Justice Assistance.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package gov.niem.ws.sample.cvc.service;

import com.sun.xml.wss.XWSSecurityException;
import com.sun.xml.wss.impl.callback.SAMLValidator;
import com.sun.xml.wss.saml.*;
import com.sun.xml.wss.saml.internal.saml20.jaxb20.AudienceRestrictionType;
import com.sun.xml.wss.saml.internal.saml20.jaxb20.NameIDType;
import com.sun.xml.wss.saml.util.SAMLUtil;
import com.sun.xml.wss.util.DateUtils;
import gov.niem.ws.util.GFIPMUtil;
import gov.niem.ws.util.SecurityUtil;
import gov.niem.ws.util.jaxb.delegate.DelegateType;
import gov.niem.ws.util.jaxb.delegate.DelegationRestrictionType;
import java.io.IOException;
import java.security.PublicKey;
import java.text.ParseException;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.security.auth.Subject;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import net.gfipm.trustfabric.TrustFabric;
import net.gfipm.trustfabric.TrustFabricFactory;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

public class GFIPMSAMLAssertionValidatorWSP implements SAMLValidator {

    private static final boolean DEBUG = true;
    private static final Logger logger = Logger.getLogger(GFIPMSAMLAssertionValidatorWSP.class.getName());
    //this is not necessary here since it was initialized alreay in teh CertificateValidator but still (in case somebody replaces cert validator with default
    private static TrustFabric tf;
    public static final String WSP_ENTITY_ID_NAME = "curewspm2";

    static {
        tf = TrustFabricFactory.getInstance("net/gfipm/trustfabric/gfipm-trust-fabric-model2-sample-signed.xml");
    }
    private long TOKEN_LIFETIME = 300000;

    @Override
    public void validate(Element elmnt, Map map, Subject sbjct) throws SAMLValidationException {
        throw new UnsupportedOperationException("Not supported yet.1");
    }

    @Override
    public void validate(XMLStreamReader xmlStreamerReader, Map map, Subject sbjct) throws SAMLValidationException {
        if (tf == null) {
            throw new SAMLValidationException("GFIPM Trust Fabric was not initialized properly");
        }
        try {
            Element domSamlAssertion = SAMLUtil.createSAMLAssertion(xmlStreamerReader);
            if (DEBUG) {
                logger.log(Level.FINEST, "<<<<<<<<<<<<<<<<<<WSP: Validating SAML Assertion>>>>>>>>>>>>>>>\n"
                        + GFIPMUtil.putOutAsString(domSamlAssertion));
            }
            if (!(SAMLUtil.validateTimeInConditionsStatement(domSamlAssertion))) {
                logger.log(Level.WARNING, "Invalid time conditions");
                throw new SAMLValidationException("Invalid time conditions");
            } else {
                if (DEBUG) {
                    logger.log(Level.FINEST, "WSP: validated time conditions - passed");
                }
            }
            PublicKey signingKey = null;
            try {
                signingKey = SecurityUtil.getSignaturePublicKey(domSamlAssertion.getOwnerDocument());
            } catch (ParserConfigurationException ex) {
                logger.log(Level.WARNING, "ParseConfigurationException while obtaining Signature Public Key", ex);
                throw new SAMLValidationException(ex);
            } catch (SAXException ex) {
                logger.log(Level.WARNING, "SAXException while obtaining Signature Public Key", ex);
                throw new SAMLValidationException(ex);
            } catch (IOException ex) {
                logger.log(Level.WARNING, "IOException while obtaining Signature Public Key", ex);
                throw new SAMLValidationException(ex);
            }
            if (signingKey != null) {
                if (!(SAMLUtil.verifySignature(domSamlAssertion, signingKey))) {
                    logger.log(Level.WARNING, "Unable to verify signature on SAML assertion.");
                    throw new SAMLValidationException("Unable to verify signature on SAML assertion.");
                } else {
                    if (DEBUG) {
                        logger.log(Level.FINEST,
                                "WSP: done verifying signature on the attached SAML assertion - valid");
                    }
                }
            } else {
                logger.log(Level.WARNING, "Unable to obtain signing key from SAML assertion.");
                throw new SAMLValidationException("Unable to obtain signing key from SAML assertion.");
            }
            String signingEntityId = tf.getEntityId(signingKey);
            if (signingEntityId == null) {
                logger.log(Level.WARNING,
                        "Certificate used by the peer is not in the GFIPM Trust Fabric. Signing key is :\n"
                                + signingKey);
                throw new SAMLValidationException("Certificate used by the peer is not in the GFIPM Trust Fabric");
            }
            if (tf.isAssertionDelegateService(signingEntityId)) {
                if (DEBUG) {
                    logger.log(Level.FINEST,
                            "WSP: SAML assertion was signed by the Assertion Delegate Service Entity in GFIPM Trust Fabric, Singing Entity ID: "
                                    + signingEntityId);
                }
            } else {
                throw new SAMLValidationException(
                        "User assertion was not signed by the Assertion Delegate Service Entity in GFIPM Trust Fabric, Singing Entity ID: "
                                + signingEntityId);
            }
            autofix3(domSamlAssertion);
            Assertion assertion = AssertionUtil.fromElement(domSamlAssertion);
            autofix11(assertion);
            Conditions conditions = assertion.getConditions();
            autofix18(conditions);
            autofix15(assertion);
            boolean isAuthenticationContextValid = false;
            HashMap<String, String> attributesHashMap = new HashMap<String, String>();
            for (Object s : assertion.getStatements()) {
                isAuthenticationContextValid = autofix16(attributesHashMap, s, isAuthenticationContextValid);
            }
            if (!isAuthenticationContextValid) {
                throw new SAMLValidationException(
                        "WSP: Authentication context is not valid in the provided SAML Assertion.");
            }
            if (!isAuthorized(attributesHashMap)) {
                throw new SAMLValidationException("WSP: Policy validation failed for the provided SAML Assertion.");
            }
            sbjct.getPublicCredentials().add(domSamlAssertion);
        } catch (XWSSecurityException ex) {
            autofix0(ex);
        } catch (XMLStreamException ex) {
            autofix1(ex);
        } catch (SAMLException ex) {
            autofix2(ex);
        }
        if (DEBUG) {
            logger.log(Level.FINEST, "<<<<<<<<<<<<<<<<<<<WSP:SAML Validation Successful>>>>>>>>>>>>>>>");
        }
    }

    @Override
    public void validate(Element elmnt) throws SAMLValidationException {
        throw new UnsupportedOperationException("Not supported yet");
    }

    @Override
    public void validate(XMLStreamReader reader) throws SAMLValidationException {
        throw new UnsupportedOperationException("Not supported yet");
    }

    /**
     * Checks whether GFIPM user attributes are included and are of the certain
     * values
     *
     * @param attributesHashMap
     * @return true if all authorization requirements are met, false otherwise.
     */
    private Boolean isAuthorized(HashMap<String, String> attributesHashMap) {

        boolean result = false;

        //Check gfipm:2.0:user:SwornLawEnforcementOfficerIndicator
        if ("true".compareToIgnoreCase(attributesHashMap.get("gfipm:2.0:user:SwornLawEnforcementOfficerIndicator")) == 0) {
            result = true;
        }

        //Check gfipm:2.0:user:CitizenshipCode
        if ("US".compareToIgnoreCase(attributesHashMap.get("gfipm:2.0:user:CitizenshipCode")) == 0) {
            result = true;
        }

        return result;
    }

    private boolean isValidSubjectConfirmationMethod(SubjectConfirmation subjectConfirmation) {
        boolean isValidSubjectConfirmationMethod = false;

        List<String> subjectConfirmationMethods = subjectConfirmation.getConfirmationMethod();

        for (String subjectConfirmationMethod : subjectConfirmationMethods) {
            if (GFIPMUtil.SAML_SENDER_VOUCHES_2_0.equals(subjectConfirmationMethod)) {
                return true;
            }
        }

        return isValidSubjectConfirmationMethod;
    }

    /**
	 * TODO: The exception might be Generic, please verify and update the same
	 * 
	 */
    private void autofix0(XWSSecurityException ex) throws SAMLValidationException {
        logger.log(Level.SEVERE, "XWSSecurityException", ex);
        throw new SAMLValidationException(ex);
    }

    /**
	 * TODO: The exception might be Generic, please verify and update the same
	 * 
	 */
    private void autofix1(XMLStreamException ex) throws SAMLValidationException {
        logger.log(Level.SEVERE, "XMLStreamException", ex);
        throw new SAMLValidationException(ex);
    }

    /**
	 * TODO: The exception might be Generic, please verify and update the same
	 * 
	 */
    private void autofix2(SAMLException ex) throws SAMLValidationException {
        logger.log(Level.SEVERE, "SAMLException", ex);
        throw new SAMLValidationException(ex);
    }

    /**
	 * TODO: The exception might be Generic, please verify and update the same
	 * 
	 */
    private void autofix3(Element domSamlAssertion) throws SAMLValidationException {
        domSamlAssertion.setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:del",
                "urn:oasis:names:tc:SAML:2.0:conditions:delegation");
        domSamlAssertion.setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:ns5",
                "urn:oasis:names:tc:SAML:2.0:conditions:delegation");
        domSamlAssertion.setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:ns8",
                "http://www.w3.org/2001/XMLSchema");
    }

    /**
	 * TODO: The exception might be Generic, please verify and update the same
	 * 
	 */
    private boolean autofix6(List<String> audienceList, boolean isAudienceRestrictionValid)
            throws SAMLValidationException {
        for (String audience : audienceList) {
            if (DEBUG) {
                logger.log(Level.FINEST, "WSP: Audience restriction: " + audience);
            }
            if (WSP_ENTITY_ID_NAME.equals(audience)) {
                isAudienceRestrictionValid = true;
            }
        }
        return isAudienceRestrictionValid;
    }

    /**
	 * TODO: The exception might be Generic, please verify and update the same
	 * 
	 */
    private void autofix18(Conditions conditions) throws SAMLValidationException {
        boolean isAudienceRestrictionValid = false;
        boolean isDelegateRestrictionValid = false;
        for (Object condition : conditions.getConditions()) {
            if (condition instanceof AudienceRestrictionType) {
                List<String> audienceList = ((AudienceRestrictionType) condition).getAudience();
                if (audienceList.isEmpty()) {
                    throw new SAMLValidationException("WSP: Audience restriction is empty.");
                }
                isAudienceRestrictionValid = autofix6(audienceList, isAudienceRestrictionValid);
            } else if (condition instanceof DelegationRestrictionType) {
                List<DelegateType> delegateTypesList = ((DelegationRestrictionType) condition).getDelegate();
                if (delegateTypesList.isEmpty()) {
                    throw new SAMLValidationException("WSP: Delegate restriction is empty.");
                }
                for (DelegateType delegateType : delegateTypesList) {
                    autofix17(delegateType);
                }
                isDelegateRestrictionValid = true;
            }
        }
        if (!isAudienceRestrictionValid) {
            throw new SAMLValidationException("WSP: Audience restriction is not valid.");
        }
        if (!isDelegateRestrictionValid) {
            throw new SAMLValidationException("WSP: Delegate restriction is not valid.");
        }
    }

    /**
	 * TODO: The exception might be Generic, please verify and update the same
	 * 
	 */
    private void autofix17(DelegateType delegateType) throws SAMLValidationException {
        autofix9(delegateType);
        XMLGregorianCalendar xmlGregorianCalendar = delegateType.getDelegationInstant();
        Date date;
        try {
            autofix12(xmlGregorianCalendar, date);
        } catch (ParseException ex) {
            Logger.getLogger(GFIPMSAMLAssertionValidatorWSP.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /**
	 * TODO: The exception might be Generic, please verify and update the same
	 * 
	 */
    private void autofix9(DelegateType delegateType) throws SAMLValidationException {
        NameIDType nameIDType = delegateType.getNameID();
        if ((nameIDType != null) && tf.isWebServiceConsumer(nameIDType.getValue())) {
            if (DEBUG) {
                logger.log(Level.FINEST, "WSP: Assertion Delegate: " + nameIDType.getValue());
            }
        } else {
            throw new SAMLValidationException(
                    "WSP: NameID is empty within Delegation or NameID entity is not a WSC in GFIPM CTF:" + nameIDType);
        }
    }

    /**
	 * TODO: The exception might be Generic, please verify and update the same
	 * 
	 */
    private void autofix11(Assertion assertion) throws SAMLValidationException {
        String assertionVersion = assertion.getVersion();
        if ((assertionVersion == null) || (!(assertionVersion.compareTo("2.0") == 0))) {
            logger.log(Level.WARNING, "Invalid version of the SAML assertion: " + assertionVersion);
            throw new SAMLValidationException("WSP: Invalid version of the SAML assertion.");
        } else {
            if (DEBUG) {
                logger.log(Level.FINEST, "WSP: Validated SAML Version : " + assertion.getVersion());
            }
        }
    }

    /**
	 * TODO: The exception might be Generic, please verify and update the same
	 * 
	 */
    private void autofix12(XMLGregorianCalendar xmlGregorianCalendar, Date date) throws SAMLValidationException {
        date = DateUtils.stringToDate(xmlGregorianCalendar.toString());
        long currentTime = System.currentTimeMillis();
        if ((currentTime - date.getTime()) > TOKEN_LIFETIME) {
            throw new SAMLValidationException("WSP: SAML Assertion Delegation token has expired: " + date.toString());
        } else {
            if (DEBUG) {
                logger.log(Level.FINEST,
                        "WSP: SAML Assertion Delegation instant is within allowed timeframe : " + date.toString());
            }
        }
    }

    /**
	 * TODO: The exception might be Generic, please verify and update the same
	 * 
	 */
    private boolean autofix16(HashMap<String, String> attributesHashMap, Object s, boolean isAuthenticationContextValid)
            throws SAMLValidationException {
        if (s instanceof AttributeStatement) {
            autofix14(attributesHashMap, s);
        } else if (s instanceof AuthnStatement) {
            isAuthenticationContextValid = autofix13(s, isAuthenticationContextValid);
        }
        return isAuthenticationContextValid;
    }

    /**
	 * TODO: The exception might be Generic, please verify and update the same
	 * 
	 */
    private boolean autofix13(Object s, boolean isAuthenticationContextValid) throws SAMLValidationException {
        AuthnStatement authnStatement = (AuthnStatement) s;
        String authnContextClassRef = authnStatement.getAuthnContextClassRef();
        if (authnContextClassRef != null && !authnContextClassRef.isEmpty()) {
            isAuthenticationContextValid = true;
        }
        if (DEBUG) {
            logger.log(Level.FINEST, "WSP: Authentication Context : " + authnContextClassRef);
        }
        return isAuthenticationContextValid;
    }

    /**
	 * TODO: The exception might be Generic, please verify and update the same
	 * 
	 */
    private void autofix14(HashMap<String, String> attributesHashMap, Object s) throws SAMLValidationException {
        List<Attribute> samlAttrs = ((AttributeStatement) s).getAttributes();
        for (Attribute samlAttr : samlAttrs) {
            String attrName = samlAttr.getName();
            String attributeValue = (String) samlAttr.getAttributes().iterator().next();
            attributesHashMap.put(attrName, attributeValue);
            if (DEBUG) {
                logger.log(Level.FINEST, "WSP: Attribute Name : " + attrName + " || Attr Value : " + attributeValue);
            }
        }
    }

    /**
	 * TODO: The exception might be Generic, please verify and update the same
	 * 
	 */
    private void autofix15(Assertion assertion) throws SAMLValidationException {
        com.sun.xml.wss.saml.Subject subject = assertion.getSubject();
        if (subject == null) {
            throw new SAMLValidationException("WSP: SAML Assertion is missing subject.");
        }
        SubjectConfirmation subjectConfirmation = subject.getSubjectConfirmation();
        if (!isValidSubjectConfirmationMethod(subjectConfirmation)) {
            logger.log(Level.WARNING, "WSP: Invalid subject confirmation method for the SAML assertion: "
                    + subjectConfirmation.getConfirmationMethod());
            throw new SAMLValidationException("WSP: Invalid subject confirmation method for the SAML assertion "
                    + subjectConfirmation.getConfirmationMethod());
        } else {
            if (DEBUG) {
                logger.log(Level.FINEST, "WSP: Validated subject confirmation method for the SAML assertion: "
                        + subjectConfirmation.getConfirmationMethod());
                logger.log(Level.FINEST,
                        "WSP: Subject confirmation Name ID: " + subjectConfirmation.getNameId().getValue());
            }
        }
    }
}
