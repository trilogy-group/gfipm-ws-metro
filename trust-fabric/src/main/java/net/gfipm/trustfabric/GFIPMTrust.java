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

package net.gfipm.trustfabric;

import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.List;
import java.util.Set;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPathExpressionException;
import org.xml.sax.SAXException;

/**
 * Main command line executable class to manipulate the GFIPM Trust Fabric
 * document and the Java keystore. <p> Use command line argument -help to see
 * on-line instructions. <p> This class helps with the interacting between the
 * TrustFabric and GFIPMKeystore classes to allow a user to add, delete, or
 * examine certificates in the trust document and Java keystore.
 *
 * @author Stefan Roth
 *
 */
public class GFIPMTrust {

    private static final long serialVersionUID = 6616L;
    // Various known URLs of trust fabric documents:
    private static String RefURL = "http://ref.gfipm.net/gfipm-signed-ref-metadata.xml";
    private static String NiefURL = "https://nief.gfipm.net/trust-fabric/nief-trust-fabric.xml";
    private static String SampleURL = "https://cisasp.swbs.gtri.gatech.edu/public/gfipm-trust-fabric-sample.xml";

    // ======================================================================
    /**
     * Constructor for GFIPMTrust class to run the main program on a command
     * line with command line argument. <p> When running the command, use -help
     * for instructions on the arguments.
     *
     */
    public GFIPMTrust() {
    }

    // ======================================================================
    /**
     * Parses the main args array and returns value of arguments. Tests if the
     * argument was on the command line and optionally returns its value if
     * present. The comparison is case sensitive.
     *
     * @param args Original command line argument list.
     *
     * @param arg A String of a command line argument, such as "-verbose".
     *
     * @param value If true, try to find the value of the arg. If false, don't
     * look for a value.
     *
     * @param defaultvalue Value to return if the arg was not found or if the
     * arg found but there was no value.
     *
     * @return If value is true: returns a String if the arg was found and a
     * value was found, or returns defaultvalue if the arg was found but no
     * value was found or returns defaultvalue if arg was not found. <p> If
     * value is false: returns arg if arg was found, otherwise returns
     * defaultvalue.
     *
     */
    private static String getArgValue(String[] args, String arg, boolean value, String defaultvalue) {


        if ((arg == null) || (arg.length() == 0)) {
            return null;
        }

        int len = args.length;
        for (int i = 0; i < len; i++) {
            if (arg.equals(args[i])) {
                if (!value) {
                    return arg;
                } else {
                    if (((i + 1) < len) && (args[i + 1].charAt(0) != '-')) {
                        i++;
                        return args[i];
                    } else {
                        return defaultvalue;
                    }
                }
            }
        }  // end for

        return defaultvalue;
    }  // end getArgValue

    // ======================================================================
    public static void main(String[] args)
            throws IOException, SAXException, ParserConfigurationException, XPathExpressionException {
        boolean verboseOut = true;
        autofix1(args);
        TrustFabric trustFabric = autofix34(args, verboseOut);
        GFIPMKeystore keyStore = new GFIPMKeystore();
        {
            trustFabric = autofix26(trustFabric, args, verboseOut);
        }
        {
            autofix16(trustFabric, args);
        }
        {
            verboseOut = autofix27(trustFabric, args, keyStore, verboseOut);
        }
        {
            autofix20(trustFabric, args, keyStore);
        }
        {
            autofix0(trustFabric, args, keyStore);
        }
        {
            String passwordArg = getArgValue(args, "-password", true, null);
            if (passwordArg != null) {
                if (passwordArg.equals("prompt")) {
                    autofix31(keyStore);
                } else if (passwordArg.equals("none")) {
                    keyStore.setKspw(null);
                } else {
                    keyStore.setKspw(passwordArg.toCharArray());
                }
            }
        }
        {
            keyStore = autofix14(args, keyStore);
        }
        {
            autofix6(args, keyStore);
        }
        {
            autofix7(args, keyStore);
        }
        {
            autofix29(trustFabric, args, keyStore);
        }
        {
            autofix17(trustFabric, args, keyStore, verboseOut);
        }
        {
            autofix18(trustFabric, args, keyStore, verboseOut);
        }
        {
            if (keyStore != null && keyStore.isKeyStoreLoaded()) {
                keyStore.storeKeyStore();
            }
        }
        {
            autofix35(trustFabric, args, keyStore, verboseOut);
        }
        {
            autofix24(args, keyStore);
        }
        System.exit(0);
    }
    // end main

    /**
	 * TODO: The exception might be Generic, please verify and update the same
	 * 
	 */
    private static void autofix0(TrustFabric trustFabric, String[] args, GFIPMKeystore keyStore)
            throws SAXException, ParserConfigurationException, IOException, XPathExpressionException {
        String keepEntityId = getArgValue(args, "-keepEntityId", false, null);
        if ((keepEntityId != null) && (keyStore != null) && (trustFabric != null)) {
            keyStore.setKeepEntityIdAsAlias(true);
        }
    }

    /**
	 * TODO: The exception might be Generic, please verify and update the same
	 * 
	 */
    private static void autofix1(String[] args)
            throws SAXException, ParserConfigurationException, IOException, XPathExpressionException {
        if ((args == null) || (args.length == 0)) {
            System.out.println("Use arg -help to get command help.");
            System.exit(0);
        }
    }

    /**
	 * TODO: The exception might be Generic, please verify and update the same
	 * 
	 */
    private static void autofix3(TrustFabric trustFabric, String entityid, String result, GFIPMKeystore keyStore)
            throws SAXException, ParserConfigurationException, IOException, XPathExpressionException {
        entityid = "https://cisaidp.swbs.gtri.gatech.edu/idp/shibboleth";
        result = trustFabric.retrieveEntityCertificate(entityid, "IDP");
        keyStore.addNewEntryFromString(entityid, result);
    }

    /**
	 * TODO: The exception might be Generic, please verify and update the same
	 * 
	 */
    private static void autofix4(int len, GFIPMKeystore keyStore, char[] indata)
            throws SAXException, ParserConfigurationException, IOException, XPathExpressionException {
        char[] pword = new char[len];
        System.arraycopy(indata, 0, pword, 0, len);
        keyStore.setKspw(pword);
    }

    /**
	 * TODO: The exception might be Generic, please verify and update the same
	 * 
	 */
    private static void autofix31(GFIPMKeystore keyStore)
            throws SAXException, ParserConfigurationException, IOException, XPathExpressionException {
        try {
            autofix30(keyStore);
        } catch (Exception e) {
            autofix5(e);
        }
    }

    /**
	 * TODO: The exception might be Generic, please verify and update the same
	 * 
	 */
    private static void autofix5(Exception e)
            throws SAXException, ParserConfigurationException, IOException, XPathExpressionException {
        System.err.println("ERROR on reading user input:");
        System.err.println(e.toString());
        System.err.flush();
    }

    /**
	 * TODO: The exception might be Generic, please verify and update the same
	 * 
	 */
    private static void autofix6(String[] args, GFIPMKeystore keyStore)
            throws SAXException, ParserConfigurationException, IOException, XPathExpressionException {
        String deleteArg = getArgValue(args, "-delete", true, null);
        if (keyStore != null) {
            if (deleteArg != null) {
                keyStore.deleteEntry(deleteArg);
            }
        }
    }

    /**
	 * TODO: The exception might be Generic, please verify and update the same
	 * 
	 */
    private static void autofix7(String[] args, GFIPMKeystore keyStore)
            throws SAXException, ParserConfigurationException, IOException, XPathExpressionException {
        String deleteallArg = getArgValue(args, "-deleteall", false, null);
        if (keyStore != null) {
            if (deleteallArg != null) {
                keyStore.deleteAllGFIPMEntries();
            }
        }
    }

    /**
	 * TODO: The exception might be Generic, please verify and update the same
	 * 
	 */
    private static void autofix35(TrustFabric trustFabric, String[] args, GFIPMKeystore keyStore, boolean verboseOut)
            throws SAXException, ParserConfigurationException, IOException, XPathExpressionException {
        String viewArg = getArgValue(args, "-view", true, null);
        if (trustFabric != null) {
            if (viewArg != null) {
                if ((viewArg.equals("cisa")) && (keyStore != null)) {
                    String result;
                    result = trustFabric.retrieveEntityCertificate("https://cisasp.swbs.gtri.gatech.edu/shibboleth",
                            "SP", "signing");
                    keyStore.writeCertToFile("/home/gfipm/cisaspcert.crt", result);
                    result = trustFabric
                            .retrieveEntityCertificate("https://cisaidp.swbs.gtri.gatech.edu/idp/shibboleth", "IDP");
                    keyStore.writeCertToFile("/home/gfipm/cisaidpcert.crt", result);
                } else if (viewArg.equals("dup")) {
                    System.out.println();
                    System.out.println("All entity ids in trust doc: (including duplicate certificates)");
                    autofix10(trustFabric);
                    System.out.println();
                } else if (viewArg.equals("nondup")) {
                    System.out.println();
                    System.out.println("All entity ids in trust doc: (only non-duplicate certificates)");
                    autofix11(trustFabric);
                    System.out.println();
                } else if (viewArg.equals("attr1")) {
                    autofix25(trustFabric);
                } else if (viewArg.equals("attr2")) {
                    autofix15(trustFabric);
                } else if (viewArg.equals("attr3")) {
                    autofix23(trustFabric, verboseOut);
                }
            }
        }
    }

    /**
	 * TODO: The exception might be Generic, please verify and update the same
	 * 
	 */
    private static void autofix10(TrustFabric trustFabric)
            throws SAXException, ParserConfigurationException, IOException, XPathExpressionException {
        List<GFIPMCertificate> allEntityCertificates = trustFabric.getAllEntityCertificates(true);
        for (GFIPMCertificate cert : allEntityCertificates) {
            System.out.print("   ");
            System.out.println(cert.toString());
        }
    }

    /**
	 * TODO: The exception might be Generic, please verify and update the same
	 * 
	 */
    private static void autofix11(TrustFabric trustFabric)
            throws SAXException, ParserConfigurationException, IOException, XPathExpressionException {
        List<GFIPMCertificate> allEntityCertificates = trustFabric.getAllEntityCertificates(false);
        for (GFIPMCertificate cert : allEntityCertificates) {
            System.out.print("   ");
            System.out.println(cert.toString());
        }
    }

    /**
	 * TODO: The exception might be Generic, please verify and update the same
	 * 
	 */
    private static GFIPMKeystore autofix14(String[] args, GFIPMKeystore keyStore)
            throws SAXException, ParserConfigurationException, IOException, XPathExpressionException {
        String keystoreArg = getArgValue(args, "-keystore", true, null);
        if (keystoreArg != null) {
            keystoreArg = keyStore.setKeyStoreFilename(keystoreArg);
            boolean success = keyStore.loadKeyStore();
            if (!success) {
                System.err.println("ERROR: Java key store failed to load from file " + keystoreArg);
                keyStore = null;
            }
        }
        return keyStore;
    }

    /**
	 * TODO: The exception might be Generic, please verify and update the same
	 * 
	 */
    private static void autofix15(TrustFabric trustFabric)
            throws SAXException, ParserConfigurationException, IOException, XPathExpressionException {
        String entityid = "https://rhelidp.ref.gfipm.net/shibboleth";
        String attrname = null;
        String result;
        System.out.println();
        System.out.println("Get Attribute: " + entityid + ", " + attrname);
        result = trustFabric.getGfipmEntityAttribute(entityid, attrname);
        System.out.println("  Value: [" + result + "]");
    }

    /**
	 * TODO: The exception might be Generic, please verify and update the same
	 * 
	 */
    private static void autofix16(TrustFabric trustFabric, String[] args)
            throws SAXException, ParserConfigurationException, IOException, XPathExpressionException {
        String validateTrustDocArg = getArgValue(args, "-validatetrustdoc", false, null);
        if (validateTrustDocArg != null) {
            if (trustFabric == null) {
                System.out.println("Please, provide GFIPM trusted document to validate");
            }
            if (!trustFabric.isValid()) {
                System.out.println("WARNING: GFIPM Cryptographic Trust Fabric is NOT VALID!!!");
                System.exit(0);
            } else {
                System.out.println("GFIPM Cryptographic Trust Fabric is VALID.");
            }
        }
    }

    /**
	 * TODO: The exception might be Generic, please verify and update the same
	 * 
	 */
    private static void autofix17(TrustFabric trustFabric, String[] args, GFIPMKeystore keyStore, boolean verboseOut)
            throws SAXException, ParserConfigurationException, IOException, XPathExpressionException {
        String addallArg = getArgValue(args, "-addall", false, null);
        if ((addallArg != null) && (keyStore != null) && (trustFabric != null)) {
            if (verboseOut) {
                System.out.println();
            }
            List<GFIPMCertificate> allEntityCertificates = trustFabric.getAllEntityCertificates(false);
            if (verboseOut) {
                System.out.println();
            }
            keyStore.addEntriesFromCertificateList(allEntityCertificates);
        }
    }

    /**
	 * TODO: The exception might be Generic, please verify and update the same
	 * 
	 */
    private static void autofix18(TrustFabric trustFabric, String[] args, GFIPMKeystore keyStore, boolean verboseOut)
            throws SAXException, ParserConfigurationException, IOException, XPathExpressionException {
        String writeallArg = getArgValue(args, "-writeall", true, null);
        if ((writeallArg != null) && (keyStore != null) && (trustFabric != null)) {
            if (verboseOut) {
                System.out.println();
            }
            List<GFIPMCertificate> allEntityCertificates = trustFabric.getAllEntityCertificates(false);
            if (verboseOut) {
                System.out.println();
            }
            keyStore.writeCertificatesToDirectory(allEntityCertificates, writeallArg);
        }
    }

    /**
	 * TODO: The exception might be Generic, please verify and update the same
	 * 
	 */
    private static void autofix20(TrustFabric trustFabric, String[] args, GFIPMKeystore keyStore)
            throws SAXException, ParserConfigurationException, IOException, XPathExpressionException {
        String debugArg = getArgValue(args, "-debug", true, "no");
        if (debugArg != null) {
            if (debugArg.equals("no")) {
                trustFabric.setDebugOut(false);
                keyStore.setDebugOut(false);
            } else if (debugArg.equals("yes")) {
                trustFabric.setDebugOut(true);
                keyStore.setDebugOut(true);
            }
        }
    }

    /**
	 * TODO: The exception might be Generic, please verify and update the same
	 * 
	 */
    private static void autofix23(TrustFabric trustFabric, boolean verboseOut)
            throws SAXException, ParserConfigurationException, IOException, XPathExpressionException {
        String entityid = "https://rhelidp.ref.gfipm.net/shibboleth";
        if (verboseOut) {
            System.out.println();
        }
        HashMap<String, String> attrs = trustFabric.getGfipmEntityAttributes(entityid);
        String value;
        Set<String> keys = attrs.keySet();
        System.out.println();
        System.out.println("Found " + keys.size() + " attributes for " + entityid);
        for (String attr : keys) {
            value = attrs.get(attr);
            System.out.println("   " + attr + " = " + value);
        }
    }

    /**
	 * TODO: The exception might be Generic, please verify and update the same
	 * 
	 */
    private static void autofix24(String[] args, GFIPMKeystore keyStore)
            throws SAXException, ParserConfigurationException, IOException, XPathExpressionException {
        String printArg = getArgValue(args, "-print", true, null);
        if (keyStore != null) {
            if (printArg != null) {
                if (printArg.equals("alias")) {
                    keyStore.printKeyStoreAliases();
                } else if (printArg.equals("rawcert")) {
                    keyStore.printKeyStoreCertificates("rawcert");
                } else if (printArg.equals("cert")) {
                    keyStore.printKeyStoreCertificates(null);
                } else if (printArg.equals("all")) {
                    keyStore.printKeyStoreContents();
                }
            }
        }
    }

    /**
	 * TODO: The exception might be Generic, please verify and update the same
	 * 
	 */
    private static void autofix25(TrustFabric trustFabric)
            throws SAXException, ParserConfigurationException, IOException, XPathExpressionException {
        String entityid = "https://rhelidp.ref.gfipm.net/shibboleth";
        String attrname = "gfipm:2.0:entity:OwnerAgencyORI";
        String result;
        System.out.println();
        System.out.println("Get Attribute: " + entityid + ", " + attrname);
        result = trustFabric.getGfipmEntityAttribute(entityid, attrname);
        System.out.println("  Value: [" + result + "]");
        attrname = "thisAttributeDoesNotExist";
        System.out.println();
        System.out.println("Get Attribute: " + entityid + ", " + attrname);
        result = trustFabric.getGfipmEntityAttribute(entityid, attrname);
        System.out.println("  Value: [" + result + "]");
    }

    /**
	 * TODO: The exception might be Generic, please verify and update the same
	 * 
	 */
    private static TrustFabric autofix26(TrustFabric trustFabric, String[] args, boolean verboseOut)
            throws SAXException, ParserConfigurationException, IOException, XPathExpressionException {
        String trustdocArg = getArgValue(args, "-trustdoc", true, "ref");
        if (verboseOut && trustdocArg != null) {
            System.out.println("Loading trustdoc from file : " + trustdocArg);
        }
        if (trustdocArg == null) {
            trustFabric = new TrustFabric();
        } else if (trustdocArg.equals("nief")) {
            trustFabric = new TrustFabric(NiefURL);
        } else if (trustdocArg.equals("ref")) {
            trustFabric = new TrustFabric(RefURL);
        } else if (trustdocArg.equals("sample")) {
            trustFabric = new TrustFabric(SampleURL);
        } else {
            trustFabric = new TrustFabric(trustdocArg);
        }
        return trustFabric;
    }

    /**
	 * TODO: The exception might be Generic, please verify and update the same
	 * 
	 */
    private static boolean autofix27(TrustFabric trustFabric, String[] args, GFIPMKeystore keyStore, boolean verboseOut)
            throws SAXException, ParserConfigurationException, IOException, XPathExpressionException {
        String verboseDefault = (verboseOut ? "yes" : "no");
        String verboseArg = getArgValue(args, "-verbose", true, verboseDefault);
        if (verboseArg == null) {
            verboseArg = verboseDefault;
        }
        if (verboseArg.equals("no")) {
            verboseOut = false;
        } else if (verboseArg.equals("yes")) {
            verboseOut = true;
        }
        trustFabric.setVerboseOut(verboseOut);
        keyStore.setVerboseOut(verboseOut);
        if (verboseOut) {
            System.out.println("");
        }
        return verboseOut;
    }

    /**
	 * TODO: The exception might be Generic, please verify and update the same
	 * 
	 */
    private static void autofix29(TrustFabric trustFabric, String[] args, GFIPMKeystore keyStore)
            throws SAXException, ParserConfigurationException, IOException, XPathExpressionException {
        String addArg = getArgValue(args, "-add", true, null);
        if (addArg != null) {
            if ((trustFabric != null) && (keyStore != null)) {
                String entityid, result;
                if (addArg.equals("cisaidp")) {
                    autofix3(trustFabric, entityid, result, keyStore);
                } else if (addArg.equals("cisasp")) {
                    entityid = "https://cisasp.swbs.gtri.gatech.edu/shibboleth";
                    result = trustFabric.retrieveEntityCertificate(entityid, "SP", "signing");
                    keyStore.addNewEntryFromString(entityid, result);
                } else {
                    entityid = addArg;
                    result = trustFabric.retrieveEntityCertificate(entityid);
                    keyStore.addNewEntryFromString(entityid, result);
                }
            }
        }
    }

    /**
	 * TODO: The exception might be Generic, please verify and update the same
	 * 
	 */
    private static void autofix30(GFIPMKeystore keyStore)
            throws SAXException, ParserConfigurationException, IOException, XPathExpressionException {
        InputStreamReader inStream = new InputStreamReader(System.in);
        int len = 100;
        char[] indata = new char[len];
        System.out.print("keystore> ");
        len = inStream.read(indata, 0, len);
        if (len < 6) {
            System.err.println("ERROR: password must be at least 6 characters long. Abort.");
            System.exit(1);
        } else {
            if ((indata[len - 1] == '\n') || (indata[len - 1] == '\r')) {
                len--;
            }
            if ((indata[len - 1] == '\n') || (indata[len - 1] == '\r')) {
                len--;
            }
            autofix4(len, keyStore, indata);
        }
    }

    /**
	 * TODO: The exception might be Generic, please verify and update the same
	 * 
	 */
    private static TrustFabric autofix34(String[] args, boolean verboseOut)
            throws SAXException, ParserConfigurationException, IOException, XPathExpressionException {
        TrustFabric trustFabric = null;
        {
            String helpArg = getArgValue(args, "-help", false, null);
            if (helpArg != null) {
                System.out.println("trustfabric options:    (options are processed in the order shown)");
                System.out.println("  -help");
                System.out.println("     Print this help and then exits.");
                System.out.println("  -verbose  yes | no");
                System.out.println("     Set verbose output (default is " + (verboseOut ? "yes" : "no") + ").");
                System.out.println("  -trustdoc  <URL> | nief | ref | sample");
                System.out.println(
                        "     Load GFIPM trust document from URL, or NIEF Fed url, or Reference Fed url, or special Sample URL.");
                System.out.println("     Default is " + trustFabric.DEFAULT_TRUST_DOCUMENT_URL);
                System.out.println("  -validatetrustdoc");
                System.out.println("     Validate loaded GFIPM trust document.");
                System.out.println("  -password  prompt | <password> | none");
                System.out.println(
                        "     Prompt user for key store password or use the one given or no password. Otherwise use default password (changeit).");
                System.out.println("  -keystore  <filename>");
                System.out
                        .println("     Load Java key store from <filename>. If no file is found one will be created.");
                System.out.println("  -delete <entityid> | <alias>");
                System.out.println("     Delete entry with entity id or alias name from key store.");
                System.out.println("  -deleteall");
                System.out.println("     Delete all GFIPM entries from key store. Does not delete non-GFIPM entries.");
                System.out.println("  -add  <entityid> | cisaidp | cisasp");
                System.out.println(
                        "     Retrieve entity with entityid from trust doc and adds it to key store. (cisaidp, cisasp is for debugging)");
                System.out.println("  -addall");
                System.out.println(
                        "     Extract all certificates from GFIPM trust doc and adds non-duplicates to Java key store.");
                System.out.println("  -keepEntityId");
                System.out.println(
                        "     Keep an EntityId as Alias in the keystore or as a file name when extracting all certificates from the GFIPM trust doc.");
                System.out.println("  -writeall <directory>");
                System.out.println(
                        "     Extract all certificates from GFIPM trust doc and writes non-duplicates to files in dirctory.");
                System.out.println("  -view nondup | dup | cisa | attr1");
                System.out.println(
                        "     Print non-duplicate or all duplicate entity ids in trust doc to terminal. cisa and attr1 are for debugging only.");
                System.out.println("  -print  alias | cert | rawcert | all");
                System.out.println(
                        "     Print contents of key store: all alias names, all base64 certs, all text certs, or everything.");
                System.exit(0);
            }
        }
        return trustFabric;
    }
}  // end class

