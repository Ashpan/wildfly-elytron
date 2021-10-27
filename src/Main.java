import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Collections;
import java.util.Iterator;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public class Main {
    public static void main(String[] args) {
        try {
            String filePath = "/home/ashpan/tmp/testproject/out/production/testproject/doc.xml";
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            DocumentBuilder builder = dbf.newDocumentBuilder();
            Document doc = builder.parse(new FileInputStream(filePath));
            // Key Generation
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(1024);
            KeyPair kp = kpg.generateKeyPair();
            PrivateKey privateKey = kp.getPrivate();
            PublicKey publicKey = kp.getPublic();

            // Ignore Signature element
            Element elem = doc.getDocumentElement();
            NodeList signatureNode = doc.getElementsByTagName("Signature");
            if(signatureNode.getLength() > 0) {
                Node sig = signatureNode.item(0);
                elem.removeChild(sig);
            }

            DOMSignContext dsc = new DOMSignContext (privateKey, elem);
            XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
            Reference ref = fac.newReference
                    ("", fac.newDigestMethod(DigestMethod.SHA256, null),
                            Collections.singletonList
                                    (fac.newTransform(Transform.ENVELOPED,
                                            (TransformParameterSpec) null)), null, null);
            String signatureMethod = "";
            if(publicKey.getAlgorithm().equals("DSA"))
                signatureMethod = SignatureMethod.DSA_SHA256;
            else if(publicKey.getAlgorithm().equals("RSA"))
                signatureMethod = SignatureMethod.RSA_SHA256;
            else if(publicKey.getAlgorithm().equals("HMAC"))
                signatureMethod = SignatureMethod.HMAC_SHA256;
            else if(publicKey.getAlgorithm().equals("EC"))
                signatureMethod = SignatureMethod.ECDSA_SHA256;

            SignedInfo si = fac.newSignedInfo
                    (fac.newCanonicalizationMethod
                                    (CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS,
                                            (C14NMethodParameterSpec) null),
                            fac.newSignatureMethod(signatureMethod, null),
                            Collections.singletonList(ref));
            KeyInfoFactory kif = fac.getKeyInfoFactory();
            KeyValue kv = kif.newKeyValue(kp.getPublic());
            KeyInfo ki = kif.newKeyInfo(Collections.singletonList(kv));
            XMLSignature signature = fac.newXMLSignature(si, ki);
            signature.sign(dsc);


            TransformerFactory transformerFactory = TransformerFactory.newInstance();
            Transformer transformer = transformerFactory.newTransformer();
            DOMSource source = new DOMSource(doc);
            FileWriter writer = new FileWriter(filePath);
            StreamResult result = new StreamResult(writer);
            transformer.transform(source, result);


            doc = dbf.newDocumentBuilder().parse(filePath);
            NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
            if (nl.getLength() == 0) {
                throw new Exception("Cannot find Signature element");
            }
            fac = XMLSignatureFactory.getInstance("DOM");
            DOMValidateContext valContext = new DOMValidateContext(publicKey, nl.item(0));
            signature = fac.unmarshalXMLSignature(valContext);
            boolean coreValidity = signature.validate(valContext);
            if (!coreValidity) {
                System.err.println("Signature failed core validation");
                boolean sv = signature.getSignatureValue().validate(valContext);
                System.out.println("signature validation status: " + sv);
                // check the validation status of each Reference
                Iterator i = signature.getSignedInfo().getReferences().iterator();
                for (int j=0; i.hasNext(); j++) {
                    boolean refValid = ((Reference)i.next()).validate(valContext);
                    System.out.println("ref["+j+"] validity status: " + refValid);
                }
            } else {
                System.out.println("Signature passed core validation");
            }

        } catch (Exception e) {
            System.out.println("[ERROR]: " + e);
        }
    }
}
