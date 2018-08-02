package piyo;

import java.util.ArrayList;
import java.util.List;

import org.opensaml.saml2.core.Attribute;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.schema.XSAny;
import org.opensaml.xml.schema.XSInteger;
import org.opensaml.xml.schema.XSString;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;
import org.springframework.stereotype.Service;

@Service
public class SAMLUserDetails implements SAMLUserDetailsService {
    private static final Logger LOG = LoggerFactory.getLogger(SAMLUserDetails.class);
    private static final String ALTERNATIVE_LOGIN_ID_ATTRIBUTE_NAME = "http://schemas.microsoft.com/ws/2013/11/alternateloginid";

    public Object loadUserBySAML(SAMLCredential credential) throws UsernameNotFoundException {
        LOG.info("in SAMLUserDetails#loadUserBySAML:{}", credential);
        LOG.info("  .RelayState: {}", credential.getRelayState());
        dumpCredential(credential);
        String userID = credential.getNameID().getValue();
        String alternativeUserID = pickupAlternativeLoginId(credential);
        LOG.info("{}({}) is logged in", userID, alternativeUserID);

        List<GrantedAuthority> authorities = new ArrayList<>();
        GrantedAuthority authority = new SimpleGrantedAuthority("ROLE_USER");
        authorities.add(authority);

        // TODO ここで仮のユーザ情報を配置。実案件ではここにユーザ判定の処理(DBからデータを取ってきてうんぬんかんぬん）を実施してください
        return new User(userID, "<abc123>", true, true, true, true, authorities);
    }

    private String pickupAlternativeLoginId(SAMLCredential credential) {
        for (Attribute attr : credential.getAttributes()) {
            if (!attr.getName().equals(ALTERNATIVE_LOGIN_ID_ATTRIBUTE_NAME)) {
                continue;
            }
            String value = pickupAttributeValue(attr);
            if (value != null) {
                return value;
            }
        }
        return null;
    }

    private String pickupAttributeValue(Attribute attr) {
        for (XMLObject xml : attr.getAttributeValues()) {
            if (xml instanceof XSAny) {
                XSAny any = XSAny.class.cast(xml);
                if (any.getTextContent() != null) {
                    return any.getTextContent();
                }
            } else if (xml instanceof XSString) {
                XSString str = XSString.class.cast(xml);
                if (str.getValue() != null) {
                    return str.getValue();
                }
            } else if (xml instanceof XSInteger) {
                XSInteger integer = XSInteger.class.cast(xml);
                if (integer.getValue() != null) {
                    return String.valueOf(integer.getValue());
                }
            }
        }
        return null;
    }

    private void dumpCredential(SAMLCredential credential) {
        if (!LOG.isDebugEnabled()) {
            return;
        }
        LOG.debug("{} attributes.", credential.getAttributes().size());
        int index = 0;
        for (Attribute a : credential.getAttributes()) {
            dumpAttribute(index, a);
            index++;
        }
    }

    private void dumpAttribute(int index, Attribute a) {
        for (XMLObject x : a.getAttributeValues()) {
            if (x instanceof XSAny) {
                XSAny any = XSAny.class.cast(x);
                LOG.debug("@{} : {}({})", a.getName(), any.getTextContent(), x.getElementQName());
            }
        }
    }
}
