package piyo;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml.SAMLAuthenticationToken;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import piyo.data.PiyoResponse;

import javax.servlet.http.HttpServletRequest;
import java.util.Set;

@Controller
public class IdpSelectionControler {
    private static final Logger LOG = LoggerFactory.getLogger(IdpSelectionControler.class);

    @Autowired
    private MetadataManager metadata;

    @RequestMapping(value = "/saml/idpSelection", method = RequestMethod.GET)
    public String idpSelection(HttpServletRequest request, /*String redirectUrl*/ Model model) {
        PiyoResponse response = new PiyoResponse();

//        if (!(SecurityContextHolder.getContext().getAuthentication() instanceof AnonymousAuthenticationToken)) {
        if (SecurityContextHolder.getContext().getAuthentication() instanceof SAMLAuthenticationToken) {
//            response.setNextUrl(redirectUrl);
            LOG.info("in /saml redirect /randing ");

            return "redirect:/landing";

        } else {
            if (isForwarded(request)) {
                Set<String> idps = metadata.getIDPEntityNames();
                for (String idp : idps) {
                    LOG.info(idp);
                }
                model.addAttribute("idps", idps);
//                response.setNextUrl("/saml");
                return "samlIdpSelection";

            } else {
                return "redirect:/";
//                response.setNextUrl("/user");

            }
        }

    }

    private boolean isForwarded(HttpServletRequest request){
        if (request.getAttribute("javax.servlet.forward.request_uri") == null)
            return false;
        else
            return true;
    }
}
