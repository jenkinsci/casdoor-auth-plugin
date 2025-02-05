package io.jenkins.plugins;

import com.google.api.client.auth.oauth2.AuthorizationCodeResponseUrl;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.model.Descriptor;
import hudson.model.Failure;
import hudson.model.User;
import hudson.model.UserProperty;
import hudson.security.SecurityRealm;
import hudson.util.FormValidation;
import hudson.util.Secret;
import jenkins.model.Jenkins;
import jenkins.security.SecurityListener;
import org.casbin.casdoor.config.Config;
import org.casbin.casdoor.exception.AuthException;
import org.casbin.casdoor.service.AuthService;
import org.casbin.casdoor.util.http.HttpClient;
import org.kohsuke.stapler.*;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import edu.umd.cs.findbugs.annotations.Nullable;

import jakarta.servlet.ServletException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

import static org.apache.commons.lang.StringUtils.isNotBlank;

public class CasdoorSecurityRealm extends SecurityRealm {

    private static final String REFERER_ATTRIBUTE = CasdoorSecurityRealm.class.getName() + ".referer";
    private static final String logoutRouter = "/api/logout";

    private final String clientId;
    private final Secret clientSecret;
    private final String endpoint;
    private final String jwtCertificate;
    private final String organizationName;
    private final String applicationName;
    private final String scopes;
    private final String groupsFieldName;

    @DataBoundConstructor
    public CasdoorSecurityRealm(String clientId, String clientSecret, String endpoint, String jwtCertificate, String organizationName, String applicationName, String scopes, String groupsFieldName) {
        this.clientId = clientId;
        this.clientSecret = Secret.fromString(clientSecret);
        this.endpoint = endpoint;
        this.jwtCertificate = jwtCertificate;
        this.organizationName = organizationName;
        this.applicationName = applicationName;
        this.scopes = scopes;
        this.groupsFieldName = groupsFieldName;
    }

    public HttpResponse doCommenceLogin(StaplerRequest2 request, StaplerResponse2 response, @Header("Referer") final String referer) throws IOException {
        request.getSession().setAttribute(REFERER_ATTRIBUTE, referer);
        String state = UUID.randomUUID().toString();
        request.getSession().setAttribute("casdoorState", state);

        String redirect = redirectUrl();
        Config casdoorConfig = new Config(endpoint, clientId, clientSecret.getPlainText(), jwtCertificate, organizationName, applicationName);
        AuthService authService = new AuthService(casdoorConfig);
        return new HttpRedirect(authService.getSigninUrl(redirect, state));
    }

    public HttpResponse doFinishLogin(StaplerRequest2 request) {
        StringBuffer buf = request.getRequestURL();
        if (request.getQueryString() != null) {
            buf.append('?').append(request.getQueryString());
        }
        // Validate state and code
        AuthorizationCodeResponseUrl responseUrl = new AuthorizationCodeResponseUrl(buf.toString());
        if (!MessageDigest.isEqual(responseUrl.getState().getBytes(StandardCharsets.UTF_8), request.getSession().getAttribute("casdoorState").toString().getBytes(StandardCharsets.UTF_8))) {
            return new Failure("Inconsistent state");
        }
        String code = responseUrl.getCode();
        if (responseUrl.getError() != null) {
            return new Failure(
                    "Error from provider: " + responseUrl.getError() + ". Details: " + responseUrl.getErrorDescription()
            );
        } else if (code == null) {
            return new Failure("Missing authorization code");
        } else {
            return onSuccess(request, code);
        }
    }

    public void doLogout(StaplerRequest2 request, StaplerResponse2 response) throws ServletException, IOException {
        Stapler.getCurrentRequest().getSession().removeAttribute("casdoorUser");
        // arg 3 is credential - what credential to use for a logout request?
        HttpClient.postString(endpoint + logoutRouter, "", "");
        super.doLogout(request, response);
    }

    private HttpResponse onSuccess(StaplerRequest2 request, String code) {
        try {
            Config casdoorConfig = new Config(endpoint, clientId, clientSecret.getPlainText(), jwtCertificate, organizationName, applicationName);
            AuthService authService = new AuthService(casdoorConfig);
            String token = authService.getOAuthToken(code, this.applicationName);
            org.casbin.casdoor.entity.User userInfo = authService.parseJwtToken(token);

            Stapler.getCurrentRequest().getSession().setAttribute("casdoorUser", userInfo);

            loginAndSetUserData(userInfo);

            String referer = (String) request.getSession().getAttribute(REFERER_ATTRIBUTE);
            if (referer != null) {
                return HttpResponses.redirectTo(referer);
            }
            return HttpResponses.redirectToContextRoot();
        } catch (IOException | AuthException e) {
            e.printStackTrace();
            return HttpResponses.error(500, e);
        }
    }

    private UsernamePasswordAuthenticationToken loginAndSetUserData(org.casbin.casdoor.entity.User userInfo) throws IOException {

        GrantedAuthority[] grantedAuthorities = determineAuthorities(userInfo);

        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(userInfo.name, "", Arrays.asList(grantedAuthorities));

        SecurityContextHolder.getContext().setAuthentication(token);

        User user = User.getOrCreateByIdOrFullName(token.getName());
        user.addProperty(new CasdoorUserProperty(userInfo.name, grantedAuthorities));

        CasdoorUserDetails userDetails = new CasdoorUserDetails(userInfo.name, grantedAuthorities);
        SecurityListener.fireAuthenticated2(userDetails);

        return token;
    }

    private GrantedAuthority[] determineAuthorities(org.casbin.casdoor.entity.User userInfo) {
        List<GrantedAuthority> grantedAuthorities = new ArrayList<>();
        grantedAuthorities.add(SecurityRealm.AUTHENTICATED_AUTHORITY2);

        if (isNotBlank(groupsFieldName) && userInfo.groups != null) {
            for (String groupName : userInfo.groups) {
                grantedAuthorities.add(new SimpleGrantedAuthority(groupName));
            }
        }

        return grantedAuthorities.toArray(new GrantedAuthority[0]);
    }

    private String redirectUrl() {
        @Nullable Jenkins instance = Jenkins.getInstanceOrNull();
        if (instance == null) {
            throw new NullPointerException("Jenkins instance should not be null");
        }
        String rootUrl = instance.getRootUrl();
        if (rootUrl == null) {
            throw new NullPointerException("Jenkins root url should not be null");
        } else {
            return rootUrl + "securityRealm/finishLogin";
        }
    }

    @Override
    public boolean allowsSignup() {
        return false;
    }

    @Override
    public String getLoginUrl() {
        return "securityRealm/commenceLogin";
    }

    @Override
    public String getAuthenticationGatewayUrl() {
        return "securityRealm/escapeHatch";
    }

    @Override
    public SecurityComponents createSecurityComponents() {
        return new SecurityComponents(authentication -> {
            if (authentication instanceof AnonymousAuthenticationToken) {
                return authentication;
            }
            throw new BadCredentialsException("Unexpected authentication type: " + authentication);
        }, (UserDetailsService) username -> {
            User u = User.get(username, false, Collections.emptyMap());
            if (u == null) {
                throw new UsernameNotFoundException(username);
            }
            List<UserProperty> props = u.getAllProperties();
            GrantedAuthority[] auths = new GrantedAuthority[0];
            for (UserProperty prop : props) {
                if (prop instanceof CasdoorUserProperty) {
                    CasdoorUserProperty oicProp = (CasdoorUserProperty) prop;
                    auths = oicProp.getAuthoritiesAsGrantedAuthorities();
                }
            }
            return new CasdoorUserDetails(username, auths);
        });
    }

    public String getClientId() {
        return clientId;
    }

    public Secret getClientSecret() {
        return clientSecret;
    }

    public String getEndpoint() {
        return endpoint;
    }

    public String getJwtCertificate() {
        return jwtCertificate;
    }

    public String getOrganizationName() {
        return organizationName;
    }

    public String getApplicationName() {
        return applicationName;
    }

    public String getScopes() {
        return scopes;
    }

    @Extension
    public static final class DescriptorImpl extends Descriptor<SecurityRealm> {
        @NonNull
        @Override
        public String getDisplayName() {
            return "Casdoor Authentication Plugin";
        }

        public FormValidation doCheckEndpoint(@QueryParameter String value) {
            if (value == null || value.trim().length() == 0) {
                return FormValidation.error("Casdoor Endpoint is required.");
            }
            return FormValidation.ok();
        }

        public FormValidation doCheckClientId(@QueryParameter String value) {
            if (value == null || value.trim().length() == 0) {
                return FormValidation.error("Client Id is required.");
            }
            return FormValidation.ok();
        }

        public FormValidation doCheckClientSecret(@QueryParameter String value) {
            if (value == null || value.trim().length() == 0) {
                return FormValidation.error("Client Secret is required.");
            }
            return FormValidation.ok();
        }

        public FormValidation doCheckJwtPublicKey(@QueryParameter String value) {
            if (value == null || value.trim().length() == 0) {
                return FormValidation.error("Jwt Public Key is required.");
            }
            return FormValidation.ok();
        }
    }
}