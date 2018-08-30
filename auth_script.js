/*
 * Template for JavaScript based authenticator's.
 * See org.keycloak.authentication.authenticators.browser.ScriptBasedAuthenticatorFactory
 */

// import enum for error lookup
AuthenticationFlowError = Java.type("org.keycloak.authentication.AuthenticationFlowError");
SimpleHttp = Java.type("org.keycloak.broker.provider.util.SimpleHttp");

/**
 * An example authenticate function.
 *
 * The following variables are available for convenience:
 * user - current user {@see org.keycloak.models.UserModel}
 * realm - current realm {@see org.keycloak.models.RealmModel}
 * session - current KeycloakSession {@see org.keycloak.models.KeycloakSession}
 * httpRequest - current HttpRequest {@see org.jboss.resteasy.spi.HttpRequest}
 * script - current script {@see org.keycloak.models.ScriptModel}
 * authenticationSession - current authentication session {@see org.keycloak.sessions.AuthenticationSessionModel}
 * LOG - current logger {@see org.jboss.logging.Logger}
 *
 * You one can extract current http request headers via:
 * httpRequest.getHttpHeaders().getHeaderString("Forwarded")
 *
 * @param context {@see org.keycloak.authentication.AuthenticationFlowContext}
 */
function authenticate(context) {

    var username = user ? user.username : "anonymous";
    LOG.info(script.name + " trace auth for: " + username);
    
    // get the user attributes, and see if this is in the user agent
    var user_agent = httpRequest.getHttpHeaders().getHeaderString("User-Agent")
    var ip = context.getConnection().getRemoteAddr()
    var attr_agent = user.getAttribute("user-agent")[0]
    LOG.info("request user-agent: "+user_agent)
    LOG.info("saved user-agent: "+attr_agent)
    if (!user_agent.contains(attr_agent)) {
        
          LOG.info("Looks like a new login, lets send an email!")
          var endpoint = "http://172.17.0.1:9393/send"
          var html = "<html><body>"
          html += "<p>A new login has been detected with the following details:"
          html += "<p><strong>User agent</strong>: "+user_agent
          html += "<p><strong>IP address</strong>: "+ip
          html += "<p>For your safety we've blocked this login attempt. Please "
          html += "contact your local security team for more assistance."
          html += "</body></html>"
          var status = SimpleHttp.doPost(endpoint,session)
                    .param("to",user.getEmail())
                    .param("subject","New login from unknown device")
                    .param("html",html).asString()
          LOG.info("status: "+status);
          context.failure(AuthenticationFlowError.INVALID_CREDENTIALS)
    } else {
      context.success();
    }
}
