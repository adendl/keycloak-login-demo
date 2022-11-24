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
    
    //set values for IP Address and username
    const username = user.username;
    const ip = context.getConnection().getRemoteAddr();
    const userRegexString = new RegExp('foo*'); //insert regex for if username is priviliged user
    const ipAddrRegexString = new RegExp('foo*'); //insert regex for if IP Address belongs to bastion host or priviliged network zone
    
    LOG.info(script.name + " trace auth for: " + username + " at IP Address: "+ ip);
    


    if (username.test(userRegexString)){     //regex check on if username is an admin/privileged user
        if (ip.test(ipAddrRegexString)){ // regex check on if IP Address matches desired format
            LOG.info("insert log message");
            context.success(); //user is admin and in priviliged network zone
        }
        else {
            LOG.info("Insert log message"); //user is admin but not on priviliged network zone
            context.failure(AuthenticationFlowError.DISPLAY_NOT_SUPPORTED);
        }
    } else{
        LOG.info("insert log message");
        context.success(); //user is not priviliged
    }

}
