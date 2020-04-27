/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2017-2018 ForgeRock AS.
 */


package org.forgerock.openam.RadiusNode;

import static org.forgerock.openam.auth.node.api.SharedStateConstants.PASSWORD;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;
import static org.forgerock.openam.utils.CollectionUtils.isEmpty;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.inject.Inject;

import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.AbstractDecisionNode;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.core.realms.Realm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.inject.assistedinject.Assisted;
import com.iplanet.sso.SSOException;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.idm.IdType;
import com.sun.identity.idm.IdUtils;

/** Import Library **/

import org.forgerock.openam.RadiusNode.client.RadiusConn;
import org.forgerock.openam.RadiusNode.client.ChallengeException;
import org.forgerock.openam.RadiusNode.client.RejectException;
import com.sun.identity.sm.RequiredValueValidator;
import org.forgerock.openam.sm.annotations.adapters.Password;
import java.util.LinkedHashSet;
import java.net.SocketException;
import com.sun.identity.authentication.spi.AuthLoginException;
import org.forgerock.openam.auth.node.api.Action.ActionBuilder;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import org.apache.commons.lang.StringUtils;
import org.forgerock.json.JsonValue;
/** for Callback */
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.TextOutputCallback;
import javax.security.auth.callback.PasswordCallback;
import static javax.security.auth.callback.TextOutputCallback.ERROR;
import javax.security.auth.message.callback.SecretKeyCallback;
import java.util.ResourceBundle;
import com.google.common.base.Strings;
import org.forgerock.openam.auth.node.api.SingleOutcomeNode;
import static org.forgerock.openam.auth.node.api.Action.send;
import static org.forgerock.openam.utils.CollectionUtils.isEmpty;
/** for Callback */
/**
 * A node that checks to see if zero-page login headers have specified username and whether that username is in a group
 * permitted to use zero-page login headers.
 */
@Node.Metadata(outcomeProvider  = AbstractDecisionNode.OutcomeProvider.class,
               configClass      = RadiusNode.Config.class)
public class RadiusNode extends AbstractDecisionNode {

    private final Pattern DN_PATTERN = Pattern.compile("^[a-zA-Z0-9]=([^,]+),");
    private final Logger logger = LoggerFactory.getLogger(RadiusNode.class);
    private final Config config;
    private final Realm realm;
    private Set<RADIUSServer> primaryServers;
    private Set<RADIUSServer> secondaryServers;
    private String sharedSecret;
    private int iServerPort = 1645;
    private int iTimeOut = 5;
    private int healthCheckInterval = 5;
    private RadiusConn radiusConn = null;
    private String Username;
    private static ChallengeException cException = null;
    private static final String BUNDLE = "org.forgerock.openam.RadiusNode.RadiusNode";
    private ResourceBundle bundle;
    private List<Callback> passwordCallbacks;
    private boolean IsChallenge = false;
    /**
     * Configuration for the node.
     */
    public interface Config {

        @Attribute(order = 100, validators = {RequiredValueValidator.class})
        Set<String> primaryServers();

        @Attribute(order = 200)
        Set<String> secondaryServers();

        @Attribute(order = 300, validators = {RequiredValueValidator.class})
        @Password
        char[] sharedSecret();

        @Attribute(order = 400, validators = {RequiredValueValidator.class})
        String portNumber();

        @Attribute(order = 500)
        default String serverTimeout(){
          return "5";
        }

        @Attribute(order = 600)
        default String healthCheckInterval(){
          return "5";
        }

        @Attribute(order = 700)
        default String authenticationLevel(){
          return "0";
        }
    }


    /**
     * Create the node using Guice injection. Just-in-time bindings can be used to obtain instances of other classes
     * from the plugin.
     *
     * @param config The service config.
     * @param realm The realm the node is in.
     * @throws NodeProcessException If the configuration was not valid.
     */
    @Inject
    public RadiusNode(@Assisted Config config, @Assisted Realm realm) throws NodeProcessException {
        this.config = config;
        this.realm = realm;
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {
      Username = context.sharedState.get(USERNAME).asString();
      bundle = context.request.locales.getBundleInPreferredLocale(BUNDLE, getClass().getClassLoader());
      String challenge = null;
      if (context.sharedState.get("challenge") != null) {
        challenge = context.sharedState.get("challenge").asString();
      } else {
        challenge = "false";
      }
      IsChallenge = Boolean.parseBoolean(challenge);
      JsonValue sharedState = context.sharedState.copy();
      Object value;
      if (initialiseRadius()) {
        if (IsChallenge) {
          List<PasswordCallback> callbacks = context.getCallbacks(PasswordCallback.class);
          if (isEmpty(callbacks)) {
            logger.debug("ChallengeCalbacks is empty");
            return send(new PasswordCallback(bundle.getString("callback.challengePassCode"), false)).build();
          }
          List<String> passwords = getPasswords(callbacks);
          if (passwords.isEmpty()) {
            passwordCallbacks = new ArrayList<>();
            passwordCallbacks.add(new PasswordCallback(bundle.getString("callback.challengePassCode"), false));
            passwordCallbacks.add(getErrorCallback("Invalid token response!"));
            return send(passwordCallbacks).build();
          }
          if (!checkPassword(passwords.get(0))) {
            logger.warn("Pass code is null or empty");
            passwordCallbacks = new ArrayList<>();
            passwordCallbacks.add(new PasswordCallback(bundle.getString("callback.challengePassCode"), false));
            passwordCallbacks.add(getErrorCallback("Invalid token response!"));
            return send(passwordCallbacks).build();
          }
          boolean state = authenticateChallenge(Username, passwords.get(0));
          cException = null;
          IsChallenge = false;
          value = "false";
          sharedState.put("challenge", value);
          if (state) {
            return goTo(true).replaceSharedState(sharedState).build();
          } else {
            return goTo(false).replaceSharedState(sharedState).build();
          }
        } else {
          List<PasswordCallback> callbacks = context.getCallbacks(PasswordCallback.class);
          if (isEmpty(callbacks)) {
            logger.debug("Calbacks is empty");
            return send(new PasswordCallback(bundle.getString("callback.passCode"), false)).build();
          }
          List<String> passwords = getPasswords(callbacks);
          if (passwords.isEmpty()) {
            logger.debug("Pass code is null or empty");
            return send(new PasswordCallback(bundle.getString("callback.passCode"), false)).build();
          }
          if (!checkPassword(passwords.get(0))) {
            logger.debug("Pass code is null or empty");
            return send(new PasswordCallback(bundle.getString("callback.passCode"), false)).build();
          }
          boolean state = authenticate(Username, passwords.get(0));
          if (state) {
            return goTo(true).build();
          } else if (!state && IsChallenge) {
            passwordCallbacks = new ArrayList<>();
            passwordCallbacks.add(new PasswordCallback(bundle.getString("callback.challengePassCode"), false));
            passwordCallbacks.add(getErrorCallback("Invalid token response!"));
            value = "true";
            sharedState.put("challenge", value);
            return send(passwordCallbacks).replaceSharedState(sharedState).build();
          } else {
            IsChallenge = false;
            value = "false";
            sharedState.put("challenge", value);
            return goTo(false).replaceSharedState(sharedState).build();
          }
        }
      } else {
        IsChallenge = false;
        value = "false";
        sharedState.put("challenge", value);
        return goTo(false).replaceSharedState(sharedState).build();
      }


    }

    private boolean authenticate(String username, String password){
      try {
        radiusConn.authenticate(username, password);
        return true;
      } catch (RejectException re) {
        logger.error("Radius login request rejected", re);
        shutdown();
        return false;
      } catch (IOException ioe) {
        logger.error("Radius request IOException", ioe);
        shutdown();
        return false;
      } catch (java.security.NoSuchAlgorithmException ne) {
        logger.error("Radius No Such Algorithm Exception", ne);
        shutdown();
        return false;
      } catch (ChallengeException ce) {
        cException = ce;
        IsChallenge = true;
        logger.error("Server challenge with challengeID: {}", ce.getReplyMessage());
        return false;
      } catch (Exception ex) {
        logger.error("Exception Class Name: {}", ex.getClass().getName());
        logger.error("RadiusLoginFailed {}", ex.getMessage());
        shutdown();
        return false;
      }
    }

    private boolean authenticateChallenge(String username, String password){
      try{
        logger.error("Challenge Username: {}, Password: {}", username, password);
        radiusConn.replyChallenge(username, password, cException);
        return true;
      } catch (ChallengeException ce) {
        cException = ce;
        if (ce.getState() == null) {
          cException = null;
          IsChallenge = false;
          shutdown();
          return false;
        }
        IsChallenge = true;
        logger.error("Server challenge with challengeID: {}", ce.getReplyMessage());
        return false;
      } catch (RejectException ex) {
          logger.error("Radius challenge response rejected", ex);
          shutdown();
          return false;
      } catch (IOException ioe) {
          logger.error("Radius challenge IOException", ioe);
          shutdown();
          return false;
      } catch (java.security.NoSuchAlgorithmException ex) {
          logger.error("Radius No Such Algorithm Exception", ex);
          shutdown();
          return false;
      } catch (Exception ex) {
          logger.error("Radius challenge exception class name: {}", ex.getClass().getName());
          logger.error("Radius authenticate failed {}", ex.getMessage());
          shutdown();
          return false;
      }
    }

    private boolean initialiseRadius(){
      try {
          String serverPort = config.portNumber();
          iServerPort = Integer.parseInt(serverPort);

          primaryServers = new LinkedHashSet<RADIUSServer>();
          Set<String> tmp;
          tmp = config.primaryServers();
          if (tmp.isEmpty()) {
              primaryServers.add(new RADIUSServer("localhost", iServerPort));
              logger.error("Error: primary server attribute " + "misconfigured using localhost");
          }
          for (String server : tmp) {
              int idx = server.indexOf(':');
              if (idx == -1) {
                  primaryServers.add(new RADIUSServer(server, iServerPort));
              } else {
                  primaryServers.add(new RADIUSServer(server.substring(0, idx), Integer.parseInt(server
                          .substring(idx + 1))));
              }
          }

          secondaryServers = new LinkedHashSet<RADIUSServer>();
          if (!config.secondaryServers().isEmpty()) {
            tmp = config.secondaryServers();
          }
          if (tmp == null) {
              secondaryServers.add(new RADIUSServer("localhost", iServerPort));
              logger.error("Error: primary server attribute " + "misconfigured using localhost");
          }
          for (String server : tmp) {
              int idx = server.indexOf(':');
              if (server.indexOf(':') == -1) {
                  secondaryServers.add(new RADIUSServer(server, iServerPort));
              } else {
                  secondaryServers.add(new RADIUSServer(server.substring(0, idx), Integer.parseInt(server
                          .substring(idx + 1))));
              }
          }

          sharedSecret = String.valueOf(config.sharedSecret());

          String timeOut = config.serverTimeout();
          iTimeOut = Integer.parseInt(timeOut);

          String interval = config.healthCheckInterval();

          healthCheckInterval = Integer.parseInt(interval);

          logger.debug("server1: {} server2: {} serverPort: {} timeOut: {}", primaryServers, secondaryServers, serverPort, timeOut);

          if ((sharedSecret == null) || (sharedSecret.length() == 0)) {
              logger.error("RADIUS initialization failure; no Shared Secret");
          }
      } catch (Exception ex) {
          logger.error("RADIUS parameters initialization failure", ex);
      }
      try {
        radiusConn = new RadiusConn(primaryServers, secondaryServers, sharedSecret, iTimeOut,healthCheckInterval);
        logger.debug("Radius connection was successful");
        return true;
      } catch (SocketException se) {
          logger.error("RADIUS login failure; Socket Exception se == ", se);
          shutdown();
          return false;
      } catch (Exception e) {
          logger.error("RADIUS login failure; Can't connect to RADIUS server", e);
          shutdown();
          return false;
      }
    }

    private List<String> getPasswords(List<PasswordCallback> callbacks) throws NodeProcessException {
        List<String> passwords = callbacks.stream()
                .map(PasswordCallback::getPassword)
                .map(String::new)
                .collect(Collectors.toList());
        if (passwords.isEmpty()) {
          logger.debug("password is empty {}", passwords.size());
        }
        return passwords;
    }

    private boolean checkPassword(String password) {
        if (StringUtils.isBlank(password) || StringUtils.isEmpty(password)) {
            return false;
        }
        return true;
    }


    public void shutdown() {
        try {
            logger.debug("Radius Connection has disconnected!");
            radiusConn.disconnect();
        } catch (IOException e) {
            // ignore since we are disconnecting
        }

        radiusConn = null;
    }

    private TextOutputCallback getErrorCallback(String message) {
        return new TextOutputCallback(ERROR, message);
    }

}
