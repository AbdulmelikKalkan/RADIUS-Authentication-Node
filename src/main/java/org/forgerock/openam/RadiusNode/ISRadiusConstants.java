package org.forgerock.openam.RadiusNode;

import java.util.UUID;

public final class ISRadiusConstants {
  private ISRadiusConstants(){

  }

  public static final int LOGIN_IGNORE = 0;

  public static final int LOGIN_START = 1;

  public static final int LOGIN_SUCCEED = -1;

  public static final int LOGIN_CHALLENGE = 2;
}
