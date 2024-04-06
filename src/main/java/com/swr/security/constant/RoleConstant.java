package com.swr.security.constant;

import java.util.List;

public class RoleConstant {

    public static final Integer ROLE_TYPE_MANAGER = 1;
    public static final Integer ROLE_TYPE_ADMIN = 2;
    public static final Integer ROLE_TYPE_USER = 3;

    public static final String ROLE_NAME_MANAGER = "ROLE_MANAGER";
    public static final String ROLE_NAME_ADMIN = "ROLE_ADMIN";
    public static final String ROLE_NAME_USER = "ROLE_USER";

    public static final List<String> ROLE_USER_PERMISSIONS = List.of("READ");
    public static final List<String> ROLE_MANAGER_PERMISSIONS = List.of("READ", "WRITE");
    public static final List<String> ROLE_ADMIN_PERMISSIONS = List.of("READ", "WRITE", "DELETE");
}
