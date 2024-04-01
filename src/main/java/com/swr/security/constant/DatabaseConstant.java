package com.swr.security.constant;

public final class DatabaseConstant {

    public static final class User {
        public static final String TABLE_NAME = "USER_INFO";
        public static final String COLUMN_USER_ID = "USER_ID";
        public static final String COLUMN_FIRST_NAME = "FIRST_NAME";
        public static final String COLUMN_LAST_NAME = "LAST_NAME";
        public static final String COLUMN_EMAIL = "EMAIL";
        public static final String COLUMN_USERNAME = "USERNAME";
        public static final String COLUMN_PASSWORD = "PASSWORD";
    }

    public static final class Role {

        public static final String TABLE_NAME = "USER_ROLE";
        public static final String COLUMN_ROLE_ID = "ROLE_ID";
        public static final String COLUMN_ROLE_NAME = "ROLE_NAME";
        public static final String COLUMN_ROLE_TYPE = "ROLE_TYPE";
    }
}
