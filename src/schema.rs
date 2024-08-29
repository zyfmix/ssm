diesel::table! {
    /// Representation of the `host` table.
    ///
    /// (Automatically generated by Diesel.)
    host (id) {
        /// The `id` column of the `host` table.
        ///
        /// Its SQL type is `Integer`.
        ///
        /// (Automatically generated by Diesel.)
        id -> Integer,
        /// The `name` column of the `host` table.
        ///
        /// Its SQL type is `Text`.
        ///
        /// (Automatically generated by Diesel.)
        name -> Text,
        /// The `username` column of the `host` table.
        ///
        /// Its SQL type is `Text`.
        ///
        /// (Automatically generated by Diesel.)
        username -> Text,
        /// The `hostname` column of the `host` table.
        ///
        /// Its SQL type is `Text`.
        ///
        /// (Automatically generated by Diesel.)
        hostname -> Text,
        /// The `port` column of the `host` table.
        ///
        /// Its SQL type is `Integer`.
        ///
        /// (Automatically generated by Diesel.)
        port -> Integer,
        /// The `key_fingerprint` column of the `host` table.
        ///
        /// Its SQL type is `Text`.
        ///
        /// (Automatically generated by Diesel.)
        key_fingerprint -> Text,
        /// The `jump_via` column of the `host` table.
        ///
        /// Its SQL type is `Nullable<Integer>`.
        ///
        /// (Automatically generated by Diesel.)
        jump_via -> Nullable<Integer>,
    }
}

diesel::table! {
    /// Representation of the `user` table.
    ///
    /// (Automatically generated by Diesel.)
    user (id) {
        /// The `id` column of the `user` table.
        ///
        /// Its SQL type is `Integer`.
        ///
        /// (Automatically generated by Diesel.)
        id -> Integer,
        /// The `username` column of the `user` table.
        ///
        /// Its SQL type is `Text`.
        ///
        /// (Automatically generated by Diesel.)
        username -> Text,
        /// The `enabled` column of the `user` table.
        ///
        /// Its SQL type is `Bool`.
        ///
        /// (Automatically generated by Diesel.)
        enabled -> Bool,
    }
}

diesel::table! {
    /// Representation of the `user_in_host` table.
    ///
    /// (Automatically generated by Diesel.)
    user_in_host (id) {
        /// The `id` column of the `user_in_host` table.
        ///
        /// Its SQL type is `Integer`.
        ///
        /// (Automatically generated by Diesel.)
        id -> Integer,
        /// The `host_id` column of the `user_in_host` table.
        ///
        /// Its SQL type is `Integer`.
        ///
        /// (Automatically generated by Diesel.)
        host_id -> Integer,
        /// The `user_id` column of the `user_in_host` table.
        ///
        /// Its SQL type is `Integer`.
        ///
        /// (Automatically generated by Diesel.)
        user_id -> Integer,
        /// The `options` column of the `user_in_host` table.
        ///
        /// Its SQL type is `Nullable<Text>`.
        ///
        /// (Automatically generated by Diesel.)
        options -> Nullable<Text>,
    }
}

diesel::table! {
    /// Representation of the `user_key` table.
    ///
    /// (Automatically generated by Diesel.)
    user_key (id) {
        /// The `id` column of the `user_key` table.
        ///
        /// Its SQL type is `Integer`.
        ///
        /// (Automatically generated by Diesel.)
        id -> Integer,
        /// The `key_type` column of the `user_key` table.
        ///
        /// Its SQL type is `Text`.
        ///
        /// (Automatically generated by Diesel.)
        key_type -> Text,
        /// The `key_base64` column of the `user_key` table.
        ///
        /// Its SQL type is `Text`.
        ///
        /// (Automatically generated by Diesel.)
        key_base64 -> Text,
        /// The `comment` column of the `user_key` table.
        ///
        /// Its SQL type is `Nullable<Text>`.
        ///
        /// (Automatically generated by Diesel.)
        comment -> Nullable<Text>,
        /// The `user_id` column of the `user_key` table.
        ///
        /// Its SQL type is `Integer`.
        ///
        /// (Automatically generated by Diesel.)
        user_id -> Integer,
    }
}

diesel::joinable!(user_in_host -> host (host_id));
diesel::joinable!(user_in_host -> user (user_id));
diesel::joinable!(user_key -> user (user_id));

diesel::allow_tables_to_appear_in_same_query!(host, user, user_in_host, user_key,);
