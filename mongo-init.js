db.createUser(
    {
        user: "user",
        pwd: "password",
        roles: [
            {
                role: "readWrite",
                db: "logger_db"
            }
        ]
    }
);