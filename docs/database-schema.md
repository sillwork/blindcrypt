# Database Schema

[Back to README](../README.md)


When provisioning databases via Liquibase, Flyway, or DDL scripts, create the blind index columns with the type that matches the Java type:

### PostgreSQL DDL

```sql
CREATE TABLE users (
    id                BIGSERIAL PRIMARY KEY,
    version           BIGINT NOT NULL DEFAULT 0,
    full_name         VARCHAR(200) NOT NULL,
    email             VARCHAR(512) NOT NULL,
    email_bidx        VARCHAR(64) NOT NULL,
    ssn               VARCHAR(128) NOT NULL,
    ssn_bidx          VARCHAR(64) NOT NULL,
    secret_notes      TEXT,
    secret_attachment BYTEA,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX ix_users_email_bidx ON users (email_bidx);
CREATE UNIQUE INDEX ux_users_ssn_bidx ON users (ssn_bidx);
```

Use `BYTEA` / `BINARY(32)` only for `EncryptedBytes` fields.

### Liquibase ChangeSet (`changelog.xml`)

```xml
<changeSet id="20260930-create-users-table" author="blindcrypt">
    <createTable tableName="users">
        <column name="id" type="BIGINT" autoIncrement="true">
            <constraints primaryKey="true" nullable="false"/>
        </column>
        <column name="version" type="BIGINT" defaultValueNumeric="0">
            <constraints nullable="false"/>
        </column>
        <column name="full_name" type="VARCHAR(200)"><constraints nullable="false"/></column>
        <column name="email" type="VARCHAR(512)"><constraints nullable="false"/></column>
        <column name="email_bidx" type="VARCHAR(64)"><constraints nullable="false"/></column>
        <column name="ssn" type="VARCHAR(128)"><constraints nullable="false"/></column>
        <column name="ssn_bidx" type="VARCHAR(64)"><constraints nullable="false"/></column>
        <column name="secret_notes" type="VARCHAR(4096)"/>
        <column name="secret_attachment" type="BLOB"/>
    </createTable>

    <createIndex tableName="users" indexName="ix_users_email_bidx">
        <column name="email_bidx"/>
    </createIndex>
    <createIndex tableName="users" indexName="ux_users_ssn_bidx" unique="true">
        <column name="ssn_bidx"/>
    </createIndex>
</changeSet>
```


