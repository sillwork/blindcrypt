package io.github.sillwork.blindcrypt.spring.test;

import io.github.sillwork.blindcrypt.core.Normalization;
import io.github.sillwork.blindcrypt.spring.annotation.BlindIndex;
import io.github.sillwork.blindcrypt.spring.annotation.Encrypted;
import io.github.sillwork.blindcrypt.spring.listener.BlindIndexListener;
import io.github.sillwork.blindcrypt.spring.model.EncryptedText;
import jakarta.persistence.AttributeOverride;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import jakarta.persistence.Version;

@Entity
@Table(name = "test_users", indexes = {
    @Index(name = "ix_users_email_bidx", columnList = "email_bidx"),
    @Index(name = "ux_users_reg_no_bidx", columnList = "registration_no_bidx", unique = true)
})
@EntityListeners(BlindIndexListener.class)
public class TestUser {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Version
    private Long version;

    @Column(nullable = false)
    private String fullName;

    @BlindIndex(name = "user_email", normalization = Normalization.TRIM_CASE_INSENSITIVE)
    @AttributeOverride(name = "encryptedValue", column = @Column(name = "email", length = 512))
    @AttributeOverride(name = "blindIndex", column = @Column(name = "email_bidx", length = 64))
    private EncryptedText email;

    @BlindIndex(name = "user_phone", normalization = Normalization.DIGITS_ONLY)
    @AttributeOverride(name = "encryptedValue", column = @Column(name = "phone", length = 128))
    @AttributeOverride(name = "blindIndex", column = @Column(name = "phone_bidx", length = 64))
    private EncryptedText phone;

    @BlindIndex(name = "user_reg_no", normalization = Normalization.TRIM_CASE_INSENSITIVE)
    @AttributeOverride(name = "encryptedValue", column = @Column(name = "registration_no", length = 160))
    @AttributeOverride(name = "blindIndex", column = @Column(name = "registration_no_bidx", length = 64))
    private EncryptedText registrationNo;

    // Encryption-ONLY: Stored as AES-256-GCM ciphertext in DB, zero blind index column, zero search overhead
    @Encrypted
    @Column(name = "secret_notes", length = 1000)
    private String secretNotes;

    protected TestUser() { }

    public TestUser(String fullName, String email, String phone, String registrationNo) {
        this.fullName = fullName;
        this.email = EncryptedText.of(email);
        this.phone = EncryptedText.of(phone);
        this.registrationNo = EncryptedText.of(registrationNo);
    }

    public Long getId() { return id; }
    public Long getVersion() { return version; }
    public String getFullName() { return fullName; }
    public void setFullName(String fullName) { this.fullName = fullName; }

    public String getEmail() { return EncryptedText.valueOf(email); }
    public void setEmail(String email) { this.email = EncryptedText.update(this.email, email); }

    public String getPhone() { return EncryptedText.valueOf(phone); }
    public void setPhone(String phone) { this.phone = EncryptedText.update(this.phone, phone); }

    public String getRegistrationNo() { return EncryptedText.valueOf(registrationNo); }
    public void setRegistrationNo(String regNo) { this.registrationNo = EncryptedText.update(this.registrationNo, regNo); }

    public String getSecretNotes() { return secretNotes; }
    public void setSecretNotes(String secretNotes) { this.secretNotes = secretNotes; }
}
